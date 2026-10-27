// SPDX-License-Identifier: MIT
// 11-2: cgroup 소켓 hook 로더. 지정한 cgroup에 connect4/sendmsg4 프로그램을 붙이고 판정을 출력한다.
//
//	cgsock -cgroup /sys/fs/cgroup/ebpf-ch11 [-deny-tcp 8080] [-deny-udp 9000] [-redirect 80:8081] [-d 5s]
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH -type event cgsock cgsock.bpf.c -- -I../../../../include

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func main() {
	cgroup := flag.String("cgroup", "", "프로그램을 붙일 cgroup v2 디렉터리")
	denyTCP := flag.Uint("deny-tcp", 0, "connect를 거부할 TCP 목적지 포트")
	denyUDP := flag.Uint("deny-udp", 0, "connect/sendmsg를 거부할 UDP 목적지 포트")
	redirect := flag.String("redirect", "", "TCP 목적지 포트 바꾸기, 예: 80:8081")
	duration := flag.Duration("d", 0, "실행 시간. 0이면 Ctrl-C까지")
	flag.Parse()
	if *cgroup == "" {
		log.Fatal("-cgroup이 필요하다")
	}
	for name, p := range map[string]uint{"-deny-tcp": *denyTCP, "-deny-udp": *denyUDP} {
		if p > 65535 {
			log.Fatalf("%s는 0(사용 안 함) 또는 1~65535: %d", name, p)
		}
	}
	var from, to uint64
	if *redirect != "" {
		a, b, ok := strings.Cut(*redirect, ":")
		var err1, err2 error
		from, err1 = strconv.ParseUint(a, 10, 16)
		to, err2 = strconv.ParseUint(b, 10, 16)
		if !ok || err1 != nil || err2 != nil || from == 0 || to == 0 {
			log.Fatalf("-redirect 형식: 원래포트:새포트, 각각 1~65535 (%q)", *redirect)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	spec, err := loadCgsock()
	if err != nil {
		log.Fatal(err)
	}
	for name, v := range map[string]uint16{
		"deny_tcp": uint16(*denyTCP), "deny_udp": uint16(*denyUDP),
		"redir_from": uint16(from), "redir_to": uint16(to),
	} {
		if err := spec.Variables[name].Set(v); err != nil {
			log.Fatalf("%s 설정 실패: %v", name, err)
		}
	}
	var objs cgsockObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	var links []link.Link
	for _, a := range []struct {
		prog *ebpf.Program
		typ  ebpf.AttachType
	}{
		{objs.Connect4, ebpf.AttachCGroupInet4Connect},
		{objs.Sendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: *cgroup, Attach: a.typ, Program: a.prog})
		if err != nil {
			log.Fatalf("cgroup attach 실패(%v): %v", a.typ, err)
		}
		links = append(links, l)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		if *duration > 0 {
			select {
			case <-stop:
			case <-time.After(*duration):
			}
		} else {
			<-stop
		}
		for _, l := range links { // 먼저 떼어 정책을 끄고, 남은 이벤트를 비운다
			l.Close()
		}
		rd.Flush()
	}()

	fmt.Printf("ready: %s 에 connect4, sendmsg4 attach\n", *cgroup)
	fmt.Printf("%-9s %-5s %-9s %-7s %-8s %s\n", "HOOK", "PROTO", "VERDICT", "PID", "COMM", "DST")
	var e cgsockEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Fatal(err)
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &e); err != nil {
			log.Fatal(err)
		}
		hook := map[uint8]string{1: "connect4", 2: "sendmsg4"}[e.Hook]
		proto := map[uint8]string{unix.SOCK_STREAM: "TCP", unix.SOCK_DGRAM: "UDP"}[e.Type]
		verdict := map[uint8]string{0: "ALLOW", 1: "DENY", 2: "REDIRECT"}[e.Verdict]
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], e.Daddr)
		dst := fmt.Sprintf("%s:%d", netip.AddrFrom4(b), e.Dport)
		if e.Verdict == 2 {
			dst += fmt.Sprintf(" → :%d", e.NewDport)
		}
		fmt.Printf("%-9s %-5s %-9s %-7d %-8s %s\n", hook, proto, verdict, e.Pid, unix.ByteSliceToString(e.Comm[:]), dst)
	}
}
