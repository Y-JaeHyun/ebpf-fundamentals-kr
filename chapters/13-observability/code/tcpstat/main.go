// SPDX-License-Identifier: MIT
// 13-2: TCP 재전송을 한 줄씩, 연결이 닫히면 RTT·재전송 횟수·전송량을 한 줄로 출력한다.
//
//	tcpstat [-netns /run/netns/이름] [-d 10s]
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH -type event tcpstat tcpstat.bpf.c -- -I../../../../include

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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// include/net/tcp_states.h
var states = []string{"?", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
	"TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV"}

func main() {
	nsPath := flag.String("netns", "", "이 network namespace의 소켓만 본다(예: /run/netns/ebpf13a). 비우면 전부")
	duration := flag.Duration("d", 0, "실행 시간. 0이면 Ctrl-C까지")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	spec, err := loadTcpstat()
	if err != nil {
		log.Fatal(err)
	}
	if *nsPath != "" {
		// netns 파일의 inode 번호가 곧 커널의 net->ns.inum이다(ls -L -i /run/netns/X 와 같다)
		var st syscall.Stat_t
		if err := syscall.Stat(*nsPath, &st); err != nil {
			log.Fatal(err)
		}
		if err := spec.Variables["netns_ino"].Set(uint32(st.Ino)); err != nil {
			log.Fatal(err)
		}
	}
	var objs tcpstatObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()
	for _, p := range []*ebpf.Program{objs.OnRetrans, objs.OnState} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
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
		rd.Flush()
	}()

	fmt.Println("ready")
	var e tcpstatEvent
	var first uint64
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
		if first == 0 {
			first = e.Ts
		}
		conn := fmt.Sprintf("%s:%d → %s:%d", ip4(e.Saddr), e.Sport, ip4(e.Daddr), e.Dport)
		at := fmt.Sprintf("+%.3fs", float64(e.Ts-first)/1e9)
		switch e.Type {
		case 1:
			fail := ""
			if e.Err != 0 {
				fail = fmt.Sprintf("  (재전송 실패: %v)", syscall.Errno(-e.Err))
			}
			fmt.Printf("%s  재전송  %s  %-11s %5d B  srtt=%.1fms  누적 재전송 %d 세그먼트%s\n",
				at, conn, state(e.State), e.SkbLen, float64(e.SrttUs)/1e3, e.TotalRetrans, fail)
		case 2:
			fmt.Printf("%s  닫힘    %s  srtt=%.1fms  재전송 %d/%d 세그먼트  보냄(ACK 받음) %d B  받음 %d B  연결 유지 %.2fs\n",
				at, conn, float64(e.SrttUs)/1e3, e.TotalRetrans, e.DataSegsOut,
				e.BytesAcked, e.BytesReceived, float64(e.LifeNs)/1e9)
		}
	}
}

func state(s uint8) string {
	if int(s) < len(states) {
		return states[s]
	}
	return fmt.Sprint(s)
}

func ip4(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
