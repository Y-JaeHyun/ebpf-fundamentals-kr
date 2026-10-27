// SPDX-License-Identifier: MIT
// 11-1: tcx egress 로더. 목적지 포트가 맞는 TCP 패킷을 버리고, 버린 패킷마다 한 줄씩 출력한다.
//
//	tcegress -if veth11a -port 8080 [-d 4s]
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH -type drop_event tcegress tcegress.bpf.c -- -I../../../../include

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
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

func main() {
	ifname := flag.String("if", "veth11a", "붙일 인터페이스")
	port := flag.Uint("port", 8080, "버릴 TCP 목적지 포트")
	duration := flag.Duration("d", 0, "실행 시간. 0이면 Ctrl-C까지")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		log.Fatalf("-port는 1~65535: %d", *port)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	spec, err := loadTcegress()
	if err != nil {
		log.Fatal(err)
	}
	if err := spec.Variables["block_port"].Set(uint16(*port)); err != nil {
		log.Fatal(err)
	}
	var objs tcegressObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatal(err)
	}
	l, err := link.AttachTCX(link.TCXOptions{Program: objs.Egress, Interface: iface.Index, Attach: ebpf.AttachTCXEgress})
	if err != nil {
		log.Fatalf("tcx egress attach 실패: %v", err)
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
		l.Close() // 먼저 떼고, 남은 이벤트를 비운다
		rd.Flush()
	}()

	fmt.Printf("ready: %s egress에 tcx attach, TCP 목적지 포트 %d 버림\n", *ifname, *port)
	var e tcegressDropEvent
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
		fmt.Printf("+%.3fs  버림  %s:%d → %s:%d  %s\n", float64(e.Ts-first)/1e9,
			ip4(e.Saddr), e.Sport, ip4(e.Daddr), e.Dport, flags(e.Flags))
	}

	var sum [2]uint64
	for i := range sum {
		var per []uint64
		if err := objs.Stats.Lookup(uint32(i), &per); err != nil {
			log.Fatal(err)
		}
		for _, v := range per {
			sum[i] += v
		}
	}
	fmt.Printf("TCP 패킷: 다음으로 넘김(TCX_NEXT) %d, 버림 %d\n", sum[0], sum[1])
}

// ip4는 네트워크 바이트 순서 그대로 담긴 u32를 주소로 바꾼다
func ip4(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func flags(f uint8) string {
	names := []string{"FIN", "SYN", "RST", "PSH", "ACK"}
	s := ""
	for i, n := range names {
		if f&(1<<i) != 0 {
			if s != "" {
				s += "|"
			}
			s += n
		}
	}
	return "[" + s + "]"
}
