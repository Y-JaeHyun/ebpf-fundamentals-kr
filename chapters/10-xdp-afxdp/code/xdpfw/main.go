// SPDX-License-Identifier: MIT
// 10-1: XDP 방화벽 로더. 차단 목록 map을 bpffs에 pin해 두고, 1초마다 통과/차단 수를 출력한다.
//
//	xdpfw -if veth10b -pin /run/ebpf-ch10/blocklist [-d 10s]
//	(다른 터미널) bpftool map update pinned /run/ebpf-ch10/blocklist key 192 0 2 1 value 1
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH xdpfw xdpfw.bpf.c -- -I../../../../include

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifname := flag.String("if", "veth10b", "붙일 인터페이스")
	pin := flag.String("pin", "", "차단 목록 map을 pin할 bpffs 경로(비우면 pin하지 않음)")
	duration := flag.Duration("d", 0, "실행 시간. 0이면 Ctrl-C까지")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var objs xdpfwObjects
	if err := loadXdpfwObjects(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	if *pin != "" {
		// pin: 파일 경로로 map을 공개해, 다른 프로세스(bpftool)가 열어서 고칠 수 있게 한다
		if err := objs.Blocklist.Pin(*pin); err != nil {
			log.Fatalf("pin 실패: %v", err)
		}
		defer objs.Blocklist.Unpin()
	}

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatal(err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: objs.XdpFw, Interface: iface.Index})
	if err != nil {
		log.Fatalf("XDP attach 실패: %v", err)
	}
	defer l.Close()
	if info, err := l.Info(); err == nil {
		if x := info.XDP(); x != nil {
			fmt.Printf("ready: %s(ifindex %d)에 XDP attach, link id %d\n", *ifname, x.Ifindex, info.ID)
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	var timeout <-chan time.Time
	if *duration > 0 {
		timeout = time.After(*duration)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var last [2]uint64
	for {
		select {
		case <-stop:
			return
		case <-timeout:
			return
		case <-tick.C:
		}
		var cur [2]uint64
		for i := range cur {
			var per []uint64
			if err := objs.Stats.Lookup(uint32(i), &per); err != nil {
				log.Fatal(err)
			}
			for _, v := range per {
				cur[i] += v
			}
		}
		fmt.Printf("%s  통과 +%d  차단 +%d  (누적 %d / %d)\n", time.Now().Format("15:04:05"),
			cur[0]-last[0], cur[1]-last[1], cur[0], cur[1])
		last = cur
	}
}
