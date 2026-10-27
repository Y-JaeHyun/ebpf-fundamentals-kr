// SPDX-License-Identifier: MIT
// 09장: 수신 경로의 hook 7곳에 프로그램을 붙이고, 실험 패킷이 각 hook을 지난 시각을 표로 보여 준다.
//
//	pktpath recv -if veth09b [-n 10] [-drop tc]   # 받는 쪽 netns에서 (root)
//	pktpath send -to 192.0.2.2:9000 [-n 10]       # 보내는 쪽 netns에서
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH -type pkt_path pktpath pktpath.bpf.c -- -I../../../../include

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// pktpath.bpf.c의 enum stage와 같은 순서
var stages = []string{"XDP", "TC", "ip_rcv_core", "NF_PRE", "NF_IN", "udp_rcv", "socket"}

const port = 9000

func main() {
	if len(os.Args) < 2 {
		log.Fatal("사용법: pktpath recv|send [옵션]")
	}
	switch os.Args[1] {
	case "recv":
		recv(os.Args[2:])
	case "send":
		send(os.Args[2:])
	default:
		log.Fatalf("알 수 없는 명령: %s", os.Args[1])
	}
}

func send(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "192.0.2.2:9000", "목적지")
	n := fs.Int("n", 10, "보낼 패킷 수")
	gap := fs.Duration("gap", 20*time.Millisecond, "패킷 간격")
	fs.Parse(args)

	conn, err := net.Dial("udp4", *to)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 32)
	copy(buf, "EBPF")
	for seq := 1; seq <= *n; seq++ {
		binary.LittleEndian.PutUint32(buf[4:], uint32(seq))
		if _, err := conn.Write(buf); err != nil {
			log.Fatal(err)
		}
		time.Sleep(*gap)
	}
}

func recv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	ifname := fs.String("if", "veth09b", "XDP·TC를 붙일 인터페이스")
	n := fs.Int("n", 10, "기다릴 패킷 수")
	drop := fs.String("drop", "", "이 단계에서 실험 패킷을 버린다: xdp|tc|nf_pre|nf_in|socket")
	timeout := fs.Duration("timeout", 3*time.Second, "패킷을 기다리는 최대 시간")
	noXDP := fs.Bool("no-xdp", false, "XDP 프로그램을 붙이지 않는다(수신 경로 비교용)")
	fs.Parse(args)

	dropAt := uint32(len(stages))
	if *drop != "" {
		i := slices.IndexFunc(stages, func(s string) bool { return strings.EqualFold(s, *drop) })
		if i < 0 || stages[i] == "ip_rcv_core" || stages[i] == "udp_rcv" {
			log.Fatalf("-drop은 xdp|tc|nf_pre|nf_in|socket 중 하나 (fentry는 버릴 수 없다)")
		}
		dropAt = uint32(i)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	spec, err := loadPktpath()
	if err != nil {
		log.Fatal(err)
	}
	if err := spec.Variables["drop_at"].Set(dropAt); err != nil {
		log.Fatal(err)
	}
	var ifn [16]byte
	copy(ifn[:15], *ifname)
	if err := spec.Variables["target_if"].Set(ifn); err != nil {
		log.Fatal(err)
	}
	var objs pktpathObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatal(err)
	}

	var links []link.Link
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	attach := func(what string, l link.Link, err error) {
		if err != nil {
			log.Fatalf("%s attach 실패: %v", what, err)
		}
		links = append(links, l)
	}
	if !*noXDP {
		l, err := link.AttachXDP(link.XDPOptions{Program: objs.AtXdp, Interface: iface.Index})
		attach("XDP", l, err)
	}
	l, err := link.AttachTCX(link.TCXOptions{Program: objs.AtTc, Interface: iface.Index, Attach: ebpf.AttachTCXIngress})
	attach("TCX", l, err)
	for name, p := range map[string]*ebpf.Program{
		"fentry/ip_rcv_core": objs.AtIpRcvCore, "fentry/ip_rcv": objs.CntIpRcv, "fentry/ip_list_rcv": objs.CntIpListRcv,
	} {
		l, err = link.AttachTracing(link.TracingOptions{Program: p})
		attach(name, l, err)
	}
	l, err = link.AttachTracing(link.TracingOptions{Program: objs.AtUdpRcv})
	attach("fentry/udp_rcv", l, err)
	for _, h := range []link.NetfilterInetHook{link.NetfilterInetPreRouting, link.NetfilterInetLocalIn} {
		// netfilter link는 이 프로세스가 속한 network namespace에 붙는다
		l, err = link.AttachNetfilter(link.NetfilterOptions{
			Program: objs.AtNf, ProtocolFamily: link.NetfilterProtoIPv4, Hook: h, Priority: 100,
		})
		attach("netfilter", l, err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	// 소켓 필터는 link가 아니라 setsockopt로 이 소켓 하나에만 붙는다
	raw, _ := conn.SyscallConn()
	var serr error
	raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.AtSock.FD())
	})
	if serr != nil {
		log.Fatalf("SO_ATTACH_BPF 실패: %v", serr)
	}

	fmt.Println("ready") // run.sh가 이 줄을 보고 송신을 시작한다
	got := map[uint32]bool{}
	buf := make([]byte, 64)
	deadline := time.Now().Add(*timeout)
	for len(got) < *n {
		conn.SetReadDeadline(deadline)
		m, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			log.Fatal(err)
		}
		if m >= 8 && string(buf[:4]) == "EBPF" {
			got[binary.LittleEndian.Uint32(buf[4:])] = true
		}
	}
	// 수신이 끝났으니 이후의 집계는 바뀌지 않는다
	for _, l := range links {
		l.Close()
	}
	links = nil

	printTable(objs.Paths, *n, got)

	var cnt [2]uint64
	for i := range cnt {
		objs.EntryCnt.Lookup(uint32(i), &cnt[i])
	}
	fmt.Printf("%s에서 IP 계층 진입: ip_rcv %d회, ip_list_rcv %d회(묶음 단위 호출)\n", *ifname, cnt[0], cnt[1])
}

func printTable(m *ebpf.Map, n int, got map[uint32]bool) {
	fmt.Printf("%-4s", "seq")
	for i, s := range stages {
		fmt.Printf(" %*s", width(i), s)
	}
	fmt.Printf(" %5s\n", "app")
	fmt.Println("     (각 칸: 앞 단계를 지난 뒤 걸린 시간 µs, '-'는 그 hook에 오지 않음)")

	deltas := make([][]float64, len(stages))
	for seq := uint32(1); seq <= uint32(n); seq++ {
		var p pktpathPktPath
		if err := m.Lookup(seq, &p); err != nil {
			fmt.Printf("%-4d (어느 hook에도 기록 없음)\n", seq)
			continue
		}
		fmt.Printf("%-4d", seq)
		var prev uint64
		for i, ts := range p.Ts {
			switch {
			case ts == 0:
				fmt.Printf(" %*s", width(i), "-")
			case prev == 0:
				fmt.Printf(" %*s", width(i), "0")
				prev = ts
			default:
				d := float64(int64(ts-prev)) / 1e3
				deltas[i] = append(deltas[i], d)
				fmt.Printf(" %*.1f", width(i), d)
				prev = ts
			}
		}
		app := "-"
		if got[seq] {
			app = "받음"
		}
		fmt.Printf(" %5s\n", app)
	}

	fmt.Printf("%-4s", "중앙")
	for i := range stages {
		if len(deltas[i]) == 0 {
			fmt.Printf(" %*s", width(i), "")
			continue
		}
		slices.Sort(deltas[i])
		fmt.Printf(" %*.1f", width(i), deltas[i][len(deltas[i])/2])
	}
	fmt.Printf("\n앱이 받은 패킷: %d/%d\n", len(got), n)
}

func width(i int) int {
	return max(8, len(stages[i]))
}
