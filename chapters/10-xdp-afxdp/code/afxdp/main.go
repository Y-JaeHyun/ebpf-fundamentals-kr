// SPDX-License-Identifier: MIT
// 10-2: 최소 AF_XDP 수신기. XDP가 넘겨준 패킷을 커널 네트워크 스택을 거치지 않고 사용자 공간에서 받는다.
// 라이브러리 없이 소켓·UMEM·링을 직접 만들어 구조를 보여 주는 것이 목적이다(수신 전용, copy 모드, 큐 0).
//
//	afxdp recv -if veth10b [-port 9000] [-n 10] [-timeout 3s]
//	afxdp send -to 192.0.2.2:9000 [-n 10]
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH afxdp afxdp.bpf.c -- -I../../../../include

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	frameSize = 2048 // UMEM을 나누는 칸(chunk) 크기. 패킷 하나가 한 칸에 들어간다
	numFrames = 128
	ringSize  = 64 // 링 크기는 2의 거듭제곱
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("사용법: afxdp recv|send [옵션]")
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
	fs.Parse(args)
	conn, err := net.Dial("udp4", *to)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	for i := 1; i <= *n; i++ {
		fmt.Fprintf(conn, "hello AF_XDP #%d", i)
		time.Sleep(20 * time.Millisecond)
	}
}

// ring은 커널과 공유하는 단일 생산자·단일 소비자 링 버퍼 하나를 가리킨다.
// producer/consumer는 커널과 동시에 읽고 쓰므로 atomic으로 접근한다.
type ring struct {
	producer *uint32
	consumer *uint32
	desc     unsafe.Pointer // 설명자 배열의 시작
	mask     uint32
}

func mapRing(fd int, off unix.XDPRingOffset, pgoff int64, entSize uintptr) ring {
	size := int(off.Desc) + ringSize*int(entSize)
	mem, err := unix.Mmap(fd, pgoff, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		log.Fatalf("링 mmap 실패: %v", err)
	}
	base := unsafe.Pointer(&mem[0])
	return ring{
		producer: (*uint32)(unsafe.Add(base, off.Producer)),
		consumer: (*uint32)(unsafe.Add(base, off.Consumer)),
		desc:     unsafe.Add(base, off.Desc),
		mask:     ringSize - 1,
	}
}

func setsockopt(fd, opt int, p unsafe.Pointer, size uintptr) {
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), unix.SOL_XDP, uintptr(opt),
		uintptr(p), size, 0); e != 0 {
		log.Fatalf("setsockopt(%d) 실패: %v", opt, e)
	}
}

func recv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	ifname := fs.String("if", "veth10b", "인터페이스")
	port := fs.Uint("port", 9000, "AF_XDP로 가로챌 UDP 목적지 포트")
	n := fs.Int("n", 10, "받을 패킷 수")
	timeout := fs.Duration("timeout", 3*time.Second, "최대 대기 시간")
	fs.Parse(args)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatal(err)
	}

	// ① AF_XDP 소켓
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		log.Fatalf("AF_XDP 소켓 생성 실패: %v", err)
	}
	defer unix.Close(fd)

	// ② UMEM: 패킷이 실제로 담길 사용자 공간 메모리. 커널에 등록하면 커널이 여기에 패킷을 복사한다
	umem, err := unix.Mmap(-1, 0, numFrames*frameSize, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		log.Fatal(err)
	}
	reg := unix.XDPUmemReg{Addr: uint64(uintptr(unsafe.Pointer(&umem[0]))), Len: uint64(len(umem)), Size: frameSize}
	setsockopt(fd, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg))

	// ③ 링 크기 설정: fill(빈 칸을 커널에 줌), completion(송신 완료, 수신 전용이라도 필요), rx(받은 패킷)
	for _, opt := range []int{unix.XDP_UMEM_FILL_RING, unix.XDP_UMEM_COMPLETION_RING, unix.XDP_RX_RING} {
		if err := unix.SetsockoptInt(fd, unix.SOL_XDP, opt, ringSize); err != nil {
			log.Fatalf("링 크기 설정 실패: %v", err)
		}
	}
	var off unix.XDPMmapOffsets
	offLen := uint32(unsafe.Sizeof(off))
	if _, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&off)), uintptr(unsafe.Pointer(&offLen)), 0); e != 0 {
		log.Fatalf("XDP_MMAP_OFFSETS 실패: %v", e)
	}
	fill := mapRing(fd, off.Fr, unix.XDP_UMEM_PGOFF_FILL_RING, 8) // 설명자 = UMEM 주소(u64)
	rx := mapRing(fd, off.Rx, unix.XDP_PGOFF_RX_RING, unsafe.Sizeof(unix.XDPDesc{}))

	// ④ fill 링에 빈 칸 주소를 채워 둔다. 커널은 여기서 칸을 꺼내 패킷을 담는다
	push := func(addr uint64) {
		p := atomic.LoadUint32(fill.producer)
		*(*uint64)(unsafe.Add(fill.desc, uintptr(p&fill.mask)*8)) = addr
		atomic.StoreUint32(fill.producer, p+1)
	}
	for i := 0; i < ringSize; i++ {
		push(uint64(i * frameSize))
	}

	// ⑤ 인터페이스의 0번 큐에 bind. XDP_COPY: 드라이버가 zero-copy를 지원하지 않아도 동작하는 복사 모드
	if err := unix.Bind(fd, &unix.SockaddrXDP{Flags: unix.XDP_COPY, Ifindex: uint32(iface.Index), QueueID: 0}); err != nil {
		log.Fatalf("bind 실패: %v", err)
	}

	// ⑥ XDP 프로그램 로드 → XSKMAP[0] = 이 소켓 → attach
	spec, err := loadAfxdp()
	if err != nil {
		log.Fatal(err)
	}
	if err := spec.Variables["port"].Set(uint16(*port)); err != nil {
		log.Fatal(err)
	}
	var objs afxdpObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()
	if err := objs.Xsks.Put(uint32(0), uint32(fd)); err != nil {
		log.Fatalf("XSKMAP 등록 실패: %v", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: objs.XdpToXsk, Interface: iface.Index})
	if err != nil {
		log.Fatalf("XDP attach 실패: %v", err)
	}
	defer l.Close()

	// 비교용: 같은 포트를 여는 보통 UDP 소켓. AF_XDP가 가로채면 여기엔 아무것도 오지 않는다
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(*port)})
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	var udpGot atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := udp.ReadFromUDP(buf); err != nil {
				return
			}
			udpGot.Add(1)
		}
	}()

	fmt.Println("ready")
	got := 0
	deadline := time.Now().Add(*timeout)
	for got < *n && time.Now().Before(deadline) {
		// ⑦ rx 링에 새 설명자가 생길 때까지 poll로 기다린다
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(pfd, 100); err != nil && err != unix.EINTR {
			log.Fatal(err)
		}
		cons := atomic.LoadUint32(rx.consumer)
		prod := atomic.LoadUint32(rx.producer)
		for ; cons != prod; cons++ {
			d := (*unix.XDPDesc)(unsafe.Add(rx.desc, uintptr(cons&rx.mask)*unsafe.Sizeof(unix.XDPDesc{})))
			pkt := umem[d.Addr : d.Addr+uint64(d.Len)]
			got++
			printPacket(got, d, pkt)
			push(d.Addr &^ (frameSize - 1)) // 다 쓴 칸을 fill 링으로 돌려준다
		}
		atomic.StoreUint32(rx.consumer, cons)
	}
	time.Sleep(200 * time.Millisecond) // 보통 UDP 소켓 쪽에 늦게 도착하는 것이 있는지 잠깐 더 본다
	fmt.Printf("AF_XDP 소켓이 받은 패킷: %d, 같은 포트의 보통 UDP 소켓이 받은 패킷: %d\n", got, udpGot.Load())
}

// printPacket은 이더넷·IP·UDP 헤더를 직접 해석해 한 줄로 보여 준다(커널이 아무 처리도 하지 않은 원본 프레임이다).
// 네트워크에서 온 바이트이므로 헤더의 길이 필드를 믿지 않고 실제 길이와 맞춰 본 뒤 자른다.
func printPacket(i int, d *unix.XDPDesc, pkt []byte) {
	bad := func(why string) {
		fmt.Printf("#%-2d umem주소=%#06x 길이=%d  (해석 불가: %s)\n", i, d.Addr, d.Len, why)
	}
	if len(pkt) < 14+20 {
		bad("IPv4 헤더보다 짧음")
		return
	}
	ip := pkt[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		bad("IP/UDP 헤더 길이")
		return
	}
	udp := ip[ihl:]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		bad("UDP 길이 필드")
		return
	}
	fmt.Printf("#%-2d umem주소=%#06x 길이=%d  %s:%d → %s:%d  %q\n", i, d.Addr, d.Len,
		net.IP(ip[12:16]), binary.BigEndian.Uint16(udp[0:2]),
		net.IP(ip[16:20]), binary.BigEndian.Uint16(udp[2:4]), udp[8:udpLen])
}
