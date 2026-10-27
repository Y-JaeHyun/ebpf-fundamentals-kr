// SPDX-License-Identifier: MIT
// 11장 실험용 클라이언트·서버(BPF 없음). 결과와 걸린 시간을 한 줄로 출력한다.
//
//	probe serve -tcp 8080,8081 -udp 9000          서버: 받은 연결·데이터그램을 출력
//	probe connect 192.0.2.2:8080 [-timeout 2s]    TCP connect 시도
//	probe udp 192.0.2.2:9000 [-connect]           UDP 송신(-connect면 connect 후 send)
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("사용법: probe serve|connect|udp [옵션]")
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "connect":
		connect(os.Args[2:])
	case "udp":
		udp(os.Args[2:])
	default:
		log.Fatalf("알 수 없는 명령: %s", os.Args[1])
	}
}

// parse는 "명령 주소 [옵션]" 순서를 허용한다(flag 패키지는 위치 인자 뒤의 옵션을 읽지 않는다)
func parse(fs *flag.FlagSet, args []string) string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		log.Fatal("주소가 필요하다")
	}
	fs.Parse(args[1:])
	return args[0]
}

// why는 오류를 시스템 콜 오류 이름 수준으로 줄인다
func why(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("%s (%s)", errno.Error(), errnoName(errno))
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "시간 초과"
	}
	return err.Error()
}

func errnoName(e syscall.Errno) string {
	switch e {
	case syscall.EPERM:
		return "EPERM"
	case syscall.ECONNREFUSED:
		return "ECONNREFUSED"
	}
	return fmt.Sprintf("errno %d", int(e))
}

func since(t time.Time) string {
	d := time.Since(t)
	if d < time.Millisecond {
		return d.Round(100 * time.Nanosecond).String()
	}
	return d.Round(10 * time.Millisecond).String()
}

func connect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	timeout := fs.Duration("timeout", 2*time.Second, "connect 제한 시간")
	addr := parse(fs, args)

	t := time.Now()
	c, err := net.DialTimeout("tcp4", addr, *timeout)
	if err != nil {
		fmt.Printf("TCP connect %-16s 실패: %s, %s\n", addr, why(err), since(t))
		return
	}
	el := since(t)
	defer c.Close()
	fmt.Fprintf(c, "hello from pid %d\n", os.Getpid())
	fmt.Printf("TCP connect %-16s 성공: 실제 연결된 상대 %s, %s\n", addr, c.RemoteAddr(), el)
}

func udp(args []string) {
	fs := flag.NewFlagSet("udp", flag.ExitOnError)
	connected := fs.Bool("connect", false, "connect() 후 send()로 보낸다")
	addr := parse(fs, args)
	ra, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	msg := []byte(fmt.Sprintf("hello from pid %d", os.Getpid()))
	how := "sendto"
	t := time.Now()
	if *connected {
		how = "connect+send"
		var c *net.UDPConn
		if c, err = net.DialUDP("udp4", nil, ra); err == nil {
			_, err = c.Write(msg)
			c.Close()
		}
	} else {
		var c *net.UDPConn
		if c, err = net.ListenUDP("udp4", nil); err == nil {
			_, err = c.WriteToUDP(msg, ra)
			c.Close()
		}
	}
	if err != nil {
		fmt.Printf("UDP %-12s %-16s 실패: %s, %s\n", how, addr, why(err), since(t))
		return
	}
	fmt.Printf("UDP %-12s %-16s 성공, %s\n", how, addr, since(t))
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	tcpPorts := fs.String("tcp", "8080,8081", "TCP 포트 목록")
	udpPorts := fs.String("udp", "9000", "UDP 포트 목록")
	fs.Parse(args)

	for _, p := range strings.Split(*tcpPorts, ",") {
		ln, err := net.Listen("tcp4", ":"+p)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetReadDeadline(time.Now().Add(time.Second))
					line, _ := bufio.NewReader(c).ReadString('\n')
					fmt.Printf("서버: TCP :%s ← %s  %q\n", p, c.RemoteAddr(), strings.TrimSpace(line))
				}()
			}
		}()
	}
	for _, p := range strings.Split(*udpPorts, ",") {
		pc, err := net.ListenPacket("udp4", ":"+p)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			buf := make([]byte, 512)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				fmt.Printf("서버: UDP :%s ← %s  %q\n", p, from, buf[:n])
			}
		}()
	}
	fmt.Println("ready")
	select {} // run.sh가 끝낼 때까지
}
