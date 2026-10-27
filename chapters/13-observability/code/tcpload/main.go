// SPDX-License-Identifier: MIT
// 13-2 실험용 TCP 송수신기(BPF 없음).
//
//	tcpload serve -addr :5000                  받은 만큼 버리고, 연결마다 받은 바이트 수를 출력
//	tcpload send 192.0.2.2:5000 -bytes 1048576 그만큼 보내고 걸린 시간을 출력
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("사용법: tcpload serve|send [옵션]")
	}
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := fs.String("addr", ":5000", "listen 주소")
		fs.Parse(os.Args[2:])
		serve(*addr)
	case "send":
		fs := flag.NewFlagSet("send", flag.ExitOnError)
		n := fs.Int64("bytes", 1<<20, "보낼 바이트 수")
		if len(os.Args) < 3 || strings.HasPrefix(os.Args[2], "-") {
			log.Fatal("주소가 필요하다")
		}
		fs.Parse(os.Args[3:])
		send(os.Args[2], *n)
	default:
		log.Fatalf("알 수 없는 명령: %s", os.Args[1])
	}
}

func serve(addr string) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ready")
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			n, _ := io.Copy(io.Discard, c)
			c.Close()
			fmt.Printf("서버: %s 에서 %d B 받음\n", c.RemoteAddr(), n)
		}()
	}
}

func send(addr string, n int64) {
	t := time.Now()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.CopyN(c, zero{}, n); err != nil {
		log.Fatal(err)
	}
	// 다 보냈다고 알리고(FIN), 서버가 다 읽고 닫을 때까지 기다린다 → 걸린 시간에 전송 완료까지 포함
	c.(*net.TCPConn).CloseWrite()
	io.Copy(io.Discard, c)
	c.Close()
	el := time.Since(t)
	fmt.Printf("클라이언트: %d B 보냄, %.2fs (%.1f Mbit/s)\n", n, el.Seconds(), float64(n)*8/el.Seconds()/1e6)
}

type zero struct{}

func (zero) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
