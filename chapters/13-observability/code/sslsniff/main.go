// SPDX-License-Identifier: MIT
// 13-3: libssl의 SSL_read/SSL_write(+_ex)에 uprobe를 붙여 TLS 평문을 출력한다.
// 지정한 network namespace 안의 프로세스만 본다(호스트의 다른 TLS 통신은 보지 않는다).
//
//	sslsniff -lib /usr/lib/x86_64-linux-gnu/libssl.so.3[,다른 libssl] -netns /run/netns/a,/run/netns/b [-d 5s]
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH -type event sslsniff sslsniff.bpf.c -- -I../../../../include

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
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
	libs := flag.String("lib", "", "libssl 경로, 여럿이면 쉼표로 구분 (예: /usr/lib/x86_64-linux-gnu/libssl.so.3)")
	nsList := flag.String("netns", "", "볼 network namespace 파일들, 쉼표로 구분 (필수)")
	duration := flag.Duration("d", 0, "실행 시간. 0이면 Ctrl-C까지")
	flag.Parse()
	if *libs == "" || *nsList == "" {
		log.Fatal("-lib와 -netns가 필요하다")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var objs sslsniffObjects
	if err := loadSslsniffObjects(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()
	for _, p := range strings.Split(*nsList, ",") {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			log.Fatal(err)
		}
		if err := objs.NetnsAllow.Put(uint32(st.Ino), uint8(1)); err != nil {
			log.Fatal(err)
		}
	}

	for _, lib := range strings.Split(*libs, ",") {
		ex, err := link.OpenExecutable(lib)
		if err != nil {
			log.Fatal(err)
		}
		n := 0
		for sym, prog := range map[string]*ebpf.Program{
			"SSL_read": objs.SslRead, "SSL_write": objs.SslWrite,
			"SSL_read_ex": objs.SslReadEx, "SSL_write_ex": objs.SslWriteEx, // _ex는 OpenSSL 1.1.1부터
		} {
			up, err := ex.Uprobe(sym, prog, nil)
			if errors.Is(err, link.ErrNoSymbol) {
				log.Printf("%s 에 %s 없음, 건너뜀", lib, sym)
				continue
			} else if err != nil {
				log.Fatalf("uprobe %s: %v", sym, err)
			}
			defer up.Close()
			ret, err := ex.Uretprobe(sym, objs.SslRet, nil)
			if err != nil {
				log.Fatalf("uretprobe %s: %v", sym, err)
			}
			defer ret.Close()
			n++
		}
		if n == 0 {
			log.Fatalf("%s 에서 SSL_read/SSL_write를 찾지 못했다", lib)
		}
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

	fmt.Printf("ready: %s 의 SSL_read/SSL_write(+_ex)에 uprobe\n", *libs)
	funcs := map[uint8]string{1: "SSL_read", 2: "SSL_write", 3: "SSL_read_ex", 4: "SSL_write_ex"}
	var e sslsniffEvent
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
		fmt.Printf("--- %s %d %-12s %d B", unix.ByteSliceToString(e.Comm[:]), e.Pid, funcs[e.Func], e.Len)
		if e.Copied < e.Len {
			fmt.Printf(" (앞 %d B만)", e.Copied)
		}
		fmt.Println()
		for _, line := range strings.SplitAfter(string(e.Data[:e.Copied]), "\n") {
			if line != "" {
				fmt.Println("    " + strings.Trim(strconv.Quote(line), `"`))
			}
		}
	}
}
