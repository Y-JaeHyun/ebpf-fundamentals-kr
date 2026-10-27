// SPDX-License-Identifier: MIT
// 12장: LSM-BPF 로더. 지정한 파일 열기와 지정한 실행 파일 실행을 막고(또는 기록만 하고) 이벤트를 출력한다.
//
//	lsmguard -open /path/file -exec /path/bin [-audit] [-d 3s]
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH -type event lsmguard lsmguard.bpf.c -- -I../../../../include

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// fileID는 stat(2) 결과를 커널 내부 표현으로 바꾼다.
// 주의: 사용자 공간 st_dev와 커널 sb->s_dev는 장치 번호 인코딩이 다르다.
// 커널 내부 dev_t는 MKDEV(major, minor) = major<<20 | minor 이다.
func fileID(path string) (ino uint64, dev uint32) {
	if path == "" {
		return 0, 0
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	return st.Ino, unix.Major(st.Dev)<<20 | unix.Minor(st.Dev)
}

func main() {
	openPath := flag.String("open", "", "열기를 막을 파일")
	execPath := flag.String("exec", "", "실행을 막을 파일")
	audit := flag.Bool("audit", false, "막지 않고 기록만 한다")
	duration := flag.Duration("d", 0, "실행 시간. 0이면 Ctrl-C까지")
	allowInactive := flag.Bool("allow-inactive", false, "bpf LSM이 꺼져 있어도 실행한다(비교 실험용)")
	flag.Parse()

	// bpf가 LSM 목록에 없어도 로드·attach는 성공하지만 hook이 불리지 않아 아무것도 막지 못한다.
	// 정책이 적용된 것처럼 보이는 것이 가장 위험하므로 기본은 시작을 거부한다(fail closed).
	lsms, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		log.Fatalf("LSM 목록을 읽지 못했다: %v", err)
	}
	list := strings.TrimSpace(string(lsms))
	if !slices.Contains(strings.Split(list, ","), "bpf") {
		if !*allowInactive {
			log.Fatalf("LSM 목록(%s)에 bpf가 없다. attach는 되지만 정책이 적용되지 않으므로 시작하지 않는다 "+
				"(비교 실험이면 -allow-inactive)", list)
		}
		fmt.Fprintf(os.Stderr, "경고: LSM 목록(%s)에 bpf가 없다. -allow-inactive로 그대로 실행한다\n", list)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	spec, err := loadLsmguard()
	if err != nil {
		log.Fatal(err)
	}
	oIno, oDev := fileID(*openPath)
	eIno, eDev := fileID(*execPath)
	for name, v := range map[string]any{
		"deny_open_ino": oIno, "deny_open_dev": oDev,
		"deny_exec_ino": eIno, "deny_exec_dev": eDev,
		"enforce": !*audit,
	} {
		if err := spec.Variables[name].Set(v); err != nil {
			log.Fatalf("%s 설정 실패: %v", name, err)
		}
	}
	var objs lsmguardObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	var links []link.Link
	lo, err := link.AttachLSM(link.LSMOptions{Program: objs.GuardOpen})
	if err != nil {
		log.Fatalf("lsm/file_open attach 실패: %v", err)
	}
	links = append(links, lo)
	le, err := link.AttachLSM(link.LSMOptions{Program: objs.GuardExec})
	if err != nil {
		log.Fatalf("lsm/bprm_check_security attach 실패: %v", err)
	}
	links = append(links, le)

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

	mode := "enforce"
	if *audit {
		mode = "audit"
	}
	fmt.Printf("ready (%s)\n", mode)
	fmt.Printf("%-20s %-7s %-7s %-6s %-12s %s\n", "HOOK", "VERDICT", "PID", "UID", "COMM", "PATH")
	var e lsmguardEvent
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
		hook := map[uint32]string{1: "file_open", 2: "bprm_check_security"}[e.Hook]
		verdict := "ALLOW"
		if e.Verdict != 0 {
			verdict = "DENY"
		}
		fmt.Printf("%-20s %-7s %-7d %-6d %-12s %s\n", hook, verdict, e.Pid, e.Uid,
			unix.ByteSliceToString(e.Comm[:]), unix.ByteSliceToString(e.Path[:]))
	}
}
