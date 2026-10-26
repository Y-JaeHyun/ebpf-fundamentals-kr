// 07-2: execve 이벤트를 ring buffer에서 읽어 출력하고, 종료 시 per-CPU 통계를 합산해 보여 준다.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -target bpfel -type event execsnoop execsnoop.bpf.c -- -I../../../../include

func main() {
	duration := flag.Duration("d", 0, "실행 시간(예: 5s). 0이면 Ctrl-C까지")
	uid := flag.Int("uid", -1, "이 UID의 execve만 보기. -1이면 전체")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// loadExecsnoopObjects 대신 spec을 먼저 읽어 상수를 바꾼 뒤 로드한다.
	spec, err := loadExecsnoop()
	if err != nil {
		log.Fatalf("ELF 읽기 실패: %v", err)
	}
	if err := spec.Variables["filter_uid"].Set(uint32(*uid)); err != nil {
		log.Fatalf("filter_uid 설정 실패: %v", err)
	}
	var objs execsnoopObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("tracepoint attach 실패: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ring buffer reader 생성 실패: %v", err)
	}
	defer rd.Close()

	// 시그널이나 시간 만료 시: ① tracepoint를 떼어 새 이벤트를 막고
	// ② Flush로 버퍼에 남은 레코드를 마저 읽게 한다. 다 읽으면 Read()가 ringbuf.ErrFlushed를 돌려준다.
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
		tp.Close()
		rd.Flush()
	}()

	fmt.Printf("%-8s %-8s %-6s %-16s %s\n", "PID", "PPID", "UID", "COMM", "FILENAME")
	var ev execsnoopEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("읽기 실패: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			log.Printf("디코딩 실패: %v", err)
			continue
		}
		fmt.Printf("%-8d %-8d %-6d %-16s %s\n", ev.Pid, ev.Ppid, ev.Uid,
			cstr(ev.Comm[:]), cstr(ev.Filename[:]))
	}

	// tracepoint를 뗀 뒤라 통계가 더 이상 바뀌지 않는다 → 출력한 줄 수와 "전송"이 일치한다.
	printStats(&objs)
}

// printStats는 per-CPU 배열의 CPU별 값을 모두 더해 출력한다.
func printStats(objs *execsnoopObjects) {
	names := []string{"전송", "버림(ring buffer 가득 참)"}
	for i, name := range names {
		var perCPU []uint64
		if err := objs.Stats.Lookup(uint32(i), &perCPU); err != nil {
			log.Printf("통계 조회 실패: %v", err)
			return
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		fmt.Printf("%s: %d (CPU %d개 합산)\n", name, sum, len(perCPU))
	}
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
