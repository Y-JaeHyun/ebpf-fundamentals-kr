// 07-1: bpf2go가 만든 코드로 BPF 프로그램을 로드하고 kprobe에 붙인 뒤,
// 1초마다 map 값을 읽어 출력한다.
package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -target bpfel counter counter.bpf.c -- -I../../../../include

func main() {
	seconds := flag.Int("n", 5, "출력 횟수(초). 0이면 Ctrl-C까지")
	flag.Parse()

	// 5.11 미만 커널은 map 메모리를 RLIMIT_MEMLOCK으로 계산하므로 제한을 푼다(이후 커널에선 아무 일도 안 함).
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// ELF에서 프로그램과 map을 읽어 커널에 로드한다. verifier 거부도 여기서 에러로 돌아온다.
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("vfs_read", objs.CountVfsRead, nil)
	if err != nil {
		log.Fatalf("kprobe attach 실패: %v", err)
	}
	defer kp.Close() // 프로세스가 끝나면 link가 닫히고 프로그램도 떨어진다

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	var prev uint64
	for i := 1; *seconds == 0 || i <= *seconds; i++ {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		var total uint64
		if err := objs.Calls.Lookup(uint32(0), &total); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			log.Fatalf("map 조회 실패: %v", err)
		}
		log.Printf("vfs_read 누적 %d회 (+%d/s)", total, total-prev)
		prev = total
	}
}
