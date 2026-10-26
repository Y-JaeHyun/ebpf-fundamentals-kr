// 04-2: 전달 방식별로 bench를 여러 라운드 돌려, 받은 이벤트·유실·bench 속도·소비자 CPU 시간을 비교한다.
// ring buffer와 perf buffer는 전체 메모리가 같도록(perf: CPU당 X, ring: X × CPU 수) 맞춘다.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/bits"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -target $GOARCH -type event transfer transfer.bpf.c -- -I../../../../include

var delay time.Duration

// work는 느린 소비자를 흉내 낸다(잠들지 않고 CPU를 쓰며 기다린다).
func work() {
	if delay == 0 {
		return
	}
	for t := time.Now(); time.Since(t) < delay; {
	}
}

var modes = []string{"집계(map)", "ringbuf reserve", "ringbuf output", "perf buffer"}

func main() {
	n := flag.Int("n", 500_000, "bench의 read 횟수")
	perCPUKB := flag.Int("kb", 64, "perf buffer의 CPU당 크기(KB). ring buffer는 이 값 × CPU 수")
	rounds := flag.Int("r", 5, "라운드 수. 라운드마다 무작위 순서로 (기준 → 방식) 쌍을 잰다")
	cpu := flag.Int("cpu", 2, "bench를 고정할 CPU 번호 (-1이면 고정 안 함)")
	bench := flag.String("bench", "bin/bench", "bench 실행 파일")
	flag.DurationVar(&delay, "delay", 0, "레코드 하나를 받을 때마다 소비자가 일부러 쓰는 시간(느린 소비자 흉내)")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	benchPath, _ := filepath.Abs(*bench)
	benchEnv = os.Environ()
	if *cpu >= 0 {
		benchEnv = append(benchEnv, fmt.Sprintf("cpu=%d", *cpu))
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		log.Fatal(err)
	}
	perCPU := *perCPUKB * 1024
	ringSize := 1 << bits.Len(uint(perCPU*ncpu-1)) // 2의 거듭제곱으로 올림
	fmt.Printf("CPU %d개, perf buffer %dKB×%d, ring buffer %dKB, 이벤트 64B, read %d회, bench CPU %d 고정, 소비자 지연 %v\n",
		ncpu, *perCPUKB, ncpu, ringSize/1024, *n, *cpu, delay)
	fmt.Printf("%d라운드(라운드마다 무작위 순서, 매번 기준값과 짝지어 측정), 값은 중앙값\n\n", *rounds)

	// 같은 라운드 안에서 "아무것도 안 붙인 bench"와 바로 이어서 재고 그 차이를 쓴다.
	all := map[int][]result{}
	for range *rounds {
		for _, mode := range rand.Perm(len(modes)) {
			base, err := run(benchPath, noAttach, *n, perCPU, ringSize)
			if err != nil {
				log.Fatalf("기준: %v", err)
			}
			r, err := run(benchPath, mode, *n, perCPU, ringSize)
			if err != nil {
				log.Fatalf("%s: %v", modes[mode], err)
			}
			r.extra = (r.nsPerRead - base.nsPerRead) * float64(*n) / float64(r.kernel)
			all[mode] = append(all[mode], r)
		}
	}

	fmt.Printf("%-16s %10s %10s %10s %10s %10s %12s\n", "방식", "커널 이벤트", "받은 수", "유실", "ns/read", "+ns/event", "소비자 CPU")
	for mode := range modes {
		rs := all[mode]
		med := func(f func(result) float64) float64 {
			v := make([]float64, len(rs))
			for i, r := range rs {
				v[i] = f(r)
			}
			slices.Sort(v)
			if len(v)%2 == 1 {
				return v[len(v)/2]
			}
			return (v[len(v)/2-1] + v[len(v)/2]) / 2
		}
		recv := fmt.Sprintf("%.0f", med(func(r result) float64 { return float64(r.received) }))
		if mode == 0 {
			recv = "-"
		}
		fmt.Printf("%-16s %10.0f %10s %10.0f %10.1f %10.1f %12s\n", modes[mode],
			med(func(r result) float64 { return float64(r.kernel) }), recv,
			med(func(r result) float64 { return float64(r.lost) }),
			med(func(r result) float64 { return r.nsPerRead }),
			med(func(r result) float64 { return r.extra }),
			time.Duration(med(func(r result) float64 { return float64(r.consumerCPU) })).Round(time.Millisecond))
	}
}

// noAttach는 BPF를 로드만 하고 attach하지 않는 기준 측정이다.
const noAttach = -1

var benchEnv []string

type result struct {
	kernel, received, lost uint64
	nsPerRead, extra       float64
	consumerCPU            time.Duration
}

func run(benchPath string, mode, n, perCPU, ringSize int) (result, error) {
	var res result
	cmd := exec.Command(benchPath, strconv.Itoa(n))
	cmd.Env = benchEnv
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return res, err
	}
	defer cmd.Wait()
	defer stdin.Close()

	spec, err := loadTransfer()
	if err != nil {
		return res, err
	}
	spec.Maps["rb"].MaxEntries = uint32(ringSize)
	spec.Variables["target_tgid"].Set(uint32(cmd.Process.Pid))
	spec.Variables["mode"].Set(uint32(max(mode, 0)))
	var objs transferObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return res, fmt.Errorf("로드: %w", err)
	}
	defer objs.Close()

	// 소비자: 모드에 맞는 reader로 이벤트를 세기만 한다(디코딩 비용은 빼고 전달 비용만 본다)
	var wg sync.WaitGroup
	var stop func()
	switch mode {
	case 1, 2:
		rd, err := ringbuf.NewReader(objs.Rb)
		if err != nil {
			return res, err
		}
		defer rd.Close()
		stop = func() { rd.Flush() }
		wg.Add(1)
		go func() {
			defer wg.Done()
			var rec ringbuf.Record
			for {
				if err := rd.ReadInto(&rec); err != nil {
					if errors.Is(err, ringbuf.ErrFlushed) || errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}
				res.received++
				work()
			}
		}()
	case 3:
		rd, err := perf.NewReader(objs.Pb, perCPU)
		if err != nil {
			return res, err
		}
		defer rd.Close()
		stop = func() { rd.Flush() }
		wg.Add(1)
		go func() {
			defer wg.Done()
			var rec perf.Record
			for {
				if err := rd.ReadInto(&rec); err != nil {
					if errors.Is(err, perf.ErrFlushed) || errors.Is(err, perf.ErrClosed) {
						return
					}
					continue
				}
				if rec.LostSamples > 0 { // 커널이 알려 주는 유실 레코드
					continue
				}
				res.received++
				work()
			}
		}()
	}

	var tp link.Link
	if mode != noAttach {
		tp, err = link.Tracepoint("syscalls", "sys_enter_read", objs.OnRead, nil)
		if err != nil {
			return res, err
		}
	}

	before := cpuTime()
	io.WriteString(stdin, "go\n")
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		return res, fmt.Errorf("bench 출력 읽기: %w", err)
	}
	res.nsPerRead, _ = strconv.ParseFloat(strings.TrimSpace(line), 64)

	if tp != nil {
		tp.Close() // 더 이상 이벤트를 만들지 않게 떼고
	}
	if stop != nil {
		stop() // 남은 레코드를 마저 읽게 한 뒤
		wg.Wait()
	}
	res.consumerCPU = cpuTime() - before

	for i, dst := range []*uint64{&res.kernel, &res.lost} {
		var perCPUVals []uint64
		if err := objs.Stats.Lookup(uint32(i), &perCPUVals); err != nil {
			return res, err
		}
		for _, v := range perCPUVals {
			*dst += v
		}
	}
	return res, nil
}

// cpuTime은 이 프로세스(소비자 고루틴 포함)가 쓴 user+sys CPU 시간이다.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
