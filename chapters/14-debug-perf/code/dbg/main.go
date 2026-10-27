// SPDX-License-Identifier: MIT
// 14장 도구. 같은 시스템 콜(getppid)에 hook 종류만 바꿔 붙여 본다.
//
//	dbg bench [-n 1000000] [-rounds 5] [-cpu 1]   hook 종류별 시스템 콜 1회 비용 비교
//	dbg hold [-d 5s]                               fentry 하나를 붙여 두고 id를 출력(bpftool로 들여다보기용)
//	dbg printk                                      bpf_printk 프로그램을 붙이고 getppid 3번
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH dbg dbg.bpf.c -- -I../../../../include

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const target = "__do_sys_getppid"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("사용법: dbg bench|hold|printk [옵션]")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	spec, err := loadDbg()
	if err != nil {
		log.Fatal(err)
	}
	for name, v := range map[string]uint32{"target_tgid": uint32(os.Getpid()), "nr_getppid": unix.SYS_GETPPID} {
		if err := spec.Variables[name].Set(v); err != nil {
			log.Fatal(err)
		}
	}
	var objs dbgObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()

	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "bench":
		n := fs.Int("n", 1_000_000, "한 라운드의 getppid 호출 수")
		rounds := fs.Int("rounds", 5, "라운드 수(중앙값을 쓴다)")
		cpu := fs.Int("cpu", 1, "벤치마크 스레드를 고정할 CPU")
		fs.Parse(os.Args[2:])
		bench(&objs, *n, *rounds, *cpu)
	case "hold":
		d := fs.Duration("d", 5*time.Second, "붙여 둘 시간")
		fs.Parse(os.Args[2:])
		hold(&objs, *d)
	case "printk":
		fs.Parse(os.Args[2:])
		l, err := link.Tracepoint("syscalls", "sys_enter_getppid", objs.TpPrintk, nil)
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		for range 3 {
			getppid()
		}
		fmt.Printf("getppid 3번 호출, pid=%d\n", os.Getpid())
	default:
		log.Fatalf("알 수 없는 명령: %s", os.Args[1])
	}
}

func getppid() { syscall.RawSyscall(syscall.SYS_GETPPID, 0, 0, 0) }

func hits(m *ebpf.Map) uint64 {
	var per []uint64
	if err := m.Lookup(uint32(0), &per); err != nil {
		log.Fatal(err)
	}
	var s uint64
	for _, v := range per {
		s += v
	}
	return s
}

func hold(objs *dbgObjects, d time.Duration) {
	l, err := link.AttachTracing(link.TracingOptions{Program: objs.FeGetppid})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	// 실행 시간 통계(run_time_ns, run_cnt)를 켠다. 호스트의 모든 BPF 프로그램에 적용되므로 잠깐만 켠다.
	// 돌려받은 fd를 닫으면 꺼진다(sysctl kernel.bpf_stats_enabled를 바꾸지 않는다). 쌓인 값은 남는다
	st, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		log.Fatal(err)
	}
	for range 3 {
		getppid()
	}
	st.Close()
	pi, _ := objs.FeGetppid.Info()
	pid, _ := pi.ID()
	mi, _ := objs.Hits.Info()
	mid, _ := mi.ID()
	li, _ := l.Info()
	fmt.Printf("ready prog=%d map=%d link=%d\n", pid, mid, li.ID)
	time.Sleep(d)
}

type mode struct {
	name   string
	prog   *ebpf.Program
	attach func(*ebpf.Program) (link.Link, error)
	res    []float64 // 라운드별 ns/호출
}

// loop은 getppid를 n번 부르고 1회 평균 ns를 돌려준다
func loop(n int) float64 {
	t := time.Now()
	for range n {
		getppid()
	}
	return float64(time.Since(t).Nanoseconds()) / float64(n)
}

func median(v []float64) float64 {
	s := slices.Sorted(slices.Values(v))
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func bench(objs *dbgObjects, n, rounds, cpu int) {
	if n < 1 || rounds < 1 || cpu < 0 || cpu >= runtime.NumCPU() {
		log.Fatalf("-n ≥ 1, -rounds ≥ 1, 0 ≤ -cpu < %d 이어야 한다", runtime.NumCPU())
	}
	// 같은 CPU에서만 돌게 해 CPU 이동·캐시 차이로 인한 흔들림을 줄인다(다른 태스크·인터럽트까지 막지는 못한다)
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		log.Fatal(err)
	}

	// fentry+ringbuf 모드에서 이벤트를 비워 주는 소비자(같은 프로세스의 다른 스레드)
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()
	var consumed atomic.Uint64
	go func() {
		for {
			if _, err := rd.Read(); err != nil {
				return
			}
			consumed.Add(1)
		}
	}()

	tracing := func(p *ebpf.Program) (link.Link, error) { return link.AttachTracing(link.TracingOptions{Program: p}) }
	modes := []*mode{
		{name: "BPF 없음"},
		{name: "tracepoint sys_enter_getppid", prog: objs.TpGetppid, attach: func(p *ebpf.Program) (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_getppid", p, nil)
		}},
		{name: "raw_tp sys_enter(모든 시스템 콜)", prog: objs.RawtpSysEnter, attach: func(p *ebpf.Program) (link.Link, error) {
			return link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: p})
		}},
		{name: "kprobe " + target, prog: objs.KpGetppid, attach: func(p *ebpf.Program) (link.Link, error) { return link.Kprobe(target, p, nil) }},
		{name: "fentry " + target, prog: objs.FeGetppid, attach: tracing},
		{name: "fentry + ring buffer 전송", prog: objs.FeGetppidRingbuf, attach: tracing},
	}
	attach := func(m *mode) io.Closer {
		if m.prog == nil {
			return io.NopCloser(nil)
		}
		l, err := m.attach(m.prog)
		if err != nil {
			log.Fatalf("%s: %v", m.name, err)
		}
		return l
	}

	// 순서 편향(CPU 클럭 변화, 캐시 상태 등)을 줄이려고 라운드마다 모든 모드를 번갈아 돌린다
	loop(n / 10) // 예열
	calls := 0
	for range rounds {
		for _, m := range modes {
			l := attach(m)
			loop(n / 10) // 붙인 직후 예열
			m.res = append(m.res, loop(n))
			l.Close()
			if m.prog != nil {
				calls += n/10 + n
			}
		}
	}
	if got, want := hits(objs.Hits), uint64(calls); got != want {
		log.Fatalf("카운터 %d, 기대 %d — 호출을 다 보지 못했다", got, want)
	}

	// 프로그램 1회 실행 시간은 통계를 켜고 모드마다 한 라운드씩 따로 잰다.
	// 통계는 호스트의 모든 BPF 프로그램에 켜지고(실행마다 시각을 두 번 읽는다) 위의 ns/호출을 부풀리므로 이 구간에만 켠다
	type stat struct {
		cnt uint64
		ns  float64
	}
	stats := map[*mode]stat{}
	for _, m := range modes[1:] {
		l := attach(m)
		before, err := m.prog.Stats()
		if err != nil {
			log.Fatal(err)
		}
		st, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		if err != nil {
			log.Fatal(err)
		}
		loop(n)
		st.Close()
		l.Close()
		after, err := m.prog.Stats()
		if err != nil {
			log.Fatal(err)
		}
		cnt := after.RunCount - before.RunCount
		stats[m] = stat{cnt, float64((after.Runtime - before.Runtime).Nanoseconds()) / float64(cnt)}
		calls += n
	}

	fmt.Printf("getppid %d회 × %d라운드(모드를 번갈아), CPU %d 고정. ns/호출은 라운드 중앙값\n", n, rounds, cpu)
	fmt.Printf("%-34s %9s %9s %12s %13s\n", "hook", "ns/호출", "추가 ns", "BPF 실행 수*", "BPF 1회 평균*")
	base := median(modes[0].res)
	fmt.Printf("%-34s %9.1f %9s %12s %13s\n", modes[0].name, base, "-", "-", "-")
	for _, m := range modes[1:] {
		med := median(m.res)
		fmt.Printf("%-34s %9.1f %+9.1f %12d %10.1f ns\n", m.name, med, med-base, stats[m].cnt, stats[m].ns)
	}
	fmt.Println("* 통계를 켜고 모드마다 따로 돌린 한 라운드(getppid", n, "회) 동안의 값. 그 시간에 다른 프로세스가 같은 hook을 지난 실행도 포함된다")

	// 보낸(=submit) 이벤트를 소비자가 다 읽을 때까지 기다린다
	sent := uint64(rounds*(n/10+n) + n)
	dropped := hits(objs.Drops)
	for end := time.Now().Add(5 * time.Second); consumed.Load()+dropped < sent && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Printf("ring buffer: 보내려던 이벤트 %d, 받은 것 %d, 가득 차서 버린 것 %d\n", sent, consumed.Load(), dropped)
}
