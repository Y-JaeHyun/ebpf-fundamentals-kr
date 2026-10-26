// 03장: hook 하나만 attach한 상태로 bench를 실행해 이벤트 수와 read 한 번당 시간을 잰다.
// 같은 라운드에서 잰 기준값(hook 없음)과 짝지어 비교해, hook마다 이벤트 한 번의 추가 비용을 추정한다.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -target $GOARCH -type counter hooks ../hooks.bpf.c -- -I../../../../include

// hooks.bpf.c의 enum hook 순서와 같다.
var hookNames = []string{
	"kprobe", "kretprobe", "fentry", "fexit",
	"tracepoint", "raw_tp", "tp_btf", "uprobe", "uretprobe",
}

func main() {
	which := flag.String("hook", "all", "all 또는 "+strings.Join(hookNames, ","))
	n := flag.Int("n", 500_000, "bench가 read()를 부르는 횟수")
	rounds := flag.Int("r", 5, "라운드 수. 라운드마다 무작위 순서로 (기준 → hook) 쌍을 잰다")
	cpu := flag.Int("cpu", 2, "bench를 고정할 CPU 번호 (-1이면 고정 안 함)")
	bench := flag.String("bench", "bin/bench", "bench 실행 파일")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	benchPath, err := filepath.Abs(*bench)
	if err != nil {
		log.Fatal(err)
	}
	env := os.Environ()
	if *cpu >= 0 {
		env = append(env, fmt.Sprintf("cpu=%d", *cpu))
	}

	targets := hookNames
	if *which != "all" {
		targets = strings.Split(*which, ",")
	}

	// 같은 라운드 안에서 기준값과 hook 값을 바로 이어서 재고 그 차이를 쓴다(짝 비교).
	// CPU 주파수·캐시 상태처럼 시간에 따라 변하는 요인이 차이에서 상쇄되도록.
	type sample struct{ base, hooked, extra float64 }
	samples := map[string][]sample{}
	events := map[string]uint64{}
	for range *rounds {
		order := slices.Clone(targets)
		rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, h := range order {
			base, _, err := measure(benchPath, env, "none", *n)
			if err != nil {
				log.Fatalf("none: %v", err)
			}
			hooked, c, err := measure(benchPath, env, h, *n)
			if err != nil {
				log.Fatalf("%s: %v", h, err)
			}
			if c.Hits == 0 {
				log.Fatalf("%s: 이벤트가 0건", h)
			}
			// read 한 번에 이벤트가 여러 번 날 수 있으므로 이벤트 수로 나눈다
			extra := (hooked - base) * float64(*n) / float64(c.Hits)
			samples[h] = append(samples[h], sample{base, hooked, extra})
			events[h] = c.Hits
		}
	}

	fmt.Printf("bench: read(/dev/zero,1) %d회, CPU %d 고정, %d라운드(라운드마다 무작위 순서), 값은 중앙값\n\n", *n, *cpu, *rounds)
	fmt.Printf("%-11s %9s %10s %10s %11s %17s\n", "HOOK", "EVENTS", "기준 ns", "hook ns", "+ns/event", "+ns/event 범위")
	for _, h := range targets {
		ss := samples[h]
		col := func(f func(sample) float64) []float64 {
			out := make([]float64, len(ss))
			for i, x := range ss {
				out[i] = f(x)
			}
			slices.Sort(out)
			return out
		}
		base := col(func(x sample) float64 { return x.base })
		hooked := col(func(x sample) float64 { return x.hooked })
		extra := col(func(x sample) float64 { return x.extra })
		fmt.Printf("%-11s %9d %10.1f %10.1f %11.1f %8.1f ~ %6.1f\n", h, events[h],
			median(base), median(hooked), median(extra), extra[0], extra[len(extra)-1])
	}
}

func median(sorted []float64) float64 {
	m := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[m]
	}
	return (sorted[m-1] + sorted[m]) / 2
}

// measure는 bench를 띄우고, 그 PID로 상수를 채워 로드한 뒤 hook 하나를 attach하고,
// bench에 시작 신호를 보내 결과(ns/read)와 해당 hook의 카운터를 돌려준다.
func measure(benchPath string, env []string, hook string, n int) (float64, hooksCounter, error) {
	var zero hooksCounter
	cmd := exec.Command(benchPath, strconv.Itoa(n))
	cmd.Env = env
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, zero, err
	}
	defer cmd.Wait()
	defer stdin.Close()

	spec, err := loadHooks()
	if err != nil {
		return 0, zero, err
	}
	if err := spec.Variables["target_tgid"].Set(uint32(cmd.Process.Pid)); err != nil {
		return 0, zero, err
	}
	var objs hooksObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return 0, zero, fmt.Errorf("로드: %w", err)
	}
	defer objs.Close()

	if hook != "none" {
		l, err := attach(&objs, hook, benchPath)
		if err != nil {
			return 0, zero, fmt.Errorf("attach: %w", err)
		}
		defer l.Close()
	}

	io.WriteString(stdin, "go\n")
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		return 0, zero, fmt.Errorf("bench 출력 읽기: %w", err)
	}
	ns, err := strconv.ParseFloat(strings.TrimSpace(line), 64)
	if err != nil {
		return 0, zero, err
	}

	idx := slices.Index(hookNames, hook)
	if idx < 0 {
		return ns, zero, nil
	}
	var perCPU []hooksCounter
	if err := objs.Counters.Lookup(uint32(idx), &perCPU); err != nil {
		return 0, zero, err
	}
	var total hooksCounter
	for _, v := range perCPU {
		total.Hits += v.Hits
		total.Sum += v.Sum
	}
	return ns, total, nil
}

func attach(objs *hooksObjects, hook, benchPath string) (link.Link, error) {
	switch hook {
	case "kprobe":
		return link.Kprobe("vfs_read", objs.KprobeVfsRead, nil)
	case "kretprobe":
		return link.Kretprobe("vfs_read", objs.KretprobeVfsRead, nil)
	case "fentry":
		return link.AttachTracing(link.TracingOptions{Program: objs.FentryVfsRead})
	case "fexit":
		return link.AttachTracing(link.TracingOptions{Program: objs.FexitVfsRead})
	case "tracepoint":
		return link.Tracepoint("syscalls", "sys_enter_read", objs.TpSysEnterRead, nil)
	case "raw_tp":
		return link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: objs.RawTpSysEnter})
	case "tp_btf":
		return link.AttachTracing(link.TracingOptions{Program: objs.TpBtfSysEnter})
	case "uprobe", "uretprobe":
		ex, err := link.OpenExecutable(benchPath)
		if err != nil {
			return nil, err
		}
		if hook == "uprobe" {
			return ex.Uprobe("do_read", objs.UprobeDoRead, nil)
		}
		return ex.Uretprobe("do_read", objs.UretprobeDoRead, nil)
	}
	return nil, fmt.Errorf("알 수 없는 hook %q", hook)
}
