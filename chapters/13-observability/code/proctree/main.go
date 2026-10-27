// SPDX-License-Identifier: MIT
// 13-1: 명령 하나를 실행하고, 그 명령과 자손 프로세스의 fork/exec/exit를 시간순으로 출력한 뒤 트리로 정리한다.
//
//	proctree [-wait 5s] -- sh -c 'ls | wc -l'
package main

//go:generate go tool bpf2go -tags linux -target $GOARCH -type event proctree proctree.bpf.c -- -I../../../../include

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type proc struct {
	pid, ppid        uint32
	name             string // 마지막 exec 파일(없으면 comm)
	start, end       uint64
	exitCode         int32
	exited, hasStart bool
	children         []uint32
}

func main() {
	wait := flag.Duration("wait", 5*time.Second, "명령이 끝난 뒤 남은 자손을 기다릴 최대 시간")
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("사용법: proctree -- 명령 [인자...]")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var objs proctreeObjects
	if err := loadProctreeObjects(&objs, nil); err != nil {
		log.Fatalf("로드 실패: %v", err)
	}
	defer objs.Close()
	for _, p := range []*ebpf.Program{objs.OnFork, objs.OnExec, objs.OnExit} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	// 시작 게이트: 셸이 한 줄을 읽을 때까지 멈춰 있게 해 두고, 그 pid를 추적 목록에 넣은 다음 문을 연다.
	// 그냥 실행하면 pid를 map에 넣기 전에 자식이 먼저 fork해 버려 놓칠 수 있다.
	cmd := exec.Command("sh", append([]string{"-c", `read _ && exec "$@"`, "sh"}, flag.Args()...)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	gate, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	root := uint32(cmd.Process.Pid)
	if err := objs.Tracked.Put(root, uint8(1)); err != nil {
		log.Fatal(err)
	}
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) // bpf_ktime_get_ns()와 같은 시계
	t0 := uint64(ts.Nano())
	procs := map[uint32]*proc{root: {pid: root, name: "sh(게이트)", start: t0, hasStart: true}}
	gate.Write([]byte("\n"))
	gate.Close()

	go func() {
		cmd.Wait()
		// 시작한 명령이 끝나도 백그라운드로 남은 자손이 있을 수 있다. 추적 목록이 빌 때까지(최대 -wait) 기다린다
		for end := time.Now().Add(*wait); time.Now().Before(end) && tracking(objs.Tracked); {
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond) // 남은 이벤트가 ring buffer에서 읽힐 시간
		rd.Close()
	}()

	fmt.Printf("ready: 시작 pid %d\n", root)
	var e proctreeEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Fatal(err)
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &e); err != nil {
			log.Fatal(err)
		}
		comm := unix.ByteSliceToString(e.Comm[:])
		at := fmt.Sprintf("+%7.3fms", float64(e.Ts-t0)/1e6)
		p := procs[e.Pid]
		switch e.Type {
		case 1: // fork
			p = &proc{pid: e.Pid, ppid: e.Ppid, name: comm, start: e.Ts, hasStart: true}
			procs[e.Pid] = p
			if pp := procs[e.Ppid]; pp != nil {
				pp.children = append(pp.children, e.Pid)
			}
			fmt.Printf("%s  fork  %6d → %-6d %s\n", at, e.Ppid, e.Pid, comm)
		case 2: // exec
			f := unix.ByteSliceToString(e.Filename[:])
			if p != nil {
				p.name = f
			}
			fmt.Printf("%s  exec  %6d   %s\n", at, e.Pid, f)
		case 3: // exit
			if p != nil {
				p.exited, p.exitCode, p.end = true, e.ExitCode, e.Ts
			}
			fmt.Printf("%s  exit  %6d   %s\n", at, e.Pid, codeStr(e.ExitCode))
		}
	}

	fmt.Println("--- 트리 (pid 이름 [종료 상태, 살아 있던 시간])")
	printTree(procs, root, "", "")
}

// tracking은 추적 목록에 아직 살아 있는 프로세스가 있는지 본다(종료하면 BPF가 지운다)
func tracking(m *ebpf.Map) bool {
	var k uint32
	var v uint8
	return m.Iterate().Next(&k, &v)
}

func codeStr(c int32) string {
	if c < 0 {
		return fmt.Sprintf("시그널 %d(%s)로 끝남", -c, unix.SignalName(unix.Signal(-c)))
	}
	return fmt.Sprintf("종료 코드 %d", c)
}

func printTree(procs map[uint32]*proc, pid uint32, prefix, branch string) {
	p := procs[pid]
	state := "아직 실행 중"
	if p.exited {
		state = fmt.Sprintf("%s, %.1fms", codeStr(p.exitCode), float64(p.end-p.start)/1e6)
	}
	fmt.Printf("%s%s%d %s [%s]\n", prefix, branch, pid, p.name, state)
	kids := p.children
	sort.Slice(kids, func(i, j int) bool { return procs[kids[i]].start < procs[kids[j]].start })
	next := prefix
	switch branch {
	case "├─ ":
		next += "│  "
	case "└─ ":
		next += "   "
	}
	for i, k := range kids {
		b := "├─ "
		if i == len(kids)-1 {
			b = "└─ "
		}
		printTree(procs, k, next, b)
	}
}
