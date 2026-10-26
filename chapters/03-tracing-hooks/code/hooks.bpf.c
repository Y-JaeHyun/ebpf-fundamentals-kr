// SPDX-License-Identifier: (MIT OR GPL-2.0)
//go:build ignore
// (위 줄은 go build가 이 C 파일을 cgo 소스로 오해하지 않게 한다)
//
// 03장: 같은 일(read 한 번)을 서로 다른 tracing hook 9가지로 관측한다.
// 모든 프로그램은 bench 프로세스(target_tgid)만 세고, 결과는 per-CPU 배열의 자기 칸에 쌓는다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Go 쪽 hookbench의 순서와 같아야 한다.
enum hook {
	H_KPROBE,
	H_KRETPROBE,
	H_FENTRY,
	H_FEXIT,
	H_TRACEPOINT,
	H_RAW_TP,
	H_TP_BTF,
	H_UPROBE,
	H_URETPROBE,
	H_MAX,
};

struct counter {
	u64 hits;
	u64 sum; // 진입 hook: 요청한 바이트 수 합, 반환 hook: 돌려준 바이트 수 합
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, H_MAX);
	__type(key, u32);
	__type(value, struct counter);
} counters SEC(".maps");

const volatile u32 target_tgid = 0;

static __always_inline void record(u32 idx, u64 val)
{
	struct counter *c;

	if ((bpf_get_current_pid_tgid() >> 32) != target_tgid)
		return;
	c = bpf_map_lookup_elem(&counters, &idx);
	if (c) {
		c->hits++;
		c->sum += val;
	}
}

// ① kprobe: 커널 함수 진입. 인자는 레지스터(pt_regs)에서 꺼낸다 → BPF_KPROBE 매크로가 대신 해 준다.
SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read, struct file *file, char *buf, size_t count)
{
	record(H_KPROBE, count);
	return 0;
}

// ② kretprobe: 커널 함수 반환. 반환값만 볼 수 있고 인자는 볼 수 없다.
SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(kretprobe_vfs_read, ssize_t ret)
{
	record(H_KRETPROBE, ret > 0 ? ret : 0);
	return 0;
}

// ③ fentry: BTF 기반 trampoline. 인자를 타입 그대로 받고, 커널 포인터를 바로 역참조할 수 있다.
SEC("fentry/vfs_read")
int BPF_PROG(fentry_vfs_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
	record(H_FENTRY, count);
	return 0;
}

// ④ fexit: 반환 시점에 인자와 반환값을 "둘 다" 본다.
SEC("fexit/vfs_read")
int BPF_PROG(fexit_vfs_read, struct file *file, char *buf, size_t count, loff_t *pos, ssize_t ret)
{
	record(H_FEXIT, ret > 0 ? ret : 0);
	return 0;
}

// ⑤ tracepoint: 정적 지점. 컨텍스트는 tracefs format 파일에 정의된 구조체.
SEC("tracepoint/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	record(H_TRACEPOINT, ctx->args[2]);
	return 0;
}

// ⑥ raw tracepoint: 같은 지점(sys_enter)이지만 가공 전 인자(pt_regs*, id)를 받는다. 모든 시스템 콜에서 불린다.
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	long id = ctx->args[1];

	if (id != 0) // x86_64의 __NR_read
		return 0;
	record(H_RAW_TP, PT_REGS_PARM3_CORE_SYSCALL(regs));
	return 0;
}

// ⑦ tp_btf: raw tracepoint + BTF. 인자를 타입 그대로 받아 BPF_CORE_READ 없이 읽는다.
SEC("tp_btf/sys_enter")
int BPF_PROG(tp_btf_sys_enter, struct pt_regs *regs, long id)
{
	if (id != 0)
		return 0;
	record(H_TP_BTF, PT_REGS_PARM3_CORE_SYSCALL(regs));
	return 0;
}

// ⑧ uprobe: 사용자 공간 함수(bench의 do_read) 진입. attach 대상은 Go 쪽에서 정한다.
SEC("uprobe")
int BPF_UPROBE(uprobe_do_read, int fd, char *buf, size_t n)
{
	record(H_UPROBE, n);
	return 0;
}

// ⑨ uretprobe: 사용자 공간 함수 반환.
SEC("uretprobe")
int BPF_URETPROBE(uretprobe_do_read, long ret)
{
	record(H_URETPROBE, ret > 0 ? ret : 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
