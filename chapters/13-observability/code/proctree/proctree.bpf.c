//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 13-1: 프로세스 트리 추적 — 지정한 pid와 그 자손의 fork/exec/exit만 골라 사용자 공간에 알린다.
// 자손 판정은 커널 안에서 한다: fork 때 부모가 추적 중이면 자식도 추적 목록에 넣는다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

enum { EV_FORK = 1, EV_EXEC = 2, EV_EXIT = 3 };

struct event {
	__u64 ts;
	__u32 pid, ppid;
	__s32 exit_code; // EV_EXIT: 종료 코드(정상 종료면 0~255, 시그널이면 -시그널번호)
	__u8 type;
	__u8 pad[3];
	__u8 comm[16];
	__u8 filename[64]; // EV_EXEC: 실행한 파일
};
const struct event *unused_event __attribute__((unused)); // bpf2go -type가 찾도록 BTF에 남긴다

// 추적 중인 프로세스(tgid) → 1. 사용자 공간이 시작 pid 하나를 넣는다
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tracked SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline struct event *reserve(__u8 type, struct task_struct *t)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = bpf_ktime_get_ns();
	e->type = type;
	e->pid = BPF_CORE_READ(t, tgid);
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	BPF_CORE_READ_STR_INTO(&e->comm, t, comm);
	return e;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 ppid = parent->tgid, pid = child->pid;
	__u8 one = 1;

	// 스레드 생성(CLONE_THREAD)도 이 tracepoint를 지난다. 새 프로세스(pid == tgid)만 본다
	if (pid != child->tgid || !bpf_map_lookup_elem(&tracked, &ppid))
		return 0;
	bpf_map_update_elem(&tracked, &pid, &one, BPF_ANY);

	struct event *e = reserve(EV_FORK, child);
	if (e)
		bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 pid = p->tgid;

	if (!bpf_map_lookup_elem(&tracked, &pid))
		return 0;
	struct event *e = reserve(EV_EXEC, p); // comm은 이미 새 프로그램 이름으로 바뀌어 있다
	if (!e)
		return 0;
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p, bool group_dead)
{
	__u32 pid = p->tgid;

	// 스레드마다 불린다. 스레드 그룹의 마지막(group_dead)만 프로세스 종료로 친다
	if (!group_dead || !bpf_map_lookup_elem(&tracked, &pid))
		return 0;
	bpf_map_delete_elem(&tracked, &pid);

	struct event *e = reserve(EV_EXIT, p);
	if (!e)
		return 0;
	int code = BPF_CORE_READ(p, exit_code);
	e->exit_code = (code & 0x7f) ? -(code & 0x7f) : (code >> 8) & 0xff;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
