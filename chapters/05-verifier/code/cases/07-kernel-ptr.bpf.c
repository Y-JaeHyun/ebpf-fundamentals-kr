// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 07. 커널 포인터를 일반 C 포인터처럼 역참조
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} out SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int prog(struct trace_event_raw_sys_enter *ctx)
{
	u32 zero = 0, ppid;
	u32 *v;

#ifdef FIX
	// 방법 1: CO-RE 읽기 (bpf_probe_read_kernel + 재배치)
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	ppid = BPF_CORE_READ(t, real_parent, tgid);
	// 방법 2: BTF 포인터를 돌려주는 helper(5.11+) — verifier가 타입을 알아 직접 역참조 가능
	struct task_struct *bt = bpf_get_current_task_btf();
	ppid = bt->real_parent->tgid;
#else
	// bpf_get_current_task()는 u64(스칼라)를 돌려준다 — verifier는 이걸 포인터로 보지 않는다
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	ppid = t->real_parent->tgid;
#endif
	v = bpf_map_lookup_elem(&out, &zero);
	if (v)
		*v = ppid;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
