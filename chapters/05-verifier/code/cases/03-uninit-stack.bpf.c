// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 03. 일부만 채운 스택 구조체(패딩 포함)를 통째로 helper에 넘김
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
	u32 pid;
	// 여기 4바이트 패딩이 생긴다 (다음 필드가 8바이트 정렬)
	u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int prog(struct trace_event_raw_sys_enter *ctx)
{
#ifdef FIX
	struct event e = {};
#else
	struct event e;
#endif
	e.pid = bpf_get_current_pid_tgid() >> 32;
	e.ts = bpf_ktime_get_ns();
	bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
