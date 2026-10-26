// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 04. ring buffer에 자리를 예약하고, 어떤 경로에서는 submit/discard 없이 반환
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int prog(struct trace_event_raw_sys_enter *ctx)
{
	u64 *e = bpf_ringbuf_reserve(&rb, sizeof(u64), 0);

	if (!e)
		return 0;
	if (ctx->args[2] == 0) { // 0바이트 read는 기록하지 않으려 했다
#ifdef FIX
		bpf_ringbuf_discard(e, 0);
#endif
		return 0;
	}
	*e = ctx->args[2];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
