// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 06. 컨텍스트(ctx)에 쓰기 — tracepoint 컨텍스트는 읽기 전용이다
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} out SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int prog(struct trace_event_raw_sys_enter *ctx)
{
	u32 zero = 0;
	u64 *v, count;

#ifdef FIX
	count = ctx->args[2];
	if (count > 4096)
		count = 4096; // 지역 변수에서 가공한다
#else
	if (ctx->args[2] > 4096)
		ctx->args[2] = 4096; // "읽는 양을 줄여 볼까?" — 불가능
	count = ctx->args[2];
#endif
	v = bpf_map_lookup_elem(&out, &zero);
	if (v)
		*v += count;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
