// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 02. 사용자 공간에서 온 값(시스템 콜 인자)을 범위 검사 없이 배열 인덱스로 사용
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct slots {
	u64 v[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct slots);
} hist SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int prog(struct trace_event_raw_sys_enter *ctx)
{
	u32 zero = 0;
	u64 idx = ctx->args[2]; // read()의 count — 어떤 값이든 올 수 있다
	struct slots *s = bpf_map_lookup_elem(&hist, &zero);

	if (!s)
		return 0;
#ifdef FIX
	if (idx >= 16)
		return 0;
#endif
	s->v[idx] += 1;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
