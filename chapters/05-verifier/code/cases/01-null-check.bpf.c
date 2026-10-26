// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 01. map lookup 결과를 NULL 검사 없이 사용
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u32);
	__type(value, u64);
} cnt SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int prog(struct trace_event_raw_sys_enter *ctx)
{
	u32 key = bpf_get_current_pid_tgid() >> 32;
	u64 *v = bpf_map_lookup_elem(&cnt, &key);

#ifdef FIX
	if (!v)
		return 0;
#endif
	*v += 1;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
