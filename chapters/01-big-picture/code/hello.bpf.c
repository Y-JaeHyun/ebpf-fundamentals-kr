// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 01장 예제: execve 시스템 콜이 불릴 때마다
//   1) UID별 호출 횟수를 hash map에 누적하고
//   2) bpf_printk로 trace_pipe에 한 줄을 남긴다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);   // uid
	__type(value, u64); // execve 호출 횟수
} exec_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int count_execve(struct trace_event_raw_sys_enter *ctx)
{
	u32 uid = (u32)bpf_get_current_uid_gid();
	u64 one = 1, *cnt;
	char comm[16];

	cnt = bpf_map_lookup_elem(&exec_count, &uid);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
	else
		bpf_map_update_elem(&exec_count, &uid, &one, BPF_NOEXIST);

	bpf_get_current_comm(comm, sizeof(comm));
	bpf_printk("execve by uid=%d comm=%s", uid, comm);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
