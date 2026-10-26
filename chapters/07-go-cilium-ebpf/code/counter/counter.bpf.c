// SPDX-License-Identifier: (MIT OR GPL-2.0)
//go:build ignore
// (위 줄은 go build가 이 C 파일을 cgo 소스로 오해하지 않게 한다)
// 07-1: 커널 함수 vfs_read 호출 횟수를 세는 최소 예제 (kprobe + array map)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} calls SEC(".maps");

SEC("kprobe/vfs_read")
int count_vfs_read(void *ctx)
{
	u32 key = 0;
	u64 *val = bpf_map_lookup_elem(&calls, &key);

	if (val)
		__sync_fetch_and_add(val, 1);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
