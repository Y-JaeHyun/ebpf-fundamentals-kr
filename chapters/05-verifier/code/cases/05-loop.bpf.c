// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 05. 반복 횟수가 실행 시점 값(사용자 입력)에 달린 루프
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} out SEC(".maps");

#ifdef FIX
static long add_one(u64 i, u64 *sum)
{
	*sum += bpf_get_prandom_u32();
	return 0; // 1을 반환하면 루프를 멈춘다
}
#endif

SEC("tracepoint/syscalls/sys_enter_read")
int prog(struct trace_event_raw_sys_enter *ctx)
{
	u64 n = ctx->args[2], sum = 0;
	u32 zero = 0;
	u64 *v;

#ifdef FIX
	// bpf_loop(5.17+): 반복은 helper가 하고 verifier는 콜백 본문만 한 번 검사한다.
	// 횟수 인자는 u32이고 최대 1<<23(약 800만)이다. 넘으면 -E2BIG을 돌려주므로 미리 자르고 결과를 확인한다.
	if (n > 1 << 20)
		n = 1 << 20;
	if (bpf_loop(n, add_one, &sum, 0) < 0)
		return 0;
#else
	for (u64 i = 0; i < n; i++)
		sum += bpf_get_prandom_u32(); // helper 호출이라 컴파일러가 루프를 없애지 못한다
#endif
	v = bpf_map_lookup_elem(&out, &zero);
	if (v)
		*v = sum;
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
