// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 08. 스택 512바이트 한도 초과 — verifier까지 가기 전에 clang이 거부한다
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct big {
	char path[600];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct big);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int prog(struct trace_event_raw_sys_enter *ctx)
{
#ifdef FIX
	// 큰 버퍼는 per-CPU array 한 칸을 "작업 공간"으로 빌려 쓴다
	u32 zero = 0;
	struct big *b = bpf_map_lookup_elem(&scratch, &zero);

	if (!b)
		return 0;
#else
	struct big buf;
	struct big *b = &buf;
#endif
	// 반환값 = NUL 포함 복사한 길이. 실패(음수)면 버리고, 성공하면 그 길이만 보낸다.
	// (작업 공간에는 이전 실행의 내용이 남아 있으므로 sizeof(*b)를 통째로 보내면 안 된다)
	long len = bpf_probe_read_user_str(b->path, sizeof(b->path), (const char *)ctx->args[1]);

	if (len <= 0 || len > sizeof(b->path))
		return 0;
	bpf_ringbuf_output(&rb, b->path, len, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
