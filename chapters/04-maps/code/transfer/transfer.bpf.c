// SPDX-License-Identifier: (MIT OR GPL-2.0)
//go:build ignore
// (위 줄은 go build가 이 C 파일을 cgo 소스로 오해하지 않게 한다)
//
// 04-2: 같은 이벤트(bench의 read 시스템 콜)를 네 가지 방식으로 사용자 공간에 넘긴다.
//   mode 0: 커널 안에서 집계만 (per-CPU 카운터)
//   mode 1: ring buffer — reserve/submit (복사 없음)
//   mode 2: ring buffer — bpf_ringbuf_output (스택에서 복사)
//   mode 3: perf buffer — bpf_perf_event_output (CPU별 버퍼)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
	u32 pid;
	u32 cpu;
	u64 ts;
	u64 count;
	u8 pad[40]; // 이벤트를 64바이트로 맞춘다
};
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // Go에서 로드 전에 다시 정한다
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} pb SEC(".maps");

// [0]=커널에서 센 이벤트 수, [1]=보내기 실패(버퍼 가득 참)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

const volatile u32 target_tgid = 0;
const volatile u32 mode = 0;

static __always_inline void bump(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		(*v)++;
}

static __always_inline void fill(struct event *e, u64 count)
{
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->cpu = bpf_get_smp_processor_id();
	e->ts = bpf_ktime_get_ns();
	e->count = count;
}

SEC("tracepoint/syscalls/sys_enter_read")
int on_read(struct trace_event_raw_sys_enter *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_tgid)
		return 0;
	bump(0);

	if (mode == 1) {
		struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

		if (!e) {
			bump(1);
			return 0;
		}
		fill(e, ctx->args[2]);
		bpf_ringbuf_submit(e, 0);
	} else if (mode == 2) {
		struct event e = {};

		fill(&e, ctx->args[2]);
		if (bpf_ringbuf_output(&rb, &e, sizeof(e), 0))
			bump(1);
	} else if (mode == 3) {
		struct event e = {};

		fill(&e, ctx->args[2]);
		if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
			bump(1);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
