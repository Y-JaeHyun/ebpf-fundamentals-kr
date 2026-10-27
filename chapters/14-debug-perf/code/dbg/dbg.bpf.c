//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 14장: 같은 시스템 콜(getppid)에 hook 종류만 바꿔 붙여 비용을 비교하고, bpftool·bpf_printk로 들여다보는 대상.
// 모든 프로그램이 하는 일은 같다: 대상 프로세스면 per-CPU 카운터 +1.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const volatile __u32 target_tgid = 0;
const volatile __u32 nr_getppid = 0; // raw_tp/sys_enter에서 거를 시스템 콜 번호(아키텍처마다 다르다)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

// ring buffer가 가득 차 reserve에 실패한 횟수(= 잃어버린 이벤트)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

struct event {
	__u64 ts;
	__u32 pid;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline bool mine(void)
{
	return (bpf_get_current_pid_tgid() >> 32) == target_tgid;
}

static __always_inline void hit(void)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&hits, &k);

	if (v)
		(*v)++; // per-CPU라 원자적 연산이 필요 없다
}

// 1) 정적 tracepoint: 이 시스템 콜에 들어갈 때만 불린다
SEC("tracepoint/syscalls/sys_enter_getppid")
int tp_getppid(void *ctx)
{
	if (mine())
		hit();
	return 0;
}

// 2) raw tracepoint: 모든 시스템 콜 진입에서 불리고, 번호로 거른다
SEC("raw_tracepoint/sys_enter")
int rawtp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	if (ctx->args[1] == nr_getppid && mine())
		hit();
	return 0;
}

// 3) kprobe: 커널 함수 진입. 시스템 콜 래퍼(__x64_sys_*)가 아니라 BTF에도 있는 본체에 붙인다
SEC("kprobe/__do_sys_getppid")
int kp_getppid(void *ctx)
{
	if (mine())
		hit();
	return 0;
}

// 4) fentry: 같은 함수, BPF trampoline으로 직접 호출
SEC("fentry/__do_sys_getppid")
int BPF_PROG(fe_getppid)
{
	if (mine())
		hit();
	return 0;
}

// 5) fentry + ring buffer: 호출마다 이벤트 하나를 사용자 공간으로 보낸다
SEC("fentry/__do_sys_getppid")
int BPF_PROG(fe_getppid_ringbuf)
{
	struct event *e;

	if (!mine())
		return 0;
	hit();
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 k = 0;
		__u64 *d = bpf_map_lookup_elem(&drops, &k);

		if (d)
			(*d)++;
		return 0;
	}
	e->ts = bpf_ktime_get_ns();
	e->pid = target_tgid;
	e->pad = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// 6) bpf_printk: 디버깅용 출력. /sys/kernel/tracing/trace 로 간다
SEC("tracepoint/syscalls/sys_enter_getppid")
int tp_printk(void *ctx)
{
	__u32 k = 0;
	__u64 *v;

	if (!mine())
		return 0;
	v = bpf_map_lookup_elem(&hits, &k);
	if (!v)
		return 0;
	(*v)++;
	bpf_printk("ebpf14: getppid pid=%d n=%llu", target_tgid, *v);
	return 0;
}
