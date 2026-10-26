// SPDX-License-Identifier: (MIT OR GPL-2.0)
//go:build ignore
// (위 줄은 go build가 이 C 파일을 cgo 소스로 오해하지 않게 한다)
// 07-2: execve 추적기 — ring buffer로 이벤트를 사용자 공간에 보내고,
// CO-RE(BPF_CORE_READ)로 커널 구조체 task_struct에서 부모 PID를 읽는다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 128

// bpf2go -type event 로 같은 모양의 Go 구조체가 생성된다.
struct event {
	u32 pid;
	u32 ppid;
	u32 uid;
	u8 comm[TASK_COMM_LEN];
	u8 filename[FILENAME_LEN];
};
// 사용되지 않는 전역 포인터로 struct event가 BTF에 남게 해서 bpf2go -type 이 찾을 수 있게 한다.
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 바이트 단위, 페이지 크기의 2의 거듭제곱 배
} events SEC(".maps");

// 사용자 공간에서 로드 직전에 값을 바꿔 넣는 상수(.rodata). verifier가 값을 알기 때문에
// 필터가 꺼져 있으면(-1) 비교 분기 자체가 제거된다.
const volatile u32 filter_uid = (u32)-1;

// 통계: [0]=보낸 이벤트, [1]=ring buffer가 가득 차서 버린 이벤트 (CPU별 카운터)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

static __always_inline void bump(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		(*v)++; // per-CPU 값이라 원자 연산이 필요 없다
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	u32 uid = (u32)bpf_get_current_uid_gid();
	struct task_struct *task;
	struct event *e;

	if (filter_uid != (u32)-1 && uid != filter_uid)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump(1);
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = uid;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[0]);

	bpf_ringbuf_submit(e, 0);
	bump(0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
