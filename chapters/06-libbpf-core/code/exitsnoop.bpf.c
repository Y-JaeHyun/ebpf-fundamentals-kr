// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 06장: 프로세스 종료 추적 — CO-RE로 커널 버전마다 다른 구조체를 흡수한다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 로더가 로드 전에 채운다(skeleton의 skel->rodata->…)
const volatile unsigned long long min_duration_ns = 0;
const volatile int target_uid = -1;

// 5.14 이전 커널의 task_struct에는 __state 대신 long state가 있었다.
// "구조체이름___아무거나" 형태(flavor)로 옛 모양을 선언해 두면, libbpf는 ___ 뒤를 떼고
// 같은 struct task_struct로 보고 재배치한다. preserve_access_index가 재배치 대상임을 표시한다.
struct task_struct___pre514 {
	long state;
} __attribute__((preserve_access_index));

static __always_inline unsigned int task_state(struct task_struct *t)
{
	// 실행 중인 커널의 BTF에 이 필드가 있는지는 "로드할 때" 결정된다. 없는 쪽 분기는 verifier가 지운다.
	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ((struct task_struct___pre514 *)t, state);
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *p)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32, tid = (u32)id;
	u64 duration;
	struct event *e;

	// 스레드 그룹 리더의 종료만 본다. 대부분은 이것이 곧 프로세스 종료지만,
	// 리더가 다른 스레드보다 먼저 끝나는 경우는 정확하지 않다(README "자주 하는 실수" 참고).
	if (pid != tid)
		return 0;
	if (target_uid >= 0 && (u32)bpf_get_current_uid_gid() != (u32)target_uid)
		return 0;

	duration = bpf_ktime_get_ns() - BPF_CORE_READ(p, start_time);
	if (min_duration_ns && duration < min_duration_ns)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->exit_code = BPF_CORE_READ(p, exit_code);
	e->state = task_state(p);
	e->duration_ns = duration;
	BPF_CORE_READ_STR_INTO(&e->comm, p, comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
