//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 12장: LSM-BPF로 특정 파일 열기와 특정 실행 파일 실행을 막는다.
// 대상은 경로가 아니라 (장치 번호, inode 번호)로 고른다. 경로는 이벤트에 보여 주기만 한다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

enum hook { H_FILE_OPEN = 1, H_BPRM_CHECK = 2 };

struct event {
	__u32 pid;
	__u32 uid;
	__u32 hook;
	__s32 verdict; // 돌려준 값: 0 = 허용, -EPERM = 거부
	__u64 ino;
	__u8 comm[16]; // __u8: bpf2go가 Go의 [16]uint8로 만들도록
	__u8 path[128];
};
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} events SEC(".maps");

// 로더가 stat(2)으로 구해 넣는다. 0이면 그 hook은 아무것도 막지 않는다.
const volatile __u64 deny_open_ino = 0;
const volatile __u32 deny_open_dev = 0;
const volatile __u64 deny_exec_ino = 0;
const volatile __u32 deny_exec_dev = 0;
// false면 막지 않고 기록만 한다(audit 모드)
const volatile bool enforce = true;

static __always_inline bool same_file(struct file *f, __u64 ino, __u32 dev)
{
	struct inode *inode = f->f_inode;

	return ino && inode->i_ino == ino && inode->i_sb->s_dev == dev;
}

static __always_inline struct event *new_event(enum hook h, __u64 ino)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return NULL;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->hook = h;
	e->verdict = enforce ? -EPERM : 0;
	e->ino = ino;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->path[0] = 0;
	return e;
}

// LSM 프로그램의 마지막 인자 ret = 같은 hook에 먼저 붙은 BPF LSM 프로그램이 돌려준 값
SEC("lsm/file_open")
int BPF_PROG(guard_open, struct file *file, int ret)
{
	struct event *e;

	if (ret)
		return ret; // 이미 거부된 요청은 그대로 둔다
	if (!same_file(file, deny_open_ino, deny_open_dev))
		return 0;

	e = new_event(H_FILE_OPEN, deny_open_ino);
	if (e) {
		// bpf_d_path: struct path → 문자열 경로. 허용된 일부 hook에서만 쓸 수 있다
		bpf_d_path(&file->f_path, (char *)e->path, sizeof(e->path));
		bpf_ringbuf_submit(e, 0);
	}
	return enforce ? -EPERM : 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(guard_exec, struct linux_binprm *bprm, int ret)
{
	struct event *e;

	if (ret)
		return ret;
	if (!same_file(bprm->file, deny_exec_ino, deny_exec_dev))
		return 0;

	e = new_event(H_BPRM_CHECK, deny_exec_ino);
	if (e) {
		// execve에 넘긴 경로 문자열(커널 메모리)
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), bprm->filename);
		bpf_ringbuf_submit(e, 0);
	}
	return enforce ? -EPERM : 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
