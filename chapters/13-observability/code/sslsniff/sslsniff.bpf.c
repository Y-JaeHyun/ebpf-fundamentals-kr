//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 13-3: uprobe로 TLS 평문 보기 — OpenSSL의 SSL_read/SSL_write에 붙어, 암호화 전·복호화 후의 버퍼를 읽는다.
// 읽기는 함수가 끝나야 버퍼가 채워지므로, 진입(uprobe)에서 버퍼 주소를 기억하고 반환(uretprobe)에서 읽는다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define MAX_DATA 256

enum { F_READ = 1, F_WRITE = 2, F_READ_EX = 3, F_WRITE_EX = 4 };

struct event {
	__u64 ts;
	__u32 pid;
	__u32 len;    // 함수가 실제로 읽거나 쓴 바이트 수
	__u32 copied; // 그중 data에 담은 바이트 수(최대 MAX_DATA)
	__u8 func;
	__u8 pad[3];
	__u8 comm[16];
	__u8 data[MAX_DATA];
};
const struct event *unused_event __attribute__((unused)); // bpf2go -type가 찾도록 BTF에 남긴다

struct call {
	__u64 buf;    // 평문 버퍼 주소(사용자 공간)
	__u64 lenptr; // *_ex 함수의 size_t *readbytes / *written. 아니면 0
	__u8 func;
};

// 진입 → 반환 사이에 인자를 들고 있는다. 같은 스레드에서 동시에 두 번 들어가지는 않으므로 key는 pid_tgid
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct call);
} calls SEC(".maps");

// 이 network namespace(inode 번호)에 있는 프로세스만 본다. 사용자 공간이 채운다
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u8);
} netns_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int enter(void *buf, void *lenptr, __u8 func)
{
	struct task_struct *t = bpf_get_current_task_btf();
	__u32 ino = BPF_CORE_READ(t, nsproxy, net_ns, ns.inum);
	__u64 id = bpf_get_current_pid_tgid();
	struct call c = { .buf = (__u64)buf, .lenptr = (__u64)lenptr, .func = func };

	if (!bpf_map_lookup_elem(&netns_allow, &ino))
		return 0;
	bpf_map_update_elem(&calls, &id, &c, BPF_ANY);
	return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num), int SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe")
int BPF_UPROBE(ssl_read, void *ssl, void *buf, int num) { return enter(buf, 0, F_READ); }
SEC("uprobe")
int BPF_UPROBE(ssl_write, void *ssl, void *buf, int num) { return enter(buf, 0, F_WRITE); }

// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) — 성공하면 1, 읽은 양은 *readbytes
SEC("uprobe")
int BPF_UPROBE(ssl_read_ex, void *ssl, void *buf, size_t num, size_t *n) { return enter(buf, n, F_READ_EX); }
SEC("uprobe")
int BPF_UPROBE(ssl_write_ex, void *ssl, void *buf, size_t num, size_t *n) { return enter(buf, n, F_WRITE_EX); }

SEC("uretprobe")
int BPF_URETPROBE(ssl_ret, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct call *c = bpf_map_lookup_elem(&calls, &id);
	__u64 len = 0;

	if (!c)
		return 0;
	if (c->lenptr) { // *_ex: 반환값은 성공 여부
		if (ret == 1)
			bpf_probe_read_user(&len, sizeof(len), (void *)c->lenptr);
	} else if (ret > 0) {
		len = ret;
	}
	if (len) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			__u32 n = len < MAX_DATA ? len : MAX_DATA;

			__builtin_memset(e, 0, sizeof(*e));
			e->ts = bpf_ktime_get_ns();
			e->pid = id >> 32;
			e->len = len;
			e->func = c->func;
			bpf_get_current_comm(e->comm, sizeof(e->comm));
			if (bpf_probe_read_user(e->data, n, (void *)c->buf) == 0)
				e->copied = n;
			bpf_ringbuf_submit(e, 0);
		}
	}
	bpf_map_delete_elem(&calls, &id);
	return 0;
}
