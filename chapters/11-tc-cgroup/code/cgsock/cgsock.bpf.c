//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 11-2: cgroup 소켓 hook — 이 cgroup에 속한 프로세스의 connect()/sendmsg()를 시스템 콜 단계에서 막거나 목적지를 바꾼다.
// 패킷이 만들어지기 전이므로, 막으면 앱은 즉시 EPERM을 받는다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 0이면 해당 기능을 쓰지 않는다
const volatile __u16 deny_tcp = 0;   // 이 포트로의 TCP connect 거부
const volatile __u16 deny_udp = 0;   // 이 포트로의 UDP connect/sendmsg 거부
const volatile __u16 redir_from = 0; // 이 포트로의 TCP connect를
const volatile __u16 redir_to = 0;   // 이 포트로 바꾼다

enum { HOOK_CONNECT4 = 1, HOOK_SENDMSG4 = 2 };
enum { V_ALLOW = 0, V_DENY = 1, V_REDIRECT = 2 };

struct event {
	__u32 pid;
	__u32 daddr;
	__u16 dport, new_dport;
	__u8 hook, verdict, type; // type: SOCK_STREAM(1) / SOCK_DGRAM(2)
	__u8 pad;
	__u8 comm[16];
};
const struct event *unused_event __attribute__((unused)); // bpf2go -type가 찾도록 BTF에 남긴다

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} events SEC(".maps");

static __always_inline void emit(struct bpf_sock_addr *ctx, __u8 hook, __u8 verdict, __u16 dport, __u16 new_dport)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e) // ring buffer가 차면 알림을 건너뛴다(정책 판단에는 영향 없음)
		return;
	__builtin_memset(e, 0, sizeof(*e)); // reserve한 공간은 0으로 초기화되지 않는다(pad 포함)
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->daddr = ctx->user_ip4;
	e->dport = dport;
	e->new_dport = new_dport;
	e->hook = hook;
	e->verdict = verdict;
	e->type = ctx->type;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

// 반환값: 1 = 허용, 0 = 거부(시스템 콜이 EPERM으로 실패)
SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
	// user_port는 32비트 필드지만 하위 16비트에 네트워크 바이트 순서 포트가 들어 있다
	__u16 dport = bpf_ntohs((__u16)ctx->user_port);

	if (ctx->type == SOCK_STREAM) {
		if (deny_tcp && dport == deny_tcp) {
			emit(ctx, HOOK_CONNECT4, V_DENY, dport, 0);
			return 0;
		}
		if (redir_from && dport == redir_from) {
			ctx->user_port = bpf_htons(redir_to); // 커널은 바뀐 주소로 연결한다
			emit(ctx, HOOK_CONNECT4, V_REDIRECT, dport, redir_to);
		}
		return 1;
	}
	// UDP도 connect()를 부르면 이 hook을 지난다(이후 send()는 sendmsg4를 거치지 않는다)
	if (ctx->type == SOCK_DGRAM && deny_udp && dport == deny_udp) {
		emit(ctx, HOOK_CONNECT4, V_DENY, dport, 0);
		return 0;
	}
	return 1;
}

// connect 하지 않은 UDP 소켓의 sendto()/sendmsg()마다 불린다
SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
	__u16 dport = bpf_ntohs((__u16)ctx->user_port);

	if (deny_udp && dport == deny_udp) {
		emit(ctx, HOOK_SENDMSG4, V_DENY, dport, 0);
		return 0;
	}
	return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
