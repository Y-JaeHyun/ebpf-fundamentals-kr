//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 13-2: TCP 재전송과 연결별 RTT — 재전송이 일어날 때마다, 그리고 연결이 닫힐 때 tcp_sock의 통계를 읽어 알린다.
// 패킷을 보지 않고 커널이 이미 계산해 둔 값(srtt_us, total_retrans 등)을 읽는 것이 핵심이다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define IPPROTO_TCP 6

// 이 network namespace(inode 번호)의 소켓만 본다. 0이면 전부
const volatile __u32 netns_ino = 0;

enum { EV_RETRANS = 1, EV_CLOSE = 2 };

struct event {
	__u64 ts;
	__u64 bytes_acked, bytes_received; // EV_CLOSE
	__u64 life_ns;                     // EV_CLOSE: ESTABLISHED가 된 뒤 닫힐 때까지
	__u32 skb_len;                     // EV_RETRANS: 재전송하려 한 skb의 데이터 크기(세그먼트 여러 개일 수 있다)
	__s32 err;                         // EV_RETRANS: 0이 아니면 재전송 시도가 실패했다
	__u32 saddr, daddr;
	__u16 sport, dport; // 호스트 바이트 순서
	__u32 srtt_us;      // 평활 RTT(µs)
	__u32 total_retrans, data_segs_out;
	__u8 type, state;
	__u8 pad[6];
};
const struct event *unused_event __attribute__((unused)); // bpf2go -type가 찾도록 BTF에 남긴다

// ESTABLISHED가 됐을 때 기록해 두는 값. 닫힐 때는 로컬 포트(skc_num)가 이미 0으로 지워져 있어 여기서 꺼낸다
struct born_info {
	__u64 ts;
	__u16 sport;
};

// 소켓 주소 → born_info
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct born_info);
} born SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline bool wanted(const struct sock *sk)
{
	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
		return false; // 예제는 IPv4만
	return !netns_ino || BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) == netns_ino;
}

static __always_inline struct event *fill(__u8 type, const struct sock *sk)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	struct tcp_sock *tp = (struct tcp_sock *)sk;

	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = bpf_ktime_get_ns();
	e->type = type;
	e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	e->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3; // 커널은 8배 한 값을 저장한다
	e->total_retrans = BPF_CORE_READ(tp, total_retrans);
	e->data_segs_out = BPF_CORE_READ(tp, data_segs_out);
	return e;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(on_retrans, const struct sock *sk, const struct sk_buff *skb, int err)
{
	if (!wanted(sk))
		return 0;
	struct event *e = fill(EV_RETRANS, sk);
	if (e) {
		e->skb_len = BPF_CORE_READ(skb, len);
		e->err = err;
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_state, const struct sock *sk, int oldstate, int newstate)
{
	__u64 key = (__u64)sk;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP || !wanted(sk))
		return 0;
	if (newstate == BPF_TCP_ESTABLISHED) {
		struct born_info b = { .ts = bpf_ktime_get_ns(), .sport = BPF_CORE_READ(sk, __sk_common.skc_num) };

		bpf_map_update_elem(&born, &key, &b, BPF_ANY);
		return 0;
	}
	if (newstate != BPF_TCP_CLOSE)
		return 0;

	struct born_info *b = bpf_map_lookup_elem(&born, &key);
	if (!b) // 연결되지 못한 소켓(또는 이 프로그램이 붙기 전에 연결된 소켓)
		return 0;
	struct event *e = fill(EV_CLOSE, sk);
	if (e) {
		struct tcp_sock *tp = (struct tcp_sock *)sk;

		e->state = oldstate;
		e->life_ns = e->ts - b->ts;
		e->sport = b->sport;
		e->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
		e->bytes_received = BPF_CORE_READ(tp, bytes_received);
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&born, &key);
	return 0;
}
