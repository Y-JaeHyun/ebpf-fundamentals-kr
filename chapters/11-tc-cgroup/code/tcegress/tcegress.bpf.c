//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 11-1: tcx egress — 인터페이스에서 나가는 TCP 패킷 중 목적지 포트가 block_port인 것을 버린다.
// 어느 프로세스가 보냈는지는 모른다. 그 인터페이스로 나가는 모든 패킷에 똑같이 적용된다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IP_OFFSET   0x1fff // 조각 위치(0이 아니면 두 번째 이후 조각)
// tcx 반환값(UAPI enum tcx_action_base). TC_ACT_OK(0)/TC_ACT_SHOT(2)와 값이 겹치지만
// TCX_NEXT는 "판단하지 않음 — 다음 프로그램(없으면 기본 동작인 통과)에 맡김"이다
#define TCX_NEXT -1
#define TCX_DROP 2

const volatile __u16 block_port = 8080;

// [0] = 판단하지 않고 넘긴(TCX_NEXT) IPv4 TCP 패킷, [1] = 버린 패킷
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// 버린 패킷을 사용자 공간에 알린다(재전송 간격을 보기 위해). ring buffer가 차면 알림은 빠질 수 있다(best effort)
struct drop_event {
	__u64 ts;
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u8 flags; // TCP 플래그 바이트 (SYN = 0x02)
	__u8 pad[3];
};
const struct drop_event *unused_drop_event __attribute__((unused)); // bpf2go -type가 찾도록 BTF에 남긴다

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} events SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		(*v)++;
}

SEC("tcx/egress")
int egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth + 1);
	struct tcphdr *tcp;
	struct drop_event *e;

	if ((void *)(ip + 1) > end)
		return TCX_NEXT;
	if (eth->h_proto != bpf_htons(ETH_P_IP) || ip->protocol != IPPROTO_TCP || ip->ihl < 5)
		return TCX_NEXT;
	// 두 번째 이후 조각은 IP 헤더 뒤가 TCP 헤더가 아니다
	if (ip->frag_off & bpf_htons(IP_OFFSET))
		return TCX_NEXT;
	if (bpf_ntohs(ip->tot_len) < ip->ihl * 4 + sizeof(*tcp))
		return TCX_NEXT;
	tcp = (void *)ip + ip->ihl * 4;
	if ((void *)(tcp + 1) > end || tcp->doff < 5)
		return TCX_NEXT;

	if (tcp->dest != bpf_htons(block_port)) {
		bump(0);
		return TCX_NEXT;
	}
	bump(1);
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		__builtin_memset(e, 0, sizeof(*e)); // reserve한 공간은 0으로 초기화되지 않는다(pad 포함)
		e->ts = bpf_ktime_get_ns();
		e->saddr = ip->saddr;
		e->daddr = ip->daddr;
		e->sport = bpf_ntohs(tcp->source);
		e->dport = bpf_ntohs(tcp->dest);
		e->flags = ((__u8 *)tcp)[13];
		bpf_ringbuf_submit(e, 0);
	}
	return TCX_DROP;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
