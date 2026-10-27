//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 10-2: UDP 목적지 포트가 맞는 패킷만 AF_XDP 소켓으로 보내고, 나머지는 커널 스택으로 통과시킨다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_UDP 17
#define XDP_PASS    2
#define IP_MF       0x2000 // 뒤에 조각이 더 있음
#define IP_OFFSET   0x1fff // 조각 위치(0이 아니면 두 번째 이후 조각)

// key: 수신 큐 번호, value: AF_XDP 소켓 fd (사용자 공간이 넣는다)
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} xsks SEC(".maps");

const volatile __u16 port = 9000;

SEC("xdp")
int xdp_to_xsk(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1); // IP 옵션 없음 가정(ihl == 5)

	if ((void *)(udp + 1) > end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP) || ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	// 조각난 패킷은 커널에 맡긴다. 두 번째 이후 조각의 ip + 1 자리는 UDP 헤더가 아니다
	if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return XDP_PASS;
	if (udp->dest != bpf_htons(port))
		return XDP_PASS;

	// 이 패킷이 들어온 큐에 연결된 소켓으로 보낸다. 소켓이 없으면 flags의 하위 비트(XDP_PASS)대로 처리
	return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_PASS);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
