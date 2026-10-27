//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 10-1: XDP 방화벽 — 차단 목록(map)에 있는 출발지 IPv4의 패킷을 드라이버 단계에서 버린다.
// 차단 목록은 프로그램을 다시 로드하지 않고 사용자 공간(bpftool 등)에서 바꾼다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define XDP_DROP 1
#define XDP_PASS 2

// key: 출발지 IPv4 주소(네트워크 바이트 순서 그대로), value: 아무 값(존재 여부만 본다)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} blocklist SEC(".maps");

// [0] = 통과한 IPv4 패킷, [1] = 버린 IPv4 패킷
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		(*v)++;
}

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP)) // ARP 등은 그대로 통과
		return XDP_PASS;

	if (bpf_map_lookup_elem(&blocklist, &ip->saddr)) {
		bump(1);
		return XDP_DROP;
	}
	bump(0);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
