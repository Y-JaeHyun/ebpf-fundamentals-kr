//go:build ignore
// SPDX-License-Identifier: (MIT OR GPL-2.0)
// 09장: 수신 패킷 하나가 커널의 어느 hook을 어떤 순서로 지나는지 기록한다.
//
// 실험 패킷: UDP 목적지 포트 9000, 페이로드 앞 8바이트 = magic(4) + seq(4)
// 각 hook은 그 패킷을 보면 seq별 칸에 bpf_ktime_get_ns()를 적는다.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP    0x0800
#define IPPROTO_UDP 17
#define DPORT       9000
#define MAGIC       0x46504245 /* "EBPF"를 리틀 엔디언 u32로 읽은 값 */

#define XDP_DROP     1
#define XDP_PASS     2
#define TC_ACT_OK    0
#define TC_ACT_SHOT  2
#define NF_DROP      0
#define NF_ACCEPT    1

enum stage {
	S_XDP,       // 드라이버 수신 직후, sk_buff 만들기 전
	S_TC,        // tcx ingress: sk_buff가 생긴 뒤 첫 프로그래머블 지점
	S_IP_RCV,    // fentry/ip_rcv_core: IP 계층 진입 (ip_rcv·ip_list_rcv 공통 경로)
	S_NF_PRE,    // netfilter PRE_ROUTING (라우팅 결정 전)
	S_NF_IN,     // netfilter LOCAL_IN (이 호스트로 온 패킷으로 결정된 뒤)
	S_UDP_RCV,   // fentry/udp_rcv: UDP 계층 진입
	S_SOCK,      // 소켓 필터: 소켓 수신 큐에 넣기 직전
	S_MAX,
};

struct pkt_path {
	__u64 ts[S_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); // seq
	__type(value, struct pkt_path);
} paths SEC(".maps");

// 이 단계에서 실험 패킷을 버린다(S_MAX면 버리지 않음). 로더가 로드 전에 정한다.
const volatile __u32 drop_at = S_MAX;
// IP 계층 진입 함수 호출 횟수를 셀 인터페이스 이름
const volatile char target_if[16] = {};

// [0] = ip_rcv 호출 수, [1] = ip_list_rcv 호출 수 (target_if에서 온 것만)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} entry_cnt SEC(".maps");

// 실험 패킷의 IP 헤더부터 페이로드 앞 8바이트까지 (IP 옵션 없음 가정)
struct probe_pkt {
	struct iphdr ip;
	struct udphdr udp;
	__u32 magic;
	__u32 seq;
} __attribute__((packed));

const struct pkt_path *unused_pkt_path __attribute__((unused));

static __always_inline int match(const struct probe_pkt *p, __u32 *seq)
{
	if (p->ip.version != 4 || p->ip.ihl != 5 || p->ip.protocol != IPPROTO_UDP)
		return 0;
	if (p->udp.dest != bpf_htons(DPORT) || p->magic != MAGIC)
		return 0;
	*seq = p->seq;
	return 1;
}

static __always_inline void record(__u32 seq, enum stage s)
{
	__u64 now = bpf_ktime_get_ns();
	struct pkt_path *v = bpf_map_lookup_elem(&paths, &seq);

	if (v) {
		v->ts[s] = now;
		return;
	}
	struct pkt_path z = {};
	z.ts[s] = now;
	bpf_map_update_elem(&paths, &seq, &z, BPF_NOEXIST);
}

// ---- XDP: struct xdp_md, 패킷 메모리를 직접 가리키는 data/data_end ----
SEC("xdp")
int at_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct probe_pkt *p = data + sizeof(*eth);
	__u32 seq;

	if ((void *)(p + 1) > end) // 경계 검사가 없으면 verifier가 거부한다
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP) || !match(p, &seq))
		return XDP_PASS;
	record(seq, S_XDP);
	return drop_at == S_XDP ? XDP_DROP : XDP_PASS;
}

// ---- TC(tcx) ingress: struct __sk_buff, 역시 data/data_end로 직접 접근 ----
SEC("tcx/ingress")
int at_tc(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct probe_pkt *p = data + sizeof(*eth);
	__u32 seq;

	if ((void *)(p + 1) > end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP) || !match(p, &seq))
		return TC_ACT_OK;
	record(seq, S_TC);
	return drop_at == S_TC ? TC_ACT_SHOT : TC_ACT_OK;
}

// ---- 커널 내부(sk_buff 포인터): 패킷 바이트는 head + network_header에 있다 ----
static __always_inline int read_skb(struct sk_buff *skb, __u32 *seq)
{
	struct probe_pkt p;
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 nh = BPF_CORE_READ(skb, network_header);
	__u32 tail = BPF_CORE_READ(skb, tail); // 64비트 커널에서 tail은 head 기준 오프셋

	// 읽을 범위가 선형 데이터(head ~ tail) 안에 있을 때만 읽는다. 짧거나 조각난 패킷이면
	// 패킷 밖의 메모리를 읽어 엉뚱한 값과 비교하게 된다.
	if (nh + sizeof(p) > tail)
		return 0;
	if (bpf_probe_read_kernel(&p, sizeof(p), head + nh))
		return 0;
	return match(&p, seq);
}

// ip_rcv(패킷 하나씩)와 ip_list_rcv(묶음) 둘 다 ip_rcv_core를 거친다
SEC("fentry/ip_rcv_core")
int BPF_PROG(at_ip_rcv_core, struct sk_buff *skb)
{
	__u32 seq;

	if (read_skb(skb, &seq))
		record(seq, S_IP_RCV);
	return 0; // fentry는 관측만 한다. 반환값으로 패킷을 바꿀 수 없다
}

static __always_inline void count_entry(struct net_device *dev, __u32 idx)
{
	char name[16];

	if (bpf_probe_read_kernel_str(name, sizeof(name), dev->name) < 0)
		return;
	for (int i = 0; i < sizeof(name); i++) {
		if (name[i] != target_if[i])
			return;
		if (!name[i])
			break;
	}
	__u64 *c = bpf_map_lookup_elem(&entry_cnt, &idx);
	if (c)
		__sync_fetch_and_add(c, 1);
}

// 어느 진입 함수로 IP 계층에 들어오는지 센다
SEC("fentry/ip_rcv")
int BPF_PROG(cnt_ip_rcv, struct sk_buff *skb, struct net_device *dev)
{
	count_entry(dev, 0);
	return 0;
}

SEC("fentry/ip_list_rcv")
int BPF_PROG(cnt_ip_list_rcv, struct list_head *head, struct packet_type *pt,
	     struct net_device *orig_dev)
{
	count_entry(orig_dev, 1);
	return 0;
}

SEC("fentry/udp_rcv")
int BPF_PROG(at_udp_rcv, struct sk_buff *skb)
{
	__u32 seq;

	if (read_skb(skb, &seq))
		record(seq, S_UDP_RCV);
	return 0;
}

// ---- netfilter(6.4+): 같은 프로그램을 PRE_ROUTING과 LOCAL_IN 두 곳에 붙인다 ----
SEC("netfilter")
int at_nf(struct bpf_nf_ctx *ctx)
{
	enum stage s = ctx->state->hook == NF_INET_PRE_ROUTING ? S_NF_PRE : S_NF_IN;
	__u32 seq;

	if (!read_skb(ctx->skb, &seq))
		return NF_ACCEPT;
	record(seq, s);
	return drop_at == s ? NF_DROP : NF_ACCEPT;
}

// ---- 소켓 필터: 특정 소켓 하나에 붙는다. 반환값 = 남길 바이트 수(0이면 버림) ----
SEC("socket")
int at_sock(struct __sk_buff *skb)
{
	struct probe_pkt p;
	__u32 seq;

	// 이 시점의 skb->data는 UDP 헤더를 가리킨다. 네트워크 헤더 기준으로 읽는다
	if (bpf_skb_load_bytes_relative(skb, 0, &p, sizeof(p), BPF_HDR_START_NET))
		return skb->len;
	if (!match(&p, &seq))
		return skb->len;
	record(seq, S_SOCK);
	return drop_at == S_SOCK ? 0 : skb->len;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
