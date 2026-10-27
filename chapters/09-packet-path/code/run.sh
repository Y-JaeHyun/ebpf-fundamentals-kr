#!/usr/bin/env bash
# 09장: netns 샌드박스에서 수신 패킷이 지나는 hook 순서 확인 (root)
#
#   [netns ebpf09a] veth09a 192.0.2.1 ── veth ── veth09b 192.0.2.2 [netns ebpf09b]
#       pktpath send  ─────── UDP :9000 ──────▶  pktpath recv (hook 7곳 + 소켓)
#
# 호스트의 실제 인터페이스에는 아무것도 붙이지 않는다. fentry 네 개만 전역이지만 관측 전용이다.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

NS_A=ebpf09a NS_B=ebpf09b
# 같은 이름의 netns가 이미 있으면 남의 것일 수 있으니 지우지 않고 멈춘다
for ns in "$NS_A" "$NS_B"; do
	if ip netns list | grep -qw "$ns"; then
		echo "FAIL: netns $ns 가 이미 있다. 이전 실행의 잔여물이면 'ip netns del $ns' 후 다시 실행"
		exit 1
	fi
done
created=() pid="" out=""
cleanup() { # 이번 실행에서 만든 것만 정리한다
	[ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
	[ -n "$out" ] && rm -f "$out"
	for ns in "${created[@]}"; do ip netns del "$ns" 2>/dev/null || true; done # veth 쌍도 함께 사라진다
}
trap cleanup EXIT

ip netns add "$NS_A" && created+=("$NS_A")
ip netns add "$NS_B" && created+=("$NS_B")
ip link add veth09a netns "$NS_A" type veth peer name veth09b netns "$NS_B"
ip -n "$NS_A" addr add 192.0.2.1/24 dev veth09a
ip -n "$NS_B" addr add 192.0.2.2/24 dev veth09b
for ns in "$NS_A" "$NS_B"; do ip -n "$ns" link set lo up; done
ip -n "$NS_A" link set veth09a up
ip -n "$NS_B" link set veth09b up
# ARP를 미리 채워 첫 패킷이 ARP 대기로 늦어지지 않게 한다
ip netns exec "$NS_A" ping -c1 -W1 192.0.2.2 >/dev/null

trial() {
	local label=$1 show=$2
	shift 2
	echo "=== $label"
	out=$(mktemp)
	ip netns exec "$NS_B" ./bin/pktpath recv -if veth09b -n 10 -timeout 1500ms "$@" >"$out" 2>&1 &
	pid=$!
	for _ in $(seq 50); do
		grep -q '^ready' "$out" && break
		sleep 0.1
	done
	if ! grep -q '^ready' "$out"; then
		cat "$out"
		echo "FAIL: 수신 프로그램이 준비되지 않았다"
		exit 1
	fi
	if [ "$show" = 1 ]; then
		echo "--- bpftool net show (netns $NS_B 안에서)"
		ip netns exec "$NS_B" bpftool net show
		echo "---"
	fi
	ip netns exec "$NS_A" ./bin/pktpath send -to 192.0.2.2:9000 -n 10
	wait "$pid"
	pid=""
	grep -v '^ready' "$out"
	rm -f "$out"
	out=""
	echo
}

trial "1) 아무것도 버리지 않을 때" 1
trial "2) TC ingress에서 버리면 (TC_ACT_SHOT)" 0 -drop tc
trial "3) netfilter LOCAL_IN에서 버리면 (NF_DROP)" 0 -drop nf_in
trial "4) XDP에서 버리면 (XDP_DROP)" 0 -drop xdp
trial "5) 소켓 필터에서 버리면 (0 반환)" 0 -drop socket
trial "6) XDP를 붙이지 않으면 (IP 계층 진입 함수 비교)" 0 -no-xdp
