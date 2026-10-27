#!/usr/bin/env bash
# 10장: netns 샌드박스에서 XDP 방화벽(map으로 실시간 차단)과 AF_XDP 수신 (root)
#
#   [netns ebpf10a] veth10a 192.0.2.1 ── veth ── veth10b 192.0.2.2 [netns ebpf10b]
# 호스트에 남기는 것: 실행 중에만 /run/ebpf-ch10 (bpffs). 끝나면 netns와 함께 지운다(이미 있으면 시작하지 않는다).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

NS_A=ebpf10a NS_B=ebpf10b
# ip netns exec는 그 netns용으로 /sys를 다시 마운트하므로 /sys/fs/bpf(bpffs)가 안에서 보이지 않는다.
# 그래서 /sys 바깥에 이 실습 전용 bpffs를 마운트해 pin 경로로 쓴다.
BPFFS=/run/ebpf-ch10 PIN=/run/ebpf-ch10/blocklist
for ns in "$NS_A" "$NS_B"; do
	if ip netns list | grep -qw "$ns"; then
		echo "FAIL: netns $ns 가 이미 있다. 이전 실행의 잔여물이면 'ip netns del $ns' 후 다시 실행"
		exit 1
	fi
done
if [ -e "$BPFFS" ]; then
	echo "FAIL: $BPFFS 가 이미 있다. 이전 실행의 잔여물이면 'umount $BPFFS; rmdir $BPFFS' 후 다시 실행"
	exit 1
fi
LOG=$(mktemp)
created=() bg="" mkdir_done="" mounted=""
cleanup() { # 이번 실행에서 만든 것만 정리한다. 한 단계가 실패해도 나머지는 계속한다
	set +e
	[ -n "$bg" ] && { kill "$bg" 2>/dev/null; wait "$bg" 2>/dev/null; }
	[ -n "$mounted" ] && { rm -f "$PIN"; umount "$BPFFS"; }
	[ -n "$mkdir_done" ] && rmdir "$BPFFS"
	rm -f "$LOG"
	for ns in "${created[@]}"; do ip netns del "$ns" 2>/dev/null; done
	return 0
}
trap cleanup EXIT

mkdir "$BPFFS"; mkdir_done=1 # set -e: 실패하면 여기서 멈추고 표시도 남기지 않는다
mount -t bpf ebpf-ch10 "$BPFFS"; mounted=1
ip netns add "$NS_A"; created+=("$NS_A")
ip netns add "$NS_B"; created+=("$NS_B")
ip link add veth10a netns "$NS_A" type veth peer name veth10b netns "$NS_B"
ip -n "$NS_A" addr add 192.0.2.1/24 dev veth10a
ip -n "$NS_B" addr add 192.0.2.2/24 dev veth10b
for ns in "$NS_A" "$NS_B"; do ip -n "$ns" link set lo up; done
ip -n "$NS_A" link set veth10a up
ip -n "$NS_B" link set veth10b up
ip netns exec "$NS_A" ping -c1 -W1 192.0.2.2 >/dev/null # ARP 미리 채우기

wait_ready() {
	for _ in $(seq 50); do
		grep -q '^ready' "$LOG" && return 0
		kill -0 "$bg" 2>/dev/null || break
		sleep 0.1
	done
	cat "$LOG"
	echo "FAIL: 준비되지 않았다"
	exit 1
}
ping_b() { # ping 결과 요약 한 줄
	ip netns exec "$NS_A" ping -c 5 -i 0.2 -W 1 192.0.2.2 | grep -E "packets transmitted" || true
}

echo "=== 10-1) XDP 방화벽: 차단 목록을 실행 중에 바꾼다"
ip netns exec "$NS_B" ./bin/xdpfw -if veth10b -pin "$PIN" -d 9s >"$LOG" 2>&1 &
bg=$!
wait_ready
head -1 "$LOG"
echo "--- 차단 전"
ping_b
echo "--- bpftool로 192.0.2.1 차단 (key = IPv4 4바이트, 네트워크 바이트 순서)"
echo "\$ bpftool map update pinned $PIN key 192 0 2 1 value 1"
bpftool map update pinned "$PIN" key 192 0 2 1 value 1
bpftool map dump pinned "$PIN"
ping_b
echo "--- 차단 해제"
bpftool map delete pinned "$PIN" key 192 0 2 1
ping_b
wait "$bg"
bg=""
echo "--- xdpfw 출력 (1초마다 통과/차단 수)"
sed -n '2,$p' "$LOG"

echo
echo "=== 10-2) AF_XDP: UDP :9000 패킷만 사용자 공간 소켓으로 바로 보낸다"
: >"$LOG"
ip netns exec "$NS_B" ./bin/afxdp recv -if veth10b -port 9000 -n 5 -timeout 3s >"$LOG" 2>&1 &
bg=$!
wait_ready
ip netns exec "$NS_A" ./bin/afxdp send -to 192.0.2.2:9000 -n 5
echo "--- 같은 시간에 ping(ICMP)은 XDP_PASS로 커널 스택이 처리"
ip netns exec "$NS_A" ping -c 2 -i 0.2 -W 1 192.0.2.2 | grep -E "packets transmitted" || true
wait "$bg"
bg=""
sed -n '2,$p' "$LOG"
