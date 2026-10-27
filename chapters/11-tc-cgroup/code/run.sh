#!/usr/bin/env bash
# 11장: 같은 정책(TCP :8080 차단)을 TC egress와 cgroup 소켓 hook으로 각각 걸어 차이를 본다 (root)
#
#   [netns ebpf11a] veth11a 192.0.2.1 ── veth ── veth11b 192.0.2.2 [netns ebpf11b]
#   임시 cgroup: /sys/fs/cgroup/ebpf-ch11 (실행 중에만. 이미 있으면 시작하지 않는다)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

NS_A=ebpf11a NS_B=ebpf11b CG=/sys/fs/cgroup/ebpf-ch11
for ns in "$NS_A" "$NS_B"; do
	if ip netns list | grep -qw "$ns"; then
		echo "FAIL: netns $ns 가 이미 있다. 이전 실행의 잔여물이면 'ip netns del $ns' 후 다시 실행"
		exit 1
	fi
done
if [ -e "$CG" ]; then
	echo "FAIL: $CG 가 이미 있다. 이전 실행의 잔여물이면 'rmdir $CG' 후 다시 실행"
	exit 1
fi
LOG=$(mktemp) SRV=$(mktemp)
created=() bg="" srv="" cg_made=""
cleanup() { # 이번 실행에서 만든 것만 정리한다. 한 단계가 실패해도 나머지는 계속한다
	set +e
	for p in "$bg" "$srv"; do [ -n "$p" ] && { kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; }; done
	rm -f "$LOG" "$SRV"
	# 중간에 끊겼다면 cgroup에 남은 실험 프로세스가 있을 수 있다. 이 cgroup은 이번 실행이 만든 것이므로 통째로 끝낸다
	[ -n "$cg_made" ] && { echo 1 >"$CG/cgroup.kill"; for _ in 1 2 3 4 5; do rmdir "$CG" 2>/dev/null && break; sleep 0.2; done; }
	for ns in "${created[@]}"; do ip netns del "$ns" 2>/dev/null; done
	return 0
}
trap cleanup EXIT

ip netns add "$NS_A"; created+=("$NS_A")
ip netns add "$NS_B"; created+=("$NS_B")
ip link add veth11a netns "$NS_A" type veth peer name veth11b netns "$NS_B"
ip -n "$NS_A" addr add 192.0.2.1/24 dev veth11a
ip -n "$NS_B" addr add 192.0.2.2/24 dev veth11b
for ns in "$NS_A" "$NS_B"; do ip -n "$ns" link set lo up; done
ip -n "$NS_A" link set veth11a up
ip -n "$NS_B" link set veth11b up
ip netns exec "$NS_A" ping -c1 -W1 192.0.2.2 >/dev/null # ARP 미리 채우기

wait_ready() { # $1 = 로그 파일, $2 = pid
	for _ in $(seq 50); do
		grep -q '^ready' "$1" && return 0
		kill -0 "$2" 2>/dev/null || break
		sleep 0.1
	done
	cat "$1"
	echo "FAIL: 준비되지 않았다"
	exit 1
}
probe_a() { ip netns exec "$NS_A" ./bin/probe "$@"; }
# cgroup에 먼저 들어간 뒤 exec한다. 소켓은 만들어질 때의 cgroup에 묶이므로 순서가 중요하다
probe_a_cg() { sh -c 'echo $$ > "$1/cgroup.procs" && shift && exec "$@"' sh "$CG" ip netns exec "$NS_A" ./bin/probe "$@"; }
server_log() { # 서버가 지금까지 받은 것을 보여 주고 비운다(O_APPEND로 쓰므로 비워도 안전)
	sleep 0.3
	echo "--- 서버(ebpf11b)가 받은 것"
	grep -v '^ready' "$SRV" || echo "(없음)"
	: >"$SRV"
}

ip netns exec "$NS_B" ./bin/probe serve -tcp 8080,8081 -udp 9000 >>"$SRV" 2>&1 &
srv=$!
wait_ready "$SRV" "$srv"
: >"$SRV"

echo "=== 11-1) TC egress(veth11a)에서 TCP :8080 패킷을 버리면"
ip netns exec "$NS_A" ./bin/tcegress -if veth11a -port 8080 -d 4s >"$LOG" 2>&1 &
bg=$!
wait_ready "$LOG" "$bg"
probe_a connect 192.0.2.2:8080 -timeout 2500ms
probe_a connect 192.0.2.2:8081
wait "$bg"
bg=""
echo "--- tcegress 출력"
sed -n '2,$p' "$LOG"
server_log

echo
echo "=== 11-2) cgroup 소켓 hook: $CG 안의 프로세스만 TCP :8080·UDP :9000 거부, TCP :80 → :8081"
mkdir "$CG"; cg_made=1
./bin/cgsock -cgroup "$CG" -deny-tcp 8080 -deny-udp 9000 -redirect 80:8081 -d 4s >"$LOG" 2>&1 &
bg=$!
wait_ready "$LOG" "$bg"
echo "--- cgroup 안의 프로세스"
probe_a_cg connect 192.0.2.2:8080
probe_a_cg udp 192.0.2.2:9000
probe_a_cg udp 192.0.2.2:9000 -connect
probe_a_cg connect 192.0.2.2:80
echo "--- cgroup 밖의 프로세스 (같은 netns, 같은 명령)"
probe_a connect 192.0.2.2:8080
probe_a udp 192.0.2.2:9000
probe_a connect 192.0.2.2:80
wait "$bg"
bg=""
echo "--- cgsock 출력"
sed -n '2,$p' "$LOG"
server_log
