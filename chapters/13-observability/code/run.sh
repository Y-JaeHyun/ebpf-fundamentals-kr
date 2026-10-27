#!/usr/bin/env bash
# 13장: 관측 실전 패턴 세 가지 (root)
#   13-1 프로세스 트리: 명령 하나와 그 자손만 추적
#   13-2 TCP RTT·재전송: netns 안 veth에 netem으로 지연·손실을 넣고 관찰
#   13-3 TLS 평문: 같은 netns 쌍에서 openssl s_server ↔ curl, libssl에 uprobe
#
#   [netns ebpf13a] veth13a 192.0.2.1 ── veth ── veth13b 192.0.2.2 [netns ebpf13b]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

NS_A=ebpf13a NS_B=ebpf13b
for ns in "$NS_A" "$NS_B"; do
	if ip netns list | grep -qw "$ns"; then
		echo "FAIL: netns $ns 가 이미 있다. 이전 실행의 잔여물이면 'ip netns del $ns' 후 다시 실행"
		exit 1
	fi
done
for c in openssl curl tcpdump ethtool; do
	command -v "$c" >/dev/null || { echo "FAIL: $c 가 필요하다"; exit 1; }
done
libssl_of() { ldd "$(command -v "$1")" | awk '$1 ~ /^libssl\.so/ {print $3}'; }
LIBSSL_CURL=$(libssl_of curl) LIBSSL_SRV=$(libssl_of openssl)
[ -n "$LIBSSL_CURL" ] && [ -n "$LIBSSL_SRV" ] || { echo "FAIL: 13-3은 OpenSSL(libssl)을 쓰는 curl과 openssl이 필요하다"; exit 1; }
# 둘이 다른 libssl을 쓰면 둘 다에 붙인다
LIBSSL=$(printf '%s\n' "$LIBSSL_CURL" "$LIBSSL_SRV" | sort -u | paste -sd,)

LOG=$(mktemp) TMP=$(mktemp -d)
created=() bg="" srv="" dump=""
cleanup() { # 이번 실행에서 만든 것만 정리한다. 한 단계가 실패해도 나머지는 계속한다
	set +e
	for p in "$bg" "$srv" "$dump"; do [ -n "$p" ] && { kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; }; done
	rm -rf "$LOG" "$TMP"
	for ns in "${created[@]}"; do ip netns del "$ns" 2>/dev/null; done
	return 0
}
trap cleanup EXIT

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

echo "=== 13-1) 프로세스 트리: 셸 명령 하나와 그 자손의 fork/exec/exit"
./bin/proctree -- sh -c 'echo hi | tr a-z A-Z; (sleep 0.1; exit 3); sh -c "kill -TERM \$\$"; (sleep 0.3 &)'

ip netns add "$NS_A"; created+=("$NS_A")
ip netns add "$NS_B"; created+=("$NS_B")
ip link add veth13a netns "$NS_A" type veth peer name veth13b netns "$NS_B"
ip -n "$NS_A" addr add 192.0.2.1/24 dev veth13a
ip -n "$NS_B" addr add 192.0.2.2/24 dev veth13b
for ns in "$NS_A" "$NS_B"; do ip -n "$ns" link set lo up; done
ip -n "$NS_A" link set veth13a up
ip -n "$NS_B" link set veth13b up
# 큰 묶음(TSO/GSO)으로 보내면 netem이 묶음 단위로 버린다. 세그먼트 하나 단위로 버리도록 끈다
ip netns exec "$NS_A" ethtool -K veth13a tso off gso off >/dev/null
ip netns exec "$NS_A" ping -c1 -W1 192.0.2.2 >/dev/null # ARP 미리 채우기

echo
echo "=== 13-2) TCP RTT·재전송: veth13a 송신에 netem으로 지연(·손실)을 넣고 1 MiB 보내기"
ip netns exec "$NS_B" ./bin/tcpload serve -addr :5000 >"$TMP/srv" 2>&1 &
srv=$!
wait_ready "$TMP/srv" "$srv"
for q in "delay 20ms" "delay 20ms loss 2%"; do
	echo "--- netem: $q"
	ip netns exec "$NS_A" tc qdisc replace dev veth13a root netem $q
	./bin/tcpstat -netns /run/netns/"$NS_A" >"$LOG" 2>&1 &
	bg=$!
	wait_ready "$LOG" "$bg"
	ip netns exec "$NS_A" ./bin/tcpload send 192.0.2.2:5000 -bytes 1048576
	sleep 0.3
	kill -INT "$bg"; wait "$bg"; bg=""
	sed -n '2,$p' "$LOG"
done
ip netns exec "$NS_A" tc qdisc del dev veth13a root
kill "$srv"; wait "$srv" 2>/dev/null || true; srv=""
grep -v '^ready' "$TMP/srv"

echo
echo "=== 13-3) TLS 평문: curl(ebpf13a) → openssl s_server(ebpf13b), libssl에 uprobe"
echo "libssl: $LIBSSL"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=ebpf13 \
	-keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null
mkdir "$TMP/www"
printf 'demo-password=hunter2\n' >"$TMP/www/secret.txt"
(cd "$TMP/www" && exec ip netns exec "$NS_B" openssl s_server -quiet -accept 4433 \
	-cert "$TMP/cert.pem" -key "$TMP/key.pem" -WWW) >"$TMP/srv" 2>&1 &
srv=$!
ok=""
for _ in $(seq 50); do ip netns exec "$NS_B" ss -ltn | grep -q ':4433 ' && { ok=1; break; }; sleep 0.1; done
[ -n "$ok" ] || { cat "$TMP/srv"; echo "FAIL: TLS 서버가 준비되지 않았다"; exit 1; }
ip netns exec "$NS_B" tcpdump -i veth13b -U -w "$TMP/tls.pcap" tcp port 4433 2>/dev/null &
dump=$!
./bin/sslsniff -lib "$LIBSSL" -netns /run/netns/"$NS_A",/run/netns/"$NS_B" >"$LOG" 2>&1 &
bg=$!
wait_ready "$LOG" "$bg"
sleep 0.5 # tcpdump 준비
echo "--- curl이 받은 응답"
ip netns exec "$NS_A" curl -sk --http1.1 https://192.0.2.2:4433/secret.txt
sleep 0.3
kill -INT "$bg"; wait "$bg"; bg=""
kill "$dump"; wait "$dump" 2>/dev/null || true; dump=""
echo "--- sslsniff 출력"
sed -n '2,$p' "$LOG"
echo "--- 같은 통신을 tcpdump로 잡은 파일에서 평문 찾기"
echo "pcap 크기: $(stat -c %s "$TMP/tls.pcap") B, 'hunter2' 등장 횟수: $(grep -ac hunter2 "$TMP/tls.pcap" || true)"
