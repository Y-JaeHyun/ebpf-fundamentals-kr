#!/usr/bin/env bash
# 03장: hook 종류별 이벤트 수·비용 비교 + USDT 맛보기 (root)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"
LIBC=$(readlink -f /lib/x86_64-linux-gnu/libc.so.6)

echo "=== 1) attach 가능 여부 확인"
echo "  vfs_read가 ftrace 대상 함수인가(=kprobe·fentry 가능): $(grep -cw '^vfs_read' /sys/kernel/tracing/available_filter_functions)개"
echo "  kprobe 금지 목록(blacklist) 크기: $(wc -l < /sys/kernel/debug/kprobes/blacklist)개"
echo "  syscalls:sys_enter_read 형식 (tracepoint 컨텍스트):"
sed -n '/^format:/,$p' /sys/kernel/tracing/events/syscalls/sys_enter_read/format | sed 's/^/    /'

echo
echo "=== 2) hook별 비교 (2~3분 걸린다)"
./bin/hookbench -hook all -n 500000 -r 5 -cpu 2

echo
echo "=== 3) USDT: libc에 심어진 정적 지점(stapsdt note) 목록 — 일부"
bpftrace -l "usdt:$LIBC:*" | sed -n '1,8p'

echo
echo "=== 4) USDT 비용: setjmp() 100만 번 (libc:setjmp 지점)"
# 라이브러리 USDT는 그 라이브러리를 쓰는 모든 프로세스에 붙는다. bench만 세도록 comm으로 거른다.
# (bpftrace -c 로 띄우면 자식이 libc를 아직 매핑하기 전이라 위치를 찾지 못한다)
export mode=setjmp cpu=2
echo "  probe 없음: $(echo go | ./bin/bench 1000000) ns/call"
BT_OUT=$(mktemp)
trap 'rm -f "$BT_OUT"' EXIT
bpftrace -e "usdt:$LIBC:libc:setjmp /comm == \"bench\"/ { @hits = count(); }" > "$BT_OUT" 2>&1 &
bt=$!
for _ in $(seq 50); do grep -q Attaching "$BT_OUT" && break; sleep 0.2; done
if ! grep -q Attaching "$BT_OUT"; then
	echo "  [FAIL] bpftrace가 USDT에 붙지 못했다:"; sed 's/^/    /' "$BT_OUT"; kill "$bt" 2>/dev/null || true; exit 1
fi
sleep 0.5
ns=$(echo go | ./bin/bench 1000000)
kill -INT "$bt"; wait "$bt" || true
echo "  USDT 사용: $ns ns/call, $(grep '@hits' "$BT_OUT")"
