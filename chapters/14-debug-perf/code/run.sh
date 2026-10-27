#!/usr/bin/env bash
# 14장: bpftool로 들여다보기, bpf_printk, hook별 오버헤드 측정 (root)
# bpftool은 항상 이 실행이 만든 객체의 id만 지정해서 본다(호스트의 다른 BPF 프로그램은 출력하지 않는다).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"
command -v bpftool >/dev/null || { echo "FAIL: bpftool이 필요하다"; exit 1; }

LOG=$(mktemp) bg=""
cleanup() {
	set +e
	[ -n "$bg" ] && { kill "$bg" 2>/dev/null; wait "$bg" 2>/dev/null; }
	rm -f "$LOG"
	return 0
}
trap cleanup EXIT

echo "=== 14-1) bpftool로 실행 중인 프로그램 들여다보기"
./bin/dbg hold -d 30s >"$LOG" 2>&1 &
bg=$!
for _ in $(seq 50); do grep -q '^ready' "$LOG" && break; kill -0 "$bg" 2>/dev/null || break; sleep 0.1; done
grep -q '^ready' "$LOG" || { cat "$LOG"; echo "FAIL: 준비되지 않았다"; exit 1; }
read -r prog map link < <(sed -nE 's/^ready prog=([0-9]+) map=([0-9]+) link=([0-9]+)$/\1 \2 \3/p' "$LOG")
# 출력의 id는 실행마다 달라서 명령 줄에서는 <PROG> 등으로 바꿔 보여 준다. 실패해도 다음 명령을 계속한다
run() {
	echo "\$ $*" | sed -E "s/ id $prog\b/ id <PROG>/; s/ id $map\b/ id <MAP>/; s/ id $link\b/ id <LINK>/"
	"$@" || echo "(종료 코드 $?)"
}
run bpftool prog show id "$prog"
run bpftool link show id "$link"
run bpftool map dump id "$map"
run bpftool prog dump xlated id "$prog"
kill "$bg"; wait "$bg" 2>/dev/null || true; bg=""

echo
echo "=== 14-2) bpf_printk: 출력은 커널 trace 버퍼로 간다"
TRACE=/sys/kernel/tracing/trace
[ -r "$TRACE" ] || TRACE=/sys/kernel/debug/tracing/trace
out=$(./bin/dbg printk)
echo "$out"
pid=${out##*pid=}
# trace 파일은 읽어도 지워지지 않는다(trace_pipe와 다름). 이번 실행(pid)이 남긴 줄만 고른다
echo "--- $TRACE 에서 'ebpf14: getppid pid=$pid' 줄"
grep "ebpf14: getppid pid=$pid " "$TRACE" || echo "(없음)"

echo
echo "=== 14-3) 같은 시스템 콜에 hook 종류만 바꿔 붙였을 때 비용"
./bin/dbg bench
