#!/usr/bin/env bash
# 12장: LSM-BPF로 파일 열기·실행 막기 (root)
# make run은 LSM 목록에 bpf를 넣어 부팅한 VM 안에서, make run-host는 호스트에서 이 스크립트를 실행한다.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

D=$(mktemp -d)
LOG=$(mktemp)
trap 'rm -rf "$D" "$LOG"' EXIT
echo "top secret" >"$D/secret.txt"
ln "$D/secret.txt" "$D/secret-hardlink.txt" # 같은 inode, 다른 이름
cp /bin/true "$D/blocked-true"
cp /bin/true "$D/copied-true"               # 내용은 같지만 다른 inode

try() { # try <설명> <명령...>: 성공/실패와 에러 메시지만 한 줄로
	local what=$1 err
	shift
	if err=$("$@" 2>&1 >/dev/null); then
		echo "  [성공] $what"
	else
		echo "  [실패] $what — ${err##*: }"
	fi
}

experiment() {
	try "secret.txt 읽기" cat "$D/secret.txt"
	try "하드링크(secret-hardlink.txt) 읽기" cat "$D/secret-hardlink.txt"
	try "blocked-true 실행" "$D/blocked-true"
	try "복사본(copied-true) 실행" "$D/copied-true"
}

start_guard() { # start_guard [옵션...]: 백그라운드로 띄우고 attach될 때까지 기다린다
	./bin/lsmguard -open "$D/secret.txt" -exec "$D/blocked-true" -d 2s ${ALLOW_INACTIVE:+-allow-inactive} "$@" >"$LOG" 2>&1 &
	guard=$!
	for _ in $(seq 50); do
		grep -q '^ready' "$LOG" && return 0
		kill -0 "$guard" 2>/dev/null || break
		sleep 0.1
	done
	cat "$LOG"
	echo "FAIL: lsmguard가 시작되지 않았다"
	exit 1
}

echo "=== 0) 활성화된 LSM 목록 (/sys/kernel/security/lsm)"
echo "  $(cat /sys/kernel/security/lsm)"

echo
echo "=== 1) 정책 없이"
experiment

echo
echo "=== 2) enforce 모드: secret.txt 열기, blocked-true 실행을 막는다"
start_guard
experiment
wait "$guard"
grep -v '^ready' "$LOG"

echo
echo "=== 3) audit 모드: 막지 않고 기록만"
start_guard -audit
experiment
wait "$guard"
grep -v '^ready' "$LOG"

echo
echo "=== 4) 프로그램이 끝난 뒤 (link가 닫혀 정책도 사라진다)"
experiment
