#!/usr/bin/env bash
# 01장: 컴파일된 오브젝트를 bpftool로 로드 → verifier/JIT 결과 확인 → attach → map/로그 확인 → 정리
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"
mkdir -p out
PIN=/sys/fs/bpf/ch01   # 이 실습 전용 경로. 시작·종료 시 지운다
TRACE_OUT=$(mktemp)
cleanup() { rm -rf "$PIN"; }
trap 'cleanup; rm -f "$TRACE_OUT"' EXIT
trap cleanup EXIT
cleanup

echo "== 1) 로드 + 자동 attach (verifier 통과 시에만 성공)"
bpftool prog loadall hello.bpf.o "$PIN" autoattach
ls -1 "$PIN" | sed 's/^/  /'

echo "== 2) 커널에 올라간 프로그램 정보"
bpftool prog show name count_execve

echo "== 3) verifier가 고쳐 쓴 뒤의 명령어(xlated) — 앞부분"
bpftool prog dump xlated name count_execve | sed -n "1,12p"

echo "== 4) JIT 결과"
# 배포판 bpftool은 LLVM 역어셈블러 없이 빌드된 경우가 많아 jited 덤프가 실패할 수 있다.
if jit=$(bpftool prog dump jited name count_execve 2>&1); then
	echo "$jit" | sed -n "1,8p"
else
	echo "  (이 bpftool은 JIT 역어셈블을 지원하지 않는다) 크기만 확인:"
	bpftool prog show name count_execve | grep -oE 'xlated [0-9]+B +jited [0-9]+B' | sed 's/^/  /'
fi
echo "== 5) 이벤트 발생: nobody 사용자로 명령 실행"
TRACE=/sys/kernel/tracing/trace_pipe
timeout 3 cat "$TRACE" > "$TRACE_OUT" &
sleep 0.5
su -s /bin/sh nobody -c '/bin/true; /bin/true' || true
sleep 1
wait || true

echo "== 6) map 내용 (key=uid, value=횟수) — 시스템 전체 execve가 집계된다"
bpftool map dump name exec_count

echo "== 7) bpf_printk 출력 (trace_pipe) — 이 예제가 남긴 줄만"
grep -E 'execve by uid=65534' "$TRACE_OUT" | sed -n "1,5p" | sed -E 's/^ +//'

echo "== 8) 정리: 핀 파일을 지우면 link가 해제되고 프로그램도 내려간다"
cleanup
bpftool prog show name count_execve 2>/dev/null || echo "  count_execve 없음 — 내려갔다"

echo "== 9) 일부러 실패시키기 ① NULL 검사 제거 (bad-null.bpf.o)"
# reject <오브젝트> <로그> <기대 메시지>: 로드가 "실패해야" 성공
reject() {
	if bpftool prog loadall "$1" "$PIN" > "$2" 2>&1; then
		echo "  [FAIL] verifier가 $1 을 받아들였다"; cleanup; exit 1
	fi
	grep -qE "$3" "$2" || { echo "  [FAIL] 기대한 메시지 없음: $3"; exit 1; }
	cleanup
}
reject bad-null.bpf.o out/bad-null.log "invalid mem access 'map_value_or_null'"
grep -E "invalid mem access|^[0-9]+: \(" out/bad-null.log | tail -3
echo "== 10) 일부러 실패시키기 ② GPL이 아닌 라이선스 (bad-license.bpf.o)"
reject bad-license.bpf.o out/bad-license.log "GPL-restricted"
grep -E "GPL-restricted" out/bad-license.log | sed -n "1,3p"
