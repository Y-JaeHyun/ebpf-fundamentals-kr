#!/usr/bin/env bash
# 05장: 사례마다 bad는 verifier가 거부하고 good은 통과하는지 확인하고, 거부 메시지를 보여 준다. (root)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"
mkdir -p out
PIN=/sys/fs/bpf/ch05
trap 'rm -f "$PIN"' EXIT
FAIL=0
# 이 커널(6.3+)에서 특권 프로그램에는 허용되는 사례. 통과해도 실패로 보지 않는다.
ALLOWED_BAD="03-uninit-stack"

# load <오브젝트> <로그 파일> [-d]: 성공하면 0.
# 실패하면 libbpf가 verifier 로그를 출력한다. 성공한 경우 통계(processed N insns)를 보려면 -d.
load() {
	rm -f "$PIN"
	bpftool ${3:-} prog load "$1" "$PIN" > "$2" 2>&1 && rm -f "$PIN"
}

# verifier 로그 본문만: libbpf 접두어가 없는 줄
vlog() { grep -v '^libbpf:' "$1" | grep -v -E '^\s*$' || true; }

for bad in obj/*.bad.o; do
	name=$(basename "$bad" .bad.o)
	good=obj/$name.good.o
	echo "=== $name"
	if load "$bad" "out/$name.bad.log"; then
		if [[ " $ALLOWED_BAD " == *" $name "* ]]; then
			echo "  bad : 통과(!) — 이 커널은 이 코드를 허용한다(예상한 결과)"
		else
			echo "  bad : [FAIL] 거부돼야 하는데 통과했다"; FAIL=1
		fi
	else
		echo "  bad : 거부 — 마지막 메시지:"
		vlog "out/$name.bad.log" | grep -v -E '^(processed|verification time|stack depth|--)' | tail -3 | sed 's/^/        /'
	fi
	if load "$good" "out/$name.good.log" -d; then
		echo "  good: 통과 — $(vlog "out/$name.good.log" | grep -m1 -E '^processed' || echo '')"
	else
		echo "  good: [FAIL] 고친 버전도 거부됨"; FAIL=1
		vlog "out/$name.good.log" | tail -5 | sed 's/^/        /'
	fi
done

echo "=== 08-stack-limit"
echo "  bad : clang 단계에서 거부:"
grep -m1 error obj/08-stack-limit.bad.clang.txt | sed 's/^/        /'
if load obj/08-stack-limit.good.o out/08-stack-limit.good.log -d; then
	echo "  good: 통과 — $(vlog out/08-stack-limit.good.log | grep -m1 -E '^processed' || echo '')"
else
	echo "  good: [FAIL]"; FAIL=1
fi

[ "$FAIL" = 0 ] && echo "결과: 예상대로 (bad 거부, good 통과)" || { echo "결과: 실패 있음"; exit 1; }
