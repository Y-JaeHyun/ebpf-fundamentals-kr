#!/usr/bin/env bash
# 여러 챕터의 root 실습을 한 번에 실행한다. 빌드는 미리 일반 사용자로 해 둔다(make build).
#   sudo ./scripts/run-chapters.sh 00 01 02 07
# 각 챕터 결과는 chapters/NN-*/code/out/run.log 에 남는다.
set -u
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다: sudo $0 $*"; exit 1; }
cd "$(dirname "$0")/.."
[ $# -gt 0 ] || set -- $(ls -d chapters/*/code | sed -E 's#chapters/([0-9]+)-.*#\1#')

rc=0
for n in "$@"; do
	dir=$(ls -d chapters/"$n"-*/code 2>/dev/null | head -1)
	[ -n "$dir" ] || { echo "챕터 $n 없음"; rc=1; continue; }
	echo "##### $dir"
	make -s -C "$dir" run SUDO= || rc=1
	# root로 만든 로그·산출물을 원래 사용자 소유로 돌려 놓는다
	if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:$SUDO_GID" "$dir"; fi
done
exit $rc
