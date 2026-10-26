#!/usr/bin/env bash
# 08장: Aya execsnoop 실행 (root). make run은 이 스크립트를 tools/vm의 VM 안에서 실행한다.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

echo "=== Aya execsnoop: 4초 동안 UID 65534(nobody)가 실행하는 프로그램 추적"
./target/release/execsnoop -d 4 -uid 65534 &
snoop=$!
sleep 1.5
# 부하: nobody 권한으로 몇 개 실행 (07장 run.sh와 같은 명령)
setpriv --reuid=65534 --regid=65534 --clear-groups /bin/sh -c 'ls / >/dev/null; uname -r >/dev/null; /bin/echo ch08 >/dev/null'
wait "$snoop"
