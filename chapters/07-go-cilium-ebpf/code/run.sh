#!/usr/bin/env bash
# 07장: 미리 빌드한 바이너리를 root로 실행한다(여기서는 go를 호출하지 않는다).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

echo "=== 07-1 counter: vfs_read 호출 수 (3초)"
./bin/counter -n 3

echo
echo "=== 07-2 execsnoop: 4초 동안 UID 65534(nobody)가 실행하는 프로그램 추적"
./bin/execsnoop -d 4s -uid 65534 &
snoop=$!
sleep 1.5
# 부하: nobody 사용자로 몇 개 실행 (UID 65534 로 보인다)
su -s /bin/sh nobody -c 'ls / >/dev/null; uname -r >/dev/null; /bin/echo ch07 >/dev/null'
wait "$snoop"   # execsnoop의 종료 코드를 그대로 돌려준다
