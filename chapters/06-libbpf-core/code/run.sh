#!/usr/bin/env bash
# 06장: CO-RE 재배치 로그 확인 + exitsnoop 실행 (root)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

echo "=== 1) libbpf 디버그 로그에서 CO-RE 재배치 부분만"
./exitsnoop -v -d 1 -u 65534 2>&1 >/dev/null | grep -E "CO-RE|relo #" | sed -n "1,40p" || true

echo
echo "=== 2) nobody(UID 65534)의 프로세스 종료 추적 (3초)"
./exitsnoop -d 3 -u 65534 &
snoop=$!
sleep 1
su -s /bin/sh nobody -c 'sleep 0.3; exit 3'  || true
su -s /bin/sh nobody -c 'kill -TERM $$'        || true
su -s /bin/sh nobody -c '/bin/true'
wait "$snoop"

echo
echo "=== 3) -m 200: 200ms 이상 산 프로세스만"
./exitsnoop -d 3 -u 65534 -m 200 &
snoop=$!
sleep 1
su -s /bin/sh nobody -c 'sleep 0.1'
su -s /bin/sh nobody -c 'sleep 0.4'
wait "$snoop"
