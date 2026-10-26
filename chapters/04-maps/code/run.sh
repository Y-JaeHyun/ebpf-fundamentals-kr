#!/usr/bin/env bash
# 04장: map 종류별 동작 + 데이터 전달 방식 비교 (root)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")"

echo "##### 04-1 maptour"
./bin/maptour

echo
echo "##### 04-2 transfer: 기본 버퍼 (CPU당 64KB) — 조건마다 1~2분"
./bin/transfer -kb 64

echo
echo "##### 04-2 transfer: 작은 버퍼 (CPU당 4KB)"
./bin/transfer -kb 4

echo
echo "##### 04-2 transfer: 작은 버퍼 + 느린 소비자 (레코드당 2µs) — 유실이 생긴다"
./bin/transfer -kb 4 -delay 2us
