#!/usr/bin/env bash
# root 권한이 필요한 점검: 실제로 BPF 프로그램을 로드할 수 있는지 확인한다.
set -eu
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다: sudo $0"; exit 1; }

echo "== 1) bpftrace로 최소 프로그램 실행"
bpftrace -e 'BEGIN { printf("hello from bpftrace (pid %d)\n", pid); exit(); }'

echo "== 2) bpftool feature probe — 주요 항목만 발췌"
bpftool feature probe kernel 2>/dev/null | grep -E \
  "JIT compiler is enabled|eBPF program_type (kprobe|tracepoint|xdp|sched_cls|lsm|tracing) is|eBPF map_type (hash|array|ringbuf|lru_hash|lpm_trie|percpu_array) is|bpf_ringbuf_reserve|bpf_loop" \
  | sed 's/^/  /' | sort -u

echo "== 3) 현재 로드된 BPF 프로그램 수"
echo "  $(bpftool prog show | grep -c '^[0-9]*:') 개 (systemd 등이 이미 쓰고 있을 수 있다)"
