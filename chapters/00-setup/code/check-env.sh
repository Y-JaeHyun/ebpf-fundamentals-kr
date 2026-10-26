#!/usr/bin/env bash
# eBPF 실습 환경 점검 스크립트 (root 불필요)
# 각 항목을 [OK] / [WARN] / [FAIL] 로 표시한다.
set -u

ok()   { printf '  [OK]   %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; FAILED=1; }
FAILED=0

KREL=$(uname -r)
CONFIG=""
for c in "/boot/config-$KREL" /proc/config.gz; do
  [ -r "$c" ] && CONFIG=$c && break
done

kconfig() { # kconfig CONFIG_NAME -> y / m / n
  local v
  if [ -z "$CONFIG" ]; then echo "?"; return; fi
  if [ "${CONFIG##*.}" = gz ]; then v=$(zcat "$CONFIG" | grep -E "^$1=" | cut -d= -f2)
  else v=$(grep -E "^$1=" "$CONFIG" | cut -d= -f2); fi
  echo "${v:-n}"
}

echo "== 커널"
echo "  버전: $KREL ($(uname -m))"
major=${KREL%%.*}; rest=${KREL#*.}; minor=${rest%%.*}
if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 8 ]; }; then
  ok "5.8 이상 (ring buffer, CAP_BPF 사용 가능)"
else
  warn "5.8 미만: ring buffer 등 일부 예제가 동작하지 않는다"
fi

echo "== BTF"
if [ -r /sys/kernel/btf/vmlinux ]; then
  ok "/sys/kernel/btf/vmlinux ($(stat -c %s /sys/kernel/btf/vmlinux) bytes) — CO-RE 사용 가능"
else
  fail "/sys/kernel/btf/vmlinux 없음 — CONFIG_DEBUG_INFO_BTF=y 커널 필요"
fi

echo "== 커널 설정 ($CONFIG)"
for opt in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_DEBUG_INFO_BTF \
           CONFIG_KPROBES CONFIG_UPROBES CONFIG_TRACEPOINTS CONFIG_FTRACE \
           CONFIG_BPF_EVENTS CONFIG_NET_CLS_BPF CONFIG_NET_SCH_INGRESS \
           CONFIG_XDP_SOCKETS CONFIG_CGROUP_BPF CONFIG_BPF_LSM; do
  v=$(kconfig "$opt")
  case $v in
    y|m) ok "$opt=$v" ;;
    \?)  warn "$opt: 커널 설정 파일을 찾지 못함" ;;
    *)   warn "$opt=n" ;;
  esac
done

echo "== 런타임 설정"
v=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "?")
case $v in
  0) warn "unprivileged_bpf_disabled=0: 일반 사용자도 일부 BPF 사용 가능(보안상 비권장)" ;;
  1|2) ok "unprivileged_bpf_disabled=$v: BPF 로드에 root(또는 CAP_BPF) 필요 — 정상" ;;
  *) warn "unprivileged_bpf_disabled 읽기 실패" ;;
esac
if [ -r /proc/sys/net/core/bpf_jit_enable ]; then
  v=$(cat /proc/sys/net/core/bpf_jit_enable)
  [ "$v" = 1 ] && ok "bpf_jit_enable=1 (JIT 사용)" || warn "bpf_jit_enable=$v"
else
  # CONFIG_BPF_JIT_ALWAYS_ON 이면 root만 읽을 수 있다
  [ "$(kconfig CONFIG_BPF_JIT_ALWAYS_ON)" = y ] && ok "CONFIG_BPF_JIT_ALWAYS_ON=y (JIT 항상 사용)" \
    || warn "bpf_jit_enable 읽기 불가(root 필요)"
fi
if grep -q ' /sys/fs/bpf bpf ' /proc/mounts; then ok "bpffs 마운트됨: /sys/fs/bpf"
else warn "bpffs 미마운트 — sudo mount -t bpf bpf /sys/fs/bpf"; fi
if grep -q ' /sys/kernel/tracing tracefs ' /proc/mounts || grep -q ' /sys/kernel/debug/tracing tracefs ' /proc/mounts; then
  ok "tracefs 마운트됨"
else warn "tracefs 미마운트"; fi
lock=$(grep -o '\[[a-z]*\]' /sys/kernel/security/lockdown 2>/dev/null | tr -d '[]')
case $lock in
  none) ok "lockdown=none" ;;
  integrity) warn "lockdown=integrity: 커널 메모리 쓰기 계열 helper 제한" ;;
  confidentiality) fail "lockdown=confidentiality: bpf_probe_read 등 추적 기능 대부분 차단" ;;
  *) warn "lockdown 상태 확인 불가" ;;
esac
lsm=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "?")
if [[ ",$lsm," == *",bpf,"* ]]; then ok "활성 LSM에 bpf 포함: $lsm"
else warn "활성 LSM에 bpf 없음($lsm) — 12장(LSM-BPF) 실습 시 부팅 인자 변경 필요"; fi

echo "== 도구"
tool() { # tool 이름 버전명령...
  local name=$1; shift
  if command -v "$name" >/dev/null 2>&1; then ok "$name: $("$@" 2>&1 | head -1)"
  else fail "$name 없음"; fi
}
tool clang    clang --version
tool llc      llc --version
tool bpftool  bpftool version
tool bpftrace bpftrace --version
tool go       go version
tool make     make --version
command -v llvm-objdump >/dev/null && ok "llvm-objdump: $(llvm-objdump --version | grep -m1 -i version)" \
  || warn "llvm-objdump 없음 (01장에서 바이트코드 보기에 사용)"

echo
if [ "$FAILED" = 0 ]; then echo "결과: 필수 항목 통과"; else echo "결과: 실패 항목이 있다"; exit 1; fi
