#!/usr/bin/env bash
# 02장: one-liner 10개를 차례로 실행한다.
# 각 스크립트는 bpftrace -c 로 "부하 명령"을 직접 띄워, 프로브가 붙은 뒤 명령을 실행하고
# 명령이 끝나면 bpftrace도 종료하면서 map을 출력한다.
# 출력이 시스템 전체를 보여 주므로, 결과 예시는 부하 명령과 관련된 줄만 걸러 보여 준다.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "root로 실행해야 한다"; exit 1; }
cd "$(dirname "$0")/oneliners"
W=$(cd ../workloads && pwd)  # bpftrace -c 는 절대 경로의 ELF 실행 파일을 받으므로 셸을 앞에 둔다
FAIL=0

# run <스크립트> <부하 명령> <출력 필터(grep -E, 빈 값이면 전체)> [최대 줄 수]
run() {
	local bt=$1 cmd=$2 filter=$3 max=${4:-15} out
	echo "=== $bt  (부하: $cmd)"
	out=$(timeout 60 bpftrace -c "$cmd" "$bt" 2>&1); local rc=$?
	if [ $rc -ne 0 ]; then
		echo "  [FAIL] 종료 코드 $rc"; echo "$out" | sed -n "1,20p" | sed 's/^/  | /'; FAIL=1; return
	fi
	if [ -n "$filter" ]; then out=$(echo "$out" | grep -E "$filter"); fi
	# "Attaching …" 줄 말고 실제 결과가 하나도 없으면 실패로 본다
	if ! echo "$out" | grep -vq '^Attaching'; then
		echo "  [FAIL] 기대한 출력이 없다"; FAIL=1
	fi
	echo "$out" | sed -n "1,${max}p"
}

echo "=== 02-list (프로브 목록 검색)"
bpftrace -l 'tracepoint:syscalls:sys_enter_exec*' || FAIL=1
n=$(bpftrace -l 'kprobe:tcp_*' | wc -l) || FAIL=1
echo "  kprobe:tcp_* 개수: $n"
bpftrace -lv 'tracepoint:syscalls:sys_enter_execve' || FAIL=1

run 01-hello.bt          "/bin/true"                                               ""
run 03-execsnoop.bt      "/bin/sh $W/exec-some.sh" "Attaching| sh +/usr/bin/(ls|uname|date)"
run 04-syscount.bt       "dd if=/dev/zero of=/dev/null bs=1 count=20000 status=none" "Attaching|@syscalls\[dd\]"
run 05-opensnoop.bt      "cat /etc/os-release"                                     "Attaching|^cat "
run 06-readsize.bt       "dd if=/dev/zero of=/dev/null bs=4k count=1000 status=none" "" 25
run 07-vfsread-latency.bt "dd if=/dev/zero of=/dev/null bs=64k count=2000 status=none" "" 25
run 08-tcpconnect.bt     "/bin/bash $W/tcp-connect.sh" "Attaching|@connects\[bash\]"
run 09-getaddrinfo.bt    "getent ahosts localhost"                                 "Attaching|^getent "
run 10-profile.bt        "dd if=/dev/zero of=/dev/null bs=1M count=20000 status=none" "Attaching|@samples\[dd\]"

echo
[ "$FAIL" = 0 ] && echo "결과: 전체 성공" || { echo "결과: 실패 있음"; exit 1; }
