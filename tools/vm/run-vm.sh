#!/usr/bin/env bash
# 호스트 커널을 KVM VM으로 부팅해 명령 하나를 root로 실행한다 (Docker 컨테이너 안의 qemu + virtme-ng).
#
#   tools/vm/run-vm.sh [--lsm-bpf] '<명령>'
#
# - 게스트는 호스트와 같은 커널 이미지(/boot/vmlinuz-$(uname -r))로 부팅한다. 부팅 인자만 다르다.
# - 저장소가 게스트의 /work 에 마운트된다. 게스트 안에서 만든 파일은 끝나고 현재 사용자 소유로 돌려 둔다.
# - --lsm-bpf: LSM 목록에 bpf를 넣어 부팅한다(12장). 호스트 재부팅 없이 LSM-BPF를 써 볼 수 있다.
# 필요: x86_64 호스트, Docker, /dev/kvm. 호스트 sudo는 필요 없다(Docker 데몬이 /dev/kvm을 넘겨준다).
# 주의: 저장소 전체가 게스트 root에게 쓰기 가능으로 보인다. 신뢰하는 스크립트만 실행한다.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
# 태그에 Dockerfile 해시를 넣어 Dockerfile이 바뀌면 새로 빌드한다
image=ebpf-fundamentals-vm:$(sha256sum "$here/Dockerfile" | cut -c1-12)

append=""
if [ "${1:-}" = "--lsm-bpf" ]; then
	# 현재 LSM 목록 맨 뒤에 bpf를 붙인다. (ima·evm은 부팅 인자와 무관하게 항상 뒤에 붙는다)
	cur=$(tr ',' '\n' </sys/kernel/security/lsm | grep -vxE 'ima|evm|bpf' | paste -sd,)
	append="lsm=$cur,bpf"
	shift
fi
[ $# -eq 1 ] || { echo "사용법: $0 [--lsm-bpf] '<명령>'"; exit 1; }

docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" "$here" >/dev/null

kver=$(uname -r)
exec docker run --rm --device /dev/kvm \
	-v /boot:/boot:ro -v /lib/modules:/lib/modules:ro -v "$repo":/work \
	"$image" bash -c '
		touch /tmp/started
		vng --run "/boot/vmlinuz-$1" --memory 2G --cpus 2 --rwdir /work ${2:+--append "$2"} --exec "cd /work && $3"
		rc=$?
		# 이번 실행 중 게스트(root)가 만든 파일만 호출한 사용자 소유로 돌린다. .git은 건드리지 않고 링크는 따라가지 않는다
		find /work -xdev -path /work/.git -prune -o -uid 0 -newer /tmp/started -exec chown -h "$4" {} + 2>/dev/null
		exit $rc' _ "$kver" "$append" "$1" "$(id -u):$(id -g)"
