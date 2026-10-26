# tools/vm — 호스트 커널을 KVM VM으로 부팅해 실습하기

호스트 재부팅이나 sudo 없이, **호스트와 같은 커널 이미지를 부팅 인자만 바꿔** 띄우고 그 안에서 root로 명령을 실행한다.
Docker 컨테이너 안의 qemu + [virtme-ng](https://github.com/arighi/virtme-ng)(GPL-2.0, 도구로만 사용)를 쓴다.

```bash
tools/vm/run-vm.sh 'uname -r; id'                     # 기본 부팅
tools/vm/run-vm.sh --lsm-bpf 'cat /sys/kernel/security/lsm'   # LSM 목록에 bpf 추가(12장)
```

| 항목 | 내용 |
|---|---|
| 필요 | x86_64 호스트, Docker, `/dev/kvm` (CPU 가상화). 사용자가 `/dev/kvm`에 직접 접근하지 못해도 Docker 데몬이 넘겨준다 |
| 커널 | 호스트의 `/boot/vmlinuz-$(uname -r)`, 모듈은 호스트 `/lib/modules` (읽기 전용) |
| 루트 파일시스템 | 이미지(Ubuntu 24.04 최소 구성)의 `/` (읽기 전용 + 임시 쓰기 영역) |
| 저장소 | 게스트의 `/work` (쓰기 가능). 게스트가 root로 만든 파일은 끝나고 호출한 사용자 소유로 돌려 둔다(`.git` 제외). 저장소 전체가 게스트 root에게 쓰기 가능하니 신뢰하는 스크립트만 실행한다 |
| 사용하는 장 | 08(Aya 실행), 12(LSM-BPF) |

게스트에는 clang·Go가 없다. 호스트에서 빌드한 **정적 링크 바이너리**(Go)나 glibc 호환 바이너리(Rust)를 `/work`에서 실행한다.
