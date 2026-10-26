# include/

| 파일 | 출처 | 라이선스 |
|---|---|---|
| `bpf/bpf_helpers.h`, `bpf/bpf_helper_defs.h`, `bpf/bpf_tracing.h`, `bpf/bpf_core_read.h`, `bpf/bpf_endian.h` | [libbpf v1.7.0](https://github.com/libbpf/libbpf/tree/v1.7.0/src) 원본 그대로 | `LGPL-2.1 OR BSD-2-Clause` ([bpf/LICENSE.BSD-2-Clause](bpf/LICENSE.BSD-2-Clause)) |
| `vmlinux.h` | **커밋하지 않는다.** `make vmlinux`가 실행 중인 커널의 `/sys/kernel/btf/vmlinux`에서 생성 | — |

시스템에 `libbpf-dev`가 없어도 예제를 빌드할 수 있도록 헤더만 복사해 두었다.
갱신하려면 libbpf 릴리스의 `src/` 아래 같은 이름의 파일로 교체한다.
