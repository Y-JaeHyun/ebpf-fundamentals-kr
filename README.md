# eBPF 기초 체력 (한국어)

eBPF와 리눅스 커널 네트워킹을 **한국어로, 실행 가능한 예제와 함께** 빠르게 익히기 위한 학습 저장소입니다.
순서대로 따라가면 eBPF 코드를 "실무에서 읽고 쓸 수 있는" 수준까지 가는 것을 목표로 합니다.

- **대상 독자**: Go나 C를 할 줄 알고 리눅스 운영 경험이 있지만, eBPF는 처음이거나 단편적으로만 아는 개발자
- **원칙**: 모든 예제는 실제 커널(6.17)에서 빌드·실행해 확인한 것만 싣고, 실행 결과를 함께 붙입니다.

## 목차

✅ 작성 완료 · 🚧 작성 예정

| # | 챕터 | 핵심 | 상태 |
|---|---|---|---|
| 00 | [실습 환경](chapters/00-setup/) | 커널·BTF·커널 설정 점검, clang/bpftool/bpftrace, 권한, VM 대안 | ✅ |
| 01 | [eBPF 큰 그림](chapters/01-big-picture/) | 프로그램 → verifier → JIT → hook → map → 사용자 공간, 쓰임새 지도 | ✅ |
| 02 | [bpftrace로 맛보기](chapters/02-bpftrace/) | one-liner 10선, 프로브 종류 | ✅ |
| 03 | [프로그램 타입과 tracing hook](chapters/03-tracing-hooks/) | kprobe/kretprobe, fentry/fexit, tracepoint/raw_tp, uprobe, USDT + 프로그램 타입 전체 지도 | ✅ |
| 04 | [Map과 데이터 전달](chapters/04-maps/) | hash/array/per-CPU/LRU/LPM, ring buffer vs perf buffer, 성능 차이 | ✅ |
| 05 | [Verifier](chapters/05-verifier/) | 동작 원리, 자주 보는 거부 메시지와 해결, 한도(명령어 수·스택·루프) | ✅ |
| 06 | [libbpf + CO-RE/BTF](chapters/06-libbpf-core/) | vmlinux.h, BPF_CORE_READ, skeleton, 커널 버전 차이 흡수 | ✅ |
| 07 | [Go: cilium/ebpf](chapters/07-go-cilium-ebpf/) | bpf2go, 로드·attach, map 읽기, ring buffer 소비, 로드 전 상수 주입 — **주력 실습** | ✅ |
| 08 | [Rust: Aya 맛보기](chapters/08-rust-aya/) *(선택)* | 같은 예제를 Aya로 작성해 비교 — Docker로 빌드, VM에서 실행 | ✅ |
| 09 | 커널 패킷 경로 | NIC → XDP → TC → netfilter → 소켓, 각 지점에서 할 수 있는 것 | 🚧 |
| 10 | XDP와 AF_XDP | drop/pass/redirect, 간단한 필터, AF_XDP 사용자 공간 처리 | 🚧 |
| 11 | TC와 cgroup 소켓 hook | egress 제어, connect4/sendmsg4로 연결 차단 | 🚧 |
| 12 | LSM-BPF | 활성화(`lsm=...,bpf`), file_open/bprm_check 예제, 차단 정책 | 🚧 |
| 13 | 관측 실전 패턴 | 프로세스 트리 추적, TCP RTT/재전송, uprobe로 TLS 평문 보기 | 🚧 |
| 14 | 디버깅과 성능 | bpftool prog/map 심화, bpf_printk, 오버헤드 측정, 운영 배포 주의점 | 🚧 |
| 15 | 다음 단계 | 오픈소스 기여 지도(Cilium, Tetragon, Falco, libbpf 등), 블로그·발표 가이드 | 🚧 |
| A | 부록: 커널 버전별 기능 표 | ring buffer(5.8), fentry(5.5), BPF 링크 등 "몇 버전부터 되나" | 🚧 |

**추천 경로**: 00 → 01 → 02 → 07(Go로 직접 만들어 보기) → 03~06(원리 보강) → 09~12(네트워크·보안) → 13~15.
07장은 06장(CO-RE)보다 먼저 읽어도 되도록 필요한 최소 개념을 본문에 담았습니다.

네트워크 챕터(09~11)는 호스트 NIC를 건드리지 않도록 network namespace + veth 샌드박스에서만 실습합니다.

## 빠른 시작

```bash
git clone https://github.com/Y-JaeHyun/ebpf-fundamentals-kr.git
cd ebpf-fundamentals-kr
make check     # 환경 점검 (root 불필요)
make build     # vmlinux.h 생성 + 모든 예제 빌드 (root 불필요)

# 실행은 root 필요: 챕터별로 (실행 단계에만 내부에서 sudo가 붙는다)
make -C chapters/01-big-picture/code run
# 또는 여러 챕터를 한 번에 (결과는 chapters/NN-*/code/out/run.log)
sudo ./scripts/run-chapters.sh 00 01 02 07
```

## 저장소 구조

```
chapters/NN-slug/README.md   챕터 본문 (형식: docs/CHAPTER_TEMPLATE.md)
chapters/NN-slug/code/       예제 코드 — make build / make run
include/bpf/                 libbpf 헤더 사본 (libbpf-dev 없이 빌드)
include/vmlinux.h            make vmlinux 로 생성 (커밋 안 함)
mk/common.mk                 챕터 Makefile 공통 규칙
scripts/run-chapters.sh      root 실습 일괄 실행
tools/vm/                    호스트 커널을 KVM VM으로 부팅해 실행 (08·12장, sudo 불필요)
tools/aya/                   Rust Aya 빌드용 Docker 이미지 (08장)
tools/bench/                 03·04장 공용 부하 프로그램(read 반복, CPU 고정)
GLOSSARY.md                  용어집 (한국어 ↔ 영어)
```

## 검증 환경

| 항목 | 버전 |
|---|---|
| OS / 커널 | Ubuntu 24.04, Linux 6.17 (x86_64, BTF 있음) |
| 컴파일러 | clang 18 |
| 도구 | bpftool v7.7 (libbpf 1.7), bpftrace 0.20 |
| Go | Go 1.26, cilium/ebpf v0.22.0 |

다른 커널에서도 대부분 동작하지만, 결과 예시는 위 환경 기준입니다. 커널 5.8 미만에서는 ring buffer 예제가 동작하지 않습니다.

## 라이선스

- **문서**(`*.md`): [CC BY-SA 4.0](LICENSE-docs)
- **코드**: [MIT](LICENSE). 단 BPF C 코드(`*.bpf.c`)는 GPL 전용 helper를 쓸 수 있도록 `MIT OR GPL-2.0` 이중 라이선스입니다.
- `include/bpf/`의 libbpf 헤더는 원본 라이선스(`LGPL-2.1 OR BSD-2-Clause`)를 따릅니다. → [include/README.md](include/README.md)
- 외부 자료를 번역·재서술한 부분은 각 챕터의 "더 읽을거리"에 원문 링크와 라이선스를 표기합니다.
