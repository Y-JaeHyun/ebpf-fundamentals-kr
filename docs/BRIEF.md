# ebpf-fundamentals-kr — 작업 브리프

## 목표
eBPF와 리눅스 커널 네트워킹의 **기초 체력 항목을 한국어로 빠르게 익힐 수 있는 학습 저장소**를 만든다. **공개(public)** 저장소다.
이 저장소만 순서대로 따라가면 각 항목을 "실무에서 읽고 쓸 수 있는" 수준까지 빠르게 이해하는 것이 목표다.

## 독자
Go나 C를 할 줄 알고 리눅스 운영 경험이 있지만, eBPF는 처음이거나 단편적으로만 아는 개발자.

## 커리큘럼 (초안 — 첫 단계에서 확정)
| # | 챕터 | 핵심 |
|---|---|---|
| 00 | 실습 환경 | 커널·BTF 확인, clang/bpftool/bpftrace, VM(Lima/Multipass) 대안, 권한 |
| 01 | eBPF 큰 그림 | 프로그램 → verifier → JIT → hook → map → 사용자 공간, 쓰임새 지도 |
| 02 | bpftrace로 맛보기 | one-liner 10선, 프로브 종류 |
| 03 | 프로그램 타입과 hook | kprobe/kretprobe, tracepoint, fentry/fexit, uprobe, USDT, XDP, TC, cgroup, LSM |
| 04 | Map과 데이터 전달 | hash/array/per-CPU/LRU/LPM, ring buffer vs perf buffer, 성능 차이 |
| 05 | Verifier | 동작 원리, 자주 보는 거부 메시지와 해결, 한도(명령어 수·스택·루프) |
| 06 | libbpf + CO-RE/BTF | vmlinux.h, BPF_CORE_READ, skeleton, 커널 버전 차이를 흡수하는 법 |
| 07 | Go: cilium/ebpf | bpf2go, 로드·attach, map 읽기, ring buffer 소비 — **주력 실습** |
| 08 | Rust: Aya 맛보기 | 같은 예제를 Aya로 작성해 보고 비교 |
| 09 | 커널 패킷 경로 | NIC → XDP → TC → netfilter → 소켓, 각 지점에서 할 수 있는 것 |
| 10 | XDP와 AF_XDP | drop/pass/redirect, 간단한 필터, AF_XDP 사용자 공간 처리 |
| 11 | TC와 cgroup 소켓 hook | egress 제어, connect4/sendmsg4로 연결 차단 |
| 12 | LSM-BPF | 활성화(`lsm=...,bpf`), file_open/bprm_check 예제, 차단 정책 |
| 13 | 관측 실전 패턴 | 프로세스 트리 추적, TCP RTT/재전송, uprobe로 TLS 평문 보기 |
| 14 | 디버깅과 성능 | bpftool prog/map, bpf_printk, 오버헤드 측정, 운영 배포 주의점 |
| 15 | 다음 단계 | 오픈소스 기여 지도(Cilium, Tetragon, Falco, OBI, libbpf), 블로그·발표·CFP 가이드 |

## 챕터 형식 (모든 챕터 공통)
- `chapters/NN-slug/README.md` 구성:
  1. **핵심 요약**(3줄)
  2. 개념 설명(그림은 mermaid)
  3. **실행 가능한 예제** 해설
  4. 직접 해보기(실습 과제)
  5. 자주 하는 실수
  6. 더 읽을거리(원문 링크)
- 예제 코드는 `chapters/NN-slug/code/`에 둔다. `make run`으로 한 번에 실행할 수 있게 하고, 실행 결과 예시를 README에 붙인다.
- **모든 예제는 이 머신(kernel 6.17)에서 실제로 빌드·실행해 확인한 것만 싣는다.** root가 필요한 실행은 사용자에게 `! sudo ...`를 요청해 결과를 받는다.

## 번역·출처 규칙
- 영어 자료는 **한국어로 번역하거나 재구성**해서 싣고, 각 섹션 끝에 원문 링크와 라이선스를 표기한다.
- 큰 분량을 그대로 번역해 옮기는 것은 원문 라이선스가 허용할 때만 한다(예: CC-BY 계열은 출처 표기 시 가능).
  - 라이선스가 불명확하면 **요약과 재서술**로 쓴다.
  - 커널 문서(GPL-2.0), ebpf.io, cilium/ebpf docs, libbpf-bootstrap 등의 라이선스는 챕터별로 확인해 기록한다.
- 용어는 처음 나올 때 `한국어(영어)`로 병기한다. 용어집은 `GLOSSARY.md`에 둔다.

## 공개 repo 주의
- **회사 관련 내용, 내부 경로, 사내 코드는 일절 넣지 않는다.** 일반 기술 자료만 싣는다.
- 기존 개인 공개 repo `Y-JaeHyun/eBPF_example`, `Y-JaeHyun/bpfEnv`(2022)에 재활용할 예제가 있으면 확인해서 갱신 후 가져온다.

## 진행 순서 (제안)
1. 커리큘럼 확정 + 저장소 골격(README 목차, GLOSSARY, 챕터 템플릿, 공통 Makefile)
2. 00~02 → 07(Go 실습)을 먼저 해서 손에 익히고, 나머지 챕터를 순서대로 채운다.
3. 챕터 하나가 끝날 때마다 커밋하고 push한다(public이니 깨진 예제를 올리지 않는다).
