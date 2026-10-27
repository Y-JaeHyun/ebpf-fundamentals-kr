# 용어집 (GLOSSARY)

본문에서는 용어가 처음 나올 때 `한국어(영어)`로 함께 쓴다. 관례상 영어 그대로 쓰는 말(map, hook, verifier 등)은 번역하지 않고 영어로 둔다.
가나다/알파벳 순이 아니라 **학습 순서에 가깝게** 묶었다.

## 기본

| 용어 | 영어 | 뜻 | 처음 나오는 곳 |
|---|---|---|---|
| eBPF | extended Berkeley Packet Filter | 커널 안에서 검증된 작은 프로그램을 안전하게 실행하는 기술. 지금은 이름보다 기술 자체를 가리킨다 | 01 |
| BPF 프로그램 | BPF program | 커널 이벤트(hook)에 붙어 실행되는 eBPF 바이트코드 묶음. 보통 C로 쓰고 clang으로 컴파일 | 01 |
| 바이트코드 | bytecode | eBPF 가상 명령어 집합(64비트 레지스터 11개, 명령어 8바이트). `llvm-objdump -d`로 볼 수 있다 | 01 |
| 상태 가지치기 | state pruning | verifier가 이미 안전하다고 확인한 상태와 같은 상태를 다시 만나면 그 경로 검사를 건너뛰는 최적화 | 05 |
| 참조 | reference (acquired pointer) | ring buffer 예약·소켓 조회처럼 얻은 뒤 반드시 돌려줘야 하는 포인터. verifier가 모든 경로에서 반환을 확인 | 05 |
| `bpf_loop` | bpf_loop | 반복을 helper가 수행해 verifier가 루프를 펼치지 않게 하는 helper(5.17+) | 05 |
| verifier | verifier | 로드 시점에 프로그램이 안전한지(무한 루프·잘못된 메모리 접근 없음 등) 정적으로 검사하는 커널 구성 요소 | 01, 05 |
| JIT 컴파일러 | Just-In-Time compiler | 검증된 바이트코드를 CPU 기계어로 번역. `bpf_jit_enable` | 01 |
| hook | hook | BPF 프로그램을 붙이는 커널(또는 사용자 공간)의 지점. 시스템 콜, 함수 진입, 패킷 수신 등 | 01 |
| attach | attach | 로드한 프로그램을 hook에 연결하는 것 | 01 |
| link | BPF link | attach 상태를 나타내는 커널 객체. 파일 디스크립터나 핀이 사라지면 detach 된다 | 01, 07 |
| map | BPF map | 커널의 BPF 프로그램과 사용자 공간이 함께 읽고 쓰는 키-값 저장소 | 01, 04 |
| helper 함수 | helper function | BPF 프로그램이 호출할 수 있는 커널 제공 함수. 예: `bpf_map_lookup_elem`, `bpf_get_current_pid_tgid` | 01 |
| kfunc | kernel function | helper보다 새로운 확장 방식. BTF로 노출된 커널 함수를 직접 호출 | 03 |
| 컨텍스트 | context (ctx) | 프로그램에 첫 인자로 전달되는 이벤트 정보. 프로그램 타입마다 모양이 다르다 | 01 |
| 프로그램 타입 | program type | 프로그램이 어디에 붙고 무엇을 할 수 있는지 정하는 종류. kprobe, tracepoint, XDP 등 | 01, 03 |
| bpffs | BPF filesystem | `/sys/fs/bpf`. 프로그램·map·link를 파일로 고정(pin)해 프로세스가 끝나도 유지 | 00, 01 |
| 핀 | pin | 객체를 bpffs 경로에 고정하는 것. 핀을 지우면 참조가 사라진다 | 01 |

## 관측(tracing) hook

| 용어 | 영어 | 뜻 | 처음 나오는 곳 |
|---|---|---|---|
| kprobe / kretprobe | kernel probe | 커널 함수의 진입/반환 지점에 동적으로 붙는 hook. 함수 이름만 있으면 되지만 커널 버전에 따라 함수가 바뀔 수 있다 | 02, 03 |
| fentry / fexit | function entry/exit | BTF 기반 trampoline으로 커널 함수에 붙는 hook(5.5+). kprobe보다 빠르고 인자를 타입 그대로 읽는다 | 03 |
| tracepoint | tracepoint | 커널 개발자가 미리 심어 둔 정적 추적 지점. 형식이 비교적 안정적 | 01, 02 |
| raw tracepoint | raw tracepoint | 인자 가공 없이 받는 tracepoint. 오버헤드가 더 적다 | 03 |
| uprobe / uretprobe | user probe | 사용자 공간 프로그램·라이브러리 함수의 진입/반환 hook | 02, 03 |
| USDT | User Statically-Defined Tracing | 사용자 프로그램에 미리 심어 둔 정적 추적 지점 | 03 |
| BPF trampoline | BPF trampoline | fentry/fexit가 쓰는, 커널 함수 진입부에서 BPF 프로그램을 직접 부르는 작은 기계어 조각. kprobe보다 가볍다 | 03 |
| 금지 목록 | kprobe blacklist | kprobe를 붙일 수 없는 커널 함수 목록(`/sys/kernel/debug/kprobes/blacklist`) | 03 |
| perf 이벤트 | perf event | CPU 샘플링(profile)·하드웨어 카운터 등. bpftrace `profile:` | 02 |

## 데이터 전달

| 용어 | 영어 | 뜻 | 처음 나오는 곳 |
|---|---|---|---|
| ring buffer | BPF ring buffer | 모든 CPU가 공유하는 이벤트 전달용 버퍼(5.8+). 순서 보장, 예약(reserve) 후 제출(submit) | 07, 04 |
| perf buffer | perf event array | CPU별 버퍼로 이벤트를 전달하는 예전 방식 | 04 |
| per-CPU map | per-CPU map | CPU마다 값을 따로 두는 map. 원자 연산 없이 갱신하고 읽을 때 합산 | 07, 04 |
| LRU | Least Recently Used | 가득 차면 가장 오래 안 쓴 원소를 축출하는 map. 커널 구현은 근사 LRU | 04 |
| LPM | Longest Prefix Match | 가장 긴 prefix가 일치하는 항목을 찾는 조회. IP 대역 정책에 사용 | 04 |
| 깨우기 | wakeup | 버퍼에 데이터가 들어왔을 때 잠든 소비자(epoll)를 깨우는 일. 이벤트 전달 비용의 큰 부분 | 04 |
| 이벤트 유실 | lost / dropped events | 버퍼가 가득 차 버려진 이벤트. 반드시 세어서 보여 줘야 한다 | 07 |

## 이식성(portability)

| 용어 | 영어 | 뜻 | 처음 나오는 곳 |
|---|---|---|---|
| BTF | BPF Type Format | 커널·프로그램의 타입 정보(구조체 배치 등)를 담는 압축된 메타데이터. `/sys/kernel/btf/vmlinux` | 00, 06 |
| CO-RE | Compile Once – Run Everywhere | 한 번 컴파일한 프로그램이 구조체 배치가 다른 커널에서도 동작하도록, 로드 시점에 필드 오프셋을 다시 계산(재배치, relocation)하는 방식 | 07, 06 |
| vmlinux.h | vmlinux.h | 커널 BTF에서 뽑아 만든, 모든 커널 타입이 들어 있는 헤더 | 00, 01 |
| 재배치 | relocation | 로더가 오브젝트 안의 map 참조·필드 오프셋 등을 실제 값으로 고쳐 쓰는 과정 | 06 |
| skeleton | BPF skeleton | `bpftool gen skeleton`이 만드는 C 로더 코드 | 06 |
| flavor 구조체 | struct flavor | `struct task_struct___pre514`처럼 `___` 뒤에 꼬리를 붙여 옛 커널의 구조체 모양을 따로 선언한 것. libbpf는 꼬리를 떼고 같은 구조체로 재배치한다 | 06 |
| libbpf | libbpf | 커널 트리에서 함께 관리되는 C용 BPF 로더 라이브러리. CO-RE 재배치·skeleton·ring buffer API 제공 | 06 |
| bpf2go | bpf2go | cilium/ebpf의 도구. BPF C를 컴파일하고 Go 바인딩(구조체·로더)을 생성 | 07 |
| 로드 전 상수 | read-only global / `const volatile` | 로드 직전에 사용자 공간이 값을 정하는 전역 상수(.rodata). verifier가 값을 알아 죽은 분기를 제거 | 07 |

## 네트워크

| 용어 | 영어 | 뜻 | 처음 나오는 곳 |
|---|---|---|---|
| XDP | eXpress Data Path | NIC 드라이버 수준에서 패킷을 가장 먼저 처리하는 hook | 09, 10 |
| TC | Traffic Control | 커널 트래픽 제어 계층. `clsact`/`tcx`로 ingress·egress에 BPF를 붙인다 | 09, 11 |
| AF_XDP | AF_XDP socket | XDP에서 바로 사용자 공간 메모리로 패킷을 넘기는 소켓 | 10 |
| UMEM | user memory | AF_XDP 소켓에 등록한 사용자 공간 패킷 버퍼. 같은 크기의 칸으로 나눠 fill/rx 링으로 주고받는다 | 10 |
| XSKMAP | XSK map | XDP가 패킷을 보낼 AF_XDP 소켓을 고르는 map. key = 수신 큐 번호 | 10 |
| sk_buff | socket buffer | 커널 네트워크 스택의 패킷 구조체 | 09 |
| netns | network namespace | 독립된 네트워크 스택. 실습 샌드박스로 사용 | 09 |
| GRO | Generic Receive Offload | 같은 흐름의 수신 패킷을 묶어 위 계층에 한 번에 올리는 최적화 | 09 |
| NAPI | New API | 인터럽트 대신 폴링으로 수신 패킷을 묶어 처리하는 드라이버 방식. native XDP는 여기서 실행된다 | 09 |
| tcx | TC express | link 기반 TC attach(6.6+). qdisc 없이 붙고 프로세스가 끝나면 함께 떨어진다 | 09 |

## 보안

| 용어 | 영어 | 뜻 | 처음 나오는 곳 |
|---|---|---|---|
| LSM | Linux Security Modules | AppArmor·SELinux 등이 쓰는 커널 보안 hook 체계 | 12 |
| LSM-BPF | BPF LSM | LSM hook에 BPF 프로그램을 붙여 정책을 구현(5.7+, 부팅 인자 `lsm=` 에 `bpf` 필요) | 00, 12 |
| CAP_BPF | CAP_BPF | BPF 사용 권한을 root 전체(CAP_SYS_ADMIN)와 분리한 capability(5.8+) | 00 |
| lockdown | kernel lockdown | 커널 메모리 접근을 제한하는 LSM. `confidentiality` 모드면 추적 기능 대부분이 막힌다 | 00 |
