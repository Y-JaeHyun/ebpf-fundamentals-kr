# 부록 A. 커널 버전별 기능 표

> **핵심 요약**
> 1. "이 기능은 몇 버전부터 되나"를 이 저장소의 장 순서대로 정리했다. 버전 값은 **커널 UAPI 헤더(`include/uapi/linux/bpf.h`)에 그 상수가 처음 들어간 릴리스**를 태그별로 직접 대조해 정했다. 헤더로 판단할 수 없는 항목은 해당 버전의 커널 소스나 BCC 문서의 커밋 링크로 확인했다.
> 2. 버전 번호는 출발점일 뿐이다. 배포판 커널은 **기능을 뒤로 옮겨 넣기도(백포트), 빌드 옵션으로 끄기도** 한다. 실제로 쓸 수 있는지는 대상 장비에서 `bpftool feature probe`와 BTF 유무로 확인하자.
> 3. 이 저장소는 6.17에서 확인했다. 아래 표에서 6.6 이후 기능(tcx 등)을 쓰는 장은 그보다 오래된 커널에서 그대로 동작하지 않는다.

## 1. 장별 기능과 최소 버전

### 1.1 기반

| 기능 | 최소 버전 | 이 저장소 | 확인 근거 |
|---|---|---|---|
| `bpf()` 시스템 콜, hash/array map | 3.18 / 3.19 | 01 | `BPF_MAP_TYPE_HASH`가 3.19 헤더에 처음 등장 |
| kprobe 프로그램, TC(`cls_bpf`) 프로그램 | 4.1 | 03, 09 | `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_SCHED_CLS` |
| bpffs에 pin | 4.4 | 10 | `BPF_OBJ_PIN` |
| per-CPU hash/array | 4.6 | 04 | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| tracepoint 프로그램 | 4.7 | 03 | `BPF_PROG_TYPE_TRACEPOINT` |
| LRU hash | 4.10 | 04 | `BPF_MAP_TYPE_LRU_HASH` |
| LPM trie | 4.11 | 04 | `BPF_MAP_TYPE_LPM_TRIE` |
| 프로그램·map id와 정보 조회(bpftool `show`의 바탕) | 4.13 | 14 | `BPF_PROG_GET_NEXT_ID`, `BPF_OBJ_GET_INFO_BY_FD` |
| raw tracepoint | 4.17 | 03, 14 | `BPF_PROG_TYPE_RAW_TRACEPOINT` |
| BTF | 4.18 | 06 | `BPF_BTF_LOAD` |
| 커널 BTF(`/sys/kernel/btf/vmlinux`) — CO-RE에 필요한 대상 커널 BTF를 얻는 일반적인 경로(없으면 BTFHub 같은 외부 BTF 파일을 지정할 수도 있다) | 5.4 | 06, 07 | v5.4에 `kernel/bpf/sysfs_btf.c`가 처음 생김. `CONFIG_DEBUG_INFO_BTF=y` 필요 |

### 1.2 verifier와 프로그램 작성

| 기능 | 최소 버전 | 이 저장소 | 확인 근거 |
|---|---|---|---|
| 프로그램당 명령어 100만 개(권한 있는 경우) | 5.2 | 05 | BCC 문서의 커밋 `c04c0d2b968a` |
| 전역 변수(`.data`/`.rodata`/`.bss`), `const volatile` 로드 전 상수 | 5.2 | 07~14 | `BPF_PSEUDO_MAP_VALUE`, `BPF_F_RDONLY_PROG` |
| 유한 루프(bounded loop) | 5.3 | 05 | BCC 문서의 커밋 `2589726d12a1` |
| `bpf_probe_read_kernel`/`_user` 분리 | 5.5 | 03 | 헬퍼 이름이 5.5 헤더에 처음 등장 |
| `bpf_get_current_task_btf` | 5.11 | 13 | 같은 방법 |
| `bpf_for_each_map_elem` | 5.13 | — | 같은 방법 |
| kfunc(커널 함수를 BPF에서 직접 호출) | 5.13 | — | `BPF_PSEUDO_KFUNC_CALL` |
| `bpf_trace_vprintk`(printk 인자 4개 이상) | 5.16 | 14 | 같은 방법 |
| `bpf_loop` | 5.17 | 05 | 같은 방법 |

### 1.3 추적(tracing)

| 기능 | 최소 버전 | 이 저장소 | 확인 근거 |
|---|---|---|---|
| perf event 프로그램(CPU 샘플링) | 4.9 | 03 | `BPF_PROG_TYPE_PERF_EVENT` |
| fentry/fexit, `tp_btf`(BPF trampoline) | 5.5 | 03, 13, 14 | `BPF_TRACE_FENTRY`, `BPF_TRACE_RAW_TP` |
| BPF link(`BPF_LINK_CREATE`), link 교체(`BPF_LINK_UPDATE`) | 5.7 | 07, 14 | 같은 상수 |
| ring buffer | 5.8 | 04, 07, 13 | `BPF_MAP_TYPE_RINGBUF` |
| BPF iterator | 5.8 | — | `BPF_TRACE_ITER` |
| sleepable 프로그램 | 5.10 | — | `BPF_F_SLEEPABLE` |
| kprobe multi(여러 함수에 한 번에) | 5.18 | — | `BPF_TRACE_KPROBE_MULTI` |
| uprobe multi | 6.6 | — | `BPF_TRACE_UPROBE_MULTI` |
| kprobe session / uprobe session | 6.10 / 6.13 | — | `BPF_TRACE_KPROBE_SESSION`, `BPF_TRACE_UPROBE_SESSION` |

uprobe 자체는 kprobe 프로그램 타입으로 붙으므로 kprobe와 같은 시기부터 쓸 수 있다(정확히는 커널의 uprobe 이벤트 지원 여부에 따른다).

### 1.4 네트워크

| 기능 | 최소 버전 | 이 저장소 | 확인 근거 |
|---|---|---|---|
| XDP | 4.8 | 09, 10 | `BPF_PROG_TYPE_XDP` |
| cgroup skb / cgroup sock | 4.10 | — | `BPF_PROG_TYPE_CGROUP_SKB`, `_SOCK` |
| sock_ops(연결별 TCP 이벤트) | 4.13 | — | `BPF_PROG_TYPE_SOCK_OPS` |
| devmap(XDP redirect 대상 인터페이스) | 4.14 | 10 | `BPF_MAP_TYPE_DEVMAP` |
| cgroup `connect4` | 4.17 | 11 | `BPF_CGROUP_INET4_CONNECT` |
| cgroup `sendmsg4` | 4.18 | 11 | `BPF_CGROUP_UDP4_SENDMSG` |
| AF_XDP, XSKMAP | 4.18 | 10 | `BPF_MAP_TYPE_XSKMAP` |
| socket lookup | 5.9 | — | `BPF_PROG_TYPE_SK_LOOKUP` |
| netfilter 프로그램 | 6.4 | 09 | `BPF_PROG_TYPE_NETFILTER` |
| **tcx**(link 기반 TC) | 6.6 | 09, 11 | `BPF_TCX_INGRESS` |
| netkit | 6.7 | — | `BPF_LINK_TYPE_NETKIT` |

### 1.5 보안·운영

| 기능 | 최소 버전 | 이 저장소 | 확인 근거 |
|---|---|---|---|
| `kernel.bpf_stats_enabled` sysctl | 5.1 | 14 | v5.1 `kernel/sysctl.c` |
| LSM-BPF | 5.7 | 12 | `BPF_PROG_TYPE_LSM`. `CONFIG_BPF_LSM=y`이고, 실행 중 LSM 목록(`/sys/kernel/security/lsm`)에 `bpf`가 있어야 한다. 빌드 설정 `CONFIG_LSM`에 없으면 부팅 인자 `lsm=...,bpf`로 넣는다(12장) |
| `CAP_BPF` (`CAP_SYS_ADMIN`과 분리) | 5.8 | 00 | v5.8 `include/uapi/linux/capability.h` |
| `BPF_ENABLE_STATS` | 5.8 | 14 | 같은 상수 |
| map 메모리를 memlock rlimit 대신 memcg로 계산 | 5.11 | 07 | v5.10의 `bpf_map_charge_memlock`이 v5.11 `kernel/bpf/syscall.c`에서 사라짐 |
| BPF token(권한 위임) | 6.9 | — | `BPF_TOKEN_CREATE` |
| arena map | 6.9 | — | `BPF_MAP_TYPE_ARENA` |
| sched_ext(BPF로 CPU 스케줄러 작성) | 6.12 | — | v6.12에 `kernel/sched/ext.c`가 처음 생김 |

> **memlock 메모.** 5.11 이전 커널에서는 map을 만들 때 `RLIMIT_MEMLOCK`이 부족하면 `EPERM`이 난다. 이 저장소의 Go 로더가 처음에 `rlimit.RemoveMemlock()`을 부르는 이유다. cilium/ebpf 문서에 따르면 5.11 이후 커널에서는 이 함수가 아무 일도 하지 않는다(no-op).

## 2. 배포판 커널과 확인 방법

| 배포판(기본 커널) | 커널 | 이 저장소 기준으로 빠지는 것(업스트림 버전 기준) |
|---|---|---|
| RHEL 8 | 4.18 | 많은 기능이 백포트되어 있어 버전만으로 판단할 수 없다. 반드시 probe로 확인 |
| Debian 11 | 5.10 | 버전상 LSM-BPF(5.7+)까지 가능(빌드 옵션·부팅 인자는 따로 확인). kfunc·`bpf_loop`·netfilter·tcx 없음 |
| RHEL 9 | 5.14 | 백포트가 많다. probe로 확인 |
| Ubuntu 22.04 | 5.15 | netfilter 프로그램(6.4), tcx(6.6) 없음 |
| Debian 12 | 6.1 | netfilter·tcx 없음 |
| Ubuntu 24.04 | 6.8 | 대부분 가능. token·arena(6.9)는 없음 |

(커널 버전은 각 배포판 출시 때의 기본 커널이다. Ubuntu HWE 커널처럼 더 새 커널을 쓸 수 있는 경우가 많다. 이 저장소를 확인한 장비도 Ubuntu 24.04에 6.17 커널이다.)

대상 장비에서 직접 확인하는 방법:

```bash
uname -r
ls /sys/kernel/btf/vmlinux                      # 커널 BTF (CO-RE, fentry, tp_btf, LSM에 필요)
sudo bpftool feature probe kernel | grep -E 'program_type|map_type'   # 프로그램·map 타입
sudo bpftool feature probe kernel | grep -i 'bpf_loop'   # 특정 helper
cat /sys/kernel/security/lsm                     # bpf가 있어야 LSM-BPF
grep -E 'CONFIG_DEBUG_INFO_BTF|CONFIG_BPF_LSM' /boot/config-$(uname -r)
```

`feature probe`는 프로그램·map 타입과 helper를 알려 주지만, tcx·netkit·kprobe/uprobe multi 같은 **attach 방식**은 알려 주지 않는다. 그런 기능은 작은 프로그램을 실제로 붙여 보는 것이 가장 확실하다(attach가 `EINVAL`이나 `EOPNOTSUPP`로 실패하면 미지원).

Go라면 cilium/ebpf의 [`features`](https://pkg.go.dev/github.com/cilium/ebpf/features) 패키지로 실행 중에 같은 확인을 할 수 있다. 예: `features.HaveProgramType(ebpf.LSM)`, `features.HaveMapType(ebpf.RingBuf)`. 없으면 다른 경로로 바꾸는 코드를 넣어 두자. 예를 들어 ring buffer가 없으면 perf buffer로, tcx가 없으면 기존 TC(clsact qdisc) attach로 바꾼다.

## 3. 이 표를 만든 방법과 한계

- **UAPI 헤더 대조**: 3.18부터 6.17까지 릴리스 태그마다 `include/uapi/linux/bpf.h`를 받아, 각 상수나 helper 이름이 처음 나타나는 버전을 찾았다. 상수가 들어간 릴리스와 기능이 실제로 쓸 만해진 릴리스는 다를 수 있다. 예를 들어 버그 수정이나 아키텍처별 JIT 지원이 뒤따라온 경우다.
- **아키텍처**: fentry/fexit(BPF trampoline) 같은 기능은 x86-64에 먼저 들어오고 다른 아키텍처는 나중에 지원된 경우가 있다. 이 표는 x86-64 기준이다.
- **빌드 옵션**: `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_BPF_LSM` 등이 꺼져 있으면 버전과 관계없이 그 기능을 쓸 수 없다. `CONFIG_BPF_JIT`가 꺼져 있으면 많은 프로그램은 인터프리터로 돌지만, BPF trampoline(fentry 등)처럼 JIT가 필요한 기능은 쓸 수 없다.
- 이 표에 없는 helper·map 타입은 BCC의 [kernel-versions.md](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)가 가장 자세하다(커밋 링크 포함). 이 부록의 1M 명령어·유한 루프 항목은 그 문서의 커밋 링크로 확인했다.

## 4. 더 읽을거리

| 자료 | 라이선스 | 이 부록에서의 사용 |
|---|---|---|
| 커널 소스 `include/uapi/linux/bpf.h` (v3.18~v6.17 태그) | GPL-2.0 WITH Linux-syscall-note | 상수·helper가 처음 등장한 버전 대조 |
| 커널 소스 `kernel/bpf/sysfs_btf.c`, `kernel/sched/ext.c`, `include/uapi/linux/capability.h`, `kernel/sysctl.c`, `kernel/bpf/syscall.c` | GPL-2.0 | 헤더로 판단할 수 없는 항목의 버전 확인 |
| [BCC: BPF Features by Linux Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) | Apache-2.0 | 1M 명령어, 유한 루프 버전과 커밋. 표 전체의 교차 확인 |
| [docs.ebpf.io](https://docs.ebpf.io/) | BSD-2-Clause | 프로그램 타입·helper별 버전 표기 참고 |
| [cilium/ebpf `features` 패키지](https://pkg.go.dev/github.com/cilium/ebpf/features) | MIT | 실행 중 기능 탐지 |
