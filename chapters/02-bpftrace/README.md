# 02. bpftrace로 맛보기

> **핵심 요약**
> 1. bpftrace는 **awk처럼 생긴 한 줄짜리 스크립트를 BPF 프로그램으로 컴파일해 바로 붙여 주는** 도구다. "지금 이 서버에서 무슨 일이 일어나나"를 묻는 가장 빠른 방법이다.
> 2. 문법은 `프로브 /필터/ { 동작 }` 하나가 전부다. `@` 변수는 map이고, `count()`·`hist()` 같은 집계는 커널 안에서 이루어진다.
> 3. one-liner 10개로 tracepoint, kprobe/kretprobe, uprobe, profile 프로브와 map 집계를 모두 맛본다.

## 1. 개념

### 1.1 bpftrace가 하는 일

```mermaid
flowchart LR
  S["one-liner / .bt 파일"] -->|파싱·LLVM 코드 생성| B["BPF 바이트코드"]
  B -->|"로드·attach (libbpf)"| K["커널 hook"]
  K -->|"@map 집계 / printf 이벤트"| U["bpftrace 프로세스가 출력"]
```

01장에서 손으로 했던 "C 작성 → clang → 로드 → attach → map 읽기"를 bpftrace가 한 번에 한다. 대신 표현력에는 한계가 있어서, 오래 돌릴 에이전트나 복잡한 로직은 07장(Go)처럼 직접 만든다.

| 상황 | 도구 |
|---|---|
| 지금 이 서버에서 한 번 확인해 보고 싶다 | **bpftrace** |
| 이미 만들어진 도구를 쓰고 싶다(`execsnoop`, `biolatency` …) | BCC / libbpf-tools |
| 제품·에이전트에 넣을 코드 | libbpf(C), cilium/ebpf(Go), Aya(Rust) |

### 1.2 문법 한눈에 보기

```
프로브[,프로브…] /필터/ { 동작; 동작; }
```

```
tracepoint:syscalls:sys_exit_read  /args.ret > 0/  { @bytes = hist(args.ret); }
└──────────── 프로브 ────────────┘ └─── 필터 ───┘ └────────── 동작 ──────────┘
```

| 요소 | 예 | 설명 |
|---|---|---|
| 내장 변수 | `pid`, `tid`, `uid`, `comm`, `nsecs`, `cpu`, `kstack`, `ustack` | 현재 실행 중인 태스크 정보 |
| 인자 | `args.필드`(tracepoint), `arg0`~`argN`(kprobe/uprobe), `retval`(ret 프로브) | 프로브마다 다르다 |
| map | `@이름[키] = 값` | 커널 안의 BPF map. 프로그램 종료 시 자동 출력 |
| 집계 함수 | `count()`, `sum(x)`, `avg(x)`, `min/max`, `hist(x)`, `lhist(x,…)` | 커널 안에서 집계 → 오버헤드가 작다 |
| 임시 변수 | `$x = …` | 한 번 실행하는 동안만 유효 |
| 함수 | `printf()`, `str()`(문자열 읽기), `ntop()`(IP 변환), `delete()`, `clear()`, `exit()` | |

### 1.3 프로브 종류

| 프로브 | 형식 | 붙는 곳 | 안정성 |
|---|---|---|---|
| `tracepoint` | `tracepoint:카테고리:이름` | 커널에 미리 심은 정적 지점 | **높음**(형식이 거의 안 바뀜) |
| `kprobe` / `kretprobe` | `kprobe:함수` | 커널 함수 진입 / 반환 | 낮음(함수 이름·인자가 버전마다 바뀔 수 있음) |
| `fentry` / `fexit` | `fentry:함수` (예전 이름 `kfunc:`/`kretfunc:`도 동작) | 커널 함수 진입 / 반환 (BTF 기반, 더 빠름) | 낮음 |
| `uprobe` / `uretprobe` | `uprobe:바이너리:함수` | 사용자 공간 함수 | 바이너리에 따라 다름 |
| `usdt` | `usdt:바이너리:프로바이더:이름` | 사용자 프로그램에 심은 정적 지점 | 높음 |
| `profile` / `interval` | `profile:hz:99`, `interval:s:1` | 타이머(CPU 샘플링 / 주기 출력) | — |
| `software` / `hardware` | `software:page-faults:100` | perf 이벤트 | — |
| `BEGIN` / `END` | | 시작·종료 시 한 번 | — |

**tracepoint가 있으면 tracepoint를 먼저 쓰자.** kprobe는 어떤 커널 함수에도 붙을 수 있어 강력하지만, 커널이 바뀌면 함수가 인라인되거나 이름이 바뀌어 스크립트가 깨질 수 있다.

## 2. 예제: one-liner 10선

| # | 파일 | 프로브 | 배우는 것 |
|---|---|---|---|
| 01 | [`01-hello.bt`](code/oneliners/01-hello.bt) | `BEGIN`/`END` | 실행 구조 |
| 02 | (명령) `bpftrace -l` | — | 프로브 찾기, 인자 확인(`-lv`) |
| 03 | [`03-execsnoop.bt`](code/oneliners/03-execsnoop.bt) | tracepoint | `args.필드`, `str()` |
| 04 | [`04-syscount.bt`](code/oneliners/04-syscount.bt) | tracepoint(raw_syscalls) | map + `count()` |
| 05 | [`05-opensnoop.bt`](code/oneliners/05-opensnoop.bt) | tracepoint 진입/종료 짝 | 스레드별 map으로 상태 전달, `delete()` |
| 06 | [`06-readsize.bt`](code/oneliners/06-readsize.bt) | tracepoint | 필터, `hist()` |
| 07 | [`07-vfsread-latency.bt`](code/oneliners/07-vfsread-latency.bt) | kprobe + kretprobe | 지연 시간 측정 패턴 |
| 08 | [`08-tcpconnect.bt`](code/oneliners/08-tcpconnect.bt) | kprobe | 커널 함수 직접 추적 |
| 09 | [`09-getaddrinfo.bt`](code/oneliners/09-getaddrinfo.bt) | uprobe | 사용자 공간 라이브러리 함수 추적 |
| 10 | [`10-profile.bt`](code/oneliners/10-profile.bt) | profile | CPU 샘플링 |

[`code/run-all.sh`](code/run-all.sh)는 각 스크립트를 `bpftrace -c "부하 명령" 스크립트.bt`로 실행한다. `-c`는 **프로브를 다 붙인 다음 명령을 실행하고, 명령이 끝나면 bpftrace도 끝내면서 map을 출력**한다. 결과 예시를 재현 가능하게 만드는 데 편리하다.

### 실행

```bash
cd chapters/02-bpftrace/code
make run               # 10개 전부(내부에서 sudo), 결과는 out/run.log

# 하나씩 직접 (Ctrl-C로 종료하면 map이 출력된다)
sudo bpftrace oneliners/04-syscount.bt
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
```

> bpftrace 출력은 **시스템 전체**를 보여 준다. 아래 결과 예시는 부하 명령과 관련된 줄만 남겼다.

### 실행 결과와 해설 (Linux 6.17 x86_64, bpftrace 0.20.2)

#### 01. hello — 실행 구조

```
// 01-hello.bt
BEGIN { printf("hello, eBPF! (bpftrace pid=%d)\n", pid); }
END   { printf("bye\n"); }
```
```
Attaching 2 probes...
hello, eBPF! (bpftrace pid=2501945)
bye
```

`BEGIN`/`END`는 커널 이벤트가 아니라 bpftrace가 시작·종료할 때 한 번 실행된다. "Attaching 2 probes"가 보이면 attach까지 성공한 것이다.

#### 02. 프로브 찾기 — `bpftrace -l`

```bash
sudo bpftrace -l 'tracepoint:syscalls:sys_enter_exec*'   # 와일드카드 검색
sudo bpftrace -l 'kprobe:tcp_*' | wc -l                  # kprobe 후보 수
sudo bpftrace -lv 'tracepoint:syscalls:sys_enter_execve' # 인자 목록(-v)
```
```
tracepoint:syscalls:sys_enter_execve
tracepoint:syscalls:sys_enter_execveat
  kprobe:tcp_* 개수: 494
tracepoint:syscalls:sys_enter_execve
    int __syscall_nr
    const char * filename
    const char *const * argv
    const char *const * envp
```

`-lv`로 본 필드 이름이 그대로 `args.filename`처럼 쓰인다. **스크립트를 쓰기 전에 항상 `-l`/`-lv`로 확인**하는 습관을 들이자.

#### 03. execsnoop — 새로 실행되는 프로그램

```
tracepoint:syscalls:sys_enter_execve
{
	printf("%-8d %-16s %s\n", pid, comm, str(args.filename));
}
```

```
Attaching 1 probe...
2884782  sh               /usr/bin/ls
2884783  sh               /usr/bin/uname
2884784  sh               /usr/bin/date
```

- `args.filename`은 **사용자 공간 메모리를 가리키는 포인터**다. `str()`이 안전하게 읽어 문자열로 바꾼다(최대 64바이트, `BPFTRACE_MAX_STRLEN`).
- `comm`은 execve를 **호출한** 프로세스 이름이다(여기서는 부하 스크립트를 실행한 `sh`). 아직 새 프로그램으로 바뀌기 전이다.
- 시스템 전체의 execve가 잡히므로 위 결과는 부하 스크립트가 실행한 3줄만 남겼다. 진입(`sys_enter_*`) tracepoint는 호출이 성공할지 모르는 시점이라 **실패한 execve도 찍힌다**(예: 어떤 프로그램은 `PATH`의 디렉터리마다 execve를 시도해 본다). 성공만 보려면 `sys_exit_execve`의 `args.ret`과 짝지어야 한다(05번 패턴).

#### 04. syscount — 프로세스별 시스템 콜 횟수

```
tracepoint:raw_syscalls:sys_enter { @syscalls[comm] = count(); }
```
```
Attaching 1 probe...
@syscalls[dd]: 40069
```

`dd bs=1 count=20000`은 read 2만 번 + write 2만 번을 하므로 약 4만 회가 나온다(나머지는 프로그램 시작·종료 시의 시스템 콜). `@syscalls[comm]`은 **comm을 키로 하는 BPF map**이고, 갱신은 전부 커널 안에서 일어난다. `count()`는 CPU마다 따로 세는 per-CPU 값을 써서 CPU끼리 경합하지 않고, 출력할 때 bpftrace가 합산한다. 사용자 공간으로는 종료 시 결과만 한 번 넘어온다. 이것이 bpftrace 집계의 오버헤드가 작은 이유다.

#### 05. opensnoop — 진입과 종료를 짝짓기

```
tracepoint:syscalls:sys_enter_openat { @fname[tid] = args.filename; }
tracepoint:syscalls:sys_exit_openat /@fname[tid]/
{
	printf("%-16s fd=%-4d %s\n", comm, args.ret, str(@fname[tid]));
	delete(@fname[tid]);
}
```
```
Attaching 2 probes...
cat              fd=3    /etc/ld.so.cache
cat              fd=3    /lib/x86_64-linux-gnu/libc.so.6
cat              fd=3    /usr/lib/locale/locale-archive
cat              fd=3    /etc/os-release
```

파일 이름은 진입 시점에만, 결과(fd)는 종료 시점에만 알 수 있다. 그래서 **진입에서 스레드 ID(`tid`)를 키로 저장하고 종료에서 꺼내 쓴 뒤 지운다.** 저장하는 것은 문자열이 아니라 사용자 메모리 **포인터**다(BCC/bpftrace의 opensnoop도 같은 방식). 진입 시점에는 그 메모리가 아직 페이지로 올라와 있지 않아 읽기가 실패할 수 있기 때문인데, 대신 그사이 다른 스레드가 버퍼를 바꾸면 실제와 다른 이름이 보일 수 있다. 관측 도구로는 충분하지만, 보안 감사처럼 정확해야 하는 곳에서는 LSM hook처럼 커널이 이미 복사한 값을 보는 지점을 쓴다(12장). 07번의 지연 시간 측정도 같은 패턴이다. `cat` 한 번에도 동적 링커(`ld.so.cache`, `libc.so.6`)와 로캘 파일이 먼저 열리는 것을 볼 수 있다.

#### 06. readsize — 필터와 히스토그램

```
tracepoint:syscalls:sys_exit_read /args.ret > 0/ { @bytes = hist(args.ret); }
```
```
@bytes:
[8, 16)               15 |                                                    |
[16, 32)               0 |                                                    |
[32, 64)              10 |                                                    |
[64, 128)             18 |                                                    |
[128, 256)             0 |                                                    |
[256, 512)             6 |                                                    |
[512, 1K)            268 |@@@@@@@@@@@@@                                       |
[1K, 2K)               1 |                                                    |
[2K, 4K)              24 |@                                                   |
[4K, 8K)            1027 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8K, 16K)            228 |@@@@@@@@@@@                                         |
```

`/args.ret > 0/` 필터로 실패(음수)와 EOF(0)를 뺐다. `hist()`는 2의 거듭제곱 구간으로 센다. `dd bs=4k count=1000`의 read 1000회가 `[4K, 8K)`에 모여 있고, 나머지는 같은 시간에 시스템의 다른 프로세스가 한 read다. 필터에 `comm == "dd"`를 더하면 dd만 볼 수 있다.

#### 07. vfs_read 지연 시간 — kprobe + kretprobe

```
kprobe:vfs_read { @start[tid] = nsecs; }
kretprobe:vfs_read /@start[tid]/
{
	@usecs = hist((nsecs - @start[tid]) / 1000);
	delete(@start[tid]);
}
END { clear(@start); }
```
```
@usecs:
[1]                   94 |@@                                                  |
[2, 4)               313 |@@@@@@@                                             |
[4, 8)              2131 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[8, 16)               20 |                                                    |
[16, 32)               5 |                                                    |
[32, 64)               5 |                                                    |
[64, 128)             13 |                                                    |
[128, 256)             6 |                                                    |
[256, 512)             0 |                                                    |
[512, 1K)              0 |                                                    |
[1K, 2K)               1 |                                                    |
[2K, 4K)              0 |                                                    |
[4K, 8K)               1 |                                                    |
[8K, 16K)              1 |                                                    |
```

`vfs_read`는 시스템 콜보다 한 단계 아래의 커널 함수(가상 파일 시스템 계층)다. `/dev/zero`에서 64KB씩 읽는 dd의 2000회가 4~8µs 구간에 몰려 있고, 뒤쪽의 긴 꼬리는 파이프나 소켓에서 데이터를 기다린 다른 프로세스의 read다. `END`의 `clear(@start)`는 종료 시 짝을 못 찾은 시작 시각이 출력되지 않게 한다.

#### 08. tcpconnect — 커널 함수 kprobe

```
kprobe:tcp_connect { @connects[comm] = count(); }
```

```
Attaching 1 probe...
@connects[bash]: 1
```

닫힌 포트로 연결을 시도해도 SYN을 보내는 `tcp_connect()`는 호출된다. tracepoint로 하고 싶다면 `tracepoint:sock:inet_sock_set_state`(TCP 상태 변화)를 쓰면 된다. 13장에서 다룬다.

#### 09. getaddrinfo — 사용자 공간 함수 uprobe

```
uprobe:/lib/x86_64-linux-gnu/libc.so.6:getaddrinfo
{
	printf("%-16s %s\n", comm, str(arg0));
}
```
```
Attaching 1 probe...
getent           localhost
```

glibc의 `getaddrinfo(const char *node, …)` 첫 인자(`arg0`)가 조회할 호스트 이름이다. **모든 프로세스의 DNS 조회를 코드 수정 없이 볼 수 있다.** libc 경로는 배포판과 아키텍처에 따라 다르다(arm64면 `/lib/aarch64-linux-gnu/libc.so.6`). `ldd $(which getent)`로 확인하자. Go 프로그램은 기본적으로 자체 DNS 리졸버를 써서 이 프로브에 잡히지 않는다.

#### 10. profile — CPU 샘플링

```
profile:hz:99 /pid != 0/ { @samples[comm] = count(); }
```
```
Attaching 1 probe...
@samples[dd]: 133
```

모든 CPU에서 초당 99번씩 "지금 무엇이 실행 중인가"를 기록한다. `pid != 0`은 idle을 제외한다. dd가 약 1.3초 동안 CPU 하나를 썼다는 뜻이다. 키를 `kstack`이나 `ustack`으로 바꾸면 스택별로 집계되고, 그 출력을 flame graph로 그릴 수 있다. 99Hz는 다른 주기적 작업과 박자가 맞아 결과가 치우치는 것을 피하려는 관례다.

## 3. 직접 해보기

1. 03번에 필터를 붙여 root가 실행하는 것만 보자: `/uid == 0/`.
2. 04번 키를 `[comm, args.id]`로 바꾸면 프로세스별·시스템 콜 번호별로 센다. `ausyscall` 같은 도구로 번호를 이름으로 바꿔 보자. 또는 `tracepoint:syscalls:sys_enter_*`에 `@[probe] = count();`를 쓰면 이름으로 바로 볼 수 있다.
3. 07번을 `fentry:vfs_read`/`fexit:vfs_read`로 바꿔 보자. `sudo bpftrace -lv 'fentry:vfs_read'`로 인자(`file`, `buf`, `count`, `pos`, 그리고 fexit의 `retval`)를 확인한 뒤 `args.count`(읽으려는 바이트 수)도 집계해 보자.
4. `interval:s:1 { print(@syscalls); clear(@syscalls); }`를 04번에 더해 1초마다 출력하게 만들자.
5. 10번 키를 `kstack`으로 바꾸고 `dd`가 커널의 어느 함수에서 시간을 쓰는지 보자.

## 4. 자주 하는 실수

- **`args->filename` vs `args.filename`** — 이전 버전 예제는 `args->`를 쓴다. 0.20은 둘 다 받지만(확인함) 새 문서는 `args.`를 쓴다.
- **`-c`에 셸 스크립트를 바로 넘김** — 0.20의 `-c`는 ELF 실행 파일만 받아서 `does not exist or is not executable`로 실패한다. `-c "/bin/sh 스크립트"`처럼 인터프리터를 앞에 둔다.
- **문자열이 잘림** — `str()`은 기본 64바이트까지만 읽는다. `BPFTRACE_MAX_STRLEN`으로 늘릴 수 있지만 BPF 스택 한도(512바이트) 때문에 무작정 늘릴 수는 없다.
- **kprobe가 "Could not resolve symbol" / 아무것도 안 잡힘** — 그 커널에서 함수가 인라인되었거나 이름이 다르다. `bpftrace -l 'kprobe:이름*'`으로 확인하고, 가능하면 tracepoint를 쓴다.
- **진입/종료 짝 맞추기에서 map을 지우지 않음** — `delete()`를 빼먹으면 map이 계속 커지다가 `BPFTRACE_MAX_MAP_KEYS`(기본 4096)에 걸린다.
- **너무 잦은 이벤트에 `printf`** — 초당 수십만 번 일어나는 이벤트(예: `vfs_read`)에 `printf`를 쓰면 출력이 밀리고 이벤트가 유실된다(`Lost N events`). 집계(`count`, `hist`)를 쓰자.
- **uprobe 경로를 심볼릭 링크로 지정** — 실제 파일 경로를 쓰는 것이 안전하다(`readlink -f`).

## 5. 더 읽을거리

| 자료 | 라이선스 | 이 챕터에서의 사용 |
|---|---|---|
| [bpftrace One-Liner Tutorial](https://github.com/bpftrace/bpftrace/blob/master/docs/tutorial_one_liners.md) | Apache-2.0 | one-liner 선정·구성을 참고해 재구성(같은 주제를 이 머신 결과로 다시 씀) |
| [bpftrace Reference Guide](https://github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc) | Apache-2.0 | 문법·내장 변수 참고 |
| [bpftrace 0.20 릴리스 노트](https://github.com/bpftrace/bpftrace/releases/tag/v0.20.0) | Apache-2.0 | 버전별 문법 차이 확인 |
| [Brendan Gregg, *BPF Performance Tools* (2019)](https://www.brendangregg.com/bpf-performance-tools-book.html) | 저작권 도서 | 배경 참고(인용·번역 없음) |
| [BCC tools](https://github.com/iovisor/bcc/tree/master/tools) | Apache-2.0 | `execsnoop`·`opensnoop` 이름 관례 참고 |
