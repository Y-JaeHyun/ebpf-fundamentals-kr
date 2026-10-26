// SPDX-License-Identifier: MIT
// 06장: libbpf skeleton으로 exitsnoop.bpf.o를 로드하고 ring buffer를 읽는 C 로더.
//
//   sudo ./exitsnoop [-d 초] [-m 최소ms] [-u uid] [-v]
//   -v: libbpf 디버그 로그(CO-RE 재배치 과정 포함)를 stderr로 출력
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "exitsnoop.h"
#include "exitsnoop.skel.h" // bpftool gen skeleton 이 만든 파일

static volatile sig_atomic_t stop;
static int verbose;

static void on_sig(int sig) { stop = 1; }

static int print_libbpf(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct event *e = data;

	// exit_code는 wait(2) status와 같은 형식: 하위 7비트 = 죽인 시그널(0이면 정상 종료),
	// 그다음 1비트 = core dump, 8~15비트 = exit() 값
	printf("%-8d %-8d %-16s %5d %4d %10.1f %#x\n", e->pid, e->ppid, e->comm,
	       (e->exit_code >> 8) & 0xff, e->exit_code & 0x7f, e->duration_ns / 1e6, e->state);
	return 0;
}

int main(int argc, char **argv)
{
	struct exitsnoop_bpf *skel;
	struct ring_buffer *rb = NULL;
	int opt, err, seconds = 0, uid = -1;
	long min_ms = 0;
	time_t end;

	while ((opt = getopt(argc, argv, "d:m:u:v")) != -1) {
		switch (opt) {
		case 'd': seconds = atoi(optarg); break;
		case 'm': min_ms = atol(optarg); break;
		case 'u': uid = atoi(optarg); break;
		case 'v': verbose = 1; break;
		default:
			fprintf(stderr, "사용법: %s [-d 초] [-m 최소ms] [-u uid] [-v]\n", argv[0]);
			return 1;
		}
	}
	libbpf_set_print(print_libbpf);
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	// ① open: ELF를 읽어 map·프로그램 정의를 메모리에 올린다(아직 커널에 없음)
	skel = exitsnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "open 실패: %s\n", strerror(errno));
		return 1;
	}
	// ② 로드 전 상수 설정: .rodata는 로드 후 읽기 전용이 된다
	skel->rodata->min_duration_ns = min_ms * 1000000ULL;
	skel->rodata->target_uid = uid;

	// ③ load: CO-RE 재배치 → map 생성 → verifier
	err = exitsnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "load 실패: %d\n", err);
		goto out;
	}
	// ④ attach: SEC 이름(tp_btf/sched_process_exit)대로 자동 attach
	err = exitsnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach 실패: %d\n", err);
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "ring buffer 생성 실패: %d\n", err);
		goto out;
	}

	printf("%-8s %-8s %-16s %5s %4s %10s %s\n", "PID", "PPID", "COMM", "EXIT", "SIG", "LIFE(ms)", "STATE");
	end = time(NULL) + seconds;
	while (!stop && (!seconds || time(NULL) < end)) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "poll 실패: %d\n", err);
			break;
		}
		err = 0; // 양수는 처리한 이벤트 수
	}
	// 먼저 detach해 새 이벤트가 생기지 않게 한 뒤, 버퍼에 남은 이벤트를 마저 읽는다
	exitsnoop_bpf__detach(skel);
	if (ring_buffer__consume(rb) < 0 && !err)
		err = -1;
out:
	ring_buffer__free(rb);
	exitsnoop_bpf__destroy(skel); // detach + 모든 fd 닫기
	return err ? 1 : 0;
}
