// SPDX-License-Identifier: MIT
// 03·04장 공용 부하 프로그램: 표준 입력으로 한 줄을 받으면 read(/dev/zero, 1바이트)를 N번 하고
// 한 번에 걸린 평균 시간(ns)을 출력한다. 로더가 hook을 붙인 "뒤에" 시작하게 하려고 대기한다.
//
//   ./bench 1000000          (엔터를 치면 시작)
//   mode=setjmp 로 실행하면 read 대신 setjmp()를 N번 호출한다(USDT 실습용).
//   cpu=N 이면 CPU N에 고정해 실행한다(측정 흔들림 줄이기).
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// uprobe가 붙을 함수. 인라인되면 심볼이 사라지므로 noinline.
__attribute__((noinline)) long do_read(int fd, char *buf, size_t n)
{
	return read(fd, buf, n);
}

static jmp_buf env;

static long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 1000000;
	const char *mode = getenv("mode");
	int use_setjmp = mode && strcmp(mode, "setjmp") == 0;
	char line[8], buf[1];
	long long t0, t1;
	int fd = open("/dev/zero", O_RDONLY);

	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (getenv("cpu")) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(atoi(getenv("cpu")), &set);
		if (sched_setaffinity(0, sizeof(set), &set)) {
			perror("sched_setaffinity");
			return 1;
		}
	}
	if (!fgets(line, sizeof(line), stdin)) // 시작 신호 대기
		return 1;

	t0 = now_ns();
	for (long i = 0; i < n; i++) {
		if (use_setjmp)
			setjmp(env);
		else if (do_read(fd, buf, 1) != 1)
			return 1;
	}
	t1 = now_ns();
	printf("%.1f\n", (double)(t1 - t0) / n);
	return 0;
}
