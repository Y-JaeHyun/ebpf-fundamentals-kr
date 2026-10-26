/* SPDX-License-Identifier: (MIT OR GPL-2.0) */
/* BPF 프로그램과 C 로더가 함께 쓰는 이벤트 형식 */
#ifndef EXITSNOOP_H
#define EXITSNOOP_H

#define TASK_COMM_LEN 16

struct event {
	int pid;
	int ppid;
	int exit_code;     /* wait(2) 형식: 하위 7비트 = 시그널, 그 위 8비트 = exit 값 */
	unsigned int state;  /* task_struct의 상태 필드 (5.14부터 이름이 __state로 바뀜) */
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
};

#endif
