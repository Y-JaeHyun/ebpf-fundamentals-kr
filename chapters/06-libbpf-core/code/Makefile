include ../../../mk/common.mk
include ../../../mk/libbpf.mk

CC     ?= cc
CFLAGS ?= -O2 -g -Wall

.PHONY: build run clean
# root 불필요: libbpf 정적 빌드 → BPF 컴파일 → skeleton 생성 → C 로더 링크
build: exitsnoop

exitsnoop.bpf.o: exitsnoop.h

# DWARF 디버그 정보(.debug_*)는 로드에 필요 없어서 떼어 낸다. BTF(.BTF, .BTF.ext)는 남는다.
# (task_struct처럼 큰 구조체를 쓰면 DWARF만 수백 KB가 된다)
exitsnoop.stripped.bpf.o: exitsnoop.bpf.o
	llvm-strip -g $< -o $@

# skeleton: BPF 오브젝트를 통째로 바이트 배열로 품고, 이름 붙은 접근자를 만든 헤더
exitsnoop.skel.h: exitsnoop.stripped.bpf.o
	$(BPFTOOL) gen skeleton $< name exitsnoop_bpf > $@.tmp
	mv $@.tmp $@

exitsnoop: exitsnoop.c exitsnoop.h exitsnoop.skel.h $(LIBBPF_A)
	$(CC) $(CFLAGS) -I$(LIBBPF_INC) $(LIBELF_CFLAGS) -o $@ $< $(LIBBPF_LDLIBS)

# root 필요
run: | $(OUT_DIR)
	@test -x exitsnoop || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf $(OUT_DIR) *.o exitsnoop exitsnoop.skel.h
