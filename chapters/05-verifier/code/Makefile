include ../../../mk/common.mk

CASES := $(basename $(basename $(notdir $(wildcard cases/*.bpf.c))))
# 08-stack-limit의 bad 버전은 clang 단계에서 실패하는 것이 정상이라 따로 다룬다
OBJS  := $(foreach c,$(CASES),obj/$(c).good.o) \
         $(foreach c,$(filter-out 08-stack-limit,$(CASES)),obj/$(c).bad.o)

.PHONY: build run clean
# root 불필요: 사례마다 틀린 버전(bad)과 고친 버전(good, -DFIX)을 컴파일
build: $(OBJS) obj/08-stack-limit.bad.clang.txt

obj/%.bad.o: cases/%.bpf.c $(VMLINUX_H)
	@mkdir -p obj
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

obj/%.good.o: cases/%.bpf.c $(VMLINUX_H)
	@mkdir -p obj
	$(CLANG) $(BPF_CFLAGS) -DFIX -c $< -o $@

# 컴파일 실패 메시지를 파일로 남긴다(실패해야 정상)
obj/08-stack-limit.bad.clang.txt: cases/08-stack-limit.bpf.c $(VMLINUX_H)
	@mkdir -p obj
	@if $(CLANG) $(BPF_CFLAGS) -c $< -o /dev/null 2> $@; then \
		echo "08-stack-limit: clang이 거부하지 않았다" >&2; exit 1; fi
	@echo "08-stack-limit.bad: clang이 예상대로 거부 → $@"

# root 필요
run: | $(OUT_DIR)
	@test -d obj || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf obj $(OUT_DIR)
