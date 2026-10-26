include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: 컴파일 + 바이트코드/섹션 확인
# 일부러 verifier에 거부당하는 변형 두 개 (README 3절 실습 1·2)
bad-null.bpf.c: hello.bpf.c
	sed -e 's/if (cnt)/if (1)/' $< > $@
bad-license.bpf.c: hello.bpf.c
	sed -e 's/"Dual MIT\/GPL"/"Proprietary"/' $< > $@

build: hello.bpf.o bad-null.bpf.o bad-license.bpf.o | $(OUT_DIR)
	llvm-objdump -h hello.bpf.o > $(OUT_DIR)/sections.txt
	llvm-objdump -d --no-show-raw-insn hello.bpf.o > $(OUT_DIR)/bytecode.txt
	@echo "섹션: $(OUT_DIR)/sections.txt, 바이트코드: $(OUT_DIR)/bytecode.txt"

# root 필요
run: hello.bpf.o bad-null.bpf.o bad-license.bpf.o | $(OUT_DIR)
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf $(OUT_DIR) *.o bad-*.bpf.c
