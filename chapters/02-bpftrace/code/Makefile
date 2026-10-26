include ../../../mk/common.mk

.PHONY: build run clean
# bpftrace는 실행 시점에 컴파일하므로 빌드할 것이 없다
build:
	@echo "bpftrace 스크립트는 빌드가 필요 없다: oneliners/*.bt"

# root 필요
run: | $(OUT_DIR)
	$(SUDO) ./run-all.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf $(OUT_DIR)
