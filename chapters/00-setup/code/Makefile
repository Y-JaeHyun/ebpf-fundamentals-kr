include ../../../mk/common.mk

.PHONY: check build run clean
# root 불필요: 커널/도구/설정 점검
check:
	./check-env.sh

# 다른 챕터가 쓰는 include/vmlinux.h 생성
build: $(VMLINUX_H)
	@ls -lh $(VMLINUX_H)

# root 필요: 실제 BPF 로드 가능 여부 점검 (결과는 out/run.log 에도 남는다)
run: | $(OUT_DIR)
	$(SUDO) ./root-check.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf $(OUT_DIR)
