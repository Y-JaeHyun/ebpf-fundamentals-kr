include ../../../mk/common.mk

.PHONY: build run run-host clean
# root 불필요: bpf2go + Go 바이너리(정적 링크라 VM 안에서도 그대로 실행된다)
build: bin/lsmguard

bin/lsmguard: lsmguard/lsmguard.bpf.c lsmguard/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./lsmguard
	CGO_ENABLED=0 $(GO) build -o bin/ ./lsmguard

# LSM 목록에 bpf를 넣어 부팅한 VM 안에서 실행한다(tools/vm). 호스트 sudo·재부팅 불필요
run: | $(OUT_DIR)
	@test -x bin/lsmguard || { echo "먼저 make build"; exit 1; }
	$(REPO_ROOT)/tools/vm/run-vm.sh --lsm-bpf 'chapters/12-lsm-bpf/code/run.sh' 2>&1 | tee $(RUN_LOG)

# 비교용: bpf가 LSM 목록에 없는 호스트에서 같은 실험 (root). 로더의 시작 거부를 -allow-inactive로 풀고 실행한다
run-host: | $(OUT_DIR)
	@test -x bin/lsmguard || { echo "먼저 make build"; exit 1; }
	$(SUDO) ALLOW_INACTIVE=1 ./run.sh 2>&1 | tee $(OUT_DIR)/run-host.log

clean:
	rm -rf bin $(OUT_DIR) lsmguard/*_bpfel.go lsmguard/*_bpfel.o
