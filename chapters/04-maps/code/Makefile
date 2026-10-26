include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: bench(C, 03장과 공용) + bpf2go + Go 바이너리 2개
build: bin/bench bin/maptour bin/transfer

bin/bench: $(REPO_ROOT)/tools/bench/bench.c
	@mkdir -p bin
	$(CC) -O2 -Wall -o $@ $<

bin/maptour: maptour/main.go go.mod
	$(GO) build -o bin/ ./maptour

bin/transfer: transfer/transfer.bpf.c transfer/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./transfer
	$(GO) build -o bin/ ./transfer

# root 필요
run: | $(OUT_DIR)
	@test -x bin/bench -a -x bin/maptour -a -x bin/transfer || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) transfer/*_bpfel.go transfer/*_bpfel.o
