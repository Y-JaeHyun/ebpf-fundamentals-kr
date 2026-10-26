include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: bench(C) + bpf2go + hookbench(Go)
build: bin/bench bin/hookbench

bin/bench: $(REPO_ROOT)/tools/bench/bench.c
	@mkdir -p bin
	$(CC) -O2 -Wall -o $@ $<

bin/hookbench: hooks.bpf.c hookbench/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./...
	$(GO) build -o bin/ ./hookbench

# root 필요
run: | $(OUT_DIR)
	@test -x bin/bench -a -x bin/hookbench || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) hookbench/*_bpfel.go hookbench/*_bpfel.o
