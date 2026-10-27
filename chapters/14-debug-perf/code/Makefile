include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: bpf2go + Go 바이너리
build: bin/dbg

bin/dbg: dbg/dbg.bpf.c dbg/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./dbg
	$(GO) build -o bin/ ./dbg

# root 필요
run: | $(OUT_DIR)
	@test -x bin/dbg || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) */*_bpfel.go */*_bpfel.o
