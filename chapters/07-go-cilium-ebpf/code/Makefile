include ../../../mk/common.mk

BPF_SRC := counter/counter.bpf.c execsnoop/execsnoop.bpf.c
GO_SRC  := $(wildcard */main.go)

.PHONY: build generate run clean
# root 불필요: bpf2go로 BPF C 컴파일 + Go 바인딩 생성 → go build
build: bin/counter bin/execsnoop

generate: $(VMLINUX_H)
	$(GO) generate ./...

bin/counter bin/execsnoop &: $(BPF_SRC) $(GO_SRC) $(VMLINUX_H) go.mod
	$(GO) generate ./...
	$(GO) build -o bin/ ./...

# root 필요
run: | $(OUT_DIR)
	@test -x bin/counter -a -x bin/execsnoop || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) */*_bpfel.go */*_bpfel.o
