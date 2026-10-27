include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: bpf2go + Go 바이너리 3개
build: bin/tcegress bin/cgsock bin/probe

bin/tcegress: tcegress/tcegress.bpf.c tcegress/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./tcegress
	$(GO) build -o bin/ ./tcegress

bin/cgsock: cgsock/cgsock.bpf.c cgsock/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./cgsock
	$(GO) build -o bin/ ./cgsock

bin/probe: probe/main.go go.mod
	$(GO) build -o bin/ ./probe

# root 필요: netns 2개 + veth 쌍 + 임시 cgroup 안에서만 실행한다
run: | $(OUT_DIR)
	@test -x bin/tcegress -a -x bin/cgsock -a -x bin/probe || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) */*_bpfel.go */*_bpfel.o
