include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: bpf2go + Go 바이너리
build: bin/pktpath

bin/pktpath: pktpath/pktpath.bpf.c pktpath/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./pktpath
	$(GO) build -o bin/ ./pktpath

# root 필요: netns 2개 + veth 쌍으로 만든 샌드박스 안에서만 실행한다
run: | $(OUT_DIR)
	@test -x bin/pktpath || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) pktpath/*_bpfel.go pktpath/*_bpfel.o
