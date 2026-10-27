include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: bpf2go + Go 바이너리 2개
build: bin/xdpfw bin/afxdp

bin/xdpfw: xdpfw/xdpfw.bpf.c xdpfw/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./xdpfw
	$(GO) build -o bin/ ./xdpfw

bin/afxdp: afxdp/afxdp.bpf.c afxdp/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./afxdp
	$(GO) build -o bin/ ./afxdp

# root 필요: netns 2개 + veth 쌍 샌드박스 안에서만 실행한다
run: | $(OUT_DIR)
	@test -x bin/xdpfw -a -x bin/afxdp || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) */*_bpfel.go */*_bpfel.o
