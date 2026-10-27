include ../../../mk/common.mk

.PHONY: build run clean
# root 불필요: bpf2go + Go 바이너리 4개
build: bin/proctree bin/tcpstat bin/sslsniff bin/tcpload

bin/proctree: proctree/proctree.bpf.c proctree/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./proctree
	$(GO) build -o bin/ ./proctree

bin/tcpstat: tcpstat/tcpstat.bpf.c tcpstat/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./tcpstat
	$(GO) build -o bin/ ./tcpstat

bin/sslsniff: sslsniff/sslsniff.bpf.c sslsniff/main.go $(VMLINUX_H) go.mod
	$(GO) generate ./sslsniff
	$(GO) build -o bin/ ./sslsniff

bin/tcpload: tcpload/main.go go.mod
	$(GO) build -o bin/ ./tcpload

# root 필요: 13-2·13-3은 netns 2개 + veth 쌍 안에서만 실행한다
run: | $(OUT_DIR)
	@test -x bin/proctree -a -x bin/tcpstat -a -x bin/sslsniff -a -x bin/tcpload || { echo "먼저 root 없이 make build"; exit 1; }
	$(SUDO) ./run.sh 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf bin $(OUT_DIR) */*_bpfel.go */*_bpfel.o
