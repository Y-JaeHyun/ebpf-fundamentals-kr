include ../../../mk/common.mk

# 이미지 태그에 Dockerfile 해시를 넣어, Dockerfile이 바뀌면 새 이미지를 만들게 한다
AYA_IMAGE := ebpf-fundamentals-aya:$(shell sha256sum $(REPO_ROOT)/tools/aya/Dockerfile | cut -c1-12)
DOCKER_RUN := docker run --rm --user $(shell id -u):$(shell id -g) -e HOME=/tmp \
	-v "$(REPO_ROOT)/.local/cargo":/usr/local/cargo/registry -v "$(REPO_ROOT)":/work \
	-w /work/chapters/08-rust-aya/code $(AYA_IMAGE)

.PHONY: build image run clean
# root 불필요: Rust 툴체인이 든 Docker 이미지 안에서 빌드한다(호스트에 Rust 설치 불필요)
# Docker가 없으면 (선택 장이므로) 건너뛰어 저장소 전체 make build를 막지 않는다
build:
	@if ! docker info >/dev/null 2>&1; then echo "08장: Docker를 쓸 수 없어 빌드를 건너뛴다"; exit 0; fi; \
	$(MAKE) image && mkdir -p $(REPO_ROOT)/.local/cargo && $(DOCKER_RUN) cargo build --release

image:
	@docker image inspect $(AYA_IMAGE) >/dev/null 2>&1 || docker build -t $(AYA_IMAGE) "$(REPO_ROOT)/tools/aya"

# 호스트 sudo 대신 KVM VM(tools/vm) 안에서 root로 실행한다
run: | $(OUT_DIR)
	@test -x target/release/execsnoop || { echo "먼저 make build"; exit 1; }
	"$(REPO_ROOT)/tools/vm/run-vm.sh" 'chapters/08-rust-aya/code/run.sh' 2>&1 | tee $(RUN_LOG)

clean:
	rm -rf target $(OUT_DIR)
