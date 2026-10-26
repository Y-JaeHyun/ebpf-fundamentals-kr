# 저장소 최상위 Makefile
#   make check   실습 환경 점검(00장, root 불필요)
#   make build   모든 챕터 예제 빌드(root 불필요)
#   make clean   빌드 산출물 삭제
# 실행(root 필요)은 각 챕터에서: sudo make -C chapters/NN-slug/code run

CHAPTER_CODE := $(sort $(wildcard chapters/*/code/Makefile))

.PHONY: check build clean vmlinux
check:
	$(MAKE) -C chapters/00-setup/code check

vmlinux:
	$(MAKE) -C chapters/00-setup/code vmlinux

build:
	@set -e; for mk in $(CHAPTER_CODE); do $(MAKE) -C $$(dirname $$mk) build; done

clean:
	@set -e; for mk in $(CHAPTER_CODE); do $(MAKE) -C $$(dirname $$mk) clean; done
	rm -f include/vmlinux.h
