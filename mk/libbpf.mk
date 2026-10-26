# libbpf(사용자 공간 라이브러리)를 소스에서 정적으로 빌드하는 규칙. C 로더를 쓰는 챕터가 include 한다.
#
#   include ../../../mk/common.mk
#   include ../../../mk/libbpf.mk
#
# 필요 패키지: libelf-dev, zlib1g-dev (Ubuntu)
# 결과: $(LIBBPF_A) (정적 라이브러리), $(LIBBPF_INC)/bpf/*.h (헤더)
# 받은 소스는 저장소 루트의 .local/ 에 둔다(커밋하지 않음).

LIBBPF_VERSION := 1.7.0
LIBBPF_SHA256  := 7ab5feffbf78557f626f2e3e3204788528394494715a30fc2070fcddc2051b7b
LIBBPF_SRC     := $(REPO_ROOT)/.local/libbpf-$(LIBBPF_VERSION)
LIBBPF_OUT     := $(REPO_ROOT)/.local/libbpf-$(LIBBPF_VERSION)-build
LIBBPF_A       := $(LIBBPF_OUT)/libbpf.a
LIBBPF_INC     := $(LIBBPF_OUT)

# libelf 헤더·라이브러리 위치를 바꿔야 할 때만 지정 (예: LIBELF_CFLAGS=-I/opt/elf/include)
LIBELF_CFLAGS ?=
LIBELF_LIBS   ?= -lelf
LIBBPF_LDLIBS := $(LIBBPF_A) $(LIBELF_LIBS) -lz

$(LIBBPF_SRC)/src/Makefile:
	@mkdir -p $(REPO_ROOT)/.local
	curl -sSfL -o $(LIBBPF_SRC).tar.gz \
		https://github.com/libbpf/libbpf/archive/refs/tags/v$(LIBBPF_VERSION).tar.gz
	echo "$(LIBBPF_SHA256)  $(LIBBPF_SRC).tar.gz" | sha256sum -c -
	tar -C $(REPO_ROOT)/.local -xzf $(LIBBPF_SRC).tar.gz
	@touch $@

$(LIBBPF_A): $(LIBBPF_SRC)/src/Makefile
	$(MAKE) -C $(LIBBPF_SRC)/src BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OUT)/obj DESTDIR=$(LIBBPF_OUT) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		EXTRA_CFLAGS="$(LIBELF_CFLAGS)" install

.PHONY: libbpf
libbpf: $(LIBBPF_A)
