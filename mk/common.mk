# 모든 챕터 code/Makefile이 공통으로 include 하는 규칙.
#
#   include ../../../mk/common.mk
#
# 제공하는 것
#   - 경로 변수: REPO_ROOT, INCLUDE_DIR, VMLINUX_H, OUT_DIR
#   - BPF C 컴파일 규칙: %.bpf.o <- %.bpf.c (CO-RE, BTF 포함)
#   - vmlinux.h 생성: 실행 중인 커널의 BTF에서 뽑는다(저장소에는 커밋하지 않음)
#   - SUDO: 이미 root면 빈 문자열, 아니면 sudo
#   - RUN_LOG: make run 결과를 남기는 파일 (out/run.log)

# `cmd | tee log` 에서 cmd 실패가 묻히지 않게 한다.
SHELL       := bash
.SHELLFLAGS := -o pipefail -c

REPO_ROOT   := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
INCLUDE_DIR := $(REPO_ROOT)/include
VMLINUX_H   := $(INCLUDE_DIR)/vmlinux.h
OUT_DIR     := out
RUN_LOG     := $(OUT_DIR)/run.log

CLANG   ?= clang
BPFTOOL ?= bpftool
GO      ?= go

# clang의 -target bpf 는 아키텍처를 모르므로 PT_REGS_* 매크로용으로 직접 알려 준다.
ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

BPF_CFLAGS ?= -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -I$(INCLUDE_DIR)

SUDO := $(if $(filter 0,$(shell id -u)),,sudo)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

%.bpf.o: %.bpf.c $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUT_DIR):
	mkdir -p $@

.PHONY: vmlinux
vmlinux: $(VMLINUX_H)
