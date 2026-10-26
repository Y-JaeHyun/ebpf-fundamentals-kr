# 호스트 커널을 qemu(KVM)로 부팅해 부팅 인자만 바꿔 보는 실습용 VM 이미지 (virtme-ng)
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        virtme-ng qemu-system-x86 busybox-static iproute2 procps kmod udev zstd ca-certificates \
    && rm -rf /var/lib/apt/lists/*
