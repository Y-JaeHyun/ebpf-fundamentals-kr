# 08장: Rust Aya 빌드 환경 (실행은 tools/vm의 VM 안에서)
# 버전 고정: Rust stable 1.96, nightly 2026-09-01 (BPF 쪽 크레이트 빌드용), bpf-linker v0.11.1
FROM rust:1.96-bookworm
ARG NIGHTLY=nightly-2026-09-01
ARG BPF_LINKER=v0.11.1
ARG BPF_LINKER_SHA256=e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8
RUN apt-get update && apt-get install -y --no-install-recommends zstd && rm -rf /var/lib/apt/lists/* \
    && rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src \
    && curl -sSfL -o /tmp/bl.tar.zst \
        "https://github.com/aya-rs/bpf-linker/releases/download/$BPF_LINKER/bpf-linker-x86_64-unknown-linux-musl.tar.zst" \
    && echo "$BPF_LINKER_SHA256  /tmp/bl.tar.zst" | sha256sum -c - \
    && tar -xpf /tmp/bl.tar.zst -C /usr/local/cargo/bin && rm /tmp/bl.tar.zst
ENV AYA_NIGHTLY=$NIGHTLY
