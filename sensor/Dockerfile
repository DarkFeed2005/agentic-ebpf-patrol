# syntax=docker/dockerfile:1
#
# Builds cyber-patrol-loader. Note this image does NOT make the eBPF
# program's kernel dependency go away -- at *run* time the container still
# needs host BTF (/sys/kernel/btf/vmlinux), a bpffs mount, tracing access,
# and CAP_BPF/CAP_SYS_ADMIN (see docker-compose.yml's `sensor` service:
# privileged, pid: host, and the /sys/fs/bpf + /sys/kernel/tracing mounts).
# For a portfolio demo, running the loader directly on the host
# (`sudo ./target/release/cyber-patrol-loader`) is often simpler and sidesteps
# any base-image-vs-host kernel/toolchain friction entirely -- see README.
FROM rust:1-bookworm AS build

# clang/llvm/pkg-config/libelf/zlib are bpf-linker's build & link-time deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libelf-dev zlib1g-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker

WORKDIR /src
COPY . .
RUN cargo build --release -p cyber-patrol-loader

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cyber-patrol-loader /usr/local/bin/cyber-patrol-loader
ENTRYPOINT ["/usr/local/bin/cyber-patrol-loader"]
