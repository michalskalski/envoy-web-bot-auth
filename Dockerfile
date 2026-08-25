# syntax=docker/dockerfile:1

# This matches Envoy's official Rust dynamic-module example. cargo-zigbuild
# links the Rust runtime without a libgcc_s.so.1 dependency, which lets the
# module run in Envoy's stock distroless image. The pinned image is tag 0.19.8.
FROM ghcr.io/rust-cross/cargo-zigbuild:0.19.8@sha256:b3b422171a9e2eacc5e4d5c6eb0d95c2c7e65cad2a62ea6938ae9805ce78df3e AS builder

RUN apt-get update \
    && apt-get install --no-install-recommends --yes clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# cargo-zigbuild 0.19.8 ships an older Cargo than this Edition 2024 project.
RUN rustup toolchain install 1.97.1 \
    && rustup default 1.97.1

WORKDIR /build

# Cache dependency compilation independently from source changes.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib
RUN cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu

# Pin the runtime image to the Envoy Gateway v1.9.0 default proxy. This is the
# multi-architecture image-index digest. BuildKit selects the target platform.
FROM docker.io/envoyproxy/envoy:distroless-v1.39.0@sha256:7877ad87afd7459e1bd2a077ff601fec7c93aeecd62e71664560d96328c62cf4

COPY --from=builder /build/target/x86_64-unknown-linux-gnu/release/libenvoy_web_bot_auth.so /etc/envoy/dynamic-modules/libenvoy_web_bot_auth.so
