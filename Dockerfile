# syntax=docker/dockerfile:1.7
#
# BitAiir Core — reproducible container image.
#
# Two stages:
#   1. `builder` compiles `bitaiird` and `bitaiir-cli` in release mode.
#   2. Runtime stage copies just the binaries onto `debian:stable-slim`,
#      creates a non-root user, and exposes the RPC + P2P ports.
#
# Build locally:
#     docker build -t bitaiir:dev .
#
# Run a testnet node with persistent data:
#     docker run --rm -v bitaiir_data:/data \
#         -p 18443:18443 -p 18444:18444 \
#         bitaiir:dev --testnet -i

FROM rust:1.95-slim-bookworm AS builder

ENV CARGO_TERM_COLOR=always \
    CARGO_INCREMENTAL=0

# `arboard` (clipboard crate used by the TUI) needs the xcb headers at
# compile time even though we never run a display inside the container.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libxcb-render0-dev \
        libxcb-shape0-dev \
        libxcb-xfixes0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo build --release --locked --bin bitaiird --bin bitaiir-cli

# -----------------------------------------------------------------------------

FROM debian:stable-slim AS runtime

# `libxcb*.so.1` — runtime counterpart of the `-dev` headers used in
# the builder stage; the `arboard` dep dlopens them on startup.
# `ca-certificates` covers any future outbound HTTPS (DNS seeds, etc.)
# so a bare `docker run` image "just works".
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libxcb-render0 \
        libxcb-shape0 \
        libxcb-xfixes0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 bitaiir \
    && useradd --system --uid 10001 --gid bitaiir --home-dir /data --shell /usr/sbin/nologin bitaiir \
    && mkdir -p /data \
    && chown -R bitaiir:bitaiir /data

COPY --from=builder /src/target/release/bitaiird   /usr/local/bin/bitaiird
COPY --from=builder /src/target/release/bitaiir-cli /usr/local/bin/bitaiir-cli

# Mainnet P2P (8444) + RPC (8443); testnet P2P (18444) + RPC (18443).
# Publishing all four lets the same image serve either network without
# a rebuild — pick at runtime with `--testnet` or `--rpc-addr`.
EXPOSE 8443 8444 18443 18444

VOLUME ["/data"]

USER bitaiir
WORKDIR /data

ENTRYPOINT ["bitaiird"]
CMD ["--data-dir", "/data"]
