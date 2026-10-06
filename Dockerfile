# syntax=docker/dockerfile:1
#
# Shareable RustMite image (control plane + CLI + scanner node).
#
#   docker build -t rustmite:latest .
#   docker run --rm -p 8080:8080 -p 8443:8443 rustmite:latest
#
# Open https://127.0.0.1:8080/ (self-signed TLS by default; accept the browser warning).

ARG RUST_VERSION=1.89.0

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src

# System deps for a full workspace build (rustls — no OpenSSL).
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Copy the whole workspace (see .dockerignore). Cache cargo registry + target.
COPY . .

# Image tag → UI / `--version`. share-image.sh passes `--build-arg VERSION=<tag>`.
# Declared after COPY so a new tag invalidates this layer (and cargo env fingerprint).
ARG VERSION=
ENV RUSTMITE_VERSION=$VERSION

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eu; \
    if [ -n "${VERSION}" ]; then \
      awk -v v="${VERSION#v}" ' \
        BEGIN { inpkg=0; done=0 } \
        $0 == "[workspace.package]" { inpkg=1 } \
        inpkg && /^version = / && !done { printf "version = \"%s\"\n", v; done=1; next } \
        /^\[/ && $0 != "[workspace.package]" { inpkg=0 } \
        { print } \
        END { if (!done) exit 1 } \
      ' Cargo.toml > Cargo.toml.version && mv Cargo.toml.version Cargo.toml; \
    fi; \
    cargo build --release \
      -p rustmite-server \
      -p rustmite-node \
      -p rustmite-cli \
    && mkdir -p /out \
 && cp target/release/rustmite-server \
       target/release/rustmite-node \
       target/release/rustmite-cli \
       /out/

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 10001 --home-dir /opt/rustmite rustmite

WORKDIR /opt/rustmite

COPY --from=builder /out/rustmite-server /out/rustmite-node /out/rustmite-cli /usr/local/bin/
COPY --chown=rustmite:rustmite checks /opt/rustmite/checks
COPY --chown=rustmite:rustmite fixtures /opt/rustmite/fixtures
COPY --chown=rustmite:rustmite docker/share/entrypoint.sh /usr/local/bin/rustmite-entrypoint

RUN chmod +x /usr/local/bin/rustmite-entrypoint \
 && mkdir -p /opt/rustmite/data /opt/rustmite/tls /opt/rustmite/vault \
 && chown -R rustmite:rustmite /opt/rustmite

ENV RUSTMITE_CHECKS=/opt/rustmite/checks \
    RUSTMITE_LISTEN=0.0.0.0:8080 \
    RUSTMITE_NODE_LISTEN=0.0.0.0:8443 \
    RUSTMITE_TLS_DIR=/opt/rustmite/tls \
    RUSTMITE_VAULT_KEY_FILE=/opt/rustmite/vault/master.key \
    RUSTMITE_CRED_PUBKEY=/opt/rustmite/vault/cred.pub \
    RUSTMITE_STORE=/opt/rustmite/data/store.json \
    RUSTMITE_AUTH_FILE=/opt/rustmite/data/auth.json \
    RUSTMITE_SEED_DEMO=0 \
    RUSTMITE_SCAN_SIM=0 \
    RUST_LOG=info

USER rustmite
EXPOSE 8080 8443
VOLUME ["/opt/rustmite/data", "/opt/rustmite/tls", "/opt/rustmite/vault"]

ENTRYPOINT ["/usr/bin/tini", "--", "rustmite-entrypoint"]
# HTTPS by default (auto self-signed certs under RUSTMITE_TLS_DIR). Empty fleet.
# Opt out: docker run … rustmite:latest server --no-tls
CMD ["server"]
