# syntax=docker/dockerfile:1
#
# Shareable RustMite appliance (control plane + CLI + scanner node + ClickHouse
# + agentless probe/loader binaries for x86_64, i686, aarch64, and armv7).
#
#   docker build -t rustmite:latest .
#   docker run --rm -p 8080:8080 -p 8443:8443 -p 8123:8123 rustmite:latest
#
# Open https://127.0.0.1:8080/ (self-signed TLS by default; accept the browser warning).
# Embedded ClickHouse listens on :8123 (rustmite / rustmite).
# Probe ELFs live under /opt/rustmite/probes/{x86_64,i686,aarch64,armv7}/ (RUSTMITE_PROBE_DIR).
#
# Runtime is Debian bookworm so the Rust binaries' glibc matches; ClickHouse is
# installed from the official deb repo into the same image.

ARG RUST_VERSION=1.89.0
ARG CLICKHOUSE_VERSION=24.8
ARG ZIG_VERSION=0.13.0

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src

ARG ZIG_VERSION

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config curl xz-utils \
 && rm -rf /var/lib/apt/lists/* \
 && set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) zarch=x86_64 ;; \
      aarch64|arm64) zarch=aarch64 ;; \
      *) zarch=x86_64 ;; \
    esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zarch}-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt \
 && ln -sf "/opt/zig-linux-${zarch}-${ZIG_VERSION}/zig" /usr/local/bin/zig \
 && zig version

# Pre-staged musl probe/loader ELFs from scripts/stage-share-probes.sh
# (x86_64, i686, aarch64, armv7). Copied as their own layer so missing
# 32-bit arches fail the build early and clearly.
COPY docker/share/probes /out/probes
RUN set -eu; \
    for arch in x86_64 i686 aarch64 armv7; do \
      test -x "/out/probes/${arch}/rustmite-probe" \
        || { echo "error: missing /out/probes/${arch}/rustmite-probe — run scripts/stage-share-probes.sh" >&2; exit 1; }; \
      test -x "/out/probes/${arch}/rustmite-loader" \
        || { echo "error: missing /out/probes/${arch}/rustmite-loader — run scripts/stage-share-probes.sh" >&2; exit 1; }; \
    done; \
    echo "==> prebuilt agentless probes:"; \
    ls -la /out/probes/x86_64 /out/probes/i686 /out/probes/aarch64 /out/probes/armv7

COPY . .

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
       /out/ \
 && for arch in x86_64 i686 aarch64 armv7; do \
      test -x "/out/probes/${arch}/rustmite-probe" \
        && test -x "/out/probes/${arch}/rustmite-loader" \
        || { echo "error: agentless ${arch} missing after build" >&2; exit 1; }; \
    done \
 && ls -la /out/probes/x86_64 /out/probes/i686 /out/probes/aarch64 /out/probes/armv7

# Official image — only used to copy the upstream entrypoint helper.
FROM clickhouse/clickhouse-server:${CLICKHOUSE_VERSION} AS clickhouse

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      tini \
      gnupg \
      apt-transport-https \
 && curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
      | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
      > /etc/apt/sources.list.d/clickhouse.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      clickhouse-server \
      clickhouse-client \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /var/lib/clickhouse /var/log/clickhouse-server \
 && mkdir -p /var/lib/clickhouse /var/log/clickhouse-server /var/run/clickhouse-server \
 && useradd --system --create-home --uid 10001 --home-dir /opt/rustmite rustmite

WORKDIR /opt/rustmite

COPY --from=builder /out/rustmite-server /out/rustmite-node /out/rustmite-cli /usr/local/bin/
COPY --from=builder /out/probes /opt/rustmite/probes
COPY --from=clickhouse /entrypoint.sh /ch-entrypoint.sh
COPY --chown=rustmite:rustmite checks /opt/rustmite/checks
COPY --chown=rustmite:rustmite fixtures /opt/rustmite/fixtures
COPY docker/clickhouse/init.sql /docker-entrypoint-initdb.d/01-rustmite.sql
COPY docker/share/clickhouse-listen.xml /etc/clickhouse-server/config.d/rustmite-listen.xml
COPY docker/share/clickhouse-users.xml /etc/clickhouse-server/users.d/rustmite.xml
COPY docker/share/entrypoint.sh /usr/local/bin/rustmite-entrypoint

RUN chmod +x /usr/local/bin/rustmite-entrypoint /ch-entrypoint.sh \
    /opt/rustmite/probes/x86_64/rustmite-probe \
    /opt/rustmite/probes/x86_64/rustmite-loader \
    /opt/rustmite/probes/i686/rustmite-probe \
    /opt/rustmite/probes/i686/rustmite-loader \
    /opt/rustmite/probes/aarch64/rustmite-probe \
    /opt/rustmite/probes/aarch64/rustmite-loader \
    /opt/rustmite/probes/armv7/rustmite-probe \
    /opt/rustmite/probes/armv7/rustmite-loader \
 && mkdir -p /opt/rustmite/data /opt/rustmite/tls /opt/rustmite/vault \
 && chown -R rustmite:rustmite /opt/rustmite \
 && rm -rf /var/lib/clickhouse/* /var/log/clickhouse-server/* \
 && mkdir -p /var/lib/clickhouse /var/log/clickhouse-server /var/run/clickhouse-server \
 && chown -R clickhouse:clickhouse /var/lib/clickhouse /var/log/clickhouse-server /var/run/clickhouse-server \
              /etc/clickhouse-server \
 && chmod 644 /etc/clickhouse-server/config.d/rustmite-listen.xml \
              /etc/clickhouse-server/users.d/rustmite.xml \
              /docker-entrypoint-initdb.d/01-rustmite.sql

# Empty control-plane + empty ClickHouse by default (no demo seed / no baked-in events).
ENV RUSTMITE_CHECKS=/opt/rustmite/checks \
    RUSTMITE_LISTEN=0.0.0.0:8080 \
    RUSTMITE_NODE_LISTEN=0.0.0.0:8443 \
    RUSTMITE_TLS_DIR=/opt/rustmite/tls \
    RUSTMITE_VAULT_KEY_FILE=/opt/rustmite/vault/master.key \
    RUSTMITE_CRED_KEY=/opt/rustmite/vault/cred.priv \
    RUSTMITE_CRED_PUBKEY=/opt/rustmite/vault/cred.pub \
    RUSTMITE_EMBEDDED_NODE=1 \
    RUSTMITE_STORE=/opt/rustmite/data/store.json \
    RUSTMITE_INGEST_DIR=/opt/rustmite/data/ingest \
    RUSTMITE_AUTH_FILE=/opt/rustmite/data/auth.json \
    RUSTMITE_PROBE_DIR=/opt/rustmite/probes \
    RUSTMITE_SEED_DEMO=0 \
    RUSTMITE_SCAN_SIM=0 \
    RUSTMITE_CLICKHOUSE=1 \
    RUSTMITE_EMBEDDED_CLICKHOUSE=1 \
    RUSTMITE_CLICKHOUSE_URL=http://127.0.0.1:8123 \
    RUSTMITE_CLICKHOUSE_USER=rustmite \
    RUSTMITE_CLICKHOUSE_PASSWORD=rustmite \
    RUSTMITE_CLICKHOUSE_DB=rustmite \
    CLICKHOUSE_USER=default \
    CLICKHOUSE_PASSWORD= \
    CLICKHOUSE_DB=rustmite \
    CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    CLICKHOUSE_WATCHDOG_ENABLE=0 \
    RUST_LOG=info

USER root
EXPOSE 8080 8443 8123
VOLUME ["/opt/rustmite/data", "/opt/rustmite/tls", "/opt/rustmite/vault", "/var/lib/clickhouse"]

ENTRYPOINT ["/usr/bin/tini", "--", "rustmite-entrypoint"]
CMD ["server"]
