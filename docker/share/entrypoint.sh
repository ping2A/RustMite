#!/bin/sh
# Select which binary to run from the shared image.
#   docker run rustmite:latest server …   # starts embedded ClickHouse + control plane
#   docker run rustmite:latest node …
#   docker run rustmite:latest cli scan-fixture --fixture /opt/rustmite/fixtures/…
#
# Note: these messages appear when the *container* starts (docker run / compose up),
# not during `docker build` / share-image.sh compilation.
set -eu

cmd="${1:-server}"
if [ "$#" -gt 0 ]; then
  shift
fi

run_as_rustmite() {
  if [ "$(id -u)" -eq 0 ]; then
    if command -v runuser >/dev/null 2>&1; then
      exec runuser -u rustmite -- "$@"
    fi
    if command -v su-exec >/dev/null 2>&1; then
      exec su-exec rustmite "$@"
    fi
    if command -v gosu >/dev/null 2>&1; then
      exec gosu rustmite "$@"
    fi
  fi
  exec "$@"
}

wait_clickhouse() {
  i=0
  while [ "$i" -lt 90 ]; do
    if curl -fsS "http://127.0.0.1:8123/ping" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "error: embedded ClickHouse did not become ready on :8123" >&2
  if [ -f /var/log/clickhouse-server/rustmite-ch.log ]; then
    echo "==> last ClickHouse log lines:" >&2
    tail -n 40 /var/log/clickhouse-server/rustmite-ch.log >&2 || true
  fi
  return 1
}

start_embedded_clickhouse() {
  case "${RUSTMITE_EMBEDDED_CLICKHOUSE:-1}" in
    0|false|off|no) return 0 ;;
  esac
  case "${RUSTMITE_CLICKHOUSE:-1}" in
    0|false|off|no) return 0 ;;
  esac

  if curl -fsS "http://127.0.0.1:8123/ping" >/dev/null 2>&1; then
    echo "==> ClickHouse already reachable on :8123"
  else
    echo "==> Starting embedded ClickHouse"
    mkdir -p /var/log/clickhouse-server /var/lib/clickhouse /var/run/clickhouse-server
    chown -R clickhouse:clickhouse /var/lib/clickhouse /var/log/clickhouse-server /var/run/clickhouse-server \
      2>/dev/null || true

    export CLICKHOUSE_WATCHDOG_ENABLE="${CLICKHOUSE_WATCHDOG_ENABLE:-0}"
    export CLICKHOUSE_USER="${CLICKHOUSE_USER:-default}"
    export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"
    export CLICKHOUSE_DB="${CLICKHOUSE_DB:-rustmite}"
    export CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT="${CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT:-1}"

    # Prefer upstream helper (copied to /ch-entrypoint.sh); else start the daemon directly.
    if [ -x /ch-entrypoint.sh ]; then
      if command -v setsid >/dev/null 2>&1; then
        setsid /ch-entrypoint.sh >>/var/log/clickhouse-server/rustmite-ch.log 2>&1 < /dev/null &
      else
        nohup /ch-entrypoint.sh >>/var/log/clickhouse-server/rustmite-ch.log 2>&1 < /dev/null &
      fi
    elif command -v clickhouse-server >/dev/null 2>&1; then
      if command -v setsid >/dev/null 2>&1; then
        setsid clickhouse-server --config-file=/etc/clickhouse-server/config.xml \
          >>/var/log/clickhouse-server/rustmite-ch.log 2>&1 < /dev/null &
      else
        nohup clickhouse-server --config-file=/etc/clickhouse-server/config.xml \
          >>/var/log/clickhouse-server/rustmite-ch.log 2>&1 < /dev/null &
      fi
    else
      echo "error: ClickHouse is not installed in this image" >&2
      return 1
    fi

    wait_clickhouse
    echo "==> Embedded ClickHouse is ready"

    # Schema (also applied by /ch-entrypoint.sh via /docker-entrypoint-initdb.d on first boot).
    if [ -f /docker-entrypoint-initdb.d/01-rustmite.sql ]; then
      clickhouse-client --multiquery < /docker-entrypoint-initdb.d/01-rustmite.sql \
        >/dev/null 2>&1 || true
    fi
  fi

  # Hint whether hosts will survive this boot (named volume vs anonymous/empty).
  if [ -d /var/lib/clickhouse/store ] || [ -d /var/lib/clickhouse/data ] \
    || [ -d /var/lib/clickhouse/metadata ]; then
    echo "==> ClickHouse data dir looks populated (reusing mounted volume)"
  else
    echo "==> ClickHouse data dir is empty — fleet starts fresh"
    echo "    Mount a named volume to keep hosts across image upgrades:"
    echo "      -v rustmite-ch-data:/var/lib/clickhouse"
    echo "      -v rustmite-data:/opt/rustmite/data"
    echo "      -v rustmite-tls:/opt/rustmite/tls"
    echo "      -v rustmite-vault:/opt/rustmite/vault"
  fi


  export RUSTMITE_CLICKHOUSE="${RUSTMITE_CLICKHOUSE:-1}"
  export RUSTMITE_CLICKHOUSE_URL="${RUSTMITE_CLICKHOUSE_URL:-http://127.0.0.1:8123}"
  export RUSTMITE_CLICKHOUSE_USER="${RUSTMITE_CLICKHOUSE_USER:-${CLICKHOUSE_USER:-default}}"
  export RUSTMITE_CLICKHOUSE_PASSWORD="${RUSTMITE_CLICKHOUSE_PASSWORD:-${CLICKHOUSE_PASSWORD:-}}"
  export RUSTMITE_CLICKHOUSE_DB="${RUSTMITE_CLICKHOUSE_DB:-${CLICKHOUSE_DB:-rustmite}}"
}

list_agentless_probes() {
  dir="${RUSTMITE_PROBE_DIR:-/opt/rustmite/probes}"
  echo "==> Agentless probes in ${dir}:"
  for arch in x86_64 i686 aarch64 armv7; do
    p="${dir}/${arch}/rustmite-probe"
    l="${dir}/${arch}/rustmite-loader"
    if [ -x "$p" ] && [ -x "$l" ]; then
      echo "    OK  ${arch}  probe=$(wc -c <"$p")B  loader=$(wc -c <"$l")B"
    else
      echo "    MISSING ${arch} (expected ${p} + loader)" >&2
    fi
  done
}

ensure_cred_keypair() {
  priv="${RUSTMITE_CRED_KEY:-/opt/rustmite/vault/cred.priv}"
  pub="${RUSTMITE_CRED_PUBKEY:-/opt/rustmite/vault/cred.pub}"
  vault_dir="$(dirname "$pub")"
  mkdir -p "$vault_dir"
  chown -R rustmite:rustmite "$vault_dir" 2>/dev/null || true
  export RUSTMITE_CRED_KEY="$priv"
  export RUSTMITE_CRED_PUBKEY="$pub"
  if [ -f "$pub" ]; then
    echo "==> Credential pubkey present: $pub"
    return 0
  fi
  echo "==> Generating fleet credential keypair ($priv + $pub)"
  if [ "$(id -u)" -eq 0 ]; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u rustmite -- rustmite-node --init-cred-keys --cred-key "$priv" --cred-pubkey "$pub"
    elif command -v su-exec >/dev/null 2>&1; then
      su-exec rustmite rustmite-node --init-cred-keys --cred-key "$priv" --cred-pubkey "$pub"
    elif command -v gosu >/dev/null 2>&1; then
      gosu rustmite rustmite-node --init-cred-keys --cred-key "$priv" --cred-pubkey "$pub"
    else
      rustmite-node --init-cred-keys --cred-key "$priv" --cred-pubkey "$pub"
    fi
  else
    rustmite-node --init-cred-keys --cred-key "$priv" --cred-pubkey "$pub"
  fi
  if [ ! -f "$pub" ]; then
    echo "error: failed to create credential pubkey at $pub" >&2
    return 1
  fi
  echo "==> Credential pubkey ready for sealing SSH secrets"
}

wait_control_plane() {
  # Allow slow TLS/boot on large appliances; virtual ingest reindex runs in the
  # background and must not block :8080 (see rustmite-server startup spawn).
  max="${RUSTMITE_WAIT_CONTROL_PLANE_SECS:-180}"
  i=0
  while [ "$i" -lt "$max" ]; do
    if curl -kfsS "https://127.0.0.1:8080/v1/health" >/dev/null 2>&1 \
      || curl -fsS "http://127.0.0.1:8080/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "error: control plane did not become ready on :8080 after ${max}s" >&2
  return 1
}

start_embedded_node() {
  case "${RUSTMITE_EMBEDDED_NODE:-1}" in
    0|false|off|no) return 0 ;;
  esac

  priv="${RUSTMITE_CRED_KEY:-/opt/rustmite/vault/cred.priv}"
  pub="${RUSTMITE_CRED_PUBKEY:-/opt/rustmite/vault/cred.pub}"
  probe_dir="${RUSTMITE_PROBE_DIR:-/opt/rustmite/probes}"
  node_url="${RUSTMITE_EMBEDDED_NODE_URL:-https://127.0.0.1:8443}"

  echo "==> Starting embedded scanner node → ${node_url}"
  mkdir -p /var/log/rustmite
  chown rustmite:rustmite /var/log/rustmite 2>/dev/null || true
  log=/var/log/rustmite/embedded-node.log

  if [ "$(id -u)" -eq 0 ]; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u rustmite -- rustmite-node \
        --server "$node_url" --allow-insecure \
        --cred-key "$priv" --cred-pubkey "$pub" \
        --probe-dir "$probe_dir" >>"$log" 2>&1 &
    elif command -v su-exec >/dev/null 2>&1; then
      su-exec rustmite rustmite-node \
        --server "$node_url" --allow-insecure \
        --cred-key "$priv" --cred-pubkey "$pub" \
        --probe-dir "$probe_dir" >>"$log" 2>&1 &
    elif command -v gosu >/dev/null 2>&1; then
      gosu rustmite rustmite-node \
        --server "$node_url" --allow-insecure \
        --cred-key "$priv" --cred-pubkey "$pub" \
        --probe-dir "$probe_dir" >>"$log" 2>&1 &
    else
      rustmite-node \
        --server "$node_url" --allow-insecure \
        --cred-key "$priv" --cred-pubkey "$pub" \
        --probe-dir "$probe_dir" >>"$log" 2>&1 &
    fi
  else
    rustmite-node \
      --server "$node_url" --allow-insecure \
      --cred-key "$priv" --cred-pubkey "$pub" \
      --probe-dir "$probe_dir" >>"$log" 2>&1 &
  fi
  NODE_PID=$!
  echo "==> Embedded scanner node pid=${NODE_PID} (log: ${log})"
}

run_server_with_embedded_node() {
  ensure_cred_keypair

  if [ "$(id -u)" -eq 0 ]; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u rustmite -- rustmite-server "$@" &
    elif command -v su-exec >/dev/null 2>&1; then
      su-exec rustmite rustmite-server "$@" &
    elif command -v gosu >/dev/null 2>&1; then
      gosu rustmite rustmite-server "$@" &
    else
      rustmite-server "$@" &
    fi
  else
    rustmite-server "$@" &
  fi
  SERVER_PID=$!
  echo "==> Control plane pid=${SERVER_PID}"

  cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    if [ -n "${NODE_PID:-}" ]; then
      kill "$NODE_PID" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT INT TERM

  if ! wait_control_plane; then
    cleanup
    exit 1
  fi
  start_embedded_node
  wait "$SERVER_PID"
  status=$?
  trap - EXIT INT TERM
  cleanup
  exit "$status"
}

case "$cmd" in
  server|rustmite-server)
    export RUSTMITE_PROBE_DIR="${RUSTMITE_PROBE_DIR:-/opt/rustmite/probes}"
    list_agentless_probes
    start_embedded_clickhouse
    run_server_with_embedded_node "$@"
    ;;
  node|rustmite-node)
    export RUSTMITE_PROBE_DIR="${RUSTMITE_PROBE_DIR:-/opt/rustmite/probes}"
    list_agentless_probes
    # Ensure the node sees bundled agentless ELFs unless the caller overrides --probe-dir.
    has_probe_dir=0
    for a in "$@"; do
      case "$a" in --probe-dir|--probe-dir=*) has_probe_dir=1 ;; esac
    done
    if [ "$has_probe_dir" -eq 0 ] && [ -d "$RUSTMITE_PROBE_DIR" ]; then
      run_as_rustmite rustmite-node --probe-dir "$RUSTMITE_PROBE_DIR" "$@"
    else
      run_as_rustmite rustmite-node "$@"
    fi
    ;;
  cli|rustmite-cli)
    run_as_rustmite rustmite-cli "$@"
    ;;
  -h|--help|help)
    cat <<'EOF'
RustMite image entrypoint

Usage:
  rustmite-entrypoint server [args…]   # control plane + ClickHouse + embedded scanner node
  rustmite-entrypoint node   [args…]   # scanner node (bundled probe/loader under /opt/rustmite/probes)
  rustmite-entrypoint cli    [args…]   # operator CLI

These messages appear on container start (docker run), not during image build.

Bundled agentless binaries:
  /opt/rustmite/probes/x86_64/{rustmite-probe,rustmite-loader}
  /opt/rustmite/probes/i686/{rustmite-probe,rustmite-loader}
  /opt/rustmite/probes/aarch64/{rustmite-probe,rustmite-loader}
  /opt/rustmite/probes/armv7/{rustmite-probe,rustmite-loader}

On server start the appliance generates /opt/rustmite/vault/cred.{priv,pub} if missing
(so SSH password hosts can be sealed) and starts an embedded scanner node unless
RUSTMITE_EMBEDDED_NODE=0.

Examples:
  docker run --rm -p 8080:8080 -p 8443:8443 -p 8123:8123 rustmite:latest
  # → https://127.0.0.1:8080/ (self-signed; accept browser warning)
  # → ClickHouse HTTP on :8123 (user/pass rustmite/rustmite)

  docker run --rm -e RUSTMITE_EMBEDDED_CLICKHOUSE=0 rustmite:latest server
  docker run --rm -e RUSTMITE_EMBEDDED_NODE=0 rustmite:latest server
  docker run --rm rustmite:latest server --no-tls
  docker run --rm rustmite:latest node --server https://host:8443 --allow-insecure
  docker run --rm rustmite:latest cli scan-fixture \
    --fixture /opt/rustmite/fixtures/diamorphine-hidden-pid
EOF
    exit 0
    ;;
  *)
    start_embedded_clickhouse
    run_server_with_embedded_node "$cmd" "$@"
    ;;
esac
