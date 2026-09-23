#!/usr/bin/env bash
# RustMite local stack control — mobipwn-style start/stop/restart/status.
# Config lives in config/dev.env (and optional .dev/config.env). No env exports required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

relpath() {
  local p="${1:-}"
  if [[ "$p" == "$ROOT"/* ]]; then
    echo "${p#"$ROOT/"}"
  else
    echo "$p"
  fi
}

PID_DIR="$ROOT/.dev"
SERVER_PID="$PID_DIR/server.pid"
SERVER_LOG="$PID_DIR/server.log"
NODE_PID="$PID_DIR/node.pid"
NODE_LOG="$PID_DIR/node.log"
CH_COMPOSE="$ROOT/docker/clickhouse/docker-compose.yml"

DEFAULT_CONFIG="$ROOT/config/dev.env"
LOCAL_CONFIG="$PID_DIR/config.env"

# ── config ──────────────────────────────────────────────────────────────────

ensure_dirs() {
  mkdir -p "$PID_DIR"
  if [[ ! -f "$LOCAL_CONFIG" && -f "$DEFAULT_CONFIG" ]]; then
    cp "$DEFAULT_CONFIG" "$LOCAL_CONFIG"
  fi
}

load_config() {
  ensure_dirs
  # Defaults first, then repo config, then local overrides.
  LISTEN=127.0.0.1:18080
  NODE_LISTEN=127.0.0.1:18443
  SEED_DEMO=0
  SEED_HOSTS=500
  SCAN_SIM=1
  DEFAULT_CHECK_SET=standard
  SCAN_INTERVAL=15m
  SCAN_JITTER_PCT=20
  MAX_CONCURRENT_SCANS=32
  SCAN_TIMEOUT_SECS=120
  SCAN_HISTORY_PER_HOST=3
  SSH_CONNECT_TIMEOUT_SECS=10
  SSH_AUTH_TIMEOUT_SECS=20
  SSH_CMD_TIMEOUT_SECS=60
  SSH_INACTIVITY_TIMEOUT_SECS=90
  SSH_DELIVERY_TIMEOUT_SECS=30
  SSH_FINGERPRINT_TIMEOUT_SECS=10
  SSH_CONNECT_DELAY_MS=0
  SSH_TIMEOUT_JITTER_PCT=10
  NOISE_XX=1
  TLS=1
  TLS_DIR=.dev/tls
  TLS_CERT=
  TLS_KEY=
  NODE_TLS_CERT=
  NODE_TLS_KEY=
  NODE_TLS_CLIENT_CA=
  VAULT_KEY_FILE=.dev/vault/master.key
  CRED_PUBKEY=.dev/vault/cred.pub
  CRED_KEY=.dev/vault/cred.priv
  CLICKHOUSE=1
  NODE=1
  CLICKHOUSE_URL=http://127.0.0.1:8123
  CLICKHOUSE_USER=rustmite
  CLICKHOUSE_PASSWORD=rustmite
  CLICKHOUSE_DB=rustmite
  CLICKHOUSE_TIMEOUT_SECS=30
  CHECKS=checks
  STORE_FILE=.dev/store.json

  if [[ -f "$DEFAULT_CONFIG" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$DEFAULT_CONFIG"; set +a
  fi
  if [[ -f "$LOCAL_CONFIG" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$LOCAL_CONFIG"; set +a
  fi
}

listen_port() {
  local addr="${1:-$LISTEN}"
  echo "${addr##*:}"
}

# ── process helpers ─────────────────────────────────────────────────────────

port_listener_pids() {
  local port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true
    return 0
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp "sport = :$port" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true
  fi
}

free_port() {
  local port=$1
  local pids
  pids=$(port_listener_pids "$port")
  if [[ -n "${pids:-}" ]]; then
    echo "    Freeing port $port"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 0.4
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
  fi
}

pid_alive() {
  local pid=${1:-}
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

server_pid() {
  if [[ -f "$SERVER_PID" ]]; then
    cat "$SERVER_PID"
  fi
}

listen_scheme() {
  if [[ "${TLS:-1}" == "0" || "${TLS:-1}" == "false" ]]; then
    echo "http"
  else
    echo "https"
  fi
}

health_url() {
  local addr="${LISTEN:-127.0.0.1:18080}"
  # If bound to 0.0.0.0, probe localhost.
  local host="${addr%:*}"
  local port="${addr##*:}"
  if [[ "$host" == "0.0.0.0" || "$host" == "::" || "$host" == "[::]" ]]; then
    host="127.0.0.1"
  fi
  echo "$(listen_scheme)://${host}:${port}/v1/health"
}

console_url() {
  local addr="${LISTEN:-127.0.0.1:18080}"
  local host="${addr%:*}"
  local port="${addr##*:}"
  if [[ "$host" == "0.0.0.0" || "$host" == "::" || "$host" == "[::]" ]]; then
    host="127.0.0.1"
  fi
  echo "$(listen_scheme)://${host}:${port}/"
}

wait_for_health() {
  local url
  url=$(health_url)
  local -a curl_opts=(-sf)
  if [[ "$(listen_scheme)" == "https" ]]; then
    curl_opts+=(-k)
  fi
  for _ in $(seq 1 60); do
    if curl "${curl_opts[@]}" "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "Server did not become healthy: $url" >&2
  echo "---- last log lines ----" >&2
  tail -n 40 "$SERVER_LOG" 2>/dev/null >&2 || true
  return 1
}

# ── clickhouse ──────────────────────────────────────────────────────────────

clickhouse_up() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker required for ClickHouse" >&2
    return 1
  fi
  echo "==> ClickHouse (docker/clickhouse)"
  docker compose -f "$CH_COMPOSE" up -d
  for i in $(seq 1 45); do
    if curl -sf "${CLICKHOUSE_URL}/ping" >/dev/null 2>&1 \
      || curl -sf -u "${CLICKHOUSE_USER}:${CLICKHOUSE_PASSWORD}" "${CLICKHOUSE_URL}/?query=SELECT%201" >/dev/null 2>&1; then
      echo "    ClickHouse ready at $CLICKHOUSE_URL"
      # Apply schema if present
      if [[ -f "$ROOT/docker/clickhouse/init.sql" ]]; then
        docker compose -f "$CH_COMPOSE" exec -T clickhouse \
          clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
          --multiquery <"$ROOT/docker/clickhouse/init.sql" >/dev/null 2>&1 || true
      fi
      return 0
    fi
    sleep 1
  done
  echo "ClickHouse did not become ready" >&2
  docker compose -f "$CH_COMPOSE" logs --tail 20 clickhouse 2>&1 || true
  return 1
}

clickhouse_down() {
  if command -v docker >/dev/null 2>&1; then
    echo "==> Stopping ClickHouse"
    docker compose -f "$CH_COMPOSE" down >/dev/null 2>&1 || true
  fi
}

# Wipe ClickHouse data volume and recreate schema (fresh install).
clickhouse_reset() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker required for ClickHouse" >&2
    return 1
  fi
  echo "==> Resetting ClickHouse (remove containers + data volume)"
  docker compose -f "$CH_COMPOSE" down -v >/dev/null 2>&1 || true
  # Named volume may linger if compose project name differs — remove explicitly.
  local vol
  for vol in rustmite_ch_data docker_rustmite_ch_data clickhouse_rustmite_ch_data \
             rustfly_ch_data docker_rustfly_ch_data clickhouse_rustfly_ch_data; do
    docker volume rm "$vol" >/dev/null 2>&1 || true
  done
  # Also catch project-prefixed names from this directory.
  docker volume ls -q --filter "name=rustmite_ch_data" | while read -r v; do
    [[ -n "$v" ]] && docker volume rm "$v" >/dev/null 2>&1 || true
  done
  docker volume ls -q --filter "name=rustfly_ch_data" | while read -r v; do
    [[ -n "$v" ]] && docker volume rm "$v" >/dev/null 2>&1 || true
  done
  echo "    volumes removed"
  clickhouse_up
  echo "    ClickHouse fresh install ready (schema from docker/clickhouse/init.sql)"
}

clickhouse_status() {
  if curl -sf "${CLICKHOUSE_URL}/ping" >/dev/null 2>&1 \
    || curl -sf -u "${CLICKHOUSE_USER}:${CLICKHOUSE_PASSWORD}" "${CLICKHOUSE_URL}/?query=SELECT%201" >/dev/null 2>&1; then
    echo "ClickHouse: up ($CLICKHOUSE_URL)"
  else
    echo "ClickHouse: down"
  fi
}

# ── commands ────────────────────────────────────────────────────────────────

build_and_run_server() {
  local -a args=(
    --listen "$LISTEN"
    --node-listen "$NODE_LISTEN"
    --checks "$CHECKS"
    --default-check-set "$DEFAULT_CHECK_SET"
    --scan-interval "$SCAN_INTERVAL"
    --scan-jitter-pct "$SCAN_JITTER_PCT"
    --max-concurrent-scans "$MAX_CONCURRENT_SCANS"
    --scan-timeout-secs "$SCAN_TIMEOUT_SECS"
    --scan-history-per-host "${SCAN_HISTORY_PER_HOST:-3}"
    --ssh-connect-timeout-secs "${SSH_CONNECT_TIMEOUT_SECS:-10}"
    --ssh-auth-timeout-secs "${SSH_AUTH_TIMEOUT_SECS:-20}"
    --ssh-cmd-timeout-secs "${SSH_CMD_TIMEOUT_SECS:-60}"
    --ssh-inactivity-timeout-secs "${SSH_INACTIVITY_TIMEOUT_SECS:-90}"
    --ssh-delivery-timeout-secs "${SSH_DELIVERY_TIMEOUT_SECS:-30}"
    --ssh-fingerprint-timeout-secs "${SSH_FINGERPRINT_TIMEOUT_SECS:-10}"
    --ssh-connect-delay-ms "${SSH_CONNECT_DELAY_MS:-0}"
    --ssh-timeout-jitter-pct "${SSH_TIMEOUT_JITTER_PCT:-10}"
    --clickhouse-timeout-secs "${CLICKHOUSE_TIMEOUT_SECS:-30}"
  )
  STORE_FILE="${STORE_FILE:-.dev/store.json}"
  args+=(--store "$STORE_FILE")
  if [[ "${RESET_STORE:-0}" == "1" || "${RESET_STORE:-0}" == "true" ]]; then
    args+=(--reset-store)
  fi
  if [[ "${SEED_DEMO}" == "1" || "${SEED_DEMO}" == "true" ]]; then
    args+=(--seed-demo --seed-hosts "$SEED_HOSTS")
  fi
  if [[ "${TLS:-1}" == "0" || "${TLS:-1}" == "false" ]]; then
    args+=(--no-tls)
  else
    if [[ -n "${TLS_DIR:-}" ]]; then
      args+=(--tls-dir "$TLS_DIR")
    fi
    if [[ -n "${TLS_CERT:-}" ]]; then
      args+=(--tls-cert "$TLS_CERT")
    fi
    if [[ -n "${TLS_KEY:-}" ]]; then
      args+=(--tls-key "$TLS_KEY")
    fi
  fi
  if [[ -n "${NODE_TLS_CERT:-}" ]]; then
    args+=(--node-tls-cert "$NODE_TLS_CERT")
  fi
  if [[ -n "${NODE_TLS_KEY:-}" ]]; then
    args+=(--node-tls-key "$NODE_TLS_KEY")
  fi
  if [[ -n "${NODE_TLS_CLIENT_CA:-}" ]]; then
    args+=(--node-tls-client-ca "$NODE_TLS_CLIENT_CA")
  fi
  if [[ -n "${VAULT_KEY_FILE:-}" ]]; then
    args+=(--vault-key-file "$VAULT_KEY_FILE")
  fi
  if [[ -n "${CRED_PUBKEY:-}" ]]; then
    args+=(--cred-pubkey "$CRED_PUBKEY")
  fi

  # Bool toggles via process env for this child only (clap env=…), so we never need
  # the operator to export anything in their shell.
  local scan_sim_env=true noise_env=true
  if [[ "${SCAN_SIM}" == "0" || "${SCAN_SIM}" == "false" ]]; then
    scan_sim_env=false
  fi
  if [[ "${NOISE_XX}" == "0" || "${NOISE_XX}" == "false" ]]; then
    noise_env=false
  fi

  (
    export RUSTMITE_SCAN_SIM="$scan_sim_env"
    export RUSTMITE_NOISE_XX="$noise_env"
    export RUSTMITE_CLICKHOUSE_USER="$CLICKHOUSE_USER"
    export RUSTMITE_CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD"
    export RUSTMITE_CLICKHOUSE_DB="$CLICKHOUSE_DB"
    export RUSTMITE_CLICKHOUSE_TIMEOUT_SECS="${CLICKHOUSE_TIMEOUT_SECS:-30}"
    if [[ "${CLICKHOUSE}" == "0" || "${CLICKHOUSE}" == "false" ]]; then
      export RUSTMITE_CLICKHOUSE=0
    else
      export RUSTMITE_CLICKHOUSE=1
      export RUSTMITE_CLICKHOUSE_URL="$CLICKHOUSE_URL"
      args+=(--clickhouse-url "$CLICKHOUSE_URL")
    fi
    local bin="$ROOT/target/debug/rustmite-server"
    if [[ ! -x "$bin" ]]; then
      echo "missing $bin — build failed?" >&2
      exit 1
    fi
    nohup "$bin" "${args[@]}" >"$SERVER_LOG" 2>&1 &
    echo $! >"$SERVER_PID"
  )
}

cmd_stop() {
  load_config
  echo "==> Stopping rustmite-node"
  local npid
  npid=$(cat "$NODE_PID" 2>/dev/null || true)
  if pid_alive "$npid"; then
    kill "$npid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      pid_alive "$npid" || break
      sleep 0.2
    done
    pid_alive "$npid" && kill -9 "$npid" 2>/dev/null || true
  fi
  rm -f "$NODE_PID"

  echo "==> Stopping rustmite-server"
  local pid
  pid=$(server_pid || true)
  if pid_alive "$pid"; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      pid_alive "$pid" || break
      sleep 0.2
    done
    pid_alive "$pid" && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$SERVER_PID"
  free_port "$(listen_port "$LISTEN")"
  free_port "$(listen_port "$NODE_LISTEN")"
  echo "    stopped"
}

  cmd_start() {
  load_config
  CLICKHOUSE_RESET=0
  RESET_STORE=0
  # Flags override config/dev.env — pass explicitly on the CLI.
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --clickhouse|clickhouse) CLICKHOUSE=1 ;;
      --no-clickhouse) CLICKHOUSE=0 ;;
      --node) NODE=1 ;;
      --no-node) NODE=0 ;;
      --fresh-clickhouse|--reset-clickhouse)
        CLICKHOUSE=1
        CLICKHOUSE_RESET=1
        ;;
      --seed-demo|seed-demo)
        SEED_DEMO=1
        if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
          SEED_HOSTS="$2"
          shift
        fi
        ;;
      --seed-hosts)
        SEED_HOSTS="${2:?--seed-hosts requires a number}"
        SEED_DEMO=1
        shift
        ;;
      --no-seed-demo|--no-seed)
        SEED_DEMO=0
        ;;
      --fresh-store|--reset-store)
        RESET_STORE=1
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        echo "Unknown start option: $1" >&2
        echo "Try: ./dev.sh start --seed-demo | --no-seed-demo | --seed-hosts N | --clickhouse | --no-clickhouse | --fresh-clickhouse | --fresh-store" >&2
        exit 1
        ;;
    esac
    shift
  done

  command -v cargo >/dev/null || { echo "cargo required" >&2; exit 1; }
  command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }

  if [[ "${CLICKHOUSE}" == "1" || "${CLICKHOUSE}" == "true" ]]; then
    if [[ "${CLICKHOUSE_RESET}" == "1" ]]; then
      clickhouse_reset
    else
      clickhouse_up
    fi
  fi

  local pid
  pid=$(server_pid || true)
  if pid_alive "$pid"; then
    echo "Already running (pid $pid). Use: ./dev.sh restart"
    cmd_status
    return 0
  fi

  free_port "$(listen_port "$LISTEN")"
  free_port "$(listen_port "$NODE_LISTEN")"

  echo "==> Building rustmite-server (+ node + linux probes)"
  cargo build -p rustmite-server -p rustmite-node --quiet
  # Keep agentless probe/loader in sync (memfd delivery).
  if command -v rustup >/dev/null 2>&1; then
    cargo xtask build-probes --target x86_64-unknown-linux-musl --quiet 2>/dev/null \
      || cargo xtask build-probes --target x86_64-unknown-linux-musl || true
  fi

  echo "==> Starting rustmite-server"
  echo "    listen=$LISTEN node=$NODE_LISTEN seed=$SEED_DEMO/$SEED_HOSTS interval=$SCAN_INTERVAL"
  {
    echo "# Generated by ./dev.sh — edit freely; overrides config/dev.env"
    echo "LISTEN=$LISTEN"
    echo "NODE_LISTEN=$NODE_LISTEN"
    echo "SEED_DEMO=$SEED_DEMO"
    echo "SEED_HOSTS=$SEED_HOSTS"
    echo "SCAN_SIM=$SCAN_SIM"
    echo "DEFAULT_CHECK_SET=$DEFAULT_CHECK_SET"
    echo "SCAN_INTERVAL=$SCAN_INTERVAL"
    echo "SCAN_JITTER_PCT=$SCAN_JITTER_PCT"
    echo "MAX_CONCURRENT_SCANS=$MAX_CONCURRENT_SCANS"
    echo "SCAN_TIMEOUT_SECS=$SCAN_TIMEOUT_SECS"
    echo "SCAN_HISTORY_PER_HOST=${SCAN_HISTORY_PER_HOST:-3}"
    echo "SSH_CONNECT_TIMEOUT_SECS=${SSH_CONNECT_TIMEOUT_SECS:-10}"
    echo "SSH_AUTH_TIMEOUT_SECS=${SSH_AUTH_TIMEOUT_SECS:-20}"
    echo "SSH_CMD_TIMEOUT_SECS=${SSH_CMD_TIMEOUT_SECS:-60}"
    echo "SSH_INACTIVITY_TIMEOUT_SECS=${SSH_INACTIVITY_TIMEOUT_SECS:-90}"
    echo "SSH_DELIVERY_TIMEOUT_SECS=${SSH_DELIVERY_TIMEOUT_SECS:-30}"
    echo "SSH_FINGERPRINT_TIMEOUT_SECS=${SSH_FINGERPRINT_TIMEOUT_SECS:-10}"
    echo "SSH_CONNECT_DELAY_MS=${SSH_CONNECT_DELAY_MS:-0}"
    echo "SSH_TIMEOUT_JITTER_PCT=${SSH_TIMEOUT_JITTER_PCT:-10}"
    echo "NOISE_XX=$NOISE_XX"
    echo "TLS=${TLS:-1}"
    echo "TLS_DIR=${TLS_DIR:-.dev/tls}"
    echo "TLS_CERT=${TLS_CERT:-}"
    echo "TLS_KEY=${TLS_KEY:-}"
    echo "NODE_TLS_CERT=${NODE_TLS_CERT:-}"
    echo "NODE_TLS_KEY=${NODE_TLS_KEY:-}"
    echo "NODE_TLS_CLIENT_CA=${NODE_TLS_CLIENT_CA:-}"
    echo "NODE=${NODE:-1}"
    echo "CLICKHOUSE=$CLICKHOUSE"
    echo "CLICKHOUSE_URL=$CLICKHOUSE_URL"
    echo "CLICKHOUSE_USER=$CLICKHOUSE_USER"
    echo "CLICKHOUSE_PASSWORD=$CLICKHOUSE_PASSWORD"
    echo "CLICKHOUSE_DB=$CLICKHOUSE_DB"
    echo "CLICKHOUSE_TIMEOUT_SECS=${CLICKHOUSE_TIMEOUT_SECS:-30}"
    echo "CHECKS=$CHECKS"
    echo "STORE_FILE=${STORE_FILE:-.dev/store.json}"
  } >"$LOCAL_CONFIG"

  build_and_run_server
  wait_for_health
  echo "    console  $(console_url)"
  echo "    health   $(health_url)"
  echo "    logs     $(relpath "$SERVER_LOG")"
  echo "    config   $(relpath "$LOCAL_CONFIG")"

  if [[ "${NODE}" == "1" || "${NODE}" == "true" ]]; then
    echo "==> Starting rustmite-node (live SSH scanner)"
    local scheme=https
    if [[ "${TLS}" == "0" || "${TLS}" == "false" ]]; then
      scheme=http
    fi
    (
      # Accept self-signed node API cert for local lab
      export SSL_CERT_FILE="${SSL_CERT_FILE:-}"
      local nbin="$ROOT/target/debug/rustmite-node"
      if [[ ! -x "$nbin" ]]; then
        echo "missing $nbin — build failed?" >&2
        exit 1
      fi
      nohup "$nbin" \
        --server "${scheme}://127.0.0.1:$(listen_port "$NODE_LISTEN")" \
        --capacity 4 \
        --checks "$CHECKS" \
        ${CRED_KEY:+--cred-key "$CRED_KEY"} \
        >"$NODE_LOG" 2>&1 &
      echo $! >"$NODE_PID"
    )
    echo "    node     running (pid $(cat "$NODE_PID" 2>/dev/null || echo ?))"
    echo "    node log $(relpath "$NODE_LOG")"
  else
    echo "    node     skipped (NODE=0) — credentialed host scans stay queued"
  fi
}

cmd_restart() {
  cmd_stop
  cmd_start "$@"
}

cmd_status() {
  load_config
  local pid url
  pid=$(server_pid || true)
  url=$(health_url)
  echo "RustMite status"
  echo "  config:  $(relpath "$LOCAL_CONFIG")"
  echo "  listen:  $LISTEN"
  echo "  node:    $NODE_LISTEN"
    if pid_alive "$pid"; then
    echo "  server:  running (pid $pid)"
    local -a curl_opts=(-sf)
    if [[ "$(listen_scheme)" == "https" ]]; then
      curl_opts+=(-k)
    fi
    if curl "${curl_opts[@]}" "$url" >/dev/null 2>&1; then
      echo "  health:  ok"
      curl "${curl_opts[@]}" "$url" | python3 -c 'import json,sys; m=json.load(sys.stdin); print("  detail:  scope=%s pid=%s cpu=%.1f%% mem=%.1f%%" % (m.get("scope"), m.get("pid"), m.get("cpu_pct",0), m.get("mem_pct",0)))' 2>/dev/null \
        || curl "${curl_opts[@]}" "$url"
    else
      echo "  health:  not responding ($url)"
    fi
    echo "  console: $(console_url)"
  else
    echo "  server:  stopped"
    rm -f "$SERVER_PID"
  fi
  if [[ "${CLICKHOUSE}" == "1" || "${CLICKHOUSE}" == "true" ]]; then
    clickhouse_status
  else
    echo "  clickhouse: disabled (set CLICKHOUSE=1 or omit --no-clickhouse)"
  fi
}

cmd_logs() {
  ensure_dirs
  local n="${1:-80}"
  if [[ ! -f "$SERVER_LOG" ]]; then
    echo "No log file yet ($(relpath "$SERVER_LOG"))" >&2
    exit 1
  fi
  if [[ "${2:-}" == "-f" || "$n" == "-f" ]]; then
    tail -n 80 -f "$SERVER_LOG"
  else
    tail -n "$n" "$SERVER_LOG"
  fi
}

cmd_config() {
  load_config
  echo "Active config (from $(relpath "$DEFAULT_CONFIG") + $(relpath "$LOCAL_CONFIG")):"
  echo "  LISTEN=$LISTEN"
  echo "  NODE_LISTEN=$NODE_LISTEN"
  echo "  SEED_DEMO=$SEED_DEMO SEED_HOSTS=$SEED_HOSTS SCAN_SIM=$SCAN_SIM"
  echo "  DEFAULT_CHECK_SET=$DEFAULT_CHECK_SET SCAN_INTERVAL=$SCAN_INTERVAL"
  echo "  SCAN_JITTER_PCT=$SCAN_JITTER_PCT MAX_CONCURRENT_SCANS=$MAX_CONCURRENT_SCANS"
  echo "  SCAN_TIMEOUT_SECS=$SCAN_TIMEOUT_SECS NOISE_XX=$NOISE_XX"
  echo "  TLS=${TLS:-1} TLS_DIR=${TLS_DIR:-.dev/tls}"
  echo "  TLS_CERT=${TLS_CERT:-(auto)} TLS_KEY=${TLS_KEY:+(set)}${TLS_KEY:-(auto)}"
  echo "  NODE_TLS_CLIENT_CA=${NODE_TLS_CLIENT_CA:-}"
  echo "  CLICKHOUSE=$CLICKHOUSE CLICKHOUSE_URL=$CLICKHOUSE_URL"
  echo "  STORE_FILE=${STORE_FILE:-.dev/store.json}"
  echo
  echo "Edit overrides in: $(relpath "$LOCAL_CONFIG")"
}

usage() {
  cat <<EOF
Usage: ./dev.sh <command> [options]

Commands:
  start [options]        Build + start (ClickHouse on by default)
  stop                   Stop the server and free ports
  restart [options]      Stop then start (same options as start)
  status                 Show process + health
  logs [N|-f]            Tail server log (default 80 lines)
  config                 Print effective settings from config files
  clickhouse up|down|status|reset   Manage ClickHouse (reset = wipe data + reinit)

Start options (override config/dev.env):
  --seed-demo [N]        Seed the demo fleet (optional host count)
  --seed-hosts N         Seed demo with N hosts (implies --seed-demo)
  --no-seed-demo         Do not seed (default; same as plain start)
  --clickhouse           Start ClickHouse (default when CLICKHOUSE=1)
  --no-clickhouse        Skip ClickHouse
  --fresh-clickhouse     Wipe ClickHouse volume and recreate schema, then start
  --fresh-store          Wipe persisted hosts/findings/scans (ClickHouse cp_entities + .dev/store.json)

Config (no shell exports needed):
  config/dev.env         Shared defaults (committed)
  .dev/config.env        Local overrides (created on first start)
  ClickHouse             Durable control-plane (hosts, findings, scans) when CLICKHOUSE=1
  .dev/store.json        Fallback only when ClickHouse is disabled/unreachable

Examples:
  ./dev.sh start                      # no demo seed (default)
  ./dev.sh start --no-seed-demo       # same as plain start
  ./dev.sh start --seed-demo
  ./dev.sh start --seed-demo 200
  ./dev.sh start --seed-hosts 1000
  ./dev.sh start --clickhouse
  ./dev.sh start --fresh-clickhouse   # empty ClickHouse + start server
  ./dev.sh start --fresh-store        # empty control-plane store + start
  ./dev.sh clickhouse reset           # wipe CH data only (recreate container)
  ./dev.sh restart                    # keeps hosts and scan results (from ClickHouse)
  ./dev.sh restart --seed-demo --no-clickhouse
  ./dev.sh status
  ./dev.sh stop
EOF
}

CMD="${1:-}"
shift || true
case "$CMD" in
  start|up) cmd_start "$@" ;;
  stop|down) cmd_stop ;;
  restart) cmd_restart "$@" ;;
  status) cmd_status ;;
  logs) cmd_logs "${1:-80}" "${2:-}" ;;
  config) cmd_config ;;
  clickhouse)
    load_config
    case "${1:-}" in
      up|start) clickhouse_up ;;
      down|stop) clickhouse_down ;;
      status) clickhouse_status ;;
      reset|fresh|clean|wipe)
        clickhouse_reset
        ;;
      *)
        echo "Usage: ./dev.sh clickhouse up|down|status|reset" >&2
        echo "  reset  Stop ClickHouse, delete data volume, start fresh + apply init.sql" >&2
        exit 1
        ;;
    esac
    ;;
  -h|--help|help|"") usage ;;
  *) echo "Unknown command: $CMD" >&2; usage; exit 1 ;;
esac
