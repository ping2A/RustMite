#!/bin/sh
# Select which binary to run from the shared image.
#   docker run rustmite:latest server …
#   docker run rustmite:latest node …
#   docker run rustmite:latest cli scan-fixture --fixture /opt/rustmite/fixtures/…
set -eu

cmd="${1:-server}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$cmd" in
  server|rustmite-server)
    exec rustmite-server "$@"
    ;;
  node|rustmite-node)
    exec rustmite-node "$@"
    ;;
  cli|rustmite-cli)
    exec rustmite-cli "$@"
    ;;
  -h|--help|help)
    cat <<'EOF'
RustMite image entrypoint

Usage:
  rustmite-entrypoint server [args…]   # control plane (default)
  rustmite-entrypoint node   [args…]   # scanner node
  rustmite-entrypoint cli    [args…]   # operator CLI

Examples:
  docker run --rm -p 8080:8080 rustmite:latest
  # → https://127.0.0.1:8080/ (self-signed; accept browser warning)
  docker run --rm rustmite:latest server --no-tls   # cleartext lab mode
  docker run --rm rustmite:latest cli scan-fixture \
    --fixture /opt/rustmite/fixtures/diamorphine-hidden-pid
EOF
    exit 0
    ;;
  *)
    # Allow `docker run … --listen …` (args meant for the server).
    exec rustmite-server "$cmd" "$@"
    ;;
esac
