#!/usr/bin/env bash
# Build musl agentless probe/loader for x86_64, i686, aarch64, armv7 and
# stage them under docker/share/probes/ for the share-image Dockerfile.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STAGE="${ROOT}/docker/share/probes"
TD="${CARGO_TARGET_DIR:-${ROOT}/target}"

specs=(
  "x86_64-unknown-linux-musl:x86_64"
  "i686-unknown-linux-musl:i686"
  "aarch64-unknown-linux-musl:aarch64"
  "armv7-unknown-linux-musleabihf:armv7"
)

need_build=0
for spec in "${specs[@]}"; do
  arch="${spec##*:}"
  if [[ ! -x "${STAGE}/${arch}/rustmite-probe" || ! -x "${STAGE}/${arch}/rustmite-loader" ]]; then
    need_build=1
    break
  fi
done

if [[ "$need_build" -eq 1 ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo required to build agentless probes" >&2
    exit 1
  fi
  echo "==> Building agentless probe/loader matrix (zigbuild)"
  for spec in "${specs[@]}"; do
    triple="${spec%%:*}"
    arch="${spec##*:}"
    echo "    ${triple} → ${arch}"
    if cargo zigbuild -p rustmite-probe -p rustmite-loader \
         --target "${triple}" --profile probe; then
      :
    else
      echo "warning: zigbuild failed for ${triple}; trying cargo build" >&2
      cargo build -p rustmite-probe -p rustmite-loader \
        --target "${triple}" --profile probe
    fi
    mkdir -p "${STAGE}/${arch}"
    cp "${TD}/${triple}/probe/rustmite-probe" \
       "${TD}/${triple}/probe/rustmite-loader" \
       "${STAGE}/${arch}/"
    chmod +x "${STAGE}/${arch}/rustmite-probe" "${STAGE}/${arch}/rustmite-loader"
  done
else
  echo "==> Reusing staged probes in docker/share/probes/"
fi

echo "==> Staged agentless binaries:"
missing=0
for spec in "${specs[@]}"; do
  arch="${spec##*:}"
  p="${STAGE}/${arch}/rustmite-probe"
  l="${STAGE}/${arch}/rustmite-loader"
  if [[ -x "$p" && -x "$l" ]]; then
    echo "    OK  ${arch}/  $(ls -lh "$p" | awk '{print $5}') probe + $(ls -lh "$l" | awk '{print $5}') loader"
  else
    echo "    MISSING ${arch}/" >&2
    missing=1
  fi
done
if [[ "$missing" -eq 1 ]]; then
  echo "error: incomplete agentless probe set under ${STAGE}" >&2
  exit 1
fi
