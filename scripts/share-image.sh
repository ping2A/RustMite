#!/usr/bin/env bash
# Build a RustMite Docker image you can share (tar file or registry push).
#
# Usage:
#   ./scripts/share-image.sh              # build for host arch → dist/rustmite-<ver>-<arch>.tar.gz
#   ./scripts/share-image.sh --x64        # build linux/amd64 (x86_64) image
#   ./scripts/share-image.sh --arm64      # build linux/arm64 image
#   ./scripts/share-image.sh --load       # same, then docker load locally (smoke)
#   ./scripts/share-image.sh --push REG   # build, tag, push to REG/rustmite:<ver>
#   ./scripts/share-image.sh --help
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NAME="rustmite"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
VERSION="${VERSION:-0.1.0}"
OUT_DIR="${ROOT}/dist"

DO_LOAD=0
DO_PUSH=0
REGISTRY=""
# Empty = detect from host; set via --x64 / --arm64 / --platform / --arch
ARCH=""
PLATFORM=""

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "amd64" ;; # safest default for sharing
  esac
}

# Normalize user input → docker arch name (amd64|arm64)
normalize_arch() {
  case "$1" in
    x64|x86_64|amd64|linux/amd64) echo "amd64" ;;
    aarch64|arm64|linux/arm64) echo "arm64" ;;
    *)
      echo "error: unsupported arch '$1' (use amd64/x64 or arm64)" >&2
      exit 1
      ;;
  esac
}

arch_to_platform() {
  case "$1" in
    amd64) echo "linux/amd64" ;;
    arm64) echo "linux/arm64" ;;
    *) echo "linux/$1" ;;
  esac
}

# Extract arch from a docker platform string (linux/amd64 → amd64)
platform_to_arch() {
  case "$1" in
    */*) echo "${1##*/}" ;;
    *) echo "$1" ;;
  esac
}

usage() {
  cat <<EOF
Build a shareable RustMite Docker image.

  ./scripts/share-image.sh [options]

Options:
  --tag TAG        Image version tag AND UI/console version
                   (default: ${VERSION} from Cargo.toml). Use Cargo-style
                   versions (0.2.0); a leading v is stripped for Cargo.toml.
  --x64, --amd64   Build for linux/amd64 (x86_64) — typical share target
  --arm64          Build for linux/arm64
  --arch ARCH      Same as above: amd64|x64|arm64
  --platform P     Pass through to docker buildx (e.g. linux/amd64)
  --out DIR        Output directory for the tar (default: dist/)
  --load           After build, docker load the archive (local smoke test)
  --push REGISTRY  Tag as REGISTRY/rustmite:TAG and docker push
  -h, --help       Show this help

Examples:
  ./scripts/share-image.sh --x64
  ./scripts/share-image.sh --tag 0.1.0 --amd64
  ./scripts/share-image.sh --push ghcr.io/you --x64

Share the file:
  scp dist/rustmite-${VERSION}-amd64.tar.gz user@host:/tmp/

On the other machine:
  gunzip -c rustmite-${VERSION}-amd64.tar.gz | docker load
  docker run --rm -p 8080:8080 -p 8443:8443 rustmite:${VERSION}
  # open https://127.0.0.1:8080/  (accept self-signed cert)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      VERSION="$2"
      shift 2
      ;;
    --x64|--amd64)
      ARCH="amd64"
      shift
      ;;
    --arm64)
      ARCH="arm64"
      shift
      ;;
    --arch)
      ARCH="$(normalize_arch "$2")"
      shift 2
      ;;
    --platform)
      PLATFORM="$2"
      ARCH="$(normalize_arch "$(platform_to_arch "$2")")"
      shift 2
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --load)
      DO_LOAD=1
      shift
      ;;
    --push)
      DO_PUSH=1
      REGISTRY="${2:?--push requires a registry, e.g. ghcr.io/you}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found in PATH" >&2
  exit 1
fi

# Resolve arch / platform
if [[ -z "$ARCH" ]]; then
  ARCH="$(host_arch)"
fi
if [[ -z "$PLATFORM" ]]; then
  PLATFORM="$(arch_to_platform "$ARCH")"
fi

IMAGE="${NAME}:${VERSION}"
LATEST="${NAME}:latest"
IMAGE_ARCH="${NAME}:${VERSION}-${ARCH}"
LATEST_ARCH="${NAME}:latest-${ARCH}"
TAR="${OUT_DIR}/${NAME}-${VERSION}-${ARCH}.tar"
GZ="${TAR}.gz"

mkdir -p "$OUT_DIR"

echo "==> Building ${IMAGE} for ${PLATFORM} (also tagged ${LATEST}, ${IMAGE_ARCH})"
if docker buildx version >/dev/null 2>&1; then
  BUILD_ARGS=(buildx build --load --platform "$PLATFORM"
    --build-arg "VERSION=${VERSION}"
    -t "$IMAGE" -t "$LATEST" -t "$IMAGE_ARCH" -t "$LATEST_ARCH"
    -f Dockerfile .)
else
  BUILD_ARGS=(build --platform "$PLATFORM"
    --build-arg "VERSION=${VERSION}"
    -t "$IMAGE" -t "$LATEST" -t "$IMAGE_ARCH" -t "$LATEST_ARCH"
    -f Dockerfile .)
fi
docker "${BUILD_ARGS[@]}"

echo "==> Saving ${GZ}"
rm -f "$TAR" "$GZ"
docker save -o "$TAR" "$IMAGE" "$LATEST" "$IMAGE_ARCH" "$LATEST_ARCH"
gzip -f "$TAR"

SIZE="$(du -h "$GZ" | awk '{print $1}')"
echo
echo "Ready to share: ${GZ} (${SIZE})"
echo
echo "  Recipient:"
echo "    gunzip -c $(basename "$GZ") | docker load"
echo "    docker run --rm -p 8080:8080 -p 8443:8443 ${IMAGE}"
echo "    # → https://127.0.0.1:8080/  (accept self-signed cert)"
echo

if [[ "$DO_LOAD" -eq 1 ]]; then
  echo "==> Loading archive locally"
  gunzip -c "$GZ" | docker load
fi

if [[ "$DO_PUSH" -eq 1 ]]; then
  REMOTE="${REGISTRY%/}/${NAME}:${VERSION}"
  REMOTE_LATEST="${REGISTRY%/}/${NAME}:latest"
  REMOTE_ARCH="${REGISTRY%/}/${NAME}:${VERSION}-${ARCH}"
  REMOTE_LATEST_ARCH="${REGISTRY%/}/${NAME}:latest-${ARCH}"
  echo "==> Pushing ${REMOTE} and ${REMOTE_ARCH}"
  docker tag "$IMAGE" "$REMOTE"
  docker tag "$LATEST" "$REMOTE_LATEST"
  docker tag "$IMAGE_ARCH" "$REMOTE_ARCH"
  docker tag "$LATEST_ARCH" "$REMOTE_LATEST_ARCH"
  docker push "$REMOTE"
  docker push "$REMOTE_LATEST"
  docker push "$REMOTE_ARCH"
  docker push "$REMOTE_LATEST_ARCH"
  echo "Pulled with: docker pull ${REMOTE}"
fi
