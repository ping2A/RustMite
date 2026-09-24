#!/usr/bin/env bash
# Build a RustMite Docker image you can share (tar file or registry push).
#
# Usage:
#   ./scripts/share-image.sh              # build + write dist/rustmite-<ver>.tar.gz
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
IMAGE="${NAME}:${VERSION}"
LATEST="${NAME}:latest"
OUT_DIR="${ROOT}/dist"
TAR="${OUT_DIR}/${NAME}-${VERSION}.tar"
GZ="${TAR}.gz"

DO_LOAD=0
DO_PUSH=0
REGISTRY=""
PLATFORM=""

usage() {
  cat <<EOF
Build a shareable RustMite Docker image.

  ./scripts/share-image.sh [options]

Options:
  --tag TAG        Image version tag (default: ${VERSION} from Cargo.toml)
  --platform P     Pass through to docker buildx (e.g. linux/amd64)
  --out DIR        Output directory for the tar (default: dist/)
  --load           After build, docker load the archive (local smoke test)
  --push REGISTRY  Tag as REGISTRY/rustmite:TAG and docker push
  -h, --help       Show this help

Examples:
  ./scripts/share-image.sh
  ./scripts/share-image.sh --tag 0.1.0 --platform linux/amd64
  ./scripts/share-image.sh --push ghcr.io/you

Share the file:
  scp dist/rustmite-${VERSION}.tar.gz user@host:/tmp/

On the other machine:
  gunzip -c rustmite-${VERSION}.tar.gz | docker load
  docker run --rm -p 8080:8080 -p 8443:8443 rustmite:${VERSION}
  # open http://127.0.0.1:8080/
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      VERSION="$2"
      IMAGE="${NAME}:${VERSION}"
      TAR="${OUT_DIR}/${NAME}-${VERSION}.tar"
      GZ="${TAR}.gz"
      shift 2
      ;;
    --platform)
      PLATFORM="$2"
      shift 2
      ;;
    --out)
      OUT_DIR="$2"
      TAR="${OUT_DIR}/${NAME}-${VERSION}.tar"
      GZ="${TAR}.gz"
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

mkdir -p "$OUT_DIR"

echo "==> Building ${IMAGE} (also tagged ${LATEST})"
BUILD_ARGS=(build -t "$IMAGE" -t "$LATEST" -f Dockerfile .)
if [[ -n "$PLATFORM" ]]; then
  if docker buildx version >/dev/null 2>&1; then
    BUILD_ARGS=(buildx build --load --platform "$PLATFORM" -t "$IMAGE" -t "$LATEST" -f Dockerfile .)
  else
    BUILD_ARGS+=(--platform "$PLATFORM")
  fi
fi
docker "${BUILD_ARGS[@]}"

echo "==> Saving ${GZ}"
rm -f "$TAR" "$GZ"
docker save -o "$TAR" "$IMAGE" "$LATEST"
gzip -f "$TAR"

SIZE="$(du -h "$GZ" | awk '{print $1}')"
echo
echo "Ready to share: ${GZ} (${SIZE})"
echo
echo "  Recipient:"
echo "    gunzip -c $(basename "$GZ") | docker load"
echo "    docker run --rm -p 8080:8080 -p 8443:8443 ${IMAGE}"
echo "    # → http://127.0.0.1:8080/"
echo

if [[ "$DO_LOAD" -eq 1 ]]; then
  echo "==> Loading archive locally"
  gunzip -c "$GZ" | docker load
fi

if [[ "$DO_PUSH" -eq 1 ]]; then
  REMOTE="${REGISTRY%/}/${NAME}:${VERSION}"
  REMOTE_LATEST="${REGISTRY%/}/${NAME}:latest"
  echo "==> Pushing ${REMOTE}"
  docker tag "$IMAGE" "$REMOTE"
  docker tag "$LATEST" "$REMOTE_LATEST"
  docker push "$REMOTE"
  docker push "$REMOTE_LATEST"
  echo "Pulled with: docker pull ${REMOTE}"
fi
