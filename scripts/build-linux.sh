#!/usr/bin/env bash
# Cross-compile static linux binaries (amd64 + arm64, musl) inside Docker, so
# a Mac can build and test the agent without a local Linux toolchain.
#
#   scripts/build-linux.sh           build dist/permanu-agent-linux-{amd64,arm64}
#   scripts/build-linux.sh --test    run `cargo test --locked` in Linux first
#
# Env: ARCHES (default "amd64 arm64"), VERSION (default Cargo version + git sha),
#      RUST_IMAGE (default rust:1.94-slim-bookworm), ZIG_VERSION (default 0.13.0).
# Output goes to dist/ (gitignored). Cargo caches live in Docker volumes.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --test) RUN_TESTS=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

ARCHES="${ARCHES:-amd64 arm64}"
RUST_IMAGE="${RUST_IMAGE:-rust:1.94-slim-bookworm}"
ZIG_VERSION="${ZIG_VERSION:-0.13.0}"
BUILDER_IMAGE="permanu-agent-linux-builder:$(echo "${RUST_IMAGE}-zig${ZIG_VERSION}" | tr ':/' '__')"
if [ -z "${VERSION:-}" ]; then
  VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
  VERSION="${VERSION}-dev.$(git rev-parse --short HEAD 2>/dev/null || echo local)"
fi

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

echo "==> builder image ${BUILDER_IMAGE}"
docker build --quiet -t "$BUILDER_IMAGE" \
  --build-arg RUST_IMAGE="$RUST_IMAGE" --build-arg ZIG_VERSION="$ZIG_VERSION" - <<'DOCKERFILE'
ARG RUST_IMAGE
FROM ${RUST_IMAGE}
ARG ZIG_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*
RUN arch="$(uname -m)" \
 && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${arch}-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /opt \
 && ln -s "/opt/zig-linux-${arch}-${ZIG_VERSION}/zig" /usr/local/bin/zig
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
 && cargo install cargo-zigbuild --locked \
 && rm -rf /usr/local/cargo/registry
DOCKERFILE

run_in_builder() {
  docker run --rm \
    -v "$ROOT_DIR":/src:ro \
    -v permanu-agent-cargo-registry:/usr/local/cargo/registry \
    -v permanu-agent-linux-target:/target \
    -v "$ROOT_DIR/dist":/dist \
    -e CARGO_TARGET_DIR=/target \
    -e PERMANU_AGENT_BUILD_VERSION \
    -w /src \
    "$BUILDER_IMAGE" bash -euo pipefail -c "$1"
}

mkdir -p dist

if [ "$RUN_TESTS" -eq 1 ]; then
  echo "==> cargo test (linux/$(docker info --format '{{.Architecture}}'))"
  run_in_builder 'cargo test --locked'
fi

for arch in $ARCHES; do
  case "$arch" in
    amd64) target="x86_64-unknown-linux-musl" ;;
    arm64) target="aarch64-unknown-linux-musl" ;;
    *) echo "unsupported arch: $arch" >&2; exit 2 ;;
  esac
  artifact="permanu-agent-linux-${arch}"
  echo "==> ${artifact} (${target})"
  PERMANU_AGENT_BUILD_VERSION="${VERSION}-${arch}" run_in_builder "
    cargo zigbuild --release --locked --target ${target}
    install -m 0755 /target/${target}/release/permanu-agent /dist/${artifact}
  "
done

(cd dist && shasum -a 256 permanu-agent-linux-* > SHA256SUMS.linux && cat SHA256SUMS.linux)
