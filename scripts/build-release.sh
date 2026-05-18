#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -z "${VERSION:-}" ]; then
  VERSION="$(scripts/check-version.sh)"
  if ! git describe --exact-match --tags HEAD >/dev/null 2>&1; then
    short_sha="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
    VERSION="${VERSION}-dev.${short_sha}"
  fi
fi
ARCHES="${ARCHES:-amd64 arm64}"

mkdir -p dist

manifest_entries=()
for arch in $ARCHES; do
  case "$arch" in
    amd64) target="x86_64-unknown-linux-musl" ;;
    arm64) target="aarch64-unknown-linux-musl" ;;
    *) echo "unsupported arch: $arch" >&2; exit 2 ;;
  esac

  artifact="permanu-agent-linux-${arch}"
  echo "building ${artifact} (${target})"
  rustup target add "$target" >/dev/null
  if command -v cargo-zigbuild >/dev/null 2>&1; then
    PERMANU_AGENT_BUILD_VERSION="${VERSION}-${arch}" cargo zigbuild \
      --release \
      --locked \
      --target "$target"
  else
    PERMANU_AGENT_BUILD_VERSION="${VERSION}-${arch}" cargo build \
      --release \
      --locked \
      --target "$target"
  fi

  cp "target/${target}/release/permanu-agent" "dist/${artifact}"
  chmod 0755 "dist/${artifact}"
  sha256="$(shasum -a 256 "dist/${artifact}" | awk '{print $1}')"
  size="$(stat -f%z "dist/${artifact}" 2>/dev/null || stat -c%s "dist/${artifact}")"
  manifest_entries+=("\"linux-${arch}\":{\"file\":\"${artifact}\",\"sha256\":\"${sha256}\",\"size_bytes\":${size}}")
done

{
  printf '{"version":"%s","artifacts":{' "$VERSION"
  first=1
  for entry in "${manifest_entries[@]}"; do
    if [ "$first" -eq 0 ]; then
      printf ','
    fi
    first=0
    printf '%s' "$entry"
  done
  printf '}}\n'
} > dist/permanu-agent-release.json

shasum -a 256 dist/permanu-agent-linux-* dist/permanu-agent-release.json > dist/SHA256SUMS
