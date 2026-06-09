#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

dist_dir="${1:-dist}"

fail() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required for release signing"
}

resolve_cosign_key() {
  if [ -n "${PERMANU_COSIGN_KEY:-}" ] && [ -z "${COSIGN_KEY:-}" ]; then
    export COSIGN_KEY="${PERMANU_COSIGN_KEY}"
  fi

  [ -n "${COSIGN_KEY:-}" ]
}

has_keyless_authority() {
  if [ -n "${PERMANU_SIGSTORE_ID_TOKEN:-}" ] && [ -z "${SIGSTORE_ID_TOKEN:-}" ]; then
    export SIGSTORE_ID_TOKEN="${PERMANU_SIGSTORE_ID_TOKEN}"
  fi

  if [ -n "${SIGSTORE_ID_TOKEN:-}" ]; then
    return 0
  fi

  [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]
}

sign_with_key() {
  local artifact="$1"
  local binary="${dist_dir}/${artifact}"
  local bundle="${binary}.bundle"
  local sig="${binary}.sig"

  rm -f "$bundle" "$sig" "${binary}.cert"
  cosign sign-blob \
    --yes \
    --key "$COSIGN_KEY" \
    --bundle "$bundle" \
    "$binary" > "$sig"

  [ -s "$bundle" ] || fail "cosign key/KMS signing did not produce $bundle"
  [ -s "$sig" ] || fail "cosign key/KMS signing did not produce $sig"
}

sign_keylessly() {
  local artifact="$1"
  local binary="${dist_dir}/${artifact}"
  local bundle="${binary}.bundle"
  local sig="${binary}.sig"
  local cert="${binary}.cert"

  rm -f "$bundle" "$sig" "$cert"
  if [ -n "${SIGSTORE_ID_TOKEN:-}" ]; then
    cosign sign-blob \
      --yes \
      --identity-token "$SIGSTORE_ID_TOKEN" \
      --bundle "$bundle" \
      --output-signature "$sig" \
      --output-certificate "$cert" \
      "$binary"
  else
    cosign sign-blob \
      --yes \
      --bundle "$bundle" \
      --output-signature "$sig" \
      --output-certificate "$cert" \
      "$binary"
  fi

  [ -s "$bundle" ] || fail "cosign keyless signing did not produce $bundle"
  [ -s "$sig" ] || fail "cosign keyless signing did not produce $sig"
  [ -s "$cert" ] || fail "cosign keyless signing did not produce $cert"
}

[ -d "$dist_dir" ] || fail "dist directory not found: $dist_dir"
require_cmd cosign

mapfile -t artifacts < <(
  find "$dist_dir" -maxdepth 1 -type f -perm -111 -name 'permanu-agent-linux-*' -exec basename {} \; | sort
)
[ "${#artifacts[@]}" -gt 0 ] || fail "no release binaries found in $dist_dir"

if resolve_cosign_key; then
  for artifact in "${artifacts[@]}"; do
    echo "signing ${artifact} with cosign key/KMS authority"
    sign_with_key "$artifact"
  done
elif has_keyless_authority; then
  for artifact in "${artifacts[@]}"; do
    echo "signing ${artifact} with cosign keyless OIDC"
    sign_keylessly "$artifact"
  done
else
  fail "cosign signing authority is missing; use GitHub Actions id-token: write, SIGSTORE_ID_TOKEN/PERMANU_SIGSTORE_ID_TOKEN, or COSIGN_KEY/PERMANU_COSIGN_KEY for KMS/key signing"
fi
