#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

fake_bin="${tmp_root}/bin"
mkdir -p "$fake_bin"
cat > "${fake_bin}/cosign" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >> "${COSIGN_ARGS_FILE}"

bundle=""
sig=""
cert=""
key_mode=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --key)
      key_mode=1
      shift 2
      ;;
    --bundle)
      bundle="$2"
      shift 2
      ;;
    --output-signature)
      sig="$2"
      shift 2
      ;;
    --output-certificate)
      cert="$2"
      shift 2
      ;;
    --identity-token)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

[ -n "$bundle" ] && printf 'bundle\n' > "$bundle"
if [ "$key_mode" -eq 1 ]; then
  printf 'signature\n'
else
  [ -n "$sig" ] && printf 'signature\n' > "$sig"
  [ -n "$cert" ] && printf 'certificate\n' > "$cert"
fi
FAKE
chmod +x "${fake_bin}/cosign"

make_dist() {
  local dist="$1"
  mkdir -p "$dist"
  printf 'amd64\n' > "${dist}/permanu-agent-linux-amd64"
  printf 'arm64\n' > "${dist}/permanu-agent-linux-arm64"
  chmod 0755 "${dist}/permanu-agent-linux-amd64" "${dist}/permanu-agent-linux-arm64"
}

assert_file() {
  [ -s "$1" ] || {
    echo "expected signed output missing: $1" >&2
    exit 1
  }
}

PATH="${fake_bin}:$PATH"
export PATH

keyless_dist="${tmp_root}/keyless"
make_dist "$keyless_dist"
COSIGN_ARGS_FILE="${tmp_root}/keyless.args"
export COSIGN_ARGS_FILE
SIGSTORE_ID_TOKEN="token-123" scripts/sign-release.sh "$keyless_dist"
assert_file "${keyless_dist}/permanu-agent-linux-amd64.bundle"
assert_file "${keyless_dist}/permanu-agent-linux-amd64.sig"
assert_file "${keyless_dist}/permanu-agent-linux-amd64.cert"
grep -q -- '--identity-token token-123' "$COSIGN_ARGS_FILE"

key_dist="${tmp_root}/key"
make_dist "$key_dist"
COSIGN_ARGS_FILE="${tmp_root}/key.args"
export COSIGN_ARGS_FILE
PERMANU_COSIGN_KEY="gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/permanu-agent" \
  scripts/sign-release.sh "$key_dist"
assert_file "${key_dist}/permanu-agent-linux-arm64.bundle"
assert_file "${key_dist}/permanu-agent-linux-arm64.sig"
grep -q -- '--key gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/permanu-agent' "$COSIGN_ARGS_FILE"

missing_dist="${tmp_root}/missing"
make_dist "$missing_dist"
COSIGN_ARGS_FILE="${tmp_root}/missing.args"
export COSIGN_ARGS_FILE
if env \
  -u PERMANU_COSIGN_KEY \
  -u COSIGN_KEY \
  -u PERMANU_SIGSTORE_ID_TOKEN \
  -u SIGSTORE_ID_TOKEN \
  -u ACTIONS_ID_TOKEN_REQUEST_URL \
  -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  scripts/sign-release.sh "$missing_dist" >"${tmp_root}/missing.out" 2>&1; then
  echo "expected missing signing authority to fail" >&2
  exit 1
fi
grep -q 'cosign signing authority is missing' "${tmp_root}/missing.out"

echo "sign-release tests passed"
