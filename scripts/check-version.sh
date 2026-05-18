#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

cargo_version="$(awk -F '"' '/^version = / { print $2; exit }' Cargo.toml)"
if [ -z "$cargo_version" ]; then
  echo "Cargo.toml package version not found" >&2
  exit 1
fi

ref_name="${GITHUB_REF_NAME:-}"
if [ -z "$ref_name" ]; then
  ref_name="$(git tag --points-at HEAD | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)"
fi

if [ -z "$ref_name" ]; then
  echo "$cargo_version"
  exit 0
fi

case "$ref_name" in
  v0.1.*) ;;
  *)
    echo "release tags must stay on the 0.1 patch line for now; got $ref_name" >&2
    exit 1
    ;;
esac

tag_version="${ref_name#v}"
if [ "$tag_version" != "$cargo_version" ]; then
  echo "tag $ref_name does not match Cargo.toml version $cargo_version" >&2
  exit 1
fi

echo "$cargo_version"
