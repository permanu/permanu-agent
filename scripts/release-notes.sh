#!/usr/bin/env bash
set -euo pipefail

tag="${GITHUB_REF_NAME:-}"
if [[ -z "$tag" && "${GITHUB_REF:-}" == refs/tags/* ]]; then
  tag="${GITHUB_REF#refs/tags/}"
fi
if [[ -z "$tag" ]]; then
  tag="$(git describe --tags --exact-match 2>/dev/null || true)"
fi
if [[ -z "$tag" ]]; then
  tag="v$(scripts/check-version.sh)"
fi

previous_tag="$(git describe --tags --abbrev=0 "${tag}^" 2>/dev/null || true)"

printf '# permanu-agent %s\n\n' "$tag"

if [[ -n "$previous_tag" ]]; then
  printf 'Changes since %s:\n\n' "$previous_tag"
  git log --no-merges --pretty=format:'- %s (%h)' "${previous_tag}..${tag}" || true
  printf '\n'
else
  printf 'Initial published release for %s.\n' "$tag"
fi

printf '\nArtifacts:\n\n'
printf -- '- `permanu-agent-linux-amd64`\n'
printf -- '- `permanu-agent-linux-arm64`\n'
printf -- '- `permanu-agent-release.json`\n'
printf -- '- `SHA256SUMS`\n'
