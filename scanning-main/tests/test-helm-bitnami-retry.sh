#!/usr/bin/env bash
# Compatibility values are explicit across every workflow; no silent retry.
set -euo pipefail
SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/../scripts" && pwd)"
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT
source "$SCRIPT_DIRECTORY/helm-render-helpers.sh"
CALLS="$TEMPORARY_DIRECTORY/calls"
python3() {
  printf '%s\n' "$*" >> "$CALLS"
  if [ "${MODE:-normal}" = normal ]; then
    printf 'apiVersion: v1\nkind: Pod\n'
    return 0
  fi
  printf 'partial output\n'
  printf 'helm failed\n' >&2
  return 1
}
helm_render "$TEMPORARY_DIRECTORY/good.yaml" chart chart helm template chart chart --set-string global.security.allowInsecureImages=true
[ "$(wc -l < "$CALLS")" -eq 1 ]
grep -Fq 'render-helm.py helm template chart chart --set-string global.security.allowInsecureImages=true' "$CALLS"
grep -Fq 'kind: Pod' "$TEMPORARY_DIRECTORY/good.yaml"
: > "$CALLS"
if MODE=failure helm_render "$TEMPORARY_DIRECTORY/bad.yaml" chart chart helm template chart chart; then
  echo 'Expected failure' >&2
  exit 1
fi
[ "$(wc -l < "$CALLS")" -eq 1 ]
[ ! -f "$TEMPORARY_DIRECTORY/bad.yaml" ]
[ "$HELM_RENDER_LAST_ERROR" = 'helm failed' ]
! grep -Fq allowInsecureImages "$CALLS"
printf 'Shared Helm wrapper tests passed.\n'
