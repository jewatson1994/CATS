#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/opt/catscan/trivy-cache}"
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT

for executable in bash base64 helm jq sha256sum trivy yq; do
  command -v "$executable" >/dev/null 2>&1 || {
    echo "Missing required CATScan executable: $executable" >&2
    exit 1
  }
done

[ -d "$TRIVY_CACHE_DIR" ] || {
  echo "Trivy offline cache is absent: $TRIVY_CACHE_DIR" >&2
  exit 1
}
[ -w "$TRIVY_CACHE_DIR" ] || {
  echo "Trivy offline cache is not writable: $TRIVY_CACHE_DIR" >&2
  exit 1
}

helm template cats-test \
  "${REPOSITORY_ROOT}/tests/fixtures/helm/umbrella" \
  --namespace cats-testing \
  --include-crds > "${TEMPORARY_DIRECTORY}/rendered.yaml"

grep -Fq 'name: cats-test-api' "${TEMPORARY_DIRECTORY}/rendered.yaml"
grep -Fq 'name: cats-test-worker' "${TEMPORARY_DIRECTORY}/rendered.yaml"

trivy config \
  --format json \
  --output "${TEMPORARY_DIRECTORY}/trivy.json" \
  --cache-dir "$TRIVY_CACHE_DIR" \
  --skip-check-update \
  "${TEMPORARY_DIRECTORY}/rendered.yaml"

bash "${REPOSITORY_ROOT}/scripts/normalize-trivy-config.sh" \
  "${TEMPORARY_DIRECTORY}/trivy.json" \
  "${TEMPORARY_DIRECTORY}/policy-findings.json" \
  "cats-test-umbrella (cats-test)" \
  "cats-testing" \
  "Helm/Kubernetes"

jq -e 'type == "array" and length > 0 and all(.[].type == "Configuration")' \
  "${TEMPORARY_DIRECTORY}/policy-findings.json" >/dev/null

echo "CATScan Trivy/Helm offline toolchain passed."
