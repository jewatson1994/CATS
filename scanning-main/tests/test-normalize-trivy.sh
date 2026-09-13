#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT

bash "${REPOSITORY_ROOT}/scripts/normalize-trivy-config.sh" \
  "${REPOSITORY_ROOT}/tests/fixtures/trivy-config.json" \
  "${TEMPORARY_DIRECTORY}/policy-findings.json" \
  "cats-test-umbrella (cats-test)" \
  "cats-testing" \
  "Helm/Kubernetes"

jq -e '
  length == 2
  and all(.[].type == "Configuration")
  and all(.[].scanner == "Trivy")
  and all(.[].namespace == "cats-testing")
  and all(.[].framework == "Helm/Kubernetes")
  and all(.[].fingerprint | test("^trivy:[a-f0-9]{64}$"))
  and ([.[].finding] | sort == ["DS002", "KSV014"])
  and all(.[];
    has("type") and has("finding") and has("severity")
    and has("scanner") and has("framework") and has("target")
    and has("namespace") and has("title") and has("description")
    and has("remediation") and has("fingerprint")
  )
' "${TEMPORARY_DIRECTORY}/policy-findings.json" >/dev/null

echo "Trivy normalization contract passed."
