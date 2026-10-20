#!/usr/bin/env bash
set -euo pipefail
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
helm template cats-test /checks/umbrella --namespace cats-testing --include-crds > "$workdir/rendered.yaml"
grep -Fq 'name: cats-test-api' "$workdir/rendered.yaml"
grep -Fq 'name: cats-test-worker' "$workdir/rendered.yaml"
trivy config --format json --output "$workdir/trivy.json" --cache-dir /opt/catscan/trivy-cache --skip-check-update "$workdir/rendered.yaml"
bash /opt/cats/scanning/scripts/normalize-trivy-config.sh "$workdir/trivy.json" "$workdir/policy-findings.json" 'cats-test-umbrella (cats-test)' cats-testing 'Helm/Kubernetes'
jq -e 'type == "array" and length > 0 and all(.[]; .type == "Configuration")' "$workdir/policy-findings.json" >/dev/null
jq '{offline_helm_configuration_findings: length, finding_types: ([.[].type] | unique)}' "$workdir/policy-findings.json"