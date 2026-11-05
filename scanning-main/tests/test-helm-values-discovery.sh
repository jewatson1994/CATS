#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/charts/root/templates" "$TMP/charts/root/charts/foo/templates" "$TMP/charts/root/charts/bar/templates"
for chart in root root/charts/foo root/charts/bar; do
  printf 'apiVersion: v2\nname: %s\nversion: 1.0.0\n' "${chart##*/}" > "$TMP/charts/$chart/Chart.yaml"
  cat > "$TMP/charts/$chart/templates/config.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-{{ .Chart.Name }}
YAML
done
cat > "$TMP/charts/root/values.yaml" <<'YAML'
services:
  foo:
    enabled: false
  bar:
    enabled: true
  metrics:
    enabled: true
YAML

(
  cd "$TMP"
  HELM_SCAN_ENABLED=true HELM_CHART_ROOTS=charts \
    TRIVY_CONFIG_ENABLED=false TRIVY_CONFIG_SCAN_ENABLED=false \
    bash "$ROOT/scripts/scan-configurations.sh" >/dev/null
)

# Vendored charts render as part of their parent, including charts whose names
# happen to match a disabled catalog entry. An enabled values key alone is not
# evidence of another chart.
[ "$(find "$TMP/helm-rendered" -type f -name '*.yaml' | wc -l)" -eq 1 ]
grep -rq 'name: root-foo' "$TMP/helm-rendered"
grep -rq 'name: root-bar' "$TMP/helm-rendered"
jq -e '.charts | length == 3' "$TMP/.cats-helm-graph.json" >/dev/null
! grep -q 'metrics' "$TMP/.cats-helm-graph.json"
echo "Helm values catalog discovery tests passed."
