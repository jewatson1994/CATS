#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/charts/root/templates" "$TMP/charts/root/charts/foo/templates" "$TMP/charts/root/charts/bar/templates"
printf 'name: root\n' > "$TMP/charts/root/Chart.yaml"
printf 'name: foo\n' > "$TMP/charts/root/charts/foo/Chart.yaml"
printf 'name: bar\n' > "$TMP/charts/root/charts/bar/Chart.yaml"
cat > "$TMP/charts/root/values.yaml" <<'YAML'
services:
  foo:
    enabled: false
  bar:
    enabled: true
  metrics:
    enabled: true
YAML

cat > "$TMP/bin/yq" <<'SCRIPT'
#!/usr/bin/env bash
case "$*" in
  *'(.services // .service'*)
    printf '%s\n' '{"name":"foo","enabled":false,"path":null,"chartPath":null,"chart_path":null,"localPath":null,"local_path":null}' '{"name":"bar","enabled":true,"path":null,"chartPath":null,"chart_path":null,"localPath":null,"local_path":null}' ;;
  *'.dependencies[]?'*) ;;
  *'.name // empty'*) basename "${@: -1}" .yaml 2>/dev/null || true ;;
  *) ;;
esac
SCRIPT
chmod +x "$TMP/bin/yq"
cat > "$TMP/bin/helm" <<'SCRIPT'
#!/usr/bin/env bash
if [ "$1" = template ]; then
  chart="${@: -1}"
  printf '%s\n' 'apiVersion: v1' 'kind: ConfigMap' 'metadata:' "  name: $(basename "$chart")"
fi
SCRIPT
chmod +x "$TMP/bin/helm"
cat > "$TMP/bin/trivy" <<'SCRIPT'
#!/usr/bin/env bash
output=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then output="$2"; shift 2; else shift; fi
done
[ -n "$output" ] && printf '{"Results":[]}\n' > "$output"
SCRIPT
chmod +x "$TMP/bin/trivy"

(
  cd "$TMP"
  PATH="$TMP/bin:$PATH" HELM_SCAN_ENABLED=true HELM_CHART_ROOTS=charts \
    TRIVY_CONFIG_ENABLED=false TRIVY_CONFIG_SCAN_ENABLED=false \
    bash "$ROOT/scripts/scan-configurations.sh" >/dev/null
)

[ "$(find "$TMP/helm-rendered" -type f -name '*.yaml' | wc -l)" -ge 3 ]
grep -q '"declared_state":false' "$TMP/helm-discovery.jsonl"
grep -q '"declared_state":true' "$TMP/helm-discovery.jsonl"
! grep -q 'metrics' "$TMP/helm-discovery.jsonl"
echo "Helm values catalog discovery tests passed."
