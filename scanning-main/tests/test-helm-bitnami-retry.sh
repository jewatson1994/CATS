#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT

mkdir -p "$TEMPORARY_DIRECTORY/bin" "$TEMPORARY_DIRECTORY/chart"
printf 'name: bitnami-probe\n' > "$TEMPORARY_DIRECTORY/chart/Chart.yaml"
ORIGINAL_DIGEST="$(sha256sum "$TEMPORARY_DIRECTORY/chart/Chart.yaml")"

cat > "$TEMPORARY_DIRECTORY/bin/helm" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$HELM_CALL_LOG"
if [ "${HELM_MODE:-normal}" = "normal" ]; then
  printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'spec:' '  containers:' '    - image: docker.io/bitnamilegacy/postgresql:17.6.0-debian-12-r4'
  exit 0
fi
if [ "${HELM_MODE:-}" = "bitnami" ] && [[ "$*" != *"global.security.allowInsecureImages=true"* ]]; then
  printf '%s\n' 'ERROR: Original containers have been substituted for unrecognized ones.' 'Unrecognized images:' '- docker.io/bitnamilegacy/postgresql:17.6.0-debian-12-r4' >&2
  exit 1
fi
if [ "${HELM_MODE:-}" = "retry-fail" ] && [[ "$*" == *"global.security.allowInsecureImages=true"* ]]; then
  printf '%s\n' 'ERROR: retry render failed: invalid values' >&2
  exit 1
fi
printf '%s\n' 'ERROR: unrelated Helm validation failed' >&2
exit 1
SCRIPT
chmod +x "$TEMPORARY_DIRECTORY/bin/helm"
cat > "$TEMPORARY_DIRECTORY/bin/yq" <<'SCRIPT'
#!/usr/bin/env bash
case "$*" in
  *'dependencies[]?'*) exit 0 ;;
  *'.name // "chart"'*) printf '%s\n' 'bitnami-probe' ;;
  *'has("image")'*) printf '%s\n' 'docker.io/bitnamilegacy/postgresql:17.6.0-debian-12-r4' ;;
  *) exit 0 ;;
esac
SCRIPT
chmod +x "$TEMPORARY_DIRECTORY/bin/yq"

export PATH="$TEMPORARY_DIRECTORY/bin:$PATH"
export HELM_CALL_LOG="$TEMPORARY_DIRECTORY/helm-calls.log"
export HELM_RENDER_WARNINGS_FILE="$TEMPORARY_DIRECTORY/warnings.json"

source "$REPOSITORY_ROOT/scripts/helm-render-helpers.sh"

: > "$HELM_CALL_LOG"
printf '[]\n' > "$HELM_RENDER_WARNINGS_FILE"
HELM_MODE=normal helm_render_with_bitnami_retry "$TEMPORARY_DIRECTORY/normal.yaml" chart-normal "$TEMPORARY_DIRECTORY/chart" helm template chart "$TEMPORARY_DIRECTORY/chart"
[ "$(wc -l < "$HELM_CALL_LOG")" -eq 1 ]
[ "$(jq 'length' "$HELM_RENDER_WARNINGS_FILE")" -eq 0 ]
grep -Fq 'bitnamilegacy/postgresql:17.6.0-debian-12-r4' "$TEMPORARY_DIRECTORY/normal.yaml"

: > "$HELM_CALL_LOG"
printf '[]\n' > "$HELM_RENDER_WARNINGS_FILE"
HELM_MODE=bitnami helm_render_with_bitnami_retry "$TEMPORARY_DIRECTORY/retried.yaml" chart-bitnami "$TEMPORARY_DIRECTORY/chart" helm template chart "$TEMPORARY_DIRECTORY/chart"
[ "$(wc -l < "$HELM_CALL_LOG")" -eq 2 ]
grep -Fq -- '--set global.security.allowInsecureImages=true' "$HELM_CALL_LOG"
jq -e 'length == 1 and .[0].type == "bitnami-image-verification-override" and (.[0].unrecognized_images | index("docker.io/bitnamilegacy/postgresql:17.6.0-debian-12-r4"))' "$HELM_RENDER_WARNINGS_FILE" >/dev/null
grep -Fq 'bitnamilegacy/postgresql:17.6.0-debian-12-r4' "$TEMPORARY_DIRECTORY/retried.yaml"
[ "$(sha256sum "$TEMPORARY_DIRECTORY/chart/Chart.yaml")" = "$ORIGINAL_DIGEST" ]

mkdir -p "$TEMPORARY_DIRECTORY/extraction/charts/bitnami"
cp "$TEMPORARY_DIRECTORY/chart/Chart.yaml" "$TEMPORARY_DIRECTORY/extraction/charts/bitnami/Chart.yaml"
printf 'images: []\n' > "$TEMPORARY_DIRECTORY/extraction/images.yml"
(
  cd "$TEMPORARY_DIRECTORY/extraction"
  HELM_MODE=bitnami HELM_RENDER_WARNINGS_FILE="$TEMPORARY_DIRECTORY/extraction/warnings.json" \
    bash "$REPOSITORY_ROOT/scripts/extract-helm-images.sh"
)
grep -Fxq 'docker.io/bitnamilegacy/postgresql:17.6.0-debian-12-r4' "$TEMPORARY_DIRECTORY/extraction/helm-images.txt"
jq -e 'length == 1' "$TEMPORARY_DIRECTORY/extraction/warnings.json" >/dev/null

: > "$HELM_CALL_LOG"
set +e
HELM_MODE=unrelated helm_render_with_bitnami_retry "$TEMPORARY_DIRECTORY/unrelated.yaml" chart-unrelated "$TEMPORARY_DIRECTORY/chart" helm template chart "$TEMPORARY_DIRECTORY/chart"
status=$?
set -e
[ "$status" -ne 0 ]
[ "$(wc -l < "$HELM_CALL_LOG")" -eq 1 ]
[[ "$HELM_RENDER_LAST_ERROR" == *"unrelated Helm validation failed"* ]]

: > "$HELM_CALL_LOG"
set +e
HELM_MODE=retry-fail helm_render_with_bitnami_retry "$TEMPORARY_DIRECTORY/failed.yaml" chart-failed "$TEMPORARY_DIRECTORY/chart" helm template chart "$TEMPORARY_DIRECTORY/chart"
status=$?
set -e
[ "$status" -ne 0 ]
[ "$(wc -l < "$HELM_CALL_LOG")" -eq 2 ]
grep -Fq 'retry render failed: invalid values' <<< "$HELM_RENDER_LAST_ERROR"

echo "Bitnami Helm static-analysis retry tests passed."
