#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT

mkdir -p "$TEMPORARY_DIRECTORY/fake-bin"
cat > "$TEMPORARY_DIRECTORY/images.yml" <<'YAML'
images:
  - registry.example/unavailable:1.0.0
YAML
cat > "$TEMPORARY_DIRECTORY/service.yml" <<'YAML'
service:
  id: unavailable-service
  name: Unavailable Service
  version: 1.0.0
YAML

cat > "$TEMPORARY_DIRECTORY/fake-bin/yq" <<'SCRIPT'
#!/usr/bin/env bash
case "$*" in
  *'.images[]'*) printf '%s\n' 'registry.example/unavailable:1.0.0' ;;
  *) exit 0 ;;
esac
SCRIPT

cat > "$TEMPORARY_DIRECTORY/fake-bin/jq" <<'SCRIPT'
#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' 'registry.example/unavailable:1.0.0'
SCRIPT

cat > "$TEMPORARY_DIRECTORY/fake-bin/docker" <<'SCRIPT'
#!/usr/bin/env bash
if [ "${1:-}" = "pull" ]; then
  exit 1
fi
exit 0
SCRIPT
chmod +x "$TEMPORARY_DIRECTORY/fake-bin/yq" "$TEMPORARY_DIRECTORY/fake-bin/jq" "$TEMPORARY_DIRECTORY/fake-bin/docker"

(
  cd "$TEMPORARY_DIRECTORY"
  PATH="$TEMPORARY_DIRECTORY/fake-bin:$PATH" \
  CI_PROJECT_DIR="$TEMPORARY_DIRECTORY" \
  IMAGE_MATERIALIZATION_DIR="$TEMPORARY_DIRECTORY/image-filesystems" \
  UPSTREAM_PROJECT_ID="" \
  UPSTREAM_PIPELINE_ID="" \
    bash "$REPOSITORY_ROOT/scripts/generate-sboms.sh"

  grep -Fxq 'registry.example/unavailable:1.0.0' skipped_images.txt
  test -z "$(find sboms -name '*.json' -print -quit)"
  PATH="$TEMPORARY_DIRECTORY/fake-bin:$PATH" \
    bash "$REPOSITORY_ROOT/scripts/scan-sboms.sh"
)

echo "Unavailable-image evidence path passed without terminating the pipeline."
