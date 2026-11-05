#!/usr/bin/env bash

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT

IMAGE='registry.example.invalid/team/cats@sha256:4aab4f958589dd1a4b9a3bf6ce44ccb3f9e6399d21a80adce8b4f4f68920cfb5'
mkdir -p "$TEMPORARY_DIRECTORY/fake-bin"
printf 'service:\n  id: cats\nimages:\n  - "%s"\n' "$IMAGE" > "$TEMPORARY_DIRECTORY/images.yml"
printf 'service:\n  id: cats\n' > "$TEMPORARY_DIRECTORY/service.yml"

cat > "$TEMPORARY_DIRECTORY/fake-bin/yq" <<SCRIPT
#!/usr/bin/env bash
case "\$*" in
  *'.images[]'*) printf '%s\n' '$IMAGE' ;;
  *) exit 0 ;;
esac
SCRIPT

cat > "$TEMPORARY_DIRECTORY/fake-bin/jq" <<'SCRIPT'
#!/usr/bin/env bash
cat >/dev/null
printf '%s\n' 'registry.example.invalid/team/cats@sha256:4aab4f958589dd1a4b9a3bf6ce44ccb3f9e6399d21a80adce8b4f4f68920cfb5'
SCRIPT

cat > "$TEMPORARY_DIRECTORY/fake-bin/docker" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_CALLS"
case "${1:-} ${2:-}" in
  'image inspect') printf '%s\n' '[{"RepoDigests":["example@sha256:abc"]}]' ;;
  'cp cats-sbom-'*) destination="${3:-}"; mkdir -p "$destination/etc"; printf 'ID=alpine\n' > "$destination/etc/os-release" ;;
esac
exit 0
SCRIPT

REAL_PYTHON="$(command -v python3)"
cat > "$TEMPORARY_DIRECTORY/fake-bin/python3" <<'SCRIPT'
#!/usr/bin/env bash
if [[ "$1" == */scanner-action.py ]]; then
  printf '%s\n' "$*" >> "$SCANNER_CALLS"
fi
exec "$REAL_PYTHON" "$@"
SCRIPT
chmod +x "$TEMPORARY_DIRECTORY/fake-bin/"*

(
  cd "$TEMPORARY_DIRECTORY"
  PATH="$TEMPORARY_DIRECTORY/fake-bin:$PATH" \
  CI_PROJECT_DIR="$TEMPORARY_DIRECTORY" \
  IMAGE_MATERIALIZATION_DIR="$TEMPORARY_DIRECTORY/image-filesystems" \
  DOCKER_CALLS="$TEMPORARY_DIRECTORY/docker.calls" \
  REAL_PYTHON="$REAL_PYTHON" SCANNER_CALLS="$TEMPORARY_DIRECTORY/scanner.calls" \
    bash "$REPOSITORY_ROOT/scripts/generate-sboms.sh"
)

grep -Eq '/scanner-action.py inventory .+-rootfs sboms/.+\.json$' "$TEMPORARY_DIRECTORY/scanner.calls"
! grep -Eq 'docker-archive:|docker save' "$TEMPORARY_DIRECTORY/scanner.calls" "$TEMPORARY_DIRECTORY/docker.calls"
test -s "$TEMPORARY_DIRECTORY"/sboms/*.json
test -s "$TEMPORARY_DIRECTORY"/sboms/*.digest
test ! -s "$TEMPORARY_DIRECTORY/skipped_images.txt"
test -z "$(find "$TEMPORARY_DIRECTORY/image-filesystems" -mindepth 1 -print -quit)"

echo "Patched digest image SBOM path passed without a Docker archive."
