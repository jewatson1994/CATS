#!/bin/bash

set -e

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_MATERIALIZATION_DIR="${IMAGE_MATERIALIZATION_DIR:-${DOCKER_IMAGE_ARCHIVE_DIR:-/docker/images}}"
SBOM_FORMATS="${SBOM_FORMATS:-syft-json}"
SBOM_CYCLONEDX_SPEC_VERSION="${SBOM_CYCLONEDX_SPEC_VERSION:-1.5}"

mkdir -p sboms sboms/formats
mkdir -p "$IMAGE_MATERIALIZATION_DIR"

ACTIVE_CONTAINER=""
ACTIVE_ROOTFS=""
cleanup_materialized_image() {
  if [ -n "$ACTIVE_CONTAINER" ]; then
    docker rm --force --volumes "$ACTIVE_CONTAINER" >/dev/null 2>&1 || true
  fi
  if [ -n "$ACTIVE_ROOTFS" ]; then
    rm -rf -- "$ACTIVE_ROOTFS"
  fi
  ACTIVE_CONTAINER=""
  ACTIVE_ROOTFS=""
}
trap cleanup_materialized_image EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Using prepared images.yml and evidence artifacts."
[ -f service.yml ] || { echo "ERROR: service.yml not found."; exit 1; }
[ -f images.yml ] || { echo "ERROR: images.yml not found."; exit 1; }
[ -f skipped_images.txt ] || : > skipped_images.txt

sort -u skipped_images.txt -o skipped_images.txt

yq -e '(.images | length > 0)' "$CI_PROJECT_DIR/images.yml" >/dev/null || {
    echo "ERROR: images.yml requires at least one image. Service metadata belongs in service.yml."
    exit 1
  }

yq -o=json '.images // []' "$CI_PROJECT_DIR/images.yml" \
  | jq -r 'def valid_image: type == "string" and (gsub("^\\s+|\\s+$"; "") | ascii_downcase as $v | ["", "---", "—", "-", "null", "none", "nil", "n/a", "na", "not provided", "unknown image"] | index($v) | not); .[]? | select(valid_image) | gsub("^\\s+|\\s+$"; "")' \
  > final_images.txt

echo ""
echo "======================================"
echo "FINAL IMAGES"
echo "======================================"
cat final_images.txt

while read IMAGE; do

  [ -z "$IMAGE" ] && continue

  echo ""
  echo "======================================"
  echo "Generating SBOM for $IMAGE"
  echo "======================================"

  if grep -Fqx "$IMAGE" skipped_images.txt; then
    echo "SKIPPED (already marked by patching): $IMAGE"
    continue
  fi

  SAFE_NAME=$(echo "$IMAGE" | tr '/:' '---')
  echo "$IMAGE" > "sboms/${SAFE_NAME}.image"

  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Using locally loaded image $IMAGE"
  elif ! docker pull "$IMAGE"; then
    echo "WARNING: Failed to pull $IMAGE"
    echo "$IMAGE" >> skipped_images.txt
    continue
  fi

  docker image inspect "$IMAGE" | jq -r '.[0].RepoDigests[0] // .[0].Id // empty' \
    > "sboms/${SAFE_NAME}.digest"

  # Docker's image store may preserve compressed OCI layers when a digest-pinned
  # patched image is pulled. `docker save` can then produce a nominal Docker
  # archive whose layer entries older Syft releases reject as invalid tar data.
  # Materialize the filesystem through Docker instead. This is also the path
  # used by the patch worker to verify patched output and works independently of
  # the daemon's internal archive/layer representation.
  WORK_ID="$(printf '%s' "$IMAGE" | sha256sum | cut -c1-20)"
  CONTAINER_NAME="cats-sbom-${WORK_ID}"
  ROOTFS_DIR="${IMAGE_MATERIALIZATION_DIR}/${WORK_ID}-rootfs"
  ACTIVE_CONTAINER="$CONTAINER_NAME"
  ACTIVE_ROOTFS="$ROOTFS_DIR"
  docker rm --force --volumes "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf -- "$ROOTFS_DIR"
  mkdir -p "$ROOTFS_DIR"

  if ! docker create --name "$CONTAINER_NAME" "$IMAGE" >/dev/null; then
    # Images such as scratch artifacts can omit CMD. Docker can still create a
    # container when an inert command is supplied; the command is never run.
    docker rm --force --volumes "$CONTAINER_NAME" >/dev/null 2>&1 || true
    if ! docker create --name "$CONTAINER_NAME" "$IMAGE" true >/dev/null; then
      echo "WARNING: Failed to materialize $IMAGE for SBOM generation"
      echo "$IMAGE" >> skipped_images.txt
      rm -rf -- "$ROOTFS_DIR"
      ACTIVE_CONTAINER=""
      ACTIVE_ROOTFS=""
      continue
    fi
  fi

  if ! docker cp "${CONTAINER_NAME}:/." "$ROOTFS_DIR"; then
    echo "WARNING: Failed to copy the filesystem for $IMAGE"
    echo "$IMAGE" >> skipped_images.txt
    docker rm --force --volumes "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf -- "$ROOTFS_DIR"
    ACTIVE_CONTAINER=""
    ACTIVE_ROOTFS=""
    continue
  fi
  docker rm --force --volumes "$CONTAINER_NAME" >/dev/null 2>&1 || true
  ACTIVE_CONTAINER=""

  echo "Scanning materialized image filesystem with Syft"
  if ! syft "dir:${ROOTFS_DIR}" \
      -o syft-json \
      > "sboms/${SAFE_NAME}.json"; then

    echo "WARNING: Failed to generate SBOM for $IMAGE"

    echo "$IMAGE" >> skipped_images.txt

    rm -f "sboms/${SAFE_NAME}.json"
    rm -rf -- "$ROOTFS_DIR"
    ACTIVE_ROOTFS=""

    continue
  fi

  echo ""
  echo "SBOM CREATED:"
  ls -lah "sboms/${SAFE_NAME}.json"

  # Serialize the one Syft inventory into any requested interchange formats.
  # This consumes the generated Syft JSON and never rescans the image.
  if ! python3 "${SCRIPT_DIRECTORY}/generate-sbom-formats.py" \
      --input "sboms/${SAFE_NAME}.json" \
      --output-dir "sboms/formats" \
      --image "$IMAGE" \
      --digest "$(cat "sboms/${SAFE_NAME}.digest" 2>/dev/null || true)" \
      --formats "$SBOM_FORMATS" \
      --cyclonedx-spec-version "$SBOM_CYCLONEDX_SPEC_VERSION"; then
    echo "WARNING: Failed to serialize requested SBOM formats for $IMAGE"
  fi

  rm -rf -- "$ROOTFS_DIR"
  ACTIVE_ROOTFS=""

done < final_images.txt

echo ""
echo "======================================"
echo "SBOM GENERATION COMPLETE"
echo "======================================"

echo ""
echo "SBOM DIRECTORY:"

if [ ! -d "sboms" ] || [ -z "$(ls -A sboms 2>/dev/null)" ]; then
    echo "WARNING: No SBOMs were generated. The assessment will continue as incomplete evidence."
fi

ls -lah sboms/

echo ""
echo "SKIPPED IMAGES:"
cat skipped_images.txt || true

# Keep pulled images available for the subsequent image-configuration pass.
# Cleanup is left to the worker/container lifecycle instead of removing the
# images before scan-configurations.sh can inspect them.
