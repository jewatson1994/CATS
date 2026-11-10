#!/bin/bash

set -eo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_MATERIALIZATION_DIR="${IMAGE_MATERIALIZATION_DIR:-${DOCKER_IMAGE_ARCHIVE_DIR:-/docker/images}}"
SBOM_FORMATS="${SBOM_FORMATS:-syft-json}"
SBOM_CYCLONEDX_SPEC_VERSION="${SBOM_CYCLONEDX_SPEC_VERSION:-1.5}"

mkdir -p sboms sboms/formats

# The CATS portal has no Docker socket by design; there, images are read
# straight from their registry or uploaded archive. run-scan.sh decides this
# once per job; standalone CI use detects it here.
if [ -z "${CATS_IMAGE_SOURCE:-}" ]; then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    CATS_IMAGE_SOURCE=docker
  else
    CATS_IMAGE_SOURCE=daemonless
  fi
fi
echo "Image source: $CATS_IMAGE_SOURCE"
if [ "$CATS_IMAGE_SOURCE" = docker ]; then
  mkdir -p "$IMAGE_MATERIALIZATION_DIR"
fi
: > image-sources.tsv

# Registry inventory retains the original manifest bytes in an OCI archive.
# Verify those bytes and the config before recording their registry digest.
# Uploaded archives have no registry provenance and retain their image ID.
record_daemonless_digest() {
  local image="$1" safe="$2" source="$3"
  if [[ "$source" == registry:* ]]; then
    python3 "${SCRIPT_DIRECTORY}/sbom_identity.py" "sboms/${safe}.json" "$image" \
      | jq -er --arg image "$image" 'select(.image_digest | type == "string") |
          ($image | sub("@.*$"; "") | sub(":[^/:]*$"; "")) + "@" + .image_digest' \
      > "sboms/${safe}.digest"
    return
  fi
  jq -r --arg image "$image" --arg source "$source" '
    (.source.metadata // {}) as $m
    | if ($source | startswith("registry:") | not) and ($m.imageID // "") != "" then $m.imageID
      elif (($m.repoDigests // []) | length) > 0 then $m.repoDigests[0]
      elif ($m.manifestDigest // "") != "" then
        ($image | sub("@.*$"; "") | sub(":[^/:]*$"; "")) + "@" + $m.manifestDigest
      else ($m.imageID // empty) end' "sboms/${safe}.json" > "sboms/${safe}.digest"
}

generate_daemonless_sbom() {
  local image="$1" safe="$2" source identity_source configuration_source mapping archive configuration_archive
  local -a acquire
  source="registry:${image}"
  if [ -s image-archive-map.tsv ]; then
    mapping="$(awk -F '\t' -v image="$image" '$1 == image { print $2 ":" $3; exit }' image-archive-map.tsv)"
    [ -n "$mapping" ] && source="$mapping"
  fi
  identity_source="$source"
  configuration_source="$source"
  if [[ "$source" == registry:* ]]; then
    mkdir -p .cats-images || return 1
    ACTIVE_IMAGE_DIRECTORY="$(mktemp -d "$(pwd)/.cats-images/image.XXXXXX")" || return 1
    mkdir -p "${TMPDIR:-$ACTIVE_IMAGE_DIRECTORY}" || return 1
    ACTIVE_ACQUIRE_TMP="$(mktemp -d "${TMPDIR:-$ACTIVE_IMAGE_DIRECTORY}/cats-acquire.XXXXXX")" || return 1
    configuration_archive="${ACTIVE_IMAGE_DIRECTORY}/image.tar"
    archive="${ACTIVE_IMAGE_DIRECTORY}/image.oci.tar"
    # Registry credentials belong only to acquisition. Offline scanner actions
    # receive an acquired archive, never this auth file or registry environment.
    # Skopeo defaults to /var/tmp even when TMPDIR is set. Keep layer
    # staging inside the worker's private job directory on a read-only root.
    # Docker archives discard the registry manifest; Syft reconstructs a new
    # digest for them. Preserve the selected platform's original manifest for
    # inventory and approval rather than approving a reconstructed manifest or
    # the multi-platform index (whose other images were never scanned).
    acquire=(skopeo --tmpdir "$ACTIVE_ACQUIRE_TMP" copy --preserve-digests)
    if [ -f "${DOCKER_CONFIG:-${HOME}/.docker}/config.json" ]; then
      acquire+=(--src-authfile "${DOCKER_CONFIG:-${HOME}/.docker}/config.json")
    fi
    if ! "${acquire[@]}" "docker://${source#registry:}" "oci-archive:${archive}"; then
      echo "WARNING: Failed to acquire $image"
      echo "$image" >> skipped_images.txt
      rm -f "$archive"
      return 1
    fi
    source="oci-archive:${archive}"
  fi
  echo "Reading acquired image without a Docker daemon: ${image}"
  if ! python3 "${SCRIPT_DIRECTORY}/scanner-action.py" inventory "${source#*:}" \
      "sboms/${safe}.json" --source-type "${source%%:*}"; then
    echo "WARNING: Failed to read $image"
    echo "$image" >> skipped_images.txt
    rm -f "sboms/${safe}.json"
    return 1
  fi
  if ! record_daemonless_digest "$image" "$safe" "$identity_source"; then
    echo "WARNING: Failed to verify acquired image identity for $image"
    echo "$image" >> skipped_images.txt
    rm -f "sboms/${safe}.json" "sboms/${safe}.digest"
    return 1
  fi
  if [[ "$identity_source" == registry:* ]]; then
    configuration_source="$source"
    if [ "${CATS_JOB_MODE:-scan}" != sbom ]; then
      # Derive configuration input from the verified bytes, never by resolving
      # the mutable tag again. SBOM-only jobs have no Docker-archive consumer.
      if ! skopeo --tmpdir "$ACTIVE_ACQUIRE_TMP" copy "$source" "docker-archive:${configuration_archive}"; then
        echo "WARNING: Failed to materialize acquired image configuration for $image"
        echo "$image" >> skipped_images.txt
        rm -f "sboms/${safe}.json" "sboms/${safe}.digest"
        return 1
      fi
      configuration_source="docker-archive:${configuration_archive}"
    fi
    # Inventory contains the verified manifest/config evidence. Nothing needs
    # the OCI archive or Skopeo staging after this point.
    rm -f -- "$archive"
    rm -rf -- "$ACTIVE_ACQUIRE_TMP"
    ACTIVE_ACQUIRE_TMP=""
  fi
  printf '%s\t%s\n' "$image" "$configuration_source" >> image-sources.tsv
}

scan_daemonless_image_configuration() {
  local image="$1" fragment configuration_rc=0
  fragment="$(mktemp -d "${CATS_IMAGE_CONFIGURATION_DIR}/image.XXXXXX")" || return 1
  printf '%s\n' "$image" > "$fragment/image" || return 1
  bash "${SCRIPT_DIRECTORY}/scan-configurations.sh" --image "$image" "$fragment" \
    > "$fragment/scan.log" 2>&1 || configuration_rc=$?
  printf '%s\n' "$configuration_rc" > "$fragment/exit-code"
}

serialize_sbom_formats() {
  local image="$1" safe="$2"
  echo ""
  echo "SBOM CREATED:"
  ls -lah "sboms/${safe}.json"

  # Serialize the one Syft inventory into any requested interchange formats.
  # This consumes the generated Syft JSON and never rescans the image.
  if ! python3 "${SCRIPT_DIRECTORY}/generate-sbom-formats.py" \
      --input "sboms/${safe}.json" \
      --output-dir "sboms/formats" \
      --image "$image" \
      --digest "$(cat "sboms/${safe}.digest" 2>/dev/null || true)" \
      --formats "$SBOM_FORMATS" \
      --cyclonedx-spec-version "$SBOM_CYCLONEDX_SPEC_VERSION"; then
    echo "WARNING: Failed to serialize requested SBOM formats for $image"
  fi
}

ACTIVE_CONTAINER=""
ACTIVE_ROOTFS=""
ACTIVE_IMAGE_DIRECTORY=""
ACTIVE_ACQUIRE_TMP=""
cleanup_materialized_image() {
  if [ -n "$ACTIVE_CONTAINER" ]; then
    docker rm --force --volumes "$ACTIVE_CONTAINER" >/dev/null 2>&1 || true
  fi
  if [ -n "$ACTIVE_ROOTFS" ]; then
    rm -rf -- "$ACTIVE_ROOTFS"
  fi
  # These are unique directories created by this invocation, never uploaded
  # archives, an input mapping, or the shared TMPDIR itself.
  [ -z "$ACTIVE_IMAGE_DIRECTORY" ] || rm -rf -- "$ACTIVE_IMAGE_DIRECTORY"
  [ -z "$ACTIVE_ACQUIRE_TMP" ] || rm -rf -- "$ACTIVE_ACQUIRE_TMP"
  ACTIVE_CONTAINER=""
  ACTIVE_ROOTFS=""
  ACTIVE_IMAGE_DIRECTORY=""
  ACTIVE_ACQUIRE_TMP=""
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
    if [ "$CATS_IMAGE_SOURCE" = daemonless ] && [ -n "${CATS_IMAGE_CONFIGURATION_DIR:-}" ]; then
      scan_daemonless_image_configuration "$IMAGE" || exit 1
    fi
    continue
  fi

  SAFE_NAME=$(echo "$IMAGE" | tr '/:' '---')
  echo "$IMAGE" > "sboms/${SAFE_NAME}.image"

  if [ "$CATS_IMAGE_SOURCE" = daemonless ]; then
    generated=false
    if generate_daemonless_sbom "$IMAGE" "$SAFE_NAME"; then
      generated=true
      serialize_sbom_formats "$IMAGE" "$SAFE_NAME"
    elif ! grep -Fqx "$IMAGE" skipped_images.txt; then
      echo "$IMAGE" >> skipped_images.txt
    fi
    if [ -n "${CATS_IMAGE_CONFIGURATION_DIR:-}" ]; then
      # Keep only small evidence fragments between phases. Both image checks
      # finish while this image's acquired bytes are still available.
      scan_daemonless_image_configuration "$IMAGE" || exit 1
    elif [ "$generated" = true ] && [ "${CATS_JOB_MODE:-scan}" != sbom ]; then
      # A standalone invocation still hands its Docker archive to a separate
      # scan-configurations.sh invocation, as before.
      ACTIVE_IMAGE_DIRECTORY=""
    fi
    cleanup_materialized_image
    continue
  fi

  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "Using locally loaded image $IMAGE"
  elif ! docker pull "$IMAGE"; then
    echo "WARNING: Failed to pull $IMAGE"
    echo "$IMAGE" >> skipped_images.txt
    continue
  fi

  docker image inspect "$IMAGE" | jq -r '.[0].RepoDigests[0] // .[0].Id // empty' \
    > "sboms/${SAFE_NAME}.digest"

  # Directory scans lack OCI metadata. Keep the inspected image provenance
  # separately; labels are evidence, never inferred vendor product identities.
  docker image inspect "$IMAGE" | jq '.[0] | {
    imageID: .Id, repoDigests: .RepoDigests, architecture: .Architecture,
    os: .Os, variant: .Variant, descriptor: .Descriptor, labels: (.Config.Labels // {})}
    | if (tojson | utf8bytelength) <= 32768 then . else null end' \
    > "sboms/${SAFE_NAME}.provenance"

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
  # This directory is an extracted image: retain installed language packages
  # that Syft's directory defaults intentionally omit (for example npm).
  if ! python3 "${SCRIPT_DIRECTORY}/scanner-action.py" inventory \
      "$ROOTFS_DIR" "sboms/${SAFE_NAME}.json"; then

    echo "WARNING: Failed to generate SBOM for $IMAGE"

    echo "$IMAGE" >> skipped_images.txt

    rm -f "sboms/${SAFE_NAME}.json"
    rm -rf -- "$ROOTFS_DIR"
    ACTIVE_ROOTFS=""

    continue
  fi

  serialize_sbom_formats "$IMAGE" "$SAFE_NAME"

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

# Docker-daemon images remain available for the separate configuration pass.
