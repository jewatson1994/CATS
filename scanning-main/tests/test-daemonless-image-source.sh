#!/usr/bin/env bash
# The CATS portal has no Docker socket. Image archives must still be scanned:
# each tagged image is read straight from the archive by Syft, Trivy and
# Dockle, and Docker is never invoked beyond the availability probe.
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for tool in syft jq yq python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIP: $tool is required for the daemonless image source test."
    exit 0
  fi
done
TEMPORARY_DIRECTORY="$(mktemp -d)"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT
cd "$TEMPORARY_DIRECTORY"
mkdir -p fake-bin archives

cat > fake-bin/docker <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_CALLS"
exit 1
SCRIPT
cat > fake-bin/trivy <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TRIVY_CALLS"
while [ "$#" -gt 0 ]; do
  [ "$1" = --output ] && printf '{"SchemaVersion":2,"Results":[]}\n' > "$2"
  shift
done
SCRIPT
cat > fake-bin/dockle <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKLE_CALLS"
while [ "$#" -gt 0 ]; do
  [ "$1" = --output ] && printf '{"summary":{},"details":[]}\n' > "$2"
  shift
done
SCRIPT
chmod +x fake-bin/*

python3 - archives <<'PYTHON'
import hashlib, io, json, sys, tarfile
from pathlib import Path

def add(archive, name, data):
    info = tarfile.TarInfo(name); info.size = len(data); archive.addfile(info, io.BytesIO(data))

def image(package):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as layer:
        add(layer, "etc/os-release", b'ID=alpine\nVERSION_ID=3.18.0\n')
        add(layer, "lib/apk/db/installed", f"P:{package}\nV:1.0.0-r0\nA:x86_64\n\n".encode())
    layer = buffer.getvalue()
    config = json.dumps({"architecture": "amd64", "os": "linux", "config": {},
                         "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}}).encode()
    return layer, config

root = Path(sys.argv[1])
with tarfile.open(root / "two-images.tar", "w") as archive:
    manifest = []
    for tag, package in (("registry.example.invalid/team/api:1.0", "apipkg"),
                         ("registry.example.invalid/team/worker:2.0", "workerpkg")):
        layer, config = image(package)
        layer_name = hashlib.sha256(layer).hexdigest() + "/layer.tar"
        config_name = hashlib.sha256(config).hexdigest() + ".json"
        add(archive, config_name, config); add(archive, layer_name, layer)
        manifest.append({"Config": config_name, "RepoTags": [tag], "Layers": [layer_name]})
    add(archive, "manifest.json", json.dumps(manifest).encode())

with tarfile.open(root / "two-oci.tar", "w") as archive:
    add(archive, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
    descriptors = []
    for tag, package in (("registry.example.invalid/team/oci-a:3.0", "ocia"),
                         ("registry.example.invalid/team/oci-b:4.0", "ocib")):
        layer, config = image(package)
        layer_digest, config_digest = hashlib.sha256(layer).hexdigest(), hashlib.sha256(config).hexdigest()
        manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                               "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + config_digest, "size": len(config)},
                               "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:" + layer_digest, "size": len(layer)}]}).encode()
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        for digest, data in ((layer_digest, layer), (config_digest, config), (manifest_digest, manifest)):
            add(archive, "blobs/sha256/" + digest, data)
        descriptors.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + manifest_digest,
                            "size": len(manifest), "annotations": {"io.containerd.image.name": tag}})
    add(archive, "index.json", json.dumps({"schemaVersion": 2, "manifests": descriptors}).encode())
PYTHON

: > image-archive-map.tsv
for archive in archives/*.tar; do
  python3 "$REPOSITORY_ROOT/scripts/split-image-archive.py" "$archive" --output-dir archives/.split >> image-archive-map.tsv
done
test "$(wc -l < image-archive-map.tsv)" -eq 4
printf 'images:\n' > images.yml
cut -f1 image-archive-map.tsv | sed 's/^/  - "/; s/$/"/' >> images.yml
printf 'service:\n  id: daemonless\n' > service.yml

export PATH="$TEMPORARY_DIRECTORY/fake-bin:$PATH" CI_PROJECT_DIR="$TEMPORARY_DIRECTORY" \
  DOCKER_CALLS="$TEMPORARY_DIRECTORY/docker.calls" TRIVY_CALLS="$TEMPORARY_DIRECTORY/trivy.calls" \
  DOCKLE_CALLS="$TEMPORARY_DIRECTORY/dockle.calls" IMAGE_MATERIALIZATION_DIR="$TEMPORARY_DIRECTORY/never-created"
bash "$REPOSITORY_ROOT/scripts/generate-sboms.sh" > generate.log 2>&1 || { cat generate.log; exit 1; }

# Docker was only probed for availability, never used.
test "$(sort -u docker.calls)" = info
test ! -e never-created
test ! -s skipped_images.txt
for pair in api:apipkg worker:workerpkg oci-a:ocia oci-b:ocib; do
  name="${pair%%:*}" package="${pair#*:}"
  sbom="$(ls sboms/registry.example.invalid-team-"${name}"-*.json)"
  # Each split archive holds exactly the named image.
  test "$(jq -c '[.artifacts[].name]' "$sbom")" = "[\"${package}\"]"
  grep -Eq '^sha256:[0-9a-f]{64}$' "${sbom%.json}.digest"
  grep -q "^registry.example.invalid/team/${name}:[0-9.]*	docker-archive:" image-sources.tsv
done

TRIVY_CONFIG_SCAN_ENABLED=false HELM_SCAN_ENABLED=false TRIVY_IMAGE_CONFIG_SCAN_ENABLED=true \
  DOCKLE_IMAGE_CONFIG_SCAN_ENABLED=true \
  bash "$REPOSITORY_ROOT/scripts/scan-configurations.sh" > configuration.log 2>&1 || { cat configuration.log; exit 1; }
test "$(grep -c -- '--input .*/archives/.split/.*\.tar$' trivy.calls)" -eq 4
test "$(grep -c -- '--input .*/archives/.split/.*\.tar$' dockle.calls)" -eq 4
test "$(sort -u docker.calls)" = info

echo "Daemonless image archives were scanned without Docker."
