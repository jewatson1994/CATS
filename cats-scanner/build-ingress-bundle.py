"""Build-only, pinned ingress-nginx distribution. Never called at runtime."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

import yaml


VERSION = "1.15.1"
CERTGEN_VERSION = "1.6.9"
SOURCE_MANIFEST_SHA256 = "2a3ae008c8786431115502644e77ab398fdebfb721a5d1195ed3089cde3299df"
IMAGES = {
    "controller": {
        "name": f"registry.k8s.io/ingress-nginx/controller:v{VERSION}",
        "digest": "594ceea76b01c592858f803f9ff4d2cb40542cae2060410b2c95f75907d659e1",
        "config": "895ddb49053a9b80e1c97354a933f59cc94fba4b6f831615687151c9b178218d",
        "archive": "controller.tar",
        "supplied": f"ingress-nginx-controller-v{VERSION}-linux-amd64.tar",
    },
    "kube-webhook-certgen": {
        "name": f"registry.k8s.io/ingress-nginx/kube-webhook-certgen:v{CERTGEN_VERSION}",
        "digest": "01038e7de14b78d702d2849c3aad72fd25903c4765af63cf16aa3398f5d5f2dd",
        "config": "1442d220fcdde0a4eb5344ef0ad24df4673d78c8a71cab38e3b051af46c87a86",
        "archive": "kube-webhook-certgen.tar",
        "supplied": f"ingress-nginx-kube-webhook-certgen-v{CERTGEN_VERSION}-linux-amd64.tar",
    },
}


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_archive(path, name, config_digest):
    """Authenticate supplied Docker archives by pinned config and diff IDs."""
    with tarfile.open(path) as archive:
        records = json.load(archive.extractfile("manifest.json"))
        if len(records) != 1 or records[0].get("RepoTags") != [name]:
            raise ValueError(f"Unexpected image tags in {path.name}")
        record = records[0]
        config = archive.extractfile(record["Config"]).read()
        if hashlib.sha256(config).hexdigest() != config_digest:
            raise ValueError(f"Image config digest mismatch: {path.name}")
        metadata = json.loads(config)
        if metadata.get("architecture") != "amd64" or metadata.get("os") != "linux":
            raise ValueError("Ingress bundle supports linux/amd64 only")
        expected = metadata["rootfs"]["diff_ids"]
        if len(expected) != len(record["Layers"]):
            raise ValueError("Image layer count mismatch")
        for layer, digest in zip(record["Layers"], expected):
            with archive.extractfile(layer) as stream:
                actual = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
            if actual != digest:
                raise ValueError(f"Image layer digest mismatch: {path.name}")


def build(source, destination):
    destination.mkdir(parents=True, exist_ok=True)
    supplied_manifest = source / f"ingress-nginx-kind-v{VERSION}.yaml"
    if supplied_manifest.is_file():
        raw = supplied_manifest.read_bytes()
    else:
        url = f"https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v{VERSION}/deploy/static/provider/kind/deploy.yaml"
        with urllib.request.urlopen(url, timeout=90) as response:
            raw = response.read(2_000_000)
    if hashlib.sha256(raw).hexdigest() != SOURCE_MANIFEST_SHA256:
        raise ValueError("Upstream ingress-nginx manifest SHA-256 mismatch")

    documents = [item for item in yaml.safe_load_all(raw) if isinstance(item, dict) and item.get("kind")]
    expected_images = {item["name"] for item in IMAGES.values()}
    seen = set()
    for document in documents:
        spec = document.get("spec") or {}
        pod = spec if document.get("kind") == "Pod" else ((spec.get("template") or {}).get("spec") or {})
        for container in [*(pod.get("initContainers") or []), *(pod.get("containers") or [])]:
            image = str(container.get("image") or "")
            base = image.split("@", 1)[0]
            if not image:
                continue
            if base not in expected_images:
                raise ValueError(f"Unpinned provider image in upstream manifest: {base}")
            container["imagePullPolicy"] = "Never"
            seen.add(base)
    if seen != expected_images:
        raise ValueError("Incomplete ingress-nginx provider manifest")

    manifest = destination / "ingress-nginx.yaml"
    manifest.write_text(yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8")
    inventory = {
        "schema_version": 1, "provider": "ingress-nginx", "version": VERSION,
        "architecture": "amd64", "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "manifest": {"path": manifest.name, "sha256": sha256(manifest)}, "images": [],
    }
    for item in IMAGES.values():
        output = destination / item["archive"]
        supplied = source / item["supplied"]
        if supplied.is_file():
            shutil.copyfile(supplied, output)
        else:
            subprocess.run([
                "skopeo", "copy", "--override-os", "linux", "--override-arch", "amd64",
                f"docker://{item['name'].split(':v', 1)[0]}@sha256:{item['digest']}",
                f"docker-archive:{output}:{item['name']}",
            ], check=True, timeout=900)
        verify_archive(output, item["name"], item["config"])
        inventory["images"].append({
            "name": item["name"], "digest": f"sha256:{item['digest']}",
            "archive": output.name, "sha256": sha256(output),
        })
    (destination / "bundle.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]))
