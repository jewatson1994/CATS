"""Build-only, pinned MetalLB native/L2 distribution. Never called by validation."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

import yaml

VERSION = "0.16.1"
MANIFEST_SHA256 = "bf25feebb7582ca7df845efd52ffbc2960d6cbf4cfc972f47fded9f788b67f0b"
# Official quay.io linux/amd64 manifest and config digests, not mutable tags.
PINS = {
    "controller": (
        "5a3e101335f5ea2cfb0ddf51acdfa9538251e0623ffcd6cbfc1b274b7898790c",
        "5e1d13fb5c2d675dc41c4882cc5b8936a29904f43d030ba6a49c200660c64559",
    ),
    "speaker": (
        "37a98a9d1cd970051c5dededb6f922c1e6c3b90fdd0fc1350d1686e67675af0e",
        "99cea31eb93c2db0623d42b1346b8761b1f64b6347c7e7b6a31b4442a9df9f30",
    ),
}


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_archive(path, name, config_digest):
    """Validate supplied archives by config and uncompressed layer content.

    Docker archive bytes vary between exporters, so archive SHA alone cannot
    authenticate a supplied offline build input. The pinned config authenticates
    every layer's diff_id. Never extract paths from an untrusted archive.
    """
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
            raise ValueError("LoadBalancer bundle supports linux/amd64 only")
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
    upstream = source / f"metallb-native-v{VERSION}.yaml"
    if upstream.is_file():
        raw = upstream.read_bytes()
    else:
        url = f"https://raw.githubusercontent.com/metallb/metallb/v{VERSION}/config/manifests/metallb-native.yaml"
        with urllib.request.urlopen(url, timeout=90) as response:
            raw = response.read(2_000_000)
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("Upstream MetalLB manifest SHA-256 mismatch")
    documents = list(yaml.safe_load_all(raw))
    expected_images = {f"quay.io/metallb/{component}:v{VERSION}" for component in PINS}
    seen = set()
    for document in documents:
        if document.get("kind") not in {"Deployment", "DaemonSet"}:
            continue
        pod = document["spec"]["template"]["spec"]
        for container in pod.get("initContainers", []) + pod.get("containers", []):
            if container["image"] not in expected_images:
                raise ValueError("Unpinned provider image in upstream manifest")
            container["imagePullPolicy"] = "Never"
            seen.add(container["image"])
    if seen != expected_images:
        raise ValueError("Incomplete provider manifest")
    manifest = destination / "metallb-native.yaml"
    manifest.write_text(yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8")
    inventory = {"schema_version": 1, "provider": "metallb", "version": VERSION,
                 "architecture": "amd64", "source_manifest_sha256": MANIFEST_SHA256,
                 "manifest": {"path": manifest.name, "sha256": sha256(manifest)}, "images": []}
    for component, (digest, config_digest) in PINS.items():
        name = f"quay.io/metallb/{component}:v{VERSION}"
        output = destination / f"{component}.tar"
        supplied = source / f"metallb-{component}-v{VERSION}-linux-amd64.tar"
        if supplied.is_file():
            shutil.copyfile(supplied, output)
        else:
            subprocess.run(["skopeo", "copy", "--override-os", "linux", "--override-arch", "amd64",
                            f"docker://quay.io/metallb/{component}@sha256:{digest}",
                            f"docker-archive:{output}:{name}"], check=True, timeout=600)
        verify_archive(output, name, config_digest)
        inventory["images"].append({"name": name, "digest": f"sha256:{digest}",
                                    "archive": output.name, "sha256": sha256(output)})
    (destination / "bundle.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]))
