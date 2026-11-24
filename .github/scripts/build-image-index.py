"""Assemble the tested platform manifests in the runner's private staging registry."""
import hashlib
import json
import os
from urllib.request import Request, urlopen

REGISTRY = "http://127.0.0.1:5000/v2/cats-tool"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
IMAGE_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")


def digest(blob):
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def descriptor(architecture):
    request = Request(f"{REGISTRY}/manifests/{architecture}", headers={"Accept": ", ".join(IMAGE_TYPES)})
    with urlopen(request, timeout=15) as response:
        manifest = response.read()
        media_type = response.headers.get_content_type()
    if media_type not in IMAGE_TYPES:
        raise ValueError(f"Expected a single image manifest for {architecture}, received {media_type}")
    config_digest = json.loads(manifest)["config"]["digest"]
    with urlopen(f"{REGISTRY}/blobs/{config_digest}", timeout=15) as response:
        config = response.read()
    decoded = json.loads(config)
    platform = {key: decoded[key] for key in ("os", "architecture")}
    if digest(config) != config_digest or platform != {"os": "linux", "architecture": architecture}:
        raise ValueError(f"Invalid platform/configuration for {architecture}")
    return {"mediaType": media_type, "digest": digest(manifest), "size": len(manifest), "platform": platform}


def main():
    index = {"schemaVersion": 2, "mediaType": OCI_INDEX,
             "annotations": {"org.opencontainers.image.revision": os.environ["GITHUB_SHA"]},
             "manifests": [descriptor(arch) for arch in ("amd64", "arm64")]}
    payload = json.dumps(index, separators=(",", ":")).encode()
    request = Request(f"{REGISTRY}/manifests/tested", method="PUT", data=payload,
                      headers={"Content-Type": OCI_INDEX})
    with urlopen(request, timeout=15) as response:
        if response.headers["Docker-Content-Digest"] != digest(payload):
            raise ValueError("Staging registry returned a different image digest")
    with open(os.environ["GITHUB_ENV"], "a") as env:
        print("CATS_IMAGE_DIGEST=" + digest(payload), file=env)


if __name__ == "__main__":
    main()
