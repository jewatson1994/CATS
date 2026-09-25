#!/usr/bin/env python3
"""Extract images only from recognized rendered Kubernetes pod specs."""

from pathlib import Path
import sys

import yaml


def images_from_resource(resource: dict) -> list[str]:
    kind = resource.get("kind")
    spec = resource.get("spec") or {}
    if not isinstance(spec, dict):
        return []
    def child(node, key):
        return node.get(key) if isinstance(node, dict) and isinstance(node.get(key), dict) else {}
    if kind == "Pod":
        pod_spec = spec
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"}:
        pod_spec = child(child(spec, "template"), "spec")
    elif kind == "CronJob":
        pod_spec = child(child(child(child(spec, "jobTemplate"), "spec"), "template"), "spec")
    else:
        return []
    if not isinstance(pod_spec, dict):
        return []
    images = []
    for field in ("containers", "initContainers", "ephemeralContainers"):
        for container in pod_spec.get(field) or []:
            if isinstance(container, dict) and isinstance(container.get("image"), str) and container["image"].strip():
                images.append(container["image"].strip())
    return images


def extract(path: Path) -> list[str]:
    values = []
    for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
        if isinstance(document, dict):
            values.extend(images_from_resource(document))
    return values


if __name__ == "__main__":
    for image in extract(Path(sys.argv[1])):
        print(image)
