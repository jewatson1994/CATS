#!/usr/bin/env python3
"""Attach retained Kubernetes identity to normalized Trivy findings.

Line ranges are scanner evidence, not permission to pick the first container.
Uncertain matches remain candidates for explicit target resolution.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

import yaml


CLUSTER_KINDS = {"Namespace", "Node", "PersistentVolume", "ClusterRole", "ClusterRoleBinding",
                 "CustomResourceDefinition", "StorageClass", "PriorityClass", "RuntimeClass",
                 "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
                 "APIService", "VolumeAttachment", "CSIDriver", "CSINode", "IngressClass"}
NAMESPACED_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job",
                    "CronJob", "ReplicationController", "Service", "ConfigMap", "Secret",
                    "ServiceAccount", "Role", "RoleBinding", "PersistentVolumeClaim", "Ingress",
                    "NetworkPolicy", "PodDisruptionBudget", "HorizontalPodAutoscaler"}


def child(node, key):
    if isinstance(node, yaml.MappingNode):
        return next((value for name, value in node.value if name.value == key), None)
    return None


def scalar(node, key):
    value = child(node, key)
    return value.value if isinstance(value, yaml.ScalarNode) else ""


def resources(path: Path, release_namespace: str = "") -> list[dict]:
    text = path.read_text(encoding="utf-8-sig")
    sidecar = path.with_suffix(".chart.json")
    chart = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.is_file() else {}
    release_namespace = chart.get("namespace") or release_namespace
    result = []
    lines = text.splitlines()
    # Node end marks include trailing comments before the next document.
    # Document separators, rather than the previous node's end, delimit Helm
    # Source headers (including headers after an empty/non-resource document).
    boundaries = [i + 1 for i, line in enumerate(lines)
                  if re.match(r"^---(?:\s|$)", line)]
    for index, node in enumerate(yaml.compose_all(text, Loader=yaml.SafeLoader)):
        if not isinstance(node, yaml.MappingNode):
            continue
        metadata = child(node, "metadata")
        kind, name = scalar(node, "kind"), scalar(metadata, "name")
        if not kind or not name:
            continue
        namespace = scalar(metadata, "namespace")
        scope = "explicit" if namespace else "cluster" if kind in CLUSTER_KINDS else "unknown"
        if not namespace and kind in NAMESPACED_KINDS and release_namespace:
            namespace, scope = release_namespace, "helm-release"
        document_start = max((line for line in boundaries if line <= node.start_mark.line), default=0)
        comments = lines[document_start:node.start_mark.line + 1]
        sources = [match.group(1) for line in comments if (match := re.match(r"\s*# Source:\s*(.+)", line))]
        base = {"rendered_artifact": path.as_posix(), "document_index": index,
                "api_version": scalar(node, "apiVersion"), "kind": kind, "namespace": namespace,
                "namespace_source": scope, "name": name, "source_template": sources[-1] if sources else "",
                "chart_id": chart.get("chart_id", ""),
                "chart_instance_id": chart.get("chart_instance_id") or chart.get("chart_id", ""),
                "source_chart": chart.get("source_chart") or chart.get("path") or chart.get("reference") or "",
                "chart_name": chart.get("name", ""), "release": chart.get("release", ""),
                "values_sources": chart.get("values") or [],
                "start_line": node.start_mark.line + 1, "end_line": node.end_mark.line}
        pod = child(node, "spec")
        prefix = "spec"
        if kind == "CronJob":
            pod = child(child(pod, "jobTemplate"), "spec")
            prefix += ".jobTemplate.spec"
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController", "CronJob"}:
            pod = child(child(pod, "template"), "spec")
            prefix += ".template.spec"
        containers = []
        if kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController", "CronJob"}:
            for field, container_type in (("containers", "container"), ("initContainers", "initContainer"),
                                          ("ephemeralContainers", "ephemeralContainer")):
                sequence = child(pod, field)
                if isinstance(sequence, yaml.SequenceNode):
                    for offset, container in enumerate(sequence.value):
                        containers.append({**base, "container_type": container_type,
                                           "container_name": scalar(container, "name"),
                                           "yaml_path": f"{prefix}.{field}[{offset}]",
                                           "start_line": container.start_mark.line + 1,
                                           "end_line": container.end_mark.line})
        result.append({**base, "containers": containers})
    return result


def enrich(rows: list[dict], input_path: str = "") -> list[dict]:
    cache = {}
    for row in rows:
        evidence = row.setdefault("evidence", {})
        # Re-enrichment must not preserve a previously resolved, now stale target.
        evidence.pop("resource_lineage", None)
        evidence.pop("candidate_resources", None)
        cause = evidence.get("cause_metadata") or {}
        scanner_target = str(evidence.get("scanner_target") or "")
        artifact_match = re.match(r"^(.*?\.(?:yaml|yml))(?::\s|\s+\(|$)", scanner_target, re.IGNORECASE)
        target = artifact_match.group(1) if artifact_match else scanner_target
        target_path = Path(target)
        candidates = []
        if input_path:
            root = Path(input_path)
            if root.is_file():
                if target_path == Path(root.name) or target_path.resolve() == root.resolve():
                    candidates.append(root)
                candidates.append(root.parent / target_path)
            else:
                candidates.append(root / target_path)
                # Trivy may already prefix the directory it was asked to scan.
                candidates.append(root.parent / target_path)
        candidates.append(target_path)
        path = next((item for item in candidates if item.is_file() and item.suffix.lower() in {".yaml", ".yml"}), None)
        if path is None:
            evidence["lineage_status"] = "unavailable"
            continue
        try:
            key = (path, evidence.get("deployment_namespace", ""))
            if key not in cache:
                cache[key] = resources(*key)
            documents = cache[key]
        except (OSError, ValueError, yaml.YAMLError):
            evidence["lineage_status"] = "unavailable"
            continue
        start, end = cause.get("StartLine"), cause.get("EndLine")
        has_lines = isinstance(start, int) and start > 0
        end = end if isinstance(end, int) and end >= (start or 0) else start
        matches = [item for item in documents if not has_lines or item["start_line"] <= start <= item["end_line"]]
        if ": " in scanner_target:
            identity = scanner_target.split(": ", 1)[1]
            # Trivy's resource suffix is affirmative evidence; never use a
            # partial name match across documents.
            identified = [item for item in matches if identity in {
                f"{item['api_version']}/{item['kind']}/{item['name']}",
                f"{item['api_version']}/{item['kind']}/{item['namespace']}/{item['name']}"}]
            matches = identified
        targets = []
        for item in matches:
            containers = item["containers"]
            matching = [container for container in containers if has_lines and
                        container["start_line"] <= start and end <= container["end_line"]]
            # Resource-wide line spans cannot identify one container; keep every
            # addressable candidate, including init/ephemeral containers.
            targets.extend(matching or containers or [{key: value for key, value in item.items() if key != "containers"}])
        evidence["candidate_resources"] = targets
        if len(targets) == 1:
            evidence["resource_lineage"] = targets[0]
            evidence["lineage_status"] = "resolved"
            row["namespace"] = targets[0]["namespace"]
        else:
            evidence["lineage_status"] = "ambiguous" if targets else "unavailable"
    return rows


def main():
    path = Path(sys.argv[1])
    rows = enrich(json.loads(path.read_text(encoding="utf-8")), sys.argv[2] if len(sys.argv) > 2 else "")
    path.write_text(json.dumps(rows, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
