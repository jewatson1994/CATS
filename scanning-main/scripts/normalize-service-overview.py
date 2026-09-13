#!/usr/bin/env python3
"""Turn rendered Kubernetes JSON into the stable CATS overview contract."""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path


WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
ACCOUNTS = {"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
IMAGE_PLACEHOLDERS = {"", "---", "—", "-", "null", "none", "nil", "n/a", "na", "not provided", "unknown image"}


def meta(item):
    return item.get("metadata") or {}


def namespace(item):
    return meta(item).get("namespace") or "default"


def workload_spec(item):
    spec = item.get("spec") or {}
    if item.get("kind") == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    if item.get("kind") == "Pod":
        return spec
    return (spec.get("template") or {}).get("spec") or {}


def resource_name(item):
    return f"{item.get('kind', 'Resource')}/{meta(item).get('name', 'unknown')}"


def chart_owner(item):
    labels = meta(item).get("labels") or {}
    chart = labels.get("helm.sh/chart") or labels.get("chart")
    if chart:
        # Helm's conventional label is NAME-VERSION. Chart names may contain
        # hyphens, so strip only a suffix that actually begins with a version.
        return re.sub(r"-[vV]?\d[0-9A-Za-z.+_-]*$", "", str(chart))
    return labels.get("app.kubernetes.io/part-of") or labels.get("app.kubernetes.io/instance")


def labels(item):
    return meta(item).get("labels") or {}


def selector_matches(selector, candidate):
    return bool(selector) and all(candidate.get(key) == value for key, value in selector.items())


def unique(values):
    return sorted({value for value in values if value})


def normalize_source_file(value):
    """Return a user-facing Helm source path without scanner temp prefixes."""
    source = str(value or "").strip().replace("\\", "/")
    if not source:
        return ""
    source = re.sub(r"^#\s*Source:\s*", "", source, flags=re.IGNORECASE)
    source = re.sub(r"^\./+", "", source)
    source = re.sub(r"/{2,}", "/", source)
    # Helm normally prefixes the submitted chart name. Keep the meaningful
    # templates/charts/crds path, which also removes /tmp and /workspace.
    for marker in ("/charts/", "/templates/", "/crds/"):
        index = source.find(marker)
        if index >= 0:
            return source[index + 1 :].lstrip("/")
    if source.startswith(("charts/", "templates/", "crds/")):
        return source
    if source.startswith(("/tmp/", "/workspace/", "/opt/cats/")):
        return source.rsplit("/", 1)[-1]
    return source.lstrip("/")


def source_file(item):
    return normalize_source_file(
        item.get("_cats_source_file")
        or item.get("source_file")
        or item.get("source_path")
        or item.get("template")
    )


def valid_image(value):
    text = str(value or "").strip()
    return bool(text) and text.lower() not in IMAGE_PLACEHOLDERS


def main(input_path: str, output_path: str):
    items = json.loads(Path(input_path).read_text(encoding="utf-8"))
    items = [item for item in items if isinstance(item, dict) and item.get("kind")]
    ports, images, accounts, dependencies = [], [], [], []
    workloads_by_sa = defaultdict(list)
    workload_records = []
    role_bindings = defaultdict(list)
    subject_bindings = defaultdict(list)
    binding_relationships = defaultdict(list)
    dependency_resources = defaultdict(set)
    dependency_images = defaultdict(set)
    dependency_parent = {}

    for item in items:
        kind = item["kind"]
        name = resource_name(item)
        owner = chart_owner(item)
        source = source_file(item)
        if owner:
            dependency_resources[owner].add(kind)
            item_labels = labels(item)
            parent = item_labels.get("app.kubernetes.io/part-of") or item_labels.get("app.kubernetes.io/instance")
            if parent and parent != owner:
                dependency_parent[owner] = parent
            else:
                dependency_parent.setdefault(owner, "Submitted chart")
        if kind in WORKLOADS:
            spec = workload_spec(item)
            service_account = spec.get("serviceAccountName") or spec.get("serviceAccount")
            if service_account:
                workloads_by_sa[(namespace(item), service_account)].append(name)
            workload_labels = ((item.get("spec") or {}).get("template") or {}).get("metadata", {}).get("labels") or labels(item)
            record = {
                "name": name,
                "namespace": namespace(item),
                "labels": workload_labels,
                "ports": [],
                "images": [],
            }
            for container in [*(spec.get("containers") or []), *(spec.get("initContainers") or [])]:
                image = container.get("image")
                if valid_image(image):
                    image_row = {"image": image, "discovered_from": name}
                    if source:
                        image_row["source_file"] = source
                    images.append(image_row)
                    record["images"].append(image)
                    if owner:
                        dependency_images[owner].add(image)
                for port in container.get("ports") or []:
                    number = port.get("containerPort")
                    if number is not None:
                        port_row = {
                            "port": number,
                            "protocol": port.get("protocol") or "TCP",
                            "service": port.get("name") or container.get("name") or "Port",
                            "declared_by": name,
                            "provenance": "spec.template.spec.containers[].ports[].containerPort",
                        }
                        if source:
                            port_row["source_file"] = source
                        ports.append(port_row)
                        record["ports"].append({**port_row, "container": container.get("name")})
            workload_records.append(record)
        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            role_ref = item.get("roleRef") or {}
            role_name = f"{role_ref.get('kind', 'Role')}/{role_ref.get('name', 'unknown')}"
            role_bindings[(role_ref.get("kind"), role_ref.get("name"))].append(name)
            subject_values = []
            for subject in item.get("subjects") or []:
                subject_name = f"{subject.get('kind', 'Subject')}/{subject.get('name', 'unknown')}"
                subject_values.append(subject_name)
                subject_bindings[(subject.get("kind"), subject.get("name"), subject.get("namespace") or namespace(item))].append(name)
            binding_relationships[(kind, meta(item).get("name"), namespace(item))] = [role_name, *subject_values]

    # Services are evaluated after workloads so targetPort names/numbers can
    # be linked to the selected workload without claiming runtime exposure.
    for item in items:
        if item["kind"] != "Service":
            continue
        service_name = resource_name(item)
        spec = item.get("spec") or {}
        selected = [
            workload for workload in workload_records
            if workload["namespace"] == namespace(item)
            and selector_matches(spec.get("selector") or {}, workload["labels"])
        ]
        for port in spec.get("ports") or []:
            target = port.get("targetPort")
            target_number = target
            target_sources = []
            for workload in selected:
                for candidate in workload["ports"]:
                    if target == candidate.get("service") or target == candidate.get("port"):
                        target_number = candidate.get("port")
                        target_sources.append(workload["name"])
            mapping = target_number if target_number is not None else target
            service_label = port.get("name") or str(target or "Port")
            port_row = {
                "port": port.get("port"),
                "target_port": mapping,
                "protocol": port.get("protocol") or "TCP",
                "service": service_label,
                "declared_by": service_name,
                "provenance": "spec.ports[].port" + (
                    f" → {', '.join(unique(target_sources))} containers[].ports[].containerPort"
                    if target_sources else " → spec.ports[].targetPort"
                ),
            }
            service_source = source_file(item)
            if service_source:
                port_row["source_file"] = service_source
            ports.append(port_row)

    for item in items:
        kind = item["kind"]
        if kind not in ACCOUNTS:
            continue
        name = meta(item).get("name") or "unknown"
        relationships = []
        if kind == "ServiceAccount":
            relationships.extend(f"Used by {workload}" for workload in workloads_by_sa[(namespace(item), name)])
            relationships.extend(f"Bound by {binding}" for binding in subject_bindings[(kind, name, namespace(item))])
        elif kind in {"Role", "ClusterRole"}:
            relationships.extend(f"Bound by {binding}" for binding in role_bindings[(kind, name)])
        else:
            binding_values = binding_relationships[(kind, name, namespace(item))]
            if binding_values:
                relationships.append(f"Grants {binding_values[0]}")
                relationships.extend(f"Binds {subject}" for subject in binding_values[1:])
        account_row = {"kind": kind, "name": name, "namespace": namespace(item), "relationships": unique(relationships)}
        if source_file(item):
            account_row["source_file"] = source_file(item)
        accounts.append(account_row)

    for dependency in sorted(dependency_resources):
        dependencies.append({"dependency": dependency, "used_by": dependency_parent.get(dependency) or "Submitted chart", "provides": sorted(dependency_resources[dependency]), "images": sorted(dependency_images[dependency])})

    # Keep the parsed Kubernetes objects alongside the normalized summary.
    # The summary is convenient for tables/export, while these objects retain
    # selectors, routes, volumes, policies, and other structural evidence used
    # by downstream architecture and relationship discovery.  This is the
    # single render/parse result persisted with the assessment; consumers do
    # not need to execute Helm again.
    result = {"source": "Helm rendered manifests", "ports": ports, "accounts": accounts, "images": images, "dependencies": dependencies,
              "rendered_resources": items}
    Path(output_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
