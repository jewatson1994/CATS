"""Allowlisted Kubernetes controller metadata and Pod-template provenance."""
from dataclasses import dataclass
import re


RESOURCES = {
    "Pod": "/api/v1/pods",
    "Namespace": "/api/v1/namespaces",
    "Deployment": "/apis/apps/v1/deployments",
    "StatefulSet": "/apis/apps/v1/statefulsets",
    "DaemonSet": "/apis/apps/v1/daemonsets",
    "ReplicaSet": "/apis/apps/v1/replicasets",
    "Job": "/apis/batch/v1/jobs",
    "CronJob": "/apis/batch/v1/cronjobs",
}


def attribution(metadata):
    labels = metadata.get("labels", {})
    annotations = metadata.get("annotations", {})
    chart = re.fullmatch(r"(.+?)-(\d+\.\d+.*)", labels.get("helm.sh/chart", ""))
    instance = labels.get("app.kubernetes.io/instance", "")
    release = annotations.get("meta.helm.sh/release-name", "")
    if not release and (chart or labels.get("app.kubernetes.io/managed-by", "").lower() == "helm"):
        release = instance
    hint = annotations.get("cats.io/service-id", "")
    digest = annotations.get("cats.io/chart-digest", "")
    return {
        "chart_digest": digest if isinstance(digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", digest) else "",
        "app_name": labels.get("app.kubernetes.io/name", ""),
        "app_part_of": labels.get("app.kubernetes.io/part-of", ""),
        "app_instance": instance,
        "app_version": labels.get("app.kubernetes.io/version", ""),
        "chart_name": chart.group(1) if chart else "",
        "chart_version": chart.group(2) if chart else "",
        "helm_release": release,
        "helm_namespace": annotations.get("meta.helm.sh/release-namespace", ""),
        "service_hint": hint if isinstance(hint, str) and re.fullmatch(r"[1-9][0-9]{0,18}", hint) else "",
    }


def controlling_owner(metadata):
    owners = [ref for ref in metadata.get("ownerReferences", []) if ref.get("controller") is True]
    if len(owners) > 1:
        raise ValueError("multiple controlling owners")
    return owners[0] if owners else {}


def owner_fields(metadata):
    owner = controlling_owner(metadata)
    return {"controller_uid": owner.get("uid", ""), "controller_kind": owner.get("kind", ""),
            "controller_name": owner.get("name", "")}


@dataclass
class Controller:
    identity: tuple
    owner: tuple
    hints: dict
    components: list


def controller(kind, obj):
    meta, spec = obj["metadata"], obj["spec"]
    template = spec["jobTemplate"]["spec"]["template"] if kind == "CronJob" else spec["template"]
    namespace, name, uid = meta["namespace"], meta["name"], meta["uid"]
    if not all(isinstance(v, str) and v for v in (namespace, name, uid)):
        raise ValueError("missing controller identity")
    hints = attribution(template.get("metadata", {}))
    hints.update({k: v for k, v in attribution(meta).items() if v})
    components = []
    for category, key in (("regular", "containers"), ("init", "initContainers")):
        for container in template["spec"].get(key, []):
            components.append((category, container["name"], container["image"]))
    if not components:
        raise ValueError("missing template containers")
    owner = controlling_owner(meta)
    return Controller((namespace, kind, name, uid), (namespace, owner.get("kind", ""), owner.get("name", ""),
                       owner.get("uid", "")), hints, components)


def resolve(row, controllers):
    """Follow exact, namespaced controller UIDs. Names can survive object replacement."""
    identity = (row["namespace"], row.get("controller_kind"), row.get("controller_name"), row.get("controller_uid"))
    visited = set()
    hints = {}
    while identity in controllers:
        if identity in visited:
            raise ValueError("cyclic controller graph")
        visited.add(identity)
        node = controllers[identity]
        row.update(workload=identity[2], workload_kind=identity[1], workload_uid=identity[3])
        for key, value in node.hints.items():
            if value:
                hints.setdefault(key, value)
        identity = node.owner
    for key, value in hints.items():
        if not row.get(key):
            row[key] = value
    if row.get("helm_release") and not row.get("helm_namespace"):
        row["helm_namespace"] = row["namespace"]
    return row


def template_rows(controllers, namespaces, record):
    for node in controllers.values():
        if node.owner in controllers:
            # ReplicaSets and Jobs owned by a Deployment or CronJob are rollout/schedule instances.
            continue
        namespace, kind, name, uid = node.identity
        for category, container, image in node.components:
            hints = dict(node.hints)
            if hints["helm_release"] and not hints["helm_namespace"]:
                hints["helm_namespace"] = namespace
            yield record(uid=f"template:{uid}:{category}:{container}", namespace=namespace,
                         namespace_uid=namespaces.get(namespace, ""), workload_uid=uid,
                         workload_kind=kind, workload=name, controller_kind=node.owner[1],
                         controller_name=node.owner[2], controller_uid=node.owner[3],
                         container_kind=category, container=container, desired_image=image,
                         state="desired", **hints)
