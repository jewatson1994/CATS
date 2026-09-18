"""Normalize rendered Kubernetes evidence into one explainable architecture graph."""
from __future__ import annotations

import logging
import json
from hashlib import sha256
from typing import Any

from .overview import normalize_overview

logger = logging.getLogger("cats.architecture")


WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}
SUPPORTED_KINDS = WORKLOAD_KINDS | {"Service", "Ingress", "Gateway", "HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute",
    "ConfigMap", "Secret", "PersistentVolumeClaim", "PersistentVolume", "NetworkPolicy", "Namespace",
    "ServiceAccount", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "HorizontalPodAutoscaler",
    "PodDisruptionBudget", "CustomResourceDefinition"}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def _text(value: Any, fallback: str = "") -> str:
    value = "" if value is None else str(value).strip()
    return value or fallback


def _metadata(resource: dict[str, Any]) -> dict[str, Any]:
    value = resource.get("metadata")
    return value if isinstance(value, dict) else {}


def _name(resource: dict[str, Any]) -> str:
    return _text(_metadata(resource).get("name") or resource.get("name"), "unnamed")


def _namespace(resource: dict[str, Any]) -> str:
    return _text(_metadata(resource).get("namespace") or resource.get("namespace"), "default")


def _kind(resource: dict[str, Any]) -> str:
    return _text(resource.get("kind") or resource.get("type"), "Unknown")


def _source(resource: dict[str, Any]) -> str:
    metadata = _metadata(resource)
    return _text(
        resource.get("_cats_source_file") or resource.get("source_file") or resource.get("source_path") or resource.get("file")
        or resource.get("template") or resource.get("chart") or resource.get("source")
        or metadata.get("source_file") or metadata.get("source_path") or metadata.get("file"),
        "Rendered manifest",
    )


def _resource_list(payload: dict[str, Any]) -> list[dict[str, Any]]:
    overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
    candidates: list[Any] = []
    for container in (payload, overview):
        for key in ("rendered_resources", "kubernetes_resources", "resources", "manifests", "rendered_manifests"):
            value = container.get(key)
            if isinstance(value, dict):
                value = value.get("items") or value.get("resources") or value.get("manifests")
            candidates.extend(_list(value))
    resources = []
    seen: set[tuple[str, str, str, str]] = set()
    for raw in candidates:
        if not isinstance(raw, dict) or not _kind(raw) or not _name(raw):
            continue
        key = (_kind(raw), _namespace(raw), _name(raw), _source(raw))
        if key not in seen:
            seen.add(key)
            resources.append(raw)
    return sorted(resources, key=lambda item: (_kind(item), _namespace(item), _name(item), _source(item), json.dumps(item, sort_keys=True)))


def _node_id(kind: str, namespace: str, name: str) -> str:
    return f"{kind.lower()}:{namespace}:{name}"


def _labels(resource: dict[str, Any]) -> dict[str, str]:
    labels = _metadata(resource).get("labels")
    return {str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {}


def _selector_matches(selector: Any, labels: dict[str, str]) -> bool:
    if not isinstance(selector, dict) or not selector:
        return False
    match_labels = selector.get("matchLabels") if isinstance(selector.get("matchLabels"), dict) else selector
    if any(labels.get(str(k)) != str(v) for k, v in match_labels.items()):
        return False
    for expr in selector.get("matchExpressions", []) if isinstance(selector.get("matchExpressions"), list) else []:
        if not isinstance(expr, dict):
            continue
        key, operator, values = str(expr.get("key", "")), expr.get("operator"), {str(v) for v in _list(expr.get("values"))}
        actual = labels.get(key)
        if operator == "In" and actual not in values:
            return False
        if operator == "NotIn" and actual in values:
            return False
        if operator == "Exists" and actual is None:
            return False
        if operator == "DoesNotExist" and actual is not None:
            return False
    return True


def _containers(resource: dict[str, Any]) -> list[dict[str, Any]]:
    spec = resource.get("spec") if isinstance(resource.get("spec"), dict) else {}
    if _kind(resource) == "CronJob":
        spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        return [c for c in [*_list(spec.get("containers")), *_list(spec.get("initContainers"))] if isinstance(c, dict)]
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    pod_spec = template.get("spec") if isinstance(template.get("spec"), dict) else spec
    return [c for c in [*_list(pod_spec.get("containers")), *_list(pod_spec.get("initContainers"))] if isinstance(c, dict)]


def _workload_labels(resource: dict[str, Any]) -> dict[str, str]:
    spec = resource.get("spec") if isinstance(resource.get("spec"), dict) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    return _labels(template) if template else _labels(resource)


def _evidence(resource: dict[str, Any], detail: str = "") -> dict[str, Any]:
    return {"source": _source(resource), "detail": detail or f"{_kind(resource)}/{_name(resource)}"}


def _container_ports(resource: dict[str, Any]) -> list[dict[str, Any]]:
    ports = []
    for container in _containers(resource):
        for port in _list(container.get("ports")):
            if isinstance(port, dict) and port.get("containerPort") is not None:
                ports.append({"containerPort": port.get("containerPort"), "name": _text(port.get("name")),
                              "protocol": _text(port.get("protocol"), "TCP"), "container": _text(container.get("name"), "unnamed")})
    return ports


def _network_label(mappings: list[dict[str, Any]], suffix: str = "") -> str:
    labels = []
    for mapping in mappings:
        service_port, target_port = mapping.get("servicePort"), mapping.get("targetPort")
        protocol = mapping.get("protocol") or "TCP"
        if service_port is None and target_port is None:
            continue
        labels.append(f"{service_port} → {target_port}/{protocol}" if service_port is not None and target_port is not None and str(service_port) != str(target_port) else f"{service_port or target_port}/{protocol}")
    label = ", ".join(dict.fromkeys(labels))
    return f"{label}{suffix}" if label else suffix.strip()


def build_architecture_graph(payload: dict[str, Any] | None, viewport_width: float = 1200, runtime_evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    overview_raw = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
    overview = normalize_overview(
        overview_raw,
        skipped_images=payload.get("skipped_images", []) or [],
        skipped_charts=payload.get("skipped_charts", []) or [],
        incomplete=not bool(payload.get("complete", True)),
    )
    resources = _resource_list(payload)
    nodes: list[dict[str, Any]] = []
    node_by_id: dict[str, dict[str, Any]] = {}
    by_key: dict[tuple[str, str, str], str] = {}
    resource_by_id: dict[str, dict[str, Any]] = {}
    for resource in resources:
        kind, namespace, name = _kind(resource), _namespace(resource), _name(resource)
        node_id = _node_id(kind, namespace, name)
        by_key[(kind, namespace, name)] = node_id
        resource_by_id[node_id] = resource
        spec = resource.get("spec") if isinstance(resource.get("spec"), dict) else {}
        ports = []
        for port in _list(spec.get("ports")) if kind == "Service" else []:
            if isinstance(port, dict):
                ports.append({"port": _text(port.get("port") or port.get("targetPort")), "protocol": _text(port.get("protocol"), "TCP"),
                              "name": _text(port.get("name"), "—"), "source": _source(resource)})
        mappings = resource.get("_cats_source_mappings") if isinstance(resource.get("_cats_source_mappings"), list) else []
        chart_provenance = resource.get("_cats_chart_provenance") if isinstance(resource.get("_cats_chart_provenance"), dict) else {}
        if node_id in node_by_id:
            existing_node = node_by_id[node_id]
            evidence = _evidence(resource)
            if evidence not in existing_node["evidence"]:
                existing_node["evidence"].append(evidence)
            for mapping in mappings:
                if mapping not in existing_node["source_mappings"]:
                    existing_node["source_mappings"].append(mapping)
            for port in ports:
                if port not in existing_node["ports"]:
                    existing_node["ports"].append(port)
            continue
        node = {"id": node_id, "kind": kind, "name": name, "namespace": namespace,
                "label": f"{kind} · {name}", "source": _source(resource), "source_mappings": mappings,
                "chart_provenance": chart_provenance,
                "generic": kind not in SUPPORTED_KINDS, "api_version": _text(resource.get("apiVersion")),
                "evidence": [_evidence(resource)], "ports": ports, "provenance": "DECLARED"}
        nodes.append(node)
        node_by_id[node_id] = node

    def find(kind: str, name: str, namespace: str) -> str | None:
        return by_key.get((kind, namespace, name))

    relationships: list[dict[str, Any]] = []
    relationship_keys: set[tuple[str, str, str]] = set()

    def edge(source: str | None, target: str | None, classification: str, label: str, evidence: list[dict[str, Any]], confidence: str = "high", network: dict[str, Any] | None = None) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, label)
        if key in relationship_keys:
            return
        relationship_keys.add(key)
        relationship = {"id": "rel-" + sha256(json.dumps(key).encode()).hexdigest()[:24], "source": source, "target": target,
                        "classification": classification, "style": "solid" if classification == "DECLARED" else "dashed",
                        "label": label, "confidence": confidence, "evidence": evidence,
                        "primary": bool(network and "policy" not in label.lower())}
        if network:
            relationship["network"] = network
        relationships.append(relationship)

    images: dict[str, str] = {}
    for resource_id, resource in resource_by_id.items():
        kind, namespace = _kind(resource), _namespace(resource)
        spec = resource.get("spec") if isinstance(resource.get("spec"), dict) else {}
        if kind in WORKLOAD_KINDS:
            for container in _containers(resource):
                image = _text(container.get("image"))
                if not image:
                    continue
                image_id = images.setdefault(image, f"image:{image}")
                if not any(node["id"] == image_id for node in nodes):
                    nodes.append({"id": image_id, "kind": "ContainerImage", "name": image, "namespace": namespace,
                                  "label": f"Image · {image}", "source": _source(resource), "evidence": [_evidence(resource, f"container {container.get('name', 'unnamed')}")]})
                edge(resource_id, image_id, "DECLARED", "runs", [_evidence(resource, f"container image {image}")])
            selector = spec.get("selector")
            if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"} and not selector:
                selector = _workload_labels(resource)
        if kind == "Service":
            selector = spec.get("selector")
            selected = [(workload_id, workload) for workload_id, workload in resource_by_id.items()
                        if _kind(workload) in WORKLOAD_KINDS and _namespace(workload) == namespace and _selector_matches(selector, _workload_labels(workload))]
            mappings = []
            for service_port in _list(spec.get("ports")):
                if not isinstance(service_port, dict):
                    continue
                target = service_port.get("targetPort")
                resolved = [port for _, workload in selected for port in _container_ports(workload)
                            if target == port.get("name") or target == port.get("containerPort")]
                target_value = resolved[0].get("containerPort") if resolved else target
                mappings.append({"servicePort": service_port.get("port"), "targetPort": target_value,
                                 "containerPort": target_value, "protocol": _text(service_port.get("protocol"), "TCP"),
                                 "name": _text(service_port.get("name"))})
            label = _network_label(mappings) or "selects"
            network = {"ports": mappings, "evidence_type": "Service selector"} if mappings else None
            for workload_id, workload in selected:
                edge(resource_id, workload_id, "DERIVED", label, [_evidence(resource, "spec.selector"), _evidence(workload, "pod template labels")], network=network)
        if kind == "Ingress":
            rules = _list(spec.get("rules"))
            for rule in rules:
                http = rule.get("http") if isinstance(rule, dict) else {}
                for path in _list(http.get("paths") if isinstance(http, dict) else []):
                    backend = path.get("backend") if isinstance(path, dict) else {}
                    service = backend.get("service") if isinstance(backend, dict) and isinstance(backend.get("service"), dict) else backend
                    if isinstance(service, dict):
                        service_name = service.get("name") or service.get("serviceName")
                        target_id = find("Service", _text(service_name), namespace)
                        target_resource = resource_by_id.get(target_id or "", {})
                        backend_port = service.get("port")
                        backend_port = backend_port.get("number") if isinstance(backend_port, dict) else backend_port
                        protocol, application_protocol = "TCP", None
                        for port in _list((target_resource.get("spec") or {}).get("ports")) if isinstance(target_resource, dict) else []:
                            if isinstance(port, dict) and (backend_port is None or backend_port in {port.get("port"), port.get("name")}):
                                backend_port, protocol = port.get("port"), _text(port.get("protocol"), "TCP")
                                application_protocol = port.get("appProtocol")
                                break
                        annotations = _metadata(resource).get("annotations") if isinstance(_metadata(resource).get("annotations"), dict) else {}
                        application_protocol = application_protocol or annotations.get("nginx.ingress.kubernetes.io/backend-protocol") or annotations.get("haproxy.org/backend-protocol")
                        mappings = [{"servicePort": backend_port, "targetPort": None, "containerPort": None, "protocol": protocol}]
                        if application_protocol:
                            mappings[0]["applicationProtocol"] = application_protocol
                        suffix = f" · {application_protocol}" if application_protocol else ""
                        edge(resource_id, target_id, "DECLARED", _network_label(mappings, suffix) or f"routes {path.get('path', '/')}", [_evidence(resource, f"host {rule.get('host', '*')}")], network={"ports": mappings, "evidence_type": "Ingress backend"})
        if kind in {"HTTPRoute", "GRPCRoute", "TCPRoute", "TLSRoute"}:
            for parent in _list(spec.get("parentRefs")):
                if isinstance(parent, dict):
                    target_kind = _text(parent.get("kind"), "Gateway")
                    target_ns = _text(parent.get("namespace"), namespace)
                    edge(find(target_kind, _text(parent.get("name")), target_ns), resource_id, "DECLARED", "accepts route", [_evidence(resource, "spec.parentRefs")])
            for rule in _list(spec.get("rules")):
                if not isinstance(rule, dict):
                    continue
                for backend in _list(rule.get("backendRefs")):
                    if not isinstance(backend, dict):
                        continue
                    target_kind = _text(backend.get("kind"), "Service")
                    target_ns = _text(backend.get("namespace"), namespace)
                    port = backend.get("port")
                    network = {"ports": [{"servicePort": port, "targetPort": None, "protocol": "TCP"}], "evidence_type": "Gateway API backendRef"} if port else None
                    edge(resource_id, find(target_kind, _text(backend.get("name")), target_ns), "DECLARED",
                         f"routes to {port}/TCP" if port else "routes to", [_evidence(resource, "spec.rules[].backendRefs")], network=network)
        if kind == "HorizontalPodAutoscaler":
            ref = spec.get("scaleTargetRef") if isinstance(spec.get("scaleTargetRef"), dict) else {}
            edge(resource_id, find(_text(ref.get("kind")), _text(ref.get("name")), namespace), "DECLARED", "scales", [_evidence(resource, "spec.scaleTargetRef")])
        if kind == "PodDisruptionBudget":
            selector = spec.get("selector")
            for workload_id, workload in resource_by_id.items():
                if _kind(workload) in WORKLOAD_KINDS and _namespace(workload) == namespace and _selector_matches(selector, _workload_labels(workload)):
                    edge(resource_id, workload_id, "DERIVED", "protects", [_evidence(resource, "spec.selector")])
        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            ref = resource.get("roleRef") if isinstance(resource.get("roleRef"), dict) else {}
            ref_namespace = namespace if ref.get("kind") == "Role" else "default"
            edge(resource_id, find(_text(ref.get("kind")), _text(ref.get("name")), ref_namespace), "DECLARED", "grants", [_evidence(resource, "roleRef")])
            for subject in _list(resource.get("subjects")):
                if isinstance(subject, dict):
                    subject_ns = _text(subject.get("namespace"), namespace)
                    edge(resource_id, find(_text(subject.get("kind")), _text(subject.get("name")), subject_ns), "DECLARED", "binds", [_evidence(resource, "subjects")])
        if kind == "NetworkPolicy":
            selector = spec.get("podSelector")
            for workload_id, workload in resource_by_id.items():
                if _kind(workload) in WORKLOAD_KINDS and _namespace(workload) == namespace and _selector_matches(selector, _workload_labels(workload)):
                    edge(resource_id, workload_id, "DERIVED", "applies to", [_evidence(resource, "spec.podSelector")])
            for rule in _list(spec.get("egress")):
                if not isinstance(rule, dict):
                    continue
                mappings = [{"servicePort": port.get("port"), "targetPort": port.get("port"), "containerPort": None, "protocol": _text(port.get("protocol"), "TCP")}
                            for port in _list(rule.get("ports")) if isinstance(port, dict) and port.get("port") is not None]
                sources = [(workload_id, workload) for workload_id, workload in resource_by_id.items()
                           if _kind(workload) in WORKLOAD_KINDS and _namespace(workload) == namespace and _selector_matches(selector, _workload_labels(workload))]
                for peer in _list(rule.get("to")):
                    peer_selector = peer.get("podSelector") if isinstance(peer, dict) else None
                    targets = [(workload_id, workload) for workload_id, workload in resource_by_id.items()
                               if _kind(workload) in WORKLOAD_KINDS and _namespace(workload) == namespace and _selector_matches(peer_selector, _workload_labels(workload))]
                    for source_id, source_workload in sources:
                        for target_id, target_workload in targets:
                            edge(source_id, target_id, "DERIVED", _network_label(mappings, " · policy") or "allowed by policy",
                                 [_evidence(resource, "egress policy"), _evidence(source_workload, "policy podSelector"), _evidence(target_workload, "policy peer podSelector")], network={"ports": mappings, "evidence_type": "NetworkPolicy egress"} if mappings else None)
        if kind in WORKLOAD_KINDS:
            pod_spec = (spec.get("template") or {}).get("spec", {}) if isinstance(spec.get("template"), dict) else spec
            for volume in _list(pod_spec.get("volumes")):
                if not isinstance(volume, dict):
                    continue
                for field, target_kind, label in (("configMap", "ConfigMap", "mounts"), ("secret", "Secret", "mounts"), ("persistentVolumeClaim", "PersistentVolumeClaim", "uses")):
                    ref = volume.get(field)
                    ref_name = ref.get("name") if isinstance(ref, dict) else None
                    edge(resource_id, find(target_kind, _text(ref_name), namespace), "DECLARED", label, [_evidence(resource, f"volume {volume.get('name', field)}")])
            for container in _containers(resource):
                for env in _list(container.get("env")):
                    value_from = env.get("valueFrom") if isinstance(env, dict) else {}
                    for field, target_kind in (("configMapKeyRef", "ConfigMap"), ("secretKeyRef", "Secret")):
                        ref = value_from.get(field) if isinstance(value_from, dict) else {}
                        edge(resource_id, find(target_kind, _text(ref.get("name") if isinstance(ref, dict) else ""), namespace), "DECLARED", "reads", [_evidence(resource, f"env {env.get('name', '')}")])
            pod_spec = (((spec.get("template") or {}).get("spec") or {}) if kind != "Pod" else spec)
            if kind == "CronJob":
                pod_spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
            service_account = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
            edge(resource_id, find("ServiceAccount", _text(service_account), namespace), "DECLARED", "runs as", [_evidence(resource, "serviceAccountName")])

    # Generic resources stay visible and gain relationships from conventional
    # Kubernetes reference objects. Unknown kinds never fail normalization.
    def walk_refs(value: Any, path: str = ""):
        if isinstance(value, dict):
            if value.get("name") and value.get("kind") and (path.endswith("Ref") or path.endswith("Refs")):
                yield value, path
            for key, child in value.items():
                yield from walk_refs(child, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for child in value:
                yield from walk_refs(child, path)

    for resource_id, resource in resource_by_id.items():
        namespace = _namespace(resource)
        for ref, path in walk_refs(resource):
            target_ns = _text(ref.get("namespace"), namespace)
            target = find(_text(ref.get("kind")), _text(ref.get("name")), target_ns)
            edge(resource_id, target, "DECLARED", "references", [_evidence(resource, path)])

    # Conservative inference: only exact service names or Kubernetes DNS names in env values.
    service_names = {(node["name"], node["namespace"]): node["id"] for node in nodes if node["kind"] == "Service"}
    service_resources = {(node["name"], node["namespace"]): resource_by_id[node["id"]] for node in nodes if node["kind"] == "Service"}
    for resource_id, resource in resource_by_id.items():
        if _kind(resource) not in WORKLOAD_KINDS:
            continue
        for container in _containers(resource):
            for env in _list(container.get("env")):
                value = _text(env.get("value") if isinstance(env, dict) else "")
                for (service_name, namespace), target in service_names.items():
                    candidates = {service_name, f"{service_name}.{namespace}", f"{service_name}.{namespace}.svc", f"{service_name}.{namespace}.svc.cluster.local"}
                    if value in candidates:
                        env_port = None
                        env_name = _text(env.get("name"))
                        for candidate in _list(container.get("env")):
                            if isinstance(candidate, dict) and str(candidate.get("name", "")).endswith("PORT"):
                                try:
                                    env_port = int(str(candidate.get("value", "")))
                                except ValueError:
                                    pass
                        mappings = []
                        for service_port in _list((service_resources[(service_name, namespace)].get("spec") or {}).get("ports")):
                            if isinstance(service_port, dict) and (env_port is None or service_port.get("port") == env_port):
                                mappings.append({"servicePort": service_port.get("port"), "targetPort": service_port.get("targetPort"), "containerPort": service_port.get("targetPort"), "protocol": _text(service_port.get("protocol"), "TCP")})
                        label = _network_label(mappings, " · inferred") if mappings else f"env {env_name} · inferred"
                        evidence = [_evidence(resource, f"{env_name}={value}")]
                        if env_port is not None:
                            evidence.append(_evidence(service_resources[(service_name, namespace)], f"exposes {env_port}"))
                        edge(resource_id, target, "INFERRED", label, evidence, "medium", network={"ports": mappings, "evidence_type": "Environment reference"} if mappings else None)

    # External is a visualization construct, not a claimed Kubernetes object.
    # Add it only when an Ingress has a resolved backend relationship.
    for ingress_id, ingress in list(resource_by_id.items()):
        if _kind(ingress) != "Ingress":
            continue
        ingress_edges = [relationship for relationship in relationships if relationship["source"] == ingress_id and relationship.get("network")]
        if not ingress_edges:
            continue
        external_id = f"external:{_namespace(ingress)}:{_name(ingress)}"
        if not any(node["id"] == external_id for node in nodes):
            nodes.append({"id": external_id, "kind": "ExternalEndpoint", "name": "External Traffic", "namespace": "outside",
                          "label": "External · Traffic", "source": _source(ingress),
                          "evidence": [_evidence(ingress, f"entry point for {_name(ingress)}")], "external": True, "provenance": "INFERRED"})
        edge(external_id, ingress_id, "DERIVED", _network_label((ingress_edges[0].get("network") or {}).get("ports", [])),
             [_evidence(ingress, "Ingress entry point")], network={"ports": (ingress_edges[0].get("network") or {}).get("ports", []), "evidence_type": "Ingress entry point"})

    runtime = runtime_evidence if isinstance(runtime_evidence, dict) else {}
    comparison = runtime.get("comparison") if isinstance(runtime.get("comparison"), dict) else {}
    expected_rows = comparison.get("expected_evidence") if isinstance(comparison.get("expected_evidence"), list) else []
    expected_by_name = {(str(item.get("kind") or ""), str(item.get("name") or "")): item for item in expected_rows if isinstance(item, dict)}
    reconciliation = (runtime.get("diagnostics") or {}).get("reconciliation", {}) if isinstance(runtime.get("diagnostics"), dict) else {}
    validation_releases = [str(value) for value in reconciliation.get("template_release_names", []) if value]

    def logical_runtime_name(item: dict[str, Any]) -> str:
        name = str(item.get("name") or "")
        for release in sorted(validation_releases, key=len, reverse=True):
            if name == release:
                return ""
            if name.startswith(release + "-"):
                return name[len(release) + 1:]
        return name

    def release_agnostic_candidate(node: dict[str, Any]) -> dict[str, Any] | None:
        matches = []
        node_name = str(node.get("name") or "")
        for item in expected_rows:
            if not isinstance(item, dict) or str(item.get("kind") or "") != str(node.get("kind") or ""):
                continue
            logical = logical_runtime_name(item)
            if logical and (node_name == logical or node_name.endswith("-" + logical)):
                matches.append(item)
        return matches[0] if len(matches) == 1 else None
    expected_by_source: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in expected_rows:
        if isinstance(item, dict) and item.get("source_file"):
            expected_by_source.setdefault((str(item.get("kind") or ""), str(item.get("source_file") or "")), []).append(item)
    observed_node_ids: set[str] = set()
    for node in nodes:
        node.setdefault("provenance", "DECLARED")
        if node.get("provenance") == "INFERRED" or node.get("kind") in {"ContainerImage", "ExternalEndpoint"}:
            continue
        candidate = expected_by_name.get((str(node.get("kind") or ""), str(node.get("name") or "")))
        if candidate is None:
            candidate = release_agnostic_candidate(node)
        if candidate is None:
            node_source = str(node.get("source") or "").replace("\\", "/").lstrip("/")
            source_candidates = [item for (kind, source), items in expected_by_source.items()
                                 if kind == str(node.get("kind") or "") and (source == node_source or source.endswith("/" + node_source) or node_source.endswith("/" + source))
                                 for item in items]
            candidate = source_candidates[0] if len(source_candidates) == 1 else None
        if candidate and candidate.get("matched"):
            node["provenance"] = "DECLARED_AND_OBSERVED"
            node["runtime_evidence"] = candidate
            observed_node_ids.add(node["id"])
        elif candidate:
            node["runtime_evidence"] = candidate
    noisy_runtime_kinds = {"Pod", "ReplicaSet", "EndpointSlice", "Endpoints", "ControllerRevision", "Event"}
    existing = {(str(node.get("kind")), str(node.get("namespace")), str(node.get("name"))) for node in nodes}
    for identity in [*(comparison.get("defaulted") or []), *(comparison.get("observed_only") or [])]:
        parts = str(identity).split("/", 2)
        if len(parts) != 3 or parts[0] in noisy_runtime_kinds or tuple(parts) in existing:
            continue
        kind, namespace, name = parts
        nodes.append({"id": _node_id(kind, namespace, name), "kind": kind, "name": name, "namespace": namespace,
                      "label": f"{kind} · {name}", "source": "Kubernetes runtime evidence", "evidence": [],
                      "ports": [], "provenance": "OBSERVED", "runtime_only": True})
    capabilities = runtime.get("capability_preflight") if isinstance(runtime.get("capability_preflight"), list) else []
    for capability in capabilities:
        if not isinstance(capability, dict) or str(capability.get("status") or "").upper() not in {"VERIFIED", "AVAILABLE", "BOUND"}:
            continue
        kind, _, name = str(capability.get("source_resource") or "").partition("/")
        for node in nodes:
            if node.get("kind") == kind and node.get("name") == name:
                node.setdefault("capability_evidence", []).append({"capability": capability.get("capability"), "status": capability.get("status"), "explanation": capability.get("explanation")})
    for relationship in relationships:
        relationship["provenance"] = "INFERRED" if relationship.get("classification") == "INFERRED" else "DECLARED"
        if relationship["provenance"] != "INFERRED" and relationship.get("source") in observed_node_ids and relationship.get("target") in observed_node_ids:
            relationship["provenance"] = "DECLARED_AND_OBSERVED"
            relationship.setdefault("evidence", []).append({"source": "Deployment Validation", "detail": "Both endpoint resources were observed for this artifact revision"})

    # Compatibility metadata uses the same topology ranking as presentation.
    from .architecture_layout import _ranks
    ranks = _ranks([node["id"] for node in nodes], [edge for edge in relationships if edge.get("network")])
    for node in nodes:
        node["flow_rank"] = ranks.get(node["id"], 0)

    node_ids = {node["id"] for node in nodes}
    connected = {item for rel in relationships for item in (rel["source"], rel["target"])}
    unresolved = [{"node_id": node["id"], "reason": "No relationship could be established from supplied evidence"}
                  for node in nodes if node["id"] in node_ids - connected]
    warnings = list(overview.get("missing_evidence", [])) + list(overview.get("warnings", []))
    if not resources:
        warnings.append({"type": "Rendered resources", "item": "Kubernetes resources", "reason": "No rendered Kubernetes resources were supplied", "source_file": "—"})
    graph = {"schema_version": "1.1", "incomplete": bool(warnings or not resources), "source": overview.get("source", "Rendered Helm/Kubernetes evidence"),
            "nodes": nodes, "relationships": relationships, "unresolved": unresolved, "warnings": warnings,
            "summary": {"nodes": len(nodes), "relationships": len(relationships), "unresolved": len(unresolved), "warnings": len(warnings),
                        "ports": len(overview.get("ports", [])),
                        "declared": sum(node.get("provenance") in {"DECLARED", "DECLARED_AND_OBSERVED"} for node in nodes),
                        "runtime_verified": sum(node.get("provenance") == "DECLARED_AND_OBSERVED" for node in nodes),
                        "differences": sum(node.get("provenance") == "OBSERVED" or (
                            node.get("provenance") == "DECLARED" and node.get("kind") not in {"ContainerImage", "ExternalEndpoint"}
                        ) for node in nodes)}, "ports": overview.get("ports", [])}
    from .architecture_layout import build_layouts
    graph["layouts"] = build_layouts(graph, viewport_width)
    logger.info("Architecture normalization complete: resources=%d nodes=%d relationships=%d unresolved=%d warnings=%d ports=%d",
                len(resources), len(nodes), len(relationships), len(unresolved), len(warnings), len(overview.get("ports", [])))
    return graph
