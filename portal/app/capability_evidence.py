"""Pure, namespace-aware runtime evidence. Never copy configuration values."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"})
LOCAL_PROVISIONERS = frozenset({"rancher.io/local-path", "kubernetes.io/no-provisioner", "microk8s.io/hostpath"})


def pod_spec(resource: Mapping) -> Mapping:
    spec = resource.get("spec") or {}
    if resource.get("kind") == "Pod":
        return spec
    if resource.get("kind") == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def _row(resource, capability, field, **extra):
    metadata = resource.get("metadata") or {}
    return {"capability": capability, "required": True, "source": "manifest",
            "source_resource": f"{resource.get('kind')}/{metadata.get('name', '')}",
            "source_namespace": metadata.get("namespace", ""), "source_field": field,
            "provider_strategy": "Kubernetes runtime evidence", "status": "PENDING",
            "provider_specific": False, "provisioned_by_cats": False, "evidence": {},
            "explanation": "Awaiting evidence from the actual workload.", **extra}


def detect_requirements(resources: Sequence[Mapping]) -> list[dict]:
    """Additional dependency and claim-template rows for existing preflight."""
    rows = []
    for resource in resources:
        kind = resource.get("kind")
        if kind == "StatefulSet":
            for claim in (resource.get("spec") or {}).get("volumeClaimTemplates") or []:
                storage_class = (claim.get("spec") or {}).get("storageClassName")
                provider_specific = bool(storage_class and storage_class not in {"standard", "local-path", "local", "microk8s-hostpath", "hostpath"})
                rows.append(_row(resource, "Storage", "spec.volumeClaimTemplates", evidence={
                    "claim_template": (claim.get("metadata") or {}).get("name"),
                    "storage_class": storage_class}, provider_specific=provider_specific,
                    status="PROVIDER_SPECIFIC" if provider_specific else "PENDING"))
        if kind not in WORKLOAD_KINDS:
            continue
        pod = pod_spec(resource)
        references = []
        for volume in pod.get("volumes") or []:
            for key, target, name_key in (("configMap", "ConfigMap", "name"), ("secret", "Secret", "secretName"), ("persistentVolumeClaim", "PersistentVolumeClaim", "claimName")):
                if volume.get(key):
                    ref = volume[key]
                    references.append((target, ref.get(name_key), bool(ref.get("optional")), "volumes"))
            for source in (volume.get("projected") or {}).get("sources") or []:
                for key, target in (("configMap", "ConfigMap"), ("secret", "Secret")):
                    if source.get(key):
                        ref = source[key]
                        references.append((target, ref.get("name"), bool(ref.get("optional")), "volumes.projected"))
        for collection in ("containers", "initContainers"):
            for container in pod.get(collection) or []:
                for entry in container.get("envFrom") or []:
                    for key, target in (("configMapRef", "ConfigMap"), ("secretRef", "Secret")):
                        if entry.get(key):
                            ref = entry[key]
                            references.append((target, ref.get("name"), bool(ref.get("optional")), collection + ".envFrom"))
                for entry in container.get("env") or []:
                    for key, target in (("configMapKeyRef", "ConfigMap"), ("secretKeyRef", "Secret")):
                        ref = (entry.get("valueFrom") or {}).get(key)
                        if ref:
                            references.append((target, ref.get("name"), bool(ref.get("optional")), collection + ".env.valueFrom"))
        for kind_name, name, optional, field in sorted(set(references), key=str):
            if name:
                rows.append(_row(resource, "Storage" if kind_name == "PersistentVolumeClaim" else "Configuration dependencies", field,
                                 required=not optional, evidence={"dependency_kind": kind_name, "dependency_name": name, "optional": optional}))
    return rows


def _identity(resource, default_namespace):
    metadata = resource.get("metadata") or {}
    return (resource.get("kind"), metadata.get("namespace") or default_namespace, metadata.get("name"))


def _owned_descendants(parent, resources):
    uid = (parent.get("metadata") or {}).get("uid")
    if not uid:
        return []
    namespace = (parent.get("metadata") or {}).get("namespace")
    owned, frontier = [], {uid}
    for _ in range(4):
        children = [item for item in resources if item not in owned and item is not parent
                    and (item.get("metadata") or {}).get("namespace") == namespace
                    and any(owner.get("uid") in frontier for owner in (item.get("metadata") or {}).get("ownerReferences") or [])]
        if not children:
            break
        owned.extend(children)
        frontier = {(item.get("metadata") or {}).get("uid") for item in children} - {None}
    return owned


def workload_evidence(resource: Mapping, resources: Sequence[Mapping]) -> dict:
    """Readiness is kind-specific; completion counts only for ordinary Jobs/Pods."""
    kind, spec, state = resource.get("kind"), resource.get("spec") or {}, resource.get("status") or {}
    metadata = resource.get("metadata") or {}
    descendants = _owned_descendants(resource, resources)
    pods = [resource] if kind == "Pod" else [item for item in descendants if item.get("kind") == "Pod"]
    generation_current = int(state.get("observedGeneration", 0)) >= int(metadata.get("generation", 1))
    ready = False
    if kind in {"Deployment", "StatefulSet"}:
        desired = int(spec.get("replicas", 1))
        ready = desired > 0 and generation_current and int(state.get("readyReplicas", 0)) >= desired
    elif kind == "DaemonSet":
        desired = int(state.get("desiredNumberScheduled", 0))
        ready = desired > 0 and generation_current and int(state.get("numberReady", 0)) >= desired
    elif kind == "Job":
        ready = any(condition.get("type") == "Complete" and condition.get("status") == "True" for condition in state.get("conditions") or [])
    elif kind == "CronJob":
        # A CronJob is verified as configured when the API accepted the exact
        # object and its job template. Do not wait indefinitely for a future
        # schedule; separately record whether an owned Job actually executed.
        ready = bool(metadata.get("uid") and isinstance(spec.get("jobTemplate"), Mapping))
    elif kind == "Pod":
        ready = state.get("phase") == "Succeeded" or any(c.get("type") == "Ready" and c.get("status") == "True" for c in state.get("conditions") or [])
    containers = []
    unhealthy = False
    for pod in pods:
        pod_state, pod_config = pod.get("status") or {}, pod.get("spec") or {}
        init_specs = {entry.get("name"): entry for entry in pod_config.get("initContainers") or []}
        for key in ("containerStatuses", "initContainerStatuses"):
            for status in pod_state.get(key) or []:
                detail = status.get("state") or {}
                terminated = detail.get("terminated") or {}
                waiting = detail.get("waiting") or {}
                is_init = key == "initContainerStatuses"
                sidecar = is_init and init_specs.get(status.get("name"), {}).get("restartPolicy") == "Always"
                healthy = bool(status.get("ready")) if not is_init or sidecar else terminated.get("exitCode") == 0
                if pod_state.get("phase") == "Succeeded" and not sidecar:
                    healthy = terminated.get("exitCode") == 0
                unhealthy |= not healthy
                containers.append({"pod": (pod.get("metadata") or {}).get("name"), "name": status.get("name"),
                                   "role": "sidecar" if sidecar else "init" if is_init else "container", "ready": healthy,
                                   "reason": waiting.get("reason") or terminated.get("reason"), "exit_code": terminated.get("exitCode")})
    scheduled = bool(pods) and all((item.get("spec") or {}).get("nodeName") for item in pods)
    evidence = {"kind": kind, "name": metadata.get("name"), "namespace": metadata.get("namespace"),
                "ready": bool(ready and not unhealthy), "scheduled": scheduled, "pod_count": len(pods), "containers": containers}
    if kind == "CronJob":
        owned_jobs = [item for item in descendants if item.get("kind") == "Job"]
        evidence.update(configured=bool(ready), execution_observed=bool(owned_jobs),
                        successful_executions=sum(1 for item in owned_jobs if workload_evidence(item, resources)["ready"]))
    return evidence


def resolve_capabilities(capabilities: list[dict], rendered: Sequence[Mapping], observed: Sequence[Mapping], namespace: str) -> list[dict]:
    """Mutate only storage/scheduling/config rows; return sanitized workload evidence.

    Call after existing legacy resolution so exact evidence replaces aggregate claims.
    Observed objects must retain metadata.uid/ownerReferences and Pod status. No values
    from ConfigMaps, Secrets, environment variables, commands or logs are returned.
    """
    index = {_identity(item, namespace): item for item in observed}
    by_kind_name = {(item.get("kind"), (item.get("metadata") or {}).get("name")): item for item in observed}
    workloads = [workload_evidence(item, observed) for item in observed if item.get("kind") in WORKLOAD_KINDS]
    for row in capabilities:
        if row.get("capability") not in {"Storage", "Node scheduling", "Configuration dependencies"} or not row.get("required"):
            continue
        if row.get("capability") == "Node scheduling" and row.get("source") == "validation-engine":
            # The validator supplies aggregate scheduler/readiness evidence;
            # there is no single manifest object to resolve here.
            continue
        kind, _, name = str(row.get("source_resource") or "").partition("/")
        ns = row.get("source_namespace") or namespace
        item = index.get((kind, ns, name))
        evidence = row.setdefault("evidence", {})
        ready = False
        if row["capability"] == "Node scheduling":
            detail = workload_evidence(item, observed) if item else {"ready": False, "scheduled": False}
            evidence.update(detail)
            ready = detail["ready"] and detail["scheduled"]
        elif row["capability"] == "Configuration dependencies":
            target = index.get((evidence.get("dependency_kind"), ns, evidence.get("dependency_name")))
            evidence.update(exists=target is not None, values_collected=False, key_presence_tested=False)
            row.update(status="AVAILABLE" if target is not None else "UNAVAILABLE", explanation="Referenced object exists; configuration values and key presence were not inspected." if target is not None else "Referenced configuration object was not observed.")
            continue
        else:
            claims = []
            if evidence.get("dependency_name"):
                claim = index.get(("PersistentVolumeClaim", ns, evidence["dependency_name"]))
                claims = [claim] if claim else []
            elif evidence.get("claim_template") and item:
                count = int((item.get("spec") or {}).get("replicas", 1))
                start = int(((item.get("spec") or {}).get("ordinals") or {}).get("start", 0))
                claims = [index.get(("PersistentVolumeClaim", ns, f"{evidence['claim_template']}-{name}-{ordinal}")) for ordinal in range(start, start + count)]
            elif kind == "PersistentVolumeClaim":
                claims = [item]
            elif kind == "StorageClass":
                # StorageClass fields live at the top level, not spec.
                source = next((obj for obj in rendered if obj.get("kind") == kind and (obj.get("metadata") or {}).get("name") == name), {})
                provisioner = (item or source).get("provisioner")
                row["provider_specific"] = bool(provisioner and provisioner not in LOCAL_PROVISIONERS)
                evidence.update(provisioner=provisioner, exists=item is not None)
                row.update(status="PROVIDER_SPECIFIC" if row["provider_specific"] else "AVAILABLE" if item else "UNAVAILABLE")
                continue
            expects_consumer = kind in WORKLOAD_KINDS or any(
                str(((volume.get("persistentVolumeClaim") or {}).get("claimName") or ""))
                in {str((claim.get("metadata") or {}).get("name") or "") for claim in claims if claim}
                for resource in rendered if resource.get("kind") in WORKLOAD_KINDS
                for volume in pod_spec(resource).get("volumes") or [] if isinstance(volume, Mapping)
            )
            claim_evidence = []
            bindings_ready = bool(claims)
            for claim in claims:
                if not claim:
                    bindings_ready = False
                    continue
                claim_metadata = claim.get("metadata") or {}
                claim_spec = claim.get("spec") or {}
                claim_name = str(claim_metadata.get("name") or "")
                volume_name = str(claim_spec.get("volumeName") or "")
                volume = by_kind_name.get(("PersistentVolume", volume_name)) if volume_name else None
                volume_spec = (volume or {}).get("spec") or {}
                volume_status = (volume or {}).get("status") or {}
                claim_ref = volume_spec.get("claimRef") if isinstance(volume_spec.get("claimRef"), Mapping) else {}
                storage_class_name = str(claim_spec.get("storageClassName") or volume_spec.get("storageClassName") or "")
                storage_class = by_kind_name.get(("StorageClass", storage_class_name)) if storage_class_name else None
                provisioner = str((storage_class or {}).get("provisioner") or "")
                exact_claim_ref = bool(
                    claim_metadata.get("uid") and claim_ref.get("uid") == claim_metadata.get("uid")
                    and str(claim_ref.get("name") or "") == claim_name
                    and str(claim_ref.get("namespace") or "") == str(ns)
                )
                local_provider = bool(storage_class and provisioner in LOCAL_PROVISIONERS)
                binding_ready = bool(
                    (claim.get("status") or {}).get("phase") == "Bound"
                    and volume and volume_status.get("phase") == "Bound"
                    and exact_claim_ref and local_provider
                )
                consumer_pods = [
                    pod for pod in observed
                    if pod.get("kind") == "Pod" and (pod.get("metadata") or {}).get("namespace") == ns
                    and any(
                        ((volume_entry.get("persistentVolumeClaim") or {}).get("claimName") == claim_name)
                        for volume_entry in (pod.get("spec") or {}).get("volumes") or []
                        if isinstance(volume_entry, Mapping)
                    )
                ]
                consumers_ready = bool(consumer_pods) and all(
                    workload_evidence(pod, observed)["ready"] and workload_evidence(pod, observed)["scheduled"]
                    for pod in consumer_pods
                )
                bindings_ready = bindings_ready and binding_ready and (consumers_ready if expects_consumer else True)
                claim_evidence.append({
                    "name": claim_name, "namespace": ns, "uid": claim_metadata.get("uid"),
                    "phase": (claim.get("status") or {}).get("phase"), "storage_class": storage_class_name,
                    "storage_provisioner": provisioner, "volume_name": volume_name,
                    "volume_phase": volume_status.get("phase"), "claim_ref_matched": exact_claim_ref,
                    "provider_correlated": local_provider,
                    "consumer_pods": [(pod.get("metadata") or {}).get("name") for pod in consumer_pods],
                    "consumers_ready": consumers_ready if expects_consumer else None,
                })
            ready = bindings_ready
            evidence["claims"] = claim_evidence
        row.update(status="PROVIDER_SPECIFIC" if row.get("provider_specific") else "VERIFIED" if ready else "UNEXERCISED",
                   explanation="The exact required resource supplied runtime evidence." if ready else "The required resource has not supplied sufficient runtime evidence.")
    return workloads
