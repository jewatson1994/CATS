"""Offline, CATS-owned generic LoadBalancer capability for kind.

The provider deliberately owns only the capability bootstrap lifecycle.  It
does not accept a user supplied controller manifest and it never downloads an
image or manifest during validation.  The distribution packaging step places a
hash-verified MetalLB bundle at ``/opt/cats/validation/loadbalancer``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import logging
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping, Sequence

import yaml


LOG = logging.getLogger("cats.deployment_validation.load_balancer")
LABEL_KEY = "cats.clanhq.io/validation-infrastructure"
RUN_LABEL_KEY = "cats.clanhq.io/validation-run"
PROVIDER_NAMESPACE = "metallb-system"
POOL_NAME = "cats-validation-pool"
ADVERTISEMENT_NAME = "cats-validation-l2"
DEFAULT_BUNDLE_DIR = "/opt/cats/validation/loadbalancer"
MAX_ERROR_CHARS = 1200


@dataclass(frozen=True)
class _Image:
    name: str
    digest: str
    archive: Path
    archive_sha256: str


def _safe_text(value: Any, limit: int = MAX_ERROR_CHARS) -> str:
    """Return bounded, non-secret command evidence."""
    text = str(value or "").replace("\x00", "")
    text = re.sub(r"(?i)(password|passwd|token|secret|authorization)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", text)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    return text if len(text) <= limit else text[:limit] + "…"


def _result_code(result: Any) -> int:
    try:
        return int(getattr(result, "returncode", 1))
    except (TypeError, ValueError):
        return 1


def _result_error(result: Any) -> str:
    return _safe_text(getattr(result, "stderr", "") or getattr(result, "stdout", "") or "command failed")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_file(root: Path, value: Any) -> Path:
    relative = Path(str(value or ""))
    if not str(value) or relative.is_absolute() or ".." in relative.parts:
        raise ValueError("bundle contains an unsafe relative path")
    target = (root / relative).resolve()
    if root.resolve() not in target.parents:
        raise ValueError("bundle path escapes its trusted directory")
    return target


def _digest(value: Any, *, field: str) -> str:
    digest = str(value or "").lower()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"bundle {field} is not a valid sha256 digest")
    return digest


def _label(document: dict[str, Any], namespace: str) -> None:
    metadata = document.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("MetalLB bundle object metadata is invalid")
    labels = metadata.setdefault("labels", {})
    if not isinstance(labels, dict):
        raise ValueError("MetalLB bundle object labels are invalid")
    labels[LABEL_KEY] = "true"
    labels[RUN_LABEL_KEY] = namespace
    # The workload itself must carry the marker as well as its controller.
    template = (document.get("spec") or {}).get("template") if isinstance(document.get("spec"), Mapping) else None
    if isinstance(template, dict):
        template_metadata = template.setdefault("metadata", {})
        if not isinstance(template_metadata, dict):
            raise ValueError("MetalLB pod template metadata is invalid")
        template_labels = template_metadata.setdefault("labels", {})
        if not isinstance(template_labels, dict):
            raise ValueError("MetalLB pod template labels are invalid")
        template_labels[LABEL_KEY] = "true"
        template_labels[RUN_LABEL_KEY] = namespace


def _set_never_and_check_images(document: dict[str, Any], expected: Mapping[str, _Image]) -> set[str]:
    found: set[str] = set()
    spec = document.get("spec") if isinstance(document.get("spec"), Mapping) else {}
    template = spec.get("template") if isinstance(spec, Mapping) and isinstance(spec.get("template"), Mapping) else {}
    pod_spec = template.get("spec") if isinstance(template, Mapping) and isinstance(template.get("spec"), Mapping) else {}
    for list_name in ("initContainers", "containers", "ephemeralContainers"):
        containers = pod_spec.get(list_name, []) if isinstance(pod_spec, Mapping) else []
        if not isinstance(containers, list):
            continue
        for container in containers:
            if not isinstance(container, dict) or not container.get("image"):
                continue
            image = str(container["image"])
            base_name = image.split("@", 1)[0]
            if base_name not in expected:
                raise ValueError(f"MetalLB bundle contains an image outside the trusted inventory: {base_name}")
            found.add(base_name)
            # Archives are imported by tag, so Never avoids any registry path.
            container["image"] = expected[base_name].name
            container["imagePullPolicy"] = "Never"
    return found


def _load_bundle(config: Any, root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[_Image], dict[str, Any]]:
    bundle_dir = Path(getattr(config, "load_balancer_bundle_dir", "") or DEFAULT_BUNDLE_DIR)
    bundle_path = bundle_dir / "bundle.json"
    if not bundle_path.is_file():
        raise FileNotFoundError("bundled MetalLB inventory is unavailable")
    inventory = json.loads(bundle_path.read_text(encoding="utf-8"))
    if not isinstance(inventory, dict) or inventory.get("schema_version") != 1 or inventory.get("provider") != "metallb":
        raise ValueError("unsupported MetalLB bundle inventory")
    if str(inventory.get("version")) != "0.16.1":
        raise ValueError("MetalLB bundle version is not the pinned CATS version")
    manifest_info = inventory.get("manifest")
    if not isinstance(manifest_info, Mapping):
        raise ValueError("MetalLB bundle manifest inventory is missing")
    manifest_path = _relative_file(bundle_dir, manifest_info.get("path"))
    expected_manifest_hash = str(manifest_info.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_hash) or _sha256(manifest_path) != expected_manifest_hash:
        raise ValueError("MetalLB manifest hash verification failed")
    documents = [dict(item) for item in yaml.safe_load_all(manifest_path.read_text(encoding="utf-8")) if isinstance(item, Mapping) and item.get("kind")]
    if not documents:
        raise ValueError("MetalLB bundle manifest contains no Kubernetes objects")
    image_entries = inventory.get("images")
    if not isinstance(image_entries, list) or not image_entries:
        raise ValueError("MetalLB image inventory is missing")
    images: list[_Image] = []
    expected: dict[str, _Image] = {}
    for entry in image_entries:
        if not isinstance(entry, Mapping):
            raise ValueError("MetalLB image inventory entry is invalid")
        name = str(entry.get("name") or "")
        if not name or name in expected:
            raise ValueError("MetalLB image inventory contains an invalid or duplicate name")
        digest = _digest(entry.get("digest"), field="image digest")
        archive = _relative_file(bundle_dir, entry.get("archive"))
        archive_hash = str(entry.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", archive_hash) or _sha256(archive) != archive_hash:
            raise ValueError(f"MetalLB archive hash verification failed for {name}")
        image = _Image(name=name, digest=digest, archive=archive, archive_sha256=archive_hash)
        expected[name] = image
        images.append(image)
    found: set[str] = set()
    for document in documents:
        _label(document, PROVIDER_NAMESPACE)
        found.update(_set_never_and_check_images(document, expected))
    if found != set(expected):
        missing = sorted(set(expected) - found)
        raise ValueError(f"MetalLB manifest does not reference all trusted images: {', '.join(missing)}")
    return inventory, documents, images, {"manifest_path": str(manifest_path), "manifest_sha256": expected_manifest_hash}


def _network_name(env: Mapping[str, str]) -> str:
    return str(env.get("KIND_EXPERIMENTAL_DOCKER_NETWORK") or "").strip()


def _network_pool(result: Any) -> dict[str, Any]:
    if _result_code(result):
        raise ValueError(f"validation Docker network inspection failed: {_result_error(result)}")
    try:
        payload = json.loads(str(getattr(result, "stdout", "") or ""))
        network = payload[0] if isinstance(payload, list) and payload else payload
        config = (network.get("IPAM") or {}).get("Config") or []
        containers = network.get("Containers") or {}
    except (TypeError, ValueError, json.JSONDecodeError, AttributeError) as exc:
        raise ValueError("validation Docker network inspection returned invalid JSON") from exc
    if not isinstance(config, list) or not config:
        raise ValueError("validation Docker network has no inspectable IPv4 subnet")
    subnet = next((item.get("Subnet") for item in config if isinstance(item, Mapping) and "." in str(item.get("Subnet") or "")), None)
    if not subnet:
        raise ValueError("validation Docker network has no IPv4 subnet")
    try:
        network_range = ipaddress.ip_network(str(subnet), strict=False)
    except ValueError as exc:
        raise ValueError("validation Docker network subnet is invalid") from exc
    if network_range.version != 4:
        raise ValueError("validation Docker network is not IPv4")
    reserved: set[ipaddress.IPv4Address] = set()
    for item in config:
        if isinstance(item, Mapping) and item.get("Gateway"):
            try:
                reserved.add(ipaddress.ip_address(str(item["Gateway"])))
            except ValueError:
                pass
    if isinstance(containers, Mapping):
        for item in containers.values():
            if not isinstance(item, Mapping):
                continue
            address = str(item.get("IPv4Address") or "").split("/", 1)[0]
            if address:
                try:
                    reserved.add(ipaddress.ip_address(address))
                except ValueError:
                    pass
    # Bounded tail scan, even if Docker uses a very large private subnet.
    usable = [ipaddress.ip_address(value) for value in range(max(int(network_range.network_address) + 1, int(network_range.broadcast_address) - 64), int(network_range.broadcast_address)) if ipaddress.ip_address(value) not in reserved]
    if len(usable) < 2:
        raise ValueError("validation Docker network has no free LoadBalancer address range")
    # Prefer a deterministic tail range, but never use a gateway/node address.
    selected = usable[-min(16, len(usable)):]
    return {"addresses": [str(item) for item in selected], "range": f"{selected[0]}-{selected[-1]}", "subnet": str(network_range), "reserved": sorted(str(item) for item in reserved)}


def _resource_manifest(namespace: str, pool: Mapping[str, Any]) -> list[dict[str, Any]]:
    labels = {LABEL_KEY: "true", RUN_LABEL_KEY: namespace}
    return [
        {"apiVersion": "metallb.io/v1beta1", "kind": "IPAddressPool", "metadata": {"name": POOL_NAME, "namespace": PROVIDER_NAMESPACE, "labels": labels}, "spec": {"addresses": [address + "/32" for address in pool["addresses"]]}},
        {"apiVersion": "metallb.io/v1beta1", "kind": "L2Advertisement", "metadata": {"name": ADVERTISEMENT_NAME, "namespace": PROVIDER_NAMESPACE, "labels": labels}, "spec": {"ipAddressPools": [POOL_NAME]}},
    ]


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("MetalLB capability bootstrap timed out")
    return max(1.0, value)


class MetalLBProvider:
    """CATS-owned, per-kind-cluster MetalLB bootstrap provider."""

    def __init__(self):
        self._state: dict[str, Any] = {}

    def bootstrap(self, config: Any, command: Callable[..., Any], root: Path, kubeconfig: Path,
                  namespace: str, env: Mapping[str, str], timeout: float) -> dict[str, Any]:
        started = time.monotonic()
        deadline = started + max(1.0, float(timeout))
        evidence: dict[str, Any] = {"provider": "metallb", "version": "0.16.1", "status": "FAILED", "controller_ready": False, "warnings": [], "duration": 0, "duration_ms": 0, "resources": [], "stages": []}
        cluster = str(env.get("KIND_CLUSTER_NAME") or "")
        if not cluster:
            evidence["warnings"].append("MetalLB bootstrap skipped because the validation cluster identity is missing.")
            evidence["duration"] = 0
            return evidence
        self._state = {"namespace": PROVIDER_NAMESPACE, "cluster": cluster, "root": root, "kubeconfig": kubeconfig, "env": dict(env)}

        def stage(name: str, action: Callable[[], Any]) -> Any:
            stage_started = time.monotonic()
            try:
                value = action()
                if hasattr(value, "returncode") and _result_code(value):
                    raise ValueError(f"{name}: {_result_error(value)}")
                evidence["stages"].append({"name": name, "status": "PASS", "duration_ms": max(0, round((time.monotonic() - stage_started) * 1000))})
                return value
            except Exception as exc:
                detail = _safe_text(exc)
                evidence["stages"].append({"name": name, "status": "FAIL", "reason": detail, "duration_ms": max(0, round((time.monotonic() - stage_started) * 1000))})
                raise

        def run(argv: Sequence[str], *, label: str) -> Any:
            return command(list(argv), _remaining(deadline), None, env)

        try:
            LOG.info("LB_PROVIDER_SELECTED provider=metallb version=0.16.1 cluster=%s", cluster)
            LOG.info("LB_BOOTSTRAP_STARTED", extra={"cluster_name": cluster, "namespace": namespace})
            inventory, documents, images, manifest_evidence = stage("verify_bundle", lambda: _load_bundle(config, root))
            for document in documents:
                _label(document, namespace)
            evidence.update({"bundle": {"provider": inventory.get("provider"), "version": inventory.get("version"), **manifest_evidence}, "images": [{"name": item.name, "digest": item.digest, "archive": item.archive.name, "archive_sha256": item.archive_sha256} for item in images]})
            network = stage("inspect_network", lambda: _network_pool(run([getattr(config, "docker_binary", "docker"), "network", "inspect", _network_name(env)], label="network_inspect")))
            evidence["address_pool"] = network
            if not _network_name(env):
                raise ValueError("validation Docker network identity is missing")
            for image in images:
                loaded = stage(f"load_{image.archive.stem}", lambda image=image: run([getattr(config, "kind_binary", "kind"), "load", "image-archive", str(image.archive), "--name", cluster], label="image_load"))
                if _result_code(loaded):
                    raise ValueError(f"kind could not load the trusted MetalLB image archive {image.archive.name}: {_result_error(loaded)}")
            manifest_path = root / "cats-metallb-native.yaml"
            manifest_path.write_text("---\n".join(yaml.safe_dump(item, sort_keys=False) for item in documents), encoding="utf-8")
            applied = stage("apply_controller", lambda: run([getattr(config, "kubectl_binary", "kubectl"), "apply", "--server-side", "--kubeconfig", str(kubeconfig), "-f", str(manifest_path)], label="manifest_apply"))
            if _result_code(applied):
                raise ValueError(f"MetalLB controller manifest apply failed: {_result_error(applied)}")
            crd_wait = stage("wait_crds", lambda: run([getattr(config, "kubectl_binary", "kubectl"), "wait", "--for=condition=Established", "crd/ipaddresspools.metallb.io", "crd/l2advertisements.metallb.io", "--timeout", f"{max(1, int(_remaining(deadline)))}s", "--kubeconfig", str(kubeconfig)], label="crd_ready"))
            if _result_code(crd_wait):
                raise ValueError(f"MetalLB CRDs did not become established: {_result_error(crd_wait)}")
            pool_path = root / "cats-metallb-pool.yaml"
            pool_documents = _resource_manifest(namespace, network)
            pool_path.write_text("---\n".join(yaml.safe_dump(item, sort_keys=False) for item in pool_documents), encoding="utf-8")
            waits: list[tuple[str, str]] = []
            for document in documents:
                kind = str(document.get("kind") or "")
                name = str((document.get("metadata") or {}).get("name") or "")
                if kind in {"Deployment", "DaemonSet"} and name:
                    waits.append((kind, name))
            for kind, name in waits:
                ready = stage(f"wait_{kind.lower()}_{name}", lambda kind=kind, name=name: run([getattr(config, "kubectl_binary", "kubectl"), "rollout", "status", f"{kind.lower()}/{name}", "--namespace", PROVIDER_NAMESPACE, "--timeout", f"{max(1, int(_remaining(deadline)))}s", "--kubeconfig", str(kubeconfig)], label="controller_ready"))
                if _result_code(ready):
                    raise ValueError(f"MetalLB {kind}/{name} did not become ready: {_result_error(ready)}")
            if {kind for kind, _ in waits} != {"Deployment", "DaemonSet"}:
                raise ValueError("MetalLB bundle must contain both controller and speaker")
            # Pool admission calls the controller webhook: wait for it first.
            pool_apply = stage("apply_pool", lambda: run([getattr(config, "kubectl_binary", "kubectl"), "apply", "--kubeconfig", str(kubeconfig), "-f", str(pool_path)], label="pool_apply"))
            if _result_code(pool_apply):
                raise ValueError(f"MetalLB address pool apply failed: {_result_error(pool_apply)}")
            label_result = stage("enable_node_advertisement", lambda: run([getattr(config, "kubectl_binary", "kubectl"), "label", "node", "--all", "node.kubernetes.io/exclude-from-external-load-balancers-", "--kubeconfig", str(kubeconfig)], label="node_label"))
            if _result_code(label_result):
                raise ValueError(f"could not remove the kind node external-load-balancer exclusion: {_result_error(label_result)}")
            evidence.update({"status": "AVAILABLE", "controller_ready": True, "namespace": PROVIDER_NAMESPACE, "resources": [{"kind": item.get("kind"), "name": (item.get("metadata") or {}).get("name"), "namespace": (item.get("metadata") or {}).get("namespace") or PROVIDER_NAMESPACE, "label": f"{LABEL_KEY}=true"} for item in [*documents, *pool_documents]]})
            self._state.update({"ready": True, "pool": network, "resources": evidence["resources"]})
            LOG.info("LB_PROVIDER_READY", extra={"cluster_name": cluster, "namespace": PROVIDER_NAMESPACE})
        except TimeoutError as exc:
            evidence["status"] = "FAILED"
            evidence["warnings"].append(_safe_text(exc))
            LOG.warning("LB_BOOTSTRAP_FAILED", extra={"cluster_name": cluster, "reason": _safe_text(exc)})
        except Exception as exc:
            evidence["status"] = "FAILED"
            evidence["warnings"].append(_safe_text(exc))
            LOG.warning("LB_BOOTSTRAP_FAILED", extra={"cluster_name": cluster, "reason": _safe_text(exc)})
        finally:
            evidence["attempted"] = True
            evidence["duration_ms"] = max(1, round((time.monotonic() - started) * 1000))
            evidence["duration"] = evidence["duration_ms"] / 1000
            if evidence["status"] == "AVAILABLE":
                LOG.info("LB_BOOTSTRAP_COMPLETED", extra={"cluster_name": cluster, "duration_ms": evidence["duration_ms"]})
        return evidence

    def collect_evidence(self, config: Any, command: Callable[..., Any], kubeconfig: Path,
                         env: Mapping[str, str], timeout: float) -> dict[str, Any]:
        """Collect bounded provider-health evidence without claiming workload success."""
        started = time.monotonic()
        kubectl = getattr(config, "kubectl_binary", "kubectl")
        try:
            result = command([kubectl, "get", "deployment,daemonset,ipaddresspool,l2advertisement", "--namespace", PROVIDER_NAMESPACE, "-o", "json", "--kubeconfig", str(kubeconfig)], max(1.0, float(timeout)), None, env)
            payload = json.loads(str(getattr(result, "stdout", "") or "{}")) if _result_code(result) == 0 else {}
            items = payload.get("items", []) if isinstance(payload, Mapping) else []
            healthy = set()
            pools = []
            advertisements = []
            for item in items:
                metadata = item.get("metadata") or {}; state = item.get("status") or {}; spec = item.get("spec") or {}
                if (metadata.get("labels") or {}).get(LABEL_KEY) != "true":
                    continue
                if item.get("kind") == "IPAddressPool" and metadata.get("name") == POOL_NAME:
                    pools.extend(spec.get("addresses") or [])
                if item.get("kind") == "L2Advertisement" and metadata.get("name") == ADVERTISEMENT_NAME:
                    advertisements.extend(spec.get("ipAddressPools") or [])
                generation_seen = int(state.get("observedGeneration", 0)) >= int(metadata.get("generation", 1))
                if item.get("kind") == "Deployment" and metadata.get("name") == "controller" and generation_seen and int(state.get("availableReplicas", 0)) >= max(1, int(spec.get("replicas", 1))) and int(state.get("updatedReplicas", 0)) >= max(1, int(spec.get("replicas", 1))):
                    healthy.add("controller")
                if item.get("kind") == "DaemonSet" and metadata.get("name") == "speaker" and generation_seen and int(state.get("desiredNumberScheduled", 0)) > 0 and int(state.get("numberReady", 0)) == int(state.get("desiredNumberScheduled", 0)) and int(state.get("updatedNumberScheduled", 0)) == int(state.get("desiredNumberScheduled", 0)):
                    healthy.add("speaker")
            ready = _result_code(result) == 0 and healthy == {"controller", "speaker"} and bool(pools) and POOL_NAME in advertisements
            return {"status": "AVAILABLE" if ready else "FAILED", "controller_ready": ready, "pool_addresses": pools, "items": items, "duration_ms": max(0, round((time.monotonic() - started) * 1000)), "error": None if ready else _result_error(result) if _result_code(result) else "Controller, speaker, pool and advertisement were not all healthy/present at collection time"}
        except Exception as exc:
            return {"status": "FAILED", "controller_ready": False, "items": [], "duration_ms": max(0, round((time.monotonic() - started) * 1000)), "error": _safe_text(exc)}

    def cleanup(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        """MetalLB has no host-side resources; kind destruction owns cleanup."""
        return {"status": "DEFERRED_TO_KIND_CLUSTER_DESTROY", "host_resources": [], "idempotent": True}


def bootstrap(config: Any, command: Callable[..., Any], root: Path, kubeconfig: Path,
              namespace: str, env: Mapping[str, str], timeout: float) -> dict[str, Any]:
    """Contract entry point used by Deployment Validation integration."""
    return MetalLBProvider().bootstrap(config, command, root, kubeconfig, namespace, env, timeout)


__all__ = ["MetalLBProvider", "bootstrap", "LABEL_KEY", "PROVIDER_NAMESPACE"]
