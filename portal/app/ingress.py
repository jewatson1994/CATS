"""Offline, CATS-owned ingress-nginx capability for ephemeral kind clusters.

Validation never downloads provider artifacts.  A release build may package the
hash-verified ingress-nginx bundle described by :data:`REQUIRED_IMAGES` at
``/opt/cats/validation/ingress``.  Missing or invalid assets are reported as an
environment capability failure, not as an application finding.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping, Sequence

import yaml

from .provider_inventory import INGRESS_NGINX


LOG = logging.getLogger("cats.deployment_validation.ingress")
LABEL_KEY = "cats.clanhq.io/validation-infrastructure"
RUN_LABEL_KEY = "cats.clanhq.io/validation-run"
PROVIDER_NAME = INGRESS_NGINX.provider_id
PROVIDER_VERSION = INGRESS_NGINX.version
PROVIDER_NAMESPACE = "ingress-nginx"
CONTROLLER_NAME = "ingress-nginx-controller"
INGRESS_CLASS_NAME = "nginx"
DEFAULT_BUNDLE_DIR = str(INGRESS_NGINX.bundle_directory)
DEPENDENCIES = INGRESS_NGINX.dependencies
MAX_ERROR_CHARS = 1200

# Official image references from the pinned upstream controller-v1.15.1 cloud
# manifest.  Archives must expose the corresponding tag; validation then uses
# imagePullPolicy=Never so no registry access is possible.
REQUIRED_IMAGES = {image.reference: str(image.digest) for image in INGRESS_NGINX.images}


@dataclass(frozen=True)
class _Image:
    name: str
    digest: str
    archive: Path
    archive_sha256: str


def _safe_text(value: Any, limit: int = MAX_ERROR_CHARS) -> str:
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


def _pod_spec(document: Mapping[str, Any]) -> Mapping[str, Any]:
    kind = str(document.get("kind") or "")
    spec = document.get("spec") if isinstance(document.get("spec"), Mapping) else {}
    if kind == "Pod":
        return spec
    template = spec.get("template") if isinstance(spec.get("template"), Mapping) else {}
    return template.get("spec") if isinstance(template.get("spec"), Mapping) else {}


def _label(document: dict[str, Any], run_identity: str) -> None:
    metadata = document.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("ingress-nginx bundle object metadata is invalid")
    labels = metadata.setdefault("labels", {})
    if not isinstance(labels, dict):
        raise ValueError("ingress-nginx bundle object labels are invalid")
    labels[LABEL_KEY] = "true"
    labels[RUN_LABEL_KEY] = run_identity
    spec = document.get("spec") if isinstance(document.get("spec"), Mapping) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else None
    if isinstance(template, dict):
        template_metadata = template.setdefault("metadata", {})
        if not isinstance(template_metadata, dict):
            raise ValueError("ingress-nginx pod template metadata is invalid")
        template_labels = template_metadata.setdefault("labels", {})
        if not isinstance(template_labels, dict):
            raise ValueError("ingress-nginx pod template labels are invalid")
        template_labels[LABEL_KEY] = "true"
        template_labels[RUN_LABEL_KEY] = run_identity


def _validate_security_boundary(document: Mapping[str, Any]) -> None:
    pod = _pod_spec(document)
    if not pod:
        return
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(field):
            raise ValueError(f"ingress-nginx bundle violates the validation security boundary: {field}")
    if pod.get("hostUsers") is False:
        # User namespaces are safe, but this pin should remain reproducible and
        # must not acquire unreviewed host-level behavior between releases.
        raise ValueError("ingress-nginx bundle contains unexpected hostUsers configuration")
    for volume in pod.get("volumes", []) if isinstance(pod.get("volumes"), list) else []:
        if isinstance(volume, Mapping) and "hostPath" in volume:
            raise ValueError("ingress-nginx bundle violates the validation security boundary: hostPath")
    for list_name in ("initContainers", "containers", "ephemeralContainers"):
        containers = pod.get(list_name, []) if isinstance(pod.get(list_name), list) else []
        for container in containers:
            context = container.get("securityContext") if isinstance(container, Mapping) else {}
            if isinstance(context, Mapping) and context.get("privileged"):
                raise ValueError("ingress-nginx bundle violates the validation security boundary: privileged container")
            if isinstance(container, Mapping) and container.get("devices"):
                raise ValueError("ingress-nginx bundle violates the validation security boundary: devices")


def _set_never_and_check_images(document: dict[str, Any], expected: Mapping[str, _Image]) -> set[str]:
    found: set[str] = set()
    pod = _pod_spec(document)
    for list_name in ("initContainers", "containers", "ephemeralContainers"):
        containers = pod.get(list_name, []) if isinstance(pod.get(list_name), list) else []
        for container in containers:
            if not isinstance(container, dict) or not container.get("image"):
                continue
            image = str(container["image"])
            base_name = image.split("@", 1)[0]
            if base_name not in expected:
                raise ValueError(f"ingress-nginx bundle contains an image outside the trusted inventory: {base_name}")
            found.add(base_name)
            container["image"] = expected[base_name].name
            container["imagePullPolicy"] = "Never"
    return found


def _validate_shape(documents: Sequence[Mapping[str, Any]]) -> None:
    identities = {(str(item.get("kind") or ""), str((item.get("metadata") or {}).get("name") or "")) for item in documents}
    required = {
        ("Namespace", PROVIDER_NAMESPACE),
        ("Deployment", CONTROLLER_NAME),
        ("Service", CONTROLLER_NAME),
        ("IngressClass", INGRESS_CLASS_NAME),
        ("Job", "ingress-nginx-admission-create"),
        ("Job", "ingress-nginx-admission-patch"),
    }
    missing = sorted(required - identities)
    if missing:
        raise ValueError("ingress-nginx bundle is missing required resources: " + ", ".join(f"{kind}/{name}" for kind, name in missing))
    for document in documents:
        kind = str(document.get("kind") or "")
        metadata = document.get("metadata") if isinstance(document.get("metadata"), Mapping) else {}
        namespace = metadata.get("namespace")
        if namespace and str(namespace) != PROVIDER_NAMESPACE:
            raise ValueError(f"ingress-nginx bundle contains an unexpected namespace: {namespace}")
        if kind == "IngressClass" and (document.get("spec") or {}).get("controller") != "k8s.io/ingress-nginx":
            raise ValueError("ingress-nginx bundle contains an unexpected IngressClass controller")


def _load_bundle(config: Any) -> tuple[dict[str, Any], list[dict[str, Any]], list[_Image], dict[str, Any]]:
    bundle_dir = Path(getattr(config, "ingress_bundle_dir", "") or DEFAULT_BUNDLE_DIR)
    bundle_path = bundle_dir / "bundle.json"
    if not bundle_path.is_file():
        raise FileNotFoundError("bundled ingress-nginx offline inventory is unavailable")
    inventory = json.loads(bundle_path.read_text(encoding="utf-8"))
    if not isinstance(inventory, dict) or inventory.get("schema_version") != 1 or inventory.get("provider") != PROVIDER_NAME:
        raise ValueError("unsupported ingress-nginx bundle inventory")
    if str(inventory.get("version")) != PROVIDER_VERSION:
        raise ValueError(f"ingress-nginx bundle version is not the pinned CATS version {PROVIDER_VERSION}")
    manifest_info = inventory.get("manifest")
    if not isinstance(manifest_info, Mapping):
        raise ValueError("ingress-nginx bundle manifest inventory is missing")
    manifest_path = _relative_file(bundle_dir, manifest_info.get("path"))
    expected_manifest_hash = str(manifest_info.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_hash) or not manifest_path.is_file() or _sha256(manifest_path) != expected_manifest_hash:
        raise ValueError("ingress-nginx manifest hash verification failed")
    documents = [dict(item) for item in yaml.safe_load_all(manifest_path.read_text(encoding="utf-8")) if isinstance(item, Mapping) and item.get("kind")]
    if not documents:
        raise ValueError("ingress-nginx bundle manifest contains no Kubernetes objects")
    _validate_shape(documents)
    image_entries = inventory.get("images")
    if not isinstance(image_entries, list) or not image_entries:
        raise ValueError("ingress-nginx image inventory is missing")
    images: list[_Image] = []
    expected: dict[str, _Image] = {}
    for entry in image_entries:
        if not isinstance(entry, Mapping):
            raise ValueError("ingress-nginx image inventory entry is invalid")
        name = str(entry.get("name") or "")
        if name not in REQUIRED_IMAGES or name in expected:
            raise ValueError("ingress-nginx image inventory contains an unexpected or duplicate name")
        digest = _digest(entry.get("digest"), field="image digest")
        if digest != REQUIRED_IMAGES[name]:
            raise ValueError(f"ingress-nginx image digest does not match the pinned release for {name}")
        archive = _relative_file(bundle_dir, entry.get("archive"))
        archive_hash = str(entry.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", archive_hash) or not archive.is_file() or _sha256(archive) != archive_hash:
            raise ValueError(f"ingress-nginx archive hash verification failed for {name}")
        image = _Image(name=name, digest=digest, archive=archive, archive_sha256=archive_hash)
        expected[name] = image
        images.append(image)
    if set(expected) != set(REQUIRED_IMAGES):
        raise ValueError("ingress-nginx image inventory is incomplete")
    found: set[str] = set()
    for document in documents:
        _validate_security_boundary(document)
        found.update(_set_never_and_check_images(document, expected))
        # The upstream static manifest deletes completed admission jobs
        # immediately.  Retain them briefly so bounded readiness collection
        # cannot lose a race with the TTL controller.  Kind destruction still
        # owns final cleanup.
        if document.get("kind") == "Job":
            spec = document.setdefault("spec", {})
            if isinstance(spec, dict):
                spec["ttlSecondsAfterFinished"] = 300
    if found != set(expected):
        missing = sorted(set(expected) - found)
        raise ValueError(f"ingress-nginx manifest does not reference all trusted images: {', '.join(missing)}")
    return inventory, documents, images, {"manifest_path": str(manifest_path), "manifest_sha256": expected_manifest_hash}


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("ingress-nginx capability bootstrap timed out")
    return max(1.0, value)


class IngressNginxProvider:
    """CATS-owned ingress provider, scoped to one disposable kind cluster."""

    spec = INGRESS_NGINX
    capability = INGRESS_NGINX.capability
    provider = PROVIDER_NAME
    version = PROVIDER_VERSION
    dependencies = DEPENDENCIES

    def __init__(self) -> None:
        self._state: dict[str, Any] = {}

    def bootstrap(self, config: Any, command: Callable[..., Any], root: Path, kubeconfig: Path,
                  namespace: str, env: Mapping[str, str], timeout: float) -> dict[str, Any]:
        started = time.monotonic()
        deadline = started + max(1.0, float(timeout))
        evidence: dict[str, Any] = {
            "capability": self.capability,
            "provider": self.provider,
            "version": self.version,
            "provisioned_by_cats": True,
            "dependencies": list(self.dependencies),
            "status": "FAILED",
            "controller_ready": False,
            "ingress_class_ready": False,
            "offline_asset_unavailable": False,
            "failure_kind": None,
            "warnings": [],
            "duration": 0,
            "duration_ms": 0,
            "resources": [],
            "stages": [],
        }
        cluster = str(env.get("KIND_CLUSTER_NAME") or "")
        if not cluster:
            evidence["failure_kind"] = "CLUSTER_IDENTITY_MISSING"
            evidence["warnings"].append("Ingress bootstrap skipped because the validation cluster identity is missing.")
            return evidence
        self._state = {"cluster": cluster, "run_identity": namespace, "root": root, "kubeconfig": kubeconfig, "env": dict(env)}

        def stage(name: str, action: Callable[[], Any]) -> Any:
            stage_started = time.monotonic()
            try:
                value = action()
                if hasattr(value, "returncode") and _result_code(value):
                    raise ValueError(f"{name}: {_result_error(value)}")
                evidence["stages"].append({"name": name, "status": "PASS", "duration_ms": max(0, round((time.monotonic() - stage_started) * 1000))})
                return value
            except Exception as exc:
                evidence["stages"].append({"name": name, "status": "FAIL", "reason": _safe_text(exc), "duration_ms": max(0, round((time.monotonic() - stage_started) * 1000))})
                raise

        def run(argv: Sequence[str]) -> Any:
            return command(list(argv), _remaining(deadline), None, env)

        try:
            LOG.info("INGRESS_PROVIDER_SELECTED provider=%s version=%s cluster=%s", self.provider, self.version, cluster)
            inventory, documents, images, manifest_evidence = stage("verify_bundle", lambda: _load_bundle(config))
            for document in documents:
                _label(document, namespace)
            evidence.update({
                "bundle": {"provider": inventory.get("provider"), "version": inventory.get("version"), **manifest_evidence},
                "images": [{"name": item.name, "digest": item.digest, "archive": item.archive.name, "archive_sha256": item.archive_sha256} for item in images],
            })
            for image in images:
                stage(f"load_{image.archive.stem}", lambda image=image: run([
                    getattr(config, "kind_binary", "kind"), "load", "image-archive", str(image.archive), "--name", cluster,
                ]))
            rendered = root / "cats-ingress-nginx.yaml"
            rendered.write_text(yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8")
            stage("apply_controller", lambda: run([
                getattr(config, "kubectl_binary", "kubectl"), "apply", "--server-side", "--kubeconfig", str(kubeconfig), "-f", str(rendered),
            ]))
            for job_name in ("ingress-nginx-admission-create", "ingress-nginx-admission-patch"):
                stage(f"wait_job_{job_name}", lambda job_name=job_name: run([
                    getattr(config, "kubectl_binary", "kubectl"), "wait", "--for=condition=complete", f"job/{job_name}",
                    "--namespace", PROVIDER_NAMESPACE, "--timeout", f"{max(1, int(_remaining(deadline)))}s", "--kubeconfig", str(kubeconfig),
                ]))
            stage("wait_deployment_controller", lambda: run([
                getattr(config, "kubectl_binary", "kubectl"), "rollout", "status", f"deployment/{CONTROLLER_NAME}",
                "--namespace", PROVIDER_NAMESPACE, "--timeout", f"{max(1, int(_remaining(deadline)))}s", "--kubeconfig", str(kubeconfig),
            ]))
            observed = stage("collect_readiness", lambda: self.collect_evidence(config, command, kubeconfig, env, _remaining(deadline)))
            if observed.get("status") != "AVAILABLE":
                raise ValueError(str(observed.get("error") or "ingress-nginx readiness evidence was incomplete"))
            # Deployment readiness and a populated EndpointSlice can precede
            # the admission listener by a few seconds. Exercise the actual
            # validating webhook with a server-side dry run before Helm can
            # race it and receive a transient connection-refused failure.
            probe = root / "cats-ingress-admission-probe.yaml"
            probe.write_text(yaml.safe_dump({
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": "cats-validation-ingress-admission-probe",
                    "namespace": namespace,
                    "labels": {LABEL_KEY: "true", RUN_LABEL_KEY: namespace},
                },
                "spec": {
                    "ingressClassName": INGRESS_CLASS_NAME,
                    "rules": [{"host": "probe.invalid", "http": {"paths": [{
                        "path": "/", "pathType": "Prefix",
                        "backend": {"service": {"name": "cats-validation-nonexistent", "port": {"number": 80}}},
                    }]}}],
                },
            }, sort_keys=False), encoding="utf-8")

            def verify_admission() -> Any:
                latest = None
                for attempt in range(5):
                    latest = run([
                        getattr(config, "kubectl_binary", "kubectl"), "apply", "--dry-run=server",
                        "--kubeconfig", str(kubeconfig), "-f", str(probe),
                    ])
                    if _result_code(latest) == 0:
                        return latest
                    if attempt < 4:
                        time.sleep(min(2.0, _remaining(deadline)))
                return latest

            stage("verify_admission_webhook", verify_admission)
            resources = [{
                "kind": item.get("kind"),
                "name": (item.get("metadata") or {}).get("name"),
                "namespace": (item.get("metadata") or {}).get("namespace"),
                "label": f"{LABEL_KEY}=true",
            } for item in documents]
            evidence.update({
                "status": "AVAILABLE",
                "controller_ready": True,
                "ingress_class_ready": True,
                "namespace": PROVIDER_NAMESPACE,
                "resources": resources,
                "readiness": observed,
            })
            self._state.update({"ready": True, "resources": resources})
            LOG.info("INGRESS_PROVIDER_READY cluster=%s namespace=%s", cluster, PROVIDER_NAMESPACE)
        except FileNotFoundError as exc:
            evidence["offline_asset_unavailable"] = True
            evidence["failure_kind"] = "OFFLINE_ASSET_UNAVAILABLE"
            evidence["warnings"].append(_safe_text(exc))
        except TimeoutError as exc:
            evidence["failure_kind"] = "BOOTSTRAP_TIMEOUT"
            evidence["warnings"].append(_safe_text(exc))
        except Exception as exc:
            evidence["failure_kind"] = "BOOTSTRAP_FAILED"
            evidence["warnings"].append(_safe_text(exc))
        finally:
            evidence["attempted"] = True
            evidence["duration_ms"] = max(1, round((time.monotonic() - started) * 1000))
            evidence["duration"] = evidence["duration_ms"] / 1000
        return evidence

    def collect_evidence(self, config: Any, command: Callable[..., Any], kubeconfig: Path,
                         env: Mapping[str, str], timeout: float) -> dict[str, Any]:
        """Collect controller readiness without claiming application Ingress success."""
        started = time.monotonic()
        try:
            result = command([
                getattr(config, "kubectl_binary", "kubectl"), "get", "deployment,service,ingressclass,endpointslice",
                "--namespace", PROVIDER_NAMESPACE, "-o", "json", "--kubeconfig", str(kubeconfig),
            ], max(1.0, float(timeout)), None, env)
            if _result_code(result):
                raise ValueError(_result_error(result))
            payload = json.loads(str(getattr(result, "stdout", "") or "{}"))
            items = payload.get("items", []) if isinstance(payload, Mapping) else []
            controller_ready = False
            ingress_class_ready = False
            service_ready = False
            endpoints_ready = False
            load_balancer_ready = False
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
                labels = metadata.get("labels") if isinstance(metadata.get("labels"), Mapping) else {}
                kind = str(item.get("kind") or "")
                name = str(metadata.get("name") or "")
                spec = item.get("spec") if isinstance(item.get("spec"), Mapping) else {}
                state = item.get("status") if isinstance(item.get("status"), Mapping) else {}
                if kind == "IngressClass" and name == INGRESS_CLASS_NAME:
                    ingress_class_ready = spec.get("controller") == "k8s.io/ingress-nginx" and labels.get(LABEL_KEY) == "true"
                if kind == "EndpointSlice" and labels.get("kubernetes.io/service-name") == CONTROLLER_NAME:
                    for endpoint in item.get("endpoints", []) if isinstance(item.get("endpoints"), list) else []:
                        conditions = endpoint.get("conditions") if isinstance(endpoint, Mapping) and isinstance(endpoint.get("conditions"), Mapping) else {}
                        if conditions.get("ready") is True:
                            endpoints_ready = True
                if labels.get(LABEL_KEY) != "true":
                    continue
                if kind == "Deployment" and name == CONTROLLER_NAME:
                    desired = max(1, int(spec.get("replicas", 1)))
                    generation_seen = int(state.get("observedGeneration", 0)) >= int(metadata.get("generation", 1))
                    controller_ready = generation_seen and int(state.get("availableReplicas", 0)) >= desired and int(state.get("updatedReplicas", 0)) >= desired
                elif kind == "Service" and name == CONTROLLER_NAME:
                    service_ready = spec.get("type") == "LoadBalancer"
                    load_balancer_ready = bool(state.get("loadBalancer", {}).get("ingress")) if isinstance(state.get("loadBalancer"), Mapping) else False
            ready = controller_ready and ingress_class_ready and service_ready and endpoints_ready
            return {
                "status": "AVAILABLE" if ready else "FAILED",
                "controller_ready": controller_ready,
                "ingress_class_ready": ingress_class_ready,
                "service_ready": service_ready,
                "controller_endpoints_ready": endpoints_ready,
                "load_balancer_ready": load_balancer_ready,
                "network_reachability_tested": False,
                "items": items,
                "duration_ms": max(0, round((time.monotonic() - started) * 1000)),
                "error": None if ready else "Controller, IngressClass, LoadBalancer Service and controller endpoints were not all ready",
            }
        except Exception as exc:
            return {
                "status": "FAILED", "controller_ready": False, "ingress_class_ready": False,
                "service_ready": False, "controller_endpoints_ready": False, "load_balancer_ready": False,
                "network_reachability_tested": False, "items": [],
                "duration_ms": max(0, round((time.monotonic() - started) * 1000)), "error": _safe_text(exc),
            }

    def cleanup(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        """Provider resources exist only inside kind and die with the cluster."""
        return {"status": "DEFERRED_TO_KIND_CLUSTER_DESTROY", "host_resources": [], "idempotent": True}


def bootstrap(config: Any, command: Callable[..., Any], root: Path, kubeconfig: Path,
              namespace: str, env: Mapping[str, str], timeout: float) -> dict[str, Any]:
    """Contract entry point used by Deployment Validation integration."""
    return IngressNginxProvider().bootstrap(config, command, root, kubeconfig, namespace, env, timeout)


__all__ = [
    "IngressNginxProvider", "bootstrap", "DEPENDENCIES", "LABEL_KEY", "PROVIDER_NAME",
    "PROVIDER_NAMESPACE", "PROVIDER_VERSION", "REQUIRED_IMAGES",
]
