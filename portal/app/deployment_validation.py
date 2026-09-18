"""Reusable, non-blocking kind validation for untrusted Helm artifacts.

The module has no web or database dependency. A caller supplies an artifact,
persists the structured result, and may inject a command runner for tests.
Static CATS scan state is intentionally outside this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol, Sequence

import yaml

from .capability_evidence import detect_requirements as detect_runtime_requirements, resolve_capabilities
from .capability_providers import (
    CallableProvider, CleanupStatus, ProviderContext, ProviderManager, ProviderRegistry,
)
from .ingress import IngressNginxProvider, bootstrap as bootstrap_ingress
from .load_balancer import MetalLBProvider, bootstrap as bootstrap_load_balancer
from .provider_inventory import INGRESS_NGINX, KIND_LOCAL_STORAGE, METALLB
from .trusted_ca import write_additive_bundle

logger = logging.getLogger(__name__)


class _HelmYamlLoader(yaml.SafeLoader):
    """Safe YAML loader tolerant of Helm's plain scalar ``=`` output."""


_HelmYamlLoader.yaml_implicit_resolvers = {
    key: [entry for entry in entries if entry[0] != "tag:yaml.org,2002:value"]
    for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


class ValidationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    COULD_NOT_VALIDATE = "COULD_NOT_VALIDATE"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


class FailureCategory(str, Enum):
    MISSING_CRD = "MISSING_CRD"
    MISSING_STORAGE_CLASS = "MISSING_STORAGE_CLASS"
    IMAGE_PULL_FAILURE = "IMAGE_PULL_FAILURE"
    PRIVATE_REGISTRY_UNAVAILABLE = "PRIVATE_REGISTRY_UNAVAILABLE"
    MISSING_OPERATOR = "MISSING_OPERATOR"
    UNSUPPORTED_LOAD_BALANCER = "UNSUPPORTED_LOAD_BALANCER"
    UNSUPPORTED_INGRESS = "UNSUPPORTED_INGRESS"
    EXTERNAL_DEPENDENCY = "EXTERNAL_DEPENDENCY"
    HELM_CHART_INVALID = "HELM_CHART_INVALID"
    HELM_LINT_FAILURE = "HELM_LINT_FAILURE"
    HELM_TEMPLATE_FAILURE = "HELM_TEMPLATE_FAILURE"
    HELM_INSTALL_FAILURE = "HELM_INSTALL_FAILURE"
    WORKLOAD_TIMEOUT = "WORKLOAD_TIMEOUT"
    CRASH_LOOP = "CRASH_LOOP"
    OOM_KILLED = "OOM_KILLED"
    INSUFFICIENT_CPU = "INSUFFICIENT_CPU"
    INSUFFICIENT_MEMORY = "INSUFFICIENT_MEMORY"
    UNSCHEDULABLE = "UNSCHEDULABLE"
    KIND_CREATION_FAILURE = "KIND_CREATION_FAILURE"
    SECURITY_POLICY_VIOLATION = "SECURITY_POLICY_VIOLATION"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    RESOURCE_LIMIT_ENFORCEMENT_UNAVAILABLE = "RESOURCE_LIMIT_ENFORCEMENT_UNAVAILABLE"
    CLEANUP_FAILURE = "CLEANUP_FAILURE"
    UNKNOWN = "UNKNOWN"


TERMINAL_STATUSES = {item.value for item in ValidationStatus}
PHASES = {
    "QUEUED", "PREFLIGHT", "RENDERING", "CREATING_CLUSTER", "INSTALLING",
    "WAITING_FOR_READY", "COLLECTING", "COMPARING", "CLEANING_UP", "COMPLETE",
}


@dataclass(frozen=True)
class CommandResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def __call__(self, command: Sequence[str], *, timeout: float, env: Mapping[str, str] | None = None) -> CommandResult: ...


@dataclass
class ValidationConfig:
    kind_binary: str = "kind"
    helm_binary: str = "helm"
    kubectl_binary: str = "kubectl"
    docker_binary: str = "docker"
    cluster_prefix: str = "cats-validation"
    namespace_prefix: str = "cats-validation"
    kind_node_image: str = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
    kind_node_archive: str = ""
    api_host: str = ""
    api_address: str = "127.0.0.1"
    create_timeout_seconds: float = 180
    install_timeout_seconds: float = 180
    readiness_timeout_seconds: float = 600
    collect_timeout_seconds: float = 60
    cleanup_timeout_seconds: float = 60
    total_timeout_seconds: float = 600
    max_source_bytes: int = 100 * 1024 * 1024
    max_render_bytes: int = 20 * 1024 * 1024
    max_diagnostic_chars: int = 12000
    max_events: int = 200
    max_objects: int = 500
    max_pods: int = 50
    max_cpu: str = "8"
    max_memory: str = "16Gi"
    max_storage: str = "20Gi"
    node_cpus: str = "4"
    node_memory: str = "8g"
    node_pids: int = 2048
    allow_network_egress: bool = False
    require_local_images: bool = True
    load_balancer_provider_enabled: bool = True
    load_balancer_provider_manifest: str = ""
    load_balancer_bundle_dir: str = "/opt/cats/validation/loadbalancer"
    load_balancer_timeout_seconds: float = 90
    ingress_controller_enabled: bool = True
    ingress_controller_manifest: str = ""
    ingress_bundle_dir: str = "/opt/cats/validation/ingress"
    ingress_timeout_seconds: float = 90

    @classmethod
    def from_env(cls) -> "ValidationConfig":
        def flag(name: str, default: bool) -> bool:
            return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}

        def number(name: str, default: int) -> int:
            try:
                return max(1, int(os.getenv(name, str(default))))
            except (TypeError, ValueError):
                return default

        return cls(
            cluster_prefix=os.getenv("CATS_DEPLOYMENT_CLUSTER_PREFIX", "cats-validation"),
            namespace_prefix=os.getenv("CATS_DEPLOYMENT_NAMESPACE_PREFIX", "cats-validation"),
            kind_node_image=os.getenv("CATS_DEPLOYMENT_KIND_NODE_IMAGE", cls.kind_node_image),
            kind_node_archive=os.getenv("CATS_DEPLOYMENT_KIND_NODE_ARCHIVE", ""),
            api_host=os.getenv("CATS_DEPLOYMENT_API_HOST", ""),
            api_address=os.getenv("CATS_DEPLOYMENT_API_ADDRESS", "127.0.0.1"),
            create_timeout_seconds=number("CATS_DEPLOYMENT_CREATE_TIMEOUT", 180),
            install_timeout_seconds=number("CATS_DEPLOYMENT_INSTALL_TIMEOUT", 180),
            readiness_timeout_seconds=number("CATS_DEPLOYMENT_READINESS_TIMEOUT", 600),
            collect_timeout_seconds=number("CATS_DEPLOYMENT_COLLECTION_TIMEOUT", 60),
            cleanup_timeout_seconds=number("CATS_DEPLOYMENT_CLEANUP_TIMEOUT", 60),
            total_timeout_seconds=number("CATS_DEPLOYMENT_TOTAL_TIMEOUT", 600),
            max_source_bytes=number("CATS_DEPLOYMENT_MAX_SOURCE_BYTES", 100 * 1024 * 1024),
            max_render_bytes=number("CATS_DEPLOYMENT_MAX_RENDER_BYTES", 20 * 1024 * 1024),
            max_diagnostic_chars=number("CATS_DEPLOYMENT_MAX_DIAGNOSTICS", 12000),
            max_events=number("CATS_DEPLOYMENT_MAX_EVENTS", 200),
            max_objects=number("CATS_DEPLOYMENT_MAX_OBJECTS", 500),
            max_pods=number("CATS_DEPLOYMENT_MAX_PODS", 50),
            max_cpu=os.getenv("CATS_DEPLOYMENT_MAX_CPU", "8"),
            max_memory=os.getenv("CATS_DEPLOYMENT_MAX_MEMORY", "16Gi"),
            max_storage=os.getenv("CATS_DEPLOYMENT_MAX_STORAGE", "20Gi"),
            node_cpus=os.getenv("CATS_DEPLOYMENT_NODE_CPUS", "4"),
            node_memory=os.getenv("CATS_DEPLOYMENT_NODE_MEMORY", "8g"),
            node_pids=number("CATS_DEPLOYMENT_NODE_PIDS", 2048),
            allow_network_egress=flag("CATS_DEPLOYMENT_ALLOW_NETWORK_EGRESS", False),
            require_local_images=flag("CATS_DEPLOYMENT_REQUIRE_LOCAL_IMAGES", True),
            load_balancer_provider_enabled=flag("CATS_DEPLOYMENT_LOAD_BALANCER_PROVIDER_ENABLED", True),
            load_balancer_provider_manifest=os.getenv("CATS_DEPLOYMENT_LOAD_BALANCER_PROVIDER_MANIFEST", ""),
            load_balancer_bundle_dir=os.getenv("CATS_DEPLOYMENT_LOAD_BALANCER_BUNDLE_DIR", cls.load_balancer_bundle_dir),
            load_balancer_timeout_seconds=number("CATS_DEPLOYMENT_LOAD_BALANCER_TIMEOUT", 90),
            ingress_controller_enabled=flag("CATS_DEPLOYMENT_INGRESS_CONTROLLER_ENABLED", True),
            ingress_controller_manifest=os.getenv("CATS_DEPLOYMENT_INGRESS_CONTROLLER_MANIFEST", ""),
            ingress_bundle_dir=os.getenv("CATS_DEPLOYMENT_INGRESS_BUNDLE_DIR", cls.ingress_bundle_dir),
            ingress_timeout_seconds=number("CATS_DEPLOYMENT_INGRESS_TIMEOUT", 90),
        )


@dataclass
class ValidationArtifact:
    source_files: Mapping[str, str] = field(default_factory=dict)
    values_files: Sequence[str] = field(default_factory=tuple)
    artifact_type: str = "ORIGINAL"
    declared_resources: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    job_id: str = "job"
    reference: str | None = None
    trusted_ca_certificates: Sequence[Mapping[str, object]] = field(default_factory=tuple)


ArtifactInput = ValidationArtifact


def _bounded(value: Any, limit: int) -> str:
    text = str(value or "").replace("\x00", "")
    for pattern, replacement in (
        (re.compile(r"(?i)(password|passwd|token|secret|authorization)(\s*[:=]\s*)\S+"), r"\1\2[REDACTED]"),
        (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    ):
        text = pattern.sub(replacement, text)
    return text if len(text) <= limit else text[-limit:]


def _command_environment() -> dict[str, str]:
    """Return only process settings required by Helm/kind/Docker tooling."""
    allowed = {
        "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR",
        "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE", "HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME",
        "XDG_RUNTIME_DIR",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _diagnostic_summary(completed: CommandResult) -> str:
    evidence = (completed.stderr or completed.stdout or "").encode("utf-8", errors="replace")
    digest = hashlib.sha256(evidence).hexdigest() if evidence else "none"
    return f"exit_code={completed.returncode}; output_bytes={len(evidence)}; output_sha256={digest}"


def _resource_limit_config(config: ValidationConfig) -> dict[str, dict[str, Any]]:
    return {
        "cpu": {"flag": "--cpus", "configured_limit": config.node_cpus},
        "memory": {"flag": "--memory", "configured_limit": config.node_memory},
        "pids": {"flag": "--pids-limit", "configured_limit": config.node_pids},
    }


def attempt_resource_isolation(config: ValidationConfig, container: str, runner: CommandRunner, *, timeout: float, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Apply and verify Docker limits independently, without making them a gate.

    A failed Docker update is not evidence that a limit was exceeded.  The
    disposable kind/Docker boundary remains the primary safety control, so
    unsupported or unexpectedly failed defense-in-depth controls are reported
    as BEST_EFFORT and validation proceeds.
    """
    controls = _resource_limit_config(config)
    warnings: list[str] = []
    for name, item in controls.items():
        entry = {"status": "UNAVAILABLE", "configured_limit": item["configured_limit"]}
        try:
            updated = runner([config.docker_binary, "update", item["flag"], str(item["configured_limit"]), container], timeout=timeout, env=env)
        except Exception as exc:
            entry.update(status="FAILED", reason=f"Docker limit update raised {type(exc).__name__}")
            warnings.append(f"{name}: {entry['reason']}")
            controls[name] = entry
            continue
        output = _bounded(updated.stderr or updated.stdout, 800)
        if updated.returncode:
            unsupported = any(marker in output.casefold() for marker in ("not supported", "unsupported", "not implemented", "invalid option", "unknown flag", "operation not permitted"))
            entry.update(status="UNSUPPORTED" if unsupported else "FAILED", reason=output or "Docker did not accept the configured limit")
            warnings.append(f"{name}: {entry['reason']}")
            controls[name] = entry
            continue
        # Verify the Docker HostConfig value when the runtime returns it.  A
        # runtime that cannot provide inspection evidence is unavailable, not
        # exceeded; the kind boundary still permits safe best-effort testing.
        try:
            inspected = runner([config.docker_binary, "inspect", "--format={{json .HostConfig}}", container], timeout=timeout, env=env)
            host_config = json.loads(inspected.stdout) if inspected.returncode == 0 and inspected.stdout.strip() else {}
        except Exception as exc:
            # Inspection is diagnostic only.  A Docker/runtime exception here
            # must not turn an optional guardrail into a pre-install gate.
            host_config = {}
            entry.update(reason=f"Docker limit inspection raised {type(exc).__name__}")
        expected_key = {"cpu": "NanoCpus", "memory": "Memory", "pids": "PidsLimit"}[name]
        verified = bool(host_config.get(expected_key)) if isinstance(host_config, Mapping) else False
        if verified:
            entry["status"] = "ENFORCED"
        else:
            entry.update(status="UNSUPPORTED", reason="Docker accepted the update but did not expose a verifiable HostConfig value")
            warnings.append(f"{name}: {entry['reason']}")
        controls[name] = entry
    overall = "ENFORCED" if all(item["status"] == "ENFORCED" for item in controls.values()) else "BEST_EFFORT"
    return {"overall": overall, "classification": None if overall == "ENFORCED" else FailureCategory.RESOURCE_LIMIT_ENFORCEMENT_UNAVAILABLE.value, **controls, "warnings": warnings}


def _sandbox_limit_event(value: Any) -> dict[str, Any] | None:
    """Recognize only explicit Docker node exhaustion evidence."""
    if not isinstance(value, Mapping):
        return None
    if value.get("OOMKilled") is True:
        return {"resource_type": "memory", "condition": "OOMKilled"}
    if value.get("PidsLimitExceeded") is True:
        return {"resource_type": "pids", "condition": "PidsLimitExceeded"}
    return None


def _safe_name(prefix: str, job_id: str, maximum: int) -> str:
    prefix = re.sub(r"[^a-z0-9-]", "-", prefix.lower()).strip("-") or "cats-validation"
    suffix = re.sub(r"[^a-z0-9-]", "-", str(job_id).lower()).strip("-")[-24:] or "job"
    return f"{prefix[:maximum-len(suffix)-1]}-{suffix}".strip("-")


def validation_names(config: ValidationConfig, job_id: str) -> tuple[str, str]:
    """Return the deterministic cluster and namespace owned by one run."""
    return _safe_name(config.cluster_prefix, job_id, 50), _safe_name(config.namespace_prefix, job_id, 63)


def _safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(str(value).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"Unsafe artifact path: {value}")
    return path


def materialize_sources(source_files: Mapping[str, str], destination: Path, *, max_bytes: int = 10 * 1024 * 1024, max_files: int | None = None) -> list[str]:
    """Materialize every retained source file within a bounded byte budget.

    ``max_files`` remains accepted for compatibility with older callers but
    is deliberately not a validation gate: repository cardinality is not a
    security boundary and large, legitimate Helm repositories must proceed.
    """
    total = 0
    written: list[str] = []
    destination.mkdir(parents=True, exist_ok=True)
    resolved_root = destination.resolve()
    for name, content in sorted(source_files.items()):
        path = _safe_path(name)
        data = str(content).encode("utf-8")
        total += len(data)
        if total > max_bytes:
            raise ValueError("Artifact exceeds the configured source size limit")
        target = (destination / Path(*path.parts)).resolve()
        if resolved_root not in target.parents:
            raise ValueError(f"Unsafe artifact path: {name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written.append(path.as_posix())
    if not written:
        raise ValueError("Artifact contains no Helm source files")
    return written


def _root_charts(root: Path) -> list[Path]:
    markers = sorted(root.rglob("Chart.yaml"))
    roots = []
    for marker in markers:
        if not any((parent / "Chart.yaml").is_file() for parent in marker.parent.parents if parent != root.parent):
            roots.append(marker.parent)
    return sorted(set(roots))


def _yaml_documents(text: str, limit: int) -> list[dict[str, Any]]:
    if len(text.encode("utf-8")) > limit:
        raise ValueError("Rendered manifests exceed the configured size limit")
    resources = []
    for document in re.split(r"(?m)^---\s*$", text):
        # Helm may preserve trailing tabs from chart templates. They carry no
        # YAML meaning, but PyYAML rejects them before CATS can inspect the
        # successfully rendered object. Never alter leading indentation.
        normalized = "\n".join(line.rstrip(" \t") for line in document.splitlines())
        item = yaml.load(normalized, Loader=_HelmYamlLoader)
        if not isinstance(item, Mapping) or not item.get("kind"):
            continue
        resource = dict(item)
        source = re.search(r"(?m)^#\s*Source:\s*(.+?)\s*$", normalized)
        if source and "_cats_source_file" not in resource:
            resource["_cats_source_file"] = source.group(1).strip()
        resources.append(resource)
    return resources


def _pod_spec(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    kind = str(resource.get("kind") or "")
    spec = resource.get("spec") or {}
    if kind == "Pod": return spec
    if kind == "CronJob": return ((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {})
    return ((spec.get("template") or {}).get("spec") or {})


def _service_dns_probe(
    services: Sequence[Mapping[str, Any]],
    rows: Sequence[Mapping[str, Any]],
    *,
    command: Callable[..., CommandResult],
    cfg: ValidationConfig,
    kubeconfig: Path,
    namespace: str,
    env: Mapping[str, str],
) -> dict[str, Any]:
    """Probe declared in-cluster Service names without retaining payloads.

    This is intentionally best-effort: it exercises CoreDNS from a ready
    workload when one exists, but does not turn a missing diagnostic utility
    into a deployment failure.  Names and boolean outcomes are safe to
    persist; command output is deliberately discarded.
    """
    ready_pod = next(
        (
            row for row in rows
            if row.get("kind") == "Pod"
            and (row.get("metadata") or {}).get("name")
            and any(
                str(condition.get("type")) == "Ready"
                and str(condition.get("status")).casefold() == "true"
                for condition in ((row.get("status") or {}).get("conditions") or [])
                if isinstance(condition, Mapping)
            )
        ),
        None,
    )
    if not ready_pod:
        return {"attempted": False, "resolved": False, "probe_method": "kubectl exec getent/nslookup", "services": []}
    pod_name = str((ready_pod.get("metadata") or {}).get("name"))
    pod_namespace = str((ready_pod.get("metadata") or {}).get("namespace") or namespace)
    evidence: list[dict[str, Any]] = []
    for service in services:
        metadata = service.get("metadata") if isinstance(service.get("metadata"), Mapping) else {}
        name = str(metadata.get("name") or "")
        service_namespace = str(metadata.get("namespace") or namespace)
        if not name:
            continue
        fqdn = f"{name}.{service_namespace}.svc.cluster.local"
        probe = command(
            [cfg.kubectl_binary, "exec", pod_name, "--namespace", pod_namespace, "--kubeconfig", str(kubeconfig), "--", "getent", "hosts", fqdn],
            min(10, cfg.collect_timeout_seconds),
            "dns_probe",
            env,
        )
        method = "getent"
        resolved = probe.returncode == 0 and bool((probe.stdout or "").strip())
        if not resolved:
            method = "nslookup"
            fallback = command(
                [cfg.kubectl_binary, "exec", pod_name, "--namespace", pod_namespace, "--kubeconfig", str(kubeconfig), "--", "nslookup", fqdn],
                min(10, cfg.collect_timeout_seconds),
                "dns_probe_fallback",
                env,
            )
            resolved = fallback.returncode == 0 and bool((fallback.stdout or "").strip())
        evidence.append({"service": {"name": name, "namespace": service_namespace}, "fqdn": fqdn, "resolved": resolved, "method": method})
    return {
        "attempted": bool(evidence),
        "resolved": bool(evidence) and all(item["resolved"] for item in evidence),
        "probe_method": "kubectl exec getent/nslookup",
        "services": evidence,
    }


def capability_preflight(resources: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Detect environmental requirements without turning prediction into a gate.

    The returned rows are bounded, manifest-derived evidence.  They describe
    what the artifact asks for; the validator updates availability after the
    real Kubernetes attempt.  Provider-specific capabilities are deliberately
    marked rather than silently mapped to a generic local implementation.
    """
    rows: list[dict[str, Any]] = []

    def add(capability: str, *, required: bool, source: str = "manifest", source_resource: str = "", source_namespace: str = "", source_field: str = "", strategy: str = "kind", status: str = "NOT_REQUIRED", explanation: str = "", provider_specific: bool = False) -> None:
        rows.append({"capability": capability, "required": required, "source": source,
                     "source_resource": source_resource, "source_namespace": source_namespace,
                     "source_field": source_field, "provider_strategy": strategy,
                     "status": status, "explanation": explanation,
                     "provisioned_by_cats": False, "provider_specific": provider_specific,
                     "evidence": {}})

    add("Kubernetes", required=True, source="validation-engine", strategy="kind", status="AVAILABLE", explanation="The validation engine provisions an isolated kind cluster.")
    found_lb = False; found_ingress = False; found_pvc = False; found_gpu = False; found_cloud = False
    found_workload = False; found_service = False; found_dns_dependency = False; found_rbac = False; found_network_policy = False
    found_hpa = False; found_webhook = False; found_tls = False
    storage_classes: set[str] = set(); custom_resources: list[str] = []
    built_in_groups = {"v1", "apps", "batch", "networking.k8s.io", "policy", "rbac.authorization.k8s.io", "autoscaling", "storage.k8s.io", "scheduling.k8s.io", "apiextensions.k8s.io"}
    for resource in resources:
        kind = str(resource.get("kind") or "")
        metadata = resource.get("metadata") if isinstance(resource.get("metadata"), Mapping) else {}
        name = str(metadata.get("name") or "unknown")
        # Helm applies namespace-less namespaced resources into the validation
        # release namespace.  Keep an empty source namespace so runtime
        # matching can use the actual installed namespace instead of falsely
        # assuming ``default``.
        namespace = str(metadata.get("namespace") or "")
        spec = resource.get("spec") if isinstance(resource.get("spec"), Mapping) else {}
        resource_id = f"{kind}/{name}"
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}:
            found_workload = True
        if kind == "StatefulSet" and (spec.get("volumeClaimTemplates") or []):
            # The PVCs are generated by the StatefulSet controller after
            # installation, so they are not standalone rendered objects.
            found_pvc = True
        if kind == "Service" and str(spec.get("type") or "ClusterIP") == "LoadBalancer":
            found_lb = True
            annotations = metadata.get("annotations") or {}
            lb_class = str(spec.get("loadBalancerClass") or "")
            specific = bool(lb_class) or any(any(marker in str(key).casefold() for marker in ("aws", "azure", "google", "gke", "cloud.google", "metallb", "cilium", "load-balancer")) for key in annotations)
            found_cloud = found_cloud or specific
            add("LoadBalancer", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field="spec.type", strategy="built-in MetalLB" if not lb_class else "provider-specific", status="PROVIDER_SPECIFIC" if specific else "PENDING",
                provider_specific=specific,
                explanation="Provider-specific LoadBalancer behavior is not emulated." if specific else "CATS will bootstrap its bundled generic LoadBalancer provider before installing this workload.")
            rows[-1]["generic_exercise"] = not bool(lb_class)
            rows[-1]["evidence"] = {"requested_class": lb_class, "annotation_keys": sorted(str(key) for key in annotations)}
            logger.info("LB_REQUIRED resource=%s provider_specific=%s", resource_id, specific)
        if kind == "Service":
            found_service = True
        if kind == "Ingress":
            found_ingress = True
            ingress_class = str(spec.get("ingressClassName") or ((metadata.get("annotations") or {}).get("kubernetes.io/ingress.class") if isinstance(metadata.get("annotations"), Mapping) else "") or "")
            annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), Mapping) else {}
            provider_specific = ingress_class.casefold() in {"alb", "gce", "gce-ingress", "azure-application-gateway", "agic", "nginx-internal"} or any(any(marker in str(key).casefold() for marker in ("alb", "azure", "gce", "google", "cloud")) for key in annotations)
            add("Ingress", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field="spec.ingressClassName" if spec.get("ingressClassName") else "metadata.annotations.kubernetes.io/ingress.class",
                strategy="provider-specific" if provider_specific else "configured generic controller", status="PROVIDER_SPECIFIC" if provider_specific else "PENDING",
                explanation=(f"IngressClass {ingress_class} is provider-specific and is not substituted." if provider_specific else "The workload requests Ingress; validation will use configured ephemeral controller support when available."), provider_specific=provider_specific)
            found_tls = found_tls or bool(spec.get("tls"))
        if kind == "PersistentVolumeClaim":
            found_pvc = True
            requested = str(spec.get("storageClassName") or "")
            if requested: storage_classes.add(requested)
            provider_specific = bool(requested and requested.casefold() not in {"standard", "local-path", "local", "microk8s-hostpath", "hostpath"})
            add("Storage", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field="spec.storageClassName", strategy="provider-specific" if provider_specific else "kind local-path/default",
                status="PROVIDER_SPECIFIC" if provider_specific else "PENDING",
                explanation=(f"StorageClass {requested} is provider-specific and will not be mapped to local storage." if provider_specific else "PVC storage will be observed against kind's local/default storage capability."), provider_specific=provider_specific)
        if kind == "StorageClass":
            provisioner = str(spec.get("provisioner") or "")
            provider_specific = bool(provisioner and any(marker in provisioner.casefold() for marker in ("aws", "ebs", "azure", "disk", "gce", "gcp", "filestore")))
            add("Storage", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field="provisioner", strategy="provider-specific" if provider_specific else "kind local-path/default",
                status="PROVIDER_SPECIFIC" if provider_specific else "PENDING",
                explanation=(f"StorageClass provisioner {provisioner} is provider-specific and will not be mapped to local storage." if provider_specific else "The chart supplies a generic StorageClass that Kubernetes will evaluate."), provider_specific=provider_specific)
        if kind in {"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}:
            found_rbac = True
        if kind == "NetworkPolicy":
            found_network_policy = True
        if kind == "HorizontalPodAutoscaler":
            found_hpa = True
        if kind in {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}:
            found_webhook = True
        if kind == "Secret" and (str((metadata.get("annotations") or {}).get("kubernetes.io/tls") or "") or resource.get("type") == "kubernetes.io/tls"):
            found_tls = True
        pod = _pod_spec(resource)
        for pod_field in ("nodeSelector", "affinity", "tolerations"):
            if pod.get(pod_field):
                add("Node scheduling", required=True, source_resource=resource_id, source_namespace=namespace,
                    source_field=f"{_pod_spec_path(kind)}.{pod_field}", strategy="kind node labels/taints",
                    status="PENDING", explanation="Scheduling constraints will be evaluated by Kubernetes.")
        node_selector = pod.get("nodeSelector") if isinstance(pod.get("nodeSelector"), Mapping) else {}
        if any(key in node_selector for key in ("kubernetes.io/arch", "beta.kubernetes.io/arch")):
            add("Architecture", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field=f"{_pod_spec_path(kind)}.nodeSelector", strategy="kind node architecture", status="PENDING",
                explanation="The requested node architecture will be evaluated by Kubernetes.")
        if pod.get("hostNetwork") is True:
            add("Host networking", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field=f"{_pod_spec_path(kind)}.hostNetwork", strategy="kind network", status="PENDING",
                explanation="Host networking is exercised only within the disposable kind node boundary.")
        for namespace_field in ("hostPID", "hostIPC"):
            if pod.get(namespace_field) is True:
                add("Host namespace access", required=True, source_resource=resource_id, source_namespace=namespace,
                    source_field=f"{_pod_spec_path(kind)}.{namespace_field}", strategy="security boundary", status="BLOCKED",
                    explanation=f"{namespace_field} is blocked by the CATS host-security boundary.")
        if any(isinstance(volume, Mapping) and isinstance(volume.get("hostPath"), Mapping) for volume in pod.get("volumes") or []):
            add("HostPath", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field=f"{_pod_spec_path(kind)}.volumes[].hostPath", strategy="security boundary", status="PENDING",
                explanation="HostPath requests are subject to the validation sandbox security boundary.")
        for container in [*(pod.get("initContainers") or []), *(pod.get("containers") or [])]:
            if not isinstance(container, Mapping): continue
            for env_item in container.get("env") or []:
                if not isinstance(env_item, Mapping):
                    continue
                # Detect a service FQDN without retaining the configured
                # value.  Secret/configMap-backed values are intentionally
                # not dereferenced during preflight.
                value = str(env_item.get("value") or "").casefold()
                if re.search(r"(?:[a-z0-9-]+\.)+svc(?:\.cluster\.local)?(?:\b|[:/])", value):
                    found_dns_dependency = True
            security_context = container.get("securityContext") if isinstance(container.get("securityContext"), Mapping) else {}
            if security_context.get("privileged") is True:
                add("Privileged/security-sensitive workload", required=True, source_resource=resource_id, source_namespace=namespace,
                    source_field=f"{_pod_spec_path(kind)}.containers[].securityContext.privileged", strategy="security boundary", status="BLOCKED",
                    explanation="Privileged workload access is blocked by the CATS host-security boundary.")
            requests = ((container.get("resources") or {}).get("requests") or {}) if isinstance(container.get("resources"), Mapping) else {}
            limits = ((container.get("resources") or {}).get("limits") or {}) if isinstance(container.get("resources"), Mapping) else {}
            extended = [str(key) for key in {*requests.keys(), *limits.keys()} if "/" in str(key) and str(key).casefold().split("/")[-1] not in {"cpu", "memory"}]
            for resource_name in extended:
                found_gpu = found_gpu or "gpu" in resource_name.casefold()
                add("GPU / extended resources", required=True, source_resource=resource_id, source_namespace=namespace,
                    source_field=f"{_pod_spec_path(kind)}.containers[].resources", strategy="runtime device inventory", status="UNAVAILABLE",
                    explanation=f"Requested extended resource {resource_name}; CATS will not pretend the device exists.")
        api_group = str(resource.get("apiVersion") or "").split("/", 1)[0]
        if kind == "CustomResourceDefinition":
            add("CRDs / custom resources", required=True, source_resource=resource_id, source_namespace=namespace,
                source_field="spec.group", strategy="Helm CRD installation", status="PENDING",
                explanation="The chart declares a CRD; Helm/Kubernetes will determine whether it can be installed safely.")
        if api_group and api_group not in built_in_groups and kind not in {"CustomResourceDefinition"}:
            custom_resources.append(resource_id)
            if any(marker in api_group.casefold() for marker in ("aws", "azure", "gcp", "google", "cloud")): found_cloud = True
    if not found_lb: add("LoadBalancer", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No LoadBalancer Service was rendered.")
    if not found_ingress: add("Ingress", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No Ingress resource was rendered.")
    if not found_pvc: add("Storage", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No PersistentVolumeClaim was rendered.")
    if not found_gpu: add("GPU / extended resources", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No GPU or extended device resource was requested.")
    if found_workload:
        add("Node scheduling", required=True, source="validation-engine", source_field="runtime workload scheduling", strategy="kind scheduler", status="PENDING", explanation="All rendered workloads must be scheduled and reach their kind-specific expected state.")
    if found_dns_dependency:
        add("DNS / Service Discovery", required=True, source="manifest", source_field="container.env service references", strategy="CoreDNS and in-cluster lookup", status="PENDING", explanation="A rendered workload references a Service name; validation will probe its in-cluster DNS record from a ready Pod.")
    elif found_service and found_workload:
        add("DNS / Service Discovery", required=False, source="manifest", source_field="Service names", strategy="CoreDNS and in-cluster lookup", status="AVAILABLE", explanation="Kubernetes Service records are available for in-cluster consumers; no arbitrary external DNS lookup is performed.",)
    else:
        add("DNS / Service Discovery", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No workload-to-Service DNS dependency was detected.")
    if found_rbac:
        add("ServiceAccount / RBAC", required=True, source="manifest", source_field="RBAC references", strategy="Kubernetes RBAC API", status="PENDING", explanation="Rendered ServiceAccounts, roles, and bindings will be correlated by exact names and subjects.")
    else:
        add("ServiceAccount / RBAC", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No explicit ServiceAccount or RBAC objects were rendered.")
    if found_network_policy:
        add("NetworkPolicy", required=True, source="manifest", source_field="spec.podSelector", strategy="Kubernetes policy API", status="PENDING", explanation="Policy configuration will be verified separately from traffic enforcement.")
    else:
        add("NetworkPolicy", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No NetworkPolicy was rendered by the artifact.")
    if found_hpa:
        add("HPA / Metrics API", required=True, source="manifest", source_field="spec.scaleTargetRef", strategy="autoscaling API", status="PENDING", explanation="HPA acceptance and target resolution are verified; a scale event is not required.")
    else:
        add("HPA / Metrics API", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No HorizontalPodAutoscaler was rendered.")
    if found_webhook:
        add("Admission Webhooks", required=True, source="manifest", source_field="webhooks", strategy="Kubernetes admission API", status="PENDING", explanation="Webhook configuration, referenced Service, endpoints, and structural CA material will be correlated without reading Secret values.")
    else:
        add("Admission Webhooks", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No admission webhook configuration was rendered.")
    if found_tls:
        add("TLS / Certificate dependencies", required=True, source="manifest", source_field="spec.tls", strategy="metadata-only certificate evidence", status="PENDING", explanation="TLS Secret references and certificate metadata are checked without exposing private material.")
    else:
        add("TLS / Certificate dependencies", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No TLS or certificate dependency was detected.")
    if storage_classes:
        add("StorageClass references", required=True, source="manifest", source_field="spec.storageClassName", strategy="Kubernetes storage API", status="PROVIDER_SPECIFIC" if any(row["provider_specific"] for row in rows if row["capability"] == "Storage") else "PENDING", explanation="Requested StorageClasses are retained as capability evidence.", provider_specific=any(value.casefold() not in {"standard", "local-path", "local", "microk8s-hostpath", "hostpath"} for value in storage_classes))
    if custom_resources:
        add("CRDs / custom resources", required=True, source="manifest", source_resource=custom_resources[0], source_field="apiVersion", strategy="existing CRD/operator", status="PENDING", explanation="Custom API groups will be attempted and classified from Helm/Kubernetes evidence.")
    if not found_cloud: add("Cloud/provider-specific capabilities", required=False, strategy="not required", status="NOT_REQUIRED", explanation="No obvious cloud-provider API group was rendered.")
    elif found_cloud: add("Cloud/provider-specific capabilities", required=True, strategy="provider-specific", status="UNSUPPORTED", explanation="Provider-specific resources are not emulated by generic kind validation.", provider_specific=True)
    return rows


def provision_validation_capabilities(
    requirements: list[dict[str, Any]], config: ValidationConfig, *, command: Callable[..., CommandResult],
    root: Path, kubeconfig: Path, namespace: str, env: Mapping[str, str], timeout: float,
    lifecycle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Plan and bootstrap only the offline providers required by the artifact."""
    started = time.monotonic()
    warnings: list[str] = []

    def load_balancer_hook(context: ProviderContext) -> Mapping[str, Any]:
        if not config.load_balancer_provider_enabled:
            return {
                "status": "DISABLED", "controller_ready": False, "attempted": False,
                "reason": "Built-in LoadBalancer provisioning was explicitly disabled by the administrator.",
                "warnings": ["Built-in LoadBalancer provisioning was explicitly disabled by the administrator."],
            }
        return bootstrap_load_balancer(
            config=config, command=command, root=root, kubeconfig=kubeconfig,
            namespace=namespace, env=env,
            timeout=min(context.remaining(), config.load_balancer_timeout_seconds),
        )

    def ingress_hook(context: ProviderContext) -> Mapping[str, Any]:
        if not config.ingress_controller_enabled:
            return {
                "status": "DISABLED", "controller_ready": False, "attempted": False,
                "reason": "Built-in Ingress provisioning was explicitly disabled by the administrator.",
                "warnings": ["Built-in Ingress provisioning was explicitly disabled by the administrator."],
            }
        return bootstrap_ingress(
            config=config, command=command, root=root, kubeconfig=kubeconfig,
            namespace=namespace, env=env,
            timeout=min(context.remaining(), config.ingress_timeout_seconds),
        )

    def storage_hook(context: ProviderContext) -> Mapping[str, Any]:
        observed = command(
            [config.kubectl_binary, "get", "storageclasses", "-o", "json", "--kubeconfig", str(kubeconfig)],
            min(context.remaining(), config.collect_timeout_seconds), "storage_provider_discovery", env,
        )
        if observed.returncode:
            return {"status": "FAILED", "ready": False, "reason": "StorageClass discovery failed.", "warnings": []}
        payload = _decode(observed.stdout)
        items = payload.get("items", []) if isinstance(payload, Mapping) else []
        usable: list[dict[str, Any]] = []
        cloud_markers = ("aws", "ebs", "azure", "gce", "gcp", "filestore")
        for item in items if isinstance(items, list) else []:
            metadata = item.get("metadata") if isinstance(item, Mapping) and isinstance(item.get("metadata"), Mapping) else {}
            annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), Mapping) else {}
            provisioner = str(item.get("provisioner") or "") if isinstance(item, Mapping) else ""
            is_default = any(str(annotations.get(key) or "").casefold() == "true" for key in (
                "storageclass.kubernetes.io/is-default-class", "storageclass.beta.kubernetes.io/is-default-class",
            ))
            local = not any(marker in provisioner.casefold() for marker in cloud_markers)
            if local and (is_default or str(metadata.get("name") or "").casefold() in {"standard", "local-path", "local", "hostpath"}):
                usable.append({
                    "name": metadata.get("name"), "provisioner": provisioner,
                    "default": is_default, "volume_binding_mode": item.get("volumeBindingMode"),
                })
        return {
            "status": "AVAILABLE" if usable else "FAILED", "ready": bool(usable),
            "provider": KIND_LOCAL_STORAGE.name, "version": KIND_LOCAL_STORAGE.version,
            "provisioned_by_cats": False, "storage_classes": usable,
            "reason": "" if usable else "No usable local or default StorageClass was detected.",
            "warnings": [] if usable else ["No usable local/default StorageClass was available; Helm validation continued."],
        }

    def reconciliation_hook(
        context: ProviderContext, requirement: Any, observations: Mapping[str, Any], provider_result: Any,
    ) -> Mapping[str, Any]:
        statuses = [str(item.get("status") or "UNEXERCISED") for item in observations.get("requirements", [])]
        if statuses and all(status == "VERIFIED" for status in statuses):
            status = "VERIFIED"
        elif any(status in {"FAILED", "UNAVAILABLE", "BLOCKED"} for status in statuses):
            status = "FAILED"
        elif any(status in {"UNSUPPORTED", "PROVIDER_SPECIFIC"} for status in statuses):
            status = "UNSUPPORTED"
        else:
            status = "UNEXERCISED"
        return {"status": status, "requirement_statuses": statuses,
                "verification_method": "exact artifact resource reconciliation"}

    def cleanup_hook(context: ProviderContext, provider_result: Any) -> Mapping[str, Any]:
        # All current provider resources are confined to the disposable kind
        # cluster. The caller independently verifies cluster/network deletion
        # and folds that result into each lifecycle record.
        return {"status": "COMPLETE", "strategy": "ephemeral kind cluster teardown"}

    providers = (
        CallableProvider(METALLB, load_balancer_hook, reconcile_hook=reconciliation_hook, cleanup_hook=cleanup_hook),
        CallableProvider(INGRESS_NGINX, ingress_hook, reconcile_hook=reconciliation_hook, cleanup_hook=cleanup_hook),
        CallableProvider(KIND_LOCAL_STORAGE, storage_hook, reconcile_hook=reconciliation_hook, cleanup_hook=cleanup_hook),
    )
    registry = ProviderRegistry(providers)
    eligible = [
        row for row in requirements
        if row.get("required") and row.get("capability") in {"LoadBalancer", "Ingress", "Storage"}
    ]
    plan = registry.plan(eligible)
    context = ProviderContext(
        config=config, command=command, root=root, kubeconfig=kubeconfig,
        namespace=namespace, env=env, timeout=max(1.0, float(timeout)),
    )
    manager = ProviderManager()
    provider_results = manager.bootstrap(plan, context)
    if lifecycle is not None:
        lifecycle.update(manager=manager, plan=plan, context=context, results=provider_results)
    normalized = {provider_id: item.to_evidence() for provider_id, item in provider_results.items()}
    provisioned: list[dict[str, Any]] = []
    for provider_id, evidence in normalized.items():
        raw = provider_results[provider_id].evidence
        warnings.extend(str(item) for item in raw.get("warnings", []) if item)
        if provider_results[provider_id].ready:
            provisioned.append({"capability": provider_results[provider_id].spec.capability, **evidence})

    selected_by_capability = {
        provider.spec.capability: provider.spec.provider_id for provider in plan.providers
    }
    for row in eligible:
        if row.get("provider_specific") or not row.get("generic_exercise", not row.get("provider_specific")):
            continue
        provider_id = selected_by_capability.get(str(row.get("capability") or ""))
        provider_result = provider_results.get(provider_id or "")
        if provider_result is None:
            row["status"] = "UNAVAILABLE"
            row["explanation"] = "No registered offline provider could satisfy this generic requirement."
            continue
        row.setdefault("evidence", {})["provider"] = provider_result.to_evidence()
        row["provisioned_by_cats"] = bool(provider_result.ready and provider_result.spec.provisioned_by_cats)
        row["status"] = "AVAILABLE" if provider_result.ready else "UNAVAILABLE"
        row["explanation"] = (
            f"{provider_result.spec.name} became ready; the artifact resource must still reconcile before this capability is verified."
            if provider_result.ready else
            f"{provider_result.spec.name} did not become ready; Helm validation continues with the failure retained as environment evidence."
        )

    for unresolved in plan.unresolved:
        for row in eligible:
            if (str(row.get("capability") or "") == unresolved.requirement.capability
                    and str(row.get("source_resource") or "") == unresolved.requirement.source_resource):
                row["status"] = unresolved.status
                row["explanation"] = unresolved.reason

    load_balancer = provider_results.get("metallb")
    ingress = provider_results.get("ingress-nginx")
    storage = provider_results.get("kind-local-path")
    return {
        "provisioned": provisioned,
        "providers": normalized,
        "provider_order": list(plan.provider_ids),
        "unresolved": [
            {"capability": item.requirement.capability, "source_resource": item.requirement.source_resource,
             "status": item.status, "reason": item.reason}
            for item in plan.unresolved
        ],
        "warnings": sorted(set(warnings)),
        "load_balancer": dict(load_balancer.evidence) if load_balancer else {"status": "NOT_REQUIRED", "controller_ready": False},
        "ingress": dict(ingress.evidence) if ingress else {"status": "NOT_REQUIRED", "controller_ready": False},
        "storage": dict(storage.evidence) if storage else {"status": "NOT_REQUIRED", "ready": False},
        "status": "ATTEMPTED" if plan.providers else "NOT_REQUIRED",
        "duration_ms": max(1 if plan.providers else 0, round((time.monotonic() - started) * 1000)),
    }


def reconcile_load_balancer(capability: dict[str, Any], service: Mapping[str, Any] | None,
                            endpointslices: Sequence[Mapping[str, Any]], provider: Mapping[str, Any],
                            namespace: str) -> None:
    """Verify this exact Service, not merely a running controller or any address."""
    if not capability.get("required"):
        return
    expected_namespace = str(capability.get("source_namespace") or namespace)
    expected_name = str(capability.get("source_resource") or "").partition("/")[2]
    metadata = (service or {}).get("metadata") or {}
    spec = (service or {}).get("spec") or {}
    status = (service or {}).get("status") or {}
    observed = bool(service and service.get("kind") == "Service" and metadata.get("name") == expected_name and metadata.get("namespace") == expected_namespace and spec.get("type") == "LoadBalancer")
    ingress = (status.get("loadBalancer") or {}).get("ingress") or []
    addresses = [item for item in ingress if isinstance(item, Mapping) and (item.get("ip") or item.get("hostname"))]
    slices = [item for item in endpointslices if (item.get("metadata") or {}).get("namespace") == expected_namespace
              and ((item.get("metadata") or {}).get("labels") or {}).get("kubernetes.io/service-name") == expected_name
              and any(owner.get("uid") == metadata.get("uid") and owner.get("kind") == "Service" for owner in (item.get("metadata") or {}).get("ownerReferences") or [])]
    ready_endpoints = [endpoint for item in slices for endpoint in item.get("endpoints") or []
                       if (endpoint.get("conditions") or {}).get("ready") is True and endpoint.get("addresses")]
    backend_required = bool(spec.get("selector"))
    pool = set((provider.get("address_pool") or {}).get("addresses") or [])
    assigned_by_provider = bool(addresses) and all(str(item.get("ip") or "") in pool for item in addresses)
    reconciled = observed and assigned_by_provider and bool(provider.get("controller_ready"))
    verified = reconciled and (not backend_required or bool(ready_endpoints))
    evidence = capability.setdefault("evidence", {})
    evidence.update(provider=dict(provider), service={"name": expected_name, "namespace": expected_namespace,
                    "observed": observed, "uid": metadata.get("uid"), "type": spec.get("type"),
                    "cluster_ip": spec.get("clusterIP"), "load_balancer_ingress": ingress,
                    "conditions": status.get("conditions") or []}, endpoint_slices=slices,
                    ready_backend_endpoints=len(ready_endpoints), backend_required=backend_required,
                    reconciliation="SUCCESSFUL" if reconciled else "NOT_VERIFIED",
                    connectivity={"attempted": False, "reason": "Control-plane reconciliation only; network reachability was not probed."})
    logger.info("LB_SERVICE_OBSERVED service=%s namespace=%s observed=%s", expected_name, expected_namespace, observed)
    logger.info("%s service=%s", "LB_RECONCILIATION_SUCCEEDED" if verified else "LB_RECONCILIATION_FAILED", expected_name)
    if capability.get("provider_specific"):
        capability.update(status="PROVIDER_SPECIFIC", explanation="Generic reconciliation was observed, but provider-specific behavior remains unverified." if verified else "Provider-specific LoadBalancer behavior could not be verified by the generic provider.")
    elif verified:
        capability.update(status="VERIFIED", explanation="CATS observed this Service receive a LoadBalancer address with a healthy provider and ready backends where applicable. Network reachability was not tested.")
    elif not provider.get("controller_ready"):
        capability.update(status="UNAVAILABLE", explanation="The built-in provider did not remain ready; this Service's LoadBalancer capability could not be verified.")
    else:
        capability.update(status="UNEXERCISED", explanation="The provider is available, but this Service did not demonstrate both reconciliation and ready backends where applicable.")


def reconcile_ingress(capability: dict[str, Any], resources: Sequence[Mapping[str, Any]],
                      provider: Mapping[str, Any], namespace: str,
                      events: Sequence[Mapping[str, Any]] = ()) -> None:
    """Reconcile one exact Ingress through its Services, slices, and Pods."""
    if not capability.get("required"):
        return
    expected_namespace = str(capability.get("source_namespace") or namespace)
    expected_name = str(capability.get("source_resource") or "").partition("/")[2]

    def metadata(item: Mapping[str, Any]) -> Mapping[str, Any]:
        value = item.get("metadata")
        return value if isinstance(value, Mapping) else {}

    ingress = next((
        item for item in resources
        if item.get("kind") == "Ingress"
        and metadata(item).get("name") == expected_name
        and metadata(item).get("namespace") == expected_namespace
    ), None)
    spec = ingress.get("spec") if isinstance(ingress, Mapping) and isinstance(ingress.get("spec"), Mapping) else {}
    state = ingress.get("status") if isinstance(ingress, Mapping) and isinstance(ingress.get("status"), Mapping) else {}
    addresses = (state.get("loadBalancer") or {}).get("ingress") or [] if isinstance(state.get("loadBalancer"), Mapping) else []
    address_accepted = bool(ingress and any(
        isinstance(item, Mapping) and (item.get("ip") or item.get("hostname")) for item in addresses
    ))
    ingress_uid = str(metadata(ingress).get("uid") or "") if isinstance(ingress, Mapping) else ""
    sync_events = [
        event for event in events
        if str(event.get("type") or "").casefold() == "normal"
        and str(event.get("reason") or "").casefold() == "sync"
        and str((event.get("involvedObject") or {}).get("kind") or "") == "Ingress"
        and str((event.get("involvedObject") or {}).get("name") or "") == expected_name
        and str((event.get("involvedObject") or {}).get("namespace") or expected_namespace) == expected_namespace
        and bool(ingress_uid)
        and str((event.get("involvedObject") or {}).get("uid") or "") == ingress_uid
    ]
    accepted = bool(address_accepted or sync_events)

    backend_ports: dict[str, set[tuple[str, str]]] = {}

    def add_backend(service: Mapping[str, Any]) -> None:
        name = str(service.get("name") or "")
        port = service.get("port") if isinstance(service.get("port"), Mapping) else {}
        if not name:
            return
        if port.get("name"):
            identity = ("name", str(port["name"]))
        elif port.get("number") is not None:
            identity = ("number", str(port["number"]))
        else:
            identity = ("missing", "")
        backend_ports.setdefault(name, set()).add(identity)

    default_backend = spec.get("defaultBackend") if isinstance(spec.get("defaultBackend"), Mapping) else {}
    default_service = default_backend.get("service") if isinstance(default_backend.get("service"), Mapping) else {}
    add_backend(default_service)
    for rule in spec.get("rules", []) if isinstance(spec.get("rules"), list) else []:
        http = rule.get("http") if isinstance(rule, Mapping) and isinstance(rule.get("http"), Mapping) else {}
        for path in http.get("paths", []) if isinstance(http.get("paths"), list) else []:
            backend = path.get("backend") if isinstance(path, Mapping) and isinstance(path.get("backend"), Mapping) else {}
            service = backend.get("service") if isinstance(backend.get("service"), Mapping) else {}
            add_backend(service)

    backend_names = set(backend_ports)

    services = {
        str(metadata(item).get("name")): item for item in resources
        if item.get("kind") == "Service" and metadata(item).get("namespace") == expected_namespace
        and str(metadata(item).get("name") or "") in backend_names
    }
    slices = [
        item for item in resources
        if item.get("kind") == "EndpointSlice" and metadata(item).get("namespace") == expected_namespace
    ]
    pods = [
        item for item in resources
        if item.get("kind") == "Pod" and metadata(item).get("namespace") == expected_namespace
    ]
    backend_evidence: list[dict[str, Any]] = []
    every_endpoint_ready = bool(backend_names)
    every_workload_ready = bool(backend_names)
    every_service_port_resolved = bool(backend_names)
    for service_name in sorted(backend_names):
        service = services.get(service_name)
        service_metadata = metadata(service) if isinstance(service, Mapping) else {}
        service_spec = service.get("spec") if isinstance(service, Mapping) and isinstance(service.get("spec"), Mapping) else {}
        exposed_ports = service_spec.get("ports") if isinstance(service_spec.get("ports"), list) else []
        requested_ports = backend_ports.get(service_name, set())
        matched_ports = {
            requested for requested in requested_ports
            if (requested[0] == "name" and any(str(port.get("name") or "") == requested[1] for port in exposed_ports if isinstance(port, Mapping)))
            or (requested[0] == "number" and any(str(port.get("port")) == requested[1] for port in exposed_ports if isinstance(port, Mapping)))
        }
        ports_resolved = bool(requested_ports) and matched_ports == requested_ports
        owned_slices = [
            item for item in slices
            if (metadata(item).get("labels") or {}).get("kubernetes.io/service-name") == service_name
            and any(
                owner.get("kind") == "Service" and owner.get("uid") == service_metadata.get("uid")
                for owner in metadata(item).get("ownerReferences", []) if isinstance(owner, Mapping)
            )
        ]
        ready_endpoints = [
            endpoint for item in owned_slices
            for endpoint in item.get("endpoints", []) if isinstance(item.get("endpoints"), list)
            if isinstance(endpoint, Mapping)
            and (endpoint.get("conditions") or {}).get("ready") is True
            and endpoint.get("addresses")
        ]
        target_names = {
            str((endpoint.get("targetRef") or {}).get("name")) for endpoint in ready_endpoints
            if isinstance(endpoint.get("targetRef"), Mapping) and (endpoint.get("targetRef") or {}).get("kind") == "Pod"
        }
        selector = service_spec.get("selector") if isinstance(service_spec.get("selector"), Mapping) else {}
        targeted_pods = [
            pod for pod in pods
            if str(metadata(pod).get("name")) in target_names
            or (selector and all((metadata(pod).get("labels") or {}).get(key) == value for key, value in selector.items()))
        ]
        ready_pods = [
            pod for pod in targeted_pods
            if any(
                condition.get("type") == "Ready" and str(condition.get("status")).casefold() == "true"
                for condition in ((pod.get("status") or {}).get("conditions") or []) if isinstance(condition, Mapping)
            )
        ]
        endpoint_ready = bool(ready_endpoints)
        workload_ready = bool(targeted_pods) and len(ready_pods) == len(targeted_pods)
        every_endpoint_ready = every_endpoint_ready and endpoint_ready
        every_workload_ready = every_workload_ready and workload_ready
        every_service_port_resolved = every_service_port_resolved and ports_resolved
        backend_evidence.append({
            "service": service_name, "service_uid": service_metadata.get("uid"),
            "observed": service is not None, "endpoint_slices": [metadata(item).get("name") for item in owned_slices],
            "requested_ports": [{kind: value} for kind, value in sorted(requested_ports)],
            "service_ports_resolved": ports_resolved,
            "ready_endpoints": len(ready_endpoints),
            "target_pods": [metadata(item).get("name") for item in targeted_pods],
            "ready_pods": len(ready_pods),
        })

    controller_ready = bool(provider.get("controller_ready"))
    services_resolved = bool(backend_names) and len(services) == len(backend_names) and every_service_port_resolved
    verified = controller_ready and accepted and services_resolved and every_endpoint_ready and every_workload_ready
    evidence = capability.setdefault("evidence", {})
    evidence.update({
        "ingress": {"name": expected_name, "namespace": expected_namespace, "uid": ingress_uid,
                    "observed": ingress is not None,
                    "class_name": spec.get("ingressClassName"), "load_balancer_ingress": addresses},
        "controller_ready": controller_ready,
        "ingress_accepted": accepted,
        "acceptance_method": "status_address" if address_accepted else "controller_sync_event" if sync_events else "not_observed",
        "sync_events": [{"type": item.get("type"), "reason": item.get("reason"), "count": item.get("count"),
                         "involved_object_uid": (item.get("involvedObject") or {}).get("uid")} for item in sync_events],
        "backend_services_resolved": services_resolved,
        "endpoints_ready": every_endpoint_ready,
        "workloads_ready": every_workload_ready,
        "backends": backend_evidence,
        "reconciliation": "SUCCESSFUL" if verified else "NOT_VERIFIED",
        "connectivity": {"attempted": False, "reason": "Control-plane reconciliation only; network reachability was not probed."},
    })
    if capability.get("provider_specific"):
        capability.update(status="PROVIDER_SPECIFIC", explanation="The Ingress requests provider-specific behavior that the generic local controller does not claim to verify.")
    elif verified:
        capability.update(status="VERIFIED", explanation="The exact Ingress was accepted and reconciled to existing Services, owned ready endpoints, and ready backend Pods. Network reachability was not tested.")
    elif not controller_ready:
        capability.update(status="UNAVAILABLE", explanation="The built-in Ingress controller did not remain ready; routing could not be verified.")
    else:
        capability.update(status="UNEXERCISED", explanation="The controller was ready, but this Ingress did not demonstrate complete backend and workload reconciliation.")


# These names are retained as compatibility exports for callers that imported the
# old policy constants.  Resource scope and API-group membership are not a
# sandbox boundary: the disposable kind cluster exists specifically to exercise
# those resources.  A deny-list here would turn every new Kubernetes API into a
# preflight regression, so it is intentionally empty.
CLUSTER_SCOPED_DENY: frozenset[str] = frozenset()
SUPPORTED_NAMESPACED_KINDS: frozenset[str] = frozenset()

# The node containers created by kind are themselves the disposable boundary.
# A workload may use normal Kubernetes features inside that boundary, but must
# not request a host/runtime interface that can control the Docker host or read
# host credentials.  Keep this list about boundary crossing, not generic Pod
# Security hardening (static CATS security analysis owns those findings).
SENSITIVE_HOST_PATH_PREFIXES = (
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/mnt",
    "/media",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/srv",
    "/sys",
    "/usr",
    "/var/lib/containerd",
    "/var/lib/docker",
    "/var/lib/kubelet",
    "/var/run",
)
SENSITIVE_HOST_PATHS = {"/"}
SENSITIVE_RUNTIME_SOCKET_NAMES = {
    "docker.sock",
    "containerd.sock",
    "crio.sock",
    "dockershim.sock",
}
# Only capabilities with a credible path to manipulate the kind node or its
# devices remain preflight boundary checks.  NET_ADMIN, SYS_PTRACE, and
# DAC_READ_SEARCH are useful static findings but do not by themselves grant
# access outside the workload's disposable node boundary.
SANDBOX_CAPABILITIES = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO"}
# Backward-compatible name for integrations that imported the old constant.
# Its preflight meaning is now deliberately limited to capabilities that can
# manipulate the disposable node boundary.
DANGEROUS_CAPABILITIES = SANDBOX_CAPABILITIES


def _normalise_host_path(value: Any) -> str:
    """Normalize a manifest hostPath without resolving it on the CATS host."""
    raw = str(value or "").replace("\\", "/").strip()
    if not raw.startswith("/"):
        return raw
    # Kubernetes hostPath paths are POSIX paths.  Avoid Path.resolve(): the
    # path belongs to the future kind node, not the machine running CATS.
    parts = [part for part in raw.split("/") if part not in {"", "."}]
    normalized: list[str] = []
    for part in parts:
        if part == "..":
            if normalized:
                normalized.pop()
            else:
                return "/"
        else:
            normalized.append(part)
    return "/" + "/".join(normalized) if normalized else "/"


def _sensitive_host_path(value: Any) -> bool:
    path = _normalise_host_path(value)
    return path in SENSITIVE_HOST_PATHS or any(path == prefix or path.startswith(prefix + "/") for prefix in SENSITIVE_HOST_PATH_PREFIXES)


def _runtime_socket_host_path(value: Any) -> bool:
    path = _normalise_host_path(value)
    return path.startswith(("/run/", "/var/run/", "/var/lib/docker/", "/var/lib/containerd/")) and Path(path).name in SENSITIVE_RUNTIME_SOCKET_NAMES


def sandbox_preflight(resources: Sequence[Mapping[str, Any]], config: ValidationConfig, *, namespace: str | None = None) -> list[dict[str, Any]]:
    """Classify sensitive behavior against the outer kind-container boundary."""
    decisions: list[dict[str, Any]] = []

    def record(classification: str, resource: str, reason: str, control: str, **values: Any) -> None:
        decisions.append({"classification": classification, "resource": resource, "reason": reason,
                          "isolation_control": control, **values})

    for resource in resources:
        kind = str(resource.get("kind") or "Resource"); metadata = resource.get("metadata") or {}
        name = f"{kind}/{metadata.get('name', 'unknown')}"; pod = _pod_spec(resource)
        if not pod:
            continue
        pod_path = _pod_spec_path(kind)
        if pod.get("hostNetwork") is True:
            if config.allow_network_egress:
                record("SANDBOX_BOUNDARY_VIOLATION", name,
                       "hostNetwork joins the kind-node network while external egress is enabled",
                       "Run validation on an internal per-run Docker network or disable hostNetwork.",
                       field_path=f"{pod_path}.hostNetwork", value=True)
            else:
                record("SANDBOX_SENSITIVE_ALLOWED", name,
                       "hostNetwork joins only the disposable kind-node network namespace, not the real host network",
                       "Per-run Docker bridge is internal and is not attached to the CATS application network.",
                       field_path=f"{pod_path}.hostNetwork", value=True)
        if pod.get("hostPID") is True:
            record("SANDBOX_BOUNDARY_VIOLATION", name,
                   "hostPID exposes privileged kind-node services; compromise of the Docker-privileged node is not a contained outcome",
                   "PID namespace sharing remains blocked while kind requires a privileged, unconfined outer node.",
                   field_path=f"{pod_path}.hostPID", value=True)
        if pod.get("hostIPC") is True:
            record("SANDBOX_BOUNDARY_VIOLATION", name,
                   "hostIPC can interfere with privileged node services and containment is not established",
                   "IPC namespace sharing remains blocked.", field_path=f"{pod_path}.hostIPC", value=True)
        mounts: dict[str, list[Mapping[str, Any]]] = {}
        for containers in (pod.get("initContainers") or [], pod.get("containers") or [], pod.get("ephemeralContainers") or []):
            for container in containers:
                if not isinstance(container, Mapping): continue
                for mount in container.get("volumeMounts") or []:
                    if isinstance(mount, Mapping): mounts.setdefault(str(mount.get("name") or ""), []).append(mount)
        for volume_index, volume in enumerate(pod.get("volumes") or []):
            if not isinstance(volume, Mapping) or not isinstance(volume.get("hostPath"), Mapping): continue
            host_path = volume["hostPath"]; path = _normalise_host_path(host_path.get("path")); volume_mounts = mounts.get(str(volume.get("name") or ""), [])
            read_only = bool(volume_mounts) and all(mount.get("readOnly") is True for mount in volume_mounts)
            field = f"{pod_path}.volumes[{volume_index}].hostPath.path"
            container_name = next((str(item.get("name") or "") for item in [*(pod.get("initContainers") or []), *(pod.get("containers") or []), *(pod.get("ephemeralContainers") or [])] if isinstance(item, Mapping) and any(isinstance(m, Mapping) and str(m.get("name") or "") == str(volume.get("name") or "") for m in item.get("volumeMounts") or [])), None)
            if _runtime_socket_host_path(path) or str(host_path.get("type") or "").lower() == "socket":
                record("SANDBOX_BOUNDARY_VIOLATION", name, "hostPath exposes a container runtime socket capable of node control",
                       "Runtime and Docker sockets are never mounted into validation workloads.", field_path=field, value=path, container=container_name)
            elif path in {"/proc", "/sys"} and read_only:
                record("SANDBOX_SENSITIVE_ALLOWED", name,
                       f"read-only {path} references the disposable kind node, not the real host filesystem",
                       "The mount must remain read-only and the outer node has no CATS data or credential mounts.",
                       field_path=field, value=path, container=container_name)
            elif _sensitive_host_path(path):
                detail = "root hostPath includes the kind-node runtime socket and control-plane credentials" if path == "/" else "the requested node path is not proven safe at the outer boundary"
                record("SANDBOX_BOUNDARY_VIOLATION", name, detail,
                       "Only explicitly proven read-only node telemetry paths are permitted.", field_path=field, value=path, container=container_name)
        for list_name, containers in (("initContainers", pod.get("initContainers") or []), ("containers", pod.get("containers") or []), ("ephemeralContainers", pod.get("ephemeralContainers") or [])):
            for index, container in enumerate(containers):
                if not isinstance(container, Mapping): continue
                security = container.get("securityContext") or {}; container_name = str(container.get("name") or "") or None
                base = f"{pod_path}.{list_name}[{index}]"
                if security.get("privileged") is True:
                    record("SANDBOX_BOUNDARY_VIOLATION", name,
                           "a privileged pod could take over the kind node, whose outer container is privileged",
                           "Privileged workload containers remain blocked until the outer node can run without a privileged Docker boundary.",
                           field_path=f"{base}.securityContext.privileged", value=True, container=container_name)
                added = {str(value).upper() for value in ((security.get("capabilities") or {}).get("add") or [])}
                if added & SANDBOX_CAPABILITIES:
                    record("SANDBOX_BOUNDARY_VIOLATION", name,
                           f"capabilities can manipulate the privileged kind-node boundary: {', '.join(sorted(added & SANDBOX_CAPABILITIES))}",
                           "Outer-boundary manipulation capabilities remain blocked.", field_path=f"{base}.securityContext.capabilities.add", value=sorted(added & SANDBOX_CAPABILITIES), container=container_name)
                if container.get("volumeDevices"):
                    record("SANDBOX_BOUNDARY_VIOLATION", name, "device mounts can expose devices available to the privileged kind node",
                           "Raw device mounts remain blocked.", field_path=f"{base}.volumeDevices", value=container.get("volumeDevices"), container=container_name)
    return decisions


def security_preflight(resources: Sequence[Mapping[str, Any]], config: ValidationConfig, *, namespace: str | None = None) -> list[dict[str, Any]]:
    """Check only requests that can cross the disposable kind boundary.

    API kind, API group, resource scope, explicit namespace, Helm hooks, host
    ports, and image pull policy are deliberately not policy gates. They are
    normal Kubernetes behavior and should be exercised by kind; incompatibility
    is reported from Helm/Kubernetes/runtime evidence instead. The remaining
    checks protect the Docker host, kind node control plane, and host devices.
    """
    failures: list[dict[str, Any]] = []
    if len(resources) > config.max_objects:
        failures.append({"resource": "Chart", "reason": f"object count {len(resources)} exceeds limit {config.max_objects}", "category": "RESOURCE_GOVERNANCE"})
    pod_count = 0
    for resource in resources:
        kind = str(resource.get("kind") or "Resource"); metadata = resource.get("metadata") or {}; name = f"{kind}/{metadata.get('name', 'unknown')}"
        spec = resource.get("spec") or {}
        try:
            if kind in {"Deployment", "StatefulSet", "ReplicaSet", "ReplicationController"}: pod_count += max(0, int(spec.get("replicas", 1) or 0))
            elif kind == "Job": pod_count += max(1, int(spec.get("parallelism", 1) or 1))
            elif kind == "CronJob": pod_count += max(1, int((((spec.get("jobTemplate") or {}).get("spec") or {}).get("parallelism", 1)) or 1))
            elif kind in {"Pod", "DaemonSet"}: pod_count += 1
        except (TypeError, ValueError, OverflowError):
            failures.append({"resource": name, "reason": "invalid replica or parallelism count is prohibited", "category": "RESOURCE_GOVERNANCE"}); pod_count = max(pod_count, config.max_pods + 1)
        pod = _pod_spec(resource)
        if not pod: continue
    if pod_count > config.max_pods: failures.append({"resource": "Chart", "reason": f"requested pods {pod_count} exceeds limit {config.max_pods}", "category": "RESOURCE_GOVERNANCE"})
    failures.extend(dict(decision) for decision in sandbox_preflight(resources, config, namespace=namespace)
                    if decision["classification"] == "SANDBOX_BOUNDARY_VIOLATION")
    return failures


_POLICY_RULES: tuple[tuple[str, str, str], ...] = (
    ("OBJECT_COUNT_LIMIT", "Object count limit", "object count"),
    ("INVALID_REPLICA_COUNT", "Invalid replica count", "invalid replica or parallelism"),
    ("VALIDATION_RUNTIME_SOCKET_ACCESS", "Validation runtime socket access", "container runtime socket"),
    ("SENSITIVE_HOST_PATH_ACCESS", "Sensitive host path access", "sensitive hostPath"),
    ("PRIVILEGED_CONTAINER", "Privileged container", "privileged container"),
    ("SANDBOX_SENSITIVE_CAPABILITY", "Sandbox-sensitive Linux capability", "sandbox-sensitive capabilities"),
    ("DEVICE_MOUNT", "Device mount", "device mounts"),
    ("POD_COUNT_LIMIT", "Pod count limit", "requested pods"),
)


def _policy_rule(reason: str) -> tuple[str, str]:
    text = str(reason).lower()
    if "hostnetwork" in text or "hostpid" in text or "hostipc" in text:
        return "HOST_NAMESPACE_ACCESS", "Host namespace access"
    for rule_id, rule_name, marker in _POLICY_RULES:
        if marker.lower() in text:
            return rule_id, rule_name
    return "SECURITY_POLICY", "Deployment Validation security policy"


def _policy_path_value(resource: Mapping[str, Any], path: str) -> Any:
    current: Any = resource
    for part in path.split(".") if path else ():
        match = re.fullmatch(r"([^\[]+)(?:\[(\d+)\])?", part)
        if not match:
            return None
        key, index = match.groups()
        if isinstance(current, Mapping):
            current = current.get(key)
        else:
            return None
        if index is not None:
            if not isinstance(current, list) or int(index) >= len(current):
                return None
            current = current[int(index)]
    return current


def _policy_source(resource: Mapping[str, Any], field_path: str) -> dict[str, Any]:
    """Return only provenance explicitly retained by the scanner."""
    source: dict[str, Any] = {}
    provenance = resource.get("_cats_chart_provenance") if isinstance(resource.get("_cats_chart_provenance"), Mapping) else {}
    template = (resource.get("_cats_source_file") or resource.get("source_file") or resource.get("source_path")
                or resource.get("template") or provenance.get("yaml_path") or provenance.get("source_file"))
    if template:
        source["template"] = str(template)
    line = resource.get("_cats_source_line") or resource.get("source_line") or provenance.get("line")
    if isinstance(line, int) and line > 0:
        source["line"] = line
    mappings = resource.get("_cats_source_mappings")
    if isinstance(mappings, list):
        matches = [item for item in mappings if isinstance(item, Mapping) and item.get("values_key") and (not item.get("field_path") or str(item.get("field_path")) == field_path)]
        if len(matches) == 1:
            source["value_path"] = str(matches[0]["values_key"])
            if matches[0].get("values_file"):
                source["values_file"] = str(matches[0]["values_file"])
    return source


def _safe_policy_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (Mapping, list, tuple)):
        try:
            return _bounded(json.dumps(value, sort_keys=True, default=str), 500)
        except (TypeError, ValueError):
            return _bounded(value, 500)
    return _bounded(value, 500)


def security_policy_violation_evidence(resources: Sequence[Mapping[str, Any]], violations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Expand legacy preflight rows into bounded, machine-readable evidence.

    The policy checks remain in :func:`security_preflight`; this adapter adds
    attribution without trusting arbitrary manifest annotations as provenance.
    """
    by_resource = {f"{resource.get('kind')}/{(resource.get('metadata') or {}).get('name', 'unknown')}": resource for resource in resources}
    evidence: list[dict[str, Any]] = []
    for violation in violations:
        reason = str(violation.get("reason") or "Policy violation")
        resource_id = str(violation.get("resource") or "Chart")
        resource = by_resource.get(resource_id, {})
        metadata = resource.get("metadata") if isinstance(resource.get("metadata"), Mapping) else {}
        kind = str(resource.get("kind") or "") or None
        name = str(metadata.get("name") or "") or None
        namespace = str(metadata.get("namespace") or "") or None
        rule_id, rule_name = _policy_rule(reason)
        # New preflight rows carry the exact field/container that triggered the
        # boundary check.  Continue deriving these values for old callers and
        # historical records that only contain resource + reason.
        field_path = str(violation.get("field_path") or "")
        container_name = str(violation.get("container") or "")
        if not field_path and resource_id == "Chart":
            field_path = "chart.object_count" if reason.startswith("object count") else "chart.pod_count"
        elif not field_path and "foreign namespace" in reason:
            field_path = "metadata.namespace"
        elif not field_path and ("hostNetwork" in reason or "hostPID" in reason or "hostIPC" in reason):
            field_path = f"{_pod_spec_path(kind)}.{next(key for key in ('hostNetwork', 'hostPID', 'hostIPC') if key in reason)}"
        elif not field_path and "hostAliases" in reason:
            field_path = f"{_pod_spec_path(kind)}.hostAliases"
        elif not field_path and "hostPath" in reason:
            field_path = f"{_pod_spec_path(kind)}.volumes[].hostPath"
        elif not field_path and ("imagePullPolicy" in reason or "container image" in reason or "privileged" in reason or "capabilities" in reason or "hostPort" in reason or "device mounts" in reason):
            pod_path = _pod_spec_path(kind)
            pod = _pod_spec(resource)
            container_lists = (("initContainers", pod.get("initContainers") or []), ("containers", pod.get("containers") or []), ("ephemeralContainers", pod.get("ephemeralContainers") or [])) if isinstance(pod, Mapping) else ()
            for list_name, candidates in container_lists:
                for list_index, candidate in enumerate(candidates):
                    if not isinstance(candidate, Mapping):
                        continue
                    security = candidate.get("securityContext") if isinstance(candidate.get("securityContext"), Mapping) else {}
                    matches = (
                        ("container image" in reason.lower() and (str(candidate.get("image") or "").startswith("-") or any(character in str(candidate.get("image") or "") for character in ("\r", "\n", "\x00")))),
                        ("privileged" in reason.lower() and security.get("privileged") is True),
                        ("capabilities" in reason.lower() and security.get("capabilities")),
                        ("hostport" in reason.lower() and any(isinstance(port, Mapping) and port.get("hostPort") for port in candidate.get("ports") or [])),
                        ("device mounts" in reason.lower() and candidate.get("volumeDevices")),
                        ("imagepullpolicy" in reason.lower() and str(candidate.get("imagePullPolicy") or "") == "Always"),
                    )
                    if any(matches):
                        container_name = str(candidate.get("name") or "")
                        leaf = "image" if "image" in reason.lower() else "securityContext"
                        if "capabilities" in reason.lower(): leaf = "securityContext.capabilities.add"
                        elif "hostport" in reason.lower(): leaf = "ports[].hostPort"
                        elif "device mounts" in reason.lower(): leaf = "volumeDevices"
                        elif "imagepullpolicy" in reason.lower(): leaf = "imagePullPolicy"
                        field_path = f"{pod_path}.{list_name}[{list_index}].{leaf}"
                        break
                if field_path:
                    break
        if not field_path:
            field_path = "metadata" if kind else "chart"
        value = violation.get("value") if "value" in violation else (_policy_path_value(resource, field_path.replace("[]", "[0]")) if resource else None)
        if resource_id == "Chart":
            count_match = re.search(r"(?:count|pods)\s+(\d+)", reason)
            if count_match:
                value = int(count_match.group(1))
        row: dict[str, Any] = {"rule_id": rule_id, "rule_name": rule_name, "reason": reason,
                               "resource": resource_id, "kind": kind, "name": name, "namespace": namespace,
                               "container": container_name or None, "field_path": field_path,
                               "value": _safe_policy_value(value)}
        if violation.get("classification"):
            row["classification"] = str(violation["classification"])
        if violation.get("isolation_control"):
            row["isolation_control"] = _bounded(violation["isolation_control"], 500)
        source = _policy_source(resource, field_path) if resource else {}
        if source:
            row["source"] = source
            if source.get("template"): row["source_template"] = source["template"]
            if source.get("line"): row["source_line"] = source["line"]
            if source.get("value_path"): row["source_value_path"] = source["value_path"]
        evidence.append(row)
    return evidence


def _pod_spec_path(kind: str | None) -> str:
    if kind == "Pod": return "spec"
    if kind == "CronJob": return "spec.jobTemplate.spec.template.spec"
    return "spec.template.spec"


def _merge_rendered_provenance(rendered: list[dict[str, Any]], declared: Sequence[Mapping[str, Any]]) -> None:
    """Carry scanner-owned provenance onto the exact Helm-rendered object."""
    declared_by_identity = {}
    for item in declared:
        if not isinstance(item, Mapping):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
        key = (str(item.get("kind") or ""), str(metadata.get("namespace") or ""), str(metadata.get("name") or ""))
        if key[0] and key[2]:
            declared_by_identity[key] = item
    for item in rendered:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
        key = (str(item.get("kind") or ""), str(metadata.get("namespace") or ""), str(metadata.get("name") or ""))
        source = declared_by_identity.get(key) or declared_by_identity.get((key[0], "", key[2]))
        if not source:
            continue
        for field in ("_cats_source_file", "_cats_source_line", "_cats_source_mappings", "_cats_chart_provenance"):
            if field not in item and field in source:
                item[field] = source[field]


def classify_failure(message: str, fallback: FailureCategory = FailureCategory.UNKNOWN) -> str:
    text = str(message or "").lower()
    if "no matches for kind" in text or "ensure crds are installed" in text: return FailureCategory.MISSING_CRD.value
    if "storageclass" in text and ("not found" in text or "does not exist" in text): return FailureCategory.MISSING_STORAGE_CLASS.value
    if "unauthorized" in text and ("registry" in text or "image" in text): return FailureCategory.PRIVATE_REGISTRY_UNAVAILABLE.value
    if any(value in text for value in ("imagepullbackoff", "errimagepull", "failed to pull image", "pull access denied")): return FailureCategory.IMAGE_PULL_FAILURE.value
    if "insufficient cpu" in text: return FailureCategory.INSUFFICIENT_CPU.value
    if "insufficient memory" in text: return FailureCategory.INSUFFICIENT_MEMORY.value
    if "oomkilled" in text or "out of memory" in text: return FailureCategory.OOM_KILLED.value
    if "crashloopbackoff" in text or "back-off restarting failed container" in text: return FailureCategory.CRASH_LOOP.value
    if "unschedulable" in text or "failedscheduling" in text or "insufficient cpu" in text or "insufficient memory" in text: return FailureCategory.UNSCHEDULABLE.value
    if "ingress" in text and ("pending" in text or "unsupported" in text or "controller" in text): return FailureCategory.UNSUPPORTED_INGRESS.value
    if "loadbalancer" in text and ("pending" in text or "unsupported" in text): return FailureCategory.UNSUPPORTED_LOAD_BALANCER.value
    if "operator" in text and ("not found" in text or "missing" in text): return FailureCategory.MISSING_OPERATOR.value
    if "timed out" in text or "timeout" in text or "deadline exceeded" in text: return FailureCategory.WORKLOAD_TIMEOUT.value
    return fallback.value


CLUSTER_SCOPED_KINDS = {
    "Namespace", "Node", "PersistentVolume", "ClusterRole", "ClusterRoleBinding",
    "CustomResourceDefinition", "IngressClass", "StorageClass", "PriorityClass",
    "RuntimeClass", "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
}


def canonical_resource_identity(resource: Mapping[str, Any], default_namespace: str = "default") -> tuple[str, str, str, str]:
    """Return Kubernetes' stable group/kind/namespace/name object identity."""
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), Mapping) else {}
    api_version = str(resource.get("apiVersion") or "")
    kind = str(resource.get("kind") or "")
    inferred_groups = {
        "Deployment": "apps", "StatefulSet": "apps", "DaemonSet": "apps", "ReplicaSet": "apps", "ControllerRevision": "apps",
        "Ingress": "networking.k8s.io", "NetworkPolicy": "networking.k8s.io", "IngressClass": "networking.k8s.io",
        "Job": "batch", "CronJob": "batch", "HorizontalPodAutoscaler": "autoscaling",
        "Role": "rbac.authorization.k8s.io", "RoleBinding": "rbac.authorization.k8s.io", "ClusterRole": "rbac.authorization.k8s.io", "ClusterRoleBinding": "rbac.authorization.k8s.io",
    }
    group = str(resource.get("group") or (api_version.split("/", 1)[0] if "/" in api_version else inferred_groups.get(kind, "")))
    name = str(resource.get("name") or metadata.get("name") or "")
    explicit_namespace = resource.get("namespace") if "namespace" in resource else metadata.get("namespace")
    namespace = "" if kind in CLUSTER_SCOPED_KINDS else str(explicit_namespace or default_namespace)
    return group, kind, namespace, name


def _identity(resource: Mapping[str, Any], default_namespace: str = "default") -> str:
    _, kind, namespace, name = canonical_resource_identity(resource, default_namespace)
    return f"{kind}/{namespace or 'cluster'}/{name}"


def _resource_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping) and isinstance(value.get("items"), list): return [dict(item) for item in value["items"] if isinstance(item, Mapping)]
    return [dict(item) for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _ready(resources: Sequence[Mapping[str, Any]], events: Sequence[Mapping[str, Any]]) -> tuple[dict, dict, list]:
    summary: dict[str, Any] = {"deployments": {"ready": 0, "expected": 0}, "statefulsets": {"ready": 0, "expected": 0}, "daemonsets": {"ready": 0, "expected": 0}, "pods": {"ready": 0, "expected": 0}, "jobs": {"ready": 0, "expected": 0}, "pvcs": {"bound": 0, "expected": 0}, "services": 0, "ingresses": 0, "cronjobs": 0, "configmaps": 0, "secrets": 0}
    conditions = {"crashloopbackoff": 0, "imagepullbackoff": 0, "oomkilled": 0, "pending_pods": 0, "unschedulable": 0, "insufficient_cpu": 0, "insufficient_memory": 0, "failed_jobs": 0, "probe_failures": 0, "unsupported_load_balancer": 0, "unsupported_ingress": 0}; unhealthy: list[dict[str, str]] = []
    for resource in resources:
        kind = str(resource.get("kind") or ""); spec = resource.get("spec") or {}; status = resource.get("status") or {}; name = _identity(resource)
        if kind in {"Deployment", "StatefulSet"}:
            key = "deployments" if kind == "Deployment" else "statefulsets"; expected = int(spec.get("replicas", 1) or 0); ready = int(status.get("readyReplicas", 0) or 0)
            summary[key]["expected"] += expected; summary[key]["ready"] += ready
            if ready < expected: unhealthy.append({"resource": name, "state": "NotReady", "detail": f"{ready}/{expected} replicas ready"})
        elif kind == "DaemonSet":
            expected = int(status.get("desiredNumberScheduled", 0) or 0); ready = int(status.get("numberReady", 0) or 0); summary["daemonsets"]["expected"] += expected; summary["daemonsets"]["ready"] += ready
            if ready < expected: unhealthy.append({"resource": name, "state": "NotReady", "detail": f"{ready}/{expected} pods ready"})
        elif kind == "Pod":
            summary["pods"]["expected"] += 1; completed_job_pod = status.get("phase") == "Succeeded" and any(owner.get("kind") == "Job" for owner in (resource.get("metadata") or {}).get("ownerReferences") or []); is_ready = completed_job_pod or any(item.get("type") == "Ready" and item.get("status") == "True" for item in status.get("conditions") or [])
            if is_ready: summary["pods"]["ready"] += 1
            phase = str(status.get("phase") or "Unknown"); waiting = [((container.get("state") or {}).get("waiting") or {}).get("reason", "") for container in status.get("containerStatuses") or []]; terminated = [((container.get("state") or {}).get("terminated") or {}).get("reason", "") for container in status.get("containerStatuses") or []]; reasons = " ".join(waiting + terminated)
            if "CrashLoopBackOff" in reasons: conditions["crashloopbackoff"] += 1
            if "ImagePullBackOff" in reasons or "ErrImagePull" in reasons: conditions["imagepullbackoff"] += 1
            if "OOMKilled" in reasons: conditions["oomkilled"] += 1
            if phase == "Pending": conditions["pending_pods"] += 1
            if any(item.get("reason") == "Unschedulable" for item in status.get("conditions") or []): conditions["unschedulable"] += 1
            if not is_ready: unhealthy.append({"resource": name, "state": reasons or phase, "detail": str(status.get("message") or "Pod did not become Ready")})
        elif kind == "Job":
            expected = int(spec.get("completions", 1) or 1); succeeded = int(status.get("succeeded", 0) or 0); summary["jobs"]["expected"] += expected; summary["jobs"]["ready"] += min(expected, succeeded)
            if int(status.get("failed", 0) or 0): conditions["failed_jobs"] += 1; unhealthy.append({"resource": name, "state": "Failed", "detail": "Job reported failed pods"})
        elif kind == "PersistentVolumeClaim":
            summary["pvcs"]["expected"] += 1
            if status.get("phase") == "Bound": summary["pvcs"]["bound"] += 1
            else: unhealthy.append({"resource": name, "state": str(status.get("phase") or "Pending"), "detail": "PVC is not Bound"})
        elif kind == "Service":
            summary["services"] += 1
            if spec.get("type") == "LoadBalancer" and not ((status.get("loadBalancer") or {}).get("ingress") or []): conditions["unsupported_load_balancer"] += 1; unhealthy.append({"resource": name, "state": "Pending", "detail": "LoadBalancer address is unavailable in kind"})
        elif kind == "Ingress":
            summary["ingresses"] += 1
            if not ((status.get("loadBalancer") or {}).get("ingress") or []): conditions["unsupported_ingress"] += 1; unhealthy.append({"resource": name, "state": "Pending", "detail": "Ingress controller or address is unavailable in kind"})
        elif kind == "CronJob": summary["cronjobs"] += 1
        elif kind == "ConfigMap": summary["configmaps"] += 1
        elif kind == "Secret": summary["secrets"] += 1
    for event in events:
        message = str(event.get("message") or "").lower(); reason = str(event.get("reason") or "").lower(); condition = str(event.get("condition") or "")
        if "probe" in message and reason in {"unhealthy", "backoff"}: conditions["probe_failures"] += 1
        if reason in {"unschedulable", "failedscheduling"} or "insufficient cpu" in message or "insufficient memory" in message:
            conditions["unschedulable"] += 1
        if "insufficient cpu" in message or condition == "INSUFFICIENT_CPU": conditions["insufficient_cpu"] += 1
        if "insufficient memory" in message or condition == "INSUFFICIENT_MEMORY": conditions["insufficient_memory"] += 1
    return summary, conditions, unhealthy


def _selector_matches(selector: Mapping[str, Any], labels: Mapping[str, Any]) -> bool:
    return bool(selector) and all(str(labels.get(key)) == str(value) for key, value in selector.items())


def build_observed_topology(resources: Sequence[Mapping[str, Any]]) -> dict[str, list]:
    nodes: list[dict[str, Any]] = []; edges: list[dict[str, Any]] = []; by_kind: dict[str, list[Mapping[str, Any]]] = {}
    for resource in resources:
        kind = str(resource.get("kind") or ""); metadata = resource.get("metadata") or {}
        if not kind or not metadata.get("name"): continue
        group, _, canonical_namespace, name = canonical_resource_identity(resource)
        api_version = str(resource.get("apiVersion") or "")
        version = api_version.split("/", 1)[-1] if api_version else ""
        identity = _identity(resource); node = {
            "id": identity, "apiVersion": api_version, "group": group, "version": version,
            "kind": kind, "name": name, "namespace": canonical_namespace,
            "uid": metadata.get("uid"), "labels": metadata.get("labels") or {},
            "annotations": metadata.get("annotations") or {},
            "owners": [
                {"apiVersion": owner.get("apiVersion"), "kind": owner.get("kind"), "name": owner.get("name"), "uid": owner.get("uid")}
                for owner in metadata.get("ownerReferences") or [] if isinstance(owner, Mapping)
            ],
            "canonical_identity": {"group": group, "kind": kind, "namespace": canonical_namespace, "name": name},
        }
        if kind != "Secret": node["status"] = resource.get("status") or {}
        nodes.append(node); by_kind.setdefault(kind, []).append(resource)
        for owner in metadata.get("ownerReferences") or []:
            if owner.get("kind") and owner.get("name"): edges.append({"source": f"{owner['kind']}/{node['namespace']}/{owner['name']}", "target": identity, "type": "owns"})
    pods = by_kind.get("Pod", [])
    for service in by_kind.get("Service", []):
        selector = (service.get("spec") or {}).get("selector") or {}; ports = [{"port": row.get("port"), "targetPort": row.get("targetPort"), "protocol": row.get("protocol", "TCP")} for row in (service.get("spec") or {}).get("ports") or []]
        for pod in pods:
            if _selector_matches(selector, (pod.get("metadata") or {}).get("labels") or {}): edges.append({"source": _identity(service), "target": _identity(pod), "type": "selects", "ports": ports})
    for ingress in by_kind.get("Ingress", []):
        backends = []; spec = ingress.get("spec") or {}
        if spec.get("defaultBackend"): backends.append(spec["defaultBackend"])
        for rule in spec.get("rules") or []:
            backends.extend((item.get("backend") or {}) for item in ((rule.get("http") or {}).get("paths") or []))
        for backend in backends:
            service = backend.get("service") or {}; name = service.get("name")
            if name: edges.append({"source": _identity(ingress), "target": f"Service/{(ingress.get('metadata') or {}).get('namespace') or 'default'}/{name}", "type": "routes", "port": service.get("port") or {}})
    for pod in pods:
        pid = _identity(pod); spec = pod.get("spec") or {}; namespace = (pod.get("metadata") or {}).get("namespace") or "default"
        if spec.get("serviceAccountName"): edges.append({"source": pid, "target": f"ServiceAccount/{namespace}/{spec['serviceAccountName']}", "type": "uses"})
        for container in [*(spec.get("initContainers") or []), *(spec.get("containers") or [])]:
            if container.get("image"):
                image_id = f"Image/-/{container['image']}"; edges.append({"source": pid, "target": image_id, "type": "runs"})
                if not any(node["id"] == image_id for node in nodes): nodes.append({"id": image_id, "kind": "Image", "name": container["image"], "namespace": None, "labels": {}})
        for volume in spec.get("volumes") or []:
            for key, kind, field_name in (("configMap", "ConfigMap", "name"), ("secret", "Secret", "secretName"), ("persistentVolumeClaim", "PersistentVolumeClaim", "claimName")):
                ref = volume.get(key) or {}; target = ref.get(field_name)
                if target: edges.append({"source": pid, "target": f"{kind}/{namespace}/{target}", "type": "mounts"})
    for pvc in by_kind.get("PersistentVolumeClaim", []):
        volume = (pvc.get("spec") or {}).get("volumeName")
        if volume: edges.append({"source": _identity(pvc), "target": f"PersistentVolume/default/{volume}", "type": "binds"})
    for policy in by_kind.get("NetworkPolicy", []):
        selector = ((policy.get("spec") or {}).get("podSelector") or {}).get("matchLabels") or {}; namespace = (policy.get("metadata") or {}).get("namespace") or "default"
        for pod in pods:
            if ((pod.get("metadata") or {}).get("namespace") or "default") == namespace and (not selector or _selector_matches(selector, (pod.get("metadata") or {}).get("labels") or {})): edges.append({"source": _identity(policy), "target": _identity(pod), "type": "selects"})
    return {"nodes": nodes, "edges": list({json.dumps(edge, sort_keys=True): edge for edge in edges}.values())}


GENERATED_KINDS = {"Pod", "ReplicaSet", "Endpoints", "EndpointSlice", "ControllerRevision", "PersistentVolumeClaim", "Event"}
CLUSTER_INFRASTRUCTURE_KINDS = CLUSTER_SCOPED_KINDS | {"Lease"}


def compare_topology(declared: Sequence[Mapping[str, Any]], observed: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, default_namespace: str = "default", release_names: Sequence[str] = ()) -> dict[str, Any]:
    observed_nodes = observed.get("nodes", []) if isinstance(observed, Mapping) else observed
    declared_items = {canonical_resource_identity(item, default_namespace): item for item in declared if item.get("kind") and (item.get("metadata") or {}).get("name")}
    declared_map = {canonical_resource_identity(item, default_namespace): _identity(item, default_namespace) for item in declared if item.get("kind") and (item.get("metadata") or {}).get("name")}
    observed_map = {canonical_resource_identity(item, default_namespace): str(item.get("id") or _identity(item, default_namespace)) for item in observed_nodes if item.get("kind") and item.get("kind") != "Image" and item.get("name")}
    matched_keys = declared_map.keys() & observed_map.keys(); missing_keys = declared_map.keys() - observed_map.keys(); extra_keys = observed_map.keys() - declared_map.keys()
    application_generated_keys: set[tuple[str, str, str, str]] = set()
    provider_keys: set[tuple[str, str, str, str]] = set()
    system_keys: set[tuple[str, str, str, str]] = set()
    environment_keys: set[tuple[str, str, str, str]] = set()
    release_set = {str(value) for value in release_names}
    for node in observed_nodes:
        key = canonical_resource_identity(node, default_namespace)
        if key not in extra_keys:
            continue
        metadata_labels = node.get("labels") if isinstance(node, Mapping) else {}
        annotations = node.get("annotations") if isinstance(node, Mapping) else {}
        namespace = key[2]
        if isinstance(metadata_labels, Mapping) and str(metadata_labels.get("cats.clanhq.io/validation-infrastructure", "")).casefold() == "true":
            provider_keys.add(key)
        elif namespace in {"kube-system", "kube-public", "kube-node-lease", "local-path-storage", "metallb-system", "ingress-nginx"} or key[1] in CLUSTER_INFRASTRUCTURE_KINDS:
            system_keys.add(key)
        elif namespace == default_namespace and (
            (key[1] == "ServiceAccount" and key[3] == "default")
            or (key[1] == "ConfigMap" and key[3] == "kube-root-ca.crt")
            or (key[1] == "Secret" and key[3].startswith("sh.helm.release.v1."))
        ):
            environment_keys.add(key)
        else:
            helm_release = str((metadata_labels or {}).get("app.kubernetes.io/instance") or (annotations or {}).get("meta.helm.sh/release-name") or "")
            if namespace == default_namespace and (key[1] in GENERATED_KINDS or bool(node.get("owners")) or helm_release in release_set):
                application_generated_keys.add(key)
    classified = application_generated_keys | provider_keys | system_keys | environment_keys
    def evidence(key: tuple[str, str, str, str], value: str, source: str, matched: bool) -> dict[str, Any]:
        group, kind, namespace, name = key
        node = next((item for item in observed_nodes if canonical_resource_identity(item, default_namespace) == key), None)
        source_item = declared_items.get(key) if source == "helm-render" else node
        return {"apiVersion": (source_item or {}).get("apiVersion") if isinstance(source_item, Mapping) else None, "group": group, "version": str((source_item or {}).get("apiVersion") or "").split("/", 1)[-1] if isinstance(source_item, Mapping) else "", "kind": kind, "namespace": namespace, "name": name, "uid": (node or {}).get("uid") if source == "kubernetes-api" and isinstance(node, Mapping) else None, "source_file": (source_item or {}).get("_cats_source_file") if source == "helm-render" and isinstance(source_item, Mapping) else None, "canonical_identity": [group, kind, namespace, name], "display_identity": value, "source": source, "matched": matched}
    return {
        "matched": sorted(observed_map[key] for key in matched_keys),
        "declared_only": sorted(declared_map[key] for key in missing_keys),
        "observed_only": sorted(observed_map[key] for key in extra_keys - classified),
        "defaulted": sorted(observed_map[key] for key in application_generated_keys),
        "cats_provisioned": sorted(observed_map[key] for key in provider_keys),
        "kubernetes_system": sorted(observed_map[key] for key in system_keys),
        "validation_environment": sorted(observed_map[key] for key in environment_keys),
        "changed": [], "unresolved": [],
        "matcher": "api-group + kind + namespace + name (API version, UID, and provenance excluded)",
        "expected_evidence": [evidence(key, declared_map[key], "helm-render", key in matched_keys) for key in sorted(declared_map)],
        "observed_evidence": [evidence(key, observed_map[key], "kubernetes-api", key in matched_keys) for key in sorted(observed_map)],
    }


def capability_assessment_groups(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate repeated capability rows without discarding technical evidence."""
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        capability = str(row.get("capability") or "Unknown")
        item = grouped.setdefault(capability, {
            "capability": capability, "required": False, "statuses": [],
            "required_count": 0, "verified_count": 0, "available_count": 0,
            "failed_count": 0, "unexercised_count": 0, "rows": [], "provisioned_by_cats": False,
        })
        status = str(row.get("status") or "NOT_REQUIRED").upper()
        item["required"] = bool(item["required"] or row.get("required"))
        item["required_count"] += int(bool(row.get("required")))
        item["verified_count"] += int(status == "VERIFIED")
        item["available_count"] += int(status in {"AVAILABLE", "PROVISIONED", "BOUND", "VERIFIED"})
        item["failed_count"] += int(status in {"FAILED", "UNAVAILABLE", "UNSUPPORTED", "BLOCKED"})
        item["unexercised_count"] += int(status == "UNEXERCISED")
        item["statuses"].append(status)
        item["rows"].append(dict(row))
        item["provisioned_by_cats"] = bool(item["provisioned_by_cats"] or row.get("provisioned_by_cats"))
    priority = {"FAILED": 6, "UNAVAILABLE": 5, "UNSUPPORTED": 4, "BLOCKED": 4, "UNEXERCISED": 3, "PENDING": 2, "AVAILABLE": 1, "VERIFIED": 0, "NOT_REQUIRED": -1}
    for item in grouped.values():
        item["status"] = max(item["statuses"], key=lambda value: priority.get(value, 2)) if item["statuses"] else "NOT_REQUIRED"
        item["explanation"] = f"{item['verified_count']} verified; {item['available_count']} available; {item['required_count']} required resource(s)."
        if item["capability"] == "Configuration dependencies":
            dependencies: dict[tuple[str, str], dict[str, Any]] = {}
            for row in item["rows"]:
                evidence = row.get("evidence") if isinstance(row.get("evidence"), Mapping) else {}
                kind = str(evidence.get("dependency_kind") or "")
                name = str(evidence.get("dependency_name") or "")
                if not kind or not name:
                    continue
                dependency = dependencies.setdefault((kind, name), {
                    "kind": kind, "name": name, "status": "NOT_REQUIRED",
                    "required_by": [], "optional": True,
                })
                row_status = str(row.get("status") or "NOT_REQUIRED").upper()
                if priority.get(row_status, 2) > priority.get(str(dependency["status"]), -1):
                    dependency["status"] = row_status
                dependency["optional"] = bool(dependency["optional"] and evidence.get("optional", False))
                source = str(row.get("source_resource") or "")
                if source and source not in dependency["required_by"]:
                    dependency["required_by"].append(source)
            dependency_rows = sorted(dependencies.values(), key=lambda value: (value["kind"], value["name"]))
            item["dependency_rows"] = dependency_rows
            item["dependency_total"] = len(dependency_rows)
            item["dependency_available"] = sum(
                1 for dependency in dependency_rows
                if dependency["status"] in {"AVAILABLE", "VERIFIED", "BOUND", "PROVISIONED"}
            )
            item["dependency_verified"] = sum(1 for dependency in dependency_rows if dependency["status"] == "VERIFIED")
    return sorted(grouped.values(), key=lambda value: value["capability"].casefold())


def classification_reason_evidence(result: Mapping[str, Any], status: str, category: str | None, reason: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build persisted, machine-readable reasons for every terminal outcome."""
    comparison = result.get("comparison") if isinstance(result.get("comparison"), Mapping) else {}
    unhealthy = result.get("unhealthy_resources") if isinstance(result.get("unhealthy_resources"), list) else []
    capabilities = result.get("capability_preflight") if isinstance(result.get("capability_preflight"), list) else []
    reasons: list[dict[str, Any]] = []
    if status == ValidationStatus.VERIFIED.value:
        reasons.append({"code": "ALL_REQUIRED_EVIDENCE_VERIFIED", "severity": "info", "explanation": reason})
    for resource in comparison.get("declared_only", []) if isinstance(comparison.get("declared_only"), list) else []:
        parts = str(resource).split("/")
        kind = parts[0] if parts else "Resource"
        namespace = parts[1] if len(parts) > 2 else ""
        name = parts[-1] if parts else resource
        reasons.append({"code": "EXPECTED_RESOURCE_NOT_OBSERVED", "severity": "blocking", "resource": {"kind": kind, "namespace": namespace, "name": name}, "expected_state": "Observed", "observed_state": "Missing", "explanation": f"The rendered {resource} was not observed after Helm installation."})
    for item in unhealthy:
        reasons.append({"code": "RUNTIME_RESOURCE_NOT_READY", "severity": "blocking", "resource": item.get("resource"), "expected_state": "Ready or completed", "observed_state": item.get("state"), "explanation": item.get("detail") or "The resource did not reach its expected runtime state."})
    for item in capabilities:
        if item.get("required") and str(item.get("status") or "").upper() in {"UNAVAILABLE", "UNSUPPORTED", "FAILED", "BLOCKED", "UNEXERCISED", "PROVIDER_SPECIFIC"}:
            source_resource = str(item.get("source_resource") or "")
            source_kind, _, source_name = source_resource.partition("/")
            reasons.append({"code": "REQUIRED_CAPABILITY_NOT_FULLY_VERIFIED", "severity": "blocking", "capability": item.get("capability"), "resource": {"kind": source_kind or "Capability", "namespace": item.get("source_namespace") or "", "name": source_name or item.get("capability") or "unknown"}, "expected_state": "Verified", "observed_state": item.get("status"), "explanation": item.get("explanation") or f"Required capability {item.get('capability')} was not fully verified."})
    if not reasons and status != ValidationStatus.VERIFIED.value:
        reasons.append({"code": str(category or "VALIDATION_INCOMPLETE_EVIDENCE"), "severity": "blocking", "expected_state": "Sufficient validation evidence", "observed_state": status, "explanation": reason})
    comparison_summary = {
        "expected_resources": len(comparison.get("matched", [])) + len(comparison.get("declared_only", [])),
        "observed_expected": len(comparison.get("matched", [])),
        "expected_only": len(comparison.get("declared_only", [])),
        "runtime_generated": len(comparison.get("defaulted", [])),
        "observed_only": len(comparison.get("observed_only", [])),
        "failed": len(unhealthy),
    }
    return reasons, comparison_summary


def _safe_event(event: Mapping[str, Any]) -> dict[str, Any]:
    involved = event.get("involvedObject") or {}
    message = str(event.get("message") or "")
    category = classify_failure(message)
    lower_message = message.lower()
    condition = "INSUFFICIENT_CPU" if "insufficient cpu" in lower_message else "INSUFFICIENT_MEMORY" if "insufficient memory" in lower_message else ""
    if "probe" in message.lower(): summary = "Probe failure observed"
    elif category != FailureCategory.UNKNOWN.value: summary = f"Classified as {category}"
    else: summary = "Technical event message withheld"
    return {
        "type": str(event.get("type") or ""), "reason": str(event.get("reason") or ""),
        "message": summary, "condition": condition, "count": event.get("count"),
        "firstTimestamp": event.get("firstTimestamp"), "lastTimestamp": event.get("lastTimestamp"),
        "involvedObject": {"kind": str(involved.get("kind") or ""), "name": str(involved.get("name") or ""),
                           "namespace": str(involved.get("namespace") or ""), "uid": str(involved.get("uid") or "")},
    }


def parse_observations(resources: Any = None, events: Any = None, pods: Any = None, *, max_events: int = 200) -> dict[str, Any]:
    rows = _resource_rows(resources); existing = {_identity(item) for item in rows}
    for pod in _resource_rows(pods):
        if _identity(pod) not in existing: rows.append(pod)
    event_rows = [_safe_event(item) for item in _resource_rows(events)[:max_events]]
    for item in rows:
        if item.get("kind") == "Secret": item.pop("data", None); item.pop("stringData", None)
    summary, conditions, unhealthy = _ready(rows, event_rows)
    return {"resources": rows, "events": event_rows, "resource_summary": summary, "conditions": conditions, "unhealthy_resources": unhealthy, "observed_topology": build_observed_topology(rows)}


def _default_runner(command: Sequence[str], *, timeout: float, env: Mapping[str, str] | None = None) -> CommandResult:
    try:
        output_limit = max(65536, min(int(os.getenv("CATS_DEPLOYMENT_MAX_COMMAND_OUTPUT_BYTES", str(24 * 1024 * 1024))), 256 * 1024 * 1024))
    except ValueError:
        output_limit = 24 * 1024 * 1024
    buffers = [bytearray(), bytearray()]
    truncated = [False, False]

    def drain(stream: Any, index: int) -> None:
        try:
            while chunk := stream.read(65536):
                remaining = output_limit - len(buffers[index])
                if remaining > 0:
                    buffers[index].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated[index] = True
        finally:
            stream.close()

    try:
        process = subprocess.Popen(
            list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(env or os.environ), start_new_session=os.name != "nt",
        )
        readers = [threading.Thread(target=drain, args=(process.stdout, 0), daemon=True), threading.Thread(target=drain, args=(process.stderr, 1), daemon=True)]
        for reader in readers: reader.start()
        try:
            returncode = process.wait(timeout=max(1, timeout))
        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt": os.killpg(process.pid, signal.SIGKILL)
                else: process.kill()
            except OSError:
                process.kill()
            process.wait()
            returncode = 124
        for reader in readers: reader.join(timeout=2)
        stdout = buffers[0].decode("utf-8", errors="replace"); stderr = buffers[1].decode("utf-8", errors="replace")
        if any(truncated):
            returncode = 125
            stderr = f"{stderr}\nCommand output exceeded the configured {output_limit}-byte limit."
        elif returncode == 124:
            stderr = f"{stderr}\nCommand timed out."
        return CommandResult(returncode, stdout, stderr.strip())
    except FileNotFoundError as exc: return CommandResult(127, "", str(exc))
    except OSError as exc: return CommandResult(127, "", str(exc))


def _policy_documents(namespace: str, config: ValidationConfig) -> str:
    labels = {"cats.clanhq.io/validation-infrastructure": "true", "cats.clanhq.io/validation-run": namespace}
    documents: list[dict[str, Any]] = [
        {"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": "cats-validation-limits", "namespace": namespace, "labels": labels}, "spec": {"hard": {"pods": str(config.max_pods), "requests.cpu": config.max_cpu, "requests.memory": config.max_memory, "requests.storage": config.max_storage, "requests.ephemeral-storage": config.max_storage, "limits.ephemeral-storage": config.max_storage, "persistentvolumeclaims": str(config.max_pods), "count/jobs.batch": str(config.max_pods), "count/cronjobs.batch": str(config.max_objects), "count/secrets": str(config.max_objects), "count/configmaps": str(config.max_objects), "count/services": str(config.max_objects), "count/deployments.apps": str(config.max_objects), "count/statefulsets.apps": str(config.max_objects), "count/daemonsets.apps": str(config.max_objects), "count/replicasets.apps": str(config.max_objects)}}},
        {"apiVersion": "v1", "kind": "LimitRange", "metadata": {"name": "cats-validation-defaults", "namespace": namespace, "labels": labels}, "spec": {"limits": [{"type": "Container", "default": {"cpu": "500m", "memory": "512Mi", "ephemeral-storage": "1Gi"}, "defaultRequest": {"cpu": "50m", "memory": "64Mi", "ephemeral-storage": "100Mi"}}]}},
    ]
    if not config.allow_network_egress: documents.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "cats-default-deny-egress", "namespace": namespace, "labels": labels}, "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []}})
    return "---\n".join(yaml.safe_dump(item, sort_keys=False) for item in documents)


def _decode(value: str) -> Any:
    try: return json.loads(value or "{}")
    except (TypeError, ValueError): return {}


def _rewrite_kubeconfig(path: Path, api_host: str) -> None:
    if not api_host or not path.is_file(): return
    config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for cluster in config.get("clusters") or []:
        server = str((cluster.get("cluster") or {}).get("server") or ""); parsed = re.match(r"^(https?://)([^:/]+)(:\d+.*)$", server)
        if parsed: cluster["cluster"]["server"] = f"{parsed.group(1)}{api_host}{parsed.group(3)}"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    try: path.chmod(0o600)
    except OSError: pass


def validate_artifact(artifact: ValidationArtifact | Mapping[str, Any], *, config: ValidationConfig | None = None, runner: CommandRunner | None = None, progress_callback: Callable[[str], None] | None = None) -> dict[str, Any]:
    cfg = config or ValidationConfig.from_env(); run = runner or _default_runner
    if isinstance(artifact, Mapping): artifact = ValidationArtifact(**{key: artifact[key] for key in ValidationArtifact.__dataclass_fields__ if key in artifact})
    cluster, namespace = validation_names(cfg, artifact.job_id); network_name = f"{cluster}-network"; started = time.monotonic(); root = Path(tempfile.mkdtemp(prefix="cats-deployment-")); kubeconfig = root / "kubeconfig.yaml"
    network_attempted = False; create_attempted = False; rendered_resources: list[dict[str, Any]] = []; diagnostics: dict[str, Any] = {}
    provider_lifecycle: dict[str, Any] = {}
    result: dict[str, Any] = {"engine": "kind", "status": ValidationStatus.NOT_ATTEMPTED.value, "classification": ValidationStatus.NOT_ATTEMPTED.value, "phase": "QUEUED", "reason_category": None, "reason": None, "classification_reasons": [], "classification_summary": {"expected_resources": 0, "observed_expected": 0, "expected_only": 0, "runtime_generated": 0, "observed_only": 0, "failed": 0}, "helm_result": {"template": "NOT_ATTEMPTED", "install": "NOT_ATTEMPTED", "release_status": "NOT_ATTEMPTED", "rendered_resource_count": 0}, "resource_summary": {}, "conditions": {}, "dependencies": {"missing_crds": [], "missing_storage_classes": [], "unavailable_images": []}, "capability_preflight": [], "capability_bootstrap": {"provisioned": [], "warnings": [], "duration_ms": 0}, "observed_topology": {"nodes": [], "edges": []}, "comparison": {"matched": [], "declared_only": [], "observed_only": [], "defaulted": [], "changed": [], "unresolved": []}, "events": [], "unhealthy_resources": [], "sandbox_sensitive_behaviors": [], "security_policy_violations": [], "policy_violations": [], "resource_isolation": {"overall": "NOT_ATTEMPTED"}, "warnings": [], "diagnostics": diagnostics, "cluster_name": cluster, "namespace": namespace, "cleanup_status": "NOT_ATTEMPTED", "duration_seconds": 0}
    helm_timing: dict[str, Any] = result["helm_result"]
    template_started_monotonic: float | None = None
    install_started_monotonic: float | None = None
    def _utc_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()
    def _start_helm_stage(stage: str) -> None:
        nonlocal template_started_monotonic, install_started_monotonic
        now = time.monotonic()
        helm_timing[f"{stage}_started_at"] = _utc_timestamp()
        if stage == "template": template_started_monotonic = now
        else: install_started_monotonic = now
    def _complete_helm_stage(stage: str) -> None:
        nonlocal template_started_monotonic, install_started_monotonic
        now = time.monotonic()
        helm_timing[f"{stage}_completed_at"] = _utc_timestamp()
        started_at = template_started_monotonic if stage == "template" else install_started_monotonic
        if started_at is not None: helm_timing[f"{stage}_duration_ms"] = max(0, round((now - started_at) * 1000))
        if stage == "install":
            # Helm total is the sum of the measured Helm stages.  Do not
            # include kind creation or optional environment-control setup that
            # occurs between template and install.
            template_ms = helm_timing.get("template_duration_ms")
            install_ms = helm_timing.get("install_duration_ms")
            if isinstance(template_ms, (int, float)) and isinstance(install_ms, (int, float)):
                helm_timing["helm_total_duration_ms"] = max(0, round(template_ms + install_ms))
    env = _command_environment(); env["KUBECONFIG"] = str(kubeconfig); env["KIND_CLUSTER_NAME"] = cluster; env["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = network_name
    trusted_bundle = write_additive_bundle(root / "trust" / "ca-bundle.pem", artifact.trusted_ca_certificates)
    if trusted_bundle:
        for key in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
            env[key] = str(trusted_bundle)
    def phase(value: str) -> None:
        result["phase"] = value
        if progress_callback:
            try:
                progress_callback(value)
            except Exception:
                # Persistence/audit availability must never prevent workload cleanup.
                pass
    def remaining(cap: float) -> float:
        left = cfg.total_timeout_seconds - (time.monotonic() - started)
        if left <= 0: raise TimeoutError("Deployment Validation total timeout exceeded")
        return max(1, min(float(cap), left))
    def command(argv: Sequence[str], cap: float, key: str | None = None, command_env: Mapping[str, str] | None = None) -> CommandResult:
        completed = run(argv, timeout=remaining(cap), env=command_env or env)
        if key:
            diagnostics[key] = _diagnostic_summary(completed)
        return completed
    def node_limit_event() -> dict[str, Any] | None:
        if result.get("resource_isolation", {}).get("overall") != "ENFORCED":
            return None
        inspected = command([cfg.docker_binary, "inspect", "--format={{json .State}}", f"{cluster}-control-plane"], cfg.collect_timeout_seconds, "kind_node_state", env)
        try:
            state = json.loads(inspected.stdout) if inspected.returncode == 0 and inspected.stdout.strip() else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            state = {}
        return _sandbox_limit_event(state)
    def record_warning(message: str) -> None:
        """Keep best-effort guardrail failures visible without changing outcome."""
        warning = _bounded(message, 1000)
        if warning not in result["warnings"]:
            result["warnings"].append(warning)
        diagnostics.setdefault("warnings", result["warnings"])
    def finish(status: ValidationStatus, category: FailureCategory | None, reason: str) -> dict[str, Any]:
        result.update(status=status.value, classification=status.value, reason_category=category.value if category else None, reason=_bounded(reason, 1000))
        reasons, summary = classification_reason_evidence(result, status.value, category.value if category else None, reason)
        if not category and status is not ValidationStatus.VERIFIED and reasons:
            result["reason_category"] = str(reasons[0].get("code") or "VALIDATION_INCOMPLETE_EVIDENCE")
        result["classification_reasons"] = reasons
        result["classification_summary"] = summary
        diagnostics["classification_summary"] = summary
        diagnostics["classification"] = {"status": status.value, "reason_category": result["reason_category"], "reason_count": len(reasons), **summary}
        return result
    try:
        phase("PREFLIGHT"); artifact_root = root / "artifact"; materialize_sources(artifact.source_files, artifact_root, max_bytes=cfg.max_source_bytes); charts = _root_charts(artifact_root)
        if not charts: return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.HELM_CHART_INVALID, "The selected artifact does not contain a concrete root Chart.yaml.")
        values_paths: list[Path] = []
        for value in artifact.values_files:
            relative = _safe_path(value); candidate = (artifact_root / Path(*relative.parts)).resolve()
            if artifact_root.resolve() not in candidate.parents or not candidate.is_file():
                return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.HELM_CHART_INVALID, f"Configured Helm values file is unavailable: {value}")
            values_paths.append(candidate)
        values_args = [argument for path in values_paths for argument in ("--values", str(path))]
        phase("RENDERING")
        _start_helm_stage("template")
        rendered_bytes = 0
        for index, chart in enumerate(charts, 1):
            lint = command([cfg.helm_binary, "lint", str(chart), *values_args], cfg.install_timeout_seconds, f"helm_lint_{index}")
            if lint.returncode:
                _complete_helm_stage("template")
                result["helm_result"]["template"] = "FAIL"
                return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.HELM_LINT_FAILURE, "Helm lint did not accept the selected chart.")
            # Render hooks and CRDs as part of the chart's real deployment
            # behavior. Boundary checks below inspect the resulting objects;
            # ordinary Kubernetes scope is not a reason to omit them.
            rendered = command([cfg.helm_binary, "template", f"cats-validation-{index}", str(chart), "--namespace", namespace, "--include-crds", *values_args], cfg.install_timeout_seconds, f"helm_template_{index}")
            if rendered.returncode:
                _complete_helm_stage("template")
                result["helm_result"]["template"] = "FAIL"
                return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.HELM_TEMPLATE_FAILURE, "Helm could not render the selected chart for validation.")
            rendered_bytes += len(rendered.stdout.encode("utf-8"))
            if rendered_bytes > cfg.max_render_bytes:
                _complete_helm_stage("template")
                return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.RESOURCE_LIMIT_EXCEEDED, "Rendered manifests exceed the configured aggregate size limit.")
            rendered_resources.extend(_yaml_documents(rendered.stdout, cfg.max_render_bytes))
        _complete_helm_stage("template")
        result["helm_result"].update(template="PASS", rendered_resource_count=len(rendered_resources)); _merge_rendered_provenance(rendered_resources, artifact.declared_resources)
        result["capability_preflight"] = capability_preflight(rendered_resources)
        result["capability_preflight"].extend(detect_runtime_requirements(rendered_resources))
        sandbox_decisions = sandbox_preflight(rendered_resources, cfg, namespace=namespace)
        result["sandbox_sensitive_behaviors"] = [
            {**decision, **_policy_source(next((resource for resource in rendered_resources if f"{resource.get('kind')}/{(resource.get('metadata') or {}).get('name', 'unknown')}" == decision.get('resource')), {}), str(decision.get('field_path') or ""))}
            for decision in sandbox_decisions
        ]
        diagnostics["sandbox_preflight"] = result["sandbox_sensitive_behaviors"]
        violations = security_preflight(rendered_resources, cfg, namespace=namespace)
        governance_violations = [item for item in violations if item.get("category") == "RESOURCE_GOVERNANCE"]
        for item in governance_violations:
            record_warning(f"{item.get('resource', 'Chart')}: {item.get('reason', 'optional resource governance check was not enforced before deployment')}; Kubernetes was allowed to evaluate the workload.")
        security_violations = [item for item in violations if item.get("category") != "RESOURCE_GOVERNANCE"]
        if security_violations:
            result["unhealthy_resources"] = security_violations
            result["security_policy_violations"] = security_policy_violation_evidence(rendered_resources, security_violations)
            result["policy_violations"] = result["security_policy_violations"]
            diagnostics["security_policy_violations"] = result["security_policy_violations"]
            return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.SECURITY_POLICY_VIOLATION, f"CATS did not execute this workload because the validation sandbox boundary detected {len(security_violations)} violation(s). See the preflight evidence below for each rejected resource and field.")
        images = sorted({str(container.get("image")) for resource in rendered_resources for container in [*(_pod_spec(resource).get("initContainers") or []), *(_pod_spec(resource).get("containers") or [])] if isinstance(container, Mapping) and container.get("image")})
        if cfg.kind_node_archive:
            if command([cfg.docker_binary, "load", "--input", cfg.kind_node_archive], cfg.create_timeout_seconds, "kind_node_archive").returncode: return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.KIND_CREATION_FAILURE, "The configured kind node archive could not be loaded.")
        node_available = command([cfg.docker_binary, "image", "inspect", "--", cfg.kind_node_image], cfg.create_timeout_seconds, "kind_node_image").returncode == 0
        if not node_available and (cfg.require_local_images or not cfg.allow_network_egress):
            return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.KIND_CREATION_FAILURE, "The pinned kind node image is unavailable in the local validation environment.")
        local_images = [image for image in images if command([cfg.docker_binary, "image", "inspect", "--", image], cfg.collect_timeout_seconds).returncode == 0]
        unavailable = sorted(set(images) - set(local_images))
        if unavailable:
            # A local Docker inspection is only a prediction.  Let Helm and
            # Kubernetes attempt the pull so ImagePullBackOff/ErrImagePull and
            # registry-auth failures become runtime evidence.
            result["dependencies"]["unavailable_images"] = unavailable
            record_warning(f"CATS could not confirm {len(unavailable)} workload image(s) locally; Helm/Kubernetes will determine image availability during deployment.")
        network_command = [cfg.docker_binary, "network", "create", "--driver", "bridge", "--label", "cats.deployment-validation=true"]
        if not cfg.allow_network_egress:
            network_command.append("--internal")
        network_command.append(network_name); network_attempted = True
        if command(network_command, cfg.create_timeout_seconds, "network_create", env).returncode:
            return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.KIND_CREATION_FAILURE, "CATS could not create the isolated container network for Deployment Validation.")
        cert_sans = sorted({value for value in ("host.docker.internal", cfg.api_host, cfg.api_address) if value and value != "0.0.0.0"})
        kubeadm_patch = yaml.safe_dump({"kind": "ClusterConfiguration", "apiServer": {"certSANs": cert_sans}}, sort_keys=False)
        kind_config = root / "kind-config.yaml"; kind_config.write_text(yaml.safe_dump({"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "networking": {"apiServerAddress": cfg.api_address}, "kubeadmConfigPatches": [kubeadm_patch]}, sort_keys=False), encoding="utf-8")
        phase("CREATING_CLUSTER"); create_attempted = True
        made = command([cfg.kind_binary, "create", "cluster", "--name", cluster, "--image", cfg.kind_node_image, "--kubeconfig", str(kubeconfig), "--config", str(kind_config), "--wait", f"{int(cfg.create_timeout_seconds)}s"], cfg.create_timeout_seconds, "kind_create", env)
        if made.returncode: return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.KIND_CREATION_FAILURE, "CATS could not create the ephemeral Kubernetes cluster.")
        resource_isolation = attempt_resource_isolation(cfg, f"{cluster}-control-plane", lambda argv, *, timeout, env=None: command(argv, timeout, None, env), timeout=remaining(cfg.create_timeout_seconds), env=env)
        result["resource_isolation"] = resource_isolation
        diagnostics["resource_isolation"] = {name: {key: value for key, value in item.items() if key != "configured_limit" or value is not None} for name, item in resource_isolation.items() if isinstance(item, Mapping)}
        for warning in resource_isolation.get("warnings", []):
            record_warning(f"Optional resource control unavailable: {warning}")
        _rewrite_kubeconfig(kubeconfig, cfg.api_host)
        if local_images:
            loaded = command([cfg.kind_binary, "load", "docker-image", "--name", cluster, *local_images], cfg.install_timeout_seconds, "kind_load_images", env)
            if loaded.returncode:
                # Loading an image into kind is an optimization.  A failed
                # load must not suppress the real Helm/Kubernetes attempt.
                record_warning("One or more locally available workload images could not be loaded into kind; Helm/Kubernetes will attempt the deployment anyway.")
        if command([cfg.kubectl_binary, "create", "namespace", namespace, "--kubeconfig", str(kubeconfig)], cfg.install_timeout_seconds, "namespace_create", env).returncode: return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.KIND_CREATION_FAILURE, "The isolated validation namespace could not be created.")
        namespace_label = command([cfg.kubectl_binary, "label", "namespace", namespace, "cats.clanhq.io/validation-infrastructure=true", f"cats.clanhq.io/validation-run={namespace}", "--overwrite", "--kubeconfig", str(kubeconfig)], cfg.install_timeout_seconds, "namespace_label", env)
        if namespace_label.returncode:
            record_warning("CATS could not label the validation namespace; raw evidence remains retained and reconciliation filters the run namespace.")
        # Do not apply a blanket restricted Pod Security profile here. It would
        # reject otherwise sandbox-safe Kubernetes behavior (for example
        # hostNetwork inside the per-run internal Docker network) and conflate
        # static hardening findings with the preflight boundary. The targeted
        # checks in security_preflight remain the execution gate.
        policy = root / "validation-policy.yaml"; policy.write_text(_policy_documents(namespace, cfg), encoding="utf-8")
        policy_result = command([cfg.kubectl_binary, "apply", "--kubeconfig", str(kubeconfig), "-f", str(policy)], cfg.install_timeout_seconds, "resource_policy", env)
        if policy_result.returncode:
            # ResourceQuota, LimitRange, and the default-deny policy are
            # defense-in-depth controls.  Their absence is recorded, but the
            # chart still needs to reach Kubernetes for authoritative evidence.
            record_warning("Optional validation ResourceQuota/LimitRange or network policy could not be applied; deployment validation continued without that guardrail.")
        bootstrap = provision_validation_capabilities(result["capability_preflight"], cfg, command=command, root=root,
                                                       kubeconfig=kubeconfig, namespace=namespace, env=env,
                                                       timeout=max(1, min(cfg.install_timeout_seconds, remaining(cfg.total_timeout_seconds) / 3)),
                                                       lifecycle=provider_lifecycle)
        result["capability_bootstrap"] = bootstrap
        for warning in bootstrap.get("warnings", []):
            record_warning(warning)
        phase("INSTALLING")
        _start_helm_stage("install")
        release_evidence: list[dict[str, str]] = []
        install_failures: list[dict[str, str]] = []
        for index, chart in enumerate(charts, 1):
            release = f"cats-validation-{index}"; installed = command([cfg.helm_binary, "upgrade", "--install", release, str(chart), "--namespace", namespace, "--kubeconfig", str(kubeconfig), "--timeout", f"{int(cfg.install_timeout_seconds)}s", *values_args], cfg.install_timeout_seconds, f"helm_install_{index}", env)
            if installed.returncode:
                result["helm_result"].update(install="FAIL", release_status="FAILED")
                install_failures.append({"release": release, "category": classify_failure(installed.stderr or installed.stdout, FailureCategory.HELM_INSTALL_FAILURE)})
                continue
            result["helm_result"]["install"] = "PASS"
            release_result = command([cfg.helm_binary, "status", release, "--namespace", namespace, "--kubeconfig", str(kubeconfig), "--output", "json"], cfg.collect_timeout_seconds, f"helm_status_{index}", env)
            release_payload = _decode(release_result.stdout); release_status = str(((release_payload.get("info") or {}).get("status") if isinstance(release_payload, Mapping) else "") or "UNKNOWN").upper()
            result["helm_result"]["release_status"] = release_status
            release_evidence.append({"name": release, "status": release_status})
            if release_result.returncode or release_status != "DEPLOYED":
                install_failures.append({"release": release, "category": FailureCategory.HELM_INSTALL_FAILURE.value})
        _complete_helm_stage("install")
        if not install_failures:
            result["helm_result"].update(install="PASS", release_status="DEPLOYED")
        else:
            result["helm_result"].update(install="FAIL", release_status="FAILED")
        result["helm_result"]["releases"] = release_evidence
        phase("WAITING_FOR_READY")
        wait_commands: list[list[str]] = []
        rendered_kinds = {str(resource.get("kind") or "") for resource in rendered_resources}
        for resource in rendered_resources:
            kind = str(resource.get("kind") or "")
            metadata = resource.get("metadata") or {}
            if kind in {"Deployment", "StatefulSet", "DaemonSet"} and metadata.get("name"):
                wait_commands.append([cfg.kubectl_binary, "rollout", "status", f"{kind.lower()}/{metadata['name']}", "--namespace", str(metadata.get("namespace") or namespace), "--timeout", f"{int(cfg.readiness_timeout_seconds)}s", "--kubeconfig", str(kubeconfig)])
        if "Job" in rendered_kinds:
            wait_commands.append([cfg.kubectl_binary, "wait", "--for=condition=Complete", "jobs", "--all", "--namespace", namespace, "--timeout", f"{int(cfg.readiness_timeout_seconds)}s", "--kubeconfig", str(kubeconfig)])
        for resource in rendered_resources:
            if resource.get("kind") == "Pod" and (resource.get("metadata") or {}).get("name"):
                wait_commands.append([cfg.kubectl_binary, "wait", "--for=condition=Ready", f"pod/{resource['metadata']['name']}", "--namespace", namespace, "--timeout", f"{int(cfg.readiness_timeout_seconds)}s", "--kubeconfig", str(kubeconfig)])
        readiness_results = [command(argv, cfg.readiness_timeout_seconds, f"readiness_{index}", env) for index, argv in enumerate(wait_commands, 1)]
        readiness = CommandResult(
            returncode=1 if any(item.returncode for item in readiness_results) else 0,
            stdout="\n".join(item.stdout for item in readiness_results),
            stderr="\n".join(item.stderr for item in readiness_results),
        )
        lb_provider = bootstrap.get("load_balancer") or {}
        lb_requirements = [item for item in result["capability_preflight"] if item.get("capability") == "LoadBalancer" and item.get("required")]
        for item in lb_requirements:
            if lb_provider.get("controller_ready") and item.get("generic_exercise", True):
                service_name = str(item.get("source_resource") or "").partition("/")[2]
                try:
                    command([cfg.kubectl_binary, "wait", "--for=jsonpath={.status.loadBalancer.ingress}", f"service/{service_name}", "--namespace", str(item.get("source_namespace") or namespace), "--timeout=20s", "--kubeconfig", str(kubeconfig)], 22, "lb_service_reconciliation", env)
                except TimeoutError:
                    record_warning("LoadBalancer reconciliation observation timed out; collecting available workload evidence.")
        if lb_requirements and lb_provider.get("attempted", lb_provider.get("controller_ready")):
            health = MetalLBProvider().collect_evidence(cfg, command, kubeconfig, env, min(15, cfg.collect_timeout_seconds))
            lb_provider["runtime_health"] = health
            expected_pool = {address + "/32" for address in (lb_provider.get("address_pool") or {}).get("addresses") or []}
            lb_provider["controller_ready"] = bool(lb_provider.get("controller_ready") and health.get("controller_ready") and expected_pool and expected_pool == set(health.get("pool_addresses") or []))
            diagnostics["load_balancer_provider"] = health
        ingress_provider = bootstrap.get("ingress") or {}
        ingress_requirements = [item for item in result["capability_preflight"] if item.get("capability") == "Ingress" and item.get("required")]
        if ingress_requirements and ingress_provider.get("attempted", ingress_provider.get("controller_ready")):
            health = IngressNginxProvider().collect_evidence(cfg, command, kubeconfig, env, min(15, cfg.collect_timeout_seconds))
            ingress_provider["runtime_health"] = {key: value for key, value in health.items() if key != "items"}
            ingress_provider["controller_ready"] = bool(ingress_provider.get("controller_ready") and health.get("controller_ready") and health.get("ingress_class_ready") and health.get("controller_endpoints_ready"))
            diagnostics["ingress_provider"] = ingress_provider["runtime_health"]
        phase("COLLECTING"); kinds = "deployments,statefulsets,daemonsets,replicasets,pods,services,ingresses,jobs,cronjobs,configmaps,persistentvolumeclaims,serviceaccounts,roles,rolebindings,networkpolicies,horizontalpodautoscalers,endpointslices,poddisruptionbudgets"
        resources_result = command([cfg.kubectl_binary, "get", kinds, "--namespace", namespace, "--ignore-not-found", "-o", "json", "--kubeconfig", str(kubeconfig)], cfg.collect_timeout_seconds, "resource_collection", env)
        # Cluster-scoped objects are valid workload resources now. Collect the
        # common cluster objects separately so comparison/history does not make
        # a successful ingress/RBAC chart look like it lost resources.
        cluster_kinds = "namespaces,clusterroles,clusterrolebindings,ingressclasses,customresourcedefinitions,mutatingwebhookconfigurations,validatingwebhookconfigurations,storageclasses,persistentvolumes,priorityclasses,runtimeclasses"
        cluster_result = command([cfg.kubectl_binary, "get", cluster_kinds, "--ignore-not-found", "-o", "json", "--kubeconfig", str(kubeconfig)], cfg.collect_timeout_seconds, "cluster_resource_collection", env)
        events_result = command([cfg.kubectl_binary, "get", "events", "--namespace", namespace, "-o", "json", "--kubeconfig", str(kubeconfig)], cfg.collect_timeout_seconds, "event_collection", env); secrets_result = command([cfg.kubectl_binary, "get", "secrets", "--namespace", namespace, "-o", "custom-columns=NAME:.metadata.name,TYPE:.type", "--no-headers", "--kubeconfig", str(kubeconfig)], cfg.collect_timeout_seconds, None, env)
        if resources_result.returncode:
            result["events"] = parse_observations([], _decode(events_result.stdout), max_events=cfg.max_events)["events"]
            exceeded = node_limit_event()
            if exceeded:
                exceeded.update({"configured_limit": result["resource_isolation"].get(exceeded["resource_type"], {}).get("configured_limit"), "component": f"{cluster}-control-plane", "observed_at": int(time.time())})
                result["resource_isolation"]["exceeded"] = exceeded
                return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.RESOURCE_LIMIT_EXCEEDED, f"The enforced {exceeded['resource_type']} limit was exceeded by the ephemeral kind node ({exceeded['condition']}).")
            return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.EXTERNAL_DEPENDENCY, "The ephemeral cluster stopped responding before CATS could collect workload evidence.")
        rows = _resource_rows(_decode(resources_result.stdout))
        if cluster_result.returncode == 0:
            rows.extend(_resource_rows(_decode(cluster_result.stdout)))
        for line in secrets_result.stdout.splitlines():
            parts = line.split(None, 1)
            if parts: rows.append({"kind": "Secret", "metadata": {"name": parts[0], "namespace": namespace}, "type": parts[1] if len(parts) > 1 else ""})
        unique_rows: dict[tuple[str, str, str], dict[str, Any]] = {}
        for row in rows:
            metadata = row.get("metadata") if isinstance(row.get("metadata"), Mapping) else {}
            key = (str(row.get("kind") or ""), str(metadata.get("namespace") or ""), str(metadata.get("name") or ""))
            if key[0] and key[2]:
                unique_rows.setdefault(key, row)
        rows = list(unique_rows.values())
        infrastructure = [row for row in rows if ((row.get("metadata") or {}).get("labels") or {}).get("cats.clanhq.io/validation-infrastructure") == "true"]
        diagnostics["validation_infrastructure"] = infrastructure
        # Exclude CATS scaffolding from workload counters as well as drift.
        rows = [row for row in rows if row not in infrastructure]
        observations = parse_observations(rows, _decode(events_result.stdout), max_events=cfg.max_events)
        for key in ("resource_summary", "conditions", "events", "unhealthy_resources", "observed_topology"): result[key] = observations[key]
        # Capability rows are provisional until Kubernetes supplies evidence.
        # Do not claim VERIFIED when a required provider/device capability is
        # explicitly unavailable, but do mark generic capabilities available
        # once the corresponding resource actually proves usable.
        for capability in result.get("capability_preflight", []):
            if not capability.get("required") and capability.get("capability") != "DNS / Service Discovery":
                continue
            source = str(capability.get("source_resource") or "")
            source_kind, _, source_name = source.partition("/")
            source_namespace = str(capability.get("source_namespace") or namespace)
            matching = next((row for row in rows
                             if str(row.get("kind") or "") == source_kind
                             and str((row.get("metadata") or {}).get("name") or "") == source_name
                             and (not source_namespace or str((row.get("metadata") or {}).get("namespace") or "") == source_namespace)), None)
            observed_ingress = ((matching or {}).get("status") or {}).get("loadBalancer", {}).get("ingress", []) if isinstance(matching, Mapping) else []
            if capability.get("capability") == "Node scheduling" and capability.get("source") == "validation-engine":
                scheduled = bool(result["resource_summary"].get("pods", {}).get("expected", 0) == result["resource_summary"].get("pods", {}).get("ready", 0) and not result["conditions"].get("unschedulable"))
                capability.update(status="VERIFIED" if scheduled else "UNEXERCISED", evidence={"workloads_scheduled": scheduled, "unschedulable_events": result["conditions"].get("unschedulable", 0)}, explanation="All expected workload Pods reached their kind-specific ready/completed state." if scheduled else "One or more expected workloads were not scheduled or ready.")
            elif capability.get("capability") == "ServiceAccount / RBAC":
                required_objects = [resource for resource in rendered_resources if resource.get("kind") in {"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}]
                observed_objects = [row for row in rows if row.get("kind") in {"ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}]
                observed_ids = {(row.get("kind"), (row.get("metadata") or {}).get("namespace") or source_namespace, (row.get("metadata") or {}).get("name")) for row in observed_objects}
                objects_resolved = all((resource.get("kind"), ((resource.get("metadata") or {}).get("namespace") or source_namespace), ((resource.get("metadata") or {}).get("name"))) in observed_ids for resource in required_objects)
                references_resolved = objects_resolved
                for resource in required_objects:
                    kind = str(resource.get("kind") or "")
                    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), Mapping) else {}
                    resource_namespace = str(metadata.get("namespace") or source_namespace)
                    if kind in {"RoleBinding", "ClusterRoleBinding"}:
                        role_ref = resource.get("roleRef") if isinstance(resource.get("roleRef"), Mapping) else {}
                        role_kind = str(role_ref.get("kind") or "Role")
                        role_name = str(role_ref.get("name") or "")
                        role_namespace = resource_namespace if role_kind == "Role" else ""
                        references_resolved = references_resolved and (role_kind, role_namespace, role_name) in observed_ids
                        for subject in resource.get("subjects") or []:
                            if not isinstance(subject, Mapping) or str(subject.get("kind") or "ServiceAccount") != "ServiceAccount":
                                continue
                            subject_namespace = str(subject.get("namespace") or resource_namespace)
                            references_resolved = references_resolved and ("ServiceAccount", subject_namespace, str(subject.get("name") or "")) in observed_ids
                resolved = objects_resolved and references_resolved
                capability.update(status="VERIFIED" if resolved else "UNEXERCISED", evidence={"required_objects": len(required_objects), "observed_objects": len(observed_objects), "objects_resolved": objects_resolved, "references_resolved": references_resolved}, explanation="Rendered RBAC objects, role references, and ServiceAccount subjects were observed by exact identity." if resolved else "One or more rendered RBAC objects, role references, or subjects were not observed.")
            elif capability.get("capability") == "DNS / Service Discovery":
                service_resources = [resource for resource in rendered_resources if resource.get("kind") == "Service"]
                observed_services = {(row.get("kind"), (row.get("metadata") or {}).get("namespace") or namespace, (row.get("metadata") or {}).get("name")) for row in rows if row.get("kind") == "Service"}
                expected_services = {("Service", str((resource.get("metadata") or {}).get("namespace") or namespace), str((resource.get("metadata") or {}).get("name") or "")) for resource in service_resources}
                service_objects_observed = bool(expected_services) and expected_services <= observed_services
                endpoint_services = {str(((row.get("metadata") or {}).get("labels") or {}).get("kubernetes.io/service-name")) for row in rows if row.get("kind") == "EndpointSlice"}
                endpoint_services |= {str((row.get("metadata") or {}).get("name")) for row in rows if row.get("kind") == "Endpoints"}
                endpoints_observed = all(name in endpoint_services for _, _, name in expected_services) if expected_services else False
                if capability.get("required"):
                    dns_evidence = _service_dns_probe(service_resources, rows, command=command, cfg=cfg, kubeconfig=kubeconfig, namespace=namespace, env=env)
                    dns_evidence.update({"service_objects_observed": service_objects_observed, "endpoints_observed": endpoints_observed})
                    capability.update(status="VERIFIED" if dns_evidence.get("resolved") and service_objects_observed else "UNEXERCISED", evidence=dns_evidence, explanation="Service objects and DNS names resolved from a ready workload Pod." if dns_evidence.get("resolved") and service_objects_observed else "The declared Service DNS dependency could not be fully exercised from a ready workload Pod.")
                else:
                    evidence = {"service_objects_observed": service_objects_observed, "endpoints_observed": endpoints_observed, "dns_probe_required": False}
                    capability.update(status="AVAILABLE" if service_objects_observed else "UNEXERCISED", evidence=evidence, explanation="Rendered Service objects were observed; no explicit workload DNS dependency required an in-cluster probe." if service_objects_observed else "One or more rendered Service objects were not observed.")
            elif capability.get("capability") == "NetworkPolicy":
                policies = [row for row in rows if row.get("kind") == "NetworkPolicy" and (row.get("metadata") or {}).get("namespace") == source_namespace]
                capability.update(status="AVAILABLE" if policies else "UNEXERCISED", evidence={"configuration_observed": bool(policies), "enforcement_tested": False}, explanation="NetworkPolicy configuration was accepted; traffic enforcement was not tested by this CNI sandbox.")
            elif capability.get("capability") == "HPA / Metrics API":
                hpas = [row for row in rows if row.get("kind") == "HorizontalPodAutoscaler" and (row.get("metadata") or {}).get("namespace") == source_namespace]
                targets = {(row.get("kind"), (row.get("metadata") or {}).get("name")) for row in rows if row.get("kind") in {"Deployment", "StatefulSet"}}
                hpa_resource = next((resource for resource in rendered_resources if resource.get("kind") == "HorizontalPodAutoscaler" and str((resource.get("metadata") or {}).get("namespace") or source_namespace) == source_namespace), None)
                target = ((hpa_resource or {}).get("spec") or {}).get("scaleTargetRef") if isinstance(hpa_resource, Mapping) else None
                target_resolved = bool(target and (target.get("kind"), target.get("name")) in targets)
                capability.update(status="AVAILABLE" if hpas and target_resolved else "UNEXERCISED", evidence={"hpa_observed": bool(hpas), "target_resolved": target_resolved, "metrics_observed": False, "scale_event_required": False}, explanation="HPA configuration and target were observed; no scaling event was required and metrics delivery was not claimed." if hpas and target_resolved else "HPA or its target was not fully observed.")
            elif capability.get("capability") == "Admission Webhooks":
                configs = [row for row in rows if row.get("kind") in {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}]
                service_names = {str((row.get("metadata") or {}).get("name")) for row in rows if row.get("kind") == "Service"}
                endpoint_services = {str(((row.get("metadata") or {}).get("labels") or {}).get("kubernetes.io/service-name")) for row in rows if row.get("kind") == "EndpointSlice"}
                endpoint_services |= {str((row.get("metadata") or {}).get("name")) for row in rows if row.get("kind") == "Endpoints"}
                references = [webhook.get("clientConfig", {}).get("service", {}).get("name") for item in configs for webhook in (item.get("webhooks") or []) if isinstance(webhook, Mapping)]
                services_resolved = all(not name or name in service_names for name in references)
                endpoints_resolved = all(not name or name in endpoint_services for name in references)
                resolved = bool(configs) and services_resolved and endpoints_resolved
                capability.update(status="AVAILABLE" if resolved else "UNEXERCISED", evidence={"configuration_observed": bool(configs), "referenced_services_resolved": services_resolved, "referenced_endpoints_observed": endpoints_resolved, "certificate_values_collected": False}, explanation="Admission webhook configuration, referenced Services, and EndpointSlices were correlated; private certificate material was not read." if resolved else "Admission webhook references or their backends were not fully resolved.")
            elif capability.get("capability") == "TLS / Certificate dependencies":
                secrets = {(row.get("kind"), (row.get("metadata") or {}).get("namespace"), (row.get("metadata") or {}).get("name")) for row in rows if row.get("kind") == "Secret"}
                tls_refs = [secret_name for resource in rendered_resources if resource.get("kind") == "Ingress" for item in ((resource.get("spec") or {}).get("tls") or []) if isinstance(item, Mapping) for secret_name in [item.get("secretName")] if secret_name]
                resolved = all(("Secret", source_namespace, name) in secrets for name in tls_refs)
                capability.update(status="AVAILABLE" if resolved else "UNEXERCISED", evidence={"required_secret_names": tls_refs, "references_resolved": resolved, "values_collected": False}, explanation="TLS Secret references were resolved by metadata only; private keys and values were not collected." if resolved else "One or more TLS Secret references were not observed.")
            elif capability.get("capability") == "CRDs / custom resources":
                crd = matching if source_kind == "CustomResourceDefinition" else next((row for row in rows if row.get("kind") == "CustomResourceDefinition"), None)
                established = any(str(condition.get("type")) == "Established" and str(condition.get("status")).casefold() == "true" for condition in ((crd or {}).get("status") or {}).get("conditions") or [])
                observed_custom = bool(source_kind != "CustomResourceDefinition" and matching)
                capability.update(status="AVAILABLE" if (established or observed_custom) else "UNEXERCISED", evidence={"crd_established": established, "custom_resource_observed": observed_custom, "controller_behavior_verified": False}, explanation="CRD/resource acceptance was observed; external operator behavior was not claimed." if (established or observed_custom) else "The required CRD or Custom Resource was not fully observed.")
            elif capability.get("capability") == "LoadBalancer":
                service_slices = [row for row in rows if row.get("kind") == "EndpointSlice"]
                if source_namespace != namespace:
                    # A chart may explicitly target another namespace: query
                    # its exact Service and slices, never any same-name object.
                    service_result = command([cfg.kubectl_binary, "get", "service", source_name, "--namespace", source_namespace, "-o", "json", "--kubeconfig", str(kubeconfig)], cfg.collect_timeout_seconds, "lb_explicit_namespace_service", env)
                    matching = _decode(service_result.stdout) if service_result.returncode == 0 else None
                    slice_result = command([cfg.kubectl_binary, "get", "endpointslices", "--selector", f"kubernetes.io/service-name={source_name}", "--namespace", source_namespace, "-o", "json", "--kubeconfig", str(kubeconfig)], cfg.collect_timeout_seconds, "lb_explicit_namespace_endpoints", env)
                    service_slices = _resource_rows(_decode(slice_result.stdout)) if slice_result.returncode == 0 else []
                reconcile_load_balancer(capability, matching, service_slices, lb_provider, namespace)
                service_events = command([cfg.kubectl_binary, "get", "events", "--field-selector", f"involvedObject.kind=Service,involvedObject.name={source_name}", "--namespace", source_namespace, "-o", "json", "--kubeconfig", str(kubeconfig)], min(10, cfg.collect_timeout_seconds), "lb_service_events", env)
                capability["evidence"]["events"] = parse_observations([], _decode(service_events.stdout), max_events=cfg.max_events)["events"] if service_events.returncode == 0 else []
                capability["evidence"]["event_collection"] = "COMPLETE" if service_events.returncode == 0 else "FAILED"
            elif capability.get("capability") == "Ingress":
                if source_namespace != namespace:
                    explicit_kinds = "ingress,services,endpointslices,pods"
                    explicit_result = command([
                        cfg.kubectl_binary, "get", explicit_kinds, "--namespace", source_namespace,
                        "--ignore-not-found", "-o", "json", "--kubeconfig", str(kubeconfig),
                    ], cfg.collect_timeout_seconds, "ingress_explicit_namespace_resources", env)
                    ingress_rows = _resource_rows(_decode(explicit_result.stdout)) if explicit_result.returncode == 0 else []
                else:
                    ingress_rows = rows
                reconcile_ingress(capability, ingress_rows, ingress_provider, namespace, result.get("events", []))
                if capability.get("status") == "VERIFIED":
                    result["conditions"]["unsupported_ingress"] = max(0, int(result["conditions"].get("unsupported_ingress", 0)) - 1)
                    exact_identity = f"Ingress/{source_namespace}/{source_name}"
                    result["unhealthy_resources"] = [
                        item for item in result["unhealthy_resources"]
                        if str(item.get("resource") or "") != exact_identity
                    ]
            elif capability.get("capability") == "Storage" and not capability.get("provider_specific") and result["resource_summary"].get("pvcs", {}).get("expected", 0) > 0 and result["resource_summary"].get("pvcs", {}).get("expected", 0) == result["resource_summary"].get("pvcs", {}).get("bound", 0):
                # Preserve claim-template identity and provider metadata. The
                # exact resolver below decides whether this specific claim (or
                # every StatefulSet-generated claim) is actually Bound.
                capability.setdefault("evidence", {})["aggregate_pvcs_bound"] = True
            elif capability.get("capability") == "Node scheduling":
                state = (matching or {}).get("status") or {}
                desired = int(((matching or {}).get("spec") or {}).get("replicas", 1) or 0)
                ready = bool(matching) and int(state.get("readyReplicas", 0)) >= max(1, desired)
                if source_kind == "Pod":
                    ready = bool(state.get("nodeName")) or bool(((matching or {}).get("spec") or {}).get("nodeName"))
                capability.update(status="VERIFIED" if ready else "UNEXERCISED", evidence={"observed_resource": source, "ready_replicas": state.get("readyReplicas", 0)}, explanation="Kubernetes scheduled the requested workload and its replicas became ready." if ready else "The workload did not demonstrate successful scheduling and readiness.")
        diagnostics["workload_evidence"] = resolve_capabilities(
            result["capability_preflight"], rendered_resources, rows, namespace,
        )
        if provider_lifecycle:
            manager = provider_lifecycle["manager"]
            plan = provider_lifecycle["plan"]
            context = provider_lifecycle["context"]
            provider_results = provider_lifecycle["results"]
            for provider in plan.providers:
                planned = plan.requirements_by_provider.get(provider.spec.provider_id, ())
                matching_rows = [
                    row for row in result["capability_preflight"]
                    if any(
                        str(row.get("capability") or "") == requirement.capability
                        and str(row.get("source_resource") or "") == requirement.source_resource
                        and str(row.get("source_namespace") or "") == requirement.source_namespace
                        for requirement in planned
                    )
                ]
                if planned:
                    provider_results[provider.spec.provider_id] = manager.reconcile(
                        provider, context, planned[0], {"requirements": matching_rows},
                        provider_results[provider.spec.provider_id],
                    )
            bootstrap["providers"] = {
                provider_id: provider_result.to_evidence()
                for provider_id, provider_result in provider_results.items()
            }
        unverified_cronjobs = [
            item for item in diagnostics["workload_evidence"]
            if item.get("kind") == "CronJob" and not item.get("ready")
        ]
        phase("COMPARING")
        release_names = [str(item.get("name")) for item in release_evidence if item.get("name")]
        result["comparison"] = compare_topology(
            rendered_resources, result["observed_topology"],
            default_namespace=namespace, release_names=release_names,
        )
        diagnostics["reconciliation"] = {
            "authoritative_expected_source": "helm-template",
            "template_release_names": [f"cats-validation-{index}" for index in range(1, len(charts) + 1)],
            "install_release_names": release_names,
            "namespace": namespace,
            "matcher": result["comparison"].get("matcher"),
            "expected_evidence": result["comparison"].get("expected_evidence", []),
            "observed_evidence": result["comparison"].get("observed_evidence", []),
        }
        combined = " ".join([readiness.stderr, readiness.stdout, events_result.stdout])
        if readiness.returncode or result["unhealthy_resources"]:
            exceeded = node_limit_event()
            if exceeded:
                exceeded.update({"configured_limit": result["resource_isolation"].get(exceeded["resource_type"], {}).get("configured_limit"), "component": f"{cluster}-control-plane", "observed_at": int(time.time())})
                result["resource_isolation"]["exceeded"] = exceeded
                return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.RESOURCE_LIMIT_EXCEEDED, f"The enforced {exceeded['resource_type']} limit was exceeded by the ephemeral kind node ({exceeded['condition']}).")
            classified = FailureCategory(classify_failure(combined, FailureCategory.WORKLOAD_TIMEOUT))
            if classified == FailureCategory.PRIVATE_REGISTRY_UNAVAILABLE: category = classified
            elif result["conditions"].get("crashloopbackoff"): category = FailureCategory.CRASH_LOOP
            elif result["conditions"].get("imagepullbackoff"): category = FailureCategory.IMAGE_PULL_FAILURE
            elif result["conditions"].get("insufficient_cpu"): category = FailureCategory.INSUFFICIENT_CPU
            elif result["conditions"].get("insufficient_memory"): category = FailureCategory.INSUFFICIENT_MEMORY
            elif result["conditions"].get("unschedulable"): category = FailureCategory.UNSCHEDULABLE
            elif result["conditions"].get("unsupported_ingress"): category = FailureCategory.UNSUPPORTED_INGRESS
            elif result["conditions"].get("unsupported_load_balancer"): category = FailureCategory.UNSUPPORTED_LOAD_BALANCER
            else: category = classified
            if category == FailureCategory.MISSING_STORAGE_CLASS:
                configured_classes = sorted({str((resource.get("spec") or {}).get("storageClassName")) for resource in rendered_resources if resource.get("kind") == "PersistentVolumeClaim" and (resource.get("spec") or {}).get("storageClassName")})
                event_classes = sorted(set(re.findall(r"(?i)storageclass(?:es)?(?:\.storage\.k8s\.io)?[ '\"]+([a-z0-9._-]+)", combined)))
                result["dependencies"]["missing_storage_classes"] = sorted(set(configured_classes + event_classes))
            if category in {FailureCategory.IMAGE_PULL_FAILURE, FailureCategory.PRIVATE_REGISTRY_UNAVAILABLE}:
                result["dependencies"]["unavailable_images"] = sorted({str((container or {}).get("image")) for resource in rows if resource.get("kind") == "Pod" for container in (resource.get("spec") or {}).get("containers") or [] if isinstance(container, Mapping) and container.get("image")})
            environmental = {FailureCategory.MISSING_CRD, FailureCategory.MISSING_STORAGE_CLASS, FailureCategory.IMAGE_PULL_FAILURE, FailureCategory.PRIVATE_REGISTRY_UNAVAILABLE, FailureCategory.MISSING_OPERATOR, FailureCategory.UNSUPPORTED_LOAD_BALANCER, FailureCategory.UNSUPPORTED_INGRESS, FailureCategory.EXTERNAL_DEPENDENCY}; status = ValidationStatus.PARTIALLY_VERIFIED if category in {FailureCategory.UNSUPPORTED_LOAD_BALANCER, FailureCategory.UNSUPPORTED_INGRESS, FailureCategory.MISSING_STORAGE_CLASS, FailureCategory.EXTERNAL_DEPENDENCY} else (ValidationStatus.COULD_NOT_VALIDATE if category in environmental else ValidationStatus.PARTIALLY_VERIFIED)
            ready = result["resource_summary"].get("pods", {}).get("ready", 0); expected = result["resource_summary"].get("pods", {}).get("expected", 0)
            reason = f"Helm installed successfully, but {ready}/{expected} pods became Ready before the validation timeout."
            if category == FailureCategory.OOM_KILLED:
                reason = f"Helm installed, but one or more containers were OOMKilled before the workload became Ready ({ready}/{expected} pods ready)."
            elif category == FailureCategory.INSUFFICIENT_CPU:
                reason = f"Helm installed, but Kubernetes could not schedule workload pods because of insufficient CPU ({ready}/{expected} pods ready)."
            elif category == FailureCategory.INSUFFICIENT_MEMORY:
                reason = f"Helm installed, but Kubernetes could not schedule workload pods because of insufficient memory ({ready}/{expected} pods ready)."
            if category == FailureCategory.MISSING_STORAGE_CLASS and result["dependencies"]["missing_storage_classes"]:
                reason = f"Helm installed, but required StorageClass {', '.join(result['dependencies']['missing_storage_classes'])} was not found in the ephemeral environment."
            elif category in {FailureCategory.IMAGE_PULL_FAILURE, FailureCategory.PRIVATE_REGISTRY_UNAVAILABLE} and result["dependencies"]["unavailable_images"]:
                reason = f"Helm installed, but workload images were unavailable in the configured validation environment: {', '.join(result['dependencies']['unavailable_images'])}."
            elif category == FailureCategory.UNSUPPORTED_LOAD_BALANCER:
                reason = "Helm installed successfully and Kubernetes workload evidence was collected, but generic LoadBalancer infrastructure was unavailable, so external service behavior could not be fully validated."
            elif category == FailureCategory.UNSUPPORTED_INGRESS:
                reason = "Helm installed successfully and Kubernetes workload evidence was collected, but a compatible Ingress controller was unavailable, so external routing behavior could not be fully validated."
            return finish(status, category, reason)
        unmet = [item for item in result.get("capability_preflight", []) if item.get("required") and item.get("status") in {"UNAVAILABLE", "UNSUPPORTED", "PROVIDER_SPECIFIC", "FAILED", "BLOCKED", "UNEXERCISED"}]
        if install_failures:
            first_failure = install_failures[0]
            return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory(first_failure["category"]), "Helm could not install one or more charts; Kubernetes evidence from the attempted releases was collected.")
        if unmet:
            names = ", ".join(sorted({str(item.get("capability") or "environmental capability") for item in unmet}))
            return finish(ValidationStatus.PARTIALLY_VERIFIED, FailureCategory.EXTERNAL_DEPENDENCY, f"The chart installed and workloads became Ready, but these required capabilities could not be fully validated: {names}.")
        if unverified_cronjobs:
            names = ", ".join(sorted(str(item.get("name") or "CronJob") for item in unverified_cronjobs))
            return finish(ValidationStatus.PARTIALLY_VERIFIED, FailureCategory.WORKLOAD_TIMEOUT,
                          f"The chart installed, but these CronJob resources were not confirmed as successfully configured: {names}.")
        if result["comparison"]["declared_only"]: return finish(ValidationStatus.PARTIALLY_VERIFIED, None, "The chart installed and workloads became Ready, but some expected resources were not observed.")
        return finish(ValidationStatus.VERIFIED, None, "The Helm chart installed and expected workloads became Ready in the ephemeral Kubernetes environment.")
    except TimeoutError as exc: return finish(ValidationStatus.PARTIALLY_VERIFIED if result["helm_result"]["install"] == "PASS" else ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.WORKLOAD_TIMEOUT, str(exc))
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError) as exc: return finish(ValidationStatus.COULD_NOT_VALIDATE, FailureCategory.UNKNOWN, str(exc))
    finally:
        phase("CLEANING_UP")
        def cleanup_command(argv: Sequence[str]) -> CommandResult:
            try:
                return run(argv, timeout=cfg.cleanup_timeout_seconds, env=env)
            except Exception as exc:
                return CommandResult(1, "", f"Cleanup command failed: {type(exc).__name__}")
        if create_attempted or network_attempted:
            if result.get("capability_bootstrap", {}).get("load_balancer", {}).get("attempted"):
                logger.info("LB_CLEANUP_STARTED cluster=%s", cluster)
            provider_results = provider_lifecycle.get("results", {})
            if provider_lifecycle:
                provider_results = provider_lifecycle["manager"].cleanup(
                    provider_lifecycle["plan"], provider_lifecycle["context"], provider_results,
                )
                provider_lifecycle["results"] = provider_results
            cluster_clean = True
            if create_attempted:
                cleaned = cleanup_command([cfg.kind_binary, "delete", "cluster", "--name", cluster]); listed = cleanup_command([cfg.kind_binary, "get", "clusters"]); remaining_clusters = {line.strip() for line in listed.stdout.splitlines()}; cluster_clean = cleaned.returncode == 0 and listed.returncode == 0 and cluster not in remaining_clusters; diagnostics["kind_delete"] = _diagnostic_summary(cleaned)
            network_present = cleanup_command([cfg.docker_binary, "network", "inspect", network_name]).returncode == 0
            network_removed = cleanup_command([cfg.docker_binary, "network", "rm", network_name]) if network_present else CommandResult()
            networks_listed = cleanup_command([cfg.docker_binary, "network", "ls", "--format", "{{.Name}}"])
            network_clean = network_removed.returncode == 0 and networks_listed.returncode == 0 and network_name not in {line.strip() for line in networks_listed.stdout.splitlines()}
            diagnostics["network_delete"] = _diagnostic_summary(network_removed)
            if not (cluster_clean and network_clean):
                for provider_result in provider_results.values():
                    if provider_result.cleanup_status is CleanupStatus.COMPLETE:
                        provider_result.cleanup_status = CleanupStatus.FAILED
                        provider_result.warnings.append(
                            "Provider cleanup could not be confirmed because ephemeral cluster/network teardown failed."
                        )
            provider_clean = all(
                provider_result.cleanup_status in {CleanupStatus.COMPLETE, CleanupStatus.NOT_REQUIRED}
                for provider_result in provider_results.values()
            )
            result["cleanup_status"] = "COMPLETE" if cluster_clean and network_clean and provider_clean else "FAILED"
            if isinstance(result.get("capability_bootstrap"), Mapping):
                result["capability_bootstrap"]["cleanup_status"] = result["cleanup_status"]
                result["capability_bootstrap"].get("load_balancer", {})["cleanup_status"] = result["cleanup_status"]
                result["capability_bootstrap"].get("ingress", {})["cleanup_status"] = result["cleanup_status"]
                result["capability_bootstrap"]["providers"] = {
                    provider_id: provider_result.to_evidence()
                    for provider_id, provider_result in provider_results.items()
                }
            logger.info("LB_CLEANUP_COMPLETED cluster=%s status=%s", cluster, result["cleanup_status"])
            if result["cleanup_status"] == "FAILED":
                # Cleanup is a separate operational outcome.  Keep the
                # validation status/category/reason intact so a workload
                # failure (or a verified run) is never misreported as a
                # preflight or runtime failure merely because teardown needs
                # administrator attention.
                cleanup_reason = "The ephemeral cluster or network could not be confirmed as destroyed; administrator cleanup is required."
                result["cleanup_error"] = cleanup_reason
                diagnostics["cleanup_failure"] = {
                    "reason": cleanup_reason,
                    "cluster": cluster if create_attempted else None,
                    "network": network_name if network_attempted else None,
                }
        else: result["cleanup_status"] = "NOT_REQUIRED"
        result["duration_seconds"] = max(0, round(time.monotonic() - started)); result["phase"] = "COMPLETE"; shutil.rmtree(root, ignore_errors=True)
        if progress_callback:
            try:
                progress_callback("COMPLETE")
            except Exception:
                pass


def cleanup_stale_clusters(cluster_names: Sequence[str], *, runner: CommandRunner | None = None, config: ValidationConfig | None = None) -> dict[str, Any]:
    cfg = config or ValidationConfig.from_env(); run = runner or _default_runner; cleanup_env = _command_environment(); allowed_prefix = re.sub(r"[^a-z0-9-]", "-", cfg.cluster_prefix.lower()).strip("-") + "-"; deleted: list[str] = []; failed: list[str] = []
    def safe(argv: Sequence[str]) -> CommandResult:
        try: return run(argv, timeout=cfg.cleanup_timeout_seconds, env=cleanup_env)
        except Exception as exc: return CommandResult(1, "", f"Cleanup command failed: {type(exc).__name__}")
    for name in sorted(set(cluster_names)):
        if not name.startswith(allowed_prefix) or not re.fullmatch(r"[a-z0-9-]{1,50}", name): failed.append(name); continue
        completed = safe([cfg.kind_binary, "delete", "cluster", "--name", name]); listed = safe([cfg.kind_binary, "get", "clusters"]); cluster_clean = completed.returncode == 0 and listed.returncode == 0 and name not in {line.strip() for line in listed.stdout.splitlines()}
        network_name = f"{name}-network"; inspected = safe([cfg.docker_binary, "network", "inspect", network_name])
        network_removed = safe([cfg.docker_binary, "network", "rm", network_name]) if inspected.returncode == 0 else CommandResult()
        networks_listed = safe([cfg.docker_binary, "network", "ls", "--format", "{{.Name}}"])
        network_clean = network_removed.returncode == 0 and networks_listed.returncode == 0 and network_name not in {line.strip() for line in networks_listed.stdout.splitlines()}
        (deleted if cluster_clean and network_clean else failed).append(name)
    return {"deleted": deleted, "failed": failed}


class KindDeploymentValidator:
    def __init__(self, config: ValidationConfig | None = None, runner: CommandRunner | None = None): self.config = config or ValidationConfig.from_env(); self.runner = runner
    def validate_artifact(self, artifact: ValidationArtifact, progress_callback: Callable[[str], None] | None = None) -> dict[str, Any]: return validate_artifact(artifact, config=self.config, runner=self.runner, progress_callback=progress_callback)
