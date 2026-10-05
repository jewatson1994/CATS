"""Locally prepared Docker-host release; no package repositories or network acquisition."""
from __future__ import annotations
import os
from pathlib import Path
import re
import uuid
from .deployment_bundle import file_digest, image_archive_identity, validate_bundle
from .validator_protocol import strict_json_loads, validate_request
from .deployment_validation import ValidationConfig

SCHEMA = "cats.managed-validator-release/v1"


def load_release(directory=None, *, verify_assets=True):
    root = Path(directory or os.getenv("CATS_MANAGED_VALIDATOR_RELEASE_DIR", ""))
    if not str(directory or os.getenv("CATS_MANAGED_VALIDATOR_RELEASE_DIR", "")):
        raise ValueError("Configure a locally prepared managed validator release")
    root = root.resolve(strict=True)
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 65536:
        raise ValueError("Invalid release manifest")
    value = strict_json_loads(manifest_path.read_bytes())
    if not isinstance(value, dict) or set(value) != {"schema_version", "cats_image", "node_image", "selftest"} or value["schema_version"] != SCHEMA:
        raise ValueError("Unsupported managed validator release")
    for key, filename in (("cats_image", "images/cats.tar"), ("node_image", "images/node.tar"), ("selftest", "selftest.zip")):
        row = value[key]
        expected = {"file", "sha256", "reference", "image_id"} if key != "selftest" else {"file", "sha256", "image_reference"}
        if key == "node_image" and isinstance(row, dict) and "base_reference" in row:
            expected.add("base_reference")
        if not isinstance(row, dict) or set(row) != expected or row["file"] != filename:
            raise ValueError("Invalid release asset declaration")
        path = root / filename
        if path.is_symlink() or path.resolve().parent != (root / filename).parent.resolve() or root not in path.resolve().parents:
            raise ValueError("Unsafe release asset")
        if not path.is_file():
            raise ValueError("Missing release asset: " + filename)
        if not verify_assets:
            continue
        if file_digest(path) != row["sha256"]:
            raise ValueError("Release asset digest mismatch: " + filename)
        if key != "selftest":
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(row["image_id"])) or image_archive_identity(path, row["reference"].split("@")[0], expected_identity=row["image_id"]) != row["image_id"]:
                raise ValueError("Release image identity mismatch")
    node = value["node_image"]
    derived_reference = "cats-kind-isolated:" + str(node["image_id"]).removeprefix("sha256:")
    if "base_reference" in node:
        if node["base_reference"] != ValidationConfig.kind_node_image or node["reference"] != derived_reference:
            raise ValueError("Isolated Kind image must declare the pinned base and its exact image identity")
    elif node["reference"] != ValidationConfig.kind_node_image:
        raise ValueError("Release must use the core's pinned Kind node image")
    if value["selftest"]["image_reference"] != value["cats_image"]["reference"]:
        raise ValueError("Self-test must use the exact CATS release image")
    if verify_assets:
        validate_bundle(root / "selftest.zip", expected_type="helm-chart", expected_digest=value["selftest"]["sha256"])
    return {**value, "_directory": str(root)}


def selftest_request(release):
    request = {"schema_version": "cats.validation/v2", "request_id": uuid.uuid4().hex,
        "validation_type": "helm-chart", "service": {"id": "managed-validator-selftest", "version": release["cats_image"]["image_id"]},
        "artifact": {"reference": "managed-validator-selftest.zip", "digest": release["selftest"]["sha256"]},
        "deployment": {"type": "helm"}, "validation_profile": "default"}
    return validate_request(request), Path(release["_directory"]) / release["selftest"]["file"]


class SelfTestError(ValueError):
    """Authored public diagnostic; never includes remote text or credentials."""


def assert_selftest(result):
    helm = result.get("helm_result") or {}
    pods = (result.get("resource_summary") or {}).get("pods") or {}
    failures = []
    categories = {
        "KIND_CREATION_FAILURE": "Kind cluster creation failed",
        "IMAGE_PULL_FAILURE": "a required container image could not be pulled",
        "HELM_CHART_INVALID": "the self-test Helm chart is invalid",
        "HELM_LINT_FAILURE": "Helm chart lint failed",
        "HELM_TEMPLATE_FAILURE": "Helm chart rendering failed",
        "HELM_INSTALL_FAILURE": "Helm installation failed",
        "WORKLOAD_TIMEOUT": "workload readiness timed out",
        "SECURITY_POLICY_VIOLATION": "the sandbox security policy rejected the workload",
        "RESOURCE_LIMIT_EXCEEDED": "sandbox resource limits were exceeded",
        "RESOURCE_LIMIT_ENFORCEMENT_UNAVAILABLE": "sandbox resource limit enforcement is unavailable",
        "ARTIFACT_INTEGRITY_FAILURE": "self-test artifact integrity verification failed",
        "INSUFFICIENT_CPU": "the sandbox has insufficient CPU",
        "INSUFFICIENT_MEMORY": "the sandbox has insufficient memory",
        "UNSCHEDULABLE": "the self-test workload could not be scheduled",
        "CRASH_LOOP": "the self-test workload repeatedly crashed",
        "OOM_KILLED": "the self-test workload ran out of memory",
        "CLEANUP_FAILURE": "sandbox cleanup failed",
    }
    category = result.get("reason_category")
    if category in categories:
        failures.append(categories[category])
    if result.get("status") != "VERIFIED":
        failures.append("validation did not finish verified")
    if helm.get("install") != "PASS":
        failures.append("Helm installation did not pass")
    if helm.get("release_status") != "DEPLOYED":
        failures.append("Helm release was not deployed")
    if helm.get("execution_mode") == "PREFLIGHTED_MANIFEST_APPLY":
        failures.append("actual Helm execution was not performed")
    if pods.get("expected") != 1 or pods.get("ready") != 1:
        failures.append("the expected self-test workload was not observed ready")
    if result.get("cleanup_status") != "COMPLETE":
        failures.append("sandbox cleanup was not confirmed complete")
    if failures:
        raise SelfTestError("Self-test failed: " + "; ".join(failures) + ".")
    return result
