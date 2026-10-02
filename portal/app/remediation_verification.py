"""Remote sandbox verification of an immutable, assembled delivery artifact."""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from zipfile import ZipFile
import yaml

from .remediation_delivery import checked_inventory, checked_values_files
from .validator_client import validate as run_remote
from .validator_protocol import SCHEMA_VERSION, validate_package


def _images(resources):
    images = set()
    for resource in resources:
        spec = resource.get("spec") or {}
        if resource.get("kind") == "CronJob":
            spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        elif resource.get("kind") != "Pod":
            spec = ((spec.get("template") or {}).get("spec") or {})
        for container in [*(spec.get("containers") or []), *(spec.get("initContainers") or []), *(spec.get("ephemeralContainers") or [])]:
            if isinstance(container, dict) and container.get("image"):
                images.add(str(container["image"]))
    return images


def verify_delivery(record, result, validator_config, root):
    digest = result.get("materialized_digest")
    response = {"status": "not_verified", "artifact_digest": digest,
                "evidence_scope": "assembled_delivery"}
    if not validator_config or not validator_config.get("endpoint"):
        return {**response, "status": "verification_unavailable", "detail": "Remote sandbox is unavailable"}
    try:
        root_path = Path(root).resolve()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", record.job_key or ""):
            raise ValueError("Invalid candidate identity")
        expected = (root_path / record.job_key).resolve()
        path = Path(result.get("artifact_path") or "")
        if expected.parent != root_path or path.is_symlink() or not path.is_file() or path.resolve().parent != expected:
            raise ValueError("Delivery artifact unavailable")
        with path.open("rb") as stream:
            actual_digest = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        if not isinstance(digest, str) or not hmac.compare_digest(actual_digest, digest):
            raise ValueError("Delivery digest mismatch")
        with ZipFile(path) as bundle:
            names = checked_inventory(bundle)
            source_files = {name[10:]: bundle.read(name).decode("utf-8") for name in names
                            if name.startswith("candidate/") and not name.endswith("/")}
        service_key = result.get("service_key") or record.service.service_key
        values_files = checked_values_files(result.get("values_files", []), source_files)
        package = {"schema_version": SCHEMA_VERSION,
            "manifest": {"service_key": service_key, "timeout_seconds": 600,
                         "referenced_images": [], "required_capabilities": ["kind", "helm", "kubectl", "docker"]},
            "artifact": {"source_files": source_files, "values_files": values_files,
                         "declared_resources": [], "artifact_type": "REMEDIATED", "reference": digest}}
        validate_package(package)
        helm = shutil.which("helm")
        if not helm:
            return {**response, "status": "verification_unavailable", "detail": "Candidate render tool is unavailable"}
        resources = []
        with tempfile.TemporaryDirectory(prefix="cats-verification-") as temp:
            work = Path(temp)
            for relative, content in source_files.items():
                target = work / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            charts = sorted(path.parent for path in work.rglob("Chart.yaml")
                            if "charts" not in path.relative_to(work).parts[:-1])
            if not charts:
                raise ValueError("No assembled Helm candidate")
            render_bytes = 0
            for index, chart in enumerate(charts):
                args = [helm, "template", f"cats-verification-{index}", str(chart), "--include-crds"]
                for value in values_files:
                    args.extend(["--values", str(work / value)])
                rendered = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)
                render_bytes += len(rendered.stdout.encode())
                if rendered.returncode or render_bytes > 16 * 1024 * 1024:
                    raise ValueError("Candidate render unavailable")
                resources.extend(doc for doc in yaml.safe_load_all(rendered.stdout) if isinstance(doc, dict) and doc.get("kind"))
        images = _images(resources)
        delivered = {row.get("reference") for row in result.get("artifact_identities", [])
                     if row.get("kind") == "image" and row.get("identity_type") == "oci_manifest"}
        if (not resources or not delivered <= images or
                any(not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image) for image in images)):
            raise ValueError("Candidate image references are unresolved")
        package["artifact"]["declared_resources"] = resources
        package["manifest"]["referenced_images"] = sorted(images)
        validate_package(package)
        remote = run_remote(validator_config, package)
        remote_status = remote.get("status")
        allowed = {"VERIFIED", "PARTIALLY_VERIFIED", "COULD_NOT_VALIDATE", "FAILED", "ERROR", "CANCELLED", "TIMED_OUT"}
        if remote_status not in allowed:
            raise ValueError("Invalid remote verification result")
        return {**response, "status": "verified" if remote_status == "VERIFIED" else "not_verified",
                "remote_status": remote_status}
    except Exception:
        # Exception strings and remote diagnostics may include secrets or workload data.
        return {**response, "status": "not_verified", "detail": "Complete candidate verification could not be established"}
