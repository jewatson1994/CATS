"""Shared offline scanner actions for Scan, Patch and candidate verification.

Acquisition is deliberately outside these actions. Tools receive only an explicit
input, an empty configuration, and retained database bytes, never a worker's
credentials, home directory, Docker socket or network access.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

from .rendering import RendererError, offline_runner
from .scanner_errors import scanner_stage
from .scanner_inputs import snapshot_digest


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity_module():
    candidates = (Path(__file__).resolve().parents[2] / "scanning-main/scripts/sbom_identity.py",
                  Path("/opt/catscan/scripts/sbom_identity.py"),
                  Path("/opt/cats/scanning/scripts/sbom_identity.py"))
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location("cats_scanner_sbom_identity", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise RendererError("Shared scanner identity implementation is unavailable", reason="file_unavailable")


def _json_output(result: dict, required: str) -> tuple[bytes, dict]:
    raw = result["stdout"].encode("utf-8")
    try:
        document = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise RendererError("Scanner returned invalid JSON evidence", reason="invalid_scanner_evidence") from exc
    if not isinstance(document, dict) or not isinstance(document.get(required), list):
        raise RendererError("Scanner returned incomplete evidence", reason="invalid_scanner_evidence")
    return raw, document


def _write(path: Path, raw: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _configuration(folder: Path) -> list[str]:
    (folder / "scanner.yaml").write_text("{}\n", encoding="utf-8")
    return ["--config", "/source/scanner.yaml"]


def _database_digest(database: Path) -> str:
    try:
        return snapshot_digest(database)
    except ValueError as exc:
        raise RendererError("Retained scanner database is unavailable",
                            reason="scanner_database_unavailable") from exc


def inventory(root: Path, destination: Path, *, image: str = "", provenance=None,
              timeout: int = 600, source_type: str = "dir", check_cancelled=None) -> dict:
    """Inventory an acquired image filesystem using the image cataloger set."""
    root, destination = Path(root), Path(destination)
    destination.unlink(missing_ok=True)
    if (source_type not in {"dir", "docker-archive", "oci-archive"}
            or not (root.is_dir() if source_type == "dir" else root.is_file())):
        raise RendererError("A materialized image filesystem or archive is required")
    target = "/inputs/rootfs" if source_type == "dir" else "/inputs/image.tar"
    with tempfile.TemporaryDirectory(prefix="cats-inventory-") as directory:
        folder = Path(directory)
        result = offline_runner("syft", [*_configuration(folder), source_type + ":" + target,
            "--override-default-catalogers", "image", "-o", "syft-json"], folder,
            read_only={root: target},
            environment={"SYFT_CHECK_FOR_APP_UPDATE": "false"}, timeout=timeout,
            max_output=128 * 1024 * 1024, check_cancelled=check_cancelled)
        raw, document = _json_output(result, "artifacts")
    _write(destination, raw)
    if image:
        _write(destination.with_suffix(".image"), image.encode("utf-8"))
    if provenance is not None:
        _write(destination.with_suffix(".provenance"), json.dumps(provenance).encode("utf-8"))
    return document


def scan_sbom(sbom_path: Path, result_path: Path, *, database: Path | None = None,
              environment: dict | None = None, only_fixed: bool = True,
              image: str | None = None, provenance=None, timeout: int = 600, check_cancelled=None) -> dict:
    """Scan a frozen native SBOM and bind both retained evidence files to bytes."""
    sbom_path, result_path = Path(sbom_path), Path(result_path)
    binding_path = result_path.with_suffix(".binding")
    with scanner_stage("evidence_publication"):
        result_path.unlink(missing_ok=True)
        binding_path.unlink(missing_ok=True)
    with scanner_stage("input_validation"):
        raw = sbom_path.read_bytes()
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise RendererError("A native Syft inventory is required", reason="invalid_scanner_input") from exc
        if not isinstance(document, dict) or not isinstance(document.get("artifacts"), list):
            raise RendererError("A native Syft inventory is required", reason="invalid_scanner_input")
        if image is None:
            sidecar = sbom_path.with_suffix(".image")
            image = sidecar.read_text(encoding="utf-8").strip() if sidecar.is_file() else ""
        if provenance is None:
            sidecar = sbom_path.with_suffix(".provenance")
            try:
                provenance = json.loads(sidecar.read_bytes()) if sidecar.is_file() else None
            except ValueError as exc:
                raise RendererError("Invalid scanner input provenance", reason="invalid_scanner_input") from exc
        binding = _identity_module().document_binding(raw, document, image, provenance)
    settings = environment if environment is not None else os.environ
    database = Path(database or settings.get("GRYPE_DB_CACHE_DIR", "/opt/catscan/grype-db"))
    with scanner_stage("database_validation"):
        database_digest = _database_digest(database)
        age = str(settings.get("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", "120h"))
        if not re.fullmatch(r"[1-9][0-9]{0,6}(?:h|m|s)", age):
            raise RendererError("Invalid scanner database age policy", reason="scanner_database_policy_invalid")
    # Preserve the trusted release/operator policy: disconnected releases can
    # explicitly retain older databases, while Grype's normal default is strict.
    validate_age = str(settings.get("GRYPE_DB_VALIDATE_AGE", "true")).lower()
    with scanner_stage("database_validation"):
        if validate_age not in {"true", "false"}:
            raise RendererError("Invalid scanner database age policy", reason="scanner_database_policy_invalid")
    with scanner_stage("input_staging"), tempfile.TemporaryDirectory(prefix="cats-grype-input-") as directory:
        folder = Path(directory)
        (folder / "inventory.json").write_bytes(raw)
        command = [*_configuration(folder), "sbom:/source/inventory.json", "--output", "json"]
        if only_fixed:
            command.append("--only-fixed")
        with scanner_stage("scanner_execution"):
            result = offline_runner("grype", command, folder,
                writable={database: "/cache/grype"}, environment={
                    "GRYPE_DB_CACHE_DIR": "/cache/grype", "GRYPE_DB_AUTO_UPDATE": "false",
                    "GRYPE_DB_REQUIRE_UPDATE_CHECK": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                    "GRYPE_DB_VALIDATE_BY_HASH_ON_START": "true", "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": age,
                    "GRYPE_DB_VALIDATE_AGE": validate_age,
                }, timeout=timeout, max_output=128 * 1024 * 1024, check_cancelled=check_cancelled)
        with scanner_stage("evidence_validation"):
            report_raw, report = _json_output(result, "matches")
    with scanner_stage("evidence_validation"):
        if _database_digest(database) != database_digest:
            raise RendererError("Bound scanner database changed during scanning", reason="scanner_database_changed")
        binding.update(image=image, scanner_report_digest=digest(report_raw),
                       scanner_database_digest=database_digest, scanner_version=result.get("version", ""),
                       scanner_database_age_policy={"validate": validate_age == "true", "max_allowed_built_age": age},
                       only_fixed=only_fixed)
    with scanner_stage("evidence_publication"):
        _write(result_path, report_raw)
        _write(binding_path, json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return report


def scan_sbom_evidence(sbom_path: Path, fixed_path: Path, full_path: Path, **options) -> dict:
    """Retain fixed-only selection and full evidence from exactly one inventory."""
    sbom_path, fixed_path, full_path = Path(sbom_path), Path(fixed_path), Path(full_path)
    outputs = (fixed_path, full_path)
    with scanner_stage("evidence_publication"):
        for path in outputs:
            path.unlink(missing_ok=True)
            path.with_suffix(".binding").unlink(missing_ok=True)
    try:
        with scanner_stage("input_staging"), tempfile.TemporaryDirectory(prefix="cats-sbom-evidence-") as directory:
            frozen = Path(directory) / "inventory.json"
            frozen.write_bytes(sbom_path.read_bytes())
            for suffix in (".image", ".provenance"):
                sidecar = sbom_path.with_suffix(suffix)
                if sidecar.is_file():
                    frozen.with_suffix(suffix).write_bytes(sidecar.read_bytes())
            fixed = scan_sbom(frozen, fixed_path, only_fixed=True, **options)
            full = scan_sbom(frozen, full_path, only_fixed=False, **options)
        with scanner_stage("evidence_validation"):
            bindings = [json.loads(path.with_suffix(".binding").read_bytes()) for path in outputs]
            if bindings[0]["scanner_database_digest"] != bindings[1]["scanner_database_digest"]:
                raise RendererError("Scanner database changed between selection and full evidence",
                                    reason="scanner_database_changed")
            if bindings[0]["sbom_digest"] != bindings[1]["sbom_digest"]:
                raise RendererError("Scanner inputs changed between selection and full evidence",
                                    reason="invalid_scanner_input")
        return {"fixed": fixed, "full": full}
    except Exception:
        for path in outputs:
            path.unlink(missing_ok=True)
            path.with_suffix(".binding").unlink(missing_ok=True)
        raise


def _trivy(source: Path, report: Path, *, mode: str, cache: Path | None,
           severity: str, skip_dirs=(), timeout: int = 600, check_cancelled=None) -> dict:
    source, report = Path(source), Path(report)
    report.unlink(missing_ok=True)
    if mode not in {"config", "rootfs"}:
        raise RendererError("Unsupported offline scanner action")
    if not source.exists():
        raise RendererError("Scanner input is unavailable")
    if not re.fullmatch(r"(?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)(?:,(?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL))*", severity):
        raise RendererError("Invalid scanner severity selection")
    cache = Path(cache or os.environ.get("TRIVY_CACHE_DIR", "/opt/catscan/trivy-cache"))
    retained = {}
    identities = {}
    for name in (("policy",) if mode == "config" else ("db", "java-db", "policy")):
        path = cache / name
        if path.is_dir():
            identities[path] = snapshot_digest(path)
            retained[path] = "/cache/" + name
    if mode == "rootfs" and not (cache / "db").is_dir():
        raise RendererError("Retained Trivy database is unavailable")
    with tempfile.TemporaryDirectory(prefix="cats-trivy-") as directory:
        folder = Path(directory)
        command = [*_configuration(folder), mode, "--format", "json", "--severity", severity,
                   "--exit-code", "0", "--cache-dir", "/cache", "--skip-version-check",
                   "--disable-telemetry", "--skip-check-update"]
        if mode == "rootfs":
            command += ["--skip-db-update", "--skip-java-db-update", "--offline-scan", "--scanners", "vuln"]
        for value in skip_dirs:
            command += ["--skip-dirs", str(value)]
        # Analyzer selection can depend on the entire basename (Dockerfile,
        # Containerfile, compose.yaml), not just a YAML or JSON extension.
        target = "/inputs/" + source.name if source.is_file() else "/inputs/target"
        command.append(target)
        result = offline_runner("trivy", command, folder,
            read_only={source: target}, writable=retained, timeout=timeout,
            max_output=128 * 1024 * 1024, check_cancelled=check_cancelled)
        raw = result["stdout"].encode("utf-8")
        document = json.loads(raw)
        if not isinstance(document, dict) or ("Results" in document and not isinstance(document["Results"], list)):
            raise RendererError("Scanner returned invalid configuration evidence")
        # Stable caller-relative paths preserve existing finding/lineage links;
        # sandbox mount paths are implementation details, not source identities.
        for item in document.get("Results", []):
            value = item.get("Target", "") if isinstance(item, dict) else ""
            if isinstance(value, str) and (value == target or value.startswith(target + "/") or value.startswith(target + " (")):
                item["Target"] = source.as_posix() + value[len(target):]
        raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    for path, identity in identities.items():
        if snapshot_digest(path) != identity:
            raise RendererError("Bound Trivy database changed during scanning")
    _write(report, raw)
    return document


def scan_configuration(source: Path, report: Path, *, cache: Path | None = None,
                       severity="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", skip_dirs=(), timeout=600) -> dict:
    return _trivy(source, report, mode="config", cache=cache, severity=severity,
                  skip_dirs=skip_dirs, timeout=timeout)


def scan_rootfs(source: Path, report: Path, *, cache: Path | None = None, timeout=600, check_cancelled=None) -> dict:
    return _trivy(source, report, mode="rootfs", cache=cache,
                  severity="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", timeout=timeout, check_cancelled=check_cancelled)


def scan_image_configuration(archive: Path, report: Path, *, tool="trivy", cache: Path | None = None,
                             severity="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", timeout=600, check_cancelled=None) -> dict:
    """Inspect acquired image configuration without registry/daemon access."""
    archive, report = Path(archive), Path(report)
    report.unlink(missing_ok=True)
    if not archive.is_file() or tool not in {"trivy", "dockle"}:
        raise RendererError("An acquired image archive and supported scanner are required")
    with tempfile.TemporaryDirectory(prefix="cats-image-config-") as directory:
        folder = Path(directory)
        retained = {}
        identities = {}
        if tool == "trivy":
            if not re.fullmatch(r"(?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)(?:,(?:UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL))*", severity):
                raise RendererError("Invalid scanner severity selection")
            cache = Path(cache or os.environ.get("TRIVY_CACHE_DIR", "/opt/catscan/trivy-cache"))
            if (cache / "policy").is_dir():
                identities[cache / "policy"] = snapshot_digest(cache / "policy")
                retained[cache / "policy"] = "/cache/policy"
            command = [*_configuration(folder), "image", "--scanners", "misconfig",
                       "--image-config-scanners", "misconfig", "--format", "json", "--severity", severity,
                       "--exit-code", "0", "--cache-dir", "/cache", "--skip-version-check",
                       "--disable-telemetry", "--skip-check-update", "--skip-db-update",
                       "--skip-java-db-update", "--offline-scan", "--input", "/inputs/image.tar"]
        else:
            command = ["--format", "json", "--exit-code", "0", "--input", "/inputs/image.tar"]
        result = offline_runner(tool, command, folder, read_only={archive: "/inputs/image.tar"},
                                writable=retained, timeout=timeout, max_output=128 * 1024 * 1024,
                                check_cancelled=check_cancelled)
        raw = result["stdout"].encode("utf-8")
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise RendererError("Scanner returned invalid image configuration evidence")
    for path, identity in identities.items():
        if snapshot_digest(path) != identity:
            raise RendererError("Bound Trivy database changed during scanning")
    _write(report, raw)
    return document
