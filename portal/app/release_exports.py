"""Bounded Export All packaging and documentation tied to one retained scan."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile

from openpyxl import Workbook
from openpyxl.writer.excel import ExcelWriter
from sqlalchemy import select

from .architecture import build_architecture_graph
from .architecture_export import build_architecture_svg
from .helm_diagram import build_helm_diagram
from .models import DeploymentValidationRun, Execution, Service, ServiceVersion
from .overview import normalize_overview
from .purpose_exports import template_for_service, workbook_for
from .remediation_summary import _redact
from .runtime_diagnostics import startup_message


class EvidenceUnavailable(ValueError):
    """A requested export cannot truthfully be produced from retained evidence."""


def _limit():
    value = int(os.getenv("CATS_RELEASE_DOC_MAX_BYTES", str(256 * 1024 * 1024)))
    if value < 1:
        raise ValueError("CATS_RELEASE_DOC_MAX_BYTES must be positive")
    return value


class _BoundedFile:
    def __init__(self, file, limit):
        self.file, self.limit = file, limit

    def write(self, data):
        if self.file.tell() + len(data) > self.limit:
            raise ValueError("Release documentation byte limit exceeded")
        return self.file.write(data)

    def __getattr__(self, name):
        return getattr(self.file, name)


def write_export_archive(output, *, workbook_builders, evidence_builders,
                         supplemental_entries=None, manifest=None, max_bytes=None):
    """Common Export All writer. Builders map archive names to zero-arg callables.

    Workbook builders return openpyxl workbooks; evidence builders return bytes,
    strings or JSON values. Missing evidence raises EvidenceUnavailable (or HTTP
    422 for the existing download builders). A supplied manifest is recorded last.
    The caller owns output and its atomic publication/response lifecycle.
    """
    limit = _limit() if max_bytes is None else max_bytes
    entries, total = [], 0
    bounded = _BoundedFile(output, limit)
    with ZipFile(bounded, "w", ZIP_DEFLATED) as archive:
        def add(name, builder, workbook=False):
            nonlocal total
            if (not name or "/" in name or "\\" in name or name in {".", ".."}
                    or any(ord(c) < 32 for c in name)):
                raise ValueError("Unsafe documentation entry name")
            if len(entries) >= 128:
                raise ValueError("Release documentation entry limit exceeded")
            status, reason = "included", None
            try:
                value = builder()
            except Exception as exc:
                if not isinstance(exc, EvidenceUnavailable) and getattr(exc, "status_code", None) != 422:
                    raise
                reason = str(getattr(exc, "detail", exc))
                value, status = reason + "\n", "unavailable"
            actual_name = name if status == "included" else name + ".unavailable.txt"
            with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as member:
                stream = _BoundedFile(member, limit - total)
                if workbook and status == "included":
                    try:
                        # openpyxl's convenience save leaves its ZIP open when
                        # writing fails; own it here so limits fail cleanly.
                        with ZipFile(stream, "w", ZIP_DEFLATED, allowZip64=True) as xlsx:
                            ExcelWriter(value, xlsx).save()
                    finally:
                        value.close()
                elif isinstance(value, bytes):
                    stream.write(value)
                elif isinstance(value, str):
                    stream.write(value.encode("utf-8"))
                else:
                    for block in json.JSONEncoder(ensure_ascii=False, sort_keys=True).iterencode(value):
                        stream.write(block.encode("utf-8"))
                size = member.seek(0, 2)
                total += size
                digest = sha256()
                member.seek(0)
                with archive.open(actual_name, "w") as destination:
                    while block := member.read(64 * 1024):
                        digest.update(block)
                        destination.write(block)
            item = {"name": name, "archive_name": actual_name, "status": status,
                    "bytes": size, "sha256": digest.hexdigest()}
            if reason:
                item["reason"] = reason
            entries.append(item)

        for name, builder in workbook_builders.items():
            add(name, builder, True)
        for name, builder in evidence_builders.items():
            add(name, builder)
        for name, value in (supplemental_entries or {}).items():
            add(name, lambda value=value: value)
        result = {**(manifest or {}), "entries": entries.copy()}
        if manifest is not None:
            add("documentation-manifest.json", lambda: result)
    return result


_OMIT = re.compile(r"password|passwd|secret|token|credential|private.?key|api.?key|authorization|"
                   r"environment|^env$|^envfrom$|stringdata|^data$|source.?files|"
                   r"script|command|^args$|^values?$|^code$|content|manifest|annotation|^logs?$|stdout|stderr", re.I)


def _safe_evidence(value, *, max_bytes):
    """Remove executable/source bodies and credentials before any rendering.

    Persisted scan source files are intentionally not assumed secret-free.
    Bound traversal, nesting and aggregate text independently of ZIP compression.
    """
    remaining = [max_bytes, 500000]

    def visit(item, depth=0):
        remaining[1] -= 1
        if depth > 40 or remaining[1] < 0:
            raise ValueError("Release evidence structure limit exceeded")
        if isinstance(item, dict):
            if str(item.get("kind", "")).lower() == "secret":
                return {"kind": "Secret", "redacted": True}
            result = {}
            for key, child in item.items():
                if _OMIT.search(str(key)):
                    continue
                safe_key = visit(str(key), depth + 1)
                result[safe_key] = visit(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            return [visit(child, depth + 1) for child in item]
        if isinstance(item, str):
            remaining[0] -= len(item.encode("utf-8"))
            if remaining[0] < 0 or len(item) > 1024 * 1024:
                raise ValueError("Release evidence byte limit exceeded")
            return startup_message(_redact(item))
        if item is None or isinstance(item, (bool, int, float)):
            return item
        return visit(str(item), depth + 1)

    return visit(value)


def _source_rows(payload, service, version):
    common = {"service": service.name, "service_id": service.service_key,
              "service_version": version.version}
    findings = []
    for kind, key in (("Vulnerability", "findings"), ("Configuration", "policy_findings")):
        for item in payload.get(key, []):
            if not isinstance(item, dict):
                continue
            evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
            title = item.get("title") or item.get("cve") or item.get("finding") or ""
            fixed = item.get("fixed_version") or ""
            mitigation = item.get("remediation") or (f"Upgrade to {fixed}" if fixed else "")
            findings.append({**common, "finding_id": item.get("cve") or item.get("finding"),
                "finding_type": kind, "finding_title": title, "severity": item.get("severity"),
                "description": item.get("description") or evidence.get("description"),
                "package": item.get("package"), "installed_version": item.get("installed_version"),
                "fixed_version": fixed, "image_artifact": item.get("image") or item.get("target"),
                "scanner": item.get("scanner"), "mitigation": mitigation,
                "finding_status": "Observed in source scan", "item_type": kind,
                "poam_title": title, "poam_status": "Source scan recommendation"})
    overview = normalize_overview(payload.get("service_overview"))
    ports = [{**common, **{field: item.get(source) for field, source in (
        ("port", "port"), ("protocol", "protocol"), ("application", "service"),
        ("declared_by", "declared_by"), ("source_file", "source_file"), ("provenance", "provenance"))}}
        for item in overview["ports"]]
    assets, seen = [], set()
    for item in overview["artifacts"]:
        name = item.get("artifact")
        kind = item.get("type")
        assets.append({**common, "asset_type": kind, "asset_name": name,
                       "chart": name if kind == "Chart" else None,
                       "chart_version": item.get("version") if kind == "Chart" else None,
                       "image": name if kind == "Image" else None,
                       "registry": item.get("registry"), "repository": item.get("repository"),
                       "tag": item.get("version") if kind == "Image" else None,
                       "digest": item.get("digest")})
    for item in [*payload.get("findings", []), *payload.get("sbom_components", []),
                 *({"image": image} for image in payload.get("sbom_images", []))]:
        if not isinstance(item, dict) or not item.get("image"):
            continue
        identity = (item["image"], item.get("image_digest"))
        if identity in seen:
            continue
        seen.add(identity)
        assets.append({**common, "asset_type": "Container image", "asset_name": identity[0],
                       "image": identity[0], "digest": identity[1]})
    return {"poam": findings, "ppsm": ports, "asset_list": assets}


def _focused_book(rows, fields):
    book = Workbook(write_only=True)
    sheet = book.create_sheet("Evidence")
    sheet.append([heading for _, heading in fields])
    for row in rows:
        values = [row.get(key) for key, _ in fields]
        sheet.append(["'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                      else value for value in values])
    return book


def _unavailable(reason):
    raise EvidenceUnavailable(reason)


def write_documentation(db, record, auth, output_path):
    """Atomically write the documentation ZIP for record's exact source identity."""
    service = db.get(Service, record.service_id)
    execution = db.get(Execution, record.source_execution_id) if record.source_execution_id else None
    version = db.get(ServiceVersion, record.source_version_id) if record.source_version_id else None
    if (service is None or execution is None or version is None
            or execution.service_id != service.id or version.service_id != service.id
            or execution.service_version_id != version.id):
        raise ValueError("Release documentation requires a consistent source service, execution and version")
    if not auth.has("service.export", service.id):
        raise PermissionError("Service export permission required")
    limit = _limit()
    payload = _safe_evidence(execution.raw_payload or {}, max_bytes=limit)
    retained_service = payload.get("service") if isinstance(payload.get("service"), dict) else {}
    snapshot_service = SimpleNamespace(name=retained_service.get("name") or service.service_key,
        service_key=service.service_key, id=service.id, manual_version=version.version)
    snapshot_execution = SimpleNamespace(raw_payload=payload)
    rows = _source_rows(payload, snapshot_service, version)
    templates, workbooks = {}, {}
    for kind in ("ppsm", "poam", "asset_list"):
        columns, source, mode = template_for_service(db, kind, service)
        templates[kind] = {"source": source, "mode": mode, "columns": columns}
        workbooks[kind + ".xlsx"] = lambda kind=kind, columns=columns: workbook_for(
            db, snapshot_service, kind, columns, rows=rows[kind])
    workbooks["findings.xlsx"] = lambda: _focused_book(rows["poam"], [
        ("finding_type", "Type"), ("finding_id", "Finding"), ("severity", "Severity"),
        ("image_artifact", "Image or Target"), ("package", "Package"),
        ("installed_version", "Installed Version"), ("fixed_version", "Fixed Version")])
    workbooks["mitigations.xlsx"] = lambda: _focused_book(
        [row for row in rows["poam"] if row.get("mitigation")], [
            ("finding_id", "Finding"), ("service_version", "Source Version"), ("mitigation", "Mitigation")])

    def diagrams():
        if not payload.get("service_overview"):
            raise EvidenceUnavailable("No architecture evidence in the source execution")
        graph = build_architecture_graph(payload)
        output = BytesIO()
        with ZipFile(_BoundedFile(output, limit), "w", ZIP_DEFLATED) as archive:
            for view in ("all", "configuration", "containers", "flow", "network", "storage"):
                archive.writestr(f"architecture-{view}.svg", build_architecture_svg(graph, view))
            archive.writestr("helm-diagram.svg", build_helm_diagram(snapshot_service, snapshot_execution))
        return output.getvalue()

    evidence = {"diagrams.zip": diagrams,
        "sbom-components.json": lambda: {"format": "cats-retained-sbom-components-v1",
            "service": service.service_key, "execution_id": execution.execution_key,
            "components": payload["sbom_components"]} if payload.get("sbom_components") else
            _unavailable("No retained SBOM components in the source execution"),
        "cats-service.zip": lambda: _unavailable(
            "The exchange bundle cannot be scoped to this retained execution; omitted to prevent newer evidence inclusion")}
    validation_fields = ("id", "run_key", "execution_id", "artifact_revision_id", "status", "phase",
                         "artifact_type", "reason_category", "cleanup_status")
    validation_query = select(*(getattr(DeploymentValidationRun, field) for field in validation_fields)).where(
        DeploymentValidationRun.service_id == service.id,
        DeploymentValidationRun.execution_id == execution.id).order_by(DeploymentValidationRun.id).limit(101)
    validations = list(db.execute(validation_query))
    # Only bounded identity and result columns; no logs, scripts, conditions or credentials.
    validation_rows = [{field: getattr(run, field) for field in validation_fields} for run in validations[:100]]
    summary = {field: getattr(record, field, None) for field in (
        "id", "job_key", "service_id", "source_execution_id", "source_version_id", "revision_number",
        "status", "phase", "remediation_status", "delivery_status", "verification_status", "signing_status",
        "artifact_digest", "original_revision", "resulting_revision")}
    summary["candidate_validation"] = _candidate_results(getattr(record, "validation_results", {}) or {})
    changes = (getattr(record, "validation_results", {}) or {}).get("summary_of_changes") or {}
    summary["changes"] = {}
    for key in ("configuration_changes", "charts", "unresolved", "remaining_configuration_findings"):
        items = changes.get(key) or []
        if not isinstance(items, list):
            continue
        summary["changes"][key] = {"total": len(items), "truncated": len(items) > 1000,
            "items": [{field: item[field] for field in ("rule_id", "resource", "field_path", "status",
                "accepted", "source_modified", "verified", "path", "original_version", "remediated_version",
                "package_status", "publish_status", "severity") if field in item
                and (item[field] is None or isinstance(item[field], (str, int, float, bool)))}
                for item in items[:1000] if isinstance(item, dict)]}
    manifest = {"format": "cats-release-documentation-v1", "service_id": service.id,
        "service_key": service.service_key, "source_execution_id": execution.id,
        "source_execution_key": execution.execution_key, "source_version_id": version.id,
        "source_version": version.version, "scanned_at": execution.scanned_at.isoformat(),
        "source_complete": execution.complete, "templates": templates,
        "unavailable": {"operational_poam": "Mutable POAM approvals, exceptions, due dates and manual mitigations have no historical snapshot; worksheets use source scan recommendations",
            "imported_inventory": "Mutable imported inventory is not historical scan evidence"},
        "redactions": ["Source files, command/script bodies, logs, secret resources and sensitive fields omitted",
                       "Credential patterns redacted; long strings bounded to 2000 characters"],
        "validation_results_truncated": len(validations) > 100}
    for kind in ("ppsm", "poam", "asset_list"):
        if not rows[kind]:
            manifest["unavailable"][kind] = "No matching evidence in source execution; worksheet contains headings only"
    if not rows["poam"]:
        manifest["unavailable"]["findings"] = "No findings retained in source execution"
    if not any(row.get("mitigation") for row in rows["poam"]):
        manifest["unavailable"]["mitigations"] = "No remediation recommendations retained in source execution"
    if not validation_rows and not summary["candidate_validation"]:
        manifest["unavailable"]["candidate_validation"] = "No candidate validation results retained"
    supplemental = {"raw-scan-evidence.json": payload,
        "release-metadata.json": {key: manifest[key] for key in (
            "service_id", "service_key", "source_execution_id", "source_execution_key", "source_version_id",
            "source_version", "scanned_at", "source_complete")},
        "remediation-summary.json": _safe_evidence(summary, max_bytes=limit),
        "candidate-validation.json": _safe_evidence(validation_rows, max_bytes=limit)}
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".release-doc-", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            result = write_export_archive(output, workbook_builders=workbooks, evidence_builders=evidence,
                supplemental_entries=supplemental, manifest=manifest, max_bytes=limit)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        return result
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _candidate_results(value):
    """Project known result/ID fields, never echo arbitrary candidate evidence."""
    allowed = {"id", "run_id", "validation_id", "validation_run_id", "run_key", "candidate_id", "execution_id", "status",
               "phase", "passed", "success", "result", "reason_category", "checks_passed", "checks_failed"}
    def project(item, depth=0):
        if depth > 4:
            return None
        if isinstance(item, dict):
            return {key: project(child, depth + 1) for key, child in list(item.items())[:100]
                    if key in allowed or (isinstance(child, (dict, list)) and key in {"candidate", "validation", "checks", "static", "runtime", "deployment", "runtime_attempts"})}
        if isinstance(item, list):
            return [project(child, depth + 1) for child in item[:100]]
        return item if item is None or isinstance(item, (str, int, float, bool)) else None
    return project(value)
