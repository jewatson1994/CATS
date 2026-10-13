"""Bounded Export All packaging and immutable release export snapshots."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile

from openpyxl.writer.excel import ExcelWriter

from .models import Execution, Service, ServiceVersion


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


def write_documentation(db, record, auth, output_path):
    """Atomically retain an Export All ZIP with current service data and templates."""
    from .service_exports import write_all

    service = db.get(Service, record.service_id)
    execution = db.get(Execution, record.source_execution_id) if record.source_execution_id else None
    version = db.get(ServiceVersion, record.source_version_id) if record.source_version_id else None
    if (service is None or execution is None or version is None
            or execution.service_id != service.id or version.service_id != service.id
            or execution.service_version_id != version.id):
        raise ValueError("Release documentation requires a consistent source service, execution and version")
    if not auth.has("service.export", service.id):
        raise PermissionError("Service export permission required")
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".release-doc-", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            result = write_all(output, service, db, auth)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        return {**result, "format": "cats-export-all-v1", "evidence_scope": "current-service-at-export",
                "service_id": service.id, "service_key": service.service_key,
                "source_execution_id": execution.id, "source_version_id": version.id}
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
