"""Versioned, service-scoped relational transfer. No executable deserialization.

Export authoritative inputs; receiving instances freshly assess them.
Legacy relational bundles are projected to the same safe input-only model.
"""
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
import re
import yaml
from zipfile import ZipFile, ZIP_DEFLATED, BadZipFile

from sqlalchemy import select, DateTime, String, Integer, Boolean, JSON

from . import models as m
from .exchange_limits import bound, bundle_bytes
from .service_bundle import encode
from .schemas import ExecutionPayload

MODELS = [m.Service, m.Execution, m.Finding, m.PolicyFinding, m.ServiceImage,
    m.ServiceArtifact, m.ServiceArtifactRevision, m.FindingObservation,
    m.ExceptionRecord, m.PolicyExceptionRecord, m.PoamEntry, m.PoamHistory,
    m.WorkflowRequest, m.PoamChangeRequest, m.PatchExecution,
    m.RemediationExecution, m.DeploymentValidationRun, m.ServiceArchiveEvent,
    m.ServiceMetadata, m.InventoryRecord, m.DependencyWatchlistEntry,
    m.DependencyWatchlistMatch, m.ServiceTransferProvenance]
TABLES = {model.__tablename__: model for model in MODELS}
PORTABLE = {"services", "service_images", "service_artifacts", "service_artifact_revisions",
    "poam_entries", "poam_history", "service_archive_events", "service_metadata",
    "inventory_records"}
OWNED_BY = {
    "service_artifact_revisions": ("artifact_id", "service_artifacts"),
    "finding_observations": ("finding_id", "findings"),
    "exceptions": ("finding_id", "findings"),
    "policy_exceptions": ("policy_finding_id", "policy_findings"),
    "poam_history": ("poam_id", "poam_entries"),
    "poam_change_requests": ("workflow_id", "workflow_requests"),
}
EXCLUDED = ["global configuration and authentication material", "user accounts, sessions, role/group assignments",
    "password/token/private-key fields and detected secret-bearing source files",
    "running processes, worker job directories, container image layers and generated remediation download files",
    "global templates and watchlist enforcement configuration",
    "derived findings, executions, exceptions, watchlist matches, runtime validation and patch results"]
SECRET = re.compile(r"(?i)(password|passwd|access.?token|refresh.?token|id.?token|client.?secret|session.?secret|private.?key|api.?key|registry.?auth|database.?url|connection.?string|authorization|credential|secret.?access.?key)")


def source_documents(text):
    """Bound YAML construction and alias expansion before recursive scrubbing."""
    count, depth = 0, 0
    for item in yaml.parse(text):
        count += 1
        if isinstance(item, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
        elif isinstance(item, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1
        if count > 200000 or depth > 40:
            raise ValueError("Source YAML exceeds portability complexity limit")
    documents = list(yaml.safe_load_all(text))
    pending = [(doc, 0) for doc in documents]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > 200000 or depth > 40:
            raise ValueError("Source YAML exceeds portability expansion limit")
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("Source YAML mapping keys must be text")
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
    return documents


def scrub(value, path="", excluded=None):
    excluded = excluded if excluded is not None else []
    if isinstance(value, dict):
        if isinstance(value.get("name"), str) and SECRET.search(value["name"]) and "value" in value:
            value = {**value, "value": "[REDACTED]"}
            excluded.append(path + "/value")
        if str(value.get("kind", "")).lower() == "secret":
            excluded.append(path)
            return {k: scrub(v, path + "/" + k, excluded) for k, v in value.items() if k not in {"data", "stringData"}}
        result = {}
        for key, item in value.items():
            if SECRET.search(key) or key.lower() in {"token", "secret", "auth", "password_encrypted"}:
                excluded.append(path + "/" + key)
                continue
            result[key] = scrub(item, path + "/" + key, excluded)
        return result
    if isinstance(value, list):
        return [scrub(item, path, excluded) for item in value]
    if isinstance(value, str):
        if path.lower().endswith((".yaml", ".yml", ".json")):
            try:
                documents = source_documents(value)
                clean = [scrub(doc, path + "/document", excluded) for doc in documents]
                if clean != documents:
                    value = yaml.safe_dump_all(clean, sort_keys=False)
            except (yaml.YAMLError, RecursionError):
                # Helm templates may not be YAML until rendered. A secret-bearing
                # unparseable file cannot be safely selectively redacted.
                if SECRET.search(value) or re.search(r"(?i)\b(secret|token|auth)\s*:", value):
                    excluded.append(path)
                    return "# Excluded secret-bearing source; supply configuration locally.\n"
        if "PRIVATE KEY-----" in value or re.search(r"(?im)^\s*kind:\s*Secret\s*$", value):
            excluded.append(path)
            return "[excluded: secret-bearing content]"
        # Also cover key=value source formats and credentials in URLs.
        value = re.sub(r"(?im)^([^\n]*(?:password|passwd|client_secret|token|secret|private_key|api_key|secret_access_key)\s*[:=]\s*).+$", r"\1[REDACTED]", value)
        value = re.sub(r"(https?://)[^\s/@:]+:[^\s/@]+@", r"\1", value)
        value = re.sub(r"(?i)([?&](?:token|password|access_token|signature|sig|key)=)[^&#\s]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/_.=-]+", r"\1 [REDACTED]", value)
    return value


def schema_signature(legacy=False):
    return sha256(encode({name: [(c.name, str(c.type), c.nullable) for c in model.__table__.columns if not (legacy and name == "services" and c.name == "assessment_status")] for name, model in TABLES.items()})).hexdigest()


def record(row):
    return {c.name: (getattr(row, c.name).isoformat() if isinstance(getattr(row, c.name), datetime) else getattr(row, c.name)) for c in row.__table__.columns}


def snapshot(db, service, authoritative=False):
    records = {"services": [record(service)]}
    remaining = bound("CATS_BUNDLE_MAX_RECORDS", 100000) - 1
    # Explicit ownership paths: never infer ownership from an arbitrary JSON id.
    for model in MODELS[1:]:
        table = model.__table__
        if authoritative and table.name not in PORTABLE:
            records[table.name] = []
            continue
        if "service_id" in table.c:
            rows = db.scalars(select(model).where(model.service_id == service.id).limit(remaining + 1)).all()
        elif model is m.DependencyWatchlistEntry:
            ids = select(m.DependencyWatchlistMatch.entry_id).where(m.DependencyWatchlistMatch.service_id == service.id)
            rows = db.scalars(select(model).where(model.id.in_(ids)).limit(remaining + 1)).all()
        else:
            parent_column, parent_name = OWNED_BY[table.name]
            ids = [row["id"] for row in records[parent_name]]
            rows = db.scalars(select(model).where(getattr(model, parent_column).in_(ids)).limit(remaining + 1)).all() if ids else []
        remaining -= len(rows)
        if remaining < 0:
            raise ValueError("Service exceeds configured bundle record count")
        records[table.name] = [record(row) for row in rows]
    return records


def authoritative_records(records):
    """Detach retained input from foreign assessment identities, without DB writes."""
    result = {name: json.loads(encode(rows)) if name in PORTABLE else [] for name, rows in records.items()}
    service = result["services"][0]
    if "assessment_status" in m.Service.__table__.columns:
        service["assessment_status"] = "assessment_pending"
    for row in result["service_images"]:
        row.update(scan_status="never_scanned", scan_job_id=None, last_scanned_at=None, scan_error=None)
    for row in result["service_artifacts"]:
        row["source_execution_id"] = None
        metadata = dict(row.get("source_metadata") or {})
        if row.get("artifact_type") == "service_definition":
            components = metadata.get("components")
            if not isinstance(components, list):
                components = []
            metadata["components"] = [{**component, "status": (
                "normalized" if component.get("source_type") in {"helm", "oci"}
                and component.get("reference") and component.get("version")
                else component.get("status") if component.get("status") in {"unsupported", "unresolved"}
                else "unresolved"), "scan_job_id": None, "chart_artifact_id": None,
                "reason": None if component.get("source_type") in {"helm", "oci"}
                    and component.get("reference") and component.get("version")
                    else component.get("reason")}
                for component in components if isinstance(component, dict)]
            metadata["run_id"] = None
        else:
            metadata.pop("scan_job_id", None)
        row["source_metadata"] = metadata
    for row in result["poam_entries"]:
        refs = {key: row[key] for key in ("finding_id", "policy_finding_id") if row.get(key) is not None}
        if refs:
            row["supplemental_fields"] = {**(row.get("supplemental_fields") or {}), "imported_finding_references": refs}
        row["finding_id"] = row["policy_finding_id"] = None
    latest = max(records.get("executions", []), key=lambda r: utc(r["scanned_at"]), default=None)
    raw = latest["raw_payload"] if latest else {}
    if not service.get("manual_version") and raw.get("service", {}).get("version"):
        service["manual_version"] = raw["service"]["version"]
    # Older ingest flows retained original input only in immutable scan payloads.
    # Recover that input, never the assessment surrounding it.
    files = raw.get("helm_source_files", {})
    if files and not result["service_artifact_revisions"]:
        aid = max((r["id"] for r in result["service_artifacts"]), default=0) + 1
        stamp = latest["scanned_at"]
        result["service_artifacts"].append(dict(id=aid, service_id=service["id"], artifact_type=raw.get("artifact_type", "helm"), artifact_name="Retained original source", source_execution_id=None, source_reference=None, parent_repository_id=None, source_type="upload", chart_name=None, chart_version=None, source_metadata={"helm_values_files": raw.get("helm_values_files", []), "origin": "retained_original_input"}, last_refreshed_at=None, lifecycle_status="active", created_at=stamp, updated_at=stamp))
        result["service_artifact_revisions"].append(dict(id=1, artifact_id=aid, revision_number=1, revision_label="ORIGINAL", files=files, checksum="", immutable=True, created_by_id=None, created_at=stamp, source_metadata={"helm_values_files": raw.get("helm_values_files", [])}))
    return result


def export_service(db, service, username):
    records = snapshot(db, service, authoritative=True)
    latest_row = db.scalar(select(m.Execution).where(m.Execution.service_id == service.id).order_by(m.Execution.scanned_at.desc(), m.Execution.id.desc()).limit(1))
    records["executions"] = [record(latest_row)] if latest_row else []
    records = authoritative_records(records)
    removed = []
    actors = {}
    for name, rows in records.items():
        for row in rows:
            for c in TABLES[name].__table__.columns:
                if c.foreign_keys and next(iter(c.foreign_keys)).column.table.name == "users" and row[c.name] is not None:
                    user = db.get(m.User, row[c.name])
                    actors[str(row[c.name])] = user.username if user else "Unavailable original identity"
            if name == "remediation_executions" and row.get("artifact_path"):
                removed.append("remediation download file: " + str(row["id"]))
                row["artifact_path"] = None
            if name == "workflow_requests":
                row["bulk_group_id"] = None
            for field in ("source_reference", "artifact_reference"):
                reference = row.get(field)
                if reference and (reference.startswith(("/", "\\", "file:")) or re.match(r"^[A-Za-z]:", reference)):
                    removed.append(name + "/" + field)
                    row[field] = None
    records = scrub(records, excluded=removed)
    # Keep source filenames while excluding known secret filenames/content.
    for table, column in [("service_artifact_revisions", "files")]:
        for row in records[table]:
            row[column] = safe_sources(row[column], removed)
            row["checksum"] = sha256(json.dumps(row[column], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    for row in records["executions"]:
        raw = row["raw_payload"]
        raw["helm_source_files"] = safe_sources(raw.get("helm_source_files", {}), removed)
        raw["helm_values_files"] = [p for p in raw.get("helm_values_files", []) if p in raw["helm_source_files"]]
        if isinstance(raw.get("service"), dict):
            raw["service"]["groups"] = []
    # Service audit only. Imported audit is provenance, never re-issued as a local approval.
    record_limit = bound("CATS_BUNDLE_MAX_RECORDS", 100000)
    activity = [record(row) for row in db.scalars(select(m.AuditEvent).where(m.AuditEvent.target_type == "service", m.AuditEvent.target_id == str(service.id)).limit(record_limit + 1))]
    if len(activity) > record_limit:
        raise ValueError("Service activity exceeds configured bundle record count")
    state = {"records": records, "actors": actors, "activity": scrub(activity, excluded=removed)}
    body = encode(state)
    if len(body) > bundle_bytes():
        raise ValueError("Service bundle exceeds configured expanded-byte limit")
    versions = [records["services"][0]["manual_version"]] if records["services"][0].get("manual_version") else []
    manifest = {"format": "cats-service-bundle", "schema_version": 3,
        "semantics": "authoritative_inputs", "assessment": "fresh_assessment",
        "compatibility": {"relational_schema": schema_signature(), "application": "CATS 2.x"},
        "exported_at": datetime.now(timezone.utc).isoformat(), "exported_by": username,
        "service_key": service.service_key, "service_name": service.name,
        "current_version": records["services"][0].get("manual_version"),
        "versions": versions, "included": list(records), "excluded": EXCLUDED,
        "redactions": removed, "counts": {k: len(v) for k, v in records.items()},
        "warning": "Import restores service inputs and enters Assessment Pending. Run a fresh local assessment. Credentials, trust configuration and image layers must be supplied locally; generated assessment output is intentionally excluded. Hashes are not signatures.",
        "files": {"service.json": {"bytes": len(body), "sha256": sha256(body).hexdigest()}}}
    manifest_body = encode(manifest)
    if len(manifest_body) > 65536:
        raise ValueError("Service bundle manifest exceeds 64 KiB; reduce retained redaction detail")
    # Never emit a bundle that this installation itself cannot import.
    validate_state(load_json(body), manifest)
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest_body)
        archive.writestr("service.json", body)
    if output.tell() > bundle_bytes():
        raise ValueError("Service bundle exceeds configured compressed-byte limit")
    return output.getvalue()


def safe_sources(files, excluded):
    if not isinstance(files, dict) or any(not isinstance(p, str) or not isinstance(c, str) for p, c in files.items()):
        raise ValueError("Source files must map relative paths to text")
    result = {}
    for path, content in files.items():
        if not path or any(p in {"", ".", ".."} for p in path.split("/")) or path.startswith(("/", "\\")) or "\\" in path or ":" in path or "\x00" in path:
            raise ValueError("Unsafe retained source path")
        if any(part == ".env" or SECRET.search(part) or "secret" in part.lower() for part in path.split("/")):
            excluded.append("source:" + path)
            continue
        result[path] = scrub(content, path, excluded)
    return result


def load_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON value")))
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 40 or nodes > bound("CATS_BUNDLE_MAX_JSON_NODES", 2000000):
            raise ValueError("Bundle JSON complexity exceeds configured limit")
        if isinstance(item, dict):
            stack.extend((x, depth + 1) for x in item.values())
        elif isinstance(item, list):
            stack.extend((x, depth + 1) for x in item)
    return value


def parse_service(data):
    if len(data) > bundle_bytes():
        raise ValueError("Bundle exceeds configured compressed-byte limit")
    try:
        with ZipFile(BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) != 2 or {x.filename for x in members} != {"manifest.json", "service.json"}:
                raise ValueError("Expected exactly manifest.json and service.json")
            if any(x.flag_bits & 1 or ((x.external_attr >> 16) & 0o170000) not in (0, 0o100000) for x in members):
                raise ValueError("Encrypted or special archive members are not supported")
            if sum(x.file_size for x in members) > bundle_bytes() + 65536 or archive.getinfo("manifest.json").file_size > 65536:
                raise ValueError("Bundle exceeds expanded-byte limit")
            manifest = load_json(archive.read("manifest.json"))
            signatures = {schema_signature()}
            if manifest.get("schema_version") == 2:
                signatures.add(schema_signature(legacy=True))
            if manifest["format"] != "cats-service-bundle" or manifest["schema_version"] not in {2, 3} or manifest["compatibility"]["relational_schema"] not in signatures:
                raise ValueError("Unsupported bundle format/schema or incompatible CATS schema")
            body = archive.read("service.json")
            if manifest["files"] != {"service.json": {"bytes": len(body), "sha256": sha256(body).hexdigest()}}:
                raise ValueError("Bundle integrity check failed")
        state = load_json(body)
        if manifest["schema_version"] == 2 and "assessment_status" in m.Service.__table__.columns:
            for service in state["records"]["services"]:
                service.setdefault("assessment_status", "assessment_pending")
        validate_state(state, manifest)
        return manifest, state
    except (BadZipFile, KeyError, TypeError, AttributeError, UnicodeError, RecursionError, OSError) as exc:
        raise ValueError("Malformed service bundle") from exc


def validate_state(state, manifest):
    if not isinstance(state, dict) or not isinstance(state.get("records"), dict) or not isinstance(state.get("actors", {}), dict) or not isinstance(state.get("activity", []), list):
        raise ValueError("Invalid service state structure")
    records = state["records"]
    if any(not isinstance(rows, list) for rows in records.values()):
        raise ValueError("Record categories must be lists")
    if len(state.get("activity", [])) > bound("CATS_BUNDLE_MAX_RECORDS", 100000):
        raise ValueError("Bundle activity exceeds configured record count")
    if set(records) != set(TABLES) or len(records["services"]) != 1:
        raise ValueError("Missing or unsupported record categories")
    if manifest.get("schema_version") == 3 and any(rows for name, rows in records.items() if name not in PORTABLE):
        raise ValueError("Authoritative input bundles cannot include derived assessment tables")
    if sum(len(rows) for rows in records.values()) > bound("CATS_BUNDLE_MAX_RECORDS", 100000):
        raise ValueError("Bundle exceeds configured record count")
    identities = {}
    for name, rows in records.items():
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("Records must be lists of objects")
        model = TABLES[name]
        ids = set()
        uniques = {}
        for row in rows:
            if set(row) != set(model.__table__.columns.keys()):
                raise ValueError("Unsupported or missing fields in " + name)
            pk = row.get("id", row.get("service_id"))
            if not isinstance(pk, int) or isinstance(pk, bool) or pk <= 0 or pk in ids:
                raise ValueError("Duplicate/invalid domain identifier in " + name)
            ids.add(pk)
            for column in model.__table__.columns:
                value = row[column.name]
                if value is None:
                    if not column.nullable:
                        raise ValueError("Missing required field " + name + "." + column.name)
                    continue
                if isinstance(column.type, Boolean) and not isinstance(value, bool):
                    raise ValueError("Invalid boolean")
                if isinstance(column.type, Integer) and (not isinstance(value, int) or isinstance(value, bool)):
                    raise ValueError("Invalid integer")
                if isinstance(column.type, String) and (not isinstance(value, str) or (column.type.length and len(value) > column.type.length)):
                    raise ValueError("Invalid or oversized text")
                if isinstance(column.type, DateTime):
                    datetime.fromisoformat(value)
                if isinstance(column.type, JSON):
                    expected = list if column.name in {"classification_reasons", "capability_preflight", "events", "unhealthy_resources", "security_policy_violations", "warnings", "changed_artifacts", "patched_images", "configuration_changes", "logs"} else dict
                    if not isinstance(value, expected):
                        raise ValueError("Invalid JSON shape in " + name + "." + column.name)
            for constraint in model.__table__.constraints:
                if constraint.__class__.__name__ == "UniqueConstraint":
                    key = tuple(row[c.name] for c in constraint.columns)
                    if None not in key:
                        seen = uniques.setdefault(tuple(c.name for c in constraint.columns), set())
                        if key in seen:
                            raise ValueError("Duplicate domain identity in " + name)
                        seen.add(key)
        identities[name] = ids
    sid = records["services"][0]["id"]
    artifact_revisions = {(r["artifact_id"], r["revision_number"]) for r in records["service_artifact_revisions"]}
    for name, rows in records.items():
        for row in rows:
            if "service_id" in row and row["service_id"] != sid:
                raise ValueError("Cross-service record rejected")
            for c in TABLES[name].__table__.columns:
                if c.foreign_keys and row[c.name] is not None:
                    parent = next(iter(c.foreign_keys)).column.table.name
                    if parent in identities and row[c.name] not in identities[parent]:
                        raise ValueError("Dangling cross-record reference")
                    if parent == "groups":
                        raise ValueError("Group assignments cannot be imported")
            if name == "service_artifact_revisions":
                safe_sources(row["files"], [])
            if name in {"service_artifacts", "deployment_validation_runs"}:
                reference = row.get("source_reference") or row.get("artifact_reference")
                if reference and (reference.startswith(("/", "\\", "file:")) or re.match(r"^[A-Za-z]:", reference)):
                    raise ValueError("Host source references cannot be imported")
            if name == "remediation_executions" and row["artifact_path"]:
                raise ValueError("Host file paths cannot be imported")
            if name == "deployment_validation_runs" and (row.get("artifact_reference") or "").startswith("artifact:"):
                match = re.fullmatch(r"artifact:(\d+):r(\d+)", row["artifact_reference"])
                if not match or (int(match[1]), int(match[2])) not in artifact_revisions:
                    raise ValueError("Invalid validation artifact revision reference")
            if name == "remediation_executions" and row["finding_id"] is not None:
                parent = {"configuration": "policy_findings", "vulnerability": "findings"}.get(row["finding_type"])
                if parent is None or row["finding_id"] not in identities[parent]:
                    raise ValueError("Invalid remediation finding reference")
            if name == "executions":
                payload = ExecutionPayload.model_validate(row["raw_payload"])
                safe_sources(payload.helm_source_files, [])
                if payload.service.id != records["services"][0]["service_key"] or utc(payload.scanned_at) != utc(row["scanned_at"]):
                    raise ValueError("Execution evidence identity/time mismatch")
    if manifest["counts"] != {k: len(v) for k, v in records.items()} or manifest["service_key"] != records["services"][0]["service_key"]:
        raise ValueError("Manifest counts/identity mismatch")
    keys = [r["execution_key"] for r in records["executions"]]
    if len(set(keys)) != len(keys):
        raise ValueError("Duplicate executions")


def fingerprint(raw):
    value = scrub(json.loads(encode(raw)))
    value["helm_source_files"] = safe_sources(value.get("helm_source_files", {}), [])
    value["helm_values_files"] = [p for p in value.get("helm_values_files", []) if p in value["helm_source_files"]]
    value = ExecutionPayload.model_validate(value).model_dump(mode="json")
    value.pop("execution_id", None)
    if isinstance(value.get("service"), dict):
        value["service"].pop("id", None)
        value["service"].pop("groups", None)
    return sha256(encode(value)).hexdigest()


def import_phase(name):
    """Failure-injection seam; no side effects."""


def restore_service(db, state, target_key, importer_id):
    records = authoritative_records(state["records"])
    mapping = {}
    deferred = []
    execution_keys = {r["execution_key"]: "transfer-" + sha256((target_key + r["execution_key"]).encode()).hexdigest() for r in records["executions"]}
    for model in MODELS:
        name = model.__tablename__
        for original in sorted(records[name], key=lambda r: r.get("id", 0)):
            values = dict(original)
            old_id = values.pop("id", values.get("service_id"))
            for column in model.__table__.columns:
                if column.name not in values:
                    continue
                value = values[column.name]
                if isinstance(column.type, DateTime) and value:
                    values[column.name] = datetime.fromisoformat(value)
                if column.foreign_keys and value is not None:
                    parent = next(iter(column.foreign_keys)).column.table.name
                    if parent == "users":
                        values[column.name] = None if column.nullable else importer_id
                    elif parent == "groups":
                        values[column.name] = None
                    elif (parent, value) in mapping:
                        values[column.name] = mapping[parent, value]
                    elif column.nullable:
                        values[column.name] = None
                        deferred.append((name, old_id, column.name, parent, value))
                    else:
                        raise ValueError("Unresolved required reference")
            if name == "services":
                values["service_key"] = target_key
            if name == "executions":
                values["execution_key"] = execution_keys[original["execution_key"]]
                values["raw_payload"] = json.loads(encode(values["raw_payload"]))
                values["raw_payload"].setdefault("service", {})["id"] = target_key
            for field in ("source_reference", "artifact_reference"):
                if values.get(field) in execution_keys:
                    values[field] = execution_keys[values[field]]
            for field in ("job_key", "run_key"):
                if field in values:
                    values[field] = sha256((target_key + values[field]).encode()).hexdigest()
            if name == "dependency_watchlist_entries":
                values["enabled"] = False  # portable evidence must not alter global enforcement
            if name == "remediation_executions" and values["finding_id"] is not None:
                parent = {"configuration": "policy_findings", "vulnerability": "findings"}[values["finding_type"]]
                values["finding_id"] = mapping[parent, values["finding_id"]]
            if name in {"patch_executions", "remediation_executions"} and values["status"].lower() in {"queued", "running"}:
                values["status"] = "failed"
                values["phase"] = "imported_evidence"
            if name == "deployment_validation_runs":
                if values["status"] not in {"VERIFIED", "PARTIALLY_VERIFIED", "COULD_NOT_VALIDATE", "NOT_ATTEMPTED", "FAILED", "ERROR", "CANCELLED", "TIMED_OUT"}:
                    values["status"] = "NOT_ATTEMPTED"
                    values["phase"] = "IMPORTED_EVIDENCE"
                values["cleanup_status"] = "NOT_STARTED"
                values["cluster_name"] = None
            row = model(**values)
            db.add(row)
            db.flush()
            mapping[name, old_id] = row.service_id if name == "service_metadata" else row.id
        import_phase(name)
    for name, old_id, column, parent, value in deferred:
        setattr(db.get(TABLES[name], mapping[name, old_id]), column, mapping[parent, value])
    for original in state["records"]["service_artifacts"]:
        if original.get("artifact_type") != "helm_chart":
            continue
        source_id = (original.get("source_metadata") or {}).get("definition_artifact_id")
        if source_id is not None:
            local = mapping.get(("service_artifacts", source_id)) if isinstance(source_id, int) and not isinstance(source_id, bool) else None
            artifact = db.get(m.ServiceArtifact, mapping["service_artifacts", original["id"]])
            metadata = dict(artifact.source_metadata or {})
            if local is None:
                metadata.pop("definition_artifact_id", None)
            else:
                metadata["definition_artifact_id"] = local
            artifact.source_metadata = metadata
    for original in records["deployment_validation_runs"]:
        reference = original.get("artifact_reference") or ""
        match = re.fullmatch(r"artifact:(\d+):r(\d+)", reference)
        if match:
            local_id = mapping.get(("service_artifacts", int(match[1])))
            if local_id is None:
                raise ValueError("Invalid validation artifact reference")
            db.get(m.DeploymentValidationRun, mapping["deployment_validation_runs", original["id"]]).artifact_reference = f"artifact:{local_id}:r{match[2]}"
    service = db.get(m.Service, mapping["services", records["services"][0]["id"]])
    # Imported provenance is informational; local user IDs never identify foreign approvers.
    db.add(m.ServiceTransferProvenance(service_id=service.id, detail={"actors": state.get("actors", {}), "activity": state.get("activity", []), "original_records": {name: [{k: v for k, v in row.items() if k.endswith("_by_id") or k in {"actor_user_id", "id", "status", "phase", "cleanup_status", "cluster_name"}} for row in rows] for name, rows in records.items() if name != "service_transfer_provenance"}}))
    db.flush()
    return service


def utc(value):
    value = datetime.fromisoformat(value) if isinstance(value, str) else value
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def plan_history(db, state, service):
    existing = db.scalars(select(m.Execution).where(m.Execution.service_id == service.id)).all()
    known = {fingerprint(row.raw_payload) for row in existing}
    for provenance in db.scalars(select(m.ServiceTransferProvenance).where(m.ServiceTransferProvenance.service_id == service.id)):
        known.update(fingerprint(row["raw_payload"]) for row in provenance.detail.get("historical_executions", []))
    latest = max((utc(row.scanned_at) for row in existing), default=None)
    planned, duplicates = [], 0
    for original in state["records"]["executions"]:
        key = fingerprint(original["raw_payload"])
        if key in known:
            duplicates += 1
            continue
        if latest is None or utc(original["scanned_at"]) >= latest:
            raise ValueError("Historical evidence must precede the current latest execution")
        planned.append(original)
        known.add(key)
    return planned, duplicates


def add_history(db, state, service):
    planned, _ = plan_history(db, state, service)
    if planned:
        db.add(m.ServiceTransferProvenance(service_id=service.id, detail={"historical_executions": scrub(json.loads(encode(planned))), "assessment_role": "informational_only"}))
    db.flush()
    import_phase("history")
    return len(planned)
