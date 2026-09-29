"""Portable evidence bundles, deliberately not full environment backups.

Only schema-validated scan summaries are portable. Source files, rendered
manifests and arbitrary free-form evidence are omitted rather than pretending
that a keyword-based secret scrubber can safely certify their contents.
"""
from hashlib import sha256
from io import BytesIO
import json
from zipfile import ZipFile, ZIP_DEFLATED, BadZipFile

from .schemas import ExecutionPayload

LIMIT = 100 * 1024 * 1024
EXCLUSIONS = ["credentials and global configuration", "users, roles, group assignments and sessions",
    "Helm sources and editable artifact revisions", "rendered manifests and free-form finding evidence",
    "approval and remediation history", "custom templates and manual metadata/inventory"]


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def portable_payload(raw):
    value = ExecutionPayload.model_validate(raw).model_dump(mode="json")
    value["helm_source_files"] = {}
    value["helm_values_files"] = []
    value["service"]["groups"] = []
    value["pipeline_url"] = None
    # Overview and free-form finding evidence can embed Kubernetes Secret
    # values, registry credentials, signed URLs, or entire configuration files.
    value["service_overview"] = {}
    for finding in value["findings"]:
        finding["evidence"] = {}
    return value


def export_bundle(executions):
    payloads = [portable_payload(e.raw_payload) for e in executions]
    if not payloads:
        raise ValueError("No scan evidence to export")
    body = encode({"executions": payloads})
    if len(body) > LIMIT:
        raise ValueError("Bundle exceeds 100 MiB expanded limit")
    manifest = {"format": "cats-evidence-bundle", "schema_version": 1,
        "service_key": payloads[0]["service"]["id"],
        "versions": sorted({p["service"]["version"] for p in payloads}),
        "excluded": EXCLUSIONS,
        "files": {"evidence.json": {"sha256": sha256(body).hexdigest(), "bytes": len(body)}}}
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", encode(manifest))
        archive.writestr("evidence.json", body)
    return output.getvalue()


def parse_bundle(data):
    from .exchange_limits import bundle_bytes
    from .service_transfer import load_json
    limit = bundle_bytes()
    if len(data) > limit:
        raise ValueError("Bundle exceeds 100 MiB compressed limit")
    try:
        with ZipFile(BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) != 2 or {m.filename for m in members} != {"manifest.json", "evidence.json"}:
                raise ValueError("Bundle must contain exactly manifest.json and evidence.json")
            if sum(m.file_size for m in members) > limit + 65536 or archive.getinfo("manifest.json").file_size > 65536:
                raise ValueError("Bundle exceeds expanded limit")
            if any(m.flag_bits & 1 or ((m.external_attr >> 16) & 0o170000) not in (0, 0o100000) for m in members):
                raise ValueError("Encrypted or special archive entries are not allowed")
            manifest = load_json(archive.read("manifest.json"))
            if manifest.get("format") != "cats-evidence-bundle" or manifest.get("schema_version") != 1:
                raise ValueError("Unsupported bundle schema")
            body = archive.read("evidence.json")
        expected = manifest["files"]["evidence.json"]
        if len(body) != expected["bytes"] or sha256(body).hexdigest() != expected["sha256"]:
            raise ValueError("Bundle integrity check failed")
        raw = load_json(body)["executions"]
        if not isinstance(raw, list) or not 1 <= len(raw) <= 1000:
            raise ValueError("Bundle must contain 1–1,000 executions")
        payloads = [ExecutionPayload.model_validate(portable_payload(p)) for p in raw]
        if any(p.service.id != manifest["service_key"] or not p.fixable_only for p in payloads):
            raise ValueError("Bundle contains inconsistent service identity or unsupported evidence")
        if sorted({p.service.version for p in payloads}) != manifest["versions"]:
            raise ValueError("Manifest versions do not match evidence")
        if len({p.execution_id for p in payloads}) != len(payloads):
            raise ValueError("Bundle contains duplicate executions")
        return manifest, payloads
    except (BadZipFile, KeyError, TypeError, AttributeError, UnicodeError, RecursionError, OSError) as exc:
        raise ValueError("Malformed evidence bundle") from exc
