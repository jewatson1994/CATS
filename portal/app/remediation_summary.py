"""Portable, secret-safe evidence of proposals, source edits and observed scans."""
from __future__ import annotations

from copy import deepcopy
import difflib
from hashlib import sha256
import json
import re
from typing import Any

import yaml
from .remediation_mutations import read_path, semantic_identity, MutationError
from .remediation_sources import container_path

REDACTED = "[REDACTED]"
_SENSITIVE = re.compile(r"password|passwd|secret|token|credential|private.?key|api.?key|authorization|environment|^env$|stringdata|^data$", re.I)
_CREDENTIAL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s/@]+:[^\s/@]+@|-----BEGIN [^-]*PRIVATE KEY-----", re.I)
_ASSIGNMENT = re.compile(r"(?:password|passwd|secret|token|credential|private.?key|api.?key|authorization)\s*[:=]\s*\S+", re.I)


def _path(value: str) -> str:
    value = str(value).replace("\\", "/")
    if not value or value.startswith("/") or ":" in value or any(p in {"", ".", ".."} for p in value.split("/")) or any(ord(c) < 32 for c in value):
        raise ValueError("Source paths must be safe relative paths")
    return value


def _files(files: dict) -> dict:
    result = {}
    for key, value in files.items():
        path = _path(key)
        if path in result:
            raise ValueError("Duplicate normalized source path")
        if not isinstance(value, (str, bytes)):
            raise ValueError("Source content must be text or bytes")
        result[path] = value
    return result


def _text(value: str | bytes) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        if value.get("kind") == "Secret":
            return {"kind": "Secret", "content": REDACTED}
        return {str(k): REDACTED if _SENSITIVE.search(str(k)) else _redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    if isinstance(value, str) and (_CREDENTIAL.search(value) or _ASSIGNMENT.search(value)):
        return REDACTED
    return value


def _sensitive_file(path: str, content: str | bytes) -> bool:
    text = _text(content)
    if _SENSITIVE.search(path) or _CREDENTIAL.search(text) or _ASSIGNMENT.search(text):
        return True
    try:
        docs = list(yaml.safe_load_all(text))
        return _redact(docs) != docs
    except yaml.YAMLError:
        # Templates and non-YAML files must also be checked before making a diff.
        return bool(_SENSITIVE.search(text))


def _lookup(value: Any, path: str) -> tuple[bool, Any]:
    parts = re.sub(r"^\.?(Values\.)?", "", path).split(".")
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            return False, None
        value = value[part]
    return True, deepcopy(value)


def _actual(row: dict, files: dict, resources: list) -> tuple[bool, Any]:
    mapping = row.get("source_mapping") or {}
    path = mapping.get("values_file")
    if path and mapping.get("values_key"):
        path = _path(path)
        if path in files:
            try:
                document = yaml.safe_load(_text(files[path]))
                key = mapping["values_key"]
                return read_path(document, key) if isinstance(key, list) else _lookup(document, str(key))
            except (yaml.YAMLError, MutationError):
                return False, None
    candidates = resources or []
    source_identity = None
    source_file = mapping.get("source_file") or mapping.get("template")
    if source_file and _path(source_file) in files:
        try:
            from .remediation_mutations import source_documents
            candidates = [doc for doc in source_documents(_text(files[_path(source_file)]))[0] if isinstance(doc, dict)]
            source_identity = mapping.get("source_resource_identity")
        except (yaml.YAMLError, MutationError):
            pass
    requested_identity = source_identity or row.get("resource_identity") or mapping.get("resource_identity")
    if isinstance(requested_identity, dict):
        requested_identity = [requested_identity.get("kind"), requested_identity.get("namespace", ""), requested_identity.get("name")]
    matches = []
    for resource in candidates:
        kind, namespace, name = semantic_identity(resource)
        identity = (namespace + "/" if namespace else "") + kind + "/" + name
        if (list(semantic_identity(resource)) == list(requested_identity) if isinstance(requested_identity, (list, tuple)) else identity == row.get("resource")):
            matches.append(resource)
    if len(matches) != 1:
        return False, None
    target = row.get("mutation_path") or mapping.get("mutation_path") or container_path(matches[0], str(row.get("field_path") or ""), row.get("container_name") or mapping.get("container_name"), row.get("container_type") or mapping.get("container_type"))
    try:
        return read_path(matches[0], target) if target else (False, None)
    except MutationError:
        return False, None


def build_summary(plan, before_files, after_files, validation, before_resources, after_resources) -> dict:
    """Build immutable evidence; only a completed final scan can verify resolution."""
    before_files, after_files = _files(before_files), _files(after_files)
    after = plan.get("after") or {}
    scan_complete = (after.get("policy_validation") in {"PASS", "FAIL"}
                     and isinstance(after.get("configuration_scan_findings"), list)
                     and type(after.get("configuration_findings")) is int
                     and after["configuration_findings"] == len(after["configuration_scan_findings"])
                     and (after["policy_validation"] == "PASS") == (after["configuration_findings"] == 0))
    failures = after.get("configuration_scan_findings") or []
    checks = validation.get("checks") or {}
    render_safe = all(checks[name].get("status") == "PASS"
                      for name in ("baseline_render", "change_scope", "intended_changes") if name in checks)
    rows = []
    for source in plan.get("configuration_changes", []):
        row = deepcopy(source)
        row.pop("target_options", None)
        mapping = row.get("source_mapping") or {}
        path = mapping.get("values_file") or mapping.get("template") or row.get("original_file")
        if path:
            path = _path(path)
        found, actual = _actual(row, after_files, after_resources)
        accepted = row.get("decision") in {"proposed", "custom"}
        before_found, before_actual = _actual(row, before_files, before_resources)
        operation = str(row.get("operation") or "SET").upper()
        modified = bool(accepted and path and before_files.get(path) != after_files.get(path)
                        and (before_found != found or type(before_actual) is not type(actual) or before_actual != actual))
        applied = bool(modified and (found or operation in {"REMOVE", "DELETE"}))
        # Scanner targets can be filenames rather than Kubernetes identities.
        # A remaining failure of the same rule prevents a resolution claim.
        failed = any(str(item.get("rule_id")) == str(row.get("rule_id")) for item in failures)
        matches = (not found if operation in {"REMOVE", "DELETE"} else found and type(actual) is type(row.get("new_value")) and actual == row.get("new_value"))
        verified = bool(render_safe and scan_complete and not failed and applied and matches)
        row.update(original_value=deepcopy(before_actual if before_found else row.get("original_value")), proposed_value=deepcopy(row.get("new_value")),
                   actual_value=actual, actual_value_available=found, accepted=accepted,
                   source_modified=modified, applied=applied, verified=verified,
                   status="VERIFIED" if verified else "UNRESOLVED" if not accepted or failed else "UNVERIFIED",
                   post_scan_result="PASS" if verified else "FAIL" if scan_complete and failed else "NOT VERIFIED")
        if (_SENSITIVE.search(str(row.get("field_path"))) or _SENSITIVE.search(str(mapping.get("values_key")))
                or (path and any(_sensitive_file(path, files[path]) for files in (before_files, after_files) if path in files))):
            for key in ("original_value", "proposed_value", "new_value", "actual_value"):
                row[key] = REDACTED
        rows.append(row)
    hashes = [{"path": path, "before_sha256": sha256(before_files[path].encode("utf-8") if isinstance(before_files[path], str) else before_files[path]).hexdigest() if path in before_files else None,
               "after_sha256": sha256(after_files[path].encode("utf-8") if isinstance(after_files[path], str) else after_files[path]).hexdigest() if path in after_files else None,
               "modified": before_files.get(path) != after_files.get(path)}
              for path in sorted(before_files.keys() | after_files.keys())]
    return _redact({"schema_version": 2, "job_id": plan.get("job_id"), "mode": plan.get("mode"),
                    "configuration_decisions": rows, "configuration_changes": [r for r in rows if r["applied"]], "images": deepcopy(plan.get("images", [])),
                    "charts": deepcopy(plan.get("charts", [])), "validation": deepcopy(validation),
                    "before": deepcopy(plan.get("before", {})), "after": deepcopy(after),
                    "final_configuration_scan_complete": scan_complete, "remaining_configuration_findings": deepcopy(failures), "source_files": hashes,
                    "unresolved": [deepcopy(r) for r in rows if not r["verified"]]})


def artifacts(summary, before_files, after_files) -> dict[str, str]:
    """Render audit documents; sensitive source files are entirely omitted from diff."""
    before_files, after_files = _files(before_files), _files(after_files)
    summary = _redact(deepcopy(summary))
    patch = []
    for path in sorted(before_files.keys() | after_files.keys()):
        before, after = before_files.get(path, ""), after_files.get(path, "")
        if before == after:
            continue
        if _sensitive_file(path, before) or _sensitive_file(path, after):
            patch.append(f"# {path}: sensitive file contents {REDACTED}\n")
        else:
            patch.extend(difflib.unified_diff(_text(before).splitlines(True), _text(after).splitlines(True),
                                             fromfile="a/" + path, tofile="b/" + path))
    lines = ["# Summary of changes", "", "Resolution requires evidence from the final configuration scan.", ""]
    for row in summary.get("configuration_changes", []):
        lines.append(f"- {row.get('resource', '')} / {row.get('rule_id', '')}: {row['status']}; accepted={row['accepted']}; source modified={row['source_modified']}")
        lines.append("  Original: " + json.dumps(row.get("original_value")) + "; proposed: " + json.dumps(row.get("proposed_value")) + "; actual: " + json.dumps(row.get("actual_value")))
        lines.append("  Target: " + json.dumps(row.get("resource_identity")) + "; resolution: " + str(row.get("target_resolution", "unresolved")) + "; source: " + json.dumps(row.get("source_mapping")))
        lines.append("  Reason: " + str(row.get("reason", "")) + "; actor: " + str(row.get("actor")) + "; approval: " + str(row.get("approval")))
    lines.extend(["", "## Remaining findings", ""])
    for row in summary.get("unresolved", []):
        lines.append(f"- {row.get('rule_id', '')}: {row.get('status', 'UNRESOLVED')}; {row.get('reason', '')}")
    for row in summary.get("remaining_configuration_findings", []):
        lines.append(f"- Final scan: {row.get('rule_id', '')} / {row.get('target', '')}: {row.get('title', 'Unresolved configuration finding')}")
    lines.extend(["", "## Image and chart evidence", "", "```json", json.dumps({"images": summary.get("images", []), "charts": summary.get("charts", [])}, indent=2), "```",
                  "", "## Validation", "", "```json", json.dumps(summary.get("validation", {}), indent=2), "```"])
    prefix = "documentation/remediation/"
    return {prefix + "summary-of-changes.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
            prefix + "summary-of-changes.md": "\n".join(lines) + "\n",
            prefix + "before-after.json": json.dumps({key: summary.get(key) for key in ("before", "after", "source_files", "configuration_changes", "images", "charts", "unresolved", "remaining_configuration_findings", "validation")}, indent=2, sort_keys=True) + "\n",
            prefix + "changes.patch": "".join(patch)}
