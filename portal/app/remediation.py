"""Deterministic remediation planning and validation.

The planner never mutates its input.  It produces a candidate and an audit
record; callers decide whether that candidate is promoted after validation.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
import json
import re

import yaml


AUTO = "AUTO-REMEDIABLE"
REVIEW = "REVIEW REQUIRED"
NOT_REMEDIABLE = "NOT REMEDIABLE"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value is None else [value])


def resource_identity(resource: dict[str, Any]) -> str:
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
    return f"{resource.get('kind', 'Resource')}/{metadata.get('name', 'unknown')}"


def rendered_resources(payload: dict[str, Any]) -> list[dict[str, Any]]:
    overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
    values = overview.get("rendered_resources") or payload.get("rendered_resources") or []
    return [deepcopy(item) for item in _list(values) if isinstance(item, dict) and item.get("kind")]


def source_mapping(resource: dict[str, Any], field_path: str = "") -> dict[str, Any]:
    mappings = resource.get("_cats_source_mappings")
    if isinstance(mappings, list):
        exact = next((item for item in mappings if isinstance(item, dict) and (
            item.get("field_path") == field_path or (field_path == "image" and str(item.get("field_path", "")).endswith(".image"))
        )), None)
        if exact:
            return {**exact, "ambiguous": bool(exact.get("ambiguous", not exact.get("values_key")))}
    template = resource.get("_cats_source_file") or resource.get("source_file") or resource.get("template")
    return {"template": template or None, "field_path": field_path, "values_key": None,
            "values_file": None, "ambiguous": True}


def _finding_text(finding: Any) -> str:
    return " ".join(str(getattr(finding, key, "") or "") for key in ("finding", "title", "description", "remediation")).lower()


def _rule_patch(finding: Any) -> dict[str, Any] | None:
    text = _finding_text(finding)
    rules = (
        (("allowprivilegeescalation", "allow privilege escalation"), "securityContext.allowPrivilegeEscalation", False),
        (("privileged container", "privileged is set", "privileged mode"), "securityContext.privileged", False),
        (("read only root", "readonlyrootfilesystem"), "securityContext.readOnlyRootFilesystem", True),
        (("run as non-root", "runasnonroot"), "securityContext.runAsNonRoot", True),
        (("drop all capabilities", "capabilities should be dropped", "capabilities must be dropped"), "securityContext.capabilities.drop", ["ALL"]),
    )
    for phrases, path, value in rules:
        if any(phrase in text for phrase in phrases):
            return {"field_path": path, "new_value": value}
    return None


def _find_target(resources: list[dict[str, Any]], target: str | None) -> dict[str, Any] | None:
    value = str(target or "").strip()
    kind_name = value.split(":", 1)[0].strip()
    if "/" in kind_name:
        kind, name = kind_name.rsplit("/", 1)
        matches = [item for item in resources if str(item.get("kind", "")).lower() == kind.lower()
                   and str((item.get("metadata") or {}).get("name", "")) == name]
        if len(matches) == 1:
            return matches[0]
    name = re.split(r"[/\s]", value)[-1] if value else ""
    matches = [item for item in resources if str((item.get("metadata") or {}).get("name", "")) == name]
    return matches[0] if len(matches) == 1 else None


def classify_policy_finding(finding: Any, payload: dict[str, Any]) -> dict[str, Any]:
    patch = _rule_patch(finding)
    if not patch:
        return {"classification": NOT_REMEDIABLE, "reason": "No deterministic CATS remediation rule is registered for this check."}
    resource = _find_target(rendered_resources(payload), getattr(finding, "target", None))
    if not resource:
        return {"classification": REVIEW, "reason": "The finding target does not resolve to one rendered resource.", **patch}
    mapping = source_mapping(resource, patch["field_path"])
    artifact_type = str(payload.get("artifact_type") or "helm").lower()
    source_files = payload.get("helm_source_files") or payload.get("source_files") or {}
    exact_source = bool(mapping.get("values_key") and mapping.get("values_file") and isinstance(source_files, dict)
                        and mapping.get("values_file") in source_files)
    raw_manifest = artifact_type in {"kubernetes", "manifest", "raw"} and bool(mapping.get("template"))
    classification = AUTO if exact_source or raw_manifest else REVIEW
    reason = ("The change has an exact source mapping." if exact_source else
              "The uploaded artifact is a raw manifest, so its source object is editable." if raw_manifest else
              "The rendered object identifies its Helm template, but the responsible values key is ambiguous.")
    return {"classification": classification, "reason": reason, "resource": resource_identity(resource),
            "source_mapping": mapping, **patch}


def snapshot(payload: dict[str, Any], findings: list[Any]) -> dict[str, Any]:
    severities = {name: 0 for name in ("Critical", "High", "Medium", "Low", "Unknown")}
    vulnerability_rows = [item for item in _list(payload.get("findings")) if isinstance(item, dict)]
    for finding in vulnerability_rows:
        severity = str(finding.get("severity", "Unknown") or "Unknown").title()
        severities[severity if severity in severities else "Unknown"] += 1
    resources = rendered_resources(payload)
    images = sorted({str(container.get("image")) for item in resources for container in _containers(item) if container.get("image")})
    return {"vulnerabilities": severities, "kev": sum(bool(item.get("kev")) for item in vulnerability_rows),
            "configuration_findings": len(findings), "images": len(images),
            "resources": len(resources), "resource_identities": sorted(resource_identity(item) for item in resources),
            "helm_render": "PASS" if resources else "FAIL", "policy_validation": "FAIL" if findings else "PASS",
            "deployment_validation": "NOT RUN"}


def _containers(resource: dict[str, Any]) -> list[dict[str, Any]]:
    spec = resource.get("spec") if isinstance(resource.get("spec"), dict) else {}
    if resource.get("kind") == "CronJob":
        spec = (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    elif resource.get("kind") != "Pod":
        spec = ((spec.get("template") or {}).get("spec") or {})
    return [item for item in [*_list(spec.get("containers")), *_list(spec.get("initContainers"))] if isinstance(item, dict)]


def build_plan(payload: dict[str, Any], findings: list[Any], job_key: str) -> dict[str, Any]:
    before = snapshot(payload, findings)
    changes = []
    for finding in findings:
        decision = classify_policy_finding(finding, payload)
        mapping = decision.get("source_mapping") or {}
        changes.append({"finding_id": getattr(finding, "id", None), "rule_id": getattr(finding, "finding", None),
                        "severity": getattr(finding, "severity", "Unknown"), "timestamp": datetime.now(timezone.utc).isoformat(),
                        "job_id": job_key, "original_file": mapping.get("values_file") or mapping.get("template"),
                        "original_line": mapping.get("line"), "original_path": mapping.get("values_key") or decision.get("field_path"),
                        "original_value": mapping.get("original_value"), **decision})
    after = deepcopy(before)
    applied = [item for item in changes if item["classification"] == AUTO]
    after["configuration_findings"] = max(0, before["configuration_findings"] - len(applied))
    after["policy_validation"] = "PASS" if after["configuration_findings"] == 0 else "FAIL"
    return {"schema_version": "1.0", "job_id": job_key, "before": before, "after": after,
            "configuration_changes": changes, "changed_artifacts": _changed_artifacts(changes),
            "images": image_plan(payload), "rollback_reference": payload.get("execution_id") or payload.get("commit_sha")}


def image_plan(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for resource in rendered_resources(payload):
        for container in _containers(resource):
            image = str(container.get("image") or "").strip()
            if not image:
                continue
            mapping = source_mapping(resource, "image")
            rows.append({"original": image, "candidate": None, "digest": None, "patch_status": "PENDING",
                         "classification": REVIEW,
                         "reason": "The existing patch, scan, publish, and sign worker must complete before this source change can be validated.",
                         "source_mapping": mapping, "resource": resource_identity(resource)})
    unique = {}
    for row in rows:
        unique.setdefault((row["original"], json.dumps(row["source_mapping"], sort_keys=True)), row)
    return list(unique.values())


def associate_patch_results(payload: dict[str, Any], plan: dict[str, Any], patch_records: list[Any]) -> None:
    """Attach only published immutable outputs from the existing patch worker."""
    source_files = payload.get("helm_source_files") or payload.get("source_files") or {}
    for row in plan.get("images", []):
        matches = [record for record in patch_records if getattr(record, "status", None) == "complete"
                   and getattr(record, "source_image", None) == row.get("original")]
        matches.sort(key=lambda item: getattr(item, "completed_at", None) or getattr(item, "created_at", None), reverse=True)
        for record in matches:
            summary = getattr(record, "summary", None) or {}
            immutable = summary.get("immutable_destination")
            mapping = row.get("source_mapping") or {}
            editable = (not mapping.get("ambiguous", True) and isinstance(source_files, dict)
                        and (mapping.get("values_file") or "") in source_files)
            if summary.get("delivery_status") == "delivered" and immutable and editable:
                row.update(candidate=immutable, digest=str(immutable).split("@", 1)[-1], patch_status=summary.get("patch_status"),
                           signature_status=summary.get("signature_status", "not_configured"), patch_job_id=record.job_key,
                           vulnerabilities_before=summary.get("vulnerabilities_before"), vulnerabilities_after=summary.get("vulnerabilities_after"),
                           classification=AUTO, reason="A published immutable result from the existing patch worker has an exact Helm source mapping.")
                break


def _changed_artifacts(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[str]] = {}
    for change in changes:
        mapping = change.get("source_mapping") or {}
        source = mapping.get("values_file") or mapping.get("template") or "Unresolved source"
        grouped.setdefault(source, []).append(f"{change.get('rule_id')}: {change.get('field_path')} → {change.get('new_value')}")
    return [{"path": path, "changes": values} for path, values in sorted(grouped.items())]


def static_validation(payload: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    resources = rendered_resources(payload)
    identities = [resource_identity(item) for item in resources]
    checks = {
        "yaml_parsing": {"status": "PASS", "detail": "All persisted rendered objects are parsed YAML."},
        "expected_resources": {"status": "PASS" if identities == plan["before"]["resource_identities"] else "FAIL",
                               "detail": f"{len(identities)} expected resources retained."},
        "image_references": {"status": "PASS" if all(row["original"] for row in plan["images"]) else "FAIL"},
        "source_mapping": {"status": "PASS" if all(not item.get("source_mapping", {}).get("ambiguous") for item in plan["configuration_changes"] if item["classification"] == AUTO) else "FAIL"},
        "helm_lint": {"status": "NOT RUN", "detail": "Requires a candidate chart directory."},
        "helm_template": {"status": "PASS" if resources else "FAIL", "detail": "Uses the persisted Helm render for planning."},
        "kubernetes_schema": {"status": "NOT RUN", "detail": "No configured schema validator was available."},
        "trivy_config_rescan": {"status": "NOT RUN", "detail": "Runs after a materialized candidate exists."},
        "vulnerability_rescan": {"status": "NOT RUN", "detail": "Runs after patched images exist."},
        "cats_policy": {"status": plan["after"]["policy_validation"]},
    }
    required = ["yaml_parsing", "expected_resources", "image_references", "source_mapping", "kubernetes_schema", "cats_policy", "trivy_config_rescan"]
    if str(payload.get("artifact_type") or "helm").lower() == "helm":
        required.extend(("helm_lint", "helm_template"))
    if plan.get("images"):
        required.append("vulnerability_rescan")
    return {"level": "STATIC", "status": "PASS" if all(checks[key]["status"] == "PASS" for key in required) else "FAIL",
            "required_checks": required, "checks": checks, "deployment": {"status": "NOT RUN", "detail": "No validation cluster was configured."}}


def candidate_files(payload: dict[str, Any], plan: dict[str, Any]) -> dict[str, str]:
    """Materialize changes only when the uploaded source is available and exact."""
    supplied = payload.get("helm_source_files") or payload.get("source_files") or {}
    files = {str(path): str(content) for path, content in supplied.items()} if isinstance(supplied, dict) else {}
    for change in plan.get("configuration_changes", []):
        if change.get("classification") != AUTO:
            continue
        mapping = change.get("source_mapping") or {}
        values_file, values_key = mapping.get("values_file"), mapping.get("values_key")
        if values_file and values_key and values_file in files:
            document = yaml.safe_load(files[values_file]) or {}
            cursor = document
            parts = [part for part in re.sub(r"^\.?(Values\.)?", "", str(values_key)).split(".") if part]
            for part in parts[:-1]:
                cursor = cursor.setdefault(part, {})
                if not isinstance(cursor, dict):
                    raise ValueError(f"Values path {values_key} crosses a non-object value")
            if not parts:
                raise ValueError("Empty values source path")
            cursor[parts[-1]] = deepcopy(change.get("new_value"))
            files[values_file] = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    for image in plan.get("images", []):
        if image.get("classification") != AUTO or not image.get("candidate"):
            continue
        mapping = image.get("source_mapping") or {}
        values_file, values_key = mapping.get("values_file"), mapping.get("values_key")
        if values_file and values_key and values_file in files:
            document = yaml.safe_load(files[values_file]) or {}
            cursor = document
            parts = [part for part in re.sub(r"^\.?(Values\.)?", "", str(values_key)).split(".") if part]
            for part in parts[:-1]:
                cursor = cursor.setdefault(part, {})
            cursor[parts[-1]] = image["candidate"]
            files[values_file] = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    if files:
        return files
    if str(payload.get("artifact_type") or "").lower() not in {"kubernetes", "manifest", "raw"}:
        return {}
    resources = rendered_resources(payload)
    by_identity = {resource_identity(item): item for item in resources}
    for change in plan.get("configuration_changes", []):
        if change.get("classification") != AUTO:
            continue
        resource = by_identity.get(change.get("resource"))
        if not resource:
            continue
        field = str(change.get("field_path") or "")
        if not field.startswith("securityContext."):
            continue
        keys = field.split(".")[1:]
        for container in _containers(resource):
            cursor = container.setdefault("securityContext", {})
            for key in keys[:-1]:
                cursor = cursor.setdefault(key, {})
            cursor[keys[-1]] = deepcopy(change.get("new_value"))
    return {"remediated-manifests.yaml": "---\n" + "\n---\n".join(yaml.safe_dump(item, sort_keys=False).strip() for item in resources) + "\n"}


def plan_yaml(plan: dict[str, Any]) -> str:
    return yaml.safe_dump(plan, sort_keys=False, allow_unicode=True)
