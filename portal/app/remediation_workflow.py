"""Pure retained-remediation workflow policy and public projection helpers."""
from collections.abc import Mapping
import os


def _get(value, key, default=None):
    return value.get(key, default) if isinstance(value, Mapping) else getattr(value, key, default)


def validation_required():
    return os.getenv("CATS_REMEDIATION_REQUIRE_VALIDATION", "true").strip().lower() not in {"0", "false", "no", "off"}


def delivery_policy(record, *, validation_required):
    """Resolve candidate validation independently from permission to publish it."""
    inputs = _get(record, "workflow_inputs", {}) or {}
    evidence = (_get(record, "validation_results", {}) or {}).get("deployment") or {}
    status = str(_get(record, "verification_status", "") or "").lower()
    outcome = str(evidence.get("status") or "").upper()
    pending = status in {"queued", "running"} or outcome in {"QUEUED", "RUNNING"}
    failed = status in {"failed", "blocked"} or outcome in {"FAILED", "BLOCKED", "PARTIALLY_VERIFIED"}
    terminal = str(_get(record, "status", "")).lower() not in {"queued", "running", ""}
    resolved = terminal and not pending and bool(
        failed or outcome in {"VERIFIED", "UNAVAILABLE", "NOT_VERIFIED", "SKIPPED"}
        or status in {"verified", "unavailable", "skipped"} or inputs.get("validation_skipped")
        or (inputs.get("workflow_version") != 2 and status == "not_verified"))
    if not resolved:
        return {"resolved": False, "publish_allowed": False, "reason": "Complete candidate validation or explicitly skip it when policy permits."}
    if failed:
        return {"resolved": True, "publish_allowed": False, "reason": "Candidate validation failed; OCI publication is blocked."}
    if str(evidence.get("cleanup_status") or "").upper() in {"UNKNOWN", "FAILED", "PENDING", "RUNNING"}:
        return {"resolved": True, "publish_allowed": False, "reason": "Candidate validation cleanup is unresolved; reconcile cleanup before OCI publication."}
    if validation_required:
        service = inputs.get("service") or {}
        expected_id = service.get("id") or _get(_get(record, "service"), "service_key")
        expected_version = service.get("version") or _get(record, "original_revision")
        bound_service = evidence.get("service") or {}
        verified = (outcome == "VERIFIED" and bool(_get(record, "artifact_digest"))
                    and evidence.get("artifact_digest") == _get(record, "artifact_digest")
                    and bool(expected_id) and bool(expected_version)
                    and bound_service.get("id") == expected_id and bound_service.get("version") == expected_version)
        if not verified:
            return {"resolved": True, "publish_allowed": False, "reason": "Policy requires verified evidence for this candidate digest and service version."}
    return {"resolved": True, "publish_allowed": True, "reason": None}


def artifact_capabilities(record):
    """Use retained inventory only; polling/projection must never read artifacts."""
    inputs = _get(record, "workflow_inputs", {}) or {}
    supplied = inputs.get("artifact_capabilities")
    if isinstance(supplied, dict):
        return {mode: supplied.get(mode) is True for mode in ("download", "oci", "standard-bundle", "offline-bundle")}
    validation = _get(record, "validation_results", {}) or {}
    manifest = validation.get("candidate_manifest") or {}
    deployment = manifest.get("deployment_manifest") or validation.get("deployment_manifest") or {}
    charts = any(row.get("archive_path") or row.get("package_path") for row in manifest.get("charts", []) if isinstance(row, dict))
    images = any(row.get("archive_path") for row in manifest.get("images", []) if isinstance(row, dict))
    deployable = bool(deployment.get("deployment", {}).get("chartPath"))
    return {"download": bool(_get(record, "artifact_path")), "oci": bool(charts or images),
            "standard-bundle": deployable,
            "offline-bundle": deployable and deployment.get("validationType") == "offline-bundle"}


def _approved_plan(value):
    from .frontend import _fields
    from .remediation_summary import _redact
    result = _fields(value, ("source_execution_id", "source_version", "plan_digest"))
    fields = {
        "images": ("original", "candidate", "classification", "reason", "patch_status", "decision"),
        "charts": ("path", "name", "original_version", "remediated_version", "classification", "reason", "decision"),
        "configuration_changes": ("rule_id", "target_id", "resource", "field_path", "new_value", "original_value", "classification", "reason", "decision", "approval", "action", "finding_id", "category", "proposed_value_source"),
        "manual_review": ("rule_id", "target_id", "resource", "field_path", "classification", "reason", "title", "decision"),
    }
    for key, names in fields.items():
        result[key] = []
        for row in value.get(key) or []:
            if not isinstance(row, dict):
                continue
            projected = _fields(row, names)
            for field in ("new_value", "original_value"):
                if field in names and isinstance(row.get(field), (dict, list, str, int, float, bool)):
                    projected[field] = _redact(row[field])
            result[key].append(_redact(projected))
    before = value.get("before") or {}
    result["before"] = _fields(before, ("kev", "configuration_findings", "images", "patchable_vulnerabilities", "epss_max"))
    result["before"]["vulnerabilities"] = _fields(_get(before, "vulnerabilities", {}), ("Critical", "High", "Medium", "Low"))
    return result


def workflow_projection(record, *, validation_required=None, can=None, service_id=None,
                        signing_required=False, include_details=True):
    required = globals()["validation_required"]() if validation_required is None else validation_required
    inputs = _get(record, "workflow_inputs", {}) or {}
    policy = delivery_policy(record, validation_required=required)
    status = str(_get(record, "status", "") or "").lower()
    verification = str(_get(record, "verification_status", "") or "").lower()
    deployment = (_get(record, "validation_results", {}) or {}).get("deployment") or {}
    outcome = str(deployment.get("status") or "").upper()
    failed = verification in {"failed", "blocked"} or outcome in {"FAILED", "BLOCKED", "PARTIALLY_VERIFIED"}
    resolved = policy["resolved"]
    stage = "remediate" if status in {"queued", "running", "failed"} else "deliver" if resolved else "validate"
    delivery = str(_get(record, "delivery_status", "") or "").lower()
    state = (status if stage == "remediate" else "running" if verification in {"queued", "running"}
             or delivery in {"queued", "running", "publishing", "staged"} else "complete" if delivery in {"published", "download_ready", "delivered"} else "ready")
    result = {"stage": stage, "state": state, "validation_outcome": "failed" if failed else "verified" if verification == "verified" or outcome == "VERIFIED" else "not_verified",
              "validation_resolved": resolved, "validation_required": required}
    if not include_details:
        return result
    permitted = lambda key: bool(callable(can) and can(key, service_id))
    approved_plan = _approved_plan(inputs["approved_plan"]) if isinstance(inputs.get("approved_plan"), dict) else None
    if approved_plan is not None and isinstance(inputs.get("plan_digest"), str):
        approved_plan["plan_digest"] = inputs["plan_digest"]
    result.update(can_skip_validation=not required and stage == "validate" and state != "running" and permitted("remediation.execute"),
                  approved_plan=approved_plan,
                  remediation_mode=inputs.get("remediation_mode") if isinstance(inputs.get("remediation_mode"), str) else None,
                  publish_allowed=policy["publish_allowed"], validation_reason=policy["reason"])
    capabilities = artifact_capabilities(record)
    result["delivery_options"] = []
    for mode, label, description in (
        ("bundle", "Download candidate", "Download the retained candidate and evidence for inspection or troubleshooting."),
        ("oci", "Publish to OCI", "Publish supported retained images and charts to an OCI destination."),
        ("standard-bundle", "Standard bundle", "Create and validate a deployable Helm bundle."),
        ("offline-bundle", "Offline bundle", "Create and validate a bundle with all required images and dependencies."),
    ):
        reason = None
        if not capabilities.get("download" if mode == "bundle" else mode):
            reason = "This candidate does not contain the artifacts required for this delivery method."
        elif not permitted("artifact.publish" if mode == "oci" else "service.export"):
            reason = "Your role does not permit this delivery method."
        elif mode == "oci" and signing_required and not permitted("artifact.sign"):
            reason = "Your role does not permit required artifact signing."
        elif mode == "oci" and not policy["publish_allowed"]:
            reason = policy["reason"]
        elif mode != "bundle" and not resolved:
            reason = "Resolve candidate validation before delivery."
        result["delivery_options"].append({"mode": mode, "label": label, "description": description, "supported": capabilities.get("download" if mode == "bundle" else mode, False), "available": reason is None, "reason": reason})
    return result
