"""Explicit governance and remediation DTOs; never serialize ORM internals."""
from .frontend_governance import entry, service
from .remediation_summary import _redact


def project_remediations(data, name, context, can, formatters):
    from .frontend import _field, _fields, _formatted, _scalar
    date = lambda value: _formatted(value, formatters.get("cats_date"))
    timestamp = lambda value: _formatted(value, formatters.get("cats_datetime"))
    def permission(key, service_id):
        data.setdefault("can", {}).setdefault(key, {})[str(service_id)] = bool(can(key, service_id)) if callable(can) else False
    data.update(_fields(context, ("tab", "can_remediate", "can_create_poam", "remediation_enabled", "page", "page_count", "total_items", "pagination_base", "request_type_filter")))
    data["return_to"] = data["next_path"]
    data["service"] = service(context.get("service") or _field(context.get("view", {}), "service"))
    sid = data["service"].get("id")
    for key in ("poam.review", "exception.revoke", "remediation.execute", "service.export"):
        permission(key, sid)
    data["services"] = [service(item) for item in context.get("services", [])]
    data["poam_services"] = [service(item) for item in context.get("poam_services", [])]
    data["summary"] = _fields(context.get("summary", {}), ("poams", "poams_overdue", "exceptions", "exceptions_soon", "mitigations"))
    data["filters"] = _fields(context.get("filters", {}), ("service", "identifier", "title", "status_filter", "owner", "severity", "due_from", "due_to", "expiration_from", "expiration_to", "sort", "page_size"))
    data["remediation_preview"] = _fields(context.get("remediation_preview", {}), ("images", "charts", "configuration_changes", "manual_review", "error"))
    data["oci_destinations"] = [_fields(row, ("id", "name", "endpoint", "namespace", "is_default", "credentials_configured", "ca_configured", "scope")) for row in context.get("oci_destinations", [])]
    for key in ("poams", "mitigations"):
        data[key] = [entry(item, formatters) for item in context.get(key, [])]
        for item in data[key]:
            item["service_id"] = item["service"]["id"]
            permission("poam.review", item["service_id"])
    data["exceptions"] = []
    for item in context.get("exceptions", []):
        row = _fields(item, ("kind", "href", "item", "severity", "status", "days_remaining", "approved_by", "justification", "revoke_href"))
        row["service"] = service(_field(item, "service") or context.get("service"))
        row["expires_at"] = date(_field(item, "expires_at"))
        permission("exception.revoke", row["service"]["id"])
        data["exceptions"].append(row)
    def validation_evidence(value):
        # Only declared public evidence fields cross the page boundary.
        projected = _fields(value, ("status", "reason", "validation_type", "offlineVerified", "artifact_digest", "detail", "request_id", "validation_id", "validator_id", "cleanup_status"))
        projected["service"] = _fields(_field(value, "service", {}) or {}, ("id", "version"))
        projected["network"] = _fields(_field(value, "network", {}) or {}, ("isolated", "external_chart_fetches", "external_image_pulls"))
        return projected
    def job(item, full=False):
        result = _fields(item, ("job_key", "finding_type", "original_revision", "resulting_revision", "retry_of_id", "status", "output_mode", "failure_reason", "rollback_reference", "source_execution_id", "source_version_id", "revision_number", "remediation_status", "delivery_status", "verification_status", "signing_status", "artifact_digest"))
        result.update(started_at=_formatted(_field(item, "started_at")), finished_at=_formatted(_field(item, "completed_at")), started_label=timestamp(_field(item, "started_at")), finished_label=timestamp(_field(item, "completed_at")), has_artifact=bool(_field(item, "artifact_path")))
        if not full:
            return result
        result["delivery_attempts"] = []
        for row in _field(item, "delivery_attempts", []) or []:
            destination = _field(row, "destination", {}) or {}
            delivery_result = _field(row, "result", {}) or {}
            result["delivery_attempts"].append({"id": _scalar(_field(row, "id")),
                "destination": _scalar(_field(destination, "name")), "artifact_digest": _scalar(_field(row, "content_digest")),
                "helm_digest": _scalar(_field(delivery_result, "materialized_digest")), "actor": _scalar(_field(row, "actor_id")),
                "timestamp": timestamp(_field(row, "started_at")), "result": _scalar(_field(row, "status")),
                "error": _scalar(_field(delivery_result, "error")),
                "validation_type": _scalar(_field(delivery_result, "validation_type")),
                "service": _fields(_field(delivery_result, "service", {}) or {}, ("id", "version")),
                "verification": validation_evidence(_field(delivery_result, "verification", {}) or {})})
        for key in ("before_snapshot", "after_snapshot"):
            snapshot = _field(item, key, {}) or {}
            result[key] = _fields(snapshot, ("kev", "configuration_findings", "images", "helm_render", "policy_validation", "patchable_vulnerabilities", "epss_max"))
            result[key]["vulnerabilities"] = _fields(_field(snapshot, "vulnerabilities", {}), ("Critical", "High", "Medium", "Low"))
        result["changed_artifacts"] = [{"path": _scalar(_field(row, "path")), "changes": [_scalar(change) for change in _field(row, "changes", [])]} for row in _field(item, "changed_artifacts", []) or []]
        result["patched_images"] = [_fields(row, ("original", "candidate", "classification", "reason", "patch_status", "patch_job_id")) for row in _field(item, "patched_images", []) or []]
        result["configuration_changes"] = []
        def target_fields(row, projected):
            projected.update(_fields(row, ("target_id", "target_resolution", "source_resolution", "actionability", "container_name", "container_type")))
            projected["resource_identity"] = _fields(_field(row, "resource_identity", {}) or {}, ("api_version", "kind", "namespace", "name", "container_type", "container_name"))
            projected["source_mapping"] = _fields(_field(row, "source_mapping", {}) or {}, ("values_file", "values_key", "template", "source_file", "field_path", "mutation_path"))
        for row in _field(item, "configuration_changes", []) or []:
            projected = _fields(row, ("rule_id", "classification", "category", "field_path", "new_value", "original_value", "reason", "resource", "proposed_value_source", "approval", "actor", "timestamp", "decision", "post_scan_result"))
            target_fields(row, projected)
            result["configuration_changes"].append(projected)
        result["stages"] = [{"name": str(key), **_fields(value, ("status", "duration_seconds", "detail"))} for key, value in (_field(item, "stages", {}) or {}).items()]
        validation = _field(item, "validation_results", {}) or {}
        summary = _field(validation, "summary_of_changes", {}) or {}
        result["summary_of_changes"] = _fields(summary, ("schema_version", "final_configuration_scan_complete"))
        result["static_status"] = _scalar(_field(validation, "status"))
        result["summary_of_changes"]["unresolved"] = [_fields(row, ("rule_id", "resource", "field_path", "status", "reason", "accepted", "source_modified")) for row in _field(summary, "unresolved", []) or []]
        result["summary_of_changes"]["remaining_configuration_findings"] = [_fields(row, ("rule_id", "target", "title", "severity", "resource")) for row in _field(summary, "remaining_configuration_findings", []) or []]
        result["summary_of_changes"]["configuration_changes"] = []
        for row in _field(summary, "configuration_changes", []) or []:
            projected = _fields(row, ("rule_id", "resource", "field_path", "original_value", "proposed_value", "actual_value", "actual_value_available", "accepted", "source_modified", "verified", "status", "reason", "actor", "approval", "proposed_value_source"))
            for key in ("original_value", "proposed_value", "actual_value"):
                value = _field(row, key)
                projected[key] = _redact(value) if isinstance(value, (dict, list, str, int, float, bool)) or value is None else None
            target_fields(row, projected)
            result["summary_of_changes"]["configuration_changes"].append(projected)
        result["summary_of_changes"]["source_files"] = [_fields(row, ("path", "before_sha256", "after_sha256", "modified")) for row in _field(summary, "source_files", []) or []]
        result["summary_of_changes"]["charts"] = [_fields(row, ("path", "original_version", "remediated_version", "package_status", "publish_status", "reason")) for row in _field(summary, "charts", []) or []]
        result["validation"] = [{"name": str(key), **_fields(value, ("status", "detail"))} for key, value in (_field(validation, "checks", {}) or {}).items()]
        result["deployment_status"] = _scalar(_field(_field(validation, "deployment", {}), "status"))
        result["original_validation"] = validation_evidence(_field(validation, "original", {}) or {})
        result["candidate_validation"] = validation_evidence(_field(validation, "deployment", {}) or {})
        result["candidate_validation_attempts"] = [validation_evidence(row) for row in _field(validation, "runtime_attempts", []) or []]
        result["logs"] = [_scalar(row) for row in _field(item, "logs", []) or []]
        return result
    data["remediation_jobs"] = [job(item) for item in context.get("remediation_jobs", [])]
    if name == "remediation_report.html":
        data["job"] = job(context.get("job"), True)
        data["status_revision"] = context.get("status_revision")
    if name == "requests.html":
        data["workflows"] = []
        for item in context.get("workflows", []):
            row = _fields(item, ("id", "request_type", "poam_id", "justification", "ticket", "review_reason"))
            row["service"] = service(_field(item, "service"))
            row["subject"] = _scalar(_field(_field(item, "finding"), "cve") or _field(_field(item, "policy_finding"), "finding"))
            row["bulk_group"] = _fields(_field(item, "bulk_group"), ("id", "name")) if _field(item, "bulk_group") else None
            row["requested_by"] = _scalar(_field(_field(item, "requested_by"), "display_name"))
            row["reviewed_by"] = _scalar(_field(_field(item, "reviewed_by"), "display_name"))
            row["status"] = _scalar(context.get("workflow_statuses", {}).get(row["id"]))
            key = "exception.review" if row["request_type"] == "exception" else "poam.review" if row["request_type"].startswith("poam") else "archive.review"
            row["can_review"] = (_field(item, "status") == "pending" and callable(can) and bool(can(key, _field(item, "service_id"))) and _field(item, "requested_by_id") != _field(context.get("current_user"), "id"))
            data["workflows"].append(row)
