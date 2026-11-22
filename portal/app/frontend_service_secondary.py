"""Read-only evidence projection and overview action metadata for React pages."""
from collections.abc import Mapping
from datetime import datetime
from .frontend_compose import compose_data


def project_secondary(data, name, context, can=None, formatters=None):
    from .frontend import _field, _fields, _formatted, _scalar
    formatters = formatters or {}
    def rows(value, fields):
        return [_fields(item, fields) for item in (value or []) if isinstance(item, Mapping)]
    def strings(value):
        return [_scalar(item) for item in (value or [])]
    def overview(value):
        result = _fields(value, ("source", "description"))
        for key, fields in {
            "missing_evidence": ("type", "item", "reason", "source_file", "removable"),
            "ports": ("port", "protocol", "service", "declared_by", "provenance"),
            "accounts": ("name", "scope", "relationships"),
            "artifacts": ("type", "registry", "repository", "artifact", "version", "discovered_from", "digest"),
        }.items():
            result[key] = rows(_field(value, key, []), fields)
        result["warnings"] = rows(_field(value, "warnings", []), ("message", "chart", "source", "original_error"))
        for projected, warning in zip(result["warnings"], _field(value, "warnings", []) or []):
            projected["unrecognized_images"] = strings(_field(warning, "unrecognized_images", []))
        result["compose"] = compose_data(_field(value, "compose"))
        return result
    def chart_graph(value):
        return {"charts": rows(_field(value, "charts", []), ("chart", "instance", "version", "parent_chart_name", "parent",
                    "discovery_method", "discovery_source_file", "source", "yaml_path", "status", "resolution",
                    "resource_count", "image_count", "render_error", "error", "source_only")),
                "unresolved": rows(_field(value, "unresolved", []), ("item", "reason", "source_file", "yaml_path"))}
    if name == "service_overview.html":
        request = context.get("request")
        data["evidence_notice"] = "stale" if request is not None and request.query_params.get("evidence_notice") == "stale" else None
        view = context.get("view", {})
        service = _field(view, "service")
        service_id = _field(service, "id")
        schedule = context.get("scan_schedule")
        if schedule is not None:
            data["scan_schedule"] = _fields(schedule, ("cadence", "timezone", "weekday", "time_of_day", "monthly_mode",
                                                       "week_of_month", "day_of_month", "last_job_id", "last_result"))
            data["scan_schedule"]["weekdays"] = strings(_field(schedule, "weekdays"))
            for field in ("next_run_at", "last_run_at"):
                data["scan_schedule"][field] = _formatted(_field(schedule, field))
            can_edit = bool(callable(can) and can("service.edit", service_id))
            data["can_schedule_scans"] = can_edit and _field(service, "lifecycle_status", "active") == "active" and bool(can("scan.ingest", service_id))
            data["can_disable_scan_schedule"] = can_edit
            data["schedule_saved"] = request is not None and request.query_params.get("schedule_saved") == "1"
        data.setdefault("can", {})["evidence.remove"] = {str(service_id): bool(can("evidence.remove", service_id)) if callable(can) else False}
        counts = {}
        precomputed = context.get("finding_counts")
        for key, first, second in (("active", "active", "policy_findings"), ("exceptions", "excepted", "policy_excepted"),
                                  ("resolved", "resolved", "policy_resolved")):
            counts[key] = len(_field(view, first, []) or []) + len(_field(view, second, []) or [])
        counts["noncompliant"] = len(_field(view, "noncompliance_items", []) or [])
        counts["warnings"] = len(_field(view, "warning_items", []) or [])
        if isinstance(precomputed, Mapping):
            # Overview counts are computed in SQL; the header carries no finding rows.
            counts = {key: int(precomputed.get(key) or 0) for key in counts}
        data["finding_counts"] = counts
        data["architecture_polling"] = bool(context.get("architecture_polling"))
        data["can_patch_images"] = bool(context.get("can_patch_images"))
        data["overview_data"] = overview(context.get("overview_data", {}))
        data["latest_execution"] = _fields(context.get("latest_execution"), ("id", "complete"))
        data["artifact_provenance"] = rows(context.get("artifact_provenance", []), (
            "artifact_kind", "digest", "identity_type", "remediation_id", "source_version",
            "revision_number", "job_key", "post_remediation_scan", "runtime_verification",
            "signature", "verification_artifact_digest", "evidence_scope"))
        data["service_images"] = [_fields(image, ("id", "image_reference", "image_digest", "lifecycle_status", "replacement_of_id"))
                                  for image in context.get("service_images", [])]
        for image in data["service_images"]:
            image["patch_history"] = rows((context.get("image_patch_history") or {}).get(image["id"], []),
                ("original_image", "patched_at", "job_id", "result_image"))
        data["architecture_verification"] = _fields(context.get("architecture_verification", {}), ("state", "label", "expected", "observed", "missing"))
        data["architecture_graph"] = {"summary": _fields(_field(context.get("architecture_graph", {}), "summary", {}),
                                                        ("declared", "differences", "relationships", "unresolved"))}
        validation = context.get("deployment_validation") or {}
        projected = _fields(validation, ("status", "reason", "static_scan_complete", "artifact_reference", "duration_seconds", "execution_key"))
        if projected["static_scan_complete"] is None:
            projected["static_scan_complete"] = _scalar(_field(context.get("latest_execution"), "complete"))
        projected["resource_summary"] = {key: _fields(_field(_field(validation, "resource_summary", {}), key, {}), ("ready", "expected"))
                                         for key in ("pods", "deployments", "statefulsets")}
        projected["helm_result"] = _fields(_field(validation, "helm_result", {}), ("install",))
        projected["conditions"] = _fields(_field(validation, "conditions", {}), ("crashloopbackoff", "imagepullbackoff"))
        projected["has_observed_topology"] = bool(_field(_field(validation, "observed_topology", {}), "nodes", []))
        data["deployment_validation"] = projected
        payload = _field(context.get("latest_execution"), "raw_payload", {}) or {}
        data["chart_graph"] = chart_graph(_field(_field(payload, "service_overview", {}), "helm_chart_graph", {}))
    elif name == "service_activity.html":
        data.update(_fields(context, ("page", "page_size", "page_count", "total_items", "pagination_base")))
        data["events"] = []
        # Only documented workflow metadata is displayed; audit detail is never copied wholesale.
        detail_fields = ("service_key", "name", "version", "finding_id", "policy_finding_id", "cve", "status", "reason",
                         "ticket", "request_type", "image", "image_reference", "replacement_reference", "phase",
                         "cleanup_status", "reason_category", "execution_id", "run_id", "artifact_revision_id",
                         "group_id", "previous_name")
        for event in context.get("events", []):
            at = _field(event, "created_at")
            detail = _field(event, "detail", {}) or {}
            projected_detail = {key: _scalar(detail[key]) for key in detail_fields if key in detail and _scalar(detail[key]) is not None}
            if isinstance(detail.get("changed"), (list, tuple)):
                projected_detail["changed"] = [key for key in detail["changed"] if key in
                    ("name", "description", "owner", "poc", "manual_version", "group_ids")]
            data["events"].append({"id": _scalar(_field(event, "id")), "action": _scalar(_field(event, "action")),
                "created_at": _formatted(at), "created_at_display": _formatted(at, formatters.get("cats_datetime")),
                "actor_name": _scalar(_field(_field(event, "actor"), "display_name", "System")),
                "detail": projected_detail})
    elif name == "service_history.html":
        data["read_only"] = True
        data["service"] = _fields(context.get("service"), ("id", "service_key"))
        data.update(_fields(context, ("page", "page_size", "total_pages", "total_items",
                                     "imported_page", "imported_total_pages", "imported_total_items")))
        data["version"] = _scalar(context.get("version"))
        data["versions"] = strings(context.get("versions", []))
        data["selected_scan"] = _scalar(context.get("selected_scan"))
        data["scan_options"] = []
        for option in context.get("scan_options", []):
            row = _fields(option, ("scan_id", "key", "name", "source"))
            row["at"] = _formatted(_field(option, "at"), formatters.get("cats_datetime"))
            data["scan_options"].append(row)
        tab = context.get("history_tab")
        data["history_tab"] = tab or "overview"
        data["releases"] = []
        for release in context.get("releases", []):
            row = _fields(release, ("release_key", "source", "digest", "scan"))
            row["approved_at"] = _formatted(_field(release, "approved_at"), formatters.get("cats_datetime"))
            data["releases"].append(row)
        for key in ("snapshots", "imported_snapshots"):
            data[key] = []
            for snapshot in context.get(key, []):
                projected = _fields(snapshot, ("scan_id", "key", "scope", "complete"))
                projected["at"] = _formatted(_field(snapshot, "at"), formatters.get("cats_datetime"))
                if tab in (None, "overview"):
                    projected["source_files"] = strings(_field(snapshot, "source_files", []))
                raw = _field(snapshot, "data", {}) or {}
                source_service = _field(raw, "service", {}) or {}
                evidence = {"service": _fields(source_service, ("id", "name", "version", "description", "owner", "poc"))}
                evidence["service"]["groups"] = strings(_field(source_service, "groups", []))
                projected["data"] = evidence
                data[key].append(projected)
                # An older consumer can omit the tab to retrieve the complete scan DTO.
                if tab in (None, "findings"):
                    finding_fields = ("cve", "severity", "package", "installed_version", "fixed_version", "image")
                    policy_fields = ("finding", "title", "severity", "target", "scanner")
                    if tab is None:
                        finding_fields += ("image_digest", "kev", "epss")
                        policy_fields += ("type", "framework", "namespace", "description", "remediation", "fingerprint")
                    evidence["findings"] = rows(raw.get("findings"), finding_fields)
                    evidence["policy_findings"] = rows(raw.get("policy_findings"), policy_fields)
                if tab == "findings":
                    continue
                if tab in (None, "dependencies"):
                    component_fields = ("name", "version", "ecosystem", "purl", "image", "license_expression")
                    if tab is None:
                        component_fields += ("image_digest", "cpe", "supplier", "author", "architecture", "hashes",
                            "copyright", "license_declared", "license_detected", "license_source", "location", "sbom",
                            "dependency_parents", "dependency_children")
                    evidence["sbom_components"] = rows(raw.get("sbom_components"), component_fields)
                raw_overview = raw.get("service_overview") or {}
                if tab == "dependencies":
                    from .overview import normalize_overview
                    dependencies = normalize_overview({"dependencies": _field(raw_overview, "dependencies")})["dependencies"]
                    evidence["service_overview"] = {"dependencies": dependencies}
                    continue
                from .history_metrics import historical_overview
                normalized, projected["summary"] = historical_overview(raw, projected["complete"])
                policy = _field(snapshot, "captured_policy") or {}
                projected["summary"].update(_fields(policy, ("posture", "watchlist", "open_poams",
                                                            "overdue_poams", "validation_failures")))
                captured_at = policy.get("posture_captured_at")
                if captured_at:
                    projected["summary"]["posture_captured_at"] = _formatted(
                        datetime.fromisoformat(captured_at), formatters.get("cats_datetime"))
                # Captures can include arbitrary imported Compose configuration.
                # Only the service inventory is needed in a historical overview.
                captured_compose = normalized.pop("compose", None)
                evidence["service_overview"] = overview(normalized)
                if captured_compose:
                    evidence["service_overview"]["compose"] = {
                        "services": rows(captured_compose.get("services"), ("name", "image", "status"))}
                if tab is None:
                    for list_key in ("sbom_images", "skipped_images", "skipped_charts"):
                        evidence[list_key] = strings(raw.get(list_key))
                    evidence["service_overview"]["dependencies"] = rows(normalized["dependencies"],
                        ("dependency", "used_by", "provides", "images"))
                    evidence["service_overview"]["images"] = rows(_field(raw_overview, "images", []),
                        ("image", "reference", "name", "digest", "image_digest", "registry", "repository", "tag", "version", "source_file", "discovered_from"))
                    evidence["service_overview"]["charts"] = rows(_field(raw_overview, "charts", []),
                        ("chart", "name", "version", "repository", "source", "source_file"))
                evidence["service_overview"]["helm_chart_graph"] = chart_graph(_field(raw_overview, "helm_chart_graph", {}))
    return data
