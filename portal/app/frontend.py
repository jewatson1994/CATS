"""Explicit page DTOs at the boundary between legacy routes and React."""
from pathlib import Path
from collections.abc import Mapping
import json
from datetime import date, datetime

from starlette.responses import HTMLResponse, JSONResponse
from starlette.templating import Jinja2Templates
from .frontend_portfolio import cybersecurity_data
from .frontend_results import public_results_data, patch_results_data
from .frontend_governance import project_governance
from .frontend_service_secondary import project_secondary
from .frontend_service_operations import project_service_operations
from .frontend_exchange import service_definitions_data, exchange_data, purpose_export_template_data
from .frontend_remediations import project_remediations
from .frontend_service_architecture import project_service_architecture
from .frontend_admin import project_admin
from .frontend_policies import policies_data

PAGE_MEDIA_TYPE = "application/vnd.cats.page+json"
MIGRATED_PAGES = frozenset({"home.html", "login.html", "dashboard.html", "password.html",
                            "appearance.html", "request_error.html", "boozled.html", "self_service.html", "patch.html", "cybersecurity.html", "service.html", "service_simplified.html", "public_results.html", "patch_results.html", "finding.html", "watchlist_match.html", "poam.html", "poam_service.html", "poam_entry.html",
                            "service_overview.html", "service_activity.html", "service_history.html",
                            "service_dependencies.html", "service_artifacts.html", "service_validation.html",
                            "service_definitions.html", "exchange.html", "purpose_export_template.html",
                            "remediations.html", "service_remediations.html", "remediation_report.html", "requests.html", "service_architecture.html",
                            "admin.html", "staging.html", "configuration.html", "audit.html", "general_policy.html", "evidence_policy.html", "workflow_policy.html", "compliance.html", "compliance_frameworks.html", "dependency_watchlist.html"})


def _field(value, name, default=None):
    return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)


def _scalar(value):
    # Never traverse ORM objects, collections, or authentication contexts.
    return value if value is None or isinstance(value, (str, int, float, bool)) else None


def _fields(value, names):
    return {name: _scalar(_field(value, name)) for name in names}


def _formatted(value, formatter=None):
    if value is None:
        return None
    # Portable history snapshots already contain serialized timestamps.
    # Date formatters accept datetime objects, not imported ISO strings.
    if isinstance(value, str):
        return value
    if callable(formatter):
        return str(formatter(value))
    return value.isoformat() if isinstance(value, (date, datetime)) else _scalar(value)


def _service_data(data, context, can, formatters):
    view = context.get("view", {})
    service = _field(view, "service")
    service_data = _fields(service, ("id", "service_key", "name", "owner", "poc", "description", "manual_version", "assessment_status"))
    service_data["groups"] = [_fields(group, ("id", "name")) for group in _field(service, "groups", [])]
    service_id = _field(service, "id")
    for permission in ("service.edit", "service.delete", "archive.request", "exception.request",
                       "exception.revoke", "poam.request", "remediation.execute", "service.export", "bundle.export"):
        data["can"][permission] = {str(service_id): bool(can(permission, service_id)) if callable(can) else False}
    data["view"] = _fields(view, ("version", "compliant", "archive"))
    data["view"]["service"] = service_data
    data["view"]["last_execution"] = _formatted(_field(view, "last_execution"), formatters.get("cats_datetime"))
    for key in ("skipped_images", "skipped_charts"):
        data["view"][key] = [_scalar(item) for item in _field(view, key, [])]
    data.update(_fields(context, ("archive_pending", "saved", "overdue_days", "remediation_enabled",
        "finding_state", "finding_type", "query", "resource", "page", "page_size", "total_pages", "total_items",
        "pagination_base", "clear_filters_url", "selected_findings_view")))
    for key in ("history_versions", "severity", "severity_options"):
        data[key] = [_scalar(item) for item in context.get(key, [])]
    data["groups"] = [_fields(group, ("id", "name")) for group in context.get("groups", [])]
    now = context.get("now")
    active_exception = context.get("active_exception")
    for key, fields, due_key in (
        ("findings", ("id", "cve", "severity", "active"), "due_dates"),
        ("policy_findings", ("id", "finding", "title", "severity", "active", "framework", "target", "description", "remediation"), "policy_due_dates")):
        data[key] = []
        for finding in context.get(key, []):
            row = _fields(finding, fields)
            finding_id = _field(finding, "id")
            started = _field(finding, "episode_started")
            row["episode_days"] = ((now - started.replace(tzinfo=now.tzinfo)).days
                                   if isinstance(now, datetime) and isinstance(started, datetime) and row.get("active") else None)
            row["due"] = _formatted(_field(view, due_key, {}).get(finding_id), formatters.get("cats_date"))
            row["last_seen"] = _formatted(_field(finding, "last_seen"), formatters.get("cats_date"))
            exception = active_exception(finding, now) if callable(active_exception) else None
            row["exception"] = ({"id": _scalar(_field(exception, "id")),
                                 "expires_at": _formatted(_field(exception, "expires_at"), formatters.get("cats_date"))}
                                if exception is not None else None)
            if key == "findings":
                risk = _field(view, "risk_metadata", {}).get(finding_id, {})
                row.update(_fields(risk, ("kev", "epss")))
                row["images"] = [_scalar(image) for image in context.get("affected_images", {}).get(finding_id, [])]
            else:
                remediation = context.get("remediation_classes", {}).get(finding_id, {})
                row["remediation_classification"] = _scalar(_field(remediation, "classification", "NOT REMEDIABLE"))
                row["remediation_reason"] = _scalar(_field(remediation, "reason", ""))
            data[key].append(row)
    for key in ("noncompliance_items", "warning_items", "simplified_findings"):
        data[key] = []
        for item in context.get(key, []):
            row = _fields(item, ("type", "item", "reason", "source_file", "finding_id", "policy_finding_id", "href",
                                 "package", "fixed_version", "severity", "remediation"))
            row["due"] = _formatted(_field(item, "due"), formatters.get("cats_date"))
            for list_key in ("images", "cves", "finding_ids"):
                row[list_key] = [_scalar(value) for value in _field(item, list_key, [])]
            data[key].append(row)


def page_data(request, name, context, deployed_version=None, formatters=None):
    user = context.get("current_user")
    can = context.get("can")
    path = request.url.path
    data = {
        "current_user": _fields(user, ("display_name", "theme")) if user is not None else None,
        "csrf_token": _scalar(context.get("csrf_token")),
        "themes": {str(key): _scalar(value) for key, value in context.get("themes", {}).items()},
        "permissions": {permission: bool(can(permission)) if callable(can) else False
                        for permission in ("user.manage", "config.manage", "audit.view")},
        "pending_request_count": _scalar(context.get("pending_request_count", 0)),
        "pending_poam_count": _scalar(context.get("pending_poam_count", 0)),
        "actionable_notifications": [_fields(item, ("label", "service"))
                                     for item in context.get("actionable_notifications", [])],
        "cats_deployed_version": _scalar(deployed_version),
        "request_path": path,
        "next_path": path + ("?" + request.url.query if request.url.query else ""),
    }
    data["can"] = {permission: {"*": allowed} for permission, allowed in data["permissions"].items()}
    if name in {"admin.html", "staging.html", "configuration.html", "audit.html"}:
        project_admin(data, name, context, can, formatters)
    elif name in {"general_policy.html", "evidence_policy.html", "workflow_policy.html", "compliance.html", "compliance_frameworks.html", "dependency_watchlist.html"}:
        data.update(policies_data(context, formatters.get("cats_datetime")))
    elif name in {"remediations.html", "service_remediations.html", "remediation_report.html", "requests.html"}:
        if name == "service_remediations.html":
            _service_data(data, context, can, formatters or {})
        project_remediations(data, name, context, can, formatters or {})
    elif name == "service_architecture.html":
        _service_data(data, context, can, formatters)
        data.update(project_service_architecture(context))
    elif name in {"service_dependencies.html", "service_artifacts.html", "service_validation.html"}:
        _service_data(data, context, can, formatters or {})
        data.update(project_service_operations(name, context))
    elif name == "service_definitions.html":
        data.update(service_definitions_data(context))
    elif name == "exchange.html":
        data.update(exchange_data(context))
    elif name == "purpose_export_template.html":
        data.update(purpose_export_template_data(context))
    elif name in {"service_overview.html", "service_activity.html", "service_history.html"}:
        if name != "service_history.html":
            _service_data(data, context, can, formatters or {})
        project_secondary(data, name, context, can, formatters or {})
    elif name in {"finding.html", "watchlist_match.html", "poam.html", "poam_service.html", "poam_entry.html"}:
        project_governance(data, name, context, can, formatters or {})
    elif name == "public_results.html":
        data.update(public_results_data(context))
    elif name == "patch_results.html":
        data.update(patch_results_data(context))
    elif name == "cybersecurity.html":
        data.update(cybersecurity_data(context, format_date=(formatters or {}).get("cats_date")))
    elif name in {"service.html", "service_simplified.html"}:
        _service_data(data, context, can, formatters or {})
    elif name in {"home.html", "login.html"}:
        data.update(_fields(context, ("error", "next", "oidc_available", "local_available", "oidc_provider_name")))
    elif name == "appearance.html":
        data["saved"] = bool(context.get("saved"))
    elif name == "password.html":
        data["error"] = _scalar(context.get("error"))
    elif name in {"request_error.html", "boozled.html"}:
        data["detail"] = _scalar(context.get("detail"))
        data["home_url"] = str(context.get("home_url") or "/")
    elif name == "patch.html":
        data.update(_fields(context, ("error", "job_id", "selected_service_id")))
        data["signing"] = _fields(context.get("signing", {}), ("enabled",))
        data["configured_registries"] = [_fields(registry, ("id", "display_name", "endpoint", "namespace"))
                                          for registry in context.get("configured_registries", [])]
        data["authenticated_services"] = [_fields(service, ("service_key", "name"))
                                           for service in context.get("authenticated_services", [])]
        data["patch_phases"] = [_scalar(phase) for phase in context.get("patch_phases", [])]
        data["job"] = _fields(context.get("job", {}), ("status", "phase", "message", "progress",
            "error", "started_at", "finished_at", "created_at"))
    elif name == "self_service.html":
        data.update(_fields(context, ("mode", "description", "image_list", "chart_url",
            "authenticated_ingest", "ingest_service_id", "ingest_service_version", "cyclonedx_spec_version",
            "job_id", "status_message")))
        data["authenticated_services"] = [_fields(service, ("service_key", "name"))
                                           for service in context.get("authenticated_services", [])]
        for key in ("archive_names", "selected_sbom_formats", "cyclonedx_spec_versions", "progress_order"):
            data[key] = [_scalar(item) for item in context.get(key, [])]
        data["progress_phases"] = [[_scalar(part) for part in pair] for pair in context.get("progress_phases", [])]
        data["sbom_output_formats"] = {str(key): _scalar(value) for key, value in context.get("sbom_output_formats", {}).items()}
        data["service_version_options"] = {str(key): [_scalar(item) for item in values]
                                           for key, values in context.get("service_version_options", {}).items()}
        data["job"] = _fields(context.get("job", {}), ("status", "phase", "message", "progress",
            "error", "started_at", "finished_at", "created_at"))
        job = context.get("job", {})
        data["job"]["skipped_charts"] = [_scalar(item) for item in _field(job, "skipped_charts", [])]
        summary = _field(job, "summary", {})
        data["job"]["summary"] = _fields(summary, ("skipped_images", "skipped_charts", "reports", "results", "configuration_findings"))
        data["job"]["summary"]["formats"] = [_scalar(item) for item in _field(summary, "formats", [])]
    elif name == "dashboard.html":
        data.update(_fields(context, (
            "now_display", "compliant_count", "noncompliant_count", "showing_archived", "lifecycle",
            "query", "sort", "page", "page_size", "total_count", "total_pages", "pagination_base",
            "overdue_days", "poam_active_count", "poam_pending_count", "poam_overdue_count")))
        data["lifecycle_counts"] = _fields(context.get("lifecycle_counts", {}), ("active", "staged", "archived"))
        data["stage_groups"] = [_fields(group, ("id", "name")) for group in context.get("stage_groups", [])]
        data["views"] = []
        for view in context.get("views", []):
            row = _fields(view, ("version", "compliant", "evidence_state", "oldest_age"))
            row["service"] = _fields(_field(view, "service"), ("id", "service_key", "name", "owner", "poc"))
            for target, first, second in (("active_count", "active", "policy_findings"),
                                           ("noncompliant_count", "noncompliant", "policy_noncompliant"),
                                           ("excepted_count", "excepted", "policy_excepted")):
                row[target] = len(_field(view, first, []) or []) + len(_field(view, second, []) or [])
            data["views"].append(row)
    if name.startswith("service") and request.query_params.get("saved") == "1":
        data["saved"] = True
    return {"schemaVersion": 1, "page": name.removesuffix(".html"), "data": data}


def _wants_page_json(accept):
    for entry in accept.split(","):
        media, *parameters = entry.strip().split(";")
        if media.lower() != PAGE_MEDIA_TYPE:
            continue
        quality = 1.0
        for parameter in parameters:
            key, _, value = parameter.strip().partition("=")
            if key.lower() == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0
        if quality > 0:
            return True
    return False


class ReactTemplates(Jinja2Templates):
    """Serve native React pages using both Starlette response call conventions."""

    def __init__(self, *args, frontend_index=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.frontend_index = Path(frontend_index) if frontend_index else Path(__file__).parent / "static" / "frontend" / "index.html"

    def TemplateResponse(self, *args, **kwargs):
        if args and isinstance(args[0], str):
            name = args[0]
            context = args[1] if len(args) > 1 else kwargs.get("context", {})
            request = context.get("request")
            remaining = args[2:]
        else:
            request = args[0] if args else kwargs.get("request")
            name = args[1] if len(args) > 1 else kwargs.get("name")
            context = args[2] if len(args) > 2 else kwargs.get("context", {})
            remaining = args[3:]
        if name not in MIGRATED_PAGES or request is None:
            return super().TemplateResponse(*args, **kwargs)
        wants_json = _wants_page_json(request.headers.get("accept", ""))
        if not wants_json and not self.frontend_index.is_file():
            response = HTMLResponse("CATS frontend assets are missing. Build portal/frontend before starting the portal.", status_code=503)
        else:
            options = dict(zip(("status_code", "headers", "media_type", "background"), remaining))
            options.update({key: kwargs[key] for key in ("status_code", "headers", "background") if key in kwargs})
            options.pop("media_type", None)
            merged = {"request": request, **(context or {})}
            for processor in self.context_processors:
                merged.update(processor(request))
            envelope = page_data(request, name, merged, self.env.globals.get("cats_deployed_version"), self.env.globals)
            if wants_json:
                response = JSONResponse(envelope,
                                        media_type=PAGE_MEDIA_TYPE, **options)
            else:
                serialized = json.dumps(envelope, ensure_ascii=False)
                for char, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                                      ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
                    serialized = serialized.replace(char, escaped)
                bootstrap = '<script type="application/json" id="cats-bootstrap">' + serialized + '</script>'
                shell = self.frontend_index.read_text(encoding="utf-8")
                shell = shell.replace("</head>", bootstrap + "</head>") if "</head>" in shell else bootstrap + shell
                response = HTMLResponse(shell, **options)
        response.headers["Cache-Control"] = "private, no-store"
        vary = [part.strip() for part in response.headers.get("Vary", "").split(",") if part.strip()]
        if not any(part.lower() == "accept" for part in vary):
            vary.append("Accept")
        response.headers["Vary"] = ", ".join(vary)
        return response


# Descriptive public name used by the application; keep the original name for callers.
FrontendTemplates = ReactTemplates
