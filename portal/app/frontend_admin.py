"""Explicit administration DTOs; credential material never crosses this boundary."""
from collections.abc import Mapping


def project_admin(data, name, context, can=None, formatters=None):
    from .frontend import _field, _fields, _formatted, _scalar
    formatters = formatters or {}
    def rows(key, fields):
        return [_fields(item, fields) for item in context.get(key, [])]
    def strings(value):
        return [item for item in (value or []) if isinstance(item, str)]
    data.update(_fields(context, ("saved", "error", "selected_group_id", "shown_count", "retained_count", "next_show")))
    for permission in ("user.manage", "role.manage", "config.manage", "audit.view"):
        data.setdefault("can", {})[permission] = {"*": bool(can(permission)) if callable(can) else False}
    data["groups"] = rows("groups", ("id", "name"))
    if name in {"admin.html", "staging.html"}:
        data["stage_groups"] = rows("stage_groups", ("id", "name"))
    if name == "admin.html":
        data["users"] = rows("users", ("id", "username", "display_name"))
        data["roles"] = rows("roles", ("id", "name", "description", "system"))
        data["services"] = rows("services", ("id", "name"))
        catalog = context.get("permission_catalog", {})
        data["permission_catalog"] = {str(key): _scalar(value) for key, value in catalog.items()}
        data["group_summaries"] = [{"group": _fields(_field(row, "group"), ("id", "name", "description")),
            **_fields(row, ("active_services", "service_count"))} for row in context.get("group_summaries", [])]
        data["user_rows"] = []
        for row in context.get("user_rows", []):
            user = _field(row, "user")
            projected = _fields(user, ("id", "username", "display_name", "auth_source", "enabled"))
            projected["is_self"] = _field(user, "id") == _field(context.get("current_user"), "id")
            projected["last_login_at"] = _formatted(_field(user, "last_login_at"), formatters.get("cats_datetime"))
            data["user_rows"].append({"user": projected,
                "assignments": [_fields(item, ("id", "role", "group", "service")) for item in _field(row, "assignments", [])],
                "permissions": [key for key in _field(row, "permissions", []) if key in catalog]})
    elif name == "audit.html":
        data["configuration"] = _fields(context.get("configuration", {}), ("audit_retention_days", "log_level"))
        detail_keys = ("actor_username", "username", "display_name", "service_key", "service_id", "group_id", "user_id",
            "role_id", "name", "previous_name", "parent_id", "version", "reason", "review_reason", "image", "replacement",
            "item_type", "item", "source_file", "execution_id", "run_id", "artifact_id", "artifact_revision_id", "repository_id",
            "path", "ref", "revision", "phase", "status", "scope", "kind", "mode", "count", "format", "source", "provider",
            "issuer", "endpoint", "success", "enabled", "configured", "fingerprint", "registry_id", "registry_action",
            "os_id", "repository_mode", "verify_tls", "verify_packages", "installed_version", "failure_reason", "purl")
        data["events"] = []
        for event in context.get("events", []):
            detail = _field(event, "detail", {}) or {}
            detail = detail if isinstance(detail, Mapping) else {}
            safe_detail = {key: _scalar(detail[key]) for key in detail_keys if key in detail and _scalar(detail[key]) is not None}
            # These are field identifiers, not setting values or credentials.
            safe_detail["changed"] = strings(detail.get("changed", []))
            safe_detail["permissions"] = strings(detail.get("permissions", []))
            conditions = detail.get("conditions", {})
            if isinstance(conditions, Mapping):
                safe_detail["conditions"] = {key: bool(conditions[key]) for key in
                    ("critical_high", "kev", "watchlist", "poam", "kind", "missing_evidence") if key in conditions}
            data["events"].append({**_fields(event, ("id", "action", "target_type", "target_id")),
                "created_at": _formatted(_field(event, "created_at"), formatters.get("cats_datetime")),
                "actor": _scalar(_field(_field(event, "actor"), "username")) or safe_detail.get("actor_username") or "system",
                "detail": {key: value for key, value in safe_detail.items() if value not in ([], {})}})
    elif name == "configuration.html":
        data["configuration"] = _fields(context.get("configuration", {}),
            ("display_timezone", "date_format", "time_format", "identity_mode", "remediation_enabled"))
        for key in ("timezones", "package_managers"):
            data[key] = strings(context.get(key, []))
        for key in ("date_formats", "time_formats"):
            data[key] = [[_scalar(value), _scalar(label)] for value, label in context.get(key, [])]
        for key, fields in {
            "oidc": ("provider_name", "issuer", "client_id", "client_secret_configured", "scopes", "username_claim", "email_claim",
                     "groups_claim", "roles_claim", "browser_issuer", "redirect_uri", "post_logout_redirect_uri"),
            "validator": ("endpoint", "client_certificate_configured", "client_key_configured", "ca_configured"),
            "signing": ("enabled", "configured", "fingerprint", "updated_at", "error"),
            "cyber_warning_policy": ("critical_high", "kev", "watchlist", "poam", "kind", "missing_evidence"),
        }.items():
            data[key] = _fields(context.get(key, {}), fields)
        data.update(_fields(context, ("oidc_result", "validator_result", "repository_result", "edit_os_id")))
        for key, fields in {
            "registries": ("id", "display_name", "endpoint", "namespace", "use_for_remediation", "resolved_path", "auth_mode", "username", "secret_configured", "status", "status_detail"),
            "certificates": ("subject", "issuer", "kind", "fingerprint"),
            "oidc_roles": ("id", "name"), "oidc_groups": ("id", "name"), "oidc_services": ("id", "name"),
            "purpose_templates": ("kind", "name", "customized"),
        }.items():
            data[key] = rows(key, fields)
        data["oidc_mappings"] = []
        for mapping in context.get("oidc_mappings", []):
            projected = _fields(mapping, ("id", "claim_path", "expected_value", "role_id", "service_id", "group_id", "global_scope", "enabled"))
            for key in ("role", "service", "group"):
                projected[key] = _fields(_field(mapping, key), ("id", "name")) if _field(mapping, key) else None
            data["oidc_mappings"].append(projected)
        data["security_data_sources"] = {}
        for key in ("kev", "epss", "grype", "trivy"):
            row = context.get("security_data_sources", {}).get(key)
            projected = _fields(row, ("source", "status", "installed_version", "failure_reason"))
            for field in ("last_attempt_at", "last_success_at"):
                projected[field] = _formatted(_field(row, field), formatters.get("cats_date"))
            data["security_data_sources"][key] = projected
        data["os_definitions"] = {str(key): _fields(value, ("name", "package_manager")) for key, value in context.get("os_definitions", {}).items()}
        data["custom_os"] = list(context.get("custom_os", {}))
        data["repository_policies"] = {str(key): _fields(value, ("mode", "url", "verify_tls", "verify_packages"))
            for key, value in context.get("repository_policies", {}).items()}
    return data
