"""Whitelisted advisory and POA&M presentation data; no ORM object serialization."""
from collections.abc import Mapping
from datetime import date, datetime


def field(value, key, default=None):
    return value.get(key, default) if isinstance(value, Mapping) else getattr(value, key, default)


def scalar(value):
    return value if value is None or isinstance(value, (str, int, float, bool)) else None


def fields(value, keys):
    return {key: scalar(field(value, key)) for key in keys}


def formatted(value, formatters, key="cats_date"):
    if value is None:
        return None
    formatter = formatters.get(key)
    return str(formatter(value)) if callable(formatter) else value.isoformat() if isinstance(value, (date, datetime)) else scalar(value)


def service(value):
    result = fields(value, ("id", "service_key", "name", "owner", "poc"))
    result["groups"] = [fields(item, ("id", "name")) for item in field(value, "groups", [])]
    return result


def entry(value, formatters):
    result = fields(value, ("id", "item_type", "title", "description", "remediation", "ticket", "status", "service_version"))
    result["service"] = service(field(value, "service"))
    result["finding"] = fields(field(value, "finding"), ("id", "cve", "severity")) if field(value, "finding") else None
    result["policy_finding"] = fields(field(value, "policy_finding"), ("id", "finding", "severity")) if field(value, "policy_finding") else None
    result["created_by"] = scalar(field(field(value, "created_by"), "display_name"))
    result["approved_by"] = scalar(field(field(value, "approved_by"), "display_name"))
    result["approved_at"] = formatted(field(value, "approved_at"), formatters, "cats_datetime")
    due = field(value, "due_date")
    result["due_date"] = formatted(due, formatters)
    result["due_input"] = due.strftime("%Y-%m-%dT%H:%M") if isinstance(due, datetime) else ""
    return result


def project_governance(data, name, context, can, formatters):
    if name == "finding.html":
        data["service"] = service(context.get("service"))
        finding = context.get("finding")
        data["finding"] = fields(finding, ("id", "cve", "severity", "active", "recurrence_count"))
        data["finding"]["first_seen"] = formatted(field(finding, "first_seen"), formatters)
        data["finding"]["last_seen"] = formatted(field(finding, "last_seen"), formatters, "cats_datetime")
        data.update(fields(context, ("age", "remediation_enabled")))
        data["due_date"] = formatted(context.get("due_date"), formatters)
        data["risk"] = fields(context.get("risk"), ("kev", "epss"))
        data["remediation_classification"] = fields(context.get("remediation_classification"), ("classification", "reason"))
        evidence = context.get("evidence", {})
        data["evidence"] = fields(evidence, ("namespace", "description", "data_source", "package_type"))
        data["evidence"]["urls"] = [scalar(item) for item in field(evidence, "urls", [])]
        data["evidence"]["cvss"] = [{"vector": scalar(field(item, "vector")), "baseScore": scalar(field(field(item, "metrics", {}), "baseScore"))} for item in field(evidence, "cvss", [])]
        exception = context.get("exception")
        data["exception"] = {"expires_at": formatted(field(exception, "expires_at"), formatters), "approved_by": scalar(field(exception, "approved_by"))} if exception else None
        data["current_observations"] = [fields(item, ("image", "package", "installed_version", "fixed_version")) for item in context.get("current_observations", [])]
        sid = data["service"]["id"]
        data["can"]["remediation.execute"] = {str(sid): bool(can("remediation.execute", sid)) if callable(can) else False}
    elif name == "watchlist_match.html":
        match = context.get("match")
        data["service"] = service(context.get("service"))
        data["match"] = fields(match, ("component_name", "component_version", "ecosystem", "component_purl", "image"))
        data["match"]["execution_key"] = scalar(field(field(match, "execution"), "execution_key"))
        data["match"]["scanned_at"] = formatted(field(field(match, "execution"), "scanned_at"), formatters)
        data["match"]["entry"] = fields(field(match, "entry"), ("purl", "name", "version_constraint"))
    elif name == "poam.html":
        data["poam_services"] = [service(item) for item in context.get("poam_services", [])]
        data["service_summaries"] = [{**fields(item, ("total", "active", "pending", "overdue")), "service": service(field(item, "service"))} for item in context.get("service_summaries", [])]
    elif name == "poam_service.html":
        data["service"] = service(context.get("service"))
        data["view"] = fields(context.get("view"), ("version",))
        data.update(fields(context, ("embedded", "can_create_poam", "status_filter", "sort_by")))
        data["overdue_entry_ids"] = [scalar(item) for item in context.get("overdue_entry_ids", [])]
        data["entries"] = [entry(item, formatters) for item in context.get("entries", [])]
    elif name == "poam_entry.html":
        data["entry"] = entry(context.get("entry"), formatters)
        data.update(fields(context, ("can_change", "is_overdue")))
        data["pending_change"] = fields(context.get("pending_change"), ("request_type",)) if context.get("pending_change") else None
        data["history"] = []
        for item in context.get("history", []):
            row = fields(item, ("action", "note"))
            row["actor"] = scalar(field(field(item, "actor"), "display_name"))
            row["created_at"] = formatted(field(item, "created_at"), formatters, "cats_datetime")
            details = field(item, "detail", {})
            row["detail"] = {key: scalar(details[key]) for key in ("title", "description", "remediation", "due_date", "ticket", "closure_note", "evidence_reference", "version", "reason", "decision") if isinstance(details, Mapping) and key in details}
            data["history"].append(row)
