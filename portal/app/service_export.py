"""Authoritative, complete Excel export for one service snapshot."""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Iterable

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .overview import normalize_overview


XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_SENSITIVE_DETAIL = re.compile(r"secret|token|password|credential|private[_-]?key|authorization|access[_-]?key", re.I)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    value = str(value).strip()
    return value if value else default


def _datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    return None


def _join(values: Iterable[Any], separator: str = "\n") -> str:
    return separator.join(dict.fromkeys(_text(value) for value in values if _text(value)))


def _items(value: Any) -> list[Any]:
    """Treat a singleton export field like its list form."""
    return value if isinstance(value, list) else ([] if value is None else [value])


def _source(row: dict[str, Any]) -> str:
    return _text(row.get("source_file") or row.get("source_path") or row.get("template"), "—")


def _reference(row: dict[str, Any]) -> str:
    return _text(row.get("image") or row.get("reference") or row.get("name") or row.get("item"), "—")


def _safe_detail(detail: dict[str, Any]) -> str:
    return "; ".join(
        f"{key}={value}" for key, value in detail.items()
        if not _SENSITIVE_DETAIL.search(str(key))
    )


def _safe_filename(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", _text(value, "service")).strip(".-")
    return value or "service"


def _format_sheet(sheet) -> None:
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    sheet.sheet_view.showGridLines = False
    fill = PatternFill("solid", fgColor="17312B")
    for cell in sheet[1]:
        cell.fill = fill
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(vertical="center")
    for column in sheet.columns:
        width = min(max(len(str(cell.value or "")) for cell in column) + 2, 60)
        sheet.column_dimensions[get_column_letter(column[0].column)].width = max(width, 12)
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)


def _sheet(workbook: Workbook, name: str, headers: list[str], rows: Iterable[Iterable[Any]] = ()): 
    sheet = workbook.create_sheet(name)
    sheet.append(headers)
    for row in rows:
        sheet.append(list(row))
    _format_sheet(sheet)
    return sheet


def _status_for_exception(exception: Any, now: datetime) -> str:
    if exception.revoked_at:
        return "Revoked"
    expires = _datetime(exception.expires_at)
    starts = _datetime(exception.starts_at)
    current = now.replace(tzinfo=None) if now.tzinfo else now
    if expires and expires <= current:
        return "Expired"
    if starts and starts > current:
        return "Pending"
    return "Active"


def _status_for_poam(entry: Any) -> str:
    return _text(entry.status).replace("_", " ").title()


def build_service_workbook(
    service: Any,
    view: dict[str, Any],
    configuration: dict[str, str],
    now: datetime,
    latest_execution: Any = None,
    activity_events: Iterable[Any] = (),
    poam_histories: Iterable[Any] = (),
) -> Workbook:
    """Build a workbook from ORM state and the latest authoritative payload.

    This deliberately does not consume rendered HTML or UI pagination.  The
    latest service overview payload supplies Helm/artifact provenance while ORM
    relationships supply complete findings and governance history.
    """
    payload = latest_execution.raw_payload if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
    raw_overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
    skipped_images = payload.get("skipped_images") or []
    skipped_charts = payload.get("skipped_charts") or []
    findings_images = [
        {"image": observation.image, "digest": observation.image_digest}
        for finding in service.findings
        for observation in finding.observations
        if observation.image
    ]
    overview = normalize_overview(
        raw_overview,
        skipped_images=skipped_images,
        skipped_charts=skipped_charts,
        findings_images=findings_images,
    )

    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    summary.append(["Field", "Value"])
    groups = ", ".join(group.name for group in service.groups)
    latest_at = latest_execution.scanned_at if latest_execution else None
    poams = list(service.poam_entries)
    exceptions = [exception for finding in service.findings for exception in finding.exceptions]
    exceptions += [exception for finding in service.policy_findings for exception in finding.exceptions]
    mitigations = [entry for entry in poams if _text(entry.item_type).lower() == "mitigation"]
    chart_records = [
        *_items(raw_overview.get("helm_components")),
        *_items(raw_overview.get("charts")),
        *_items(raw_overview.get("helm_charts")),
    ]
    chart_keys = set()
    for raw in chart_records:
        raw = raw if isinstance(raw, dict) else {"chart": raw}
        chart_keys.add((_text(raw.get("chart") or raw.get("name") or raw.get("artifact"), "Unknown chart"), _text(raw.get("path") or raw.get("chart_path")), _text(raw.get("declared_by"))))
    summary_rows = [
        ("Service Name", service.name), ("Service ID", service.service_key),
        ("Current Status", "Archived" if view.get("archive") else "Active"),
        ("Compliance Status", "Compliant" if view.get("compliant") else "Non-Compliant"),
        ("Owner", service.owner), ("Organization / Group", groups),
        ("Last Assessment", _datetime(latest_at)), ("Last Ingestion", _datetime(latest_at)),
        ("Assessment Status", view.get("evidence_state")), ("Created Date", _datetime(service.created_at)),
        ("Exported At", _datetime(now)), ("Containers", len([a for a in overview["artifacts"] if a.get("type") == "Image"])),
        ("Helm Charts", len(chart_keys) or len([a for a in overview["artifacts"] if a.get("type") == "Chart"])),
        ("Artifacts", len(overview["artifacts"])), ("Missing Evidence", len(overview["missing_evidence"])),
        ("Ports", len(overview["ports"])), ("Accounts", len(overview["accounts"])),
        ("Active Findings", len(view.get("active", [])) + len(view.get("policy_findings", []))),
        ("POA&Ms", len(poams)), ("Exceptions", len(exceptions)), ("Mitigations", len(mitigations)),
    ]
    for label, value in summary_rows:
        summary.append([label, value])
    _format_sheet(summary)

    # Keep one row per unique image identity while combining all known source
    # relationships.  A valid Helm source always wins over an empty fallback.
    containers: dict[tuple[str, str], dict[str, Any]] = {}

    def add_container(raw: dict[str, Any], *, status: str = "Observed") -> None:
        ref = _reference(raw)
        if ref == "—":
            return
        digest = _text(raw.get("digest") or raw.get("image_digest"), "—")
        if "@" in ref:
            ref, embedded_digest = ref.rsplit("@", 1)
            digest = embedded_digest or digest
        # Prefer a resolved identity and reconcile an earlier unresolved row
        # for the same normalized image reference.
        key = (ref, digest)
        if digest != "—":
            unresolved_key = (ref, "—")
            if unresolved_key in containers and key not in containers:
                row = containers.pop(unresolved_key)
                row["digest"] = digest
                containers[key] = row
        row = containers.setdefault(key, {"image": ref, "digest": digest, "source_file": set(), "source_chart": set(), "status": status})
        row["status"] = status if status != "Observed" else row.get("status", status)
        source = _source(raw)
        if source != "—": row["source_file"].add(source)
        if raw.get("discovered_from") or raw.get("source_chart"):
            row["source_chart"].add(_text(raw.get("source_chart") or raw.get("discovered_from")))

    for raw in [*_items(raw_overview.get("images")), *_items(raw_overview.get("container_images"))]:
        if not isinstance(raw, dict):
            raw = {"image": raw}
        add_container(raw)
    for image in service.images:
        add_container({"image": image.image_reference, "digest": image.image_digest}, status=image.lifecycle_status)
    container_rows = []
    for row in sorted(containers.values(), key=lambda item: item["image"].casefold()):
        ref = row["image"]
        parts = ref.split("@", 1)[0].rsplit(":", 1)
        image_name = parts[0]
        tag = parts[1] if len(parts) == 2 and "/" not in parts[1] else "—"
        path = image_name.split("/")
        registry = path[0] if len(path) > 1 and ("." in path[0] or ":" in path[0] or path[0] == "localhost") else "docker.io"
        repository = "/".join(path[1:-1] if registry != "docker.io" else (path[:-1] if len(path) > 1 else ["library"])) or "—"
        artifact = path[-1] if path else image_name
        container_rows.append([ref, registry, repository, artifact, tag, row["digest"], _join(sorted(row["source_file"])), _join(sorted(row["source_chart"])), row["status"], "Observed"])
    _sheet(workbook, "Containers", ["Image", "Registry", "Repository", "Artifact", "Tag", "Digest", "Source File", "Source Chart / Resource", "Lifecycle Status", "Assessment Status"], container_rows)

    chart_rows = []
    chart_seen = set()
    for raw in chart_records:
        if not isinstance(raw, dict): raw = {"chart": raw}
        name = _text(raw.get("chart") or raw.get("name") or raw.get("artifact"), "Unknown chart")
        key = (name, _text(raw.get("path") or raw.get("chart_path")), _text(raw.get("declared_by")))
        if key in chart_seen: continue
        chart_seen.add(key)
        declared_state = raw.get("enabled") if "enabled" in raw else raw.get("declared_state")
        chart_rows.append([name, _text(raw.get("version"), "—"), _text(raw.get("path") or raw.get("chart_path"), "—"), _source(raw), _text(raw.get("parent_chart") or raw.get("parent"), "—"), _text(raw.get("declared_by"), "—"), _text(declared_state, "—"), _text(raw.get("dependency_status"), "—"), _text(raw.get("render_status") or raw.get("status"), "—")])
    _sheet(workbook, "Helm Charts", ["Chart Name", "Chart Version", "Chart Path", "Source File", "Parent Chart", "Declared By", "Enabled State", "Dependency Status", "Render Status"], sorted(chart_rows, key=lambda row: str(row[0]).casefold()))

    artifact_rows = []
    for raw in overview["artifacts"]:
        artifact_rows.append([raw.get("type"), raw.get("artifact"), raw.get("version"), raw.get("registry"), raw.get("repository"), raw.get("digest"), _source(raw), raw.get("discovered_from")])
    _sheet(workbook, "Artifacts", ["Type", "Name", "Version / Tag", "Registry", "Repository", "Digest", "Source File", "Relationship / Declared By"], artifact_rows)

    _sheet(workbook, "Missing Evidence", ["Type", "Item", "Why Missing", "Source File"], [[row.get("type"), row.get("item"), row.get("reason"), row.get("source_file") or "—"] for row in overview["missing_evidence"]])
    raw_ports = raw_overview.get("ports")
    port_rows = _items(raw_ports) if raw_ports is not None else overview["ports"]
    port_rows = [row for row in port_rows if isinstance(row, dict)]
    _sheet(workbook, "Ports & Protocols", ["Port", "Protocol", "Service", "Declared By", "Source File", "Provenance"], [[row.get("port"), row.get("protocol"), row.get("service"), row.get("declared_by"), row.get("source_file") or "—", row.get("provenance")] for row in port_rows])
    raw_accounts = raw_overview.get("accounts")
    if raw_accounts is None:
        raw_accounts = raw_overview.get("rbac")
    account_rows = _items(raw_accounts) if raw_accounts is not None else overview["accounts"]
    account_rows = [row for row in account_rows if isinstance(row, dict)]
    _sheet(workbook, "Accounts", ["Name", "Scope", "Relationships", "Source File"], [[row.get("name"), row.get("scope") or row.get("namespace") or "—", _join(row.get("relationships") if isinstance(row.get("relationships"), list) else [row.get("relationships")]), row.get("source_file") or "—"] for row in account_rows])
    _sheet(workbook, "Dependencies", ["Dependency", "Used By", "Provides", "Images"], [[row.get("dependency"), row.get("used_by"), row.get("provides"), row.get("images")] for row in overview["dependencies"]])
    _sheet(workbook, "Render Warnings", ["Type", "Chart", "Source", "Message", "Unrecognized Images", "Diagnostic"], [[row.get("type"), row.get("chart"), row.get("source"), row.get("message"), _join(row.get("unrecognized_images") or []), row.get("original_error") or "—"] for row in overview["warnings"]])

    raw_rows = []
    for finding in sorted(service.findings, key=lambda item: (not item.active, item.cve)):
        observations = list(finding.observations) or [None]
        for observation in observations:
            evidence = observation.evidence if observation and isinstance(observation.evidence, dict) else {}
            raw_rows.append([finding.id, finding.cve, finding.severity, "Active" if finding.active else "Resolved", _datetime(finding.first_seen), _datetime(finding.last_seen), observation.id if observation else None, observation.image if observation else None, observation.package if observation else None, observation.installed_version if observation else None, observation.fixed_version if observation else None, evidence.get("description"), evidence.get("data_source")])
    for finding in sorted(service.policy_findings, key=lambda item: (not item.active, item.finding)):
        raw_rows.append([f"policy:{finding.id}", finding.finding, finding.severity, "Active" if finding.active else "Resolved", _datetime(finding.first_seen), _datetime(finding.last_seen), None, finding.target, finding.namespace, None, None, finding.description, finding.scanner])
    raw_headers = ["Finding ID", "CVE", "Severity", "Status", "First Seen", "Last Seen", "Observation ID", "Image", "Package", "Installed Version", "Fixed Version", "Description", "Data Source"]
    _sheet(workbook, "Raw Findings", raw_headers, raw_rows)
    vulnerability_rows = []
    for finding in sorted(service.findings, key=lambda item: (not item.active, item.cve)):
        observations = list(finding.observations) or [None]
        for observation in observations:
            evidence = observation.evidence if observation and isinstance(observation.evidence, dict) else {}
            safe_evidence = {key: value for key, value in evidence.items() if not _SENSITIVE_DETAIL.search(str(key))}
            vulnerability_rows.append([
                finding.id, finding.cve, finding.severity, "Active" if finding.active else "Resolved",
                _datetime(finding.first_seen), _datetime(finding.last_seen), observation.id if observation else None,
                observation.image if observation else None, observation.package if observation else None,
                observation.installed_version if observation else None, observation.fixed_version if observation else None,
                json.dumps(safe_evidence, default=str, sort_keys=True),
            ])
    _sheet(workbook, "Vulnerabilities", ["Finding ID", "CVE", "Severity", "Status", "First Seen", "Last Seen", "Observation ID", "Image", "Package", "Installed Version", "Fixed Version", "Evidence"], vulnerability_rows)
    # Keep the historical sheet name as a compatibility alias for existing
    # consumers while Raw Findings is the authoritative name going forward.
    _sheet(workbook, "Findings", ["Advisory ID", *raw_headers[2:]], [[row[1], *row[2:]] for row in raw_rows])
    for sheet in (workbook["Raw Findings"],):
        for column in ("E", "F"):
            for cell in sheet[column][1:]: cell.number_format = "yyyy-mm-dd hh:mm"

    simplified_rows = []
    for finding in sorted(service.findings, key=lambda item: (not item.active, item.cve)):
        observations = list(finding.observations)
        packages = sorted({_text(item.package) for item in observations if _text(item.package)})
        images = sorted({_text(item.image) for item in observations if _text(item.image)})
        evidence = next((item.evidence for item in reversed(observations) if isinstance(item.evidence, dict)), {})
        simplified_rows.append(["Vulnerability", finding.cve, "; ".join(packages) or "—", "; ".join(images) or "—", evidence.get("description") or "—", finding.severity, "Active" if finding.active else "Resolved", _datetime(view.get("due_dates", {}).get(finding.id)) if finding.active else None])
    for finding in sorted(service.policy_findings, key=lambda item: (not item.active, item.finding)):
        simplified_rows.append(["Configuration", finding.finding, finding.target or "—", finding.namespace or "—", finding.title or finding.description or "—", finding.severity, "Active" if finding.active else "Resolved", _datetime(view.get("policy_due_dates", {}).get(finding.id)) if finding.active else None])
    _sheet(workbook, "Simplified Findings", ["Type", "Item", "Details", "Artifact / Image", "Reason", "Severity", "Status", "Due Date"], simplified_rows)

    configuration_rows = []
    for finding in sorted(service.policy_findings, key=lambda item: (not item.active, item.finding)):
        configuration_rows.append([finding.finding, finding.title, finding.severity, "Active" if finding.active else "Resolved", finding.scanner, finding.framework, finding.target, finding.namespace, _datetime(finding.first_seen), _datetime(finding.last_seen), finding.description, finding.remediation])
    _sheet(workbook, "Configuration Findings", ["Finding", "Title", "Severity", "State", "Scanner", "Framework", "Target", "Namespace", "First Seen", "Last Seen", "Description", "Remediation"], configuration_rows)

    poam_rows = []
    for entry in sorted(poams, key=lambda item: (not item.status == "active", item.created_at or now)):
        linked = entry.finding.cve if entry.finding else (entry.policy_finding.finding if entry.policy_finding else "—")
        severity = entry.finding.severity if entry.finding else (entry.policy_finding.severity if entry.policy_finding else "—")
        poam_rows.append([linked, entry.item_type, severity, _status_for_poam(entry), entry.title, _datetime(entry.created_at), _datetime(entry.due_date), entry.created_by.display_name if entry.created_by else "—", entry.approved_by.display_name if entry.approved_by else "—", _datetime(entry.approved_at), entry.description, entry.remediation, entry.ticket])
    _sheet(workbook, "POA&Ms", ["Finding", "Type", "Severity", "Status", "Title", "Created", "Due Date", "Created By", "Approved By", "Approval Date", "Description", "Remediation", "Ticket"], poam_rows)

    exception_rows = []
    for exception in sorted(exceptions, key=lambda item: item.created_at or now):
        finding = getattr(exception, "finding", None) or getattr(exception, "policy_finding", None)
        exception_rows.append([getattr(finding, "cve", None) or getattr(finding, "finding", "—"), "Configuration" if exception.policy_finding else "Vulnerability", getattr(finding, "severity", "—"), _status_for_exception(exception, now), _datetime(exception.expires_at), exception.approved_by, _datetime(exception.starts_at), _datetime(exception.revoked_at), exception.justification, exception.ticket])
    _sheet(workbook, "Exceptions", ["Finding", "Type", "Severity", "Status", "Expiration", "Approved By", "Approval Date", "Revoked Date", "Reason / Justification", "Ticket"], exception_rows)

    mitigation_rows = []
    for entry in sorted(mitigations, key=lambda item: item.created_at or now):
        finding = entry.finding or entry.policy_finding
        mitigation_rows.append([getattr(finding, "cve", None) or getattr(finding, "finding", "—"), entry.item_type, getattr(finding, "severity", "—"), _status_for_poam(entry), entry.title, _datetime(entry.created_at), _datetime(entry.due_date), entry.description, entry.remediation, entry.ticket])
    _sheet(workbook, "Mitigations", ["Finding", "Type", "Severity", "Status", "Title", "Created", "Due Date", "Description", "Remediation", "Ticket"], mitigation_rows)

    activity_rows = []
    for event in activity_events:
        detail = event.detail if isinstance(event.detail, dict) else {}
        activity_rows.append([_datetime(event.created_at), event.actor.display_name if event.actor else detail.get("actor_display_name") or "System", event.action, event.target_type, event.target_id, _safe_detail(detail)])
    for event in service.archive_events:
        activity_rows.append([_datetime(event.created_at), event.performed_by, f"archive.{event.action}", "service", service.id, f"reason={event.reason}; ticket={event.ticket or '—'}"])
    for history in poam_histories:
        activity_rows.append([_datetime(history.created_at), history.actor.display_name if history.actor else "System", f"poam.{history.action}", "poam_entry", history.poam_id, _text(history.note)])
    _sheet(workbook, "Activity", ["Timestamp", "Actor", "Action", "Object Type", "Object", "Details"], sorted(activity_rows, key=lambda row: row[0] or datetime.min))
    return workbook


def service_export_filename(service: Any, now: datetime) -> str:
    return f"CATS_{_safe_filename(service.name)}_{now:%Y-%m-%d}.xlsx"
