"""History-free header preparation for service tabs with independent row queries.

Tabs needing finding lists retain canonical scalar policy evaluation. The
architecture and validation frontend header uses database compliance predicates
and bounded metadata without projecting any finding or observation rows.
"""
from .findings_query import prepare_findings_view


def prepare_service_tab_view(db, service, now, configuration, service_view_callback, *, include_global_latest=True,
                             header_only=False):
    if header_only:
        return _prepare_header(db, service, now, configuration, service_view_callback,
                               include_global_latest=include_global_latest)
    return prepare_findings_view(db, service, now, configuration, service_view_callback,
                                 include_global_latest=include_global_latest)


def _prepare_header(db, service, now, configuration, service_view_callback, *, include_global_latest):
    """Architecture/validation's explicit frontend header, without finding rows.

    These pages consume only service metadata, version, archive, scan time,
    skipped evidence and compliance. Other tabs retain the full finding view.
    Evaluate evidence against the current version with the canonical callback;
    test vulnerability and hardening compliance with the shared SQL policy.
    """
    from types import SimpleNamespace
    from sqlalchemy import func, select
    from sqlalchemy.orm import defer
    from .execution_summaries import load_execution_summaries
    from .findings_query import _rows
    from .main import _risk_finding_expressions, _hardening_overdue_expression
    from .models import (Execution, Finding, FindingObservation, ExceptionRecord,
                         PolicyFinding, PolicyExceptionRecord, Group, ServiceGroup,
                         ServiceArchiveEvent, ServiceVersion)

    proxy = SimpleNamespace(**{column.key: getattr(service, column.key)
                               for column in service.__table__.columns})
    proxy.findings, proxy.policy_findings, proxy.poam_entries = [], [], []
    proxy.groups = [SimpleNamespace(**dict(row)) for row in db.execute(
        select(*Group.__table__.columns).join(ServiceGroup, ServiceGroup.group_id == Group.id)
        .where(ServiceGroup.service_id == service.id).order_by(Group.id)).mappings()]
    proxy.archive_events = [SimpleNamespace(**dict(row)) for row in db.execute(
        select(*ServiceArchiveEvent.__table__.columns).where(ServiceArchiveEvent.service_id == service.id)
        .order_by(ServiceArchiveEvent.created_at.desc(), ServiceArchiveEvent.id.desc()).limit(1)).mappings()]
    proxy.current_version = next(iter(_rows(db, ServiceVersion,
        ServiceVersion.id == service.current_version_id)), None) if service.current_version_id else None
    scan_query = select(Execution).options(defer(Execution.raw_payload)).where(Execution.service_id == service.id)
    if service.current_version_id is not None:
        scan_query = scan_query.where(Execution.service_version_id == service.current_version_id)
    current = db.scalar(scan_query.order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    latest = db.scalar(select(Execution).options(defer(Execution.raw_payload)).where(Execution.service_id == service.id)
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1)) if include_global_latest else current
    view = prepare_summary_header(db, proxy, current, latest, now, configuration, service_view_callback)
    configs = {service.id: configuration}
    exception = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id,
        ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now,
        ExceptionRecord.expires_at > now).exists()
    _, noncompliant, needs_observations = _risk_finding_expressions(configs, now, exception)
    vulnerable = select(Finding.id).where(Finding.service_id == service.id,
        Finding.active.is_(True), noncompliant, ~exception)
    if needs_observations:
        latest_observation = select(FindingObservation.finding_id,
            func.max(FindingObservation.id).label("latest_id")).join(Finding,
                Finding.id == FindingObservation.finding_id).where(Finding.service_id == service.id)
        latest_observation = latest_observation.group_by(FindingObservation.finding_id).subquery()
        vulnerable = vulnerable.outerjoin(latest_observation,
            latest_observation.c.finding_id == Finding.id).outerjoin(FindingObservation,
                FindingObservation.id == latest_observation.c.latest_id)
    policy_exception = select(PolicyExceptionRecord.id).where(
        PolicyExceptionRecord.policy_finding_id == PolicyFinding.id,
        PolicyExceptionRecord.revoked_at.is_(None), PolicyExceptionRecord.starts_at <= now,
        PolicyExceptionRecord.expires_at > now).exists()
    hardening = select(PolicyFinding.id).where(PolicyFinding.service_id == service.id,
        PolicyFinding.active.is_(True), _hardening_overdue_expression(configs, now), ~policy_exception)
    has_vulnerability, has_hardening = db.execute(select(vulnerable.exists(), hardening.exists())).one()
    view["compliant"] = not has_vulnerability and not has_hardening and not view["evidence_noncompliant"]
    return view, proxy, current


def prepare_dependency_evidence(db, service, selected_id, latest_scan):
    """Retain every history choice while loading only selected scan evidence."""
    from types import SimpleNamespace
    from sqlalchemy import select
    from sqlalchemy.orm import defer
    from .models import Execution, FindingObservation
    from .findings_query import _rows

    columns = [column for column in Execution.__table__.columns if column.key != "raw_payload"]
    choices = [SimpleNamespace(**dict(row)) for row in db.execute(
        select(*columns).where(Execution.service_id == service.id)).mappings()]
    selected = db.scalar(select(Execution).options(defer(Execution.raw_payload)).where(Execution.service_id == service.id,
        Execution.id == selected_id)) if selected_id is not None else latest_scan
    return selected, choices


def prepare_summary_header(db, proxy, current, latest, now, configuration, service_view_callback):
    """Run canonical header callback using bounded persisted evidence previews.

    Restore deferred authoritative executions for detail readers afterward.
    """
    from types import SimpleNamespace
    from .models import Execution
    from .execution_summaries import load_execution_summaries
    executions = list({scan.id: scan for scan in (current, latest) if scan is not None}.values())
    summaries = load_execution_summaries(db, [scan.id for scan in executions], include_header=True)
    # Callback sees bounded source metadata. Keep the actual deferred ORM
    # executions afterward so detail tabs hydrate authoritative evidence cold.
    proxy.executions = [SimpleNamespace(**{column.key: getattr(scan, column.key)
        for column in Execution.__table__.columns if column.key != "raw_payload"},
        raw_payload={"service": {"version": summaries[scan.id].get("raw_version")}})
        for scan in executions]
    view = service_view_callback(proxy, now, configuration)
    proxy.executions = executions
    if current is not None:
        summary = summaries[current.id]
        header = summary["header"]
        skipped_images = header["skipped_images"]
        skipped_charts = header["skipped_charts"]
        missing = header["missing_evidence"]
        incomplete = not current.complete or bool(header["missing_evidence_count"])
        evidence_state = "Incomplete" if incomplete else "Complete"
        if summary["skipped_image_count"] and incomplete:
            evidence_state = f'Incomplete · {summary["skipped_image_count"]} skipped'
        if summary["skipped_chart_count"] and incomplete:
            evidence_state = (f'Incomplete · {summary["skipped_image_count"]} skipped images, {summary["skipped_chart_count"]} skipped charts'
                              if summary["skipped_image_count"] else f'Incomplete · {summary["skipped_chart_count"]} skipped charts')
        evidence_noncompliant = incomplete and configuration.get("incomplete_noncompliant") == "true"
        view.update(skipped_images=skipped_images, skipped_charts=skipped_charts,
                    incomplete=incomplete, evidence_state=evidence_state,
                    evidence_noncompliant=evidence_noncompliant,
                    skipped_image_count=summary["skipped_image_count"],
                    skipped_chart_count=summary["skipped_chart_count"],
                    missing_evidence_count=header["missing_evidence_count"],
                    evidence_preview_truncated=any((summary["skipped_image_count"] > len(skipped_images),
                        summary["skipped_chart_count"] > len(skipped_charts),
                        header["missing_evidence_count"] > len(missing))))
        view["warning_items"] = [item for item in view["warning_items"] if item["type"] != "Evidence"]
        view["noncompliance_items"] = [item for item in view["noncompliance_items"] if item["type"] != "Evidence"]
        if incomplete and not evidence_noncompliant:
            view["warning_items"].append({"type": "Evidence", "item": "Incomplete evidence",
                "reason": "Latest assessment is incomplete", "due": None,
                "href": f"/services/{proxy.service_key}?overview=true"})
        if evidence_noncompliant:
            view["noncompliance_items"].extend({"type": "Evidence",
                "item": row["type"] if row["item"] != "Assessment" else "Assessment",
                "evidence_image": row["item"] if row["item"] != "Assessment" else "",
                "source_file": row.get("source_file", ""), "reason": row["reason"],
                "due": None, "status": "Non-Compliant"} for row in missing)
            view["noncompliance_items"].sort(key=lambda item: (
                str(item.get("item", "")).casefold(), str(item.get("type", "")).casefold()))
    return view
