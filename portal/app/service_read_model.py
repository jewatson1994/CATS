"""Page-sized finding adapters; summary counts never stand in for real rows."""
from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select, union
from sqlalchemy.orm import defer

from .findings_query import _rows, load_page_support
from .findings_sql import get_raw_finding_page
from .models import (Execution, Finding, FindingObservation, Group, PolicyFinding,
                     ServiceArchiveEvent, ServiceGroup, ServiceVersion)


def excepted_selectors(service_id, configuration, now, classified):
    """SQL id selectors for the Exceptions state, matching ``service_view``:

    * ``excepted``: active, risk-eligible findings with a current exception;
    * ``policy_excepted``: active policy findings with a current exception.
    """
    from .findings_sql import _current
    from .models import ExceptionRecord, PolicyExceptionRecord
    if classified:
        from .finding_classification import FC
        excepted = select(FC.finding_id).where(FC.service_id == service_id, FC.active.is_(True),
                                               FC.eligible.is_(True), FC.excepted.is_(True))
    else:
        from .main import _risk_finding_expressions
        exception = select(ExceptionRecord.id).where(*_current(ExceptionRecord, ExceptionRecord.finding_id, Finding.id, now)).exists()
        eligible, _, needs_observations = _risk_finding_expressions({service_id: configuration}, now, exception)
        excepted = select(Finding.id).where(Finding.service_id == service_id, Finding.active.is_(True), eligible, exception)
        if needs_observations:
            from sqlalchemy import func
            latest = select(FindingObservation.finding_id, func.max(FindingObservation.id).label("latest_id")).join(
                Finding, Finding.id == FindingObservation.finding_id).where(Finding.service_id == service_id).group_by(
                FindingObservation.finding_id).subquery()
            excepted = excepted.outerjoin(latest, latest.c.finding_id == Finding.id).outerjoin(
                FindingObservation, FindingObservation.id == latest.c.latest_id)
    policy_exception = select(PolicyExceptionRecord.id).where(*_current(
        PolicyExceptionRecord, PolicyExceptionRecord.policy_finding_id, PolicyFinding.id, now)).exists()
    policy = select(PolicyFinding.id).where(PolicyFinding.service_id == service_id, PolicyFinding.active.is_(True),
                                            policy_exception)
    return {"excepted": excepted, "policy_excepted": policy}


def prepare_raw_page(db, service, now, configuration, service_view, summary_view,
                     *, state, finding_type, severities, query, resource, page, page_size, severity_query=None,
                     policy_severity_query=None):
    """Hydrate only the selected page, and evaluate the header in SQL.

    Raw active and resolved visibility has no risk-policy membership filter.
    Exceptions uses the policy evaluator's exact selectors in SQL (stored
    classification rows when current, the live expressions otherwise).
    """
    from .finding_classification import ensure_current
    # The currency check reads the latest execution itself.
    classified = ensure_current(db, service.id, configuration, now)
    selectors = excepted_selectors(service.id, configuration, now, classified) if state == "exceptions" else {}
    result = get_raw_finding_page(db, service.id, selectors, now, state=state,
        finding_type=finding_type, severities=severities, query=query,
        resource=resource, page=page, page_size=page_size, raw_selector=state != "exceptions",
        classified=classified)
    proxy = SimpleNamespace(**{c.key: getattr(service, c.key) for c in service.__table__.columns})
    proxy.findings = result["findings"]
    proxy.policy_findings = result["policy_findings"]
    proxy.groups = [SimpleNamespace(**dict(row)) for row in db.execute(
        select(*Group.__table__.columns).join(ServiceGroup, ServiceGroup.group_id == Group.id)
        .where(ServiceGroup.service_id == service.id).order_by(Group.id)).mappings()]
    proxy.archive_events = _rows(db, ServiceArchiveEvent,
        ServiceArchiveEvent.id == select(ServiceArchiveEvent.id)
        .where(ServiceArchiveEvent.service_id == service.id)
        .order_by(ServiceArchiveEvent.created_at.desc(), ServiceArchiveEvent.id.desc()).limit(1).scalar_subquery())
    proxy.current_version = next(iter(_rows(db, ServiceVersion,
        ServiceVersion.id == service.current_version_id)), None) if service.current_version_id else None
    proxy.poam_entries = []
    current = select(Execution).options(defer(Execution.raw_payload)).where(Execution.service_id == service.id)
    if service.current_version_id is not None:
        current = current.where(Execution.service_version_id == service.current_version_id)
    current = db.scalar(current.order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    latest = db.scalar(select(Execution).options(defer(Execution.raw_payload)).where(Execution.service_id == service.id)
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    proxy.executions = list({e.id: e for e in (current, latest) if e is not None}.values())
    images = load_page_support(db, service.id, proxy.findings, latest)
    # Policy/risk display uses latest-ever observation, independently of the
    # execution used for the page's affected-image set.
    from sqlalchemy import func
    ids = [f.id for f in proxy.findings]
    observations = {}
    if ids:
        latest_ids = select(func.max(FindingObservation.id)).where(
            FindingObservation.finding_id.in_(ids)).group_by(FindingObservation.finding_id)
        if classified:
            from .finding_classification import FC
            latest_ids = select(FC.latest_observation_id).where(FC.finding_id.in_(ids), FC.latest_observation_id.is_not(None))
        observations = {o.finding_id: o for o in _rows(db, FindingObservation,
            FindingObservation.id.in_(latest_ids))}
    page_findings = []
    for finding in proxy.findings:
        row = SimpleNamespace(**{c.key: getattr(finding, c.key) for c in Finding.__table__.columns})
        row.exceptions = finding.exceptions
        row.observations = [observations[row.id]] if row.id in observations else []
        page_findings.append(row)
    proxy.findings = page_findings
    from .service_tab_queries import prepare_summary_header
    view = prepare_summary_header(db, proxy, current, latest, now, configuration, service_view)
    summary = summary_view(db, service, now, configuration)
    # Dashboard evidence describes the latest global execution; service headers
    # describe the selected current version. Reuse SQL risk counts but retain
    # the canonical current-version evidence decision above.
    view["compliant"] = not summary["noncompliant"] and not summary["policy_noncompliant"] and not view["evidence_noncompliant"]
    view["oldest_age"] = summary["oldest_age"]
    # The policy evaluator assigns due dates to active rows only, as before.
    stored_choices = None
    if classified and severity_query is not None:
        # The Raw severity choices, from the stored classification: inactive
        # findings, findings without a current exception, and eligible ones.
        from .finding_classification import severity_choices
        stored = severity_choices(db, service.id)
        stored_choices = stored[1] if stored else None
        if stored_choices is None:
            from sqlalchemy import or_
            from .finding_classification import FC
            severity_query = select(FC.severity).where(FC.service_id == service.id, or_(
                FC.active.is_(False), FC.excepted.is_(False), FC.eligible.is_(True)))
    policy = policy_severity_query if policy_severity_query is not None else select(PolicyFinding.severity).where(
        PolicyFinding.service_id == service.id)
    if stored_choices is not None:
        severity_rows = list(stored_choices) + list(db.execute(policy).scalars())
    else:
        severity_rows = db.execute(union(
            severity_query if severity_query is not None else select(Finding.severity).where(Finding.service_id == service.id),
            policy)).scalars()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    severities = sorted({str(value) for value in severity_rows if value},
        key=lambda value: (order.get(value.casefold(), 4), value.casefold()))
    return view, proxy, latest, result, images, severities
