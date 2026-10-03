"""Scalar projections for the findings page, without loading evidence history.

Risk and compliance still require one scalar row per finding. This is an
intentional service-sized scan, not a paginated risk evaluation. Evidence is
bounded to the latest observation per finding; page support loads only the
selected findings' relevant execution.
"""
from types import SimpleNamespace

from sqlalchemy import func, select, tuple_

from .models import (
    ExceptionRecord, Execution, Finding, FindingObservation, Group,
    PoamEntry, PolicyExceptionRecord, PolicyFinding, ServiceArchiveEvent,
    ServiceGroup, ServiceVersion,
)


def _rows(db, model, *conditions, order_by=None):
    statement = select(*model.__table__.columns).where(*conditions)
    if order_by is not None:
        statement = statement.order_by(order_by)
    return [SimpleNamespace(**dict(row)) for row in db.execute(statement).mappings()]


def prepare_findings_view(db, service, now, configuration, service_view_callback):
    """Return the existing view contract backed by scalar, history-free adapters."""
    proxy = SimpleNamespace(**{
        column.key: getattr(service, column.key) for column in service.__table__.columns
    })
    proxy.findings = _rows(db, Finding, Finding.service_id == service.id, order_by=Finding.id)
    proxy.policy_findings = _rows(db, PolicyFinding, PolicyFinding.service_id == service.id,
                                  order_by=PolicyFinding.id)
    findings = {finding.id: finding for finding in proxy.findings}
    policies = {finding.id: finding for finding in proxy.policy_findings}
    for finding in findings.values():
        finding.exceptions = []
        finding.observations = []
    for finding in policies.values():
        finding.exceptions = []
        finding.type = "Configuration"

    for model, parent_model, foreign_key, parents in (
        (ExceptionRecord, Finding, ExceptionRecord.finding_id, findings),
        (PolicyExceptionRecord, PolicyFinding, PolicyExceptionRecord.policy_finding_id, policies),
    ):
        statement = (select(*model.__table__.columns)
                     .join(parent_model, foreign_key == parent_model.id)
                     .where(parent_model.service_id == service.id, model.revoked_at.is_(None),
                            model.starts_at <= now, model.expires_at > now)
                     .order_by(model.id))
        for row in db.execute(statement).mappings():
            exception = SimpleNamespace(**dict(row))
            parents[getattr(exception, foreign_key.key)].exceptions.append(exception)

    latest_ids = (select(func.max(FindingObservation.id).label("id"))
                  .join(Finding, Finding.id == FindingObservation.finding_id)
                  .where(Finding.service_id == service.id)
                  .group_by(FindingObservation.finding_id).subquery())
    for observation in _rows(db, FindingObservation, FindingObservation.id.in_(select(latest_ids.c.id))):
        findings[observation.finding_id].observations = [observation]

    execution_query = select(Execution).where(Execution.service_id == service.id)
    if service.current_version_id is not None:
        execution_query = execution_query.where(Execution.service_version_id == service.current_version_id)
    latest_execution = db.scalar(execution_query.order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    # The header evaluates the current version, while detail-page evidence has
    # historically used the newest scan across every version. Keep both bounded
    # candidates so callers can retain that distinction without scan history.
    global_latest = db.scalar(select(Execution).where(Execution.service_id == service.id)
                              .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    proxy.executions = list({execution.id: execution for execution in (latest_execution, global_latest)
                             if execution is not None}.values())
    archive_query = (select(*ServiceArchiveEvent.__table__.columns)
                     .where(ServiceArchiveEvent.service_id == service.id)
                     .order_by(ServiceArchiveEvent.created_at.desc(), ServiceArchiveEvent.id.desc()).limit(1))
    proxy.archive_events = [SimpleNamespace(**dict(row)) for row in db.execute(archive_query).mappings()]
    group_query = (select(*Group.__table__.columns)
                   .join(ServiceGroup, ServiceGroup.group_id == Group.id)
                   .where(ServiceGroup.service_id == service.id).order_by(Group.id))
    proxy.groups = [SimpleNamespace(**dict(row)) for row in db.execute(group_query).mappings()]
    versions = _rows(db, ServiceVersion, ServiceVersion.id == service.current_version_id) if service.current_version_id else []
    proxy.current_version = versions[0] if versions else None
    proxy.poam_entries = _rows(db, PoamEntry, PoamEntry.service_id == service.id, PoamEntry.status == "active")
    return service_view_callback(proxy, now, configuration), proxy, latest_execution


def load_page_support(db, service_id, findings, latest_execution):
    """Attach relevant scalar observations and return images for selected rows.

    Active findings use the current execution. Historical findings use the
    execution containing their latest observation, matching the legacy page.
    """
    selected = {finding.id: finding for finding in findings}
    if not selected:
        return {}
    latest = (select(FindingObservation.finding_id,
                     func.max(FindingObservation.id).label("id"))
              .join(Finding, Finding.id == FindingObservation.finding_id)
              .where(Finding.service_id == service_id, Finding.id.in_(selected))
              .group_by(FindingObservation.finding_id).subquery())
    execution_by_finding = dict(db.execute(
        select(FindingObservation.finding_id, FindingObservation.execution_id)
        .join(latest, latest.c.id == FindingObservation.id)
    ).all())
    for finding in selected.values():
        if finding.active and latest_execution:
            execution_by_finding[finding.id] = latest_execution.id
    observations_by_finding = {finding_id: [] for finding_id in selected}
    # Match exact pairs so a page containing several historical executions does
    # not accidentally retrieve each selected finding's history across them.
    if execution_by_finding:
        observations = _rows(
            db, FindingObservation,
            tuple_(FindingObservation.finding_id, FindingObservation.execution_id)
            .in_(list(execution_by_finding.items())),
            order_by=FindingObservation.id,
        )
        for observation in observations:
            if execution_by_finding.get(observation.finding_id) == observation.execution_id:
                observations_by_finding[observation.finding_id].append(observation)
    for finding in selected.values():
        if isinstance(finding, SimpleNamespace):
            finding.observations = observations_by_finding[finding.id]
    return {finding_id: sorted({observation.image for observation in observations})
            for finding_id, observations in observations_by_finding.items()}


def load_filter_support(db, service_id, findings):
    """Load at most twenty scalar observations per projected search candidate.

    Call only when query/resource filters are present. The window is evaluated
    in SQL, preserving the legacy latest-twenty search surface without fetching
    the history into application memory.
    """
    selected = {finding.id: finding for finding in findings}
    if not selected:
        return
    ranked = (select(FindingObservation.id,
                     func.row_number().over(partition_by=FindingObservation.finding_id,
                                            order_by=FindingObservation.id.desc()).label("position"))
              .join(Finding, Finding.id == FindingObservation.finding_id)
              .where(Finding.service_id == service_id, Finding.id.in_(selected)).subquery())
    observations = _rows(db, FindingObservation,
                         FindingObservation.id.in_(select(ranked.c.id).where(ranked.c.position <= 20)),
                         order_by=FindingObservation.id.desc())
    for finding in selected.values():
        if isinstance(finding, SimpleNamespace):
            finding.observations = []
    for observation in observations:
        finding = selected[observation.finding_id]
        if isinstance(finding, SimpleNamespace):
            finding.observations.append(observation)


def load_simplified_support(db, service_id, findings, latest_execution):
    """Load current evidence before grouping, with latest-ever fallback.

    Unlike page images, simplified remediation uses the latest-ever observation
    when a finding has no current execution evidence. Current image sets still
    remain empty in that case because the fallback retains its execution ID.
    """
    selected = {finding.id: finding for finding in findings if finding.active}
    if not selected:
        return
    # Preserve latest-ever evidence already supplied by the risk projection or
    # bounded search support before replacing observations with current rows.
    fallbacks = {finding.id: max(finding.observations, key=lambda row: row.id, default=None)
                 for finding in selected.values()}
    load_page_support(db, service_id, selected.values(), latest_execution)
    for finding in selected.values():
        if isinstance(finding, SimpleNamespace) and not finding.observations and fallbacks[finding.id]:
            finding.observations = [fallbacks[finding.id]]
