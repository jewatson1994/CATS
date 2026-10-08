"""SQL count projection for the Service Overview finding summary.

Overview shows five numbers (active, exceptions, resolved, non-compliant and
warnings).  They are computed here with the same database predicates as the
Services dashboard and the findings tabs, so no finding, exception or
observation row is transferred to Python.  Semantics mirror ``service_view``:

* active       eligible, not excepted, not non-compliant; plus active policy
               findings that are neither excepted nor non-compliant
* exceptions   eligible findings and policy findings with an active exception
* resolved     inactive findings plus inactive policy findings
* noncompliant overdue risk findings, overdue hardening findings, and every
               missing-evidence row when incomplete evidence is non-compliant
* warnings     CVE due dates approaching and exceptions expiring (restricted to
               CVEs of eligible findings), plus the non-finding warning rows the
               header already produced (evidence, watchlist, validation)
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from sqlalchemy import and_, case, false, func, or_, select, true


def _due_window_expression(model, configuration: dict, now: datetime, warning_days: int):
    """``now < episode_started + due_days <= now + warning_days`` per severity rule."""
    overdue_days = max(1, int(configuration.get("overdue_days", "90")))
    due_by_severity = {}
    if configuration.get("compliance_mode") == "raw":
        try:
            rules = json.loads(configuration.get("raw_due_rules", "[]"))
        except (TypeError, ValueError):
            rules = []
        for rule in rules if isinstance(rules, list) else []:
            if isinstance(rule, dict):
                due_by_severity[str(rule.get("severity", "")).lower()] = max(1, int(rule.get("days", overdue_days)))
    cutoff = now + timedelta(days=warning_days)
    severity = func.lower(model.severity)

    def window(days):
        return and_(model.episode_started > now - timedelta(days=days),
                    model.episode_started <= cutoff - timedelta(days=days))
    parts = [and_(severity == name, window(days)) for name, days in due_by_severity.items()]
    known = list(due_by_severity)
    parts.append(and_(or_(~severity.in_(known), model.severity.is_(None)) if known else true(), window(overdue_days)))
    return or_(*parts)


def overview_finding_counts(db, service_id: int, configuration: dict, now: datetime, view: dict) -> dict[str, int]:
    from .main import _hardening_overdue_expression, _risk_finding_expressions
    from .models import (ExceptionRecord, Finding, FindingObservation, PolicyExceptionRecord, PolicyFinding)
    from .sql_sets import member_of

    configurations = {service_id: configuration}
    warning_days = max(1, int(configuration.get("warning_days", "14")))
    cutoff = now + timedelta(days=warning_days)
    active_exception = and_(ExceptionRecord.finding_id == Finding.id, ExceptionRecord.revoked_at.is_(None),
                            ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now)
    exception = select(ExceptionRecord.id).where(active_exception).exists()
    eligible, noncompliant, needs_observations = _risk_finding_expressions(configurations, now, exception)

    def with_observations(query):
        if not needs_observations:
            return query
        latest = select(FindingObservation.finding_id, func.max(FindingObservation.id).label("latest_id")).join(
            Finding, Finding.id == FindingObservation.finding_id).where(
            Finding.service_id == service_id, Finding.active.is_(True)).group_by(FindingObservation.finding_id).subquery()
        return query.outerjoin(latest, latest.c.finding_id == Finding.id).outerjoin(
            FindingObservation, FindingObservation.id == latest.c.latest_id)

    from . import finding_classification as classification
    # Overview GETs never write: use rows only when they are already current.
    if classification.is_current(db, service_id, configuration, now):
        return _classified_counts(db, service_id, configuration, now, view, warning_days, cutoff)

    finding = db.execute(with_observations(select(
        func.count(Finding.id).label("all"),
        func.coalesce(func.sum(case((eligible, 1), else_=0)), 0).label("eligible"),
        func.coalesce(func.sum(case((and_(eligible, exception), 1), else_=0)), 0).label("excepted"),
        func.coalesce(func.sum(case((and_(noncompliant, ~exception), 1), else_=0)), 0).label("noncompliant"),
    ).where(Finding.service_id == service_id, Finding.active.is_(True)))).one()

    policy_exception = select(PolicyExceptionRecord.id).where(
        PolicyExceptionRecord.policy_finding_id == PolicyFinding.id, PolicyExceptionRecord.revoked_at.is_(None),
        PolicyExceptionRecord.starts_at <= now, PolicyExceptionRecord.expires_at > now).exists()
    policy = db.execute(select(
        func.count(PolicyFinding.id).label("all"),
        func.coalesce(func.sum(case((policy_exception, 1), else_=0)), 0).label("excepted"),
        func.coalesce(func.sum(case((and_(_hardening_overdue_expression(configurations, now), ~policy_exception), 1),
                                    else_=0)), 0).label("noncompliant"),
    ).where(PolicyFinding.service_id == service_id, PolicyFinding.active.is_(True))).one()

    resolved = (db.scalar(select(func.count(Finding.id)).where(Finding.service_id == service_id, Finding.active.is_(False))) or 0) \
        + (db.scalar(select(func.count(PolicyFinding.id)).where(PolicyFinding.service_id == service_id,
                                                                PolicyFinding.active.is_(False))) or 0)

    # service_view uses the first active exception (relationship order: id).
    first_exception_expiry = select(ExceptionRecord.expires_at).where(active_exception).order_by(
        ExceptionRecord.id).limit(1).scalar_subquery()
    due_window = _due_window_expression(Finding, configuration, now, warning_days)
    candidates = db.execute(select(Finding.cve).where(
        Finding.service_id == service_id, Finding.active.is_(True),
        or_(and_(~exception, due_window), and_(exception, first_exception_expiry <= cutoff)))).scalars().all()
    warning_count = 0
    if candidates:
        eligible_cves = set(db.execute(with_observations(select(Finding.cve).distinct().where(
            Finding.service_id == service_id, Finding.active.is_(True), eligible,
            member_of(Finding.cve, sorted(set(candidates)))))).scalars())
        warning_count = sum(cve in eligible_cves for cve in candidates)

    evidence_noncompliant = bool(view.get("evidence_noncompliant"))
    other_warnings = [item for item in view.get("warning_items", []) if item.get("type") not in {"CVE", "Exception"}]
    return {
        "active": int(finding.eligible) - int(finding.excepted) - int(finding.noncompliant)
        + int(policy.all) - int(policy.excepted) - int(policy.noncompliant),
        "exceptions": int(finding.excepted) + int(policy.excepted),
        "resolved": int(resolved),
        "noncompliant": int(finding.noncompliant) + int(policy.noncompliant)
        + (int(view.get("missing_evidence_count") or 0) if evidence_noncompliant else 0),
        "warnings": warning_count + len(other_warnings),
    }


def _policy_and_resolved(db, service_id, configurations, now):
    from .main import _hardening_overdue_expression
    from .models import Finding, PolicyExceptionRecord, PolicyFinding
    policy_exception = select(PolicyExceptionRecord.id).where(
        PolicyExceptionRecord.policy_finding_id == PolicyFinding.id, PolicyExceptionRecord.revoked_at.is_(None),
        PolicyExceptionRecord.starts_at <= now, PolicyExceptionRecord.expires_at > now).exists()
    policy = db.execute(select(
        func.count(PolicyFinding.id).label("all"),
        func.coalesce(func.sum(case((policy_exception, 1), else_=0)), 0).label("excepted"),
        func.coalesce(func.sum(case((and_(_hardening_overdue_expression(configurations, now), ~policy_exception), 1),
                                    else_=0)), 0).label("noncompliant"),
    ).where(PolicyFinding.service_id == service_id, PolicyFinding.active.is_(True))).one()
    resolved = (db.scalar(select(func.count(Finding.id)).where(Finding.service_id == service_id, Finding.active.is_(False))) or 0) \
        + (db.scalar(select(func.count(PolicyFinding.id)).where(PolicyFinding.service_id == service_id,
                                                                PolicyFinding.active.is_(False))) or 0)
    return policy, resolved


def _classified_counts(db, service_id, configuration, now, view, warning_days, cutoff):
    """``overview_finding_counts`` from current classification rows (same predicates)."""
    from .finding_classification import FC, predicates
    from .models import ExceptionRecord
    from .sql_sets import member_of
    configurations = {service_id: configuration}
    eligible, excepted, noncompliant = predicates(configurations, now)
    finding = db.execute(select(
        func.count(FC.finding_id).label("all"),
        func.coalesce(func.sum(case((eligible, 1), else_=0)), 0).label("eligible"),
        func.coalesce(func.sum(case((and_(eligible, excepted), 1), else_=0)), 0).label("excepted"),
        func.coalesce(func.sum(case((and_(noncompliant, ~excepted), 1), else_=0)), 0).label("noncompliant"),
    ).where(FC.service_id == service_id, FC.active.is_(True))).one()
    policy, resolved = _policy_and_resolved(db, service_id, configurations, now)
    # service_view uses the first active exception (relationship order: id).
    first_exception_expiry = select(ExceptionRecord.expires_at).where(
        ExceptionRecord.finding_id == FC.finding_id, ExceptionRecord.revoked_at.is_(None),
        ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).order_by(
        ExceptionRecord.id).limit(1).correlate(FC).scalar_subquery()
    due_window = _due_window_expression(FC, configuration, now, warning_days)
    candidates = db.execute(select(FC.cve).where(
        FC.service_id == service_id, FC.active.is_(True),
        or_(and_(~excepted, due_window), and_(excepted, first_exception_expiry <= cutoff)))).scalars().all()
    warning_count = 0
    if candidates:
        eligible_cves = set(db.execute(select(FC.cve).distinct().where(
            FC.service_id == service_id, FC.active.is_(True), eligible,
            member_of(FC.cve, sorted(set(candidates))))).scalars())
        warning_count = sum(cve in eligible_cves for cve in candidates)
    evidence_noncompliant = bool(view.get("evidence_noncompliant"))
    other_warnings = [item for item in view.get("warning_items", []) if item.get("type") not in {"CVE", "Exception"}]
    return {
        "active": int(finding.eligible) - int(finding.excepted) - int(finding.noncompliant)
        + int(policy.all) - int(policy.excepted) - int(policy.noncompliant),
        "exceptions": int(finding.excepted) + int(policy.excepted),
        "resolved": int(resolved),
        "noncompliant": int(finding.noncompliant) + int(policy.noncompliant)
        + (int(view.get("missing_evidence_count") or 0) if evidence_noncompliant else 0),
        "warnings": warning_count + len(other_warnings),
    }
