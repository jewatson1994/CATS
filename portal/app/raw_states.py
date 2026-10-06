"""SQL-paged Raw Findings views for the Non-Compliant and Warnings states.

The legacy implementation materialized every finding of the service, evaluated
``service_view`` in Python, then sorted, filtered and sliced the result.  These
queries select, order and count the same rows in the database and project only
the requested page, keeping the item dictionaries, ordering and filters
identical:

* Non-Compliant rows are ordered by (item, type) case-insensitively and by code
  point (``COLLATE "C"`` on PostgreSQL); equal keys keep CVE rows by finding id,
  then configuration rows by id, then evidence rows in their recorded order.  Text filtering matches the joined, per-field
  (500 character) text of each row; a severity filter matches no row because
  non-compliance items carry no severity.  Case folding uses SQL ``lower``, which
  equals Python ``casefold`` for the ASCII identifiers used by CVE IDs and rules.
* Warnings keep the legacy order: CVE/exception warnings by finding id, then the
  evidence, watchlist and validation rows from the header.
"""
from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import String, and_, case, func, literal, or_, select, union_all

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_TYPE_NAMES = {"evidence": "Evidence", "configuration": "Configuration", "vulnerability": "CVE",
               "watchlist": "Dependency Watchlist"}


def _aware(value):
    from .main import aware
    return aware(value)


def _due_days(configuration):
    overdue_days = max(1, int(configuration.get("overdue_days", "90")))
    rules = {}
    if configuration.get("compliance_mode") == "raw":
        try:
            parsed = json.loads(configuration.get("raw_due_rules", "[]"))
        except (TypeError, ValueError):
            parsed = []
        for rule in parsed if isinstance(parsed, list) else []:
            if isinstance(rule, dict):
                rules[str(rule.get("severity", "")).lower()] = max(1, int(rule.get("days", overdue_days)))
    return lambda severity: rules.get(str(severity or "").lower(), overdue_days)


def _codepoint_order(db, *columns):
    """Order text by code point, as Python sorts the legacy casefolded keys.

    SQLite's default BINARY collation already compares code points.  PostgreSQL
    columns use the database collation (often a linguistic ``en_US.UTF-8``
    order that ignores punctuation), so the ``"C"`` collation is explicit there;
    UTF-8 byte order equals code point order.
    """
    if db.get_bind().dialect.name == "postgresql":
        return [column.collate("C") for column in columns]
    return list(columns)


LIKE_ESCAPE = "!"


def _like(needle):
    """Literal substring pattern.  ``!`` (not backslash) is the escape character:
    a backslash escape literal is rendered differently by PostgreSQL depending
    on ``standard_conforming_strings``, while ``ESCAPE '!'`` is identical on
    SQLite and PostgreSQL."""
    escaped = needle.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return f"%{escaped}%"


def _joined_text(*parts):
    """SQL equivalent of ``" ".join(str(v)[:500] for v in parts if v)``, lower-cased."""
    text = None
    for part in parts:
        piece = func.substr(part, 1, 500, type_=String)
        present = func.coalesce(part, literal("", String)) != ""
        if text is None:
            text = case((present, piece), else_=literal("", String))
        else:
            text = case((~present, text), (text == "", piece), else_=text.concat(" ").concat(piece))
    return func.lower(text, type_=String)


def _exception_predicates(now):
    from .models import ExceptionRecord, Finding, PolicyExceptionRecord, PolicyFinding
    finding_exception = select(ExceptionRecord.id).where(
        ExceptionRecord.finding_id == Finding.id, ExceptionRecord.revoked_at.is_(None),
        ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).exists()
    policy_exception = select(PolicyExceptionRecord.id).where(
        PolicyExceptionRecord.policy_finding_id == PolicyFinding.id, PolicyExceptionRecord.revoked_at.is_(None),
        PolicyExceptionRecord.starts_at <= now, PolicyExceptionRecord.expires_at > now).exists()
    return finding_exception, policy_exception


def _with_latest_observation(query, service_id, needed):
    from .models import Finding, FindingObservation
    if not needed:
        return query
    latest = select(FindingObservation.finding_id, func.max(FindingObservation.id).label("latest_id")).join(
        Finding, Finding.id == FindingObservation.finding_id).where(
        Finding.service_id == service_id, Finding.active.is_(True)).group_by(FindingObservation.finding_id).subquery()
    return query.outerjoin(latest, latest.c.finding_id == Finding.id).outerjoin(
        FindingObservation, FindingObservation.id == latest.c.latest_id)


def severity_options(db, service_id, configuration, now):
    """Severities offered by the Raw view: raw-visible findings and listed policy findings."""
    from .main import _hardening_overdue_expression, _risk_finding_expressions
    from .models import Finding, PolicyFinding
    finding_exception, policy_exception = _exception_predicates(now)
    configurations = {service_id: configuration}
    eligible, _, needs_observations = _risk_finding_expressions(configurations, now, finding_exception)
    values = set(db.execute(_with_latest_observation(select(Finding.severity).distinct().where(
        Finding.service_id == service_id,
        or_(Finding.active.is_(False), ~finding_exception, eligible)), service_id, needs_observations)).scalars())
    policy_noncompliant = and_(_hardening_overdue_expression(configurations, now), ~policy_exception)
    values.update(db.execute(select(PolicyFinding.severity).distinct().where(
        PolicyFinding.service_id == service_id,
        or_(PolicyFinding.active.is_(False), policy_exception, ~policy_noncompliant))).scalars())
    return sorted({str(value) for value in values if value},
                  key=lambda value: (_SEVERITY_ORDER.get(value.casefold(), 4), value.casefold()))


def evidence_rows(view, payload, execution):
    """Missing-evidence non-compliance rows exactly as ``service_view`` builds them."""
    from .overview import normalize_overview
    if not view.get("evidence_noncompliant") or execution is None:
        return []
    missing = normalize_overview(payload.get("service_overview") or {},
        skipped_images=payload.get("skipped_images", []) or [], skipped_charts=payload.get("skipped_charts", []) or [],
        incomplete=not execution.complete, digest_resolver=None)["missing_evidence"]
    return [{"type": "Evidence", "item": row["type"] if row["item"] != "Assessment" else "Assessment",
             "evidence_image": row["item"] if row["item"] != "Assessment" else "",
             "source_file": row.get("source_file", ""), "reason": row["reason"], "due": None,
             "status": "Non-Compliant"} for row in missing]


def _evidence_text(item):
    return " ".join(str(value)[:500] for value in (item.get("item"), item.get("reason"), item.get("type"),
                    item.get("evidence_image"), item.get("target"), item.get("namespace")) if value).casefold()


def noncompliant_page(db, service_id, configuration, now, evidence, *, finding_type="all", query="",
                      resource="", severities=(), page=1, page_size=50):
    from .main import _hardening_overdue_expression, _risk_finding_expressions
    from .models import Finding, PolicyFinding
    finding_exception, policy_exception = _exception_predicates(now)
    configurations = {service_id: configuration}
    _, noncompliant, needs_observations = _risk_finding_expressions(configurations, now, finding_exception)
    needle, resource_needle = query.strip().casefold(), resource.strip().casefold()
    severity_filter = any(value.strip() for value in severities)
    wanted = _TYPE_NAMES[finding_type] if finding_type != "all" else None

    cve_text = _joined_text(Finding.cve, literal("Overdue fixable vulnerability"), literal("CVE"))
    cve_rows = _with_latest_observation(select(
        literal(0).label("kind"), Finding.id.label("id"), func.lower(Finding.cve).label("sort_item"),
        literal("cve").label("sort_type"), cve_text.label("text")).where(
        Finding.service_id == service_id, Finding.active.is_(True), noncompliant, ~finding_exception),
        service_id, needs_observations)
    policy_reason = func.coalesce(func.nullif(PolicyFinding.title, ""), literal("Overdue configuration finding"))
    policy_image = func.coalesce(func.nullif(PolicyFinding.target, ""), literal("No target reported"))
    policy_rows = select(
        literal(1).label("kind"), PolicyFinding.id.label("id"), func.lower(PolicyFinding.finding).label("sort_item"),
        literal("configuration").label("sort_type"),
        _joined_text(PolicyFinding.finding, policy_reason, literal("Configuration"), policy_image).label("text")).where(
        PolicyFinding.service_id == service_id, PolicyFinding.active.is_(True),
        _hardening_overdue_expression(configurations, now), ~policy_exception)
    parts = []
    if wanted in (None, "CVE"):
        parts.append(cve_rows)
    if wanted in (None, "Configuration"):
        parts.append(policy_rows)
    evidence = [item for item in evidence if (wanted in (None, "Evidence"))
                and not severity_filter and (not needle or needle in _evidence_text(item))
                and (not resource_needle or resource_needle in _evidence_text(item))]
    rows, sql_total = [], 0
    if parts and not severity_filter:
        combined = (union_all(*parts) if len(parts) > 1 else parts[0]).subquery()
        filters = []
        if needle:
            filters.append(combined.c.text.like(_like(needle), escape=LIKE_ESCAPE))
        if resource_needle:
            filters.append(combined.c.text.like(_like(resource_needle), escape=LIKE_ESCAPE))
        sql_total = db.scalar(select(func.count()).select_from(combined).where(*filters)) or 0
    total = sql_total + len(evidence)
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(int(page or 1), pages))
    start = (page - 1) * page_size
    evidence_keys = [((item.get("item") or "").casefold(), "evidence") for item in evidence]
    if sql_total:
        # Evidence rows interleave by sort key; read enough SQL rows to cover them.
        offset = min(max(0, start - len(evidence)), sql_total - 1)
        window = db.execute(select(combined.c.kind, combined.c.id, combined.c.sort_item, combined.c.sort_type)
            .where(*filters).order_by(*_codepoint_order(db, combined.c.sort_item, combined.c.sort_type),
                                      combined.c.kind, combined.c.id)
            .offset(offset).limit(page_size + len(evidence))).all()
        before = sum(key < ((window[0].sort_item or ""), window[0].sort_type) for key in evidence_keys) if window else 0
        merged = []
        ordered = sorted(range(len(evidence)), key=lambda index: evidence_keys[index])
        first = ((window[0].sort_item or ""), window[0].sort_type) if window else None
        leading = [index for index in ordered if first is not None and evidence_keys[index] < first]
        if offset == 0:
            # Rows before the window are only evidence rows, at known positions.
            merged.extend((at, ("evidence", index)) for at, index in enumerate(leading))
        # Otherwise they precede ``start`` (offset + len(leading) <= start) and are off-page.
        position = offset + before
        pending = [index for index in ordered if index not in leading]
        for row in window:
            key = ((row.sort_item or ""), row.sort_type)
            while pending and evidence_keys[pending[0]] < key:
                merged.append((position, ("evidence", pending.pop(0)))); position += 1
            merged.append((position, ("sql", row))); position += 1
        if offset + len(window) >= sql_total:
            for index in pending:
                merged.append((position, ("evidence", index))); position += 1
        selected = [entry for at, entry in merged if start <= at < start + page_size]
    else:
        order = sorted(range(len(evidence)), key=lambda index: evidence_keys[index])
        selected = [("evidence", index) for index in order[start:start + page_size]]
    finding_ids = [entry[1].id for entry in selected if entry[0] == "sql" and entry[1].kind == 0]
    policy_ids = [entry[1].id for entry in selected if entry[0] == "sql" and entry[1].kind == 1]
    from .findings_query import _rows
    from .sql_sets import member_of
    findings = {row.id: row for row in _rows(db, Finding, member_of(Finding.id, finding_ids, numeric=True))} if finding_ids else {}
    policies = {row.id: row for row in _rows(db, PolicyFinding, member_of(PolicyFinding.id, policy_ids, numeric=True))} if policy_ids else {}
    due_days = _due_days(configuration)
    hardening_days = max(1, int(configuration.get("hardening_overdue_days", "90")))
    items = []
    for kind, value in selected:
        if kind == "evidence":
            items.append(dict(evidence[value]))
        elif value.kind == 0:
            finding = findings[value.id]
            items.append({"type": "CVE", "item": finding.cve, "finding_id": finding.id,
                          "reason": "Overdue fixable vulnerability",
                          "due": _aware(finding.episode_started) + timedelta(days=due_days(finding.severity)),
                          "status": "Non-Compliant"})
        else:
            policy = policies[value.id]
            items.append({"type": "Configuration", "item": policy.finding, "policy_finding_id": policy.id,
                          "evidence_image": policy.target or "No target reported",
                          "reason": policy.title or "Overdue configuration finding",
                          "due": _aware(policy.episode_started) + timedelta(days=hardening_days),
                          "status": "Non-Compliant"})
    return {"items": items, "findings": list(findings.values()), "page": page, "total_items": total,
            "total_pages": pages}


def warning_page(db, service_id, configuration, now, service_key, other_items, *, finding_type="all",
                 page=1, page_size=50):
    """CVE/exception warnings (finding id order) followed by the header's other warnings."""
    from .main import _risk_finding_expressions
    from .models import ExceptionRecord, Finding
    from .service_counts import _due_window_expression
    finding_exception, _ = _exception_predicates(now)
    configurations = {service_id: configuration}
    eligible, _, needs_observations = _risk_finding_expressions(configurations, now, finding_exception)
    warning_days = max(1, int(configuration.get("warning_days", "14")))
    cutoff = now + timedelta(days=warning_days)
    active_exception = and_(ExceptionRecord.finding_id == Finding.id, ExceptionRecord.revoked_at.is_(None),
                            ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now)
    first_expiry = select(ExceptionRecord.expires_at).where(active_exception).order_by(
        ExceptionRecord.id).limit(1).scalar_subquery()
    due_window = _due_window_expression(Finding, configuration, now, warning_days)
    eligible_cves = _with_latest_observation(select(Finding.cve).where(
        Finding.service_id == service_id, Finding.active.is_(True), eligible), service_id, needs_observations)
    kinds = []
    if finding_type in ("all", "vulnerability"):
        kinds.append(and_(~finding_exception, due_window))
    if finding_type == "all":
        kinds.append(and_(finding_exception, first_expiry <= cutoff))
    others = [item for item in other_items
              if finding_type == "all" or item.get("type") == _TYPE_NAMES[finding_type]]
    sql_total = 0
    candidates = None
    if kinds:
        candidates = select(Finding.id, Finding.cve, Finding.severity, Finding.episode_started,
                            finding_exception.label("excepted"), first_expiry.label("expires_at")).where(
            Finding.service_id == service_id, Finding.active.is_(True), or_(*kinds),
            Finding.cve.in_(eligible_cves.correlate(None).scalar_subquery()))
        sql_total = db.scalar(select(func.count()).select_from(candidates.subquery())) or 0
    total = sql_total + len(others)
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(int(page or 1), pages))
    start = (page - 1) * page_size
    items = []
    if candidates is not None and start < sql_total:
        due_days = _due_days(configuration)
        for row in db.execute(candidates.order_by(Finding.id).offset(start).limit(page_size)):
            href = f"/services/{service_key}/findings/{row.id}"
            if row.excepted:
                items.append({"type": "Exception", "item": row.cve, "reason": "Exception expires soon",
                              "due": _aware(row.expires_at), "href": href})
            else:
                items.append({"type": "CVE", "item": row.cve, "reason": "Due date approaching",
                              "due": _aware(row.episode_started) + timedelta(days=due_days(row.severity)),
                              "href": href})
    remaining = page_size - len(items)
    if remaining > 0:
        other_start = max(0, start - sql_total)
        items.extend(others[other_start:other_start + remaining])
    return {"items": items, "page": page, "total_items": total, "total_pages": pages}
