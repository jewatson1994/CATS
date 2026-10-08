"""Precomputed current finding classification: a rebuildable read model.

Findings, Simplified Findings and the service header used to evaluate, on
every request and for every finding of the service, the risk-eligibility
rules (minimum severity, KEV and EPSS evidence and catalogs), exceptions,
each finding's current observation, its Simplified group and its search
surface. This module stores those per-finding results in
``finding_classifications`` and serves them while they are provably current.

Semantics hold by construction: every stored value is produced by the same
SQL expressions the readers used (``_risk_finding_expressions``, the current-
exception predicate, the Simplified current-observation rule and the search
surface), evaluated for one service.

What is stored, and what is not:
  * ``eligible`` - the canonical eligibility expression.
  * ``noncompliant_rule`` - the canonical non-compliance expression with its
    overdue term set to true. Every non-compliance branch is "rule AND
    overdue" with one shared overdue term, so the live value is exactly
    ``noncompliant_rule AND overdue(now)``.
  * Overdue itself is never stored: readers evaluate the canonical overdue
    expression on the stored ``severity`` and ``episode_started`` at the
    request's own instant, so time can never make a stored value wrong.
  * ``excepted`` - the current-exception predicate at build time. It is
    valid on ``[valid_from, valid_until)``: the latest and next exception
    start/expiry instants around the build time. Outside that window the
    state is stale and the findings with exceptions are reclassified.

A service's rows are current only if (see ``status``): its state row exists
with the current algorithm version, posture epoch (replaced by unnarrowable
bulk writes) and classification-configuration digest (including the KEV/EPSS
catalog token when the configuration uses the catalogs); it was built against
the service's current latest execution; the request instant lies in its
validity window; and no change-log row is pending for the service.

Writers record changes in ``finding_classification_changes`` in their own
transaction (a finding id, or NULL for the whole service), so a commit can
never be missed. A refresh reads the pending rows, reclassifies just those
findings (or the whole service), and deletes exactly the rows it read, in one
transaction under a per-service advisory lock; a concurrent write leaves its
own row behind and the service stays stale. An interrupted refresh rolls back
and changes nothing.

Readers use the rows only when current; otherwise they reclassify inline
when that is small, or schedule a background refresh and use the original
live queries. Security-sensitive actions never read this model.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
from itertools import chain
import json
import logging
import os
from threading import Lock
from time import perf_counter

from sqlalchemy import and_, case, delete, event, false, func, insert, literal, or_, select, text, true, update
from sqlalchemy.orm import Session, aliased

from .models import (Execution, ExceptionRecord, Finding, FindingClassification, FindingClassificationChange,
                     FindingClassificationState, FindingObservation, Service)
from .sql_sets import member_of

logger = logging.getLogger("cats.classification")
ALGORITHM_VERSION = 2
LOCK_KEY = 0x43464331  # "CFC1"
_PENDING = "cats_classification_marks"
_TOUCHED = "cats_classification_touched"
_BULK = "cats_classification_bulk"
FC = FindingClassification
# Configuration keys that classification depends on. Due-date and warning
# settings only affect the overdue term, which is evaluated at read time.
RELEVANT_KEYS = ("compliance_mode", "minimum_severity", "kev_enabled", "kev_noncompliant",
                 "epss_enabled", "epss_threshold", "epss_rules")
SEVERITY_RANKS = ("unknown", "negligible", "low", "medium", "high", "critical")


def _int_env(name, default):
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def enabled() -> bool:
    return os.getenv("CATS_FINDING_CLASSIFICATION", "true").strip().lower() not in {"0", "false", "no", "off"}


def target_limit() -> int:
    """Most pending finding ids reclassified individually; more means the whole service."""
    return max(1, _int_env("CATS_CLASSIFICATION_TARGET_LIMIT", 2000))


def inline_findings() -> int:
    """Largest service a page read reclassifies in full inline before serving.

    Larger services are refreshed in the background while readers use the
    original live queries, so a first read after a scan never waits longer
    than the live page would.
    """
    return _int_env("CATS_CLASSIFICATION_SYNC_FINDINGS", 5000)


def _aware(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _chunks(values, size=500):
    values = list(values)
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _utcnow():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- provenance

def uses_catalogs(configuration: dict) -> bool:
    return (configuration.get("compliance_mode", "risk_based") != "raw"
            and (configuration.get("kev_enabled") == "true" or configuration.get("epss_enabled") == "true"))


def config_digest(configuration: dict) -> str:
    relevant = {key: str(configuration.get(key)) for key in RELEVANT_KEYS}
    if uses_catalogs(configuration):
        from .policy_data import risk_catalog_token
        relevant["intelligence"] = risk_catalog_token()
    return sha256(json.dumps(relevant, sort_keys=True).encode("utf-8")).hexdigest()


def _epoch(db) -> str:
    from .service_posture import current_epoch
    return current_epoch(db)


def latest_execution_id(db, service_id):
    """The service's newest execution across versions (the Simplified "latest")."""
    return db.scalar(select(Execution.id).where(Execution.service_id == service_id)
                     .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))


# ---------------------------------------------------------------- building

def _classification_select(db, service_id, configuration, now, latest_id, finding_ids=None):
    """One row per finding, from the canonical expressions (see module docstring)."""
    from . import main as m
    from .risk_sql import evidence_score, evidence_truth, key_present
    from .simplified_queries import observation_metadata
    F, O = Finding, FindingObservation
    latest = latest_id if latest_id is not None else -1
    scope = [F.service_id == service_id]
    if finding_ids is not None:
        scope.append(member_of(F.id, sorted(finding_ids), numeric=True))
    postgresql = db.get_bind().dialect.name == "postgresql"
    in_latest = case((O.execution_id == latest, 1), else_=0)
    # One pass over the service's observations: the current-observation rank,
    # the risk-evidence (newest) id, and the search-history rank.
    ranked = (select(O.finding_id.label("finding_id"), O.id.label("id"), O.execution_id.label("execution_id"),
                     O.fixed_version.label("fixed_version"), O.simplified_key.label("simplified_key"),
                     O.simplified_package.label("simplified_package"),
                     O.simplified_remediation.label("simplified_remediation"),
                     O.simplified_fixed.label("simplified_fixed"),
                     O.simplified_package_sort.label("simplified_package_sort"),
                     O.simplified_fixed_sort.label("simplified_fixed_sort"),
                     O.search_folded.label("text_value"),
                     # Current observation: the newest from the latest execution,
                     # else the newest overall (the Simplified rule).
                     func.row_number().over(partition_by=O.finding_id,
                                            order_by=(in_latest.desc(), O.id.desc())).label("position"),
                     # Search surface: the latest twenty observations, newest first.
                     func.row_number().over(partition_by=O.finding_id, order_by=O.id.desc()).label("recent_position"),
                     # Risk evidence: the newest observation overall.
                     func.max(O.id).over(partition_by=O.finding_id).label("ever_id"))
              .join(F, F.id == O.finding_id).where(*scope)).cte("ranked")
    ranked = ranked.prefix_with("MATERIALIZED", dialect="postgresql")
    chosen = select(ranked).where(ranked.c.position == 1).subquery("chosen")
    recent_rows = select(ranked.c.finding_id, ranked.c.id, ranked.c.text_value).where(
        ranked.c.recent_position <= 20, ranked.c.text_value != "")
    if postgresql:
        from sqlalchemy.dialects.postgresql import aggregate_order_by
        recent_rows = recent_rows.subquery("recent_rows")
        joined = func.string_agg(recent_rows.c.text_value, aggregate_order_by(literal(" "), recent_rows.c.id.desc()))
    else:
        recent_rows = recent_rows.order_by(ranked.c.finding_id, ranked.c.id.desc()).subquery("recent_rows")
        joined = func.group_concat(recent_rows.c.text_value, " ")
    history = select(recent_rows.c.finding_id, joined.label("history")).group_by(recent_rows.c.finding_id).subquery("history")
    exception = select(ExceptionRecord.id).where(
        ExceptionRecord.finding_id == F.id, ExceptionRecord.revoked_at.is_(None),
        ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).exists()
    eligible, rule, _ = m._risk_finding_expressions({service_id: configuration}, now, exception, overdue=true())
    defaults = observation_metadata({})
    evidence = O.evidence
    if postgresql:
        # The stored KEV/EPSS evidence values read the newest observation's
        # evidence parsed once (casting jsonb to jsonb is a no-op), instead of
        # re-parsing the JSON text in every expression.
        from sqlalchemy import cast
        from sqlalchemy.dialects.postgresql import JSONB
        parsed_observation = aliased(FindingObservation)
        # OFFSET 0 keeps PostgreSQL from flattening the lateral into each
        # reference (which would parse again per expression).
        parsed = select(cast(parsed_observation.evidence, JSONB).label("evidence")).where(
            parsed_observation.id == chosen.c.ever_id).offset(0).lateral("parsed")
        evidence = parsed.c.evidence
    has_score = or_(key_present(evidence, "epss"), key_present(evidence, "epss_score"))
    rank = case(*[(func.lower(F.severity) == name, value) for value, name in enumerate(SEVERITY_RANKS)], else_=0)
    columns = {
        "finding_id": F.id, "service_id": F.service_id, "active": F.active, "cve": F.cve,
        "cve_normalized": F.cve_normalized, "severity": F.severity, "severity_folded": F.severity_folded,
        "severity_rank": rank, "episode_started": F.episode_started,
        # Stored exactly as the canonical expressions evaluate, NULL included:
        # SQL three-valued logic then gives every reader the live result
        # (for example ``NOT noncompliant`` excluding a NULL row).
        "eligible": eligible, "noncompliant_rule": rule,
        "excepted": exception,
        "kev_evidence": func.coalesce(evidence_truth(evidence), false()),
        "epss_evidence": case((func.coalesce(has_score, false()), evidence_score(evidence)), else_=None),
        "fixable": func.coalesce(and_(chosen.c.fixed_version.is_not(None), chosen.c.fixed_version != ""), false()),
        "current_observation_id": chosen.c.id, "latest_observation_id": chosen.c.ever_id,
        "current_execution_id": chosen.c.execution_id,
        "in_latest_execution": func.coalesce(chosen.c.execution_id == latest, false()),
        "group_id": func.coalesce(chosen.c.simplified_key, defaults["simplified_key"]),
        "package": func.coalesce(chosen.c.simplified_package, "Package update"),
        "remediation": func.coalesce(chosen.c.simplified_remediation, "Update the affected package to the fixed version."),
        "fixed": func.coalesce(chosen.c.simplified_fixed, "Latest fixed version"),
        "package_sort": func.coalesce(chosen.c.simplified_package_sort, "package update"),
        "fixed_sort": func.coalesce(chosen.c.simplified_fixed_sort, "latest fixed version"),
        "search_text": F.search_folded + case((func.coalesce(history.c.history, "") != "",
                                               literal(" ") + history.c.history), else_=""),
    }
    statement = (select(*[value.label(key) for key, value in columns.items()]).select_from(F)
                 .outerjoin(chosen, chosen.c.finding_id == F.id)
                 .outerjoin(O, O.id == chosen.c.ever_id)
                 .outerjoin(history, history.c.finding_id == F.id)
                 .where(*scope))
    if postgresql:
        statement = statement.outerjoin(parsed, true())
    return list(columns), statement


def _service_configuration(db, service_id):
    from . import main as m
    from .service_posture import resolve_configurations
    return resolve_configurations(db, [service_id], m.get_configuration(db))[service_id]


def _lock(db, service_id) -> bool:
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(db.execute(text("select pg_try_advisory_xact_lock(:key, :service)"),
                           {"key": LOCK_KEY, "service": service_id}).scalar())


def _window_columns(service_id, now):
    """``valid_from``/``valid_until`` as SQL: the latest exception start or
    expiry at or before ``now`` and the earliest after it."""
    owned = select(Finding.id).where(Finding.service_id == service_id)
    live = (ExceptionRecord.finding_id.in_(owned), ExceptionRecord.revoked_at.is_(None))

    def boundary(column, aggregate, past):
        return select(aggregate(column)).where(*live, column <= now if past else column > now).scalar_subquery()
    starts, expiries = ExceptionRecord.starts_at, ExceptionRecord.expires_at
    before = [boundary(starts, func.max, True), boundary(expiries, func.max, True)]
    after = [boundary(starts, func.min, False), boundary(expiries, func.min, False)]
    # Two-argument max/min skipping NULLs, on both dialects.
    def pick(first, second, larger):
        compare = first >= second if larger else first <= second
        return case((first.is_(None), second), (second.is_(None), first), (compare, first), else_=second)
    return pick(*before, True), pick(*after, False)


def _state_values(service_id, *, epoch, digest, latest, now, findings, build_ms, severities, raw_severities):
    valid_from, valid_until = _window_columns(service_id, now)
    lists = FindingClassificationState.severities.type
    return {"severities": literal(severities, type_=lists), "raw_severities": literal(raw_severities, type_=lists),"service_id": literal(service_id), "algorithm": literal(ALGORITHM_VERSION), "epoch": literal(epoch),
            "config_digest": literal(digest), "latest_execution_id": literal(latest, type_=FindingClassificationState.latest_execution_id.type),
            "valid_from": valid_from, "valid_until": valid_until,
            "built_at": literal(now, type_=FindingClassificationState.built_at.type), "findings": findings,
            "build_ms": literal(build_ms, type_=FindingClassificationState.build_ms.type)}


def refresh(bind, service_id, now=None, *, configuration=None, epoch=None, latest=..., full=False):
    """Reclassify one service (pending findings, or all of it) in one transaction.

    A reader passes the configuration, epoch and latest execution it checked
    against (and ``full`` when it saw that a full rebuild is needed), so the
    refresh issues only its own statements. Returns a summary dict, or
    ``None`` when another refresh holds the service's lock (that refresh, or
    the next read, completes the work).
    """
    started = perf_counter()
    with Session(bind=bind) as db:
        if not _lock(db, service_id):
            return None
        if configuration is None:
            if db.scalar(select(Service.id).where(Service.id == service_id)) is None:
                _forget(db.connection(), [service_id])
                db.commit()
                return {"service_id": service_id, "mode": "deleted"}
            configuration = _service_configuration(db, service_id)
        now = _aware(now) if now is not None else _utcnow()
        digest = config_digest(configuration)
        epoch = _epoch(db) if epoch is None else epoch
        latest = latest_execution_id(db, service_id) if latest is ... else latest
        changes = db.execute(select(FindingClassificationChange.id, FindingClassificationChange.finding_id)
                             .where(FindingClassificationChange.service_id == service_id)).all()
        ids = {finding_id for _, finding_id in changes if finding_id is not None}
        state = None
        if not full:
            state = db.execute(select(FindingClassificationState).where(
                FindingClassificationState.service_id == service_id)).scalars().first()
            full = (state is None or state.algorithm != ALGORITHM_VERSION or state.epoch != epoch
                    or state.config_digest != digest or state.latest_execution_id != latest
                    or any(finding_id is None for _, finding_id in changes))
        if not full and not _in_window(state, now):
            # Only exception state changes with time alone.
            ids.update(db.scalars(select(ExceptionRecord.finding_id).distinct().join(
                Finding, Finding.id == ExceptionRecord.finding_id).where(
                Finding.service_id == service_id, ExceptionRecord.revoked_at.is_(None))))
        # Per-finding work beats a rebuild only for a small share of the
        # service (measured: 1,000 of 1,050 findings took 1.1 s targeted
        # against 0.2 s in full).
        if len(ids) > target_limit() or (state is not None and len(ids) * 4 > max(int(state.findings or 0), 1)):
            full = True
        connection = db.connection()
        # A row is removed only by its own service, or by the service that now
        # owns that finding id (SQLite reuses the ids of deleted rows, so a
        # stale row of another service may hold an id this service now owns).
        owned = select(Finding.id).where(Finding.service_id == service_id)
        if full:
            connection.execute(delete(FC.__table__).where(or_(FC.service_id == service_id, FC.finding_id.in_(owned))))
            names, statement = _classification_select(db, service_id, configuration, now, latest)
            count = connection.execute(insert(FC.__table__).from_select(names, statement)).rowcount
            count = literal(count) if count is not None and count >= 0 else (
                select(func.count()).select_from(FC).where(FC.service_id == service_id).scalar_subquery())
        else:
            for chunk in _chunks(sorted(ids)):
                connection.execute(delete(FC.__table__).where(member_of(FC.finding_id, chunk, numeric=True), or_(
                    FC.service_id == service_id, FC.finding_id.in_(owned))))
                names, statement = _classification_select(db, service_id, configuration, now, latest, chunk)
                connection.execute(insert(FC.__table__).from_select(names, statement))
            count = select(func.count()).select_from(FC).where(FC.service_id == service_id).scalar_subquery()
        visible = or_(FC.active.is_(False), FC.excepted.is_(False), FC.eligible.is_(True))
        choices = connection.execute(select(FC.severity, func.max(case((visible, 1), else_=0))).where(
            FC.service_id == service_id).group_by(FC.severity)).all()
        values = _state_values(service_id, epoch=epoch, digest=digest, latest=latest, now=now, findings=count,
                               build_ms=round((perf_counter() - started) * 1000, 1),
                               severities=sorted(value for value, _ in choices if value is not None),
                               raw_severities=sorted(value for value, raw in choices if value is not None and raw))
        table = FindingClassificationState.__table__
        connection.execute(delete(table).where(table.c.service_id == service_id))
        connection.execute(insert(table).from_select(list(values), select(*[value.label(key) for key, value in values.items()])))
        # Exactly the rows read: a concurrent writer's row survives and keeps
        # the service stale until the next refresh.
        for chunk in _chunks([change_id for change_id, _ in changes]):
            connection.execute(delete(FindingClassificationChange.__table__).where(
                member_of(FindingClassificationChange.id, chunk, numeric=True)))
        db.commit()
    elapsed = round((perf_counter() - started) * 1000, 1)
    summary = {"service_id": service_id, "mode": "full" if full else "targeted", "changed": len(ids), "ms": elapsed,
               "severities": values["severities"].value, "raw_severities": values["raw_severities"].value,
               "digest": digest, "epoch": epoch, "latest": latest}
    logger.info("finding_classification_refreshed %s", json.dumps(
        {key: summary[key] for key in ("service_id", "mode", "changed", "ms")}))
    return summary


def _in_window(state, now) -> bool:
    valid_from, valid_until = _aware(state.valid_from), _aware(state.valid_until)
    return (valid_from is None or valid_from <= now) and (valid_until is None or now < valid_until)


# ---------------------------------------------------------------- reading

_CACHE = "cats_classification_verdicts"
_SEEN = "cats_classification_seen"
_CHOICES = "cats_classification_choices"


def _status_statement(service_ids, limit):
    """One statement: per requested service, its state row (if any), its
    pending-change summary, the posture epoch and its latest execution id."""
    from .models import PortalSetting
    from .service_posture import EPOCH_KEY
    S, C = FindingClassificationState, FindingClassificationChange
    sid = Service.id
    pending = select(C.finding_id).where(C.service_id == sid).limit(limit + 1).correlate(Service).subquery()
    latest = select(Execution.id).where(Execution.service_id == sid).order_by(
        Execution.scanned_at.desc(), Execution.id.desc()).limit(1).correlate(Service).scalar_subquery()
    return select(sid.label("service_id"), S.service_id.label("state_service_id"), S.algorithm, S.epoch, S.config_digest,
                  S.latest_execution_id, S.valid_from, S.valid_until, S.severities, S.raw_severities,
                  select(PortalSetting.value).where(PortalSetting.key == EPOCH_KEY).scalar_subquery().label("current_epoch"),
                  latest.label("current_latest"),
                  select(func.count()).select_from(pending).scalar_subquery().label("pending"),
                  select(func.count()).select_from(pending).where(pending.c.finding_id.is_(None)).scalar_subquery().label("whole"),
                  ).select_from(Service).outerjoin(S, S.service_id == sid).where(
                      member_of(Service.id, list(service_ids), numeric=True))


def _judge(row, configuration, now, limit, latest_id=...):
    if row is None or row.state_service_id is None:
        return "full", None
    epoch = row.current_epoch or "initial"
    latest = row.current_latest if latest_id is ... else latest_id
    if (row.algorithm != ALGORITHM_VERSION or row.epoch != epoch or row.config_digest != config_digest(configuration)
            or row.latest_execution_id != latest or row.whole or row.pending > limit):
        return "full", None
    stale = int(row.pending) + (0 if _in_window(row, _aware(now)) else 1)
    return ("targeted", stale) if stale else ("current", 0)


def _cache_key(service_id, configuration, now, latest_id):
    return service_id, _aware(now), config_digest(configuration), latest_id


def status(db, service_id, configuration, now, latest_id=...):
    """``(verdict, n)`` - ``current``, ``targeted`` or ``full`` - in one query.

    Verdicts are remembered for the session (one request) and the same
    instant, so the header and the page check once; a refresh records its
    result there. Also returns, through the session cache, the epoch and
    latest execution the check saw (``_seen``) for the refresh to reuse.
    """
    cache = db.info.setdefault(_CACHE, {})
    key = _cache_key(service_id, configuration, now, latest_id)
    if key in cache:
        return cache[key]
    limit = target_limit()
    row = db.execute(_status_statement([service_id], limit)).first()
    verdict = _judge(row, configuration, now, limit, latest_id)
    cache[key] = verdict
    if row is None:
        return verdict  # the service no longer exists: the caller's live query decides
    db.info.setdefault(_SEEN, {})[service_id] = (row.current_epoch or "initial", row.current_latest)
    if verdict[0] == "current":
        db.info.setdefault(_CHOICES, {})[service_id] = (row.severities, row.raw_severities)
    if latest_id is ...:
        cache[_cache_key(service_id, configuration, now, row.current_latest)] = verdict
    return verdict


def is_current(db, service_id, configuration, now, latest_id=...) -> bool:
    """Read-only variant of ``ensure_current``: never writes; schedules a
    background refresh when the rows are not current."""
    if not enabled():
        return False
    state, _ = status(db, service_id, configuration, now, latest_id)
    if state == "current":
        return True
    schedule(db.get_bind(), [service_id])
    return False


def ensure_current(db, service_id, configuration, now, latest_id=...) -> bool:
    """True when ``service_id``'s rows may be read at ``now``.

    Small staleness is repaired inline; a large rebuild is scheduled in the
    background and the caller uses its live query meanwhile. A write that
    commits during the inline refresh leaves its change-log row, so the next
    read refreshes again; this read is served as of the refresh.
    """
    if not enabled():
        return False
    from .service_posture import background_enabled
    state, _ = status(db, service_id, configuration, now, latest_id)
    if state == "current":
        return True
    bind = db.get_bind()
    background = background_enabled(bind)
    if state == "full" and background:
        size = db.scalar(select(func.count()).select_from(Finding).where(Finding.service_id == service_id)) or 0
        if size > inline_findings():
            schedule(bind, [service_id])
            return False
    if service_id not in db.info.get(_SEEN, {}):
        return False  # no such service (deleted meanwhile): serve the live query
    epoch, seen_latest = db.info[_SEEN][service_id]
    try:
        summary = refresh(bind, service_id, now, configuration=configuration, epoch=epoch,
                          latest=seen_latest if latest_id is ... else latest_id, full=state == "full")
    except Exception:
        logger.exception("Finding classification refresh failed; serving the live queries")
        return False
    if summary is None or summary.get("digest") != config_digest(configuration):
        return False
    cache = db.info.setdefault(_CACHE, {})
    for key in {_cache_key(service_id, configuration, now, latest_id), _cache_key(service_id, configuration, now, summary["latest"])}:
        cache[key] = ("current", 0)
    db.info.setdefault(_CHOICES, {})[service_id] = (summary["severities"], summary["raw_severities"])
    return True


def severity_choices(db, service_id):
    """``(all, raw-visible)`` stored severities for a service this session
    found current, or ``None`` (the caller then queries them)."""
    return db.info.get(_CHOICES, {}).get(service_id)


def current_services(db, service_ids, configurations, now) -> set[int]:
    """Services whose rows are current, checked without refreshing anything."""
    if not enabled() or not service_ids:
        return set()
    cache = db.info.setdefault(_CACHE, {})
    result = {sid for sid in service_ids if any(key[0] == sid and key[1] == _aware(now) and verdict[0] == "current"
                                                and key[2] == config_digest(configurations[sid])
                                                for key, verdict in cache.items())}
    remaining = sorted(set(service_ids) - result)
    limit = target_limit()
    for chunk in _chunks(remaining):
        for row in db.execute(_status_statement(chunk, limit)):
            if _judge(row, configurations[row.service_id], now, limit)[0] == "current":
                result.add(row.service_id)
    return result


def predicates(configurations, now):
    """``(eligible, excepted, noncompliant)`` on ``FindingClassification`` at ``now``.

    Each has the live expression's value, NULL included. ``noncompliant`` is
    the stored rule AND the canonical overdue expression evaluated now (AND
    distributes over the live OR of per-rule terms in three-valued logic); it
    does not include the exception test, exactly like the live expression.
    """
    from .main import _raw_overdue_expression
    return FC.eligible, FC.excepted.is_(True), and_(FC.noncompliant_rule, _raw_overdue_expression(FC, configurations, now))


# ---------------------------------------------------------------- background

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cats-classification")
_queued: set[int] = set()
_queue_lock = Lock()


def schedule(bind, service_ids):
    """Background refresh (single worker, coalesced); never blocks a request."""
    from .database import background_bind
    from .service_posture import background_enabled
    if not enabled() or not background_enabled(bind):
        return None
    bind = background_bind(bind)
    with _queue_lock:
        fresh = set(service_ids) - _queued
        if not fresh:
            return None
        _queued.update(fresh)

    def run():
        with _queue_lock:
            batch = sorted(_queued)
            _queued.clear()
        for service_id in batch:
            try:
                refresh(bind, service_id)
            except Exception:
                logger.exception("Finding classification refresh failed; readers use the live queries")
    return _executor.submit(run)


def warm(bind, chunk_size=100, max_chunks=10000) -> int:
    """Bounded, resumable startup preparation (each service commits alone).

    Cheap scalar checks select candidates (missing state, other algorithm or
    epoch, pending changes, or a newer execution); configuration digests and
    time windows are verified on read. Also removes rows whose service no
    longer exists.
    """
    if not enabled():
        return 0
    with Session(bind=bind) as db:
        for table in (FC.__table__, FindingClassificationState.__table__, FindingClassificationChange.__table__):
            db.execute(delete(table).where(table.c.service_id.not_in(select(Service.id))))
        db.commit()
    total, last = 0, 0
    for _ in range(max_chunks):
        with Session(bind=bind) as db:
            epoch = _epoch(db)
            ids = list(db.scalars(select(Service.id).where(Service.id > last).order_by(Service.id).limit(chunk_size)))
            if not ids:
                break
            last = ids[-1]
            states = {row.service_id: row for row in db.execute(select(FindingClassificationState).where(
                member_of(FindingClassificationState.service_id, ids, numeric=True))).scalars()}
            pending = set(db.scalars(select(FindingClassificationChange.service_id).distinct().where(
                member_of(FindingClassificationChange.service_id, ids, numeric=True))))
            latest = {sid: latest_execution_id(db, sid) for sid in ids}
            stale = [sid for sid in ids if sid in pending or sid not in states or states[sid].algorithm != ALGORITHM_VERSION
                     or states[sid].epoch != epoch or states[sid].latest_execution_id != latest[sid]]
        for sid in stale:
            if refresh(bind, sid) is not None:
                total += 1
    return total


# ---------------------------------------------------------------- invalidation

def _forget(connection, service_ids):
    for chunk in _chunks(sorted(set(service_ids))):
        for table in (FC.__table__, FindingClassificationState.__table__, FindingClassificationChange.__table__):
            connection.execute(delete(table).where(member_of(table.c.service_id, chunk, numeric=True)))


def _record(session, marks):
    """Write change-log rows for ``{service_id: set(finding ids) | None}``.

    With classification switched off nothing consumes the log, so the touched
    services' state rows are removed instead: switching it back on rebuilds
    exactly those services, and the log cannot grow unbounded.
    """
    if not enabled():
        touched = sorted(service_id for service_id in marks if service_id is not None)
        if touched:
            connection = session.connection()
            for chunk in _chunks(touched):
                connection.execute(delete(FindingClassificationState.__table__).where(
                    member_of(FindingClassificationState.service_id, chunk, numeric=True)))
        return
    recorded = session.info.setdefault(_PENDING, {})
    rows = []
    for service_id, ids in marks.items():
        if service_id is None:
            continue
        previous = recorded.get(service_id, set())
        if previous is None:
            continue  # the whole service is already marked in this transaction
        if ids is None or len(previous) + len(ids) > target_limit():
            rows.append({"service_id": service_id, "finding_id": None})
            recorded[service_id] = None
        else:
            fresh = set(ids) - previous
            rows.extend({"service_id": service_id, "finding_id": finding_id} for finding_id in sorted(fresh))
            recorded[service_id] = previous | fresh
        session.info.setdefault(_TOUCHED, set()).add(service_id)
    if rows:
        connection = session.connection()
        for chunk in _chunks(rows, 1000):
            connection.execute(insert(FindingClassificationChange.__table__), chunk)


@event.listens_for(Session, "after_flush")
def _mark_changes(session, _context):
    marks: dict[int, set | None] = {}
    unresolved: set[int] = set()
    deleted_services: set[int] = set()

    def mark(service_id, finding_id):
        if service_id is None:
            if finding_id is not None:
                unresolved.add(finding_id)
            return
        current = marks.setdefault(service_id, set())
        if current is not None and finding_id is not None:
            current.add(finding_id)

    dirty = session.dirty  # recomputed on every access: take it once
    for instance in chain(session.new, dirty, session.deleted):
        if instance in dirty and not session.is_modified(instance, include_collections=False):
            continue
        if isinstance(instance, Finding):
            mark(instance.service_id, instance.id)
        elif isinstance(instance, (FindingObservation, ExceptionRecord)):
            finding = instance.__dict__.get("finding")
            finding_id = instance.finding_id if instance.finding_id is not None else getattr(finding, "id", None)
            mark(getattr(finding, "service_id", None), finding_id)
        elif isinstance(instance, Execution):
            if instance.service_id is not None:
                marks[instance.service_id] = None
        elif isinstance(instance, Service) and instance in session.deleted and instance.id is not None:
            deleted_services.add(instance.id)
    if not (marks or unresolved or deleted_services):
        return
    connection = session.connection()
    for chunk in _chunks(unresolved):
        for finding_id, service_id in connection.execute(select(Finding.id, Finding.service_id).where(
                member_of(Finding.id, chunk, numeric=True))):
            mark(service_id, finding_id)
    if deleted_services:
        _forget(connection, deleted_services)
        for service_id in deleted_services:
            marks.pop(service_id, None)
    _record(session, marks)


_BULK_OWNERS = {Finding.__table__.name: Finding, FindingObservation.__table__.name: None,
                ExceptionRecord.__table__.name: None, Execution.__table__.name: Execution,
                Service.__table__.name: Service}


@event.listens_for(Session, "do_orm_execute")
def _mark_bulk(state):
    """Bulk statements that name their services mark them whole; others replace
    the posture epoch (``service_posture``), which every state also checks."""
    if not (state.is_delete or state.is_update or state.is_insert):
        return
    table = getattr(state.statement, "table", None)
    name = getattr(table, "name", None)
    if name not in _BULK_OWNERS:
        return
    from .service_posture import _bulk_keys, _narrowing_values
    keys = _bulk_keys(name)
    narrowed = None if state.is_insert else _narrowing_values(state.statement, keys)
    if narrowed is None:
        return  # unnarrowed: the posture epoch is replaced at commit
    column, values = narrowed
    owner = keys[column]
    connection = state.session.connection()
    if name == Service.__table__.name:
        if state.is_delete:
            _forget(connection, values)
        return  # service fields do not affect classification
    pending = state.session.info.setdefault(_BULK, {})
    if owner is None:
        pending.setdefault(None, set()).update(values)
    elif owner.__table__.name == name:
        # Resolve now, before a delete removes the rows naming the service.
        for chunk in _chunks(values):
            pending.setdefault(None, set()).update(connection.execute(select(owner.service_id).where(
                member_of(owner.id, chunk, numeric=True))).scalars())
    else:
        pending.setdefault(owner, set()).update(values)


@event.listens_for(Session, "before_commit")
def _publish_bulk(session):
    pending = session.info.pop(_BULK, None)
    if not pending:
        return
    service_ids = set(pending.pop(None, set()))
    connection = session.connection()
    for owner, values in pending.items():
        for chunk in _chunks(values):
            service_ids.update(connection.execute(select(owner.service_id).where(
                member_of(owner.id, chunk, numeric=True))).scalars())
    _record(session, {service_id: None for service_id in service_ids})


@event.listens_for(Session, "after_commit")
def _schedule_touched(session):
    touched = session.info.pop(_TOUCHED, None)
    session.info.pop(_PENDING, None)
    if touched:
        try:
            schedule(session.get_bind(), sorted(touched))
        except Exception:
            logger.exception("Finding classification refresh could not be scheduled; readers refresh on demand")


@event.listens_for(Session, "after_rollback")
def _discard(session):
    for key in (_PENDING, _TOUCHED, _BULK):
        session.info.pop(key, None)
