"""Service Posture read model: bounded portfolio reads with exact semantics.

Services and Cybersecurity used to recompute every accessible service's
active findings (with KEV/EPSS, exception, overdue and evidence rules) on
every request, so their cost grew with portfolio x finding population. This
module stores, per service, the *outputs of those same functions* and serves
them while they are provably current. Parity holds by construction: a row is
only ever produced by the original computation, restricted to that service.

Services and Cybersecurity rows are built independently (each page pays
only for its own computation). A stored row is current only if all hold:
  * its built generation equals ``data_generation`` - every posture-relevant write
    (findings, observations, exceptions, policy findings, executions and
    their summaries, POA&Ms, archive events, validation runs, watchlist
    matches, service fields and group membership) bumps the service's data
    generation in the same flush, so the bump commits atomically with it;
  * the KEV/EPSS catalog content token is unchanged;
  * the service's resolved configuration digest (per page) is unchanged;
  * the portfolio posture epoch is unchanged (replaced by bulk deletes);
  * ``now < *_valid_until`` - the next time boundary at which any count can
    change by time alone (overdue/warning thresholds, exception start or
    expiry, POA&M due dates, oldest-finding age in days);
  * the algorithm version matches.

Readers recompute stale or missing rows for just those services, in one
set-based batch, before serving. Beyond a bound (a portfolio-wide event such
as a catalog refresh), existing rows are served as stale and refreshed in the
background; missing rows are always computed. Security-sensitive actions
never read this model.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from itertools import chain
import json
import logging
import os
from threading import Lock
from time import perf_counter
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import bindparam, case, event, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .sql_sets import member_of
from .models import (DependencyWatchlistMatch, DeploymentValidationRun, ExceptionRecord, Execution,
                     ExecutionSummary, Finding, FindingObservation, PoamEntry, PolicyExceptionRecord,
                     PolicyFinding, PortalSetting, Service, ServiceArchiveEvent, ServiceGroup, ServicePosture)

logger = logging.getLogger("cats.posture")
ALGORITHM_VERSION = 1
EPOCH_KEY = "service_posture_epoch"
# Settings that never affect posture (they change for unrelated reasons).
_CONFIG_EXCLUDED = frozenset({"authorization_revision", EPOCH_KEY})
_FLAG = "cats_posture_bulk_change"
_SERVICE_TABLES = (Finding, PolicyFinding, Execution, PoamEntry, ServiceArchiveEvent, DeploymentValidationRun,
                   DependencyWatchlistMatch, ServiceGroup)
_BULK_TABLES = frozenset(model.__table__.name for model in (
    Finding, FindingObservation, ExceptionRecord, PolicyFinding, PolicyExceptionRecord, Execution, ExecutionSummary,
    PoamEntry, ServiceArchiveEvent, DeploymentValidationRun, DependencyWatchlistMatch, ServiceGroup, Service))
_SERVICES_ROW_COUNTS = ("active", "noncompliant", "policy_noncompliant", "excepted", "policy_excepted", "overdue")


def sync_limit() -> int:
    try:
        return max(1, int(os.getenv("CATS_POSTURE_SYNC_LIMIT", "250")))
    except ValueError:
        return 250


def shadow_enabled() -> bool:
    return os.getenv("CATS_POSTURE_SHADOW", "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------- invalidation

def _chunks(values, size=500):
    values = list(values)
    for start in range(0, len(values), size):
        yield values[start:start + size]


@event.listens_for(Session, "after_flush")
def _mark_changed_services(session, _context):
    service_ids: set[int] = set()
    new_services: set[int] = set()
    finding_ids: set[int] = set()
    policy_ids: set[int] = set()
    execution_ids: set[int] = set()
    for instance in chain(session.new, session.dirty, session.deleted):
        if isinstance(instance, ServicePosture):
            continue
        if instance in session.dirty and not session.is_modified(instance, include_collections=True):
            continue  # touched without a net change (e.g. idempotent backfills)
        if isinstance(instance, _SERVICE_TABLES):
            if getattr(instance, "service_id", None) is not None:
                service_ids.add(instance.service_id)
        elif isinstance(instance, Service):
            if instance.id is not None:
                (new_services if instance in session.new else service_ids).add(instance.id)
        elif isinstance(instance, FindingObservation):
            finding = instance.__dict__.get("finding")
            if finding is not None and finding.service_id is not None:
                service_ids.add(finding.service_id)
            elif instance.finding_id is not None:
                finding_ids.add(instance.finding_id)
        elif isinstance(instance, ExceptionRecord):
            finding = instance.__dict__.get("finding")
            if finding is not None and finding.service_id is not None:
                service_ids.add(finding.service_id)
            elif instance.finding_id is not None:
                finding_ids.add(instance.finding_id)
        elif isinstance(instance, PolicyExceptionRecord):
            if instance.policy_finding_id is not None:
                policy_ids.add(instance.policy_finding_id)
        elif isinstance(instance, ExecutionSummary):
            if instance.execution_id is not None:
                execution_ids.add(instance.execution_id)
    if not (service_ids or new_services or finding_ids or policy_ids or execution_ids):
        return
    connection = session.connection()
    for chunk in _chunks(finding_ids):
        service_ids.update(connection.execute(select(Finding.service_id).where(member_of(Finding.id, chunk, numeric=True))).scalars())
    for chunk in _chunks(policy_ids):
        service_ids.update(connection.execute(select(PolicyFinding.service_id).where(member_of(PolicyFinding.id, chunk, numeric=True))).scalars())
    for chunk in _chunks(execution_ids):
        service_ids.update(connection.execute(select(Execution.service_id).where(member_of(Execution.id, chunk, numeric=True))).scalars())
    service_ids.discard(None)
    for chunk in _chunks(service_ids - new_services):
        connection.execute(update(ServicePosture.__table__).where(member_of(ServicePosture.service_id, chunk, numeric=True))
                           .values(data_generation=ServicePosture.data_generation + 1))
    for service_id in new_services:
        # A row exists from creation onward, so no later write can miss it.
        connection.execute(insert(ServicePosture.__table__).values(service_id=service_id, data_generation=1))


@event.listens_for(Session, "do_orm_execute")
def _detect_bulk_changes(state):
    if not (state.is_delete or state.is_update or state.is_insert):
        return
    table = getattr(state.statement, "table", None)
    if getattr(table, "name", None) in _BULK_TABLES:
        state.session.info[_FLAG] = True


@event.listens_for(Session, "before_commit")
def _publish_epoch(session):
    # Bulk statements bypass the unit of work and name no service: replace
    # the epoch so every row is treated as stale (rare: service deletion).
    if session.info.pop(_FLAG, False):
        with session.no_autoflush:
            row = session.scalar(select(PortalSetting).where(PortalSetting.key == EPOCH_KEY))
        if row is None:
            session.add(PortalSetting(key=EPOCH_KEY, value=uuid4().hex))
        else:
            row.value = uuid4().hex


@event.listens_for(Session, "after_rollback")
def _discard(session):
    session.info.pop(_FLAG, None)


def ensure_rows(connection):
    """Startup migration: every service has a posture row to invalidate."""
    existing = select(ServicePosture.service_id)
    missing = [row[0] for row in connection.execute(select(Service.id).where(Service.id.not_in(existing)))]
    for chunk in _chunks(missing, 100):
        connection.execute(insert(ServicePosture.__table__), [{"service_id": sid, "data_generation": 1} for sid in chunk])


def current_epoch(db) -> str:
    return db.scalar(select(PortalSetting.value).where(PortalSetting.key == EPOCH_KEY)) or "initial"


# ---------------------------------------------------------------- provenance

def config_digest(configuration: dict) -> str:
    relevant = {str(key): str(value) for key, value in configuration.items() if key not in _CONFIG_EXCLUDED}
    return sha256(json.dumps(relevant, sort_keys=True).encode("utf-8")).hexdigest()


def _intelligence_token() -> str:
    from .policy_data import risk_catalog_token
    return risk_catalog_token()[:80]


def _aware(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _days(value, default):
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _rules(value):
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return []
    return [rule for rule in parsed or [] if isinstance(rule, dict)] if isinstance(parsed, list) else []


def valid_until(db, ids, configurations, now) -> dict[int, datetime | None]:
    """Earliest future instant at which any posture count changes by time alone.

    Conservative (may be earlier than necessary, never later): every
    configured overdue, warning and hardening offset is considered for every
    service, as are exception start/expiry (and expiry-warning) instants,
    POA&M due dates and the next whole-day boundary of the oldest finding.
    """
    finding_offsets, policy_offsets, warnings = set(), set(), set()
    for cfg in configurations:
        overdue = _days(cfg.get("overdue_days"), 90)
        warning = _days(cfg.get("warning_days"), 14)
        warnings.add(warning)
        offsets = {overdue} | {_days(rule.get("days"), overdue) for rule in _rules(cfg.get("raw_due_rules"))}
        for days in offsets:
            finding_offsets.add(days)
            if days - warning > 0:
                finding_offsets.add(days - warning)
        policy_offsets.add(_days(cfg.get("hardening_overdue_days"), 90))
    boundaries: dict[int, list[datetime]] = {sid: [] for sid in ids}

    def gather(model, offsets):
        columns = [func.min(case((model.episode_started > now - timedelta(days=days), model.episode_started))).label(f"o{index}")
                   for index, days in enumerate(sorted(offsets))]
        query = select(model.service_id, func.min(model.episode_started).label("oldest"), *columns).where(
            member_of(model.service_id, ids, numeric=True), model.active.is_(True)).group_by(model.service_id)
        for row in db.execute(query):
            for index, days in enumerate(sorted(offsets)):
                value = _aware(getattr(row, f"o{index}"))
                if value is not None:
                    boundaries[row.service_id].append(value + timedelta(days=days))
            oldest = _aware(row.oldest)
            if oldest is not None:
                boundaries[row.service_id].append(oldest + timedelta(days=(now - oldest).days + 1))

    def exceptions(record, parent, key):
        columns = [func.min(case((record.starts_at > now, record.starts_at))).label("start"),
                   func.min(case((record.expires_at > now, record.expires_at))).label("expiry")]
        columns += [func.min(case((record.expires_at > now + timedelta(days=days), record.expires_at))).label(f"w{index}")
                    for index, days in enumerate(sorted(warnings))]
        query = select(parent.service_id, *columns).join(parent, parent.id == key).where(
            member_of(parent.service_id, ids, numeric=True), record.revoked_at.is_(None)).group_by(parent.service_id)
        for row in db.execute(query):
            for value in (row.start, row.expiry):
                if value is not None:
                    boundaries[row.service_id].append(_aware(value))
            for index, days in enumerate(sorted(warnings)):
                value = _aware(getattr(row, f"w{index}"))
                if value is not None:
                    boundaries[row.service_id].append(value - timedelta(days=days))

    if ids:
        gather(Finding, finding_offsets or {90})
        gather(PolicyFinding, policy_offsets or {90})
        exceptions(ExceptionRecord, Finding, ExceptionRecord.finding_id)
        exceptions(PolicyExceptionRecord, PolicyFinding, PolicyExceptionRecord.policy_finding_id)
        for row in db.execute(select(PoamEntry.service_id, func.min(PoamEntry.due_date)).where(
                member_of(PoamEntry.service_id, ids, numeric=True), PoamEntry.status == "active", PoamEntry.due_date > now).group_by(PoamEntry.service_id)):
            if row[1] is not None:
                boundaries[row[0]].append(_aware(row[1]))
    return {sid: min((value for value in values if value > now), default=None) for sid, values in boundaries.items()}


# ---------------------------------------------------------------- building

def resolve_configurations(db, service_ids, configuration):
    """Per-service effective configuration (same rules as the page readers)."""
    from . import main as m
    groups: dict[int, list[int]] = {}
    group_ids: set[int] = set()
    for chunk in _chunks(service_ids):
        for row in db.execute(select(ServiceGroup.service_id, ServiceGroup.group_id).where(member_of(ServiceGroup.service_id, chunk, numeric=True))):
            groups.setdefault(row.service_id, []).append(row.group_id)
            group_ids.add(row.group_id)
    settings: dict[int, list] = {group_id: [] for group_id in group_ids}
    for chunk in _chunks(group_ids):
        for setting in db.scalars(select(PortalSetting).where(member_of(PortalSetting.group_id, chunk, numeric=True))):
            settings.setdefault(setting.group_id, []).append(setting)
    resolved = {}
    for service_id in service_ids:
        values = dict(configuration)
        for group_id in sorted(groups.get(service_id, [])):
            for setting in settings.get(group_id, []):
                key = setting.key.split(":", 2)[-1]
                if key not in m.GLOBAL_CONFIGURATION_KEYS:
                    values[key] = setting.value
        resolved[service_id] = values
    return resolved


def _services_row(row):
    stored = {key: len(row[key]) for key in _SERVICES_ROW_COUNTS}
    stored.update({key: row[key] for key in ("compliant", "version", "evidence_state", "oldest_age", "archive", "poam")})
    return stored


def _cyber_row(row):
    stored = dict(row)
    stored.pop("service", None)
    if isinstance(stored.get("last_scan"), datetime):
        stored["last_scan"] = _aware(stored["last_scan"]).isoformat()
    return stored


def _restore_cyber(row):
    restored = dict(row)
    if isinstance(restored.get("last_scan"), str):
        restored["last_scan"] = datetime.fromisoformat(restored["last_scan"])
    return restored


KINDS = ("services", "cyber")


def _column(kind, name):
    return getattr(ServicePosture, f"{kind}_{name}")


def rebuild(bind, kind, service_ids, now=None) -> int:
    """Recompute one page's posture rows with the original function.

    ``now`` is the reader's clock, so a row recomputed for a request is exact
    for the instant it is served (background refreshes use the current time).
    """
    from . import main as m
    from .dashboard_portfolio import compute_rows
    if kind not in KINDS:
        raise ValueError("Unknown posture kind")
    ids = sorted(set(service_ids))
    if not ids:
        return 0
    started = perf_counter()
    with Session(bind=bind) as db:
        def generations():
            return dict(db.execute(select(ServicePosture.service_id, ServicePosture.data_generation)
                                   .where(member_of(ServicePosture.service_id, ids, numeric=True))).all())
        # Generations are read before any source data, so a concurrent write
        # (which bumps the generation) always leaves the row stale.
        built_from = generations()
        missing = [sid for sid in ids if sid not in built_from]
        if missing:
            try:
                with Session(bind=bind) as writer, writer.begin():
                    for chunk in _chunks(missing, 100):
                        writer.execute(insert(ServicePosture.__table__), [{"service_id": sid, "data_generation": 1} for sid in chunk])
            except IntegrityError:
                pass
            built_from = generations()
        epoch, token = current_epoch(db), _intelligence_token()
        now = _aware(now) if now is not None else _aware(m.utcnow())
        columns = (Service.id, Service.name, Service.service_key, Service.owner, Service.poc,
                   Service.manual_version, Service.lifecycle_status)
        services = [SimpleNamespace(**row._mapping) for row in db.execute(select(*columns).where(member_of(Service.id, ids, numeric=True)))]
        present = [service.id for service in services]
        if kind == "services":
            base = m.get_configuration(db)
            configurations = resolve_configurations(db, present, base)
            rows, _poam = m.service_overview_rows_aggregated(db, None, now, base, services, configurations)
            stored = {row["service"].id: _services_row(row) for row in rows}
        else:
            base = m.get_global_configuration(db)
            configurations = resolve_configurations(db, present, base)
            stored = {sid: _cyber_row(row) for sid, row in compute_rows(db, services, configurations, base, now).items()}
        boundaries = valid_until(db, present, configurations.values(), now)
        fields = ("built_generation", "algorithm", "epoch", "token", "config_digest", "row", "valid_until", "calculated_at")
        statement = update(ServicePosture.__table__).where(ServicePosture.__table__.c.service_id == bindparam("target")).values(
            {f"{kind}_{name}": bindparam(f"v_{name}") for name in fields})
        # Batched executemany: a handful of statements per rebuild, each well
        # within bind/parameter-set budgets.
        for chunk in _chunks(present, 100):
            db.connection().execute(statement, [{
                "target": sid, "v_built_generation": built_from.get(sid, 1), "v_algorithm": ALGORITHM_VERSION,
                "v_epoch": epoch, "v_token": token, "v_config_digest": config_digest(configurations[sid]),
                "v_row": stored[sid], "v_valid_until": boundaries.get(sid), "v_calculated_at": now} for sid in chunk])
        db.commit()
    logger.info("service_posture_rebuilt %s", json.dumps({"kind": kind, "services": len(present),
                                                          "ms": round((perf_counter() - started) * 1000, 1)}))
    return len(present)


_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cats-posture")
_queued: set[tuple[str, int]] = set()
_queue_lock = Lock()


def schedule(bind, service_ids, kinds=KINDS):
    """Background refresh (single worker, coalesced); never blocks a request."""
    from .database import background_bind
    bind = background_bind(bind)
    with _queue_lock:
        fresh = {(kind, sid) for kind in kinds for sid in service_ids} - _queued
        if not fresh:
            return None
        _queued.update(fresh)

    def run():
        with _queue_lock:
            batch = sorted(_queued)
            _queued.clear()
        for kind in KINDS:
            for chunk in _chunks([sid for item_kind, sid in batch if item_kind == kind], 250):
                try:
                    rebuild(bind, kind, chunk)
                except Exception:
                    logger.exception("Service posture refresh failed; readers recompute on demand")
    return _executor.submit(run)


# ---------------------------------------------------------------- reading

def _load(db, kind, service_ids, configurations, now):
    token, epoch = _intelligence_token(), current_epoch(db)
    row_column = _column(kind, "row")
    rows = {}
    for chunk in _chunks(service_ids):
        for row in db.execute(select(
                ServicePosture.service_id, ServicePosture.data_generation,
                _column(kind, "built_generation").label("built"), _column(kind, "algorithm").label("algorithm"),
                _column(kind, "epoch").label("epoch"), _column(kind, "token").label("token"),
                _column(kind, "config_digest").label("digest"), _column(kind, "valid_until").label("until"),
                row_column.label("row")).where(member_of(ServicePosture.service_id, chunk, numeric=True))):
            rows[row.service_id] = row
    stale, missing = [], []
    for sid in service_ids:
        row = rows.get(sid)
        if row is None or row.row is None:
            missing.append(sid)
        elif not (row.algorithm == ALGORITHM_VERSION and row.built == row.data_generation and row.epoch == epoch
                  and row.token == token and row.digest == config_digest(configurations[sid])
                  and (row.until is None or _aware(row.until) > now)):
            stale.append(sid)
    refreshing = len(missing) + len(stale) > sync_limit()
    synchronous = missing if refreshing else missing + stale
    if refreshing:
        # Portfolio-wide invalidation (e.g. catalog refresh): keep the GET
        # bounded, serve the previous rows and refresh in the background.
        schedule(db.get_bind(), stale, kinds=(kind,))
    for chunk in _chunks(synchronous, 250):
        rebuild(db.get_bind(), kind, chunk, now=now)
    for chunk in _chunks(synchronous):
        for row in db.execute(select(ServicePosture.service_id, row_column.label("row")).where(member_of(ServicePosture.service_id, chunk, numeric=True))):
            rows[row.service_id] = row
    meta = {"services": len(service_ids), "stale": len(stale), "missing": len(missing),
            "recomputed": len(synchronous), "refreshing": refreshing}
    return {sid: rows[sid].row for sid in service_ids if sid in rows and rows[sid].row is not None}, meta


def services_rows(db, services, configurations, configuration, now):
    """Projection-backed equivalent of service_overview_rows_aggregated."""
    from .execution_summaries import CountOnly
    from . import main as m
    ids = [service.id for service in services]
    stored, meta = _load(db, "services", ids, configurations, now)
    rows, poam_counts = [], {}
    for service in services:
        value = stored[service.id]
        row = {key: CountOnly(int(value[key])) for key in _SERVICES_ROW_COUNTS}
        row.update({key: value[key] for key in ("compliant", "version", "evidence_state", "oldest_age", "archive")})
        row.update(service=service, policy_findings=[], poam=dict(value["poam"]))
        rows.append(row)
        poam_counts[service.id] = dict(value["poam"])
    if shadow_enabled():
        direct, _ = m.service_overview_rows_aggregated(db, None, now, configuration, services, configurations)
        _compare("services", {row["service"].id: _services_row(row) for row in direct}, stored)
    return rows, poam_counts, meta


def cyber_rows(db, services, configurations, configuration, now):
    """Projection-backed Cybersecurity rows keyed by service id."""
    ids = [service.id for service in services]
    stored, meta = _load(db, "cyber", ids, configurations, now)
    if shadow_enabled():
        from .dashboard_portfolio import compute_rows
        _compare("cyber", {sid: _cyber_row(row) for sid, row in compute_rows(db, services, configurations, configuration, now).items()}, stored)
    return {sid: _restore_cyber(row) for sid, row in stored.items()}, meta


def _compare(kind, direct, stored):
    mismatched = sorted(sid for sid in direct if json.loads(json.dumps(direct[sid], default=str)) != json.loads(json.dumps(stored.get(sid), default=str)))
    if mismatched:
        logger.warning("service_posture_shadow_mismatch %s", json.dumps({"kind": kind, "services": len(mismatched), "first": mismatched[:5]}))
    return mismatched


def background_enabled(bind) -> bool:
    """Background work is skipped for in-memory SQLite (tests, ephemeral tools)."""
    url = bind.url
    return not (url.get_backend_name() == "sqlite" and url.database in (None, "", ":memory:"))


def warm(bind, chunk_size=200, max_chunks=1000) -> int:
    """Bounded, resumable startup preparation of rows that are not current.

    Selects rows by cheap scalar checks only (generation, algorithm version,
    intelligence token, epoch); configuration and time freshness are verified
    on read. Each chunk commits independently, so a restart resumes.
    """
    token = _intelligence_token()
    total = 0
    for kind in KINDS:
        for _ in range(max_chunks):
            with Session(bind=bind) as db:
                epoch = current_epoch(db)
                ids = list(db.scalars(select(ServicePosture.service_id).where(
                    (_column(kind, "built_generation") != ServicePosture.data_generation)
                    | (_column(kind, "algorithm") != ALGORITHM_VERSION)
                    | _column(kind, "token").is_distinct_from(token)
                    | _column(kind, "epoch").is_distinct_from(epoch)
                    | _column(kind, "row").is_(None)).order_by(ServicePosture.service_id).limit(chunk_size)))
            if not ids:
                break
            total += rebuild(bind, kind, ids)
    return total
