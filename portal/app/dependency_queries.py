"""Exact dependency projection with SQL filtering and bounded row hydration.

The cache is derived and disposable. Production warm reads compare source and
catalog revision tokens; ORM/bulk finding, observation and watchlist writers
invalidate headers transactionally. External SQL writers must invalidate the
header explicitly. Arbitrary risk callables without a token use scalar fallback.
Cache writes use a separate transaction when possible, otherwise the caller
owns the commit.
"""
from sqlalchemy import delete, func, insert, select

from .dependency_view import dependency_rows
from .execution_summaries import payload_digest
from .models import DependencyProjection, DependencyProjectionRow

PROJECTION_VERSION = 1


def dependency_version(db, execution):
    from .execution_summaries import load_execution_summaries
    summary = load_execution_summaries(db, [execution.id]).get(execution.id, {})
    return summary.get("raw_version") or "Unknown"


def persist_projection(db, execution, matches, findings, risk_metadata, *, fingerprint=None, expected_token=None):
    """Persist independently only when the binding permits a separate transaction.

    Evidence must refer to a committed execution (as it does on GET endpoints).
    Shared-connection SQLite and an existing SQLite writer use the caller's
    transaction without committing it. Their projection remains visible to
    this page, but a request rollback also discards the disposable cache.
    """
    if expected_token is not None:
        return ensure_projection(db, execution, matches, findings, risk_metadata, fingerprint=fingerprint, expected_token=expected_token)
    from sqlalchemy.orm import Session
    from sqlalchemy.engine import Connection
    from sqlalchemy.pool import StaticPool, SingletonThreadPool
    binding = db.get_bind()
    caller_owned = isinstance(binding, Connection)
    if binding.dialect.name == "sqlite":
        pool = getattr(binding, "pool", None)
        caller_owned |= isinstance(pool, (StaticPool, SingletonThreadPool))
        # SQLite permits one writer. An independently committing cache session
        # cannot coexist with already-flushed request writes on a file database.
        driver = db.connection().connection.driver_connection
        caller_owned |= bool(driver.in_transaction)
    if caller_owned:
        with db.no_autoflush:
            return ensure_projection(db, execution, matches, findings, risk_metadata, fingerprint=fingerprint, expected_token=expected_token)
    with db.no_autoflush, Session(bind=binding) as cache_db, cache_db.begin():
        return ensure_projection(cache_db, execution, matches, findings, risk_metadata, fingerprint=fingerprint, expected_token=expected_token)


def ensure_projection(db, execution, matches, findings, risk_metadata, *, fingerprint=None, expected_token=None):
    answers = {finding.cve: risk_metadata(finding.cve) for finding in findings}
    evidence = []
    for finding in findings if fingerprint is None else []:
        evidence.append([finding.cve, finding.severity, [
            [observation.package, observation.installed_version, observation.image,
             observation.fixed_version, observation.evidence]
            for observation in finding.observations if observation.execution_id == execution.id]])
    fingerprint = fingerprint or payload_digest({"version": PROJECTION_VERSION,
        # ORM payload writers maintain this digest transactionally. Legacy rows
        # without it hash source evidence until the summary backfill runs.
        "source": getattr(execution, "payload_digest", None) or payload_digest(execution.raw_payload),
        "findings": evidence, "risk": answers,
        "matches": sorted([list((m.component_name, m.component_version, m.component_purl, m.image))
                           for m in matches], key=repr)})
    existing = db.scalar(select(DependencyProjection).where(
        DependencyProjection.execution_id == execution.id).execution_options(populate_existing=True))
    if existing is not None and existing.fingerprint == fingerprint and existing.status == "ready":
        return False
    # Serialize cold rebuilds without locking warm read requests.
    from .models import Execution
    db.execute(select(Execution.id).where(Execution.id == execution.id).with_for_update())
    existing = db.scalar(select(DependencyProjection).where(
        DependencyProjection.execution_id == execution.id).execution_options(populate_existing=True))
    if existing is not None and existing.fingerprint == fingerprint and existing.status == "ready":
        return False
    if expected_token is not None:
        existing = db.scalar(select(DependencyProjection).where(DependencyProjection.execution_id == execution.id).with_for_update().execution_options(populate_existing=True))
        if existing is None or existing.build_token != expected_token or existing.status != "building":
            return False
    rows = dependency_rows(execution, matches, findings, lambda cve: answers[cve])
    db.execute(delete(DependencyProjectionRow).where(DependencyProjectionRow.execution_id == execution.id))
    for offset in range(0, len(rows), 250):
        records = []
        for position, row in enumerate(rows[offset:offset + 250], offset):
            licenses = ("license_declared", "license_detected", "license_expression")
            records.append({"execution_id": execution.id, "position": position, "data": row,
                "search_text": " ".join(str(row.get(key) or "") for key in
                    ("name", "version", "purl", "cpe", "image", "license_declared", "license_expression")).casefold(),
                "license_text": " ".join(str(row.get(key) or "") for key in licenses).casefold(),
                "component_type": row["type"], "image": row["image"],
                "severity": row["severity"].lower(), "epss": row["epss"],
                "vulnerable": bool(row["vulnerabilities"]), "kev": bool(row["kev"]),
                "fixed": bool(row["fixed_versions"]), "watchlisted": bool(row["watchlisted"]),
                "license_unknown": not any(row.get(key) for key in licenses)})
        db.execute(insert(DependencyProjectionRow), records)
    if existing is None:
        db.add(DependencyProjection(execution_id=execution.id, fingerprint=fingerprint))
    else:
        existing.fingerprint = fingerprint
        existing.status = "ready"
        existing.error = None
        from datetime import datetime, timezone
        existing.updated_at = datetime.now(timezone.utc)
    db.flush()
    return True


def dependency_page(db, execution_id, *, q="", component_type="", image="", license="",
                    filter="all", epss=None, page=1, page_size=50):
    row = DependencyProjectionRow
    base = row.execution_id == execution_id
    conditions = [base]
    search = q.casefold().strip()
    if search:
        conditions.append(row.search_text.contains(search, autoescape=True))
    if component_type:
        conditions.append(row.component_type == component_type)
    if image:
        conditions.append(row.image == image)
    if license:
        conditions.append(row.license_text.contains(license.casefold(), autoescape=True))
    flags = {"vulnerable": row.vulnerable, "kev": row.kev, "fixed": row.fixed,
             "watchlisted": row.watchlisted, "license_unknown": row.license_unknown}
    if filter != "all":
        conditions.append(flags[filter].is_(True) if filter in flags else row.severity == filter.lower())
    if epss is not None:
        conditions.append(row.epss >= epss)
    total = db.scalar(select(func.count()).select_from(row).where(*conditions))
    size = max(10, min(page_size, 100))
    pages = max(1, (total + size - 1) // size)
    current = min(max(1, page), pages)
    data = db.scalars(select(row.data).where(*conditions).order_by(row.position)
                      .offset((current - 1) * size).limit(size)).all()
    counts = {"dependency_all_total": db.scalar(select(func.count()).select_from(row).where(base))}
    for name, condition in {"vulnerable_components": row.vulnerable.is_(True),
            "critical_components": row.severity == "critical", "kev_components": row.kev.is_(True),
            "fixed_components": row.fixed.is_(True), "license_unknown_components": row.license_unknown.is_(True),
            "watchlisted_components": row.watchlisted.is_(True)}.items():
        counts[name] = db.scalar(select(func.count()).select_from(row).where(base, condition))
    types = sorted(db.scalars(select(row.component_type).where(base, row.component_type != "").distinct()).all())
    images = sorted(db.scalars(select(row.image).where(base).distinct()).all())
    return {**counts, "dependency_projection_status": "ready", "dependency_projection_error": None,
        "dependency_rows": data, "dependency_total": total,
            "dependency_page": current, "dependency_pages": pages,
            "dependency_types": types, "dependency_images": [value for value in images if value],
            "dependency_artifacts": len(images)}


def persist_current_projection(db, execution, risk_metadata, *, expected_token=None):
    """Revision-aware warm reads are constant-size; hydrate evidence only cold.

    ORM and SQLAlchemy bulk observation writers invalidate the disposable header.
    External SQL writers must delete that header in their write transaction.
    """
    from types import SimpleNamespace
    from hashlib import sha256
    import json
    from .models import Finding, FindingObservation, DependencyWatchlistMatch
    from .execution_summaries import refresh_execution_summary
    # Legacy executions establish their source digest once, in the caller's
    # transaction. Normal ingestion already maintains this scalar.
    if not execution.payload_digest:
        refresh_execution_summary(db, execution)
        db.flush()
    digest = sha256()
    def add(value):
        digest.update(json.dumps(value, sort_keys=True, default=str).encode())
        digest.update(b"\n")
    add([PROJECTION_VERSION, execution.payload_digest])
    relevant = select(Finding.id, Finding.cve, Finding.severity).where(
        Finding.id.in_(select(FindingObservation.finding_id).where(
            FindingObservation.execution_id == execution.id))).order_by(Finding.id)
    watch_query = select(DependencyWatchlistMatch.component_name,
        DependencyWatchlistMatch.component_version, DependencyWatchlistMatch.component_purl,
        DependencyWatchlistMatch.image).where(DependencyWatchlistMatch.execution_id == execution.id)
    catalog_token = getattr(risk_metadata, "cache_token", None)
    if catalog_token is not None:
        # Production catalogs supply a constant-time token. Findings, evidence,
        # and watchlist writers invalidate the persisted header transactionally.
        add(catalog_token())
    else:
        # Compatibility for arbitrary catalog callables without a revision API.
        for row in db.execute(relevant).yield_per(250):
            add([row.id, row.cve, row.severity, risk_metadata(row.cve)])
        for row in db.execute(watch_query.order_by(*watch_query.selected_columns)).yield_per(250):
            add(list(row))
    fingerprint = digest.hexdigest()
    existing_fingerprint = db.scalar(select(DependencyProjection.fingerprint).where(
        DependencyProjection.execution_id == execution.id))
    existing_status = db.scalar(select(DependencyProjection.status).where(DependencyProjection.execution_id == execution.id))
    if existing_fingerprint == fingerprint and existing_status == "ready":
        return False
    observations = {}
    columns = [getattr(FindingObservation, name) for name in ("finding_id", "execution_id", "package", "installed_version", "image", "fixed_version", "evidence")]
    for values in db.execute(select(*columns).where(
            FindingObservation.execution_id == execution.id).order_by(FindingObservation.id)).mappings():
        observation = SimpleNamespace(**values)
        observations.setdefault(observation.finding_id, []).append(observation)
    findings = [SimpleNamespace(cve=row.cve, severity=row.severity,
        observations=observations.get(row.id, [])) for row in db.execute(relevant)]
    matches = [SimpleNamespace(**dict(row)) for row in db.execute(watch_query).mappings()]
    return persist_projection(db, execution, matches, findings,
        risk_metadata, fingerprint=fingerprint, expected_token=expected_token)



def _invalidate_observation_projection(mapper, connection, observation):
    from sqlalchemy import inspect
    ids = {observation.execution_id, *inspect(observation).attrs.execution_id.history.deleted}
    connection.execute(delete(DependencyProjection).where(
        DependencyProjection.execution_id.in_(ids)))


# Mapping events cover every ORM session, including maintenance sessions.
from sqlalchemy import event
from .models import FindingObservation
for _operation in ("after_insert", "after_update", "after_delete"):
    event.listen(FindingObservation, _operation, _invalidate_observation_projection)


def _invalidate_bulk_observations(state):
    if not (state.is_update or state.is_delete or state.is_insert):
        return
    table = getattr(state.statement, "table", None)
    if table is not None and table.name in {FindingObservation.__tablename__, "findings", "dependency_watchlist_matches"}:
        # Bulk predicates can touch any execution. A broad cache invalidation
        # is safe, transactional, and avoids fetching the modified evidence.
        state.session.connection().execute(delete(DependencyProjection))


from sqlalchemy.orm import Session
# Session events include subclasses used by the application session factory.
event.listen(Session, "do_orm_execute", _invalidate_bulk_observations)



def _invalidate_finding_projection(mapper, connection, finding):
    connection.execute(delete(DependencyProjection).where(
        DependencyProjection.execution_id.in_(select(FindingObservation.execution_id).where(
            FindingObservation.finding_id == finding.id))))


def _invalidate_watchlist_projection(mapper, connection, match):
    from sqlalchemy import inspect
    ids = {match.execution_id, *inspect(match).attrs.execution_id.history.deleted}
    connection.execute(delete(DependencyProjection).where(
        DependencyProjection.execution_id.in_(ids)))


from .models import Finding, DependencyWatchlistMatch
for _operation in ("before_update", "before_delete"):
    event.listen(Finding, _operation, _invalidate_finding_projection)
for _operation in ("after_insert", "after_update", "after_delete"):
    event.listen(DependencyWatchlistMatch, _operation, _invalidate_watchlist_projection)


# A bounded executor isolates expensive disposable projections from GET latency.
# Database tokens coordinate claims across processes; executor slots bound local work.
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore
from datetime import datetime, timedelta, timezone
from uuid import uuid4

_projection_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cats-projection")
_projection_slots = BoundedSemaphore(4)


def _requested_fingerprint(execution, risk_metadata):
    token = getattr(risk_metadata, "cache_token", None)
    return payload_digest([PROJECTION_VERSION, execution.payload_digest, token() if token else None])


def request_current_projection(db, execution, risk_metadata, *, retry=False):
    """Return scalar lifecycle state without reading raw scan/evidence populations.

    Call schedule_projection only after response serialization (BackgroundTask).
    Source writers transactionally delete headers; a deleted build cannot activate.
    Legacy sources without a digest are established by the worker, never the GET.
    """
    from sqlalchemy.orm import Session
    from sqlalchemy.exc import IntegrityError
    wanted = _requested_fingerprint(execution, risk_metadata)
    now = datetime.now(timezone.utc)
    def state(row):
        return {"status": row.status, "build_token": row.build_token,
                "error": "Dependency projection failed; retry the request." if row.error else None}
    with Session(bind=db.get_bind()) as cache:
        row = cache.get(DependencyProjection, execution.id)
        if row is not None:
            stamp = row.updated_at
            if stamp is not None and stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            # Recover abandoned claims after process exit/crash with a conservative lease.
            expired = row.status == "building" and (stamp is None or now - stamp > timedelta(minutes=30))
            if row.status == "ready" and row.build_token == wanted:
                return state(row)
            if row.status in {"pending", "building"} and not expired:
                return state(row)
            if row.status == "failed" and not retry:
                return state(row)
            row.status = "pending"
            row.fingerprint = wanted
            row.build_token = uuid4().hex
            row.error = None
            row.updated_at = now
        else:
            row = DependencyProjection(execution_id=execution.id, fingerprint=wanted,
                status="pending", build_token=uuid4().hex, updated_at=now)
            cache.add(row)
        result = state(row)
        try:
            cache.commit()
        except IntegrityError:
            cache.rollback()
            return state(cache.get(DependencyProjection, execution.id))
        return result


def build_projection(binding, execution_id, token, risk_metadata):
    """Claim, build transactionally, and activate only the retained source token."""
    from sqlalchemy.orm import Session
    from sqlalchemy import update
    from .models import Execution
    try:
        with Session(bind=binding) as cache, cache.begin():
            claimed = cache.execute(update(DependencyProjection).where(
                DependencyProjection.execution_id == execution_id,
                DependencyProjection.build_token == token,
                DependencyProjection.status == "pending").values(status="building", updated_at=datetime.now(timezone.utc)))
            if claimed.rowcount != 1:
                return False
        with Session(bind=binding) as cache, cache.begin():
            execution = cache.get(Execution, execution_id)
            if execution is None:
                return False
            changed = persist_current_projection(cache, execution, risk_metadata, expected_token=token)
            row = cache.get(DependencyProjection, execution_id)
            if changed and row is not None and row.status == "ready" and row.build_token == token:
                # Keep both the exact evidence fingerprint and cheap request revision.
                row.build_token = _requested_fingerprint(execution, risk_metadata)
            return changed
    except Exception as exc:
        with Session(bind=binding) as cache, cache.begin():
            cache.execute(update(DependencyProjection).where(
                DependencyProjection.execution_id == execution_id,
                DependencyProjection.build_token == token).values(
                    status="failed", error=type(exc).__name__, updated_at=datetime.now(timezone.utc)))
        return False


def schedule_projection(binding, execution_id, token, risk_metadata):
    """Submit after the response; excess work stays PENDING for a subsequent GET."""
    from .database import background_bind
    binding = background_bind(binding)
    if not _projection_slots.acquire(blocking=False):
        return None
    try:
        future = _projection_executor.submit(build_projection, binding, execution_id, token, risk_metadata)
    except Exception:
        _projection_slots.release()
        raise
    future.add_done_callback(lambda _: _projection_slots.release())
    return future


def pending_dependency_page(status):
    """Unavailable derived evidence is distinct from an assessed zero count."""
    return {"dependency_rows": [], "dependency_total": None,
        "dependency_all_total": None, "dependency_page": 1, "dependency_pages": 1,
        "dependency_types": [], "dependency_images": [], "dependency_artifacts": None,
        "vulnerable_components": None, "critical_components": None, "kev_components": None,
        "fixed_components": None, "license_unknown_components": None, "watchlisted_components": None,
        "dependency_projection_status": status["status"], "dependency_projection_error": status["error"]}



def upgrade_dependency_schema(connection):
    """Add lifecycle fields to legacy disposable projections without source changes."""
    from sqlalchemy import inspect, text
    columns = {item["name"] for item in inspect(connection).get_columns("dependency_projections")}
    additions = {"status": "VARCHAR(16) NOT NULL DEFAULT 'ready'", "build_token": "VARCHAR(64)",
                 "error": "TEXT", "updated_at": "TIMESTAMP"}
    for name, sql in additions.items():
        if name not in columns:
            connection.execute(text(f"ALTER TABLE dependency_projections ADD COLUMN {name} {sql}"))
