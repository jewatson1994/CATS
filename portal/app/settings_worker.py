"""Apply saved dependency watchlist changes outside the HTTP process."""
from __future__ import annotations

from sqlalchemy import delete, func, select, text, update

from .durable_jobs import DurableJob, JobCancelled, JobError, run_worker, submit
from .imported_services import imported_service_predicate
from .models import (DependencyWatchlistEntry, DependencyWatchlistMatch, Execution,
                     PendingWatchlistDeletion, WatchlistRefreshState)
from .replica_models import ReplicaRecordMap
from .watchlist import index_entries, match_rows, publish_matches

KIND = "watchlist_refresh"
PAGE_SIZE = 32


def editable_watchlist_entry():
    """Hide requested deletions and watchlist evidence owned by an upstream service."""
    entry = DependencyWatchlistEntry
    return (~entry.id.in_(select(PendingWatchlistDeletion.entry_id))
            & ~entry.id.in_(select(ReplicaRecordMap.local_id).where(
                ReplicaRecordMap.table_name == entry.__tablename__)))


def queue_watchlist_refresh(db, requester_id, *, rules_changed=True):
    """Enqueue in the transaction that saves the rules. Coalesce unstarted passes."""
    if db.get_bind().dialect.name == "postgresql":
        # Serialize the first insertion as well as edits on multiple portal instances.
        db.execute(text("SELECT pg_advisory_xact_lock(73488341)"))
    else:
        # SQLite ignores FOR UPDATE. Even when the singleton does not exist,
        # a no-op UPDATE reserves the writer for the surrounding transaction.
        db.execute(update(WatchlistRefreshState).where(WatchlistRefreshState.id == 1)
                   .values(job_id=WatchlistRefreshState.job_id))
    state = db.scalar(select(WatchlistRefreshState).where(WatchlistRefreshState.id == 1).with_for_update())
    if state:
        job = db.scalar(select(DurableJob).where(DurableJob.id == state.job_id).with_for_update())
        if job and not job.cancel_requested:
            if job.status == "queued" and not job.attempts:
                return job
            if not rules_changed and job.status in {"queued", "running"}:
                return job
    job = submit(db, kind=KIND, payload={}, requested_by_id=requester_id, commit=False)
    if state:
        state.job_id = job.id
    else:
        db.add(WatchlistRefreshState(id=1, job_id=job.id))
    return job


def latest_watchlist_refresh(db):
    row = db.execute(select(DurableJob.id, DurableJob.status, DurableJob.progress, DurableJob.stage,
                            DurableJob.error).join(WatchlistRefreshState,
                            WatchlistRefreshState.job_id == DurableJob.id).where(
                            WatchlistRefreshState.id == 1)).mappings().first()
    return dict(row) if row else None


def fence_ingestion(db):
    """A refresh must include any uncommitted scan that already read the old rules."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock_shared(73488342)"))


def _current_owner(db, ctx):
    # Lock order is identical to queue admission. A superseded worker cannot
    # publish even when its lease heartbeat or CPU calculation finishes late.
    if db.get_bind().dialect.name == "sqlite":
        # SQLite ignores FOR UPDATE. Obtain its writer reservation before checking.
        current = db.execute(update(WatchlistRefreshState).where(WatchlistRefreshState.id == 1,
            WatchlistRefreshState.job_id == ctx.job.id).values(job_id=ctx.job.id)).rowcount
    else:
        current = db.scalar(select(WatchlistRefreshState.id).where(WatchlistRefreshState.id == 1,
            WatchlistRefreshState.job_id == ctx.job.id).with_for_update(read=True))
    if not current:
        return None
    job = ctx._owned(db)
    if job.cancel_requested:
        raise JobCancelled()
    return job


def _finish_deletions(ctx):
    while True:
        with ctx.session_factory.begin() as db:
            if _current_owner(db, ctx) is None:
                return False
            ids = list(db.scalars(select(PendingWatchlistDeletion.entry_id)
                                  .order_by(PendingWatchlistDeletion.entry_id).limit(200)))
            if not ids:
                return True
            if db.scalar(select(DependencyWatchlistMatch.id).where(
                    DependencyWatchlistMatch.entry_id.in_(ids)).limit(1)) is not None:
                raise JobError("A deleted watchlist rule still has retained evidence")
            db.execute(delete(PendingWatchlistDeletion).where(PendingWatchlistDeletion.entry_id.in_(ids)))
            db.execute(delete(DependencyWatchlistEntry).where(DependencyWatchlistEntry.id.in_(ids)))


def handler(ctx, payload):
    # Standalone workers need the same transactional view-invalidation listeners as ingest.
    from . import dependency_queries, service_posture  # noqa: F401
    from .operating_mode import is_replica
    if is_replica():
        raise JobError("Watchlist refresh is available only in full operating mode")
    with ctx.session_factory.begin() as db:
        if db.get_bind().dialect.name == "postgresql":
            # The exclusive gate only captures the high-water mark. Matching and
            # publication run after release; ingestion continues for the entire pass.
            db.execute(text("SELECT pg_advisory_xact_lock(73488342)"))
        job = _current_owner(db, ctx)
        if job is None:
            return {"superseded": True}
        result = job.result or {}
        cursor = result.get("execution_cursor", 0)
        upper = result.get("last_execution_id")
        if upper is None:
            upper = db.scalar(select(func.max(Execution.id))) or 0
        entries = list(db.scalars(select(DependencyWatchlistEntry).where(
            DependencyWatchlistEntry.enabled.is_(True), editable_watchlist_entry())))
        for entry in entries:
            db.expunge(entry)
        job.stage = "Refreshing historical watchlist matches"
        job.result = {**result, "last_execution_id": upper}
    indexed = index_entries(entries)
    local = ~imported_service_predicate(Execution.service_id)
    while cursor < upper:
        with ctx.session_factory() as db:
            ids = list(db.scalars(select(Execution.id).where(Execution.id > cursor, Execution.id <= upper,
                                  local).order_by(Execution.id).limit(PAGE_SIZE)))
        if not ids:
            break
        for execution_id in ids:
            with ctx.session_factory() as db:
                scan = db.execute(select(Execution.service_id, Execution.raw_payload["sbom_components"])
                                  .where(Execution.id == execution_id, local)).first()
            rows = match_rows(scan[1], indexed, execution_id, scan[0]) if scan else {}
            with ctx.session_factory.begin() as db:
                job = _current_owner(db, ctx)
                if job is None:
                    return {"superseded": True}
                if scan:
                    # A service or scan can be removed while matching is in progress.
                    current = db.scalar(select(Execution.id).where(Execution.id == execution_id,
                        Execution.service_id == scan[0], local).with_for_update())
                    if current is not None:
                        publish_matches(db, execution_id, scan[0], rows)
                cursor = execution_id
                job.result = {**job.result, "execution_cursor": cursor}
                job.progress = min(99, cursor * 100 // upper)
    return {"superseded": True} if not _finish_deletions(ctx) else {"last_execution_id": upper}


if __name__ == "__main__":
    run_worker((KIND,), handler)
