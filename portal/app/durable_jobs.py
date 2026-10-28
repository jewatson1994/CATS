"""Database-backed work for HQ workers, using the scan coordinator's lease pattern.

Only trusted HQ processes use these helpers. No broker, browser credentials or
external command execution is required by the portal. Handler effects must be
idempotent and check the current lease before publishing results.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import logging
import os
import signal
import threading
import time
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, func, select, update, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base, SessionLocal


def now():
    return datetime.now(timezone.utc)


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def setting(name, default):
    return max(1, int(os.getenv(name, str(default))))


class DurableJob(Base):
    __tablename__ = "durable_jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(48), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), index=True)
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    source_execution_id: Mapped[int | None] = mapped_column(ForeignKey("executions.id"))
    version: Mapped[str] = mapped_column(String(255), default="")
    dedupe_key: Mapped[str | None] = mapped_column(String(255), unique=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(160), default="Queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(32), default=lambda: uuid.uuid4().hex)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    worker_id: Mapped[str | None] = mapped_column(String(128))
    lease_token: Mapped[str | None] = mapped_column(String(32))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class JobError(Exception):
    """Handler-authored safe diagnostic, never raw external exception text."""


class LeaseLost(Exception):
    pass


class JobCancelled(Exception):
    pass


def submit(db, *, kind, payload, service_id=None, requested_by_id=None,
           source_execution_id=None, version="", dedupe_key=None, max_attempts=3, commit=True):
    if dedupe_key:
        existing = db.scalar(select(DurableJob).where(DurableJob.dedupe_key == dedupe_key))
        if existing:
            return existing
    # Serialize queue admission on PostgreSQL; the same database stores scans.
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(73488294)"))
        # Another transaction may have admitted this key while we waited.
        # Recheck before capacity and insertion, including commit=False callers
        # whose surrounding approval transaction must not be rolled back.
        if dedupe_key:
            existing = db.scalar(select(DurableJob).where(DurableJob.dedupe_key == dedupe_key))
            if existing:
                return existing
    count = db.scalar(select(func.count()).select_from(DurableJob).where(
        DurableJob.status.in_(("queued", "running"))))
    if count >= setting("CATS_JOB_QUEUE_CAPACITY", 200):
        from fastapi import HTTPException
        raise HTTPException(429, "Background work queue is full; retry later")
    row = DurableJob(id=uuid.uuid4().hex, kind=kind, payload=payload,
        service_id=service_id, requested_by_id=requested_by_id,
        source_execution_id=source_execution_id, version=version,
        dedupe_key=dedupe_key, max_attempts=max(1, min(5, max_attempts)))
    db.add(row)
    if not commit:
        # Keep job admission atomic with the caller's decision and job binding.
        db.flush()
        return row
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(DurableJob).where(DurableJob.dedupe_key == dedupe_key)) if dedupe_key else None
        if existing is None:
            raise
        return existing
    return row


def recover(db, kinds):
    """Expired owners are fenced; attempts are bounded even after process death."""
    rows = db.scalars(select(DurableJob).where(DurableJob.kind.in_(kinds),
        DurableJob.status == "running", DurableJob.lease_until < now()).with_for_update(skip_locked=True)).all()
    for row in rows:
        terminal = row.cancel_requested or row.attempts >= row.max_attempts
        row.status = "cancelled" if row.cancel_requested else "failed" if terminal else "queued"
        row.stage = "Worker lease expired" if terminal else "Waiting to retry after worker loss"
        row.error = "Worker stopped before completing this job. Review the result before retrying." if terminal else None
        row.completed_at = now() if terminal else None
        row.available_at = now() + timedelta(seconds=min(300, 5 * 2 ** row.attempts))
        row.lease_token, row.lease_until = None, None
    db.commit()


def claim(kinds, worker_id, session_factory=SessionLocal):
    with session_factory() as db:
        recover(db, kinds)
        row = db.scalar(select(DurableJob).where(DurableJob.kind.in_(kinds),
            DurableJob.status == "queued", DurableJob.available_at <= now(),
            DurableJob.cancel_requested.is_(False)).order_by(DurableJob.created_at)
            .with_for_update(skip_locked=True).limit(1))
        if row is None:
            return None
        token = uuid.uuid4().hex
        changed = db.execute(update(DurableJob).where(DurableJob.id == row.id,
            DurableJob.status == "queued").values(status="running", stage="Starting",
            lease_token=token, worker_id=worker_id, heartbeat_at=now(),
            lease_until=now() + timedelta(seconds=setting("CATS_JOB_LEASE_SECONDS", 120)),
            started_at=row.started_at or now(), attempts=DurableJob.attempts + 1))
        db.commit()
        if not changed.rowcount:
            return None
        db.refresh(row)
        db.expunge(row)
        return row


class JobContext:
    def __init__(self, job, session_factory=SessionLocal):
        self.job, self.session_factory = job, session_factory
        self.lost = threading.Event()

    def _owned(self, db):
        row = db.scalar(select(DurableJob).where(DurableJob.id == self.job.id).with_for_update())
        if (self.lost.is_set() or not row or row.status != "running" or
                row.lease_token != self.job.lease_token or not row.lease_until or aware(row.lease_until) <= now()):
            raise LeaseLost()
        return row

    def check(self):
        with self.session_factory() as db:
            if self._owned(db).cancel_requested:
                raise JobCancelled()

    def stage(self, stage, progress=None):
        with self.session_factory() as db:
            row = self._owned(db)
            if row.cancel_requested:
                raise JobCancelled()
            row.stage = stage[:160]
            if progress is not None:
                row.progress = max(0, min(99, int(progress)))
            db.commit()

    def checkpoint(self, result):
        with self.session_factory() as db:
            row = self._owned(db)
            if row.cancel_requested:
                raise JobCancelled()
            row.result = {**row.result, **result}
            db.commit()
            self.job.result = dict(row.result)

    def heartbeat(self):
        with self.session_factory() as db:
            row = self._owned(db)
            row.heartbeat_at = now()
            row.lease_until = now() + timedelta(seconds=setting("CATS_JOB_LEASE_SECONDS", 120))
            db.commit()

    def finish(self, result=None, error=None, cancelled=False, retry=False):
        with self.session_factory() as db:
            row = self._owned(db)
            cancelled = cancelled or row.cancel_requested
            retry = retry and not cancelled and row.attempts < row.max_attempts
            status = "cancelled" if cancelled else "queued" if retry else "failed" if error else "completed"
            row.stage = "Waiting to retry" if retry else status.capitalize()
            row.error = error
            if result is not None:
                row.result = {**row.result, **result}
            if status == "completed" and row.kind == "patch_campaign_item":
                from .patch_campaigns import complete_inventory
                # Inventory and completion commit together under the job lock.
                row.result = {**row.result, **complete_inventory(db, row)}
            row.status = status
            row.progress = 100 if row.status == "completed" else row.progress
            row.completed_at = None if retry else now()
            row.available_at = now() + timedelta(seconds=min(300, 5 * 2 ** row.attempts))
            row.lease_token, row.lease_until = None, None
            db.commit()


def execute(job, handler, session_factory=SessionLocal):
    ctx = JobContext(job, session_factory)
    done = threading.Event()
    def renew():
        while not done.wait(max(1, setting("CATS_JOB_LEASE_SECONDS", 120) // 3)):
            try:
                ctx.heartbeat()
            except Exception:
                ctx.lost.set()
                return
    thread = threading.Thread(target=renew, daemon=True)
    thread.start()
    try:
        ctx.check()
        result = handler(ctx, job.payload)
        ctx.finish(result or {})
    except LeaseLost:
        pass
    except JobCancelled:
        try:
            ctx.finish(cancelled=True)
        except LeaseLost:
            pass
    except Exception as exc:
        safe = str(exc) if isinstance(exc, JobError) else "Operation failed; inspect worker configuration and retry."
        logging.getLogger(__name__).error("job_failure kind=%s correlation_id=%s exception_type=%s",
            job.kind, job.correlation_id, type(exc).__name__)
        try:
            ctx.finish(error=f"{safe} Reference: {job.correlation_id}", retry=not isinstance(exc, JobError))
        except LeaseLost:
            pass
    finally:
        done.set()
        thread.join(timeout=2)


def run_worker(kinds, handler, *, maintenance=None, max_workers=1):
    """Claim only available execution slots; active jobs keep their own leases."""
    if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 32:
        raise ValueError("max_workers must be an integer from 1 to 32")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    worker_id = os.getenv("HOSTNAME", "worker") + "-" + uuid.uuid4().hex[:8]
    last_maintenance = 0
    # The single-worker path retains its main-thread database routing. Other
    # worker services keep that default and their existing connection budgets.
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="cats-job") as pool:
        active = set()
        while not stop.is_set():
            try:
                completed = {future for future in active if future.done()}
                active -= completed
                for future in completed:
                    try:
                        future.result()
                    except Exception as exc:
                        logging.getLogger(__name__).error("worker_job_failure exception_type=%s", type(exc).__name__)
                if maintenance and time.monotonic() - last_maintenance >= 60:
                    # Failed reconciliation must neither busy-loop nor prevent
                    # already queued work from running until the next interval.
                    last_maintenance = time.monotonic()
                    try:
                        maintenance()
                    except Exception as exc:
                        logging.getLogger(__name__).error("worker_maintenance_failure exception_type=%s", type(exc).__name__)
                if len(active) < max_workers and not stop.is_set():
                    job = claim(kinds, worker_id)
                    if job:
                        if max_workers == 1:
                            execute(job, handler)
                        else:
                            active.add(pool.submit(execute, job, handler))
                        continue
                stop.wait(2)
            except Exception as exc:
                logging.getLogger(__name__).error("worker_loop_failure exception_type=%s", type(exc).__name__)
                stop.wait(5)
        # Executor shutdown waits for active handlers; their heartbeat threads
        # remain alive while they finish. No queued job is claimed on shutdown.
