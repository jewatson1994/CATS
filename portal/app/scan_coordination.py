"""Durable scan coordination. Scanner workers never import this module."""
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from collections.abc import MutableMapping

from fastapi import HTTPException
from sqlalchemy import DateTime, Integer, JSON, String, Text, select, update, func, text
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base, SessionLocal


def now():
    return datetime.now(timezone.utc)


def setting(name, default):
    return max(1, int(os.getenv(name, str(default))))


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    service_key: Mapped[str] = mapped_column(String(120), default="")
    service_version: Mapped[str] = mapped_column(String(120), default="")
    input_digest: Mapped[str] = mapped_column(String(64), default="")
    attempt_id: Mapped[str | None] = mapped_column(String(32))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ScanAttempt(Base):
    __tablename__ = "scan_attempts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    job_id: Mapped[str] = mapped_column(String(32), index=True)
    worker_id: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(24))
    manifest_digest: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


TERMINAL = {"complete", "incomplete", "error", "cancelled"}


class DurableJobs(MutableMapping):
    """Compatibility read interface for the existing public job endpoints."""
    def __getitem__(self, key):
        with SessionLocal() as db:
            row = db.get(ScanJob, key)
            if row is None:
                raise KeyError(key)
            return dict(row.payload)

    def __setitem__(self, key, payload):
        with SessionLocal() as db:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(text("SELECT pg_advisory_xact_lock(73488292)"))
            count = db.scalar(select(func.count()).select_from(ScanJob).where(ScanJob.status.not_in(TERMINAL)))
            if count >= setting("CATS_SCAN_QUEUE_CAPACITY", 100):
                raise HTTPException(429, "Scan queue is full")
            db.add(ScanJob(id=key, status=payload["status"], payload=dict(payload),
                           service_key=payload.get("ingest_service_id", ""),
                           service_version=payload.get("ingest_service_version", ""),
                           input_digest=payload.get("input_digest", ""), available_at=now()))
            db.commit()

    def __delitem__(self, key):
        raise TypeError("Scan history is retained")

    def __iter__(self):
        with SessionLocal() as db:
            return iter(list(db.scalars(select(ScanJob.id))))

    def __len__(self):
        with SessionLocal() as db:
            return db.scalar(select(func.count()).select_from(ScanJob))

    def update_job(self, key, values):
        with SessionLocal() as db:
            row = db.scalar(select(ScanJob).where(ScanJob.id == key).with_for_update())
            if row:
                if row.status == "cancelled" and values.get("status", "cancelled") != "cancelled":
                    return
                if values.get("status") == "cancelled" and row.status in TERMINAL:
                    return
                row.payload = {**row.payload, **values}
                row.status = row.payload["status"]
                if row.status in {"cancelled", "error"}:
                    from .models import ServiceImage
                    db.execute(update(ServiceImage).where(ServiceImage.scan_job_id == key)
                               .values(scan_status="failed", scan_error=row.payload.get("error") or "Scan cancelled"))
                db.commit()


def recover(db):
    expired = list(db.scalars(select(ScanJob).where(
        ScanJob.status.in_(["running", "claimed"]), ScanJob.lease_until < now()).with_for_update(skip_locked=True)))
    for job in expired:
        attempt = db.get(ScanAttempt, job.attempt_id)
        if attempt:
            attempt.state = "expired"
        exhausted = job.attempts >= setting("CATS_SCAN_MAX_ATTEMPTS", 3)
        job.status = "error" if exhausted else "queued"
        job.available_at = now() + timedelta(seconds=min(300, 2 ** job.attempts))
        job.lease_until = None
        job.payload = {**job.payload, "status": job.status, "phase": "error" if exhausted else "recovering",
                       "error": "Worker lease expired; retry limit reached" if exhausted else "Worker lease expired; queued for recovery"}
        if exhausted:
            from .models import ServiceImage
            db.execute(update(ServiceImage).where(ServiceImage.scan_job_id == job.id)
                       .values(scan_status="failed", scan_error=job.payload["error"]))


def claim(worker_id):
    with SessionLocal() as db:
        recover(db)
        row = db.scalar(select(ScanJob).where(ScanJob.status == "queued", ScanJob.available_at <= now())
                        .order_by(ScanJob.created_at).with_for_update(skip_locked=True).limit(1))
        if row is None:
            db.commit()
            return None
        attempt_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        # The conditional update also fences SQLite tests and concurrent callers.
        changed = db.execute(update(ScanJob).where(ScanJob.id == row.id, ScanJob.status == "queued")
                             .values(status="claimed", attempt_id=attempt_id, attempts=ScanJob.attempts + 1,
                                     lease_until=now() + timedelta(seconds=setting("CATS_SCAN_LEASE_SECONDS", 90))))
        if changed.rowcount != 1:
            db.rollback()
            return None
        row.payload = {**row.payload, "status": "running", "phase": "prepare", "attempt_id": attempt_id,
                       "started_at": now().isoformat(), "error": ""}
        db.add(ScanAttempt(id=attempt_id, job_id=row.id, worker_id=worker_id,
                           token_hash=hashlib.sha256(token.encode()).hexdigest(), state="running"))
        db.commit()
        return {"job_id": row.id, "attempt_id": attempt_id, "attempt_token": token,
                "input_digest": row.input_digest, "service_key": row.service_key,
                "service_version": row.service_version, "job": {key: value for key, value in row.payload.items() if key in {"job_kind", "image_list", "chart_url", "skipped_charts", "sbom_formats", "cyclonedx_spec_version", "definition_component", "definition_components"}}}


def fenced(db, job_id, attempt_id, token, *, completed=False):
    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
    attempt = db.get(ScanAttempt, attempt_id)
    if not job or not attempt or attempt.job_id != job_id or job.attempt_id != attempt_id:
        raise HTTPException(409, "Stale or unrelated scan attempt")
    if not token or not secrets.compare_digest(attempt.token_hash, hashlib.sha256(token.encode()).hexdigest()):
        raise HTTPException(403, "Invalid attempt credential")
    if completed and attempt.state == "received":
        return job, attempt
    lease = job.lease_until
    if lease and lease.tzinfo is None:
        lease = lease.replace(tzinfo=timezone.utc)
    if job.status not in {"running", "claimed"} or not lease or lease <= now():
        raise HTTPException(409, "Scan attempt is no longer active")
    return job, attempt


def heartbeat(job_id, attempt_id, token, phase, log_tail=""):
    with SessionLocal() as db:
        job, _ = fenced(db, job_id, attempt_id, token)
        job.status = "running"
        job.lease_until = now() + timedelta(seconds=setting("CATS_SCAN_LEASE_SECONDS", 90))
        job.payload = {**job.payload, "status": "running", "phase": str(phase)[:32], "log_tail": str(log_tail)[-8192:]}
        db.commit()
    return {"cancelled": False}
