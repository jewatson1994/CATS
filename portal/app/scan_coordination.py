"""Durable scan coordination. Scanner workers never import this module."""
import hashlib
import os
import secrets
import re
import json
from datetime import datetime, timedelta, timezone
from collections.abc import MutableMapping

from fastapi import HTTPException
from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text, select, update, func, text, inspect, delete
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
    definition_pending: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), index=True)
    anonymous: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


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
            anonymous = not (payload.get("owner_user_id") or payload.get("ingest_service_id") or payload.get("definition_context"))
            if anonymous:
                anonymous_count = db.scalar(select(func.count()).select_from(ScanJob).where(ScanJob.status.not_in(TERMINAL), ScanJob.anonymous.is_(True)))
                if anonymous_count >= min(setting("CATS_SCAN_ANONYMOUS_QUEUE_CAPACITY", 10), setting("CATS_SCAN_QUEUE_CAPACITY", 100) - 1):
                    raise HTTPException(429, "Anonymous scan queue is full")
            db.add(ScanJob(id=key, status=payload["status"], payload=dict(payload),
                           anonymous=anonymous, definition_pending=bool(payload.get("definition_context")),
                           service_key=payload.get("ingest_service_id", ""),
                           service_version=payload.get("ingest_service_version", ""),
                           input_digest=payload.get("input_digest", ""), available_at=now()))
            db.commit()

    def reserve(self, key, payload):
        self[key] = {**payload, "status": "preparing", "phase": "prepare"}

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
                if row.status in TERMINAL and values.get("status", row.status) != row.status:
                    return
                if values.get("status") == "cancelled" and row.status in TERMINAL:
                    return
                row.payload = {**row.payload, **values}
                row.status = row.payload["status"]
                row.input_digest = row.payload.get("input_digest", row.input_digest)
                row.definition_pending = bool(row.payload.get("definition_context")) and not bool(row.payload.get("definition_notified"))
                if row.status in TERMINAL:
                    row.finished_at = now()
                    row.lease_until = None
                    attempt = db.get(ScanAttempt, row.attempt_id) if row.attempt_id else None
                    if attempt and attempt.state not in {"received", "failed", "expired"}:
                        attempt.state = row.status
                if row.status in {"cancelled", "error"}:
                    from .models import ServiceImage
                    db.execute(update(ServiceImage).where(ServiceImage.scan_job_id == key)
                               .values(scan_status="failed", scan_error=row.payload.get("error") or "Scan cancelled"))
                db.commit()


def recover(db):
    abandoned = list(db.scalars(select(ScanJob).where(
        ScanJob.status == "preparing",
        ScanJob.created_at < now() - timedelta(seconds=setting("CATS_SCAN_PREPARATION_TTL_SECONDS", 900)))
        .with_for_update(skip_locked=True).limit(setting("CATS_SCAN_CLEANUP_BATCH_SIZE", 20))))
    for job in abandoned:
        job.status = "error"
        job.finished_at = now()
        job.payload = {**job.payload, "status": "error", "phase": "error", "error": "Scan input preparation expired before submission"}
        from .models import ServiceImage
        db.execute(update(ServiceImage).where(ServiceImage.scan_job_id == job.id)
                   .values(scan_status="failed", scan_error=job.payload["error"]))
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
        if exhausted:
            job.finished_at = now()
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
                        .order_by(ScanJob.anonymous, ScanJob.created_at).with_for_update(skip_locked=True).limit(1))
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
                "lease_until": row.lease_until.isoformat(), "input_digest": row.input_digest, "service_key": row.service_key,
                "service_version": row.service_version, "job": {key: value for key, value in row.payload.items() if key in {"job_kind", "image_list", "chart_url", "skipped_charts", "sbom_formats", "cyclonedx_spec_version", "definition_component", "definition_components"}}}


def fenced(db, job_id, attempt_id, token, *, completed=False, worker_id=None):
    job = db.scalar(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
    attempt = db.get(ScanAttempt, attempt_id)
    if not job or not attempt or attempt.job_id != job_id or job.attempt_id != attempt_id:
        raise HTTPException(409, "Stale or unrelated scan attempt")
    if worker_id is not None and attempt.worker_id != worker_id:
        raise HTTPException(403, "Attempt belongs to another worker")
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


def heartbeat(job_id, attempt_id, token, phase, log_tail="", worker_id=None):
    with SessionLocal() as db:
        job, _ = fenced(db, job_id, attempt_id, token, worker_id=worker_id)
        job.status = "running"
        job.lease_until = now() + timedelta(seconds=setting("CATS_SCAN_LEASE_SECONDS", 90))
        job.payload = {**job.payload, "status": "running", "phase": str(phase)[:32], "log_tail": sanitize_diagnostic(log_tail, 8192)}
        lease_until = job.lease_until.isoformat()
        db.commit()
    return {"cancelled": False, "lease_until": lease_until}


FAILURE_POLICY = {
    "artifact_acquisition": True, "registry_authorization": False,
    "scanner_execution": False, "scanner_timeout": True,
    "invalid_output": False, "insufficient_storage": True,
    "evidence_transfer": True, "evidence_integrity": False,
    "evidence_ingestion": False, "worker_infrastructure": True,
}


def sanitize_diagnostic(value, limit=1024):
    value = str(value or "")
    # Remove configured credentials and common credential-bearing diagnostic fields.
    tokens = [os.getenv("CATS_SCAN_WORKER_TOKEN", "")]
    try:
        credentials = json.loads(os.getenv("CATS_SCAN_WORKER_CREDENTIALS", "{}"))
        for record in credentials.values():
            tokens.extend(record.values() if isinstance(record, dict) else [record])
    except (ValueError, AttributeError):
        pass
    for token in tokens:
        if isinstance(token, str) and token:
            value = value.replace(token, "[redacted]")
    value = re.sub(r"(?i)(bearer\s+)\S+", r"\1[redacted]", value)
    value = re.sub(r"(?i)(password|token|secret|authorization|credential)(\s*[:=]\s*)[^\s,;]+", r"\1\2[redacted]", value)
    value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", value)
    return "".join(c for c in value if c.isprintable() or c in "\n\t")[:limit]


def report_failure(job_id, attempt_id, token, category, reason="", log_tail="", worker_id=None):
    if category not in FAILURE_POLICY:
        raise HTTPException(422, "Invalid failure category")
    with SessionLocal() as db:
        job, attempt = fenced(db, job_id, attempt_id, token, worker_id=worker_id)
        retry = FAILURE_POLICY[category] and job.attempts < setting("CATS_SCAN_MAX_ATTEMPTS", 3)
        diagnostic = sanitize_diagnostic(reason)
        failure = {"category": category, "reason": diagnostic, "retryable": FAILURE_POLICY[category],
                   "attempt_id": attempt_id, "reported_at": now().isoformat()}
        attempt.state = "failed"
        job.status = "queued" if retry else "error"
        job.lease_until = None
        job.available_at = now() + timedelta(seconds=min(300, 2 ** job.attempts))
        if not retry:
            job.finished_at = now()
        job.payload = {**job.payload, "status": job.status, "phase": "recovering" if retry else "error",
                       "error": diagnostic or category.replace("_", " ").capitalize(), "failure": failure,
                       "failure_history": [*job.payload.get("failure_history", []), failure][-10:],
                       "log_tail": sanitize_diagnostic(log_tail, 8192)}
        if not retry:
            job.payload = {**job.payload, "finished_at": job.finished_at.isoformat()}
            from .models import ServiceImage
            db.execute(update(ServiceImage).where(ServiceImage.scan_job_id == job_id)
                       .values(scan_status="failed", scan_error=job.payload["error"]))
        db.commit()
    return {"accepted": True, "retry": retry, "status": "queued" if retry else "error"}


def upgrade_connection(connection):
    """Add indexed scheduling state to existing deployments in their migration lock."""
    inspector = inspect(connection)
    if not inspector.has_table("scan_jobs"):
        return
    columns = {column["name"] for column in inspector.get_columns("scan_jobs")}
    additions = {"definition_pending": "BOOLEAN NOT NULL DEFAULT false", "anonymous": "BOOLEAN NOT NULL DEFAULT false",
                 "finished_at": "TIMESTAMP"}
    for name, declaration in additions.items():
        if name not in columns:
            connection.execute(text(f"ALTER TABLE scan_jobs ADD COLUMN {name} {declaration}"))
    # One-time migration backfill, never a maintenance history sweep.
    if "definition_pending" not in columns:
        if connection.dialect.name == "postgresql":
            condition = "COALESCE((payload->'definition_context')::text, '{}') NOT IN ('{}', 'null') AND COALESCE((payload->>'definition_notified')::boolean, false) = false"
        else:
            condition = "json_extract(payload, '$.definition_context') IS NOT NULL AND json_extract(payload, '$.definition_context') <> '{}' AND COALESCE(json_extract(payload, '$.definition_notified'), 0) = 0"
        connection.execute(text(f"UPDATE scan_jobs SET definition_pending = true WHERE {condition}"))
    if "anonymous" not in columns:
        if connection.dialect.name == "postgresql":
            condition = "COALESCE(payload->>'owner_user_id', '') = '' AND COALESCE(service_key, '') = '' AND COALESCE(payload->'definition_context', '{}'::json)::text = '{}'"
        else:
            condition = "COALESCE(json_extract(payload, '$.owner_user_id'), '') = '' AND COALESCE(service_key, '') = '' AND COALESCE(json_extract(payload, '$.definition_context'), '{}') = '{}'"
        connection.execute(text(f"UPDATE scan_jobs SET anonymous = true WHERE {condition}"))
    if "finished_at" not in columns:
        connection.execute(text("UPDATE scan_jobs SET finished_at = CURRENT_TIMESTAMP WHERE status IN ('complete','incomplete','error','cancelled')"))
    for name in additions:
        connection.execute(text(f"CREATE INDEX IF NOT EXISTS ix_scan_jobs_{name} ON scan_jobs ({name})"))


def admin_remove_job(key):
    """Explicit terminal-only administrative deletion; never part of public mapping."""
    with SessionLocal() as db:
        row = db.get(ScanJob, key)
        if row is None:
            raise KeyError(key)
        if row.status not in TERMINAL:
            raise ValueError("Active scan history cannot be removed")
        db.execute(delete(ScanAttempt).where(ScanAttempt.job_id == key))
        db.delete(row)
        db.commit()
