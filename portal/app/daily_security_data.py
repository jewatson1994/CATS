"""Refresh each installed security data source once per UTC day on a dedicated worker."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from . import scan_intelligence, security_data
from .auth import record_audit
from .database import SessionLocal
from .durable_jobs import JobCancelled, JobError, LeaseLost, now, run_worker, submit
from .models import PortalSetting, SecurityDataSource
from .patching import redact
from .trusted_ca import additional_pem


KIND = "security_data_refresh"
AUTO_SETTING = "security_data_auto_refresh"


def _setting(db, key):
    return db.scalar(select(PortalSetting.value).where(PortalSetting.key == key, PortalSetting.group_id.is_(None)))


def enabled(db):
    value = _setting(db, AUTO_SETTING)
    return value is None or value.strip().lower() == "true"


def lock_source(db, key):
    """Serialize saves, manual uploads and scheduled downloads for one feed."""
    if key not in security_data.SOURCE_KEYS:
        raise ValueError("Unknown security data source")
    query = select(SecurityDataSource).where(SecurityDataSource.key == key).with_for_update()
    record = db.scalar(query)
    if record is None:
        insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
        db.execute(insert(SecurityDataSource).values(key=key).on_conflict_do_nothing(index_elements=["key"]))
        record = db.scalar(query)
    return record


class RefreshSkipped(Exception):
    pass


def refresh_source(db, record, *, auth=None, upload=None, grype_listing=None, scheduled_job=None, refresh=None):
    """Validate and install using the saved mirror or upstream, retaining the last good data on failure.

    The caller holds the source lock and commits the source status, audit and job checkpoint together.
    """
    action = "upload" if upload is not None else "refresh"
    detail = {"trigger": "daily" if scheduled_job else "manual"}
    options = {"grype_listing": grype_listing} if record.key == "grype" else {}
    if scheduled_job:
        original_attempt = record.last_attempt_at
        def before_activate():
            if db.get_bind().dialect.name == "sqlite":
                # SQLite has no row locks. Take its writer lock only when
                # publishing, and yield to a mirror change or manual install.
                matched = db.execute(update(SecurityDataSource).where(
                    SecurityDataSource.key == record.key, SecurityDataSource.source == record.source,
                    SecurityDataSource.last_attempt_at == original_attempt,
                ).values(key=record.key).execution_options(synchronize_session=False)).rowcount
                if not matched:
                    raise RefreshSkipped()
            # Lock the current lease only at publication. Heartbeats can renew it
            # during the remote transfer, native validation and generation hashing.
            if scheduled_job._owned(db).cancel_requested:
                raise JobCancelled()
            if not enabled(db):
                raise RefreshSkipped()
        options["before_activate"] = before_activate
    source = record.source or security_data.DEFAULT_SOURCES[record.key]
    record.last_attempt_at = now()
    record_audit(db, auth, f"security_data.{action}_requested", "security_data_source", record.key, **detail)
    try:
        certificates = json.loads(_setting(db, "trusted_ca_certificates") or "[]")
        bundle = additional_pem(certificates) or None
        version = (refresh or security_data.refresh)(record.key, source, upload, bundle, **options)
    except (JobCancelled, LeaseLost, RefreshSkipped, SQLAlchemyError):
        raise
    except Exception as exc:
        if scheduled_job:
            before_activate()
        record.status = "FAILED"
        record.failure_reason = f"{type(exc).__name__}: {redact(exc)}"[:1000]
        record_audit(db, auth, "security_data.update_failed", "security_data_source", record.key,
                     reason=record.failure_reason, **detail)
        return False
    record.installed_at = record.last_success_at = now()
    record.installed_version = version
    record.status = "READY"
    record.failure_reason = None
    record_audit(db, auth, "security_data.updated", "security_data_source", record.key, version=version, **detail)
    return True


def maintenance(session_factory=SessionLocal):
    day = now().date().isoformat()
    with session_factory() as db:
        if enabled(db):
            for key in security_data.DEFAULT_SOURCES:
                submit(db, kind=KIND, dedupe_key=f"{KIND}:{day}:{key}", payload={"day": day, "key": key})


def handler(context, payload):
    key = payload["key"]
    # The checkpoint and source status are a single transaction, even if the
    # process dies before durable_jobs can mark the outer job terminal.
    outcome = context.job.result.get("outcome")
    if not outcome:
        with context.session_factory() as db:
            if payload["day"] != now().date().isoformat() or not enabled(db):
                return {"outcome": "skipped"}
            if db.get_bind().dialect.name == "sqlite":
                # A first-use insert must release SQLite's writer lock before
                # the download, so lease heartbeats can continue.
                db.execute(sqlite_insert(SecurityDataSource).values(key=key).on_conflict_do_nothing(index_elements=["key"]))
                db.commit()
            record = lock_source(db, key)
            try:
                success = refresh_source(db, record, scheduled_job=context)
            except RefreshSkipped:
                db.rollback()
                return {"outcome": "skipped"}
            owned = context._owned(db)
            if owned.cancel_requested:
                raise JobCancelled()
            outcome = "updated" if success else "failed"
            owned.result = {"outcome": outcome}
            db.commit()
    if outcome == "failed":
        # Offline is an expected daily outcome. Continue with the other feeds
        # and retry this source on the next scheduled day.
        raise JobError(f"{key.upper()} refresh failed. See the source status in Settings.")
    if key in scan_intelligence.DEFAULT_SOURCES:
        variable = "GRYPE_DB_CACHE_DIR" if key == "grype" else "TRIVY_CACHE_DIR"
        root = Path(os.getenv(variable, scan_intelligence.DEFAULT_SOURCES[key]))
        try:
            scan_intelligence.prune_scheduled(root)
        except (OSError, ValueError, KeyError):
            logging.getLogger(__name__).exception("Could not retire older %s databases", key)
    return {"outcome": outcome}


if __name__ == "__main__":
    run_worker((KIND,), handler, maintenance=maintenance)
