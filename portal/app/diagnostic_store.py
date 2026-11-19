"""Small local diagnostic history, separate from security audit and job truth."""
from datetime import datetime, timedelta, timezone
import logging
import os
from queue import Empty, Full, Queue
import threading

from sqlalchemy import DateTime, Index, Integer, JSON, String, delete, select
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base, SessionLocal
from .diagnostics import sanitize

logger = logging.getLogger("cats.diagnostics")


def bounded_setting(name, default, low, high):
    try:
        return max(low, min(high, int(os.getenv(name, str(default)))))
    except (TypeError, ValueError):
        return default


def retention_days():
    return bounded_setting("CATS_DIAGNOSTIC_RETENTION_DAYS", 30, 1, 365)


class DiagnosticEvent(Base):
    __tablename__ = "diagnostic_events"
    error_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    component: Mapped[str] = mapped_column(String(160))
    operation: Mapped[str] = mapped_column(String(255))
    code: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(16))
    service_id: Mapped[int | None] = mapped_column(Integer, index=True)
    job_id: Mapped[str | None] = mapped_column(String(128), index=True)
    summary: Mapped[str] = mapped_column(String(1024))
    diagnostic: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (
        Index("ix_diagnostic_component_time", "component", "timestamp"),
        Index("ix_diagnostic_severity_time", "severity", "timestamp"),
        Index("ix_diagnostic_code_time", "code", "timestamp"),
    )


def cleanup(db):
    """Indexed, bounded deletes; no vacuum, full log scan, or external service."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days())
    old = select(DiagnosticEvent.error_id).where(DiagnosticEvent.timestamp < cutoff).order_by(DiagnosticEvent.timestamp).limit(1000)
    db.execute(delete(DiagnosticEvent).where(DiagnosticEvent.error_id.in_(old)))
    limit = bounded_setting("CATS_DIAGNOSTIC_MAX_EVENTS", 20000, 100, 200000)
    excess = select(DiagnosticEvent.error_id).order_by(DiagnosticEvent.timestamp.desc(), DiagnosticEvent.error_id.desc()).offset(limit).limit(1000)
    db.execute(delete(DiagnosticEvent).where(DiagnosticEvent.error_id.in_(excess)))


def record_diagnostic(diagnostic, session_factory=None):
    try:
        item = sanitize(diagnostic)
        resource = item.get("resource") or {}
        service_id = resource.get("service_id")
        if not isinstance(service_id, int) or isinstance(service_id, bool):
            service_id = None
        with (session_factory or SessionLocal)() as db:
            # Dedicated short transaction, never commit/rollback caller work.
            if db.get(DiagnosticEvent, item["error_id"]) is not None:
                return True
            db.add(DiagnosticEvent(error_id=item["error_id"], correlation_id=item["correlation_id"],
                timestamp=datetime.fromisoformat(item["timestamp"]), component=item["component"][:160],
                operation=item["operation"][:255], code=item["code"][:80], severity=item["severity"][:16],
                service_id=service_id, job_id=str(resource["job_id"])[:128] if resource.get("job_id") is not None else None,
                summary=item["summary"][:1024], diagnostic=item))
            db.flush()
            cleanup(db)
            db.commit()
        return True
    except Exception as exc:
        # Never recurse through diagnostic persistence or log exception content.
        logger.warning("diagnostic_store_unavailable error_id=%s exception_type=%s", diagnostic.get("error_id", "unknown"), type(exc).__name__)
        return False


_queue = Queue(maxsize=128)
_lock = threading.Lock()
_thread = None


def _consume():
    while True:
        try:
            diagnostic = _queue.get(timeout=60)
        except Empty:
            # Cleanup even when the installation is idle, without holding a pool connection.
            try:
                with SessionLocal() as db:
                    cleanup(db)
                    db.commit()
            except Exception:
                pass
            continue
        try:
            record_diagnostic(diagnostic)
        finally:
            _queue.task_done()


def enqueue_diagnostic(diagnostic):
    """No wait on a database, executor backlog or full queue in a request path."""
    global _thread
    from .database import engine
    if engine.url.get_backend_name() == "sqlite" and engine.url.database in (None, "", ":memory:"):
        # Disposable single-connection databases cannot support a reporter thread.
        return record_diagnostic(diagnostic)
    with _lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_consume, name="cats-diagnostics", daemon=True)
            _thread.start()
    try:
        _queue.put_nowait(sanitize(diagnostic))
        return True
    except Full:
        logger.warning("diagnostic_queue_full error_id=%s", diagnostic.get("error_id", "unknown"))
        return False
