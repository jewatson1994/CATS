"""Source-bound component log intake at HQ, including committed-retry receipts."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
import secrets
import time
import uuid

from anyio import fail_after
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import Boolean, DateTime, Integer, String, case, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column
from starlette.concurrency import run_in_threadpool

from .audit_forward_routes import administrator, authorize_change
from .auth import record_audit, token_hash
from .database import Base, get_db
from .diagnostic_store import DiagnosticEvent, cleanup as clean_diagnostics
from .diagnostics import redact_audit_value
from .models import AuditEvent
from .operating_mode import is_replica

router = APIRouter(tags=["component logs"])
SOURCES = "/api/admin/log-forwarding/sources"
MAX_EVENT_BYTES = 1024 * 1024
MAX_EVENTS_PER_MINUTE = 6000
MAX_BYTES_PER_MINUTE = 64 * 1024 * 1024
_CATEGORIES = {"audit", "diagnostic", "operational"}
_TOKEN_PATTERN = re.compile(r"Bearer (cats-log-[A-Za-z0-9_-]{43})", re.ASCII | re.IGNORECASE)


def utcnow():
    return datetime.now(timezone.utc)


class ComponentLogSource(Base):
    __tablename__ = "component_log_sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    token_digest: Mapped[str | None] = mapped_column(String(64), unique=True)
    allow_audit: Mapped[bool] = mapped_column(Boolean)
    allow_diagnostics: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rate_minute: Mapped[int] = mapped_column(Integer, default=0)
    rate_count: Mapped[int] = mapped_column(Integer, default=0)
    rate_bytes: Mapped[int] = mapped_column(Integer, default=0)


class ComponentLogReceipt(Base):
    __tablename__ = "component_log_receipts"
    source_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    content_digest: Mapped[str] = mapped_column(String(64))
    diagnostic_id: Mapped[str | None] = mapped_column(String(32), index=True)


def upgrade_connection(connection):
    for model in (ComponentLogSource, ComponentLogReceipt):
        model.__table__.create(connection, checkfirst=True)
    # Operational/diagnostic receipt retention follows the corresponding HQ record.
    for table, predicate in (
        ("component_operational_events", "source_id = OLD.source_id AND event_id = OLD.event_id"),
        ("diagnostic_events", "diagnostic_id = OLD.error_id"),
    ):
        name = "cats_clean_receipt_" + table
        deletion = f"DELETE FROM component_log_receipts WHERE {predicate}"
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql(f"CREATE TRIGGER IF NOT EXISTS {name} AFTER DELETE ON {table} BEGIN {deletion}; END")
        else:
            connection.exec_driver_sql(f"""CREATE OR REPLACE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql
                AS $fn$ BEGIN {deletion}; RETURN OLD; END; $fn$""")
            connection.exec_driver_sql(f"""DO $fn$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = '{table}'::regclass AND tgname = '{name}') THEN
                    CREATE TRIGGER {name} AFTER DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION {name}();
                END IF; END; $fn$""")


def _plain_json(obj, depth=0):
    if depth > 32:
        raise HTTPException(422, "Component log exceeds the nesting limit")
    if isinstance(obj, str) and "\0" in obj:
        raise HTTPException(422, "Component log contains an invalid character")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str) or "\0" in key:
                raise HTTPException(422, "Invalid component log field")
            _plain_json(value, depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            _plain_json(value, depth + 1)


def record_component_event(db: Session, source_id: str, source_name: str, event: dict) -> str:
    """Record one event from a verified caller. The caller owns commit and rollback."""
    if not source_id or len(source_id) > 100 or not source_name or len(source_name) > 160:
        raise ValueError("Invalid authenticated component identity")
    if not isinstance(event, dict) or set(event) != {"event_id", "timestamp", "category", "data"}:
        raise HTTPException(422, "Expected event_id, timestamp, category and data")
    event_id, category, data = event["event_id"], event["category"], event["data"]
    if not isinstance(event_id, str) or not re.fullmatch(r"[!-~][ -~]{0,199}", event_id):
        raise HTTPException(422, "Supply a printable component event identifier")
    if not isinstance(category, str) or category not in _CATEGORIES or not isinstance(data, dict):
        raise HTTPException(422, "Invalid component event category or data")
    try:
        occurred = datetime.fromisoformat(event["timestamp"])
        if occurred.tzinfo is None:
            raise ValueError
        occurred = occurred.astimezone(timezone.utc)
        stamp = occurred.isoformat().replace("+00:00", "Z")
        _plain_json(data)
        normalized = {**event, "timestamp": stamp}
        canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        raise HTTPException(422, "Supply a timezone-aware timestamp and UTF-8 JSON data") from None
    if len(canonical) > MAX_EVENT_BYTES:
        raise HTTPException(413, "Component log exceeds the 1 MiB event limit")
    digest = sha256(canonical).hexdigest()
    error_id = uuid.uuid4().hex if category == "diagnostic" else None
    insert = postgres_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    won = db.scalar(insert(ComponentLogReceipt).values(source_id=source_id, event_id=event_id,
        content_digest=digest, diagnostic_id=error_id).on_conflict_do_nothing(
            index_elements=["source_id", "event_id"]).returning(ComponentLogReceipt.event_id))
    if won is None:
        previous = db.get(ComponentLogReceipt, (source_id, event_id))
        if previous is None:
            raise HTTPException(503, "Component record retention changed during intake. Retry the event.",
                                headers={"Retry-After": "1"})
        if previous.content_digest != digest:
            raise HTTPException(409, "The source event ID was already used with different contents")
        return "duplicate"
    if category == "operational":
        from .audit_forward_store import record_operational_log
        record_operational_log(db, source_id=source_id, source_name=source_name, event=normalized)
    else:
        safe_data = redact_audit_value(data)
        report = {"source_id": source_id, "source_name": source_name, "source_event_id": event_id,
                  "source_timestamp": stamp, "reported": safe_data}
        if category == "audit":
            db.add(AuditEvent(action="component.reported_audit", target_type="component_log_source",
                              target_id=source_id, detail=report))
        else:
            received = utcnow()
            # Keep remote identifiers and actor claims out of local service/identity fields.
            summary = str(safe_data.get("summary") or "Component reported a diagnostic event")[:1024]
            severity = "warning" if safe_data.get("severity") == "warning" else "error"
            diagnostic = {"schema_version": 1, "error_id": error_id, "correlation_id": error_id,
                          "timestamp": received.isoformat(), "component": source_name, "operation": "component.report",
                          "code": "CAT-COMPONENT-REPORT", "severity": severity, "summary": summary,
                          "resolution": [], "resource": {}, "context": {}, "technical": report}
            db.add(DiagnosticEvent(error_id=error_id, correlation_id=error_id, timestamp=received, component=source_name,
                                   operation=diagnostic["operation"], code=diagnostic["code"], severity=severity,
                                   summary=summary, diagnostic=diagnostic))
            db.flush()
            clean_diagnostics(db)
    return "accepted"


async def _read_object(request, limit):
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise HTTPException(413, "Component log request is too large")
        data.extend(chunk)
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(422, "Supply a valid JSON object") from None
    if not isinstance(value, dict):
        raise HTTPException(422, "Supply a valid JSON object")
    return value, len(data)


def _credential(db, digest):
    source = db.scalar(select(ComponentLogSource.id).where(ComponentLogSource.token_digest == digest))
    if source is None:
        raise HTTPException(401, "Invalid component log credential")
    return source


def _authorize_upload(db, digest):
    _credential(db, digest)
    # Slow uploaders must not retain a DB connection or block revocation.
    db.rollback()


def _accept(db, digest, event, size):
    minute = int(time.time() // 60)
    new_window = ComponentLogSource.rate_minute != minute
    # This write acquires the same lock as revoke/rotate, including on SQLite.
    source = db.scalar(update(ComponentLogSource).where(ComponentLogSource.token_digest == digest,
        or_(new_window, ComponentLogSource.rate_count < MAX_EVENTS_PER_MINUTE),
        or_(new_window, ComponentLogSource.rate_bytes <= MAX_BYTES_PER_MINUTE - size)).values(
        rate_count=case((new_window, 1), else_=ComponentLogSource.rate_count + 1),
        rate_bytes=case((new_window, size), else_=ComponentLogSource.rate_bytes + size),
        rate_minute=minute).returning(ComponentLogSource))
    if source is None:
        _credential(db, digest)
        raise HTTPException(429, "Component source rate limit reached", headers={"Retry-After": "60"})
    category = event.get("category")
    if (category == "audit" and not source.allow_audit) or (
            category in ("diagnostic", "operational") and not source.allow_diagnostics):
        raise HTTPException(403, "This source cannot report that event category")
    status = record_component_event(db, "enrolled:" + source.id, source.name, event)
    db.commit()
    return {"status": status, "event_id": event["event_id"]}


@router.post("/api/v1/component-logs/events")
async def receive(request: Request, db=Depends(get_db)):
    # Rejected machine input must not recursively generate new diagnostic events.
    try:
        if is_replica():
            raise HTTPException(403, "Component log intake is available at HQ")
        match = _TOKEN_PATTERN.fullmatch(request.headers.get("Authorization", ""))
        if not match:
            raise HTTPException(401, "Invalid component log credential")
        digest = token_hash(match.group(1))
        await run_in_threadpool(_authorize_upload, db, digest)
        try:
            with fail_after(30):
                event, size = await _read_object(request, MAX_EVENT_BYTES)
        except TimeoutError:
            raise HTTPException(408, "Component log upload timed out") from None
        return await run_in_threadpool(_accept, db, digest, event, size)
    except HTTPException as exc:
        await run_in_threadpool(db.rollback)
        request.state.component_log_rejected = True
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


def _public(source):
    return {"id": source.id, "name": source.name, "allow_audit": source.allow_audit,
            "allow_diagnostics": source.allow_diagnostics, "revoked": source.token_digest is None,
            "created_at": source.created_at}


def _issue(db, source, auth, response, action):
    token = "cats-log-" + secrets.token_urlsafe(32)
    source.token_digest = token_hash(token)
    db.add(source)
    record_audit(db, auth, action, "component_log_source", source.id, name=source.name,
                 allow_audit=source.allow_audit, allow_diagnostics=source.allow_diagnostics)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {"source": _public(source), "token": token}


@router.get(SOURCES)
def sources(auth=Depends(administrator), db=Depends(get_db)):
    rows = db.scalars(select(ComponentLogSource).order_by(ComponentLogSource.name, ComponentLogSource.id))
    return {"sources": [_public(source) for source in rows]}


async def _enrollment(request: Request, auth=Depends(authorize_change)):
    data, _ = await _read_object(request, 4096)
    name = data.get("name")
    if (set(data) - {"name", "allow_audit", "allow_diagnostics"} or not isinstance(name, str)
            or not name.strip() or not name.isprintable() or len(name) > 160):
        raise HTTPException(422, "Supply a component name of 1 to 160 printable characters")
    audit, diagnostics = data.get("allow_audit", False), data.get("allow_diagnostics", True)
    if not isinstance(audit, bool) or not isinstance(diagnostics, bool) or not (audit or diagnostics):
        raise HTTPException(422, "Choose which records this source may submit")
    return {"name": name.strip(), "allow_audit": audit, "allow_diagnostics": diagnostics}


@router.post(SOURCES, status_code=201)
def enroll(response: Response, values=Depends(_enrollment), db=Depends(get_db), auth=Depends(authorize_change)):
    return _issue(db, ComponentLogSource(id=str(uuid.uuid4()), **values), auth, response, "log_source.enrolled")


def _source(db, source_id):
    row = db.scalar(update(ComponentLogSource).where(ComponentLogSource.id == source_id)
                    .values(name=ComponentLogSource.name).returning(ComponentLogSource))
    if row is None:
        raise HTTPException(404, "Component log source not found")
    return row


@router.post(SOURCES + "/{source_id}/rotate")
def rotate(source_id: str, response: Response, db=Depends(get_db), auth=Depends(authorize_change)):
    source = _source(db, source_id)
    if source.token_digest is None:
        raise HTTPException(409, "Enroll a new source to replace a revoked source")
    return _issue(db, source, auth, response, "log_source.rotated")


@router.post(SOURCES + "/{source_id}/revoke")
def revoke(source_id: str, db=Depends(get_db), auth=Depends(authorize_change)):
    source = _source(db, source_id)
    if source.token_digest is not None:
        source.token_digest = None
        record_audit(db, auth, "log_source.revoked", "component_log_source", source.id, name=source.name)
        db.commit()
    return {"source": _public(source)}
