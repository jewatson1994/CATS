"""Local validator journal, fetched and acknowledged over the existing HQ mTLS connection."""
from contextlib import closing
from datetime import datetime, timezone
import json
import logging
import os
import re
import sqlite3
import sys
import uuid

from fastapi import HTTPException, Request

from .validator_settings import fingerprints, state_dir
from .diagnostics import redact_audit_value


BATCH = 100


def _db():
    path = state_dir() / "component-log.sqlite3"
    if path.is_symlink():
        raise OSError("Unsafe validator log journal")
    db = sqlite3.connect(path, timeout=0.25)
    db.execute("CREATE TABLE IF NOT EXISTS entries (id TEXT NOT NULL UNIQUE, event TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS losses (count INTEGER NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS entry_category ON entries(json_extract(event,'$.category'))")
    return db


def event(category, code, **fields):
    """Callers supply fixed field names and approved values, never raw credentials or request content."""
    try:
        limit = max(100, min(100000, int(os.getenv("CATS_VALIDATOR_LOG_CAPACITY", "10000"))))
        with closing(_db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if category != "audit" and db.execute(
                    "SELECT count(*) FROM entries WHERE json_extract(event,'$.category')='operational'").fetchone()[0] >= limit:
                db.execute("INSERT INTO losses SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM losses)")
                db.execute("UPDATE losses SET count=count+1")
                return
            _insert(db, category, {"code": code, **fields})
    except (OSError, sqlite3.Error, ValueError):
        print("cats-validator: local_log_journal_unavailable", file=sys.stderr)


def _insert(db, category, data):
    identifier = str(uuid.uuid4())
    value = {"event_id": identifier, "timestamp": datetime.now(timezone.utc).isoformat(),
             "category": category, "data": redact_audit_value(data)}
    db.execute("INSERT INTO entries (id,event) VALUES (?,?)", (identifier, json.dumps(value)))


def batch():
    with closing(_db()) as db:
        return [json.loads(row[0]) for row in db.execute("SELECT event FROM entries ORDER BY rowid LIMIT ?", (BATCH,))]


def acknowledge(ids):
    if not isinstance(ids, list) or not 1 <= len(ids) <= BATCH or any(
            not isinstance(i, str) or not re.fullmatch(r"[0-9a-f-]{36}", i) for i in ids):
        raise HTTPException(422, "Invalid acknowledgment")
    with closing(_db()) as db, db:
        deleted = db.executemany("DELETE FROM entries WHERE id=?", [(i,) for i in ids]).rowcount
        loss = db.execute("SELECT count FROM losses").fetchone()
        if deleted and loss:
            _insert(db, "operational", {"code": "local_log_capacity_exceeded", "dropped": loss[0], "severity": "warning"})
            db.execute("DELETE FROM losses")


def _log_reader(request):
    trusted = {item.strip().replace(":", "").lower() for item in fingerprints().split(",") if item.strip()}
    selected = os.getenv("CATS_VALIDATOR_LOG_CLIENT_SHA256", "").strip().replace(":", "").lower()
    if not selected and len(trusted) == 1:
        selected = next(iter(trusted))
    if not selected or selected not in trusted or request.state.client_identity != selected:
        raise HTTPException(403, "The HQ log reader identity is required")


def register(app):
    @app.get("/api/v1/component-logs")
    def fetch(request: Request):
        _log_reader(request)
        return {"validator_id": os.getenv("CATS_MANAGED_VALIDATOR_ID", ""), "events": batch()}

    @app.post("/api/v1/component-logs/ack")
    async def ack(request: Request):
        _log_reader(request)
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > 8192:
                raise HTTPException(413, "Acknowledgment is too large")
            raw.extend(chunk)
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            raise HTTPException(422, "Invalid acknowledgment") from None
        acknowledge(data.get("event_ids") if isinstance(data, dict) else None)
        return {"accepted": True}


class ServerEvents(logging.Handler):
    def emit(self, record):
        if record.name.startswith(("uvicorn.access", "cats.validator.audit")):
            return
        # Do not forward exception text, HTTP paths/query strings, CLI output, or logging arguments.
        data = {"severity": record.levelname.lower(), "logger": record.name[:100]}
        # Template is operator-written. Values substituted by the logger can include untrusted request content.
        if isinstance(record.msg, str):
            data["message"] = redact_audit_value(record.msg)[:1024]
        if record.exc_info and record.exc_info[0]:
            data["exception_type"] = record.exc_info[0].__name__[:100]
        event("operational", "server_log", **data)


def attach_server_logging():
    for logger in (logging.getLogger(), logging.getLogger("uvicorn")):
        if not any(isinstance(handler, ServerEvents) for handler in logger.handlers):
            logger.addHandler(ServerEvents(level=logging.INFO))


def capture_output(stream, console, listener, channel):
    """Keep container output, and journal output bypassing the API and standard server loggers."""
    private_key = False
    with stream:
        while True:
            raw = stream.readline(16384)
            if not raw:
                return
            # Local stdout/stderr retain their production behavior. Bounded reads prevent huge-line allocations.
            text = raw.decode("utf-8", errors="replace")
            console.write(text)
            console.flush()
            if len(raw) == 16384 and not raw.endswith(b"\n"):
                while raw and not raw.endswith(b"\n"):
                    raw = stream.readline(16384)
                    console.write(raw.decode("utf-8", errors="replace"))
                event("operational", "container_line_oversize", listener=listener, stream=channel, severity="warning")
                continue
            if re.search(r"-----BEGIN [^-\n]*PRIVATE KEY-----", text):
                private_key = True
            if private_key:
                if re.search(r"-----END [^-\n]*PRIVATE KEY-----", text):
                    private_key = False
                continue
            # Uvicorn access/diagnostic logging already goes through the structured server hooks.
            if re.match(r"^(?:INFO|WARNING|ERROR|DEBUG|CRITICAL):\s", text) or "local_log_journal_unavailable" in text:
                continue
            event("operational", "container_output", listener=listener, stream=channel,
                  severity="warning" if channel == "stderr" else "info", message=redact_audit_value(text.rstrip())[:4096])


def audit_request(app, listener):
    @app.middleware("http")
    async def audit_http(request, call_next):
        try:
            response = await call_next(request)
        except Exception:
            event("operational", "request_failed", listener=listener, severity="error")
            raise
        route = request.scope.get("route")
        name = getattr(route, "name", "unmatched")
        # A successful automated collection or probe must never generate its own next log.
        if name not in ("fetch", "ack", "health", "self_test_result", "result") or response.status_code >= 400:
            category = "audit" if request.method != "GET" or response.status_code in (401, 403) else "operational"
            peer = getattr(request.state, "client_identity", None)
            actor = {"client_fingerprint": peer} if isinstance(peer, str) and re.fullmatch("[0-9a-f]{64}", peer) else {}
            event(category, "http_request", listener=listener, route=name, method=request.method[:12],
                  http_status=response.status_code, severity="warning" if response.status_code >= 400 else "info", **actor)
        return response
