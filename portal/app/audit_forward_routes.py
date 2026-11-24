"""Global administrator controls for outbound audit and diagnostic delivery."""
from datetime import timezone
from hashlib import sha256
import hmac
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .audit_forward_store import (
    ForwardDelivery, ForwardDestination, delete_destination, pending_count, queue_test, request_backfill,
)
from .audit_forward_transports import validate_config
from .auth import AuthContext, record_audit, require_user
from .database import get_db
from .secrets import encrypt_secret, secret_configured


router = APIRouter(prefix="/api/admin/log-forwarding/destinations", tags=["log forwarding"])
_RECIPIENT_FIELDS = {
    "syslog": ("host", "port", "transport"),
    "splunk": ("url", "index"),
    "azure": ("endpoint", "rule_id", "stream", "tenant_id", "client_id", "cloud"),
}


def may_manage_log_forwarding(auth):
    return bool(auth and auth.can_manage_group(None) and auth.has("audit.view"))


def administrator(auth: AuthContext = Depends(require_user)):
    if not may_manage_log_forwarding(auth):
        raise HTTPException(403, "Global configuration and audit access are required")
    return auth


def authorize_change(request: Request, auth: AuthContext = Depends(administrator)):
    token = request.headers.get("X-CSRF-Token", "")
    if not token or not hmac.compare_digest(token.encode(), auth.csrf_token.encode()):
        raise HTTPException(403, "Invalid CSRF token")
    return auth


async def destination_input(request: Request, auth=Depends(authorize_change)):
    # Parse after authorization and return field-level errors without reflecting secrets.
    buffer = bytearray()
    async for chunk in request.stream():
        if len(buffer) + len(chunk) > 131072:
            raise HTTPException(413, "Destination configuration is too large")
        buffer.extend(chunk)
    try:
        value = json.loads(buffer)
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(422, "Supply a JSON object") from None
    allowed = {"name", "kind", "config", "secret", "enabled", "audit", "diagnostics"}
    if not isinstance(value, dict) or value.keys() - allowed:
        raise HTTPException(422, "Unexpected destination fields")
    name = value.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 120 or not name.isprintable():
        raise HTTPException(422, "Supply a destination name of 1 to 120 printable characters")
    value["name"] = name.strip()
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in _RECIPIENT_FIELDS or not isinstance(value.get("config"), dict):
        raise HTTPException(422, "Supply a supported destination kind and configuration")
    for flag, default in (("enabled", False), ("audit", True), ("diagnostics", False)):
        if not isinstance(value.setdefault(flag, default), bool):
            raise HTTPException(422, f"{flag} must be true or false")
    if value["enabled"] and not (value["audit"] or value["diagnostics"]):
        raise HTTPException(422, "Select audit events or diagnostics before enabling forwarding")
    if "secret" in value:
        secret = value["secret"]
        if (kind == "syslog" or not isinstance(secret, str) or not secret.strip()
                or len(secret) > 16384 or any(ch in secret for ch in ("\r", "\n", "\0"))):
            raise HTTPException(422, "Supply a valid credential for this destination")
        try:
            secret.encode("utf-8")
        except UnicodeError:
            raise HTTPException(422, "Supply a UTF-8 credential") from None
        if kind == "splunk" and (not secret.isascii() or not secret.isprintable() or " " in secret):
            raise HTTPException(422, "Supply a valid Splunk HEC token")
    try:
        value["config"] = validate_config(kind, value["config"])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return value


def _get_locked(db, destination_id):
    row = db.scalar(select(ForwardDestination).where(ForwardDestination.id == destination_id).with_for_update())
    if row is None:
        raise HTTPException(404, "Forwarding destination not found")
    return row


def _public(row, pending):
    last_sent = row.last_success_at
    if last_sent and last_sent.tzinfo is None:
        last_sent = last_sent.replace(tzinfo=timezone.utc)
    return {
        "id": row.id, "name": row.name, "kind": row.kind, "config": row.config,
        "enabled": row.enabled, "audit": row.include_audit, "diagnostics": row.include_diagnostics,
        "has_secret": secret_configured(row.secret_ciphertext),
        "pending": pending, "last_sent_at": last_sent, "last_error": row.last_error,
        "replay_pending": row.backfill_limit is not None,
    }


def _save(db, auth, row, values, creating):
    kind, config = values["kind"], values["config"]
    if not creating and (kind != row.kind or any(
        row.config.get(field) != config.get(field) for field in _RECIPIENT_FIELDS[kind]
    )):
        raise HTTPException(409, "Create a new destination for a different recipient")
    if kind != "syslog" and "secret" not in values:
        if creating or not secret_configured(row.secret_ciphertext):
            raise HTTPException(422, "Supply the destination credential")
        if row.config.get("ca_pem") != config.get("ca_pem"):
            raise HTTPException(422, "Re-enter the destination credential when changing TLS trust")
    if "secret" in values:
        try:
            row.secret_ciphertext = encrypt_secret(values["secret"])
        except ValueError as exc:
            raise HTTPException(503, str(exc)) from None
    row.name, row.kind, row.config = values["name"], kind, config
    row.enabled, row.include_audit, row.include_diagnostics = values["enabled"], values["audit"], values["diagnostics"]
    db.add(row)
    db.flush()
    action = "log_forwarding.created" if creating else "log_forwarding.updated"
    ca = config.get("ca_pem")
    record_audit(db, auth, action, "log_destination", row.id, name=row.name, kind=kind,
                 recipient={field: config.get(field) for field in _RECIPIENT_FIELDS[kind]},
                 enabled=row.enabled, audit=row.include_audit, diagnostics=row.include_diagnostics,
                 ca_bundle_sha256=sha256(ca.encode()).hexdigest() if ca else None,
                 sourcetype=config.get("sourcetype"),
                 credential_supplied="secret" in values)
    db.commit()
    return _public(row, pending_count(db, row.id))


@router.get("")
def destinations(db: Session = Depends(get_db), auth=Depends(administrator)):
    pending = select(func.count()).select_from(ForwardDelivery).where(
        ForwardDelivery.destination_id == ForwardDestination.id, ForwardDelivery.delivered_at.is_(None)
    ).scalar_subquery()
    rows = db.execute(select(ForwardDestination, pending).order_by(ForwardDestination.id))
    return {"destinations": [_public(row, count) for row, count in rows]}


@router.post("", status_code=201)
def create(values=Depends(destination_input), db: Session = Depends(get_db), auth=Depends(authorize_change)):
    return _save(db, auth, ForwardDestination(), values, True)


@router.put("/{destination_id}")
def update(destination_id: int, values=Depends(destination_input), db: Session = Depends(get_db),
           auth=Depends(authorize_change)):
    return _save(db, auth, _get_locked(db, destination_id), values, False)


@router.delete("/{destination_id}")
def remove(destination_id: int, discard_count: int | None = Query(None, ge=0),
           db: Session = Depends(get_db), auth=Depends(authorize_change)):
    row = _get_locked(db, destination_id)
    name, kind = row.name, row.kind
    cancelled_replay = row.backfill_limit is not None
    try:
        delete_destination(db, row, discard_count=discard_count)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    record_audit(db, auth, "log_forwarding.deleted", "log_destination", destination_id,
                 name=name, kind=kind, discarded_copies=discard_count or 0, cancelled_replay=cancelled_replay)
    db.commit()
    return {"status": "removed"}


@router.post("/{destination_id}/test", status_code=202)
def test_delivery(destination_id: int, db: Session = Depends(get_db), auth=Depends(authorize_change)):
    row = _get_locked(db, destination_id)
    event_id = queue_test(db, row)
    record_audit(db, auth, "log_forwarding.test_requested", "log_destination", row.id, event_id=event_id)
    db.commit()
    return {"event_id": event_id}


@router.post("/{destination_id}/replay", status_code=202)
def replay(destination_id: int, db: Session = Depends(get_db), auth=Depends(authorize_change)):
    row = _get_locked(db, destination_id)
    if not row.enabled or not row.include_audit:
        raise HTTPException(409, "Enable audit forwarding before replaying retained events")
    try:
        request_backfill(db, row)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    record_audit(db, auth, "log_forwarding.replay_requested", "log_destination", row.id)
    db.commit()
    return {"status": "queued"}
