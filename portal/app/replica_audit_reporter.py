"""Route a replica's persistent outbox to its configured CATS HQ."""
import base64
from datetime import timezone
import logging
import os
import time

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, insert, select, text, update

from .audit_forward_store import ForwardDestination, pending_count, utcnow
from .audit_forward_transports import DeliveryError, _https, _json, _post, _tls_context
from .auth import require_user
from .database import get_db
from .models import AuditEvent
from .operating_mode import is_replica


RELAY_ID = -1
INGEST_PATH = "/api/v1/component-logs/events"
router = APIRouter()
logger = logging.getLogger("cats.replica_audit_reporter")


def install_portal_relay(connection):
    """Install once under the existing schema lock. Capture begins before enrollment."""
    table = ForwardDestination.__table__
    connection.execute(update(table).where(table.c.kind != "portal", table.c.enabled).values(enabled=False))
    existing = connection.scalar(select(table.c.kind).where(table.c.id == RELAY_ID))
    if existing is None:
        latest_audit = connection.scalar(select(func.max(AuditEvent.id))) or 0
        connection.execute(insert(table).values(
            id=RELAY_ID, name="CATS HQ", kind="portal", config={}, secret_ciphertext="",
            enabled=True, include_audit=True, include_diagnostics=True, include_operational=True,
            backfill_cursor=0, backfill_limit=latest_audit,
        ))
        # Preserve unsent events from installations with older direct destinations,
        # including captured payloads whose original local records have aged out.
        connection.execute(text("""
            INSERT INTO audit_forward_deliveries
                (destination_id, event_id, category, timestamp, source_audit_id, payload)
            SELECT :relay, event_id, category, timestamp, source_audit_id, payload
            FROM audit_forward_deliveries
            WHERE destination_id != :relay AND delivered_at IS NULL
              AND category IN ('audit', 'diagnostic', 'operational')
            ON CONFLICT (destination_id, event_id) DO NOTHING
        """), {"relay": RELAY_ID})
    elif existing != "portal":
        raise RuntimeError("Reserved HQ relay identifier is already in use")
    else:
        connection.execute(update(table).where(table.c.id == RELAY_ID).values(
            enabled=True, include_audit=True, include_diagnostics=True, include_operational=True))


def relay_sender(environment):
    """Validate the deployment-provided HTTPS origin once. No redirects or database endpoints."""
    url = environment.get("CATS_AUDIT_HQ_URL", "").strip()
    token = environment.get("CATS_AUDIT_HQ_TOKEN", "").strip()
    if not (url or token):
        return None
    parts = _https(url)
    if parts.path not in ("", "/"):
        raise ValueError("CATS_AUDIT_HQ_URL must be the HQ portal HTTPS origin")
    if not token or not token.isascii() or not all(33 <= ord(c) <= 126 for c in token):
        raise ValueError("CATS_AUDIT_HQ_TOKEN requires the HQ component source token")
    ca = None
    encoded = environment.get("CATS_AUDIT_HQ_CA_B64", "").strip()
    if encoded:
        try:
            ca = base64.b64decode(encoded, validate=True).decode("ascii")
            if not ca.strip().startswith("-----BEGIN CERTIFICATE-----") or "PRIVATE KEY" in ca:
                raise ValueError
            _tls_context(ca)
        except (ValueError, OSError) as exc:
            raise ValueError("Invalid public CA certificate in CATS_AUDIT_HQ_CA_B64") from exc
    endpoint = parts._replace(path=INGEST_PATH).geturl()

    def send(kind, config, secret, event):
        if kind != "portal" or event["category"] not in ("audit", "diagnostic", "operational"):
            raise DeliveryError("Invalid event for the HQ relay")
        ack = _post("CATS HQ", endpoint, _json(event), {
            "Authorization": "Bearer " + token, "Content-Type": "application/json",
        }, ca)
        if ack.get("event_id") != event["event_id"] or ack.get("status") not in ("accepted", "duplicate"):
            raise DeliveryError("CATS HQ did not acknowledge this event ID")
    return send


def may_view_log_relay(auth):
    return bool(is_replica() and auth and auth.can_manage_group(None) and auth.has("audit.view"))


@router.get("/api/admin/log-forwarding/relay")
def relay_status(auth=Depends(require_user), db=Depends(get_db)):
    if not is_replica():
        raise HTTPException(404, "HQ relay status is available on a replica")
    if not may_view_log_relay(auth):
        raise HTTPException(403, "Global configuration and audit access are required")
    dest = db.get(ForwardDestination, RELAY_ID)
    if dest is None:
        raise HTTPException(503, "HQ relay has not initialized")
    last_sent = dest.last_success_at
    if last_sent and last_sent.tzinfo is None:
        last_sent = last_sent.replace(tzinfo=timezone.utc)
    if not dest.config.get("configured"):
        state = "unconfigured"
    elif dest.last_error:
        state = "retrying"
    else:
        state = "active" if last_sent else "waiting"
    return {"state": state, "pending": pending_count(db, RELAY_ID), "dropped_operational": dest.dropped_operational,
            "last_sent_at": last_sent, "last_error": dest.last_error}


def main():
    from .audit_forward_worker import BackgroundSession, run_worker
    if not is_replica():
        raise RuntimeError("The HQ relay requires replica mode")
    error = None
    try:
        sender = relay_sender(os.environ)
    except ValueError as exc:
        sender = None
        error = str(exc)
    while True:
        try:
            with BackgroundSession.begin() as db:
                dest = db.get(ForwardDestination, RELAY_ID)
                if dest is None:
                    raise RuntimeError("HQ relay schema is missing")
                dest.config = {"configured": sender is not None}
                if sender is None:
                    dest.last_error = error or "Configure the HQ URL and component token on this replica"
                    dest.last_error_at = utcnow()
            break
        except Exception as exc:
            logger.warning("Waiting for HQ relay database (%s)", type(exc).__name__)
            time.sleep(5)
    if sender is None:
        logger.warning("Replica logs are queued until the HQ connection is configured")
    run_worker(portal_only=True, sender=sender, deliver=sender is not None)


if __name__ == "__main__":
    main()
