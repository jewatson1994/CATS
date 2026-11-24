"""Deliver queued events outside portal requests. A crash may repeat a stable event ID."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import time
import uuid

from sqlalchemy import delete, exists, or_, select, update
from sqlalchemy.orm import aliased, sessionmaker

from .audit_forward_store import (
    ForwardDelivery, ForwardDestination, backfill_page, maintain_operational_logs, operational_limits, utcnow,
)
from .database import background_engine
from .diagnostics import redact_audit_value
from .models import AuditEvent
from .operating_mode import is_replica
from .secrets import decrypt_secret


logger = logging.getLogger("cats.audit_forwarding")
BackgroundSession = sessionmaker(bind=background_engine, expire_on_commit=False)
LEASE_SECONDS = 180


@dataclass(frozen=True)
class Claim:
    id: int
    destination_id: int
    lease: str
    kind: str
    config: dict
    secret_ciphertext: str
    attempts: int
    event: dict


def claim_one(db, now, *, portal_only=False):
    delivery = ForwardDelivery
    dest = ForwardDestination
    authority = dest.kind == "portal" if portal_only else dest.kind != "portal"
    active = aliased(ForwardDelivery)
    due = or_(delivery.available_at.is_(None), delivery.available_at <= now)
    idle = ~exists(select(active.id).where(active.destination_id == dest.id,
                          active.lease_token.is_not(None), active.available_at > now)).correlate(dest)
    # Test messages can run for disabled destinations. Use their dedicated index
    # instead of sorting every pending audit event to prioritize a rare test.
    item = db.execute(select(delivery.id, dest).join(dest, dest.id == delivery.destination_id)
        .where(authority, delivery.category == "test", delivery.delivered_at.is_(None), due, idle)
        .order_by(delivery.id).limit(1)
        .with_for_update(skip_locked=True, of=dest, key_share=True)).first()
    if item is None:
        # Look up one indexed item per eligible destination. This avoids scanning
        # a failed collector's backlog when other collectors are healthy.
        oldest = select(delivery.id).where(delivery.destination_id == dest.id,
                 delivery.delivered_at.is_(None), due).order_by(delivery.id).limit(1).correlate(dest).scalar_subquery()
        item = db.execute(select(oldest, dest).where(authority, dest.enabled.is_(True), idle,
            or_(dest.retry_at.is_(None), dest.retry_at <= now), oldest.is_not(None))
            .order_by(oldest).limit(1).with_for_update(skip_locked=True, of=dest, key_share=True)).first()
        if item is None:
            return None
    row_id, destination = item
    row = db.get(delivery, row_id)
    if row is None:
        return None
    lease = str(uuid.uuid4())
    locked = db.execute(update(delivery).where(delivery.id == row.id, due,
                        delivery.delivered_at.is_(None)).values(lease_token=lease,
                        available_at=now + timedelta(seconds=LEASE_SECONDS),
                        attempts=delivery.attempts + 1).execution_options(synchronize_session=False))
    if locked.rowcount != 1:
        return None
    timestamp = datetime.fromisoformat(row.timestamp.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    event = {"event_id": row.event_id, "category": row.category,
             "timestamp": timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
             "data": row.payload}
    return Claim(row.id, destination.id, lease, destination.kind, destination.config,
                 destination.secret_ciphertext, row.attempts + 1, event)


def finish(db, claim, error, now):
    # Lock in the same order as claiming/deleting. An expired lease cannot overwrite
    # progress after another process has reclaimed the delivery.
    dest = db.scalar(select(ForwardDestination).where(ForwardDestination.id == claim.destination_id)
                     .with_for_update(key_share=True))
    row = db.scalar(select(ForwardDelivery).where(ForwardDelivery.id == claim.id,
                    ForwardDelivery.lease_token == claim.lease).with_for_update())
    if dest is None or row is None:
        return
    if error is not None:
        delay = min(3600, 2 ** min(claim.attempts, 12))
        row.available_at = now + timedelta(seconds=delay)
        row.lease_token = None
        dest.last_error = error
        dest.last_error_at = now
        dest.retry_at = now + timedelta(seconds=min(delay, 60))
        return
    dest.last_success_at = now
    dest.last_error = None
    dest.last_error_at = None
    dest.retry_at = None
    if row.category == "audit":
        # Keep only a small receipt while the source can still be replayed.
        row.delivered_at = now
        row.payload = row.available_at = row.lease_token = None
    else:
        db.delete(row)


def require_delivery_authority(portal_only, sender, *, deliver=True):
    if is_replica() != portal_only:
        raise RuntimeError("External forwarding runs on HQ; replicas may only report to HQ")
    if portal_only and deliver and sender is None:
        raise RuntimeError("Replica delivery requires its authenticated HQ reporting transport")


def deliver_one(session_factory=BackgroundSession, sender=None, clock=utcnow, *, portal_only=False):
    from .audit_forward_transports import DeliveryError, send_event
    require_delivery_authority(portal_only, sender)
    with session_factory.begin() as db:
        claim = claim_one(db, clock(), portal_only=portal_only)
    if claim is None:
        return False
    # Release DB locks and the connection before DNS, TLS and collector I/O.
    error = None
    try:
        event = dict(claim.event, data=redact_audit_value(claim.event["data"]))
        config = {**claim.config, "relay_lease_token": claim.lease} if portal_only else claim.config
        secret = decrypt_secret(claim.secret_ciphertext)
        if sender is None:
            send_event(claim.kind, config, secret, event, checkpoint={
                "sessions": session_factory, "destination_id": claim.destination_id, "lease": claim.lease})
        else:
            sender(claim.kind, config, secret, event)
    except DeliveryError as exc:
        # Transport creates these errors from fixed text and numeric status only.
        error = str(exc)[:300]
    except Exception as exc:
        # Libraries may embed request URLs, secrets or response bodies in errors.
        error = f"Delivery failed ({type(exc).__name__})"
    with session_factory.begin() as db:
        finish(db, claim, error, clock())
    return True


def prune_receipts(db, cursor=0):
    # Bound both reads and deletes even if every source record is retained.
    ids = db.scalars(select(ForwardDelivery.id).where(ForwardDelivery.id > cursor,
        ForwardDelivery.delivered_at.is_not(None)).order_by(ForwardDelivery.id).limit(500)).all()
    if ids:
        db.execute(delete(ForwardDelivery).where(ForwardDelivery.id.in_(ids),
            ForwardDelivery.delivered_at.is_not(None),
            ~exists(select(AuditEvent.id).where(AuditEvent.id == ForwardDelivery.source_audit_id))))
    return ids[-1] if len(ids) == 500 else 0


def run_worker(*, portal_only=False, sender=None, deliver=True):
    require_delivery_authority(portal_only, sender, deliver=deliver)
    maintenance_at = time.monotonic()
    operational_maintenance_at = maintenance_at
    limits = operational_limits()
    receipt_cursor = 0
    while True:
        try:
            more_ops = False
            with BackgroundSession.begin() as db:
                replaying = backfill_page(db, portal_only=portal_only)
                if time.monotonic() >= maintenance_at:
                    receipt_cursor = prune_receipts(db, receipt_cursor)
                    maintenance_at = time.monotonic() + (10 if receipt_cursor else 300)
                if time.monotonic() >= operational_maintenance_at:
                    more_ops = maintain_operational_logs(db, utcnow(), **limits)
                    operational_maintenance_at = time.monotonic() + (0 if more_ops else 30)
            delivered = deliver and deliver_one(sender=sender, portal_only=portal_only)
            if not delivered and not replaying and not more_ops:
                time.sleep(2)
        except Exception as exc:
            logger.warning("Audit forwarding worker retrying (%s)", type(exc).__name__)
            time.sleep(5)


def main():
    require_delivery_authority(False, None)
    from .validator_log_poll import start_validator_log_poll
    start_validator_log_poll()
    run_worker()


if __name__ == "__main__":
    main()
