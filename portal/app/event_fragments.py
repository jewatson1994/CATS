"""Deterministic wire representation shared by the HQ relay and external collectors."""
import base64
from datetime import timedelta
from hashlib import sha256
import json

from sqlalchemy import select, update
from sqlalchemy.orm import load_only

from .audit_forward_store import ForwardDelivery, utcnow


FRAGMENT_BYTES = 30 * 1024
FORMAT = "cats.event-fragment.v1"


def canonical_bytes(event):
    return json.dumps(event, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def send_fragments(event, content, send, *, sessions=None, destination_id=None, lease=None, metadata=None):
    """Advance a persistent lease cursor after each individual transport acknowledgment."""
    from .audit_forward_transports import DeliveryError
    from .audit_forward_worker import LEASE_SECONDS

    digest = sha256(content).hexdigest()
    count = (len(content) + FRAGMENT_BYTES - 1) // FRAGMENT_BYTES
    resume_at = 0
    if sessions is not None:
        with sessions.begin() as db:
            row = db.scalar(select(ForwardDelivery).options(load_only(
                ForwardDelivery.id, ForwardDelivery.relay_fragment_sha256, ForwardDelivery.relay_fragment_next)).where(
                ForwardDelivery.destination_id == destination_id, ForwardDelivery.event_id == event["event_id"],
                ForwardDelivery.lease_token == lease, ForwardDelivery.delivered_at.is_(None)).with_for_update())
            if not lease or row is None:
                raise DeliveryError("Audit fragment transfer no longer has an active lease")
            if row.relay_fragment_sha256 != digest:
                row.relay_fragment_sha256, row.relay_fragment_next = digest, 0
            delivery_id, resume_at = row.id, row.relay_fragment_next
    for index in range(resume_at, count):
        start = index * FRAGMENT_BYTES
        fragment_id = f"fragment:{digest}:{index}"
        fragment = {"category": event["category"], "timestamp": event["timestamp"], "event_id": fragment_id,
                    "data": {"format": FORMAT, "original_event_id": event["event_id"],
                             "sha256": digest, "index": index, "count": count,
                             "content_b64": base64.b64encode(content[start:start + FRAGMENT_BYTES]).decode("ascii")}}
        if metadata:
            fragment["data"].update(metadata)
        send(fragment)
        if sessions is not None:
            with sessions.begin() as db:
                advanced = db.execute(update(ForwardDelivery).where(
                    ForwardDelivery.id == delivery_id, ForwardDelivery.lease_token == lease,
                    ForwardDelivery.relay_fragment_sha256 == digest, ForwardDelivery.relay_fragment_next == index,
                ).values(relay_fragment_next=index + 1, available_at=utcnow() + timedelta(seconds=LEASE_SECONDS)))
                if advanced.rowcount != 1:
                    raise DeliveryError("Audit fragment transfer was reclaimed")
