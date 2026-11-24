"""Two installations, the real authenticated HQ intake, and a lost acknowledgement."""
from datetime import timedelta
import json
from urllib.parse import urlsplit

from sqlalchemy import select

from app import replica_audit_reporter
from app.audit_forward_store import (
    ComponentOperationalEvent, ForwardDestination, record_operational_log, upgrade_connection, utcnow,
)
from app.audit_forward_transports import DeliveryError
from app.audit_forward_worker import deliver_one
from app.models import AuditEvent
from test_audit_forward_store import audit, sessions
from test_component_log_ingest import enroll, site


def test_replica_retries_through_hq_then_hq_fans_out_once(sessions, site, monkeypatch):
    client, hq, _ = site
    source, headers = enroll(client, name="Replica North", allow_audit=True, allow_diagnostics=True)
    with hq.begin() as db:
        for kind in ("syslog", "splunk"):
            db.add(ForwardDestination(name=kind, kind=kind, config={}, enabled=True,
                                      include_audit=True, include_operational=True))

    now = utcnow()
    monkeypatch.setenv("CATS_MODE", "replica")
    with sessions.begin() as db:
        upgrade_connection(db.connection())
        audit(db, "role.changed", detail={"token": "secret-to-redact"})
        record_operational_log(db, source_id="compose:proxy", source_name="OCI proxy", event={
            "event_id": "proxy:123", "category": "operational", "timestamp": now,
            "data": {"message": "pull completed"},
        })
    statuses = []
    def post_to_hq(operation, url, body, request_headers, ca):
        # Each installation has a different role in production. Scope the ASGI
        # request's environment here because the two apps share a test process.
        with monkeypatch.context() as remote:
            remote.setenv("CATS_MODE", "full")
            response = client.post(urlsplit(url).path, content=body, headers=request_headers)
        response.raise_for_status()
        ack = response.json()
        statuses.append(ack["status"])
        if len(statuses) == 1:
            raise DeliveryError("Acknowledgement lost in transit")
        return ack
    monkeypatch.setattr(replica_audit_reporter, "_post", post_to_hq)
    upstream = replica_audit_reporter.relay_sender({
        "CATS_AUDIT_HQ_URL": "https://hq.test", "CATS_AUDIT_HQ_TOKEN": headers["Authorization"][7:],
    })
    assert deliver_one(sessions, upstream, lambda: now, portal_only=True)
    while deliver_one(sessions, upstream, lambda: now + timedelta(hours=1), portal_only=True):
        pass
    assert statuses == ["accepted", "duplicate", "accepted"]

    monkeypatch.setenv("CATS_MODE", "full")
    with hq() as db:
        audit_row = db.scalars(select(AuditEvent).where(AuditEvent.action == "component.reported_audit")).one()
        ops_row = db.scalars(select(ComponentOperationalEvent)).one()
        assert audit_row.target_id == ops_row.source_id == "enrolled:" + source
        assert audit_row.detail["reported"]["action"] == "role.changed"
        assert ops_row.source_name == "Replica North"
        assert ops_row.data["source_name"] == "OCI proxy"
        assert ops_row.data["reported"]["message"] == "pull completed"
    received = {"syslog": [], "splunk": []}
    while deliver_one(hq, lambda kind, cfg, token, event: received[kind].append(event)):
        pass
    assert received["syslog"] == received["splunk"]
    assert sorted(item["category"] for item in received["syslog"]) == ["audit", "operational"]
    assert "secret-to-redact" not in json.dumps(received)
