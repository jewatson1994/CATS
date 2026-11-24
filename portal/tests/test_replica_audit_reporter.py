import base64
from datetime import timedelta
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, func, select

from app import replica_audit_reporter as reporter
from app.audit_forward_store import (
    ForwardDestination, backfill_page, pending_count, record_operational_log, upgrade_connection, utcnow,
)
from app.audit_forward_transports import DeliveryError
from app.audit_forward_worker import deliver_one
from app.diagnostic_store import DiagnosticEvent
from app.diagnostics import redact_audit_value
from app.models import AuditEvent
from test_audit_forward_store import audit, destination, sessions
from test_component_log_ingest import PATH, enroll, site


def test_replica_captures_prior_audit_and_each_new_category_before_enrollment(sessions, monkeypatch):
    with sessions.begin() as db:
        legacy = destination(db, "old syslog target")
        audit(db, "prior")
        db.execute(delete(AuditEvent).where(AuditEvent.action == "prior"))
        legacy.enabled = False
        db.flush()
        audit(db, "retained")
    monkeypatch.setenv("CATS_MODE", "replica")
    with sessions.begin() as db:
        upgrade_connection(db.connection())
        upgrade_connection(db.connection())
        assert not db.get(ForwardDestination, legacy.id).enabled
        audit(db, "new")
        db.add(DiagnosticEvent(error_id="diag1", correlation_id="c", timestamp=utcnow(), component="replica",
            operation="sync", code="ERR", severity="error", summary="failure", diagnostic={"summary": "failure"}))
        record_operational_log(db, source_id="compose:db", source_name="db", event={
            "event_id": "log1", "category": "operational", "timestamp": utcnow(), "data": {"message": "example"},
        })
        assert backfill_page(db, portal_only=True)
    sent = []
    with pytest.raises(RuntimeError):
        deliver_one(sessions, lambda *args: pytest.fail("Replica attempted third-party forwarding"))
    while deliver_one(sessions, lambda kind, cfg, secret, event: sent.append((kind, event)), portal_only=True):
        pass
    assert {kind for kind, _ in sent} == {"portal"}
    assert sorted(event["category"] for _, event in sent) == ["audit", "audit", "audit", "diagnostic", "operational"]
    assert sorted(event["data"]["action"] for _, event in sent if event["category"] == "audit") == ["new", "prior", "retained"]
    assert len({event["event_id"] for _, event in sent}) == 5
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(ForwardDestination)) == 2
        assert pending_count(db, reporter.RELAY_ID) == 0
        assert pending_count(db, legacy.id) == 1


def test_hq_acknowledgement_and_pinned_origin(monkeypatch):
    send = reporter.relay_sender({"CATS_AUDIT_HQ_URL": "https://hq.test:8443/", "CATS_AUDIT_HQ_TOKEN": "private-test"})
    event = {"event_id": "event:123", "timestamp": utcnow().isoformat(), "category": "audit", "data": {}}
    response = {}
    def post(operation, url, body, headers, ca):
        assert url == "https://hq.test:8443/api/v1/component-logs/events"
        assert headers["Authorization"] == "Bearer private-test"
        assert json.loads(body) == event
        return response
    monkeypatch.setattr(reporter, "_post", post)
    for status in ("accepted", "duplicate"):
        response.update(status=status, event_id=event["event_id"])
        send("portal", {"url": "https://unexpected.test"}, "", event)
    response["event_id"] = "another-id"
    with pytest.raises(DeliveryError):
        send("portal", {}, "", event)
    with pytest.raises(DeliveryError):
        send("splunk", {}, "", event)


def test_large_event_resumes_after_lost_ack_and_reconstructs_redacted_audit(sessions, site, monkeypatch):
    client, hq, _ = site
    source_id, credentials = enroll(client, allow_audit=True)
    monkeypatch.setenv("CATS_MODE", "replica")
    with sessions.begin() as db:
        upgrade_connection(db.connection())
        audit(db, "many.components", detail={"components": ["worker Ω" * 150] * 1000, "password": "unsafe"})
    attempts = []
    def post(operation, url, body, headers, ca):
        assert len(body) < 65507
        event = json.loads(body)
        index = event["data"]["index"]
        attempts.append(index)
        with monkeypatch.context() as remote:
            remote.setenv("CATS_MODE", "full")
            result = client.post(PATH, content=body, headers=headers)
        assert result.status_code == 200, result.text
        ack = result.json()
        if index == 1 and ack["status"] == "accepted":
            raise DeliveryError("HQ acknowledgment lost")
        return ack
    monkeypatch.setattr(reporter, "_post", post)
    send = reporter.relay_sender({"CATS_AUDIT_HQ_URL": "https://hq.test",
                                  "CATS_AUDIT_HQ_TOKEN": credentials["Authorization"][7:]}, sessions=sessions)
    now = utcnow()
    assert deliver_one(sessions, send, lambda: now, portal_only=True)
    with sessions() as db:
        assert pending_count(db, reporter.RELAY_ID) == 1
    assert attempts == [0, 1]
    assert deliver_one(sessions, send, lambda: now + timedelta(minutes=1), portal_only=True)
    with hq() as db:
        rows = db.scalars(select(AuditEvent).where(AuditEvent.target_id == "enrolled:" + source_id,
                                                    AuditEvent.action == "component.reported_audit")).all()
        parts = [row.detail["reported"] for row in rows]
    captured = {part["index"]: part for part in parts}
    count = captured[0]["count"]
    assert len(parts) == len(captured) == count
    assert attempts == [0, 1, *range(1, count)]
    raw = b"".join(base64.b64decode(captured[i]["content_b64"], validate=True) for i in range(count))
    assert captured[0]["sha256"] == sha256(raw).hexdigest()
    original = json.loads(raw)
    assert original["event_id"] == captured[0]["original_event_id"]
    assert original["data"]["detail"]["password"] == "[REDACTED]"
    assert original["data"]["detail"]["components"] == ["worker Ω" * 150] * 1000
    with sessions() as db:
        assert pending_count(db, reporter.RELAY_ID) == 0


def test_redaction_handles_large_alphanumeric_fields_with_embedded_urls():
    prefix = "B" * 500000
    suffix = "https://example.test?q=secret"
    data = prefix + " (CuStOm://user:pass@hq/path) " + suffix
    assert redact_audit_value(data) == prefix + " (CuStOm://[REDACTED]@hq/path) https://example.test?[REDACTED QUERY]"


@pytest.mark.parametrize("url", ["http://hq.test", "https://user:secret@hq.test", "https://hq.test/splunk", "https://hq.test/?q=1"])
def test_rejects_non_hq_origins(url):
    with pytest.raises(ValueError):
        reporter.relay_sender({"CATS_AUDIT_HQ_URL": url, "CATS_AUDIT_HQ_TOKEN": "private-test"})
    assert reporter.relay_sender({}) is None


def test_only_replica_global_admins_see_status(sessions, monkeypatch):
    admin = SimpleNamespace(can_manage_group=lambda group: group is None, has=lambda scope: scope == "audit.view")
    with sessions.begin() as db:
        with pytest.raises(HTTPException) as exc:
            reporter.relay_status(admin, db)
        assert exc.value.status_code == 404
        monkeypatch.setenv("CATS_MODE", "replica")
        upgrade_connection(db.connection())
        assert reporter.relay_status(admin, db)["state"] == "unconfigured"
        scoped = SimpleNamespace(can_manage_group=lambda group: False, has=lambda scope: True)
        with pytest.raises(HTTPException) as exc:
            reporter.relay_status(scoped, db)
        assert exc.value.status_code == 403
