"""Outbox acceptance against SQLite and an optional disposable PostgreSQL schema."""
from datetime import timedelta
import os
import uuid

import pytest
from sqlalchemy import create_engine, delete, func, insert, select, text
from sqlalchemy.orm import sessionmaker

from app.audit_forward_store import (
    ComponentOperationalEvent, ForwardDelivery, ForwardDestination, backfill_page,
    delete_destination, maintain_operational_logs, pending_count, queue_test,
    record_operational_log, request_backfill, upgrade_connection, utcnow,
)
from app.audit_forward_worker import LEASE_SECONDS, claim_one, deliver_one, finish, prune_receipts
from app.diagnostic_store import DiagnosticEvent
from app.models import AuditEvent, User


@pytest.fixture(params=["sqlite", "postgresql"])
def sessions(request, tmp_path):
    admin = None
    if request.param == "postgresql":
        url = os.getenv("CATS_TEST_POSTGRES_URL")
        if not url:
            pytest.skip("Requires a disposable CATS_TEST_POSTGRES_URL")
        assert url.startswith("postgresql")
        schema = "cats_forward_" + uuid.uuid4().hex
        admin = create_engine(url)
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    try:
        with engine.begin() as connection:
            for model in (User, AuditEvent, DiagnosticEvent):
                model.__table__.create(connection)
            upgrade_connection(connection)
            upgrade_connection(connection)
        yield sessionmaker(bind=engine, expire_on_commit=False)
    finally:
        engine.dispose()
        if admin is not None:
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()


def destination(db, name="collector", **options):
    row = ForwardDestination(name=name, kind="syslog", config={"name": name}, enabled=True, **options)
    db.add(row)
    db.flush()
    return row


def audit(db, action, **values):
    db.execute(insert(AuditEvent.__table__).values(action=action, target_type="service", **values))


def test_transactional_capture_filters_and_redaction(sessions):
    with sessions.begin() as db:
        dest = destination(db)
        diag = destination(db, "operations", include_audit=False, include_diagnostics=True)
        user = User(username="admin", display_name="CATS Admin")
        db.add(user)
        db.flush()
    with sessions() as db:
        audit(db, "rolled-back")
        assert pending_count(db, dest.id) == 1
        db.rollback()
    with sessions.begin() as db:
        assert pending_count(db, dest.id) == 0
        decisions = [{"authorization_source": "local_override", "digest": str(i)} for i in range(80)]
        audit(db, "oci.pull", actor_user_id=user.id,
              detail={"decisions": decisions, "client_secret": "never-export", "long": "a" * 6000})
        db.add(DiagnosticEvent(error_id="d1", correlation_id="c1", timestamp=utcnow(),
            component="portal", operation="scan", code="x", severity="error", summary="failed",
            diagnostic={"error_id": "d1", "message": "failed"}))
    sent = []
    while deliver_one(sessions, lambda *args: sent.append(args[-1])):
        pass
    assert [e["category"] for e in sent] == ["audit", "diagnostic"]
    assert sent[0]["data"]["actor_username"] == "admin"
    assert sent[0]["data"]["actor_display_name"] == "CATS Admin"
    detail = sent[0]["data"]["detail"]
    assert detail["client_secret"] == "[REDACTED]" and detail["decisions"] == decisions
    assert len(detail["long"]) == 6000 and sent[0]["timestamp"].endswith("Z")
    with sessions.begin() as db:
        assert pending_count(db, diag.id) == pending_count(db, dest.id) == 0
        receipt = db.scalar(select(ForwardDelivery))
        assert receipt.payload is None and receipt.delivered_at is not None
        db.execute(delete(AuditEvent))
        prune_receipts(db)
        assert db.scalar(select(func.count()).select_from(ForwardDelivery)) == 0


def test_destination_independence_failure_recovery_after_source_pruning(sessions):
    from app.audit_forward_transports import DeliveryError
    now = utcnow()
    calls = []
    def sender(kind, config, secret, event):
        calls.append((config["name"], event["event_id"]))
        if config["name"] == "down" and len(calls) == 1:
            raise DeliveryError("Connection failed")
    with sessions.begin() as db:
        offline = destination(db, "down")
        destination(db, "up")
        audit(db, "permission.granted", target_id="123")
        db.execute(delete(AuditEvent))
    assert deliver_one(sessions, sender, lambda: now)
    assert deliver_one(sessions, sender, lambda: now)
    assert not deliver_one(sessions, sender, lambda: now)
    with sessions() as db:
        prune_receipts(db)
        assert pending_count(db, offline.id) == 1
        assert db.get(ForwardDestination, offline.id).last_error == "Connection failed"
    assert deliver_one(sessions, sender, lambda: now + timedelta(hours=1))
    assert [name for name, _ in calls] == ["down", "up", "down"]
    assert len({id_ for _, id_ in calls}) == 1


def test_test_delivery_delete_confirmation_and_stale_lease(sessions):
    with sessions.begin() as db:
        dest = destination(db)
        dest.enabled = False
        event_id = queue_test(db, dest)
    now = utcnow()
    with sessions.begin() as db:
        lost = claim_one(db, now)
        assert lost.event["event_id"] == event_id
    with sessions.begin() as db:
        assert claim_one(db, now) is None
        with pytest.raises(ValueError, match="active delivery"):
            delete_destination(db, db.get(ForwardDestination, dest.id), discard_count=1)
    later = now + timedelta(seconds=LEASE_SECONDS + 1)
    with sessions.begin() as db:
        other = claim_one(db, later)
        assert other.lease != lost.lease
        finish(db, lost, None, later)
        assert pending_count(db, dest.id) == 1
        finish(db, other, None, later)
    with sessions.begin() as db:
        dest = db.get(ForwardDestination, dest.id)
        queue_test(db, dest)
        db.flush()
        with pytest.raises(ValueError, match="current count"):
            delete_destination(db, dest, discard_count=2)
        delete_destination(db, dest, discard_count=1)


def test_replay_reuses_live_event_ids_and_never_resends_receipts(sessions):
    with sessions.begin() as db:
        audit(db, "old")
        dest = destination(db)
        audit(db, "live")
        request_backfill(db, dest)
    sent = []
    def sender(kind, config, secret, event):
        sent.append(event["data"]["action"])
    assert deliver_one(sessions, sender)
    with sessions.begin() as db:
        assert backfill_page(db, batch_size=1)
        audit(db, "newer")
    with sessions.begin() as db:
        assert backfill_page(db, batch_size=1)
        request_backfill(db, db.get(ForwardDestination, dest.id))
    with sessions.begin() as db:
        assert backfill_page(db)
    while deliver_one(sessions, sender):
        pass
    assert sorted(sent) == ["live", "newer", "old"]


def test_postgres_reversed_commit_order_and_parallel_claims(sessions):
    if sessions.kw["bind"].dialect.name != "postgresql":
        pytest.skip("Requires concurrent PostgreSQL writers")
    with sessions.begin() as db:
        destination(db)
    with sessions() as first:
        audit(first, "uncommitted")
        with sessions.begin() as second:
            audit(second, "committed")
        now = utcnow()
        with sessions.begin() as worker_a:
            visible = claim_one(worker_a, now)
            assert visible.event["data"]["action"] == "committed"
            with sessions.begin() as worker_b:
                assert claim_one(worker_b, now) is None
        first.commit()
    with sessions.begin() as worker:
        finish(worker, visible, None, now)
    with sessions.begin() as worker:
        assert claim_one(worker, now).event["data"]["action"] == "uncommitted"


def test_separate_operational_channel_source_binding_retention_and_overflow(sessions):
    now = utcnow()
    def log(db, seq, *, source_id="host-A"):
        record_operational_log(db, source_id=source_id, source_name="scan-worker", event={
            "category": "operational", "event_id": str(seq), "timestamp": now.isoformat(),
            "data": {"message": f"log {seq}", "token": "sensitive", "source_id": "untrusted-reporter-label"},
        })
    with sessions.begin() as db:
        audit_only = destination(db, "security")
        ops = destination(db, "ops", include_audit=True, include_operational=True)
        diag = destination(db, "diagnostic", include_audit=False, include_diagnostics=True)
        for seq in range(4):
            log(db, seq)
        log(db, 3)
        log(db, 3, source_id="host-B")
        audit(db, "security.audit")
    with sessions.begin() as db:
        assert pending_count(db, audit_only.id) == 1 and pending_count(db, diag.id) == 0
        assert pending_count(db, ops.id) == 6
        maintain_operational_logs(db, now, history_days=7, history_limit=1, pending_limit=2)
        assert db.scalar(select(func.count()).select_from(ComponentOperationalEvent)) == 1
        assert pending_count(db, ops.id) == 3
        assert db.get(ForwardDestination, ops.id).dropped_operational == 3
        assert db.get(ForwardDestination, ops.id).last_operational_drop_at is not None
    sent = []
    while deliver_one(sessions, lambda *args: sent.append(args[-1])):
        pass
    ops_data = [event["data"] for event in sent if event["category"] == "operational"]
    assert {entry["source_id"] for entry in ops_data} == {"host-A", "host-B"}
    assert all(entry["reported"]["token"] == "[REDACTED]" and
               entry["source_name"] == "scan-worker" and entry["event_id"] == "3" for entry in ops_data)
    assert sum(event["category"] == "audit" for event in sent) == 2


def test_only_hq_forwards_external_and_replicas_use_internal_portal_transport(sessions, monkeypatch):
    with sessions.begin() as db:
        external = destination(db)
        internal = ForwardDestination(name="HQ", kind="portal", config={}, enabled=True,
                                      include_audit=True, include_operational=True)
        db.add(internal)
        db.flush()
        audit(db, "event.at.site")
        queue_test(db, external)
        queue_test(db, internal)
    sent = []
    def sender(kind, config, secret, event):
        sent.append(kind)
    monkeypatch.setenv("CATS_MODE", "replica")
    with pytest.raises(RuntimeError, match="External forwarding"):
        deliver_one(sessions, sender)
    with pytest.raises(RuntimeError, match="authenticated HQ"):
        deliver_one(sessions, portal_only=True)
    while deliver_one(sessions, sender, portal_only=True):
        pass
    assert sent == ["portal", "portal"]
    monkeypatch.setenv("CATS_MODE", "full")
    with pytest.raises(RuntimeError, match="External forwarding"):
        deliver_one(sessions, sender, portal_only=True)
    while deliver_one(sessions, sender):
        pass
    assert sent == ["portal", "portal", "syslog", "syslog"]
