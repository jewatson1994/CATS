from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import audit_forward_store as forwarding, component_log_ingest as intake
from app.auth import require_user
from app.database import Base, get_db
from app.diagnostic_http import DiagnosticMiddleware
from app.diagnostic_store import DiagnosticEvent
from app.models import AuditEvent, User


PATH = "/api/v1/component-logs/events"
CSRF = {"X-CSRF-Token": "csrf"}
EVENT = {"event_id": "native:1", "timestamp": "2026-01-01T12:30:00Z", "category": "audit",
         "data": {"actor_user_id": 99, "action": "release.approved", "password": "do-not-ship"}}


@pytest.fixture
def site(monkeypatch):
    monkeypatch.setenv("CATS_MODE", "full")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as conn:
        Base.metadata.create_all(conn, tables=[User.__table__, AuditEvent.__table__, DiagnosticEvent.__table__])
        forwarding.upgrade_connection(conn)
        intake.upgrade_connection(conn)
    factory = sessionmaker(engine)
    api = FastAPI()
    api.include_router(intake.router)
    api.add_middleware(DiagnosticMiddleware)
    auth = SimpleNamespace(user=SimpleNamespace(id=None, username="global-admin", display_name="Admin"),
        can_manage_group=lambda group: group is None, has=lambda permission: permission == "audit.view", csrf_token="csrf")
    api.dependency_overrides[require_user] = lambda: auth

    def session():
        with factory() as db:
            yield db

    api.dependency_overrides[get_db] = session
    with TestClient(api) as client:
        yield client, factory, auth
    engine.dispose()


def enroll(client, **settings):
    result = client.post(intake.SOURCES, json={"name": "Site A", **settings}, headers=CSRF)
    assert result.status_code == 201, result.text
    assert result.headers["Cache-Control"] == "no-store"
    body = result.json()
    return body["source"]["id"], {"Authorization": "Bearer " + body["token"]}


def test_source_lifecycle_bound_authority_and_revocation(site, monkeypatch):
    client, factory, auth = site
    assert client.post(intake.SOURCES, json={"name": "Site"}).status_code == 403
    source_id, headers = enroll(client)
    assert headers["Authorization"][7:] not in client.get(intake.SOURCES).text
    rejected = client.post(PATH, json=EVENT)
    assert rejected.status_code == 401 and "diagnostic" not in rejected.json()
    assert rejected.headers["X-Correlation-ID"] and "no-store" in rejected.headers["Cache-Control"]
    assert client.post(PATH, json=EVENT, headers=headers).status_code == 403
    assert client.post(PATH, json={**EVENT, "source_id": "spoof", "category": "operational"}, headers=headers).status_code == 422
    path = intake.SOURCES + "/" + source_id
    response = client.post(path + "/rotate", headers=CSRF)
    rotated = {"Authorization": "Bearer " + response.json()["token"]}
    assert client.post(PATH, json=EVENT, headers=headers).status_code == 401
    diagnostic = {**EVENT, "category": "diagnostic"}
    assert client.post(PATH, json=diagnostic, headers=rotated).json()["status"] == "accepted"
    assert client.post(path + "/revoke", headers=CSRF).json()["source"]["revoked"]
    assert client.post(PATH, json=diagnostic, headers=rotated).status_code == 401
    assert client.post(path + "/rotate", headers=CSRF).status_code == 409
    auth.can_manage_group = lambda group: False
    assert client.get(intake.SOURCES).status_code == 403
    auth.can_manage_group = lambda group: True
    monkeypatch.setenv("CATS_MODE", "replica")
    assert client.get(intake.SOURCES).status_code == 403
    assert client.post(PATH, json=EVENT, headers=rotated).status_code == 403


def test_attribution_idempotency_and_transactional_forwarding(site):
    client, factory, _ = site
    source_id, headers = enroll(client, allow_audit=True)
    with factory.begin() as db:
        db.add(forwarding.ForwardDestination(name="remote", kind="syslog", config={}, enabled=True,
            include_audit=True, include_diagnostics=True, include_operational=True))
    assert client.post(PATH, json=EVENT, headers=headers).json()["status"] == "accepted"
    assert client.post(PATH, json=EVENT, headers=headers).json()["status"] == "duplicate"
    assert client.post(PATH, json={**EVENT, "data": {}}, headers=headers).status_code == 409
    with factory() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "component.reported_audit"))
        assert event.actor_user_id is None and event.target_id == "enrolled:" + source_id
        assert event.detail["source_event_id"] == EVENT["event_id"]
        assert event.detail["reported"]["action"] == "release.approved"
        assert "do-not-ship" not in str(event.detail)
        assert db.scalar(select(func.count()).select_from(forwarding.ForwardDelivery)) == 1
    _, second_source = enroll(client, allow_audit=True)
    assert client.post(PATH, json=EVENT, headers=second_source).json()["status"] == "accepted"


def test_operational_and_diagnostic_history_bounds_and_limits(site, monkeypatch):
    client, factory, _ = site
    _, headers = enroll(client)
    for category in ("operational", "diagnostic"):
        item = {**EVENT, "category": category, "event_id": category}
        assert client.post(PATH, headers=headers, json=item).json()["status"] == "accepted"
        assert client.post(PATH, headers=headers, json=item).json()["status"] == "duplicate"
    with factory.begin() as db:
        assert db.scalar(select(func.count()).select_from(intake.ComponentLogReceipt)) == 2
        db.execute(delete(forwarding.ComponentOperationalEvent))
        db.execute(delete(DiagnosticEvent))
        assert db.scalar(select(func.count()).select_from(intake.ComponentLogReceipt)) == 0
    monkeypatch.setattr(intake, "MAX_EVENT_BYTES", 128)
    assert client.post(PATH, headers=headers, content=b"{" + b" " * 128).status_code == 413
    monkeypatch.setattr(intake, "MAX_EVENTS_PER_MINUTE", 0)
    limited = client.post(PATH, headers=headers, json={**EVENT, "data": {}, "category": "operational"})
    assert limited.status_code == 429 and "Retry-After" in limited.headers
