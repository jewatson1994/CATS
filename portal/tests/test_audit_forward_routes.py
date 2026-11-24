"""API-level contracts for sending privileged audit data outside the portal."""
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.audit_forward_routes import router
from app.audit_forward_store import ForwardDestination, upgrade_connection
from app.auth import require_user
from app.database import Base, get_db
from app.diagnostic_store import DiagnosticEvent
from app.models import AuditEvent, User
from app.secrets import decrypt_secret


PATH = "/api/admin/log-forwarding/destinations"
HEADERS = {"X-CSRF-Token": "test-csrf"}
SYSLOG = {"name": "Collector", "kind": "syslog", "config": {"host": "syslog.example"}}


@pytest.fixture
def setup(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as connection:
        Base.metadata.create_all(connection, tables=[User.__table__, AuditEvent.__table__, DiagnosticEvent.__table__])
        upgrade_connection(connection)
    factory = sessionmaker(engine)
    app = FastAPI()
    app.include_router(router)
    auth = SimpleNamespace(
        csrf_token=HEADERS["X-CSRF-Token"],
        user=SimpleNamespace(id=None, username="admin", display_name="Administrator"),
        has=lambda permission: permission == "audit.view",
        can_manage_group=lambda group: group is None,
    )

    def session():
        with factory() as db:
            yield db

    app.dependency_overrides[require_user] = lambda: auth
    app.dependency_overrides[get_db] = session
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with TestClient(app) as client:
        yield client, auth, factory
    engine.dispose()


def test_permissions_and_csrf_checked_before_reading_credentials(setup):
    client, auth, _ = setup
    for method, suffix in (("POST", ""), ("PUT", "/1"), ("DELETE", "/1"),
                           ("POST", "/1/test"), ("POST", "/1/replay")):
        response = client.request(method, PATH + suffix, content=b"invalid sensitive input")
        assert response.status_code == 403
        assert "sensitive" not in response.text
    auth.can_manage_group = lambda group: group == 4
    assert client.get(PATH, params={"group_id": 4}).status_code == 403
    assert client.post(PATH, json=SYSLOG, headers=HEADERS).status_code == 403
    auth.can_manage_group = lambda group: True
    auth.has = lambda permission: False
    assert client.get(PATH).status_code == 403


def test_secret_rotation_preservation_and_recipient_binding(setup):
    client, _, factory = setup
    settings = {"name": "Splunk", "kind": "splunk", "config": {"url": "https://hec.example:8088"}}
    submitted = "first-test-credential"
    rotated = "second-test-credential"
    response = client.post(PATH, headers=HEADERS, json={**settings, "secret": submitted})
    assert response.status_code == 201, response.text
    target = response.json()
    assert target["has_secret"] and submitted not in response.text
    endpoint = f"{PATH}/{target['id']}"
    assert client.put(endpoint, headers=HEADERS, json={**settings, "name": "Renamed"}).status_code == 200
    with factory() as db:
        stored = db.get(ForwardDestination, target["id"]).secret_ciphertext
        assert stored != submitted and decrypt_secret(stored) == submitted
    changed = {**settings, "config": {"url": "https://other.example:8088"}}
    assert client.put(endpoint, headers=HEADERS, json=changed).status_code == 409
    assert client.put(endpoint, headers=HEADERS, json={**settings, "secret": rotated}).status_code == 200
    listed = client.get(PATH)
    assert listed.json()["destinations"][0]["has_secret"]
    with factory() as db:
        assert decrypt_secret(db.get(ForwardDestination, target["id"]).secret_ciphertext) == rotated
        events = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
        assert [row.action for row in events] == [
            "log_forwarding.created", "log_forwarding.updated", "log_forwarding.updated",
        ]
        for token in (submitted, rotated):
            assert token not in listed.text and all(token not in str(row.detail) for row in events)


def test_test_before_enabling_replay_and_counted_discard(setup):
    client, _, factory = setup
    response = client.post(PATH, headers=HEADERS, json=SYSLOG)
    assert response.status_code == 201, response.text
    target = response.json()
    assert target["enabled"] is False and target["config"]["port"] == 6514
    endpoint = f"{PATH}/{target['id']}"
    assert client.post(endpoint + "/replay", headers=HEADERS).status_code == 409
    queued = client.post(endpoint + "/test", headers=HEADERS)
    assert queued.status_code == 202, queued.text
    assert client.get(PATH).json()["destinations"][0]["pending"] == 1
    assert client.delete(endpoint, headers=HEADERS).status_code == 409
    assert client.delete(endpoint, headers=HEADERS, params={"discard_count": 0}).status_code == 409
    assert client.delete(endpoint, headers=HEADERS, params={"discard_count": 1}).status_code == 200
    with factory() as db:
        test = db.scalar(select(AuditEvent).where(AuditEvent.action == "log_forwarding.test_requested"))
        assert test.detail["event_id"] == queued.json()["event_id"]
        removed = db.scalar(select(AuditEvent).where(AuditEvent.action == "log_forwarding.deleted"))
        assert removed.detail["discarded_copies"] == 1
    assert client.get(PATH).json() == {"destinations": []}


def test_replay_only_for_enabled_audit_after_creation(setup):
    client, _, factory = setup
    response = client.post(PATH, json={**SYSLOG, "enabled": True}, headers=HEADERS)
    assert response.status_code == 201, response.text
    endpoint = f"{PATH}/{response.json()['id']}"
    assert client.delete(endpoint, headers=HEADERS).status_code == 409
    assert client.post(endpoint + "/replay", headers=HEADERS).status_code == 202
    with factory() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "log_forwarding.replay_requested"))
