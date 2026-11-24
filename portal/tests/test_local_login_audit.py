import hashlib
import json
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app import main
from app.account_models import AccountRetirement
from app.auth import hash_password, utcnow
from app.database import Base
from app.models import AuditEvent, User, UserSession


@pytest.fixture
def portal(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory.begin() as db:
        db.add(User(username="operator", display_name="Operator",
                    password_hash=hash_password("correct-test-password")))

    config = {"identity_mode": "local"}
    monkeypatch.setattr(main, "get_global_configuration", lambda db: config)
    try:
        yield factory, config
    finally:
        engine.dispose()


def attempt(factory, username):
    request = Request({"type": "http", "method": "POST", "path": "/login",
                       "scheme": "https", "server": ("cats.example", 443),
                       "client": ("192.0.2.14", 41400), "query_string": b"",
                       "headers": [(b"accept", b"application/vnd.cats.page+json")]})
    with factory() as db:
        return main.login(request, username, "never-record-this", "/", db)


@pytest.mark.parametrize("account_state,expected_reason", [
    ("enabled", "invalid_credentials"),
    ("disabled", "account_disabled"),
    ("locked", "account_locked"),
    ("retired", "account_retired"),
    ("oidc_only", "local_login_disabled"),
])
def test_local_denial_audits_one_event_and_preserves_account_behavior(portal, account_state, expected_reason):
    factory, config = portal
    with factory.begin() as db:
        user = db.scalar(select(User))
        identity = user.id
        user.failed_login_count = 4
        if account_state == "disabled":
            user.enabled = False
        elif account_state == "locked":
            user.locked_until = utcnow() + timedelta(minutes=10)
        elif account_state == "retired":
            survivor = User(username="survivor", display_name="Survivor")
            db.add(survivor)
            db.flush()
            db.add(AccountRetirement(user_id=user.id, survivor_id=survivor.id, administrator_id=survivor.id))
        elif account_state == "oidc_only":
            config["identity_mode"] = "oidc"

    response = attempt(factory, "  OPERATOR ")
    assert response.status_code == (403 if account_state == "oidc_only" else 401)
    if account_state != "oidc_only":
        assert b"Invalid username or password" in response.body
    with factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == "auth.login_failed")).one()
        assert (event.actor_user_id, event.target_type, event.target_id) == (None, "authentication", str(identity))
        assert event.detail["target_username"] == "operator"
        assert event.detail["reason"] == expected_reason and event.detail["outcome"] == "denied"
        assert event.detail["client_address"] == "192.0.2.14"
        lockout_applied = account_state in ("enabled", "locked", "retired")
        assert event.detail["lockout_applied"] is lockout_applied
        assert db.get(User, identity).failed_login_count == (0 if lockout_applied else 4)
        assert "never-record-this" not in json.dumps(event.detail)
        assert db.scalars(select(UserSession)).first() is None


def test_unknown_local_account_cannot_inject_text_or_secrets_into_audit(portal):
    factory, _ = portal
    identity = "X" * 180 + "\n\x00pasted-secret"
    response = attempt(factory, identity)
    assert response.status_code == 401 and b"Invalid username or password" in response.body
    with factory() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == "auth.login_failed")).one()
        assert event.actor_user_id is None and event.target_id is None
        assert event.detail["reason"] == "unknown_account"
        assert event.detail["attempted_identity_sha256"] == hashlib.sha256(identity.lower().encode()).hexdigest()
        assert "pasted-secret" not in json.dumps(event.detail) and "never-record-this" not in json.dumps(event.detail)
