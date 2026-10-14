"""Callback boundary tests with real CATS persistence and controlled provider I/O."""
import io
import json
import logging
import urllib.error
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import main
from app.auth import AuthContext
from app.database import Base
from app.models import AuditEvent, Role, User, UserRoleAssignment, UserSession
from app.oidc_diagnostics import RedactOidcAccessQuery, failure_reason


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "get_global_configuration", lambda db: {})
    monkeypatch.setattr(main, "oidc_exchange_code", lambda *args: (
        {"access_token": "secret-access-token"}, {"userinfo_endpoint": "https://provider.example/userinfo"}))
    monkeypatch.setattr(main, "verify_oidc_id_token", lambda *args: {"iss": "https://provider.example", "sub": "verified-sub"})
    monkeypatch.setattr(main.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps({"sub": "verified-sub"}).encode()))
    with Session(engine) as session:
        yield session
    engine.dispose()


def request(query="state=state&code=secret-code", cookies="cats_oidc_state=state; cats_oidc_nonce=nonce"):
    return Request({"type": "http", "method": "GET", "path": "/auth/oidc/callback",
                    "query_string": query.encode(), "headers": [(b"cookie", cookies.encode())],
                    "scheme": "https", "server": ("cats.example", 443)})


def assert_failure(db, response, stage, reason):
    assert response.status_code == 303
    assert response.headers["cache-control"] == "no-store"
    message = parse_qs(urlsplit(response.headers["location"]).query)["error"][0]
    reference = message.split("Reference: ")[1]
    event = db.scalar(select(AuditEvent).where(AuditEvent.action == "auth.oidc_failed"))
    assert event.detail == {"correlation_id": reference, "stage": stage, "reason": reason, "outcome": "failed"}
    assert not db.scalars(select(UserSession)).all()
    assert "secret" not in json.dumps(event.detail) + message


@pytest.mark.parametrize("query,cookies,reason", [
    ("code=secret-code", "", "state_missing_or_mismatched"),
    ("state=wrong&code=secret-code", "cats_oidc_state=state", "state_missing_or_mismatched"),
    ("state=state&code=secret-code", "cats_oidc_state=state", "nonce_cookie_missing"),
    ("state=state", "cats_oidc_state=state; cats_oidc_nonce=nonce", "authorization_code_missing"),
    ("state=state&error=secret-provider-detail", "cats_oidc_state=state; cats_oidc_nonce=nonce", "provider_authorization_denied"),
])
def test_state_session_and_provider_failures(db, query, cookies, reason):
    assert_failure(db, main.oidc_callback(request(query, cookies), db), "state_session", reason)


@pytest.mark.parametrize("exception,reason", [
    (jwt.InvalidIssuerError("secret"), "issuer_mismatch"),
    (jwt.InvalidAudienceError("secret"), "audience_mismatch"),
    (jwt.InvalidSignatureError("secret"), "signature_invalid"),
    (jwt.ExpiredSignatureError("secret"), "token_expired"),
    (jwt.ImmatureSignatureError("secret"), "token_not_yet_valid"),
    (ValueError("OIDC nonce validation failed secret"), "nonce_mismatch"),
])
def test_validation_failures_correlate_without_exception_text(db, monkeypatch, caplog, exception, reason):
    def fail(*args):
        raise exception
    monkeypatch.setattr(main, "verify_oidc_id_token", fail)
    assert_failure(db, main.oidc_callback(request(), db), "token_validation", reason)
    assert "secret" not in caplog.text
    assert reason in caplog.text


def test_exchange_failure_is_sanitized(db, monkeypatch, caplog):
    def fail(*args):
        raise ValueError("provider disclosed secret-client-secret")
    monkeypatch.setattr(main, "oidc_exchange_code", fail)
    assert_failure(db, main.oidc_callback(request(), db), "token_exchange", "token_exchange_failed")
    assert "secret" not in caplog.text


def test_username_collision_is_actionable_in_admin_diagnostics(db, monkeypatch):
    def fail(*args):
        raise ValueError("An explicit OIDC account link is required")
    monkeypatch.setattr(main, "provision_oidc_user", fail)
    assert_failure(db, main.oidc_callback(request(), db), "account_provisioning", "account_link_required")


@pytest.mark.parametrize("userinfo,reason", [({"sub": "other"}, "userinfo_subject_mismatch"),
                                            (None, "userinfo_subject_mismatch")])
def test_userinfo_subject_must_match_validated_token(db, monkeypatch, userinfo, reason):
    monkeypatch.setattr(main.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps(userinfo).encode()))
    assert_failure(db, main.oidc_callback(request(), db), "userinfo", reason)


def test_userinfo_cannot_supply_configurable_authorization_claims(db, monkeypatch):
    user = User(username="unscoped", display_name="Unscoped", auth_source="oidc")
    db.add(user)
    db.commit()
    received = []
    def provision(session, claims, config):
        received.append(claims)
        return user
    monkeypatch.setattr(main, "provision_oidc_user", provision)
    monkeypatch.setattr(main.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps({
        "sub": "verified-sub", "groups": ["admins"], "email": "administrator", "name": "admin"}).encode()))
    response = main.oidc_callback(request(), db)
    assert received == [{"iss": "https://provider.example", "sub": "verified-sub"}]
    assert response.headers["location"] == "/account/access"
    assert db.scalar(select(UserSession)).user_id == user.id
    event = db.scalar(select(AuditEvent).where(AuditEvent.action == "auth.oidc_login"))
    assert event.detail["reason"] == "no_assigned_access"
    assert event.detail["outcome"] == "success"


def test_access_log_filter_strips_callback_query_before_formatting():
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                               ("127.0.0.1", "GET", "/auth/oidc/callback?code=secret-code&state=secret-state", "1.1", 303), None)
    assert RedactOidcAccessQuery().filter(record)
    assert "secret" not in record.getMessage()
    assert "/auth/oidc/callback HTTP" in record.getMessage()
