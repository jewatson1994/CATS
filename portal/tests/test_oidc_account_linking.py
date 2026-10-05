import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.auth import oidc_identity_key, provision_oidc_user
from app.database import Base
from app.models import AuditEvent, Role, User, UserRoleAssignment


@pytest.fixture
def db(monkeypatch):
    for setting in ("CATS_OIDC_DEFAULT_ROLE", "CATS_OIDC_ACCOUNT_LINKS"):
        monkeypatch.delenv(setting, raising=False)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def admin(db):
    role = Role(name="Administrator", permissions=["config.manage"])
    user = User(username="admin", display_name="Administrator", auth_source="local")
    db.add_all([role, user])
    db.flush()
    assignment = UserRoleAssignment(user_id=user.id, role_id=role.id, source="local")
    event = AuditEvent(actor_user_id=user.id, action="historical.action", target_type="user", target_id=str(user.id))
    db.add_all([assignment, event])
    db.commit()
    return user, assignment, event


def claims(subject="admin-sub", issuer="https://idp.example/realm"):
    return {"iss": issuer, "sub": subject, "preferred_username": "admin"}


def config(subject="admin-sub", issuer="https://idp.example/realm"):
    return {"issuer": issuer, "account_links": {issuer: {subject: "admin"}}}


def test_local_admin_link_is_idempotent_and_preserves_authorization_and_history(db):
    user, assignment, event = admin(db)
    for _ in range(3):
        linked = provision_oidc_user(db, claims(), config())
        db.commit()
        assert linked.id == user.id
    assert user.auth_source == "local"  # Preserve emergency password recovery.
    assert db.get(UserRoleAssignment, assignment.id).role.permissions == ["config.manage"]
    assert db.get(AuditEvent, event.id).actor_user_id == user.id
    assert db.scalar(select(func.count(User.id))) == 1
    assert user.external_subject == oidc_identity_key(claims()["iss"], claims()["sub"])


def test_disabled_admin_keeps_link_roles_and_history_and_reenable_restores_login(db):
    user, assignment, event = admin(db)
    provision_oidc_user(db, claims(), config())
    db.commit()
    user.enabled = False
    db.commit()
    for _ in range(3):
        assert provision_oidc_user(db, claims(), config()).enabled is False
        db.commit()
    assert db.scalar(select(func.count(User.id))) == 1
    assert db.get(UserRoleAssignment, assignment.id)
    assert db.get(AuditEvent, event.id).actor_user_id == user.id
    user.enabled = True
    db.commit()
    assert provision_oidc_user(db, claims(), config()).enabled


@pytest.mark.parametrize("enabled", [True, False])
def test_username_and_unverified_email_cannot_take_over_or_replace_admin(db, enabled):
    user, _, _ = admin(db)
    user.enabled = enabled
    db.commit()
    with pytest.raises(ValueError, match="explicit OIDC account link"):
        provision_oidc_user(db, {**claims(), "email": "admin", "email_verified": False}, {"issuer": claims()["iss"]})
    db.rollback()
    assert db.scalar(select(func.count(User.id))) == 1
    assert user.enabled is enabled
    assert user.external_subject is None


def test_other_subject_or_issuer_cannot_overwrite_existing_link(db):
    user, _, _ = admin(db)
    provision_oidc_user(db, claims(), config())
    db.commit()
    identity = user.external_subject
    user.enabled = False
    db.commit()
    for subject, issuer in [("attacker", claims()["iss"]), ("admin-sub", "https://other.example")]:
        with pytest.raises(ValueError, match="already linked"):
            provision_oidc_user(db, claims(subject, issuer), config(subject, issuer))
        db.rollback()
    assert user.external_subject == identity
    assert not user.enabled
    assert db.scalar(select(func.count(User.id))) == 1


def test_legacy_identity_migrates_only_with_explicit_binding(db):
    user, _, _ = admin(db)
    user.auth_source = "oidc"
    user.external_subject = "admin-sub"
    db.commit()
    with pytest.raises(ValueError, match="Legacy OIDC identity"):
        provision_oidc_user(db, claims(), {"issuer": claims()["iss"]})
    db.rollback()
    assert provision_oidc_user(db, claims(), config()).id == user.id
    db.commit()
    assert user.external_subject == oidc_identity_key(claims()["iss"], "admin-sub")


def test_issuer_mismatch_is_rejected_before_mutation(db):
    user, _, _ = admin(db)
    with pytest.raises(ValueError, match="issuer"):
        provision_oidc_user(db, claims(issuer="https://evil.example"), config())
    assert user.external_subject is None


def test_callback_denies_disabled_admin_without_session_and_records_audit(db, monkeypatch):
    import json
    import urllib.error
    from starlette.requests import Request
    from app import main
    from app.models import UserSession

    user, assignment, event = admin(db)
    monkeypatch.setattr(main, "get_global_configuration", lambda session: {"oidc_configuration": json.dumps(config())})
    monkeypatch.setattr(main, "oidc_exchange_code", lambda *args: ({"access_token": "provider-token"}, {"userinfo_endpoint": "https://idp.example/userinfo"}))
    monkeypatch.setattr(main, "verify_oidc_id_token", lambda *args: claims())

    def denied_userinfo(*args, **kwargs):
        raise urllib.error.HTTPError("https://idp.example/userinfo", 401, "not available", {}, None)

    monkeypatch.setattr(main.urllib.request, "urlopen", denied_userinfo)
    request = Request({"type": "http", "method": "GET", "path": "/auth/oidc/callback",
                       "query_string": b"state=expected&code=provider-code",
                       "headers": [(b"cookie", b"cats_oidc_state=expected; cats_oidc_nonce=nonce")],
                       "scheme": "https", "server": ("cats.example", 443)})
    assert main.oidc_callback(request, db).status_code == 303
    assert db.scalar(select(func.count(UserSession.id))) == 1
    user.enabled = False
    db.commit()
    for _ in range(3):
        response = main.oidc_callback(request, db)
        assert "disabled" in response.headers["location"]
        assert not any("cats_session=" in value for key, value in response.headers.items() if key == "set-cookie")
        assert db.scalar(select(func.count(UserSession.id))) == 1
    assert not user.enabled
    assert db.scalar(select(func.count(User.id))) == 1
    assert db.get(UserRoleAssignment, assignment.id)
    assert db.get(AuditEvent, event.id).actor_user_id == user.id
    assert db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.action == "auth.oidc_denied_disabled")) == 3
    user.enabled = True
    db.commit()
    assert main.oidc_callback(request, db).status_code == 303
    assert db.scalar(select(func.count(UserSession.id))) == 2
