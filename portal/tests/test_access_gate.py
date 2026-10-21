"""Exercise real login, cookies, middleware and claim transitions in a disposable DB."""
from datetime import timedelta
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.access_requests import ClaimInput, claim_route
from app.account_models import AccountAccessRequest
from app.auth import AuthContext, SESSION_COOKIE, SYSTEM_ROLES, hash_password
from app.database import Base
from app.models import Group, Role, User, UserRoleAssignment, UserSession, utcnow

PASSWORD = "integration-test-password"


@pytest.fixture
def environment(monkeypatch):
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        target = User(username="new", display_name="New", password_hash=hash_password(PASSWORD), must_change_password=False)
        actor = User(username="cyber", display_name="Cyber", must_change_password=False)
        group = Group(name="Empty group")
        cyber = Role(name="Cybersecurity", system=True, permissions=SYSTEM_ROLES["Cybersecurity"])
        assessor = Role(name="Assessor", system=True, permissions=SYSTEM_ROLES["Assessor"])
        db.add_all([target, actor, group, cyber, assessor]); db.flush()
        db.add(UserRoleAssignment(user_id=actor.id, role_id=cyber.id, group_id=group.id))
        db.add(UserSession(user_id=actor.id, token_hash="cyber", csrf_token="csrf", expires_at=utcnow()+timedelta(hours=1)))
        db.commit()
        ids = target.id, actor.id, group.id, assessor.id
    def database():
        with factory() as db:
            yield db
    main.app.dependency_overrides[main.get_db] = database
    monkeypatch.setattr(main, "SessionLocal", factory)
    monkeypatch.setattr(main, "get_global_configuration", lambda db: {"identity_mode": "both"})
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("CATS_OIDC_AUTO_PROVISION", "true")
    for key in ("CATS_OIDC_DEFAULT_ROLE", "CATS_OIDC_ROLE_MAP", "CATS_OIDC_GROUP_ROLE_MAP"):
        monkeypatch.delenv(key, raising=False)
    client = TestClient(main.app, follow_redirects=False)
    try:
        yield client, factory, ids
    finally:
        client.close()
        main.app.dependency_overrides.clear()
        engine.dispose()


def login(client):
    return client.post("/login", data={"username": "new", "password": PASSWORD, "next": "/admin/accounts"})


class BodyText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_body = False
        self.text = []
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "body":
            self.in_body = True

    def handle_endtag(self, tag):
        if tag == "body":
            self.in_body = False

    def handle_data(self, data):
        if self.in_body:
            self.text.append(data)


def test_local_login_creates_pending_and_only_contact_message_is_visible(environment):
    client, factory, ids = environment
    response = login(client)
    assert response.status_code == 303 and response.headers["location"] == "/account/access"
    assert client.cookies.get(SESSION_COOKIE)
    with factory() as db:
        assert db.get(AccountAccessRequest, ids[0]).status == "pending"
    for path in ("/account/access", "/", "/admin/accounts", "/scan"):
        response = client.get(path)
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        parsed = BodyText(); parsed.feed(response.text)
        assert "".join(parsed.text).strip() == main.ACCESS_PENDING_MESSAGE
        assert not {"nav", "script", "form", "a", "table"} & set(parsed.tags)
    for method, path in (("GET", "/api/accounts/access-requests"), ("POST", "/scan"), ("POST", "/login")):
        response = client.request(method, path)
        assert response.status_code == 403
        assert response.json() == {"detail": main.ACCESS_PENDING_MESSAGE}


def test_claim_unlocks_existing_session_and_empty_group_counts_as_access(environment):
    client, factory, ids = environment
    login(client)
    cookie = client.cookies.get(SESSION_COOKIE)
    with factory() as db:
        actor = db.get(User, ids[1])
        session = db.scalar(select(UserSession).where(UserSession.user_id == actor.id))
        claim_route(ids[0], ClaimInput(csrf_token="csrf"), db, AuthContext(actor, session))
        assert db.get(Group, ids[2]).services == []
    response = client.get("/account/access")
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert client.cookies.get(SESSION_COOKIE) == cookie
    # Login with the same empty-group role does not return to the access gate.
    client.cookies.clear()
    response = login(client)
    assert response.headers["location"] == "/admin/accounts"


def test_oidc_login_without_roles_registers_pending_request(environment, monkeypatch):
    client, factory, _ = environment
    monkeypatch.setattr(main, "configured_ca_bundle", lambda configuration: None)
    monkeypatch.setattr(main, "oidc_exchange_code", lambda *args: ({"access_token": "test"}, {}))
    monkeypatch.setattr(main, "verify_oidc_id_token", lambda *args: {
        "iss": "https://issuer.example", "sub": "new-oidc-subject", "preferred_username": "oidc-new"})
    client.cookies.set("cats_oidc_state", "state")
    client.cookies.set("cats_oidc_nonce", "nonce")
    response = client.get("/auth/oidc/callback?state=state&code=code")
    assert response.status_code == 303 and response.headers["location"] == "/account/access"
    with factory() as db:
        user = db.scalar(select(User).where(User.username == "oidc-new"))
        assert user and db.get(AccountAccessRequest, user.id).status == "pending"
        assert user.role_assignments == []
    assert client.cookies.get(SESSION_COOKIE)
    assert main.ACCESS_PENDING_MESSAGE in client.get("/").text
