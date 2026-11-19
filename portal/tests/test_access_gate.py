"""Exercise real login, cookies, middleware and claim transitions in a disposable DB."""
from datetime import timedelta
from html.parser import HTMLParser
from http.cookies import SimpleCookie

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.access_requests import ClaimInput, claim_route
from app.account_models import AccountAccessRequest, ServiceAccessRequest
from app.auth import AuthContext, SESSION_COOKIE, SYSTEM_ROLES, hash_password
from app.database import Base
from app.frontend import PAGE_MEDIA_TYPE
from app.models import AuditEvent, Group, Role, Service, ServiceArchiveEvent, User, UserRoleAssignment, UserSession, utcnow

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
        assert response.json()["detail"] == main.ACCESS_PENDING_MESSAGE


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


def sign_in_oidc(client, monkeypatch):
    monkeypatch.setattr(main, "configured_ca_bundle", lambda configuration: None)
    monkeypatch.setattr(main, "oidc_exchange_code", lambda *args: ({"access_token": "test"}, {}))
    monkeypatch.setattr(main, "verify_oidc_id_token", lambda *args: {
        "iss": "https://issuer.example", "sub": "new-oidc-subject", "preferred_username": "oidc-new"})
    client.cookies.set("cats_oidc_state", "state")
    client.cookies.set("cats_oidc_nonce", "nonce")
    response = client.get("/auth/oidc/callback?state=state&code=code")
    assert response.status_code == 303 and response.headers["location"] == "/account/access"


def test_oidc_directory_round_trip_scopes_and_retries(environment, monkeypatch):
    client, factory, ids = environment
    sign_in_oidc(client, monkeypatch)
    with factory() as db:
        user = db.scalar(select(User).where(User.username == "oidc-new"))
        assert user and user.role_assignments == [] and db.get(AccountAccessRequest, user.id) is None
        user_id = user.id
        csrf = db.scalar(select(UserSession.csrf_token).where(UserSession.user_id == user_id))
        group = db.get(Group, ids[2])
        outside_group = Group(name="Other group")
        services = [Service(service_key=key, name=name, groups=[owner], lifecycle_status=status,
                            description="sensitive description")
                    for key, name, owner, status in [
                        ("first", "Alpha & Delta", group, "active"), ("second", "Beta", group, "active"),
                        ("outside", "Other service", outside_group, "active"), ("stage", "Hidden stage", group, "staged"),
                        ("archive", "Hidden archive", group, "active")]]
        db.add_all(services)
        db.add(ServiceArchiveEvent(service=services[-1], action="archive", performed_by="operator", reason="retired"))
        db.commit()
        first, second, outside, staged, archived = [service.id for service in services]

    cookie = client.cookies.get(SESSION_COOKIE)
    landing = client.get("/account/access")
    assert landing.status_code == 200 and landing.headers["Cache-Control"] == "no-store"
    assert "Alpha &amp; Delta" in landing.text and "Beta" in landing.text
    assert all(text not in landing.text for text in ["Hidden stage", "Hidden archive", "sensitive description", "cats-bootstrap"])
    assert client.get("/services/first").headers["location"] == "/account/access"
    assert client.get("/api/accounts/access-requests").status_code == 403
    headers = {"accept": "application/json"}
    def submit(service_id, token=csrf):
        return client.post("/account/access/service", data={"service_id": service_id, "csrf_token": token}, headers=headers)
    assert submit(first, "invalid").status_code == 403
    assert submit(staged).status_code == submit(archived).status_code == 404
    for service in [first, first, second, outside]:
        assert submit(service).status_code == 303
    assert client.get("/account/access").text.count("Pending review") == 3
    with factory() as db:
        # A pre-upgrade general request cannot be used to grant a wider group.
        db.add(AccountAccessRequest(user_id=user_id))
        db.commit()
        cyber = AuthContext(db.get(User, ids[1]), db.scalar(select(UserSession).where(UserSession.user_id == ids[1])))
        assert [r["service_id"] for r in main.access_requests.list_pending_requests(db, cyber)] == [first, second]
        assert len(db.scalars(select(AuditEvent).where(AuditEvent.action == "account.service_access_requested")).all()) == 3
        with pytest.raises(main.HTTPException, match="Select a pending service request"):
            claim_route(user_id, ClaimInput(csrf_token="csrf", group_id=ids[2]), db, cyber)
        with pytest.raises(main.HTTPException) as rejected:
            claim_route(user_id, ClaimInput(csrf_token="csrf", service_id=outside), db, cyber)
        assert rejected.value.status_code == 403
        for service in [first, second]:
            assert claim_route(user_id, ClaimInput(csrf_token="csrf", service_id=service), db, cyber)["service_id"] == service
            with pytest.raises(main.HTTPException) as duplicate:
                claim_route(user_id, ClaimInput(csrf_token="csrf", service_id=service), db, cyber)
            assert duplicate.value.status_code == 409
        grants = db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id == user_id)).all()
        assert {(g.service_id, g.group_id, g.role.name, g.source) for g in grants} == {
            (first, None, "Assessor", "local"), (second, None, "Assessor", "local")}
        assert [r.service_id for r in db.scalars(select(ServiceAccessRequest))] == [outside]
    assert client.cookies.get(SESSION_COOKIE) == cookie
    assert client.get("/account/access").headers["location"] == "/"


def test_pending_oidc_user_can_read_announcement_and_sign_out(environment, monkeypatch):
    client, factory, _ = environment
    sign_in_oidc(client, monkeypatch)
    with factory() as db:
        user = db.scalar(select(User).where(User.username == "oidc-new"))
        csrf = db.scalar(select(UserSession.csrf_token).where(UserSession.user_id == user.id))
        notice = main.announcements.PortalAnnouncement(title="Outage", message="Maintenance <window>")
        db.add(notice)
        db.commit()
        read_path = f"/account/announcements/{notice.id}/read"
    response = client.get("/account/access")
    assert "No active services" in response.text and "Maintenance &lt;window&gt;" in response.text
    assert read_path in response.text and "Mark as read" in response.text
    response = client.post(read_path, data={"csrf_token": csrf})
    assert response.status_code == 303 and response.headers["location"] == "/account/access"
    assert "Mark as read" not in client.get("/account/access").text
    assert client.post("/logout", data={"csrf_token": csrf}).status_code == 303
    assert not client.cookies.get(SESSION_COOKIE)


@pytest.mark.parametrize("next_path", [None, "/?lifecycle=staged", "/home"])
def test_oidc_callback_session_is_ready_for_first_landing_page(environment, monkeypatch, next_path):
    client, factory, ids = environment
    claims = {"iss": "https://issuer.example", "sub": "cyber-subject", "preferred_username": "cyber"}
    with factory() as db:
        # This flow exercises the full dashboard; the shared fixture's role is
        # limited to an empty group for access-request tests.
        assignment = db.scalar(select(UserRoleAssignment).where(UserRoleAssignment.user_id == ids[1]))
        assignment.group_id = None
        main.provision_oidc_user(db, claims, {
            "account_links": {claims["iss"]: {claims["sub"]: "cyber"}},
        })
        db.commit()
    monkeypatch.setattr(main, "configured_ca_bundle", lambda configuration: None)
    monkeypatch.setattr(main, "oidc_authorization_url", lambda state, *args: f"https://issuer.example/authorize?state={state}")
    monkeypatch.setattr(main, "oidc_exchange_code", lambda *args: ({"access_token": "test"}, {}))
    monkeypatch.setattr(main, "verify_oidc_id_token", lambda *args: claims)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    client.base_url = "https://testserver"

    response = client.get("/auth/oidc/login", params={"next": next_path} if next_path else {})
    assert response.status_code == 303
    state = client.cookies.get("cats_oidc_state")
    assert state and client.cookies.get("cats_oidc_nonce")
    response = client.get("/auth/oidc/callback", params={"state": state, "code": "code"})
    assert response.status_code == 303
    assert response.headers["location"] == (next_path or "/")
    assert response.headers["cache-control"] == "no-store"

    # TestClient does not enforce browser SameSite rules. Assert Lax explicitly:
    # Strict loses the session on the first redirect back from the external IdP.
    cookies = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        cookies.load(header)
    session_cookie = cookies[SESSION_COOKIE]
    assert session_cookie["samesite"] == "lax"
    assert session_cookie["httponly"] and session_cookie["secure"]
    assert session_cookie["path"] == "/"
    assert int(session_cookie["max-age"]) > 0
    assert all(not client.cookies.get(name) for name in ("cats_oidc_state", "cats_oidc_nonce", "cats_oidc_next"))

    landing = client.get(response.headers["location"], headers={"Accept": PAGE_MEDIA_TYPE}, follow_redirects=True)
    assert landing.status_code == 200
    assert landing.json()["page"] == "dashboard"
    with factory() as db:
        assert db.scalar(select(UserSession).where(UserSession.user_id == ids[1], UserSession.token_hash != "cyber"))
