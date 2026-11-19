from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import announcements, main
from app.auth import SESSION_COOKIE, token_hash
from app.database import Base
from app.models import AuditEvent, Group, Role, User, UserRoleAssignment, UserSession, utcnow


@pytest.fixture
def portal(monkeypatch):
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory.begin() as db:
        role = Role(name="Platform configuration", permissions=["config.manage", "service.view"])
        group = Group(name="One group")
        db.add_all([group, role])
        db.flush()
        for name, scope in [("admin", None), ("scoped", group.id)]:
            user = User(username=name, display_name=name, must_change_password=False)
            db.add(user)
            db.flush()
            db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, group_id=scope))
            db.add(UserSession(user_id=user.id, token_hash=token_hash(name), csrf_token=name,
                               expires_at=utcnow() + timedelta(hours=1)))

    def db_session():
        with factory() as db:
            yield db

    monkeypatch.setitem(main.app.dependency_overrides, main.get_db, db_session)
    monkeypatch.setattr(main, "SessionLocal", factory)
    client = TestClient(main.app, follow_redirects=False, headers={"Accept": "application/json"})
    yield client, factory
    client.close()
    engine.dispose()


PUBLISH = "/admin/configuration/announcements"
CURRENT = "/api/announcements/current"


def test_announcement_lifecycle_and_per_user_receipts(portal, monkeypatch):
    client, factory = portal
    assert client.get(CURRENT).status_code == 303
    client.cookies.set(SESSION_COOKIE, "admin")
    payload = {"title": " Outage ", "message": "Maintenance at 14:00 UTC", "csrf_token": "admin"}
    assert client.post(PUBLISH, data=payload).status_code == 303
    response = client.get(CURRENT)
    assert "no-store" in response.headers["Cache-Control"]
    first = response.json()
    assert first["title"] == "Outage" and first["unread"]
    read = f"/account/announcements/{first['id']}/read"
    assert client.post(read, data={"csrf_token": "bad"}).status_code == 403
    client.cookies.set(SESSION_COOKIE, "scoped")
    for _ in range(2):
        result = client.post(read, data={"csrf_token": "scoped"}, headers={"Accept": "application/json"})
        assert result.status_code == 200 and result.json()["unread"] is False
    assert client.get(CURRENT).json()["unread"] is False
    assert client.post(PUBLISH, data={**payload, "csrf_token": "scoped"}).status_code == 403
    assert client.post(f"{PUBLISH}/{first['id']}/withdraw", data={"csrf_token": "scoped"}).status_code == 403
    client.cookies.set(SESSION_COOKIE, "admin")
    assert client.get(CURRENT).json()["unread"]
    future = utcnow() + timedelta(hours=1)
    assert client.post(PUBLISH, data={**payload, "title": "Updated outage", "expires_at": future.isoformat()}).status_code == 303
    second = client.get(CURRENT).json()
    assert first["id"] != second["id"] and second["expires_at"] == future.isoformat()
    assert client.post(f"{PUBLISH}/{first['id']}/withdraw", data={"csrf_token": "admin"}).status_code == 303
    client.cookies.set(SESSION_COOKIE, "scoped")
    assert client.get(CURRENT).json() == second
    # Expiring the newest notice must never resurrect the superseded bulletin.
    with monkeypatch.context() as clock:
        clock.setattr(announcements, "utcnow", lambda: future + timedelta(seconds=1))
        assert client.get(CURRENT).json() is None
    client.cookies.set(SESSION_COOKIE, "admin")
    assert client.post(f"{PUBLISH}/{second['id']}/withdraw", data={"csrf_token": "bad"}).status_code == 403
    assert client.post(f"{PUBLISH}/{second['id']}/withdraw", data={"csrf_token": "admin"}).status_code == 303
    assert client.get(CURRENT).json() is None
    with factory() as db:
        assert len(db.scalars(select(announcements.AnnouncementRead)).all()) == 1
        assert db.scalars(select(AuditEvent.action).order_by(AuditEvent.id)).all() == [
            "announcement.published", "announcement.published", "announcement.withdrawn", "announcement.withdrawn"]


def test_announcement_validation_and_replica_routes(portal, monkeypatch):
    client, _ = portal
    client.cookies.set(SESSION_COOKIE, "admin")
    form = {"title": "Maintenance", "message": "Offline soon", "csrf_token": "admin"}
    for bad in ({"title": " "}, {"message": " "}, {"message": "x" * 2001}, {"title": "x" * 121},
                {"expires_at": "tomorrow"}, {"expires_at": "1999-12-31T23:59"}):
        assert client.post(PUBLISH, data={**form, **bad}).status_code == 422
    assert client.post(PUBLISH, data={**form, "csrf_token": "bad"}).status_code == 403
    assert client.get(CURRENT).json() is None
    monkeypatch.setenv("CATS_MODE", "replica")
    assert client.post(PUBLISH, data=form).status_code == 303
    notice = client.get(CURRENT).json()
    assert client.post(f"/account/announcements/{notice['id']}/read", data={"csrf_token": "admin"},
                       headers={"Accept": "text/html"}).status_code == 303
    assert client.post(f"{PUBLISH}/{notice['id']}/withdraw", data={"csrf_token": "admin"}).status_code == 303
