"""Client page-cache scope: partitions by session and authorization revision."""
from sqlalchemy import delete, select, update

from app.database import SessionLocal
from app.models import Group, Role, Service, User, UserRoleAssignment
from app.auth import hash_password
from test_portal import new_client, setup_function  # noqa: F401

PAGE = {"Accept": "application/vnd.cats.page+json"}


def scope(client, url="/account/appearance"):
    response = client.get(url, headers=PAGE)
    assert response.status_code == 200, response.text[:200]
    return response.json()["cacheScope"]


def test_scope_is_per_session_and_stable_without_access_changes():
    first, second = new_client(), new_client()
    assert scope(first) and scope(first) == scope(first)
    assert scope(first) != scope(second)  # same user, different session


def test_access_changes_replace_the_scope_but_login_bookkeeping_does_not():
    client = new_client()
    original = scope(client)
    with SessionLocal() as db:
        db.execute(update(User).where(User.username == "admin").values(failed_login_count=0))
        db.commit()
    assert scope(client) == original
    with SessionLocal() as db:
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        user = User(username="scoped", display_name="Scoped", password_hash=hash_password("test-password-long"),
                    must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id)); db.commit()
    changed = scope(client)
    assert changed != original
    with SessionLocal() as db:  # bulk ORM delete (as used by service/user removal)
        user_id = db.scalar(select(User.id).where(User.username == "scoped"))
        db.execute(delete(UserRoleAssignment).where(UserRoleAssignment.user_id == user_id)); db.commit()
    after_delete = scope(client)
    assert after_delete != changed
    with SessionLocal() as db:  # service group membership changes group-scoped access
        group = Group(name="scope-group")
        service = Service(service_key="scope-service", name="Scope", lifecycle_status="active")
        db.add_all([group, service]); db.flush()
        service.groups.append(group); db.commit()
    assert scope(client) != after_delete
    membership = scope(client)
    with SessionLocal() as db:
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        role.permissions = [*role.permissions]
        role.description = "edited"
        db.commit()
    assert scope(client) != membership


def test_rolled_back_changes_do_not_publish_a_revision():
    client = new_client()
    original = scope(client)
    with SessionLocal() as db:
        db.add(Group(name="rolled-back")); db.flush(); db.rollback()
    assert scope(client) == original


def test_session_identity_survives_authorization_changes_but_not_sessions():
    """Tabs of one session keep their shown page on an authorization change
    (same identity, new scope); another session or sign-out differs."""
    first, second = new_client(), new_client()
    page = lambda client: client.get("/account/appearance", headers=PAGE).json()
    before = page(first)
    assert before["sessionIdentity"] and before["sessionIdentity"] != page(second)["sessionIdentity"]
    with SessionLocal() as db:
        group = Group(name="identity-check"); db.add(group); db.commit()
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        db.add(UserRoleAssignment(user_id=admin.id, role_id=role.id, group_id=group.id)); db.commit()
    after = page(first)
    assert after["cacheScope"] != before["cacheScope"] and after["sessionIdentity"] == before["sessionIdentity"]
    assert first.cookies.get("cats_session") not in after["sessionIdentity"]  # opaque, never the token
    from fastapi.testclient import TestClient
    from app.main import app
    login = TestClient(app).get("/login", headers=PAGE).json()
    assert login["page"] == "login" and login["sessionIdentity"] == "" and login["cacheScope"] == ""
