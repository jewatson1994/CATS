from datetime import timedelta
import json

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.account_models import AccountRetirement
from app.auth import AuthContext, SESSION_COOKIE, SYSTEM_ROLES, aware, token_hash
from app.database import Base
from app.models import AuditEvent, Group, Role, Service, ServiceArchiveEvent, User, UserRoleAssignment, UserSession, utcnow
from app.project_credentials import ProjectCredential, audit_project_use, authenticate_project
from app.replica_models import ReplicaServiceState

PATH = "/api/services/alpha/project-credentials"
CREATE = {"csrf_token": "csrf", "project_label": "ops/platform", "scopes": ["artifacts.submit"]}


@pytest.fixture
def env(monkeypatch):
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        owner = Group(name="one")
        service = Service(name="Alpha", service_key="alpha", groups=[owner])
        other = Service(name="Beta", service_key="beta", groups=[Group(name="two")])
        actor = User(username="manager", display_name="Manager", must_change_password=False)
        grant = UserRoleAssignment(user=actor, service=service, role=Role(name="Service Manager", system=True,
                                                                          permissions=SYSTEM_ROLES["Service Manager"]))
        admin = User(username="admin", display_name="Admin", must_change_password=False)
        admin_grant = UserRoleAssignment(user=admin, role=Role(name="Administrator", permissions=SYSTEM_ROLES["Administrator"], system=True))
        def session(user, raw):
            return UserSession(user=user, token_hash=token_hash(raw), csrf_token="csrf", expires_at=utcnow()+timedelta(hours=1))
        db.add_all([grant, other, admin_grant, session(actor, "manager-cookie"), session(admin, "admin-cookie")])
        db.commit()
    def db_override():
        with factory() as db:
            yield db
    main.app.dependency_overrides[main.get_db] = db_override
    monkeypatch.setattr(main, "SessionLocal", factory)
    client = TestClient(main.app, follow_redirects=False, headers={"accept": "application/json"})
    client.cookies.set(SESSION_COOKIE, "manager-cookie")
    try:
        yield client, factory
    finally:
        client.close()
        main.app.dependency_overrides.pop(main.get_db)
        engine.dispose()


def issue(client, **kwargs):
    response = client.post(PATH, json={**CREATE, **kwargs})
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def test_issue_use_and_revoke(env):
    client, factory = env
    issued = issue(client)
    cid, token = issued["credential"]["id"], issued["token"]
    assert token.startswith("cats_project_")
    assert issued["credential"]["scopes"] == ["artifacts.submit"]
    assert client.get(PATH).json() == {"credentials": [issued["credential"]]}
    with factory() as db:
        row = authenticate_project(db, "Bearer " + token, scope="artifacts.submit", service_key="alpha")
        assert row.id == cid and row.token_hash == token_hash(token) and row.token_hash != token
        assert timedelta(days=29) < aware(row.expires_at) - aware(row.created_at) <= timedelta(days=30)
        audit_project_use(db, row, "submission.accepted", target_type="scan_job", target_id="job-one")
        db.commit()
        for scope, key in [("evidence.write", "alpha"), ("artifacts.submit", "beta")]:
            with pytest.raises(HTTPException) as denied:
                authenticate_project(db, "Bearer " + token, scope=scope, service_key=key)
            assert denied.value.status_code == 403
        for bad_header in [None, "Basic " + token, token, "Bearer cats_project_bad", "Bearer " + token + " extra"]:
            with pytest.raises(HTTPException) as denied:
                authenticate_project(db, bad_header, scope="artifacts.submit")
            assert denied.value.status_code == 401
    for _ in range(2):
        response = client.post(f"{PATH}/{cid}/revoke", json={"csrf_token": "csrf"})
        assert response.status_code == 200
        assert response.json()["credential"]["status"] == "revoked"
        assert token not in response.text
    with factory() as db:
        actions = db.scalars(select(AuditEvent).where(AuditEvent.action.like("project_credential.%")).order_by(AuditEvent.id)).all()
        assert [a.action for a in actions] == ["project_credential.created", "project_credential.used", "project_credential.revoked"]
        assert actions[1].actor_user_id is None and actions[1].detail["project_label"] == "ops/platform"
        assert actions[1].detail["credential_id"] == cid
        assert token not in json.dumps([a.detail for a in actions])
        with pytest.raises(HTTPException) as denied:
            authenticate_project(db, "Bearer " + token, scope="artifacts.submit")
        assert denied.value.status_code == 401


def test_scope_csrf_validation_rotation_and_admin_delegation(env):
    client, _ = env
    for override in [{"scopes":[]}, {"scopes":["admin"]}, {"expires_in_days":366}, {"expires_in_days":0},
                     {"expires_in_days":"15"}, {"project_label":"  "}, {"service_id":11}]:
        assert client.post(PATH, json={**CREATE, **override}).status_code == 422
    assert client.post(PATH, json={**CREATE, "csrf_token":"invalid"}).status_code == 403
    issued = issue(client, expires_in_days=1)
    rotated = issue(client)
    assert issued["token"] != rotated["token"]
    cid = issued["credential"]["id"]
    assert client.post(f"{PATH}/{cid}/revoke", json={"csrf_token":"bad"}).status_code == 403
    assert client.post(PATH.replace("alpha","beta"), json=CREATE).status_code == 403
    assert client.get(PATH.replace("alpha","beta")).status_code == 403
    client.cookies.set(SESSION_COOKIE, "admin-cookie")
    assert client.get(PATH).status_code == 200
    assert client.post(PATH, json=CREATE).status_code == 403
    assert client.post(f"{PATH.replace('alpha', 'beta')}/{cid}/revoke", json={"csrf_token":"csrf"}).status_code == 404
    assert client.post(f"{PATH}/{cid}/revoke", json={"csrf_token":"csrf"}).status_code == 200


@pytest.mark.parametrize("change", ["expired", "archived", "staged", "transferred", "unowned", "imported",
                                    "disabled", "retired", "issuer_lost_ingest", "issuer_lost_edit", "replica"])
def test_authentication_rechecks_live_delegation(env, change, monkeypatch):
    client, factory = env
    issued = issue(client, scopes=["evidence.write"])
    with factory() as db:
        row = db.get(ProjectCredential, issued["credential"]["id"])
        user, service = row.creator, row.service
        if change == "expired":
            row.expires_at = utcnow() - timedelta(seconds=1)
        elif change == "archived":
            db.add(ServiceArchiveEvent(service=service, action="archive", reason="done", performed_by="operator"))
        elif change == "staged":
            service.lifecycle_status = "staged"
        elif change == "transferred":
            service.groups = [db.scalar(select(Group).where(Group.name == "two"))]
        elif change == "unowned":
            service.groups = []
        elif change == "imported":
            db.add(ReplicaServiceState(service_id=service.id, publisher="remote", source_service_id="upstream",
                                       source_id=91, upstream_id=92))
        elif change == "disabled":
            user.enabled = False
        elif change == "retired":
            admin = db.scalar(select(User).where(User.username == "admin"))
            db.add(AccountRetirement(user_id=user.id, survivor_id=admin.id, administrator_id=admin.id))
        elif change.startswith("issuer_lost_"):
            user.role_assignments[0].role.permissions = ["service.view", "service.edit" if change.endswith("ingest") else "scan.ingest"]
        else:
            monkeypatch.setenv("CATS_MODE", "replica")
        db.commit()
        with pytest.raises(HTTPException) as denied:
            authenticate_project(db, "Bearer " + issued["token"], scope="evidence.write")
        assert denied.value.status_code == (403 if change == "replica" else 401)


def test_deleted_user_credentials_cannot_revive_on_sqlite_id_reuse(env):
    client, factory = env
    issued = issue(client)
    with factory() as db:
        row = db.get(ProjectCredential, issued["credential"]["id"])
        issuer_id = row.created_by_id
        admin = db.scalar(select(User).where(User.username == "admin"))
        session = db.scalar(select(UserSession).where(UserSession.user_id == admin.id))
        main.delete_user_account(issuer_id, "csrf", db, AuthContext(admin, session))
        assert row.created_by_id is None and row.revoked_at is not None
        replacement = User(id=issuer_id, username="next-user", display_name="Next user")
        db.add(UserRoleAssignment(user=replacement, service=row.service, role=db.scalar(select(Role).where(Role.name == "Service Manager"))))
        db.commit()
        with pytest.raises(HTTPException) as denied:
            authenticate_project(db, "Bearer " + issued["token"], scope="artifacts.submit")
        assert denied.value.status_code == 401


def test_deleted_service_credentials_cannot_revive_on_sqlite_id_reuse(env):
    client, factory = env
    issued = issue(client)
    with factory() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        session = db.scalar(select(UserSession).where(UserSession.user_id == admin.id))
        old_id = db.scalar(select(Service.id).where(Service.service_key == "alpha"))
        main.delete_service("alpha", "delete Alpha", "retire service", "csrf", db, AuthContext(admin, session))
        assert db.get(ProjectCredential, issued["credential"]["id"]) is None
        db.add(Service(id=old_id, service_key="alpha", name="Alpha", groups=[db.scalar(select(Group).where(Group.name=="one"))]))
        db.commit()
        with pytest.raises(HTTPException) as denied:
            authenticate_project(db, "Bearer " + issued["token"], scope="artifacts.submit")
        assert denied.value.status_code == 401
