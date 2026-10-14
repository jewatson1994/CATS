"""Role eligibility and durable role-bound scope are intersected, never unioned."""
from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.auth import AuthContext, provision_oidc_user
from app.database import Base
from app.models import Group, Role, Service, User, UserRoleAssignment, OidcClaimMapping, OidcRoleEligibility

CONFIG = {"issuer": "https://id.example/realms/cats", "account_links": {}}

@pytest.fixture
def store(monkeypatch):
    monkeypatch.setenv("CATS_OIDC_DEFAULT_ROLE", "")
    monkeypatch.setenv("CATS_OIDC_ROLE_MAP", "{}")
    monkeypatch.setenv("CATS_OIDC_GROUP_ROLE_MAP", "{}")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name="Service Manager", permissions=["service.view", "service.edit", "service.export", "remediation.execute"])
        services = [Service(service_key=key, name=key) for key in ["A", "B", "C"]]
        group = Group(name="AB", services=services[:2])
        db.add_all([role, group, *services]); db.flush()
        mapping = OidcClaimMapping(claim_path="custom.groups", expected_value="cats-service", role=role, scope_mode="cats_managed")
        db.add(mapping); db.commit()
        yield db, role, services, group, mapping
    engine.dispose()

def login(db, name, roles=True):
    user = provision_oidc_user(db, {"iss": CONFIG["issuer"], "sub": name, "preferred_username": name,
                                    "custom": {"groups": ["cats-service"] if roles else []}}, CONFIG)
    db.commit()
    return user

def ctx(user):
    return AuthContext(user, SimpleNamespace(csrf_token="csrf"))

def test_shared_role_independent_scope_no_scope_and_role_removal(store):
    db, role, services, _, mapping = store
    alice, bob, nobody = [login(db, name) for name in ["alice", "bob", "nobody"]]
    db.add_all([UserRoleAssignment(user=alice, role=role, service=s, source="cats_scope") for s in services[:2]])
    db.add(UserRoleAssignment(user=bob, role=role, service=services[2], source="cats_scope")); db.commit()
    assert ctx(alice).accessible_service_ids("service.view") == {services[0].id, services[1].id}
    assert not ctx(alice).has("service.view", services[2].id)
    assert ctx(bob).accessible_service_ids("service.view") == {services[2].id}
    assert ctx(nobody).accessible_service_ids("service.view") == set()
    assert not ctx(alice).has("service.view")
    login(db, "alice", roles=False)
    assert ctx(alice).accessible_service_ids("service.view") == set()
    assert len(alice.role_assignments) == 2
    login(db, "alice")
    assert ctx(alice).has("service.view", services[0].id)
    mapping.enabled = False; db.commit()
    assert not ctx(alice).has("service.view", services[0].id)

def test_group_scope_stronger_role_cannot_borrow_scope_and_explicit_global(store):
    db, role, services, group, mapping = store
    alice = login(db, "alice")
    stronger = Role(name="Publisher", permissions=["artifact.publish", "service.view", "audit.view"])
    db.add(stronger); db.flush()
    strong_mapping = OidcClaimMapping(claim_path="custom.groups", expected_value="publisher", role=stronger, scope_mode="cats_managed")
    db.add(strong_mapping); db.flush()
    db.add(OidcRoleEligibility(user=alice, mapping=strong_mapping))
    db.add_all([UserRoleAssignment(user=alice, role=role, group=group, source="cats_scope"),
                UserRoleAssignment(user=alice, role=stronger, service=services[2], source="cats_scope")]); db.commit()
    assert ctx(alice).accessible_service_ids("service.edit") == {s.id for s in services[:2]}
    assert not ctx(alice).has("artifact.publish", services[0].id)
    assert ctx(alice).has("artifact.publish", services[2].id)
    assert not ctx(alice).has("audit.view", services[2].id)
    db.add(UserRoleAssignment(user=alice, role=role, source="cats_scope")); db.commit()
    assert ctx(alice).accessible_service_ids("service.edit") is None
    login(db, "alice", roles=False)
    assert ctx(alice).accessible_service_ids("service.edit") == set()
    recovery = Role(name="Recovery", permissions=["user.manage", "service.view"])
    db.add(UserRoleAssignment(user=alice, role=recovery, source="local")); db.commit()
    assert ctx(alice).has("user.manage")
    assert ctx(alice).accessible_service_ids("service.view") is None

def test_migration_preview_matches_result_and_keeps_local_recovery(store):
    from app.managed_scope import mapping_preview, retire_mapping_projection
    db, role, services, group, mapping = store
    mapping.scope_mode = "fixed"; mapping.global_scope = True; db.commit()
    alice = login(db, "alice")
    db.add(UserRoleAssignment(user=alice, role=role, service=services[0], source="cats_scope")); db.commit()
    proposed = dict(claim_path=mapping.claim_path, expected_value=mapping.expected_value, role_id=role.id,
                    scope_mode="cats_managed", global_scope=False, service_id=None, group_id=None, enabled=True)
    preview = mapping_preview(db, mapping, proposed)
    assert len(preview["users"][0]["before"]["services"]) == 3
    assert [s["name"] for s in preview["users"][0]["after"]["services"]] == ["A"]
    assert ctx(alice).has("service.view", services[2].id)  # preview is read-only
    retire_mapping_projection(db, mapping, preserve_eligibility=True)
    mapping.scope_mode="cats_managed"; mapping.global_scope=False; db.commit()
    assert ctx(alice).accessible_service_ids("service.view") == {services[0].id}

def test_service_plus_group_does_not_expand_selected_service(store):
    db, role, services, group, mapping = store
    role.permissions = [*role.permissions, "config.manage"]
    user = login(db, "alice")
    db.add(UserRoleAssignment(user=user, role=role, service=services[0], group=group, source="cats_scope")); db.commit()
    assert ctx(user).accessible_service_ids("service.view") == {services[0].id}
    assert not ctx(user).has("service.view", services[1].id)
    assert not ctx(user).can_manage_group(group.id)


def test_fixed_mapping_collision_activates_only_its_exact_scope(store):
    db, role, services, group, mapping = store
    user = login(db, "alice")
    db.add_all([UserRoleAssignment(user=user, role=role, service=s, source="cats_scope") for s in services[:2]])
    mapping.scope_mode = "fixed"; mapping.service = services[0]; db.commit()
    login(db, "alice")
    assert ctx(user).accessible_service_ids("service.view") == {services[0].id}
    login(db, "alice", roles=False)
    assert ctx(user).accessible_service_ids("service.view") == set()

@pytest.mark.parametrize("suffix", ["", "/export.xlsx", "/exports/all.zip", "/remediations/plan", "/remediations/job/candidate.zip", "/remediations/job/deliveries/1/bundle.zip"])
def test_direct_http_objects_and_artifacts_reject_other_scope(store, suffix):
    from fastapi.testclient import TestClient
    from app import main
    db, role, services, _, mapping = store
    user = login(db, "alice")
    db.add(UserRoleAssignment(user=user, role=role, service=services[0], source="cats_scope")); db.commit()
    main.app.dependency_overrides[main.get_db] = lambda: db
    main.app.dependency_overrides[main.require_user] = lambda: ctx(user)
    try:
        with TestClient(main.app, follow_redirects=False) as client:
            response = client.get("/services/C" + suffix)
            assert response.status_code == 403
    finally:
        main.app.dependency_overrides.clear()


def test_active_session_observes_scope_changes_without_new_login(store):
    from datetime import timedelta
    from fastapi.testclient import TestClient
    from app import main
    from app.auth import token_hash, utcnow
    from app.models import UserSession
    db, role, services, _, mapping = store
    user = login(db, "alice")
    session = UserSession(user=user, token_hash=token_hash("session-secret"), csrf_token="csrf", expires_at=utcnow() + timedelta(hours=1))
    db.add(session); db.commit()
    main.app.dependency_overrides[main.get_db] = lambda: db
    try:
        with TestClient(main.app, follow_redirects=False) as client:
            client.cookies.set("cats_session", "session-secret")
            path = "/services/C/remediations/plan"
            assert client.get(path).status_code == 403
            grant = UserRoleAssignment(user=user, role=role, service=services[2], source="cats_scope")
            db.add(grant); db.commit()
            # Authorization now passes; this empty fixture has no source scan.
            allowed = client.get(path, headers={"Accept": "application/json"})
            assert allowed.status_code == 422
            assert allowed.json()["detail"] == "No source assessment is available"
            db.delete(grant); db.commit()
            assert client.get(path).status_code == 403
            assert db.get(UserSession, session.id) is not None
    finally:
        main.app.dependency_overrides.clear()


def test_mapping_edit_requires_current_preview_and_explicit_scope(store):
    from fastapi.testclient import TestClient
    from app import main
    db, role, services, _, mapping = store
    mapping.scope_mode = "fixed"; mapping.global_scope = True; db.commit()
    alice = login(db, "alice")
    admin = User(username="admin", display_name="Admin")
    admin_role = Role(name="Administrator", permissions=["config.manage", "role.manage", "user.manage"])
    db.add(UserRoleAssignment(user=admin, role=admin_role)); db.commit()
    main.app.dependency_overrides[main.get_db] = lambda: db
    main.app.dependency_overrides[main.require_user] = lambda: ctx(admin)
    form = dict(csrf_token="csrf", mapping_id=mapping.id, claim_path=mapping.claim_path,
                expected_value=mapping.expected_value, role_id=role.id, scope="cats_managed", enabled="true")
    try:
        with TestClient(main.app, follow_redirects=False) as client:
            endpoint = "/admin/configuration/oidc-mappings"
            assert client.post(endpoint, data=form).status_code == 409
            preview = client.post(endpoint, data={**form, "action": "preview"}).json()
            assert preview["users"][0]["after"]["services"] == []
            assert client.post(endpoint, data={**form, "preview_token": preview["token"]}).status_code == 303
            assert not ctx(alice).has("service.view", services[0].id)
            grant_form = dict(csrf_token="csrf", user_id=alice.id, role_id=role.id, assignment_mode="cats_scope")
            assert client.post("/admin/assignments", data=grant_form).status_code == 422
            assert client.post("/admin/assignments", data={**grant_form, "explicit_global": "true"}).status_code == 303
            assert ctx(alice).accessible_service_ids("service.view") is None
    finally:
        main.app.dependency_overrides.clear()
