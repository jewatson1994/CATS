from datetime import timedelta
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.account_management import PreviewInput, ApplyInput, make_preview, apply_route, preview_route
from app.account_models import AccountRetirement, OidcAccountIdentity
from app.auth import AuthContext, hash_password, oidc_identity_key, provision_oidc_user, verify_password
from app.database import Base
from app.models import AuditEvent, Role, User, UserRoleAssignment, UserSession, utcnow
from app.scan_coordination import ScanJob

ISSUER = "https://provider.example/realms/cats"


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.delenv("CATS_OIDC_ACCOUNT_LINKS", raising=False)
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        role = Role(name="Administrator", permissions=["user.manage", "role.manage", "service.view"])
        viewer = Role(name="Viewer", permissions=["service.view"])
        actor = User(username="operator", display_name="Operator", password_hash=hash_password("a-long-recovery-password"))
        local = User(username="local", display_name="Local", password_hash=hash_password("local-password-retained"))
        source = User(username="duplicate", display_name="Duplicate", auth_source="oidc", external_subject=oidc_identity_key(ISSUER, "subject"))
        db.add_all([role, viewer, actor, local, source]); db.flush()
        db.add_all([UserRoleAssignment(user_id=actor.id, role_id=role.id),
                    UserRoleAssignment(user_id=local.id, role_id=viewer.id),
                    UserRoleAssignment(user_id=source.id, role_id=role.id, source="oidc"),
                    OidcAccountIdentity(identity_key=source.external_subject, issuer=ISSUER, subject="subject", user_id=source.id)])
        session = UserSession(user_id=actor.id, token_hash="actor", csrf_token="csrf", expires_at=utcnow() + timedelta(hours=1))
        db.add(session); db.commit()
        yield db, AuthContext(actor, session), local, source


def preview(db, auth, local, source=None, subject="subject"):
    return json.loads(preview_route(PreviewInput(csrf_token="csrf", survivor_id=local.id,
        source_id=source.id if source else None, issuer=ISSUER, subject=subject, identity_verified=True), db, auth).body)


def apply(db, auth, result, selected=None):
    return apply_route(ApplyInput(csrf_token="csrf", preview_token=result["preview_token"],
        selected_assignment_ids=selected if selected is not None else [r["id"] for r in result["survivor"]["roles"] if r["selectable"]],
        confirmation=result["confirmation"]), db, auth)


def test_prelink_preserves_local_credentials_and_resolves_oidc(setup):
    db, auth, local, _ = setup
    result = preview(db, auth, local, subject="new-subject")
    apply(db, auth, result)
    assert verify_password("local-password-retained", local.password_hash)
    oidc = provision_oidc_user(db, {"iss": ISSUER, "sub": "new-subject", "preferred_username": "different-name"}, {"issuer": ISSUER})
    assert oidc.id == local.id
    assert oidc.auth_source == "local"


def test_merge_retains_history_transfers_ownership_and_revokes_sessions(setup):
    db, auth, local, source = setup
    source_id = source.id
    event = AuditEvent(actor_user_id=source.id, action="historical", target_type="user")
    db.add(event)
    db.add(ScanJob(id="scan", status="complete", payload={"owner_user_id": source.id}, available_at=utcnow()))
    for user in (source, local):
        db.add(UserSession(user_id=user.id, token_hash=str(user.id), csrf_token="x", expires_at=utcnow()+timedelta(hours=1)))
    db.commit()
    result = preview(db, auth, local, source)
    assert result["source"]["historical_references"]["audit_events.actor_user_id"] == 1
    assert not result["source"]["roles"][0]["selectable"]
    apply(db, auth, result)
    assert not source.enabled and source.password_hash is None and source.external_subject is None
    assert db.get(AccountRetirement, source_id).survivor_id == local.id
    assert db.get(AuditEvent, event.id).actor_user_id == source_id
    assert db.get(ScanJob, "scan").payload == {"owner_user_id": local.id, "original_owner_user_id": source_id}
    assert db.scalar(select(func.count(UserSession.id)).where(UserSession.user_id.in_([local.id, source_id]))) == 0
    assert [a.role.name for a in local.role_assignments] == ["Viewer"]
    assert provision_oidc_user(db, {"iss": ISSUER, "sub": "subject", "preferred_username": "duplicate"}, {"issuer": ISSUER}).id == local.id
    assert verify_password("local-password-retained", local.password_hash)
    with pytest.raises(HTTPException, match="Preview expired"):
        apply(db, auth, result)


def test_identity_collision_and_disabled_source_are_rejected(setup):
    db, auth, local, source = setup
    with pytest.raises(HTTPException, match="different account"):
        preview(db, auth, local)
    source.enabled = False; db.commit()
    with pytest.raises(HTTPException, match="disabled source"):
        preview(db, auth, local, source)
    local.enabled = False; db.commit()
    apply(db, auth, preview(db, auth, local, source))
    assert not local.enabled


def test_stale_preview_and_injected_assignments_roll_back(setup):
    db, auth, local, source = setup
    result = preview(db, auth, local, source)
    with pytest.raises(HTTPException, match="selectable"):
        apply(db, auth, result, [auth.user.role_assignments[0].id])
    assert db.get(AccountRetirement, source.id) is None
    assert source.enabled
    # Failed application rolled back the one-shot token claim as well.
    local.display_name = "Changed"; db.commit()
    with pytest.raises(HTTPException, match="changed"):
        apply(db, auth, result)
    assert source.enabled and db.get(OidcAccountIdentity, source.external_subject).user_id == source.id


def test_permissions_and_csrf_and_self_protection(setup):
    db, auth, local, source = setup
    with pytest.raises(HTTPException, match="Another administrator"):
        preview(db, auth, auth.user, subject="new")
    with pytest.raises(HTTPException, match="CSRF"):
        make_preview(db, auth, PreviewInput(csrf_token="bad", survivor_id=local.id, issuer=ISSUER, subject="new", identity_verified=True))
    limited = AuthContext(local, SimpleNamespace(csrf_token="csrf"))
    with pytest.raises(HTTPException, match="Global account"):
        preview(db, limited, local, source)


def test_last_recovery_guard_rolls_back_every_mutation(setup):
    db, auth, local, source = setup
    # Simulate an authorized OIDC administrator; only the local survivor is a
    # password-backed recovery admin. Dropping its role must be atomic failure.
    auth.user.password_hash = None
    local.role_assignments[0].role_id = auth.user.role_assignments[0].role_id
    db.commit(); db.expire_all()
    result = preview(db, auth, local, source)
    with pytest.raises(HTTPException, match="last usable"):
        apply(db, auth, result, [])
    assert db.get(AccountRetirement, source.id) is None
    assert source.enabled
    assert db.get(OidcAccountIdentity, source.external_subject).user_id == source.id
    assert local.role_assignments[0].role.name == "Administrator"


def test_split_global_roles_preserve_last_recovery_admin(setup):
    db, auth, local, source = setup
    auth.user.password_hash = None
    users_role = Role(name="Account manager", permissions=["user.manage"])
    roles_role = Role(name="Role manager", permissions=["role.manage"])
    db.add_all([users_role, roles_role]); db.flush()
    local.role_assignments[0].role_id = users_role.id
    db.add(UserRoleAssignment(user_id=local.id, role_id=roles_role.id, source="local"))
    db.commit(); db.expire_all()
    result = preview(db, auth, local, source)
    keep_account_management = [a.id for a in local.role_assignments if a.role_id == users_role.id]
    with pytest.raises(HTTPException, match="last usable"):
        apply(db, auth, result, keep_account_management)
    assert db.get(AccountRetirement, source.id) is None
    assert source.enabled
    assert {a.role.name for a in local.role_assignments} == {"Account manager", "Role manager"}


def test_password_removal_invalidates_preview(setup):
    db, auth, local, source = setup
    result = preview(db, auth, local, source)
    local.password_hash = None; db.commit()
    with pytest.raises(HTTPException, match="changed"):
        apply(db, auth, result)
    assert db.get(AccountRetirement, source.id) is None


def test_active_owned_scan_blocks_merge(setup):
    db, auth, local, source = setup
    db.add(ScanJob(id="active", status="running", payload={"owner_user_id": source.id}, available_at=utcnow())); db.commit()
    with pytest.raises(HTTPException, match="scans to finish"):
        preview(db, auth, local, source)


def test_disabled_prelink_never_reactivates(setup):
    db, auth, local, _ = setup
    local.enabled = False; db.commit()
    apply(db, auth, preview(db, auth, local, subject="disabled"))
    user = provision_oidc_user(db, {"iss": ISSUER, "sub": "disabled", "preferred_username": "local"}, {"issuer": ISSUER})
    assert user.id == local.id and not user.enabled


def test_retirement_guard_denies_even_a_stale_reenabled_session(setup):
    from starlette.requests import Request
    from starlette.responses import Response
    from app.auth import optional_user, require_user, token_hash
    db, auth, local, source = setup
    apply(db, auth, preview(db, auth, local, source))
    source.enabled = True  # Defense against a stale worker or direct DB edit.
    db.add(UserSession(user_id=source.id, token_hash=token_hash("old-token"), csrf_token="stale", expires_at=utcnow()+timedelta(hours=1)))
    db.commit()
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [(b"cookie", b"cats_session=old-token")], "scheme": "https", "server": ("cats.example", 443)})
    assert optional_user(request, db) is None
    with pytest.raises(HTTPException) as denied:
        require_user(request, Response(), db)
    assert denied.value.status_code == 303
    with pytest.raises(ValueError, match="Retired"):
        provision_oidc_user(db, {"iss": ISSUER, "sub": "another", "preferred_username": source.username},
                            {"issuer": ISSUER, "account_links": {ISSUER: {"another": source.username}}})


def test_http_routes_enforce_privilege_csrf_and_reviewed_changes(setup):
    import asyncio
    import httpx
    from fastapi import FastAPI
    from app.account_management import router
    from app.auth import require_user
    from app.database import get_db
    db, auth, local, source = setup
    app = FastAPI(); app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_user] = lambda: auth
    body = dict(csrf_token="csrf", survivor_id=local.id, source_id=source.id,
                issuer=ISSUER, subject="subject", identity_verified=True)

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/admin/accounts/preview", json={**body, "csrf_token": "bad"})
            assert response.status_code == 403
            app.dependency_overrides[require_user] = lambda: AuthContext(local, SimpleNamespace(csrf_token="csrf"))
            assert (await client.post("/api/admin/accounts/preview", json=body)).status_code == 403
            app.dependency_overrides[require_user] = lambda: auth
            result = (await client.post("/api/admin/accounts/preview", json=body)).json()
            response = await client.post("/api/admin/accounts/apply", json=dict(csrf_token="csrf",
                preview_token=result["preview_token"], selected_assignment_ids=[], confirmation=result["confirmation"]))
            assert response.status_code == 200
            assert response.json()["retired_id"] == source.id
    asyncio.run(exercise())
