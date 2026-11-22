from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from app import imported_services  # Register provenance tables used by scoped permission checks.
from app.access_requests import (ClaimInput, claim_route, register_pending_request,
    list_pending_requests, authorized_claim_groups, pending_route)
from app.account_models import AccountAccessRequest, AccountRetirement, ServiceAccessRequest
from app.auth import AuthContext, SYSTEM_ROLES
from app.database import Base
from app.models import Group, Role, Service, User, UserRoleAssignment, UserSession, AuditEvent, utcnow


@pytest.fixture
def setup():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        actor = User(username="cyber", display_name="Cyber")
        target = User(username="new", display_name="New")
        group = Group(name="one")
        other = Group(name="other")
        cyber = Role(name="Cybersecurity", system=True, permissions=SYSTEM_ROLES["Cybersecurity"])
        assessor = Role(name="Assessor", system=True, permissions=SYSTEM_ROLES["Assessor"])
        manager = Role(name="Service Manager", system=True, permissions=SYSTEM_ROLES["Service Manager"])
        db.add_all([actor, target, group, other, cyber, assessor, manager]); db.flush()
        grant = UserRoleAssignment(user_id=actor.id, role_id=cyber.id, group_id=group.id)
        session = UserSession(user_id=actor.id, token_hash="token", csrf_token="csrf", expires_at=utcnow()+timedelta(hours=1))
        db.add_all([grant, session]); db.commit()
        auth = AuthContext(actor, session)
        register_pending_request(db, AuthContext(target, session)); db.commit()
        yield db, auth, target, group, other, grant


def claim(db, auth, target, **kwargs):
    return claim_route(target.id, ClaimInput(csrf_token="csrf", **kwargs), db, auth)


@pytest.mark.parametrize("identity", ["oidc", "linked-local"])
def test_generic_request_cannot_grant_group_access_after_identity_link(setup, identity):
    db, auth, target, group, _, _ = setup
    if identity == "oidc":
        target.auth_source = "oidc"
    target.external_subject = "linked-subject"
    db.commit()
    assert db.get(AccountAccessRequest, target.id).status == "pending"
    assert list_pending_requests(db, auth) == []
    with pytest.raises(HTTPException, match="Select a pending service request"):
        claim(db, auth, target, group_id=group.id)
    assert not db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id == target.id)).all()


def test_deduplicated_request_bell_and_single_group_claim(setup):
    db, auth, target, group, _, _ = setup
    register_pending_request(db, AuthContext(target, auth.session)); db.commit()
    assert db.scalar(select(func.count()).select_from(AccountAccessRequest)) == 1
    assert list_pending_requests(db, auth)[0]["user_id"] == target.id
    result = claim(db, auth, target)
    assert result["group_id"] == group.id and result["role"] == "Assessor"
    assert list_pending_requests(db, auth) == []
    grants = db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id == target.id)).all()
    assert len(grants) == 1 and grants[0].role.name == "Assessor" and grants[0].source == "local"
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "account.access_claimed"))
    with pytest.raises(HTTPException) as exc:
        claim(db, auth, target)
    assert exc.value.status_code == 409


def test_cross_group_and_csrf_rejected(setup):
    db, auth, target, _, other, _ = setup
    with pytest.raises(HTTPException) as exc:
        claim(db, auth, target, group_id=other.id)
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        claim_route(target.id, ClaimInput(csrf_token="bad"), db, auth)
    assert exc.value.status_code == 403
    assert db.get(AccountAccessRequest, target.id).status == "pending"


def test_multiple_groups_require_selection_and_global_cyber_gets_all(setup):
    db, auth, target, _, other, grant = setup
    grant.group_id = None; db.commit()
    assert len(authorized_claim_groups(db, auth)) == 2
    with pytest.raises(HTTPException) as exc:
        claim(db, auth, target)
    assert exc.value.status_code == 422
    assert claim(db, auth, target, group_id=other.id)["group_id"] == other.id


def test_notification_requires_actual_cyber_role_and_no_descendant_scope(setup):
    db, auth, target, group, other, _ = setup
    other.parent_id = group.id
    db.commit()
    assert [item.id for item in authorized_claim_groups(db, auth)] == [group.id]
    assert list_pending_requests(db, AuthContext(target, auth.session)) == []
    with pytest.raises(HTTPException) as exc:
        claim(db, auth, target, group_id=other.id)
    assert exc.value.status_code == 403


def test_pending_target_with_new_access_cannot_be_claimed(setup):
    db, auth, target, group, _, _ = setup
    role = db.scalar(select(Role).where(Role.name == "Assessor"))
    db.add(UserRoleAssignment(user_id=target.id, role_id=role.id, group_id=group.id))
    db.commit()
    assert list_pending_requests(db, auth) == []
    with pytest.raises(HTTPException) as exc:
        claim(db, auth, target)
    assert exc.value.status_code == 409


@pytest.mark.parametrize("reason", ["disabled", "retired", "revoked", "custom_role", "privileged_assessor"])
def test_unavailable_targets_or_stale_privilege_rejected(setup, reason):
    db, auth, target, _, _, grant = setup
    if reason == "disabled":
        target.enabled = False
    elif reason == "retired":
        db.add(AccountRetirement(user_id=target.id, survivor_id=auth.user.id, administrator_id=auth.user.id))
    elif reason == "revoked":
        db.delete(grant)
    elif reason == "custom_role":
        grant.role.system = False
    else:
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        role.permissions = ["role.manage"]
    db.commit()
    with pytest.raises(HTTPException) as exc:
        claim(db, auth, target)
    assert exc.value.status_code in {403, 409}
    assert db.get(AccountAccessRequest, target.id).status == "pending"


def request_for_service(db, target, group):
    service = Service(name="Requested service", service_key="requested", groups=[group])
    db.add(service)
    db.flush()
    db.add(ServiceAccessRequest(user_id=target.id, service_id=service.id))
    db.commit()
    return service


@pytest.mark.parametrize(("name", "permission"), [
    ("Service Manager", "remediation.execute"),
    ("Cybersecurity", "approval.decide"),
])
def test_selected_service_role_is_scoped_audited_and_cannot_be_replayed(setup, name, permission):
    db, auth, target, group, _, _ = setup
    service = request_for_service(db, target, group)
    sibling = Service(name="Another service", service_key="another", groups=[group])
    db.add(sibling)
    db.commit()
    options = pending_route(db, auth)["roles"]
    assert [option["name"] for option in options] == ["Assessor", "Service Manager", "Cybersecurity"]
    role_id = next(option["id"] for option in options if option["name"] == name)
    result = claim(db, auth, target, service_id=service.id, role_id=role_id)
    assert result["role"] == name and result["status"] == "claimed"
    assignments = db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id == target.id)).all()
    assert [(a.role_id, a.service_id, a.group_id, a.source) for a in assignments] == [
        (role_id, service.id, None, "local")]
    recipient = AuthContext(target, auth.session)
    assert recipient.has(permission, service.id)
    assert not recipient.has(permission, sibling.id) and not recipient.has(permission)
    assert not recipient.has("role.manage") and not recipient.has("validator.provision", service.id)
    assert not db.get(ServiceAccessRequest, (target.id, service.id))
    event = db.scalars(select(AuditEvent).where(AuditEvent.action == "account.service_access_claimed")).one()
    assert event.actor_user_id == auth.user.id
    assert (event.detail["role_id"], event.detail["service_id"]) == (role_id, service.id)
    with pytest.raises(HTTPException) as replay:
        claim(db, auth, target, service_id=service.id, role_id=role_id)
    assert replay.value.status_code == 409


@pytest.mark.parametrize("existing_role", ["Assessor", "Service Manager"])
def test_preexisting_group_access_is_checked_against_selected_service_role(setup, existing_role):
    db, auth, target, group, _, _ = setup
    service = request_for_service(db, target, group)
    existing = db.scalar(select(Role).where(Role.name == existing_role))
    manager = db.scalar(select(Role).where(Role.name == "Service Manager"))
    db.add(UserRoleAssignment(user=target, role=existing, group=group))
    db.commit()
    result = claim(db, auth, target, service_id=service.id, role_id=manager.id)
    scoped = db.scalars(select(UserRoleAssignment).where(
        UserRoleAssignment.user_id == target.id, UserRoleAssignment.service_id == service.id)).all()
    if existing_role == "Assessor":
        assert result["status"] == "claimed" and [a.role_id for a in scoped] == [manager.id]
    else:
        assert result["status"] == "already_granted" and not scoped
    group_grants = db.scalars(select(UserRoleAssignment).where(
        UserRoleAssignment.user_id == target.id, UserRoleAssignment.group_id == group.id)).all()
    assert [grant.role_id for grant in group_grants] == [existing.id]
    assert AuthContext(target, auth.session).has("service.edit", service.id)
    assert not db.get(ServiceAccessRequest, (target.id, service.id))


def test_claim_without_role_preserves_existing_service_access(setup):
    db, auth, target, group, _, _ = setup
    service = request_for_service(db, target, group)
    manager = db.scalar(select(Role).where(Role.name == "Service Manager"))
    db.add(UserRoleAssignment(user=target, role=manager, group=group))
    db.commit()
    result = claim(db, auth, target, service_id=service.id)
    assert result["status"] == "already_granted"
    assert [(a.role_id, a.group_id, a.service_id) for a in target.role_assignments] == [(manager.id, group.id, None)]


def test_general_request_grants_selected_role_only_for_reviewers_group(setup):
    db, auth, target, group, _, _ = setup
    role = db.scalar(select(Role).where(Role.name == "Service Manager"))
    result = claim(db, auth, target, group_id=group.id, role_id=role.id)
    assert result["role"] == role.name and result["group_id"] == group.id
    assignment = db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id == target.id)).one()
    assert (assignment.role_id, assignment.group_id, assignment.service_id) == (role.id, group.id, None)


@pytest.mark.parametrize("forgery", ["custom", "altered", "administrator", "outside", "user_admin_only", "reduced_reviewer"])
def test_unauthorized_role_or_scope_keeps_request_pending(setup, forgery):
    db, auth, target, group, other, grant = setup
    service = request_for_service(db, target, other if forgery == "outside" else group)
    role = db.scalar(select(Role).where(Role.name == "Service Manager"))
    if forgery == "custom":
        role = Role(name="Manager clone", permissions=SYSTEM_ROLES["Service Manager"], system=False)
        db.add(role)
    elif forgery == "altered":
        role.permissions = [*role.permissions, "user.manage"]
    elif forgery == "administrator":
        role = Role(name="Administrator", permissions=SYSTEM_ROLES["Administrator"], system=True)
        db.add(role)
    elif forgery == "reduced_reviewer":
        grant.role.permissions = ["service.view"]
    elif forgery == "user_admin_only":
        grant.role = Role(name="Account operator", permissions=["user.manage"], system=False)
        grant.group_id = None
    db.commit()
    with pytest.raises(HTTPException) as rejected:
        claim(db, auth, target, service_id=service.id, role_id=role.id)
    assert rejected.value.status_code in (403, 409, 422)
    assert db.get(ServiceAccessRequest, (target.id, service.id))
    assert not target.role_assignments


def test_service_only_cyber_cannot_review_another_account(setup):
    db, auth, target, group, _, grant = setup
    service = Service(name="Scoped service", service_key="scoped", groups=[group])
    db.add(service)
    grant.service = service
    grant.group_id = None
    db.commit()
    assert list_pending_requests(db, auth) == []
    request = ServiceAccessRequest(user_id=target.id, service_id=service.id)
    db.add(request)
    db.commit()
    assert list_pending_requests(db, auth) == []
    with pytest.raises(HTTPException) as denied:
        claim(db, auth, target, service_id=service.id, role_id=grant.role_id)
    assert denied.value.status_code == 403
    assert db.get(ServiceAccessRequest, (target.id, service.id))
