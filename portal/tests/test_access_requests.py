from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from app.access_requests import (ClaimInput, claim_route, register_pending_request,
    list_pending_requests, authorized_claim_groups)
from app.account_models import AccountAccessRequest, AccountRetirement
from app.auth import AuthContext, SYSTEM_ROLES
from app.database import Base
from app.models import Group, Role, User, UserRoleAssignment, UserSession, AuditEvent, utcnow


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
        db.add_all([actor, target, group, other, cyber, assessor]); db.flush()
        grant = UserRoleAssignment(user_id=actor.id, role_id=cyber.id, group_id=group.id)
        session = UserSession(user_id=actor.id, token_hash="token", csrf_token="csrf", expires_at=utcnow()+timedelta(hours=1))
        db.add_all([grant, session]); db.commit()
        auth = AuthContext(actor, session)
        register_pending_request(db, AuthContext(target, session)); db.commit()
        yield db, auth, target, group, other, grant


def claim(db, auth, target, **kwargs):
    return claim_route(target.id, ClaimInput(csrf_token="csrf", **kwargs), db, auth)


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
