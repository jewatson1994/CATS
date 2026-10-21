from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.auth import AuthContext, SYSTEM_ROLES
from app.database import Base
from app.main import assign_role, remove_assignment, manageable_groups, scoped_role_allowed, scoped_assignment_visible, stage_service
from app.models import Group, Role, User, UserRoleAssignment, UserSession, utcnow


@pytest.fixture
def setup():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        actor = User(username='cyber', display_name='Cyber')
        target = User(username='target', display_name='Target')
        group, other = Group(name='one'), Group(name='other')
        cyber = Role(name='Cybersecurity', system=True, permissions=SYSTEM_ROLES['Cybersecurity'])
        assessor = Role(name='Assessor', system=True, permissions=SYSTEM_ROLES['Assessor'])
        manager = Role(name='Service Manager', system=True, permissions=SYSTEM_ROLES['Service Manager'])
        db.add_all([actor, target, group, other, cyber, assessor, manager]); db.flush()
        db.add_all([UserRoleAssignment(user_id=actor.id, role_id=cyber.id, group_id=group.id),
                    UserRoleAssignment(user_id=target.id, role_id=assessor.id, group_id=group.id)])
        session = UserSession(user_id=actor.id, token_hash='token', csrf_token='csrf', expires_at=utcnow()+timedelta(hours=1))
        db.add(session); db.commit()
        yield db, AuthContext(actor, session), target, group, other, assessor, manager


def assign(setup, **overrides):
    db, auth, target, group, other, assessor, manager = setup
    values = dict(user_id=target.id, role_id=manager.id, service_ids=[], service_id='', group_id=str(group.id),
                  assignment_mode='local', explicit_global=False, csrf_token='csrf', db=db, auth=auth)
    values.update(overrides)
    return assign_role(**values)


def test_group_assignment_and_revocation(setup):
    db, auth, target, group, _, _, manager = setup
    assert assign(setup).status_code == 303
    grant = db.scalar(select(UserRoleAssignment).where(UserRoleAssignment.user_id == target.id, UserRoleAssignment.role_id == manager.id))
    assert grant.group_id == group.id
    assert remove_assignment(grant.id, 'csrf', db, auth).status_code == 303


@pytest.mark.parametrize('change', ['global', 'foreign', 'oidc', 'elevated', 'unclaimed'])
def test_scope_and_delegation_rejections(setup, change):
    db, auth, target, group, other, assessor, manager = setup
    kwargs = {}
    if change == 'global': kwargs['group_id'] = ''
    if change == 'foreign': kwargs['group_id'] = str(other.id)
    if change == 'oidc': kwargs['assignment_mode'] = 'cats_scope'
    if change == 'elevated':
        role = Role(name='Custom administrator', permissions=['user.manage']); db.add(role); db.commit()
        kwargs['role_id'] = role.id
    if change == 'unclaimed':
        user = User(username='new', display_name='New'); db.add(user); db.commit(); kwargs['user_id'] = user.id
    with pytest.raises(HTTPException) as exc:
        assign(setup, **kwargs)
    assert exc.value.status_code in (403, 422)


def test_global_permissions_and_group_visibility(setup):
    db, auth, target, group, other, assessor, manager = setup
    assert scoped_role_allowed(auth, assessor, group.id)
    assert not scoped_role_allowed(auth, Role(name='Audit clone', permissions=SYSTEM_ROLES['Assessor']), group.id)
    assert not scoped_assignment_visible(UserRoleAssignment(group_id=other.id), {group.id})
    assert not scoped_assignment_visible(UserRoleAssignment(), {group.id})
    assert [g.id for g in manageable_groups(db, auth)] == [group.id]
    auth.user.role_assignments[0].group_id = None
    assert {g.id for g in manageable_groups(db, auth)} == {group.id, other.id}


def test_oidc_managed_grant_cannot_be_removed(setup):
    db, auth, target, group, _, assessor, _ = setup
    grant = target.role_assignments[0]; grant.source = 'oidc'; db.commit()
    with pytest.raises(HTTPException) as exc:
        remove_assignment(grant.id, 'csrf', db, auth)
    assert exc.value.status_code == 409


def test_single_group_staging_rejects_supplied_foreign_group(setup):
    db, auth, _, _, other, _, _ = setup
    with pytest.raises(HTTPException) as exc:
        stage_service('new-service', str(other.id), 'csrf', '/admin/staging', db, auth)
    assert exc.value.status_code == 403

def test_canonical_cyber_role_delegation_stays_in_group(setup):
    db, auth, target, group, other, _, _ = setup
    cyber = db.scalar(select(Role).where(Role.name == 'Cybersecurity'))
    assert assign(setup, role_id=cyber.id).status_code == 303
    with pytest.raises(HTTPException) as exc:
        assign(setup, role_id=cyber.id, group_id=str(other.id))
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        assign(setup, role_id=cyber.id, group_id='')
    assert exc.value.status_code == 403


def test_admin_context_hides_foreign_grants_and_accounts(setup, monkeypatch):
    from starlette.requests import Request
    from app import main
    from app.account_models import OidcAccountIdentity
    db, auth, target, group, other, assessor, manager = setup
    outsider = User(username='outside', display_name='Outside')
    target.password_hash = 'present'
    db.add(outsider); db.flush()
    db.add_all([UserRoleAssignment(user_id=outsider.id, role_id=assessor.id, group_id=other.id),
                UserRoleAssignment(user_id=target.id, role_id=manager.id, group_id=other.id),
                OidcAccountIdentity(identity_key='identity', issuer='https://issuer', subject='subject', user_id=target.id)])
    db.commit()
    monkeypatch.setattr(main.templates, 'TemplateResponse', lambda request, template, context: context)
    result = main.admin_page(Request({'type':'http', 'query_string':b''}), db, auth)
    assert outsider.id not in {user.id for user in result['users']}
    row = next(row for row in result['user_rows'] if row['user'].id == target.id)
    assert len(row['assignments']) == 1
    assert row['assignments'][0]['group'] == group.name
    assert row['application_permissions'] == [] and row['eligibility'] == []
    assert row['sign_in_methods'] == ['local', 'oidc']
    assert {g.id for g in result['groups']} == {group.id}
