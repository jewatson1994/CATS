"""Owning-group pull policy persistence, scope enforcement, and live resolution."""
import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import oci_admin, oci_group_policy as policy
from app.auth import AuthContext, require_user
from app.database import Base, get_db
from app.imported_services import is_imported_service
from app.models import AuditEvent, Group, PortalSetting, Service, ServiceGroup
from app.operating_mode import ReplicaModeMiddleware
from app.replica_models import ReplicaRecordMap


@pytest.fixture
def context():
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        groups = [Group(name='A'), Group(name='B'), Group(name='Child')]
        services = [Service(name=name, service_key=name) for name in ('a', 'b', 'unowned')]
        db.add_all([*groups, *services])
        db.flush()
        groups[2].parent_id = groups[0].id
        db.add_all([ServiceGroup(service_id=services[0].id, group_id=groups[0].id),
                    ServiceGroup(service_id=services[1].id, group_id=groups[1].id)])
        db.commit()
        assignment = SimpleNamespace(role=SimpleNamespace(permissions=['config.manage']),
                                     service_id=None, group_id=None)
        auth = AuthContext(user=SimpleNamespace(id=None, username='policy-admin',
            display_name='Policy Admin', role_assignments=[assignment]),
            session=SimpleNamespace(csrf_token='csrf'))
        app = FastAPI()
        app.include_router(oci_admin.router)
        app.add_middleware(ReplicaModeMiddleware)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[require_user] = lambda: auth
        with TestClient(app) as client:
            yield SimpleNamespace(db=db, groups=groups, services=services, auth=auth,
                                  assignment=assignment, client=client)
    engine.dispose()


def url(group):
    return f'/api/oci/pull-policy?group_id={group.id}'


def save(context, value, group=None, *, csrf='csrf'):
    return context.client.put(url(group or context.groups[0]), json=value,
                              headers={'X-CSRF-Token': csrf})


def test_default_is_approval_only_and_group_admin_needs_no_registry_permission(context):
    c = context
    c.assignment.group_id = c.groups[0].id
    response = c.client.get(url(c.groups[0]))
    assert response.status_code == 200, response.text
    assert response.json() == {'group_id': c.groups[0].id, 'policy': policy.DEFAULT_POLICY, 'is_default': True}
    assert response.headers['Cache-Control'] == 'private, no-store'
    assert policy.policy_for_service(c.db, c.services[0].id) == {
        **policy.DEFAULT_POLICY, 'group_id': c.groups[0].id}
    assert policy.policy_for_service(c.db, c.services[2].id) == {**policy.DEFAULT_POLICY, 'group_id': None}
    assert c.client.get('/api/oci/upstreams').status_code == 403


@pytest.mark.parametrize('mode', ['approved_release', 'compliance', 'both'])
def test_save_is_scoped_audited_and_immediately_resolved(context, mode):
    c = context
    c.assignment.group_id = c.groups[0].id
    value = {**policy.DEFAULT_POLICY, 'mode': mode, 'max_scan_age_days': 30}
    response = save(c, value)
    assert response.status_code == 200, response.text
    assert response.json() == {'group_id': c.groups[0].id, 'policy': value, 'is_default': False}
    assert response.headers['Cache-Control'] == 'private, no-store'
    assert c.client.get(url(c.groups[0])).json()['policy'] == value
    assert policy.policy_for_service(c.db, c.services[0].id) == {**value, 'group_id': c.groups[0].id}
    assert policy.policy_for_service(c.db, c.services[1].id)['mode'] == 'approved_release'
    row = c.db.scalar(select(PortalSetting).where(PortalSetting.key.like("group:%:oci_pull_policy")))
    assert row.key == f'group:{c.groups[0].id}:oci_pull_policy' and row.group_id == c.groups[0].id
    event = c.db.scalar(select(AuditEvent))
    assert event.action == 'oci.group_pull_policy.updated' and event.target_id == str(c.groups[0].id)
    assert event.detail['previous_policy'] == policy.DEFAULT_POLICY and event.detail['policy'] == value


def test_other_groups_parent_groups_and_service_assignments_do_not_grant_policy_authority(context):
    c = context
    c.assignment.group_id = c.groups[0].id
    for group in c.groups[1:]:
        assert c.client.get(url(group)).status_code == 403
        assert save(c, policy.DEFAULT_POLICY, group).status_code == 403
    c.assignment.service_id = c.services[0].id
    assert c.client.get(url(c.groups[0])).status_code == 403
    assert save(c, policy.DEFAULT_POLICY).status_code == 403
    c.assignment.service_id = None
    c.assignment.role.permissions = ['release.destination.manage']
    assert c.client.get(url(c.groups[0])).status_code == 403
    assert save(c, policy.DEFAULT_POLICY).status_code == 403
    assert c.db.scalar(select(PortalSetting.id).where(PortalSetting.key.like("group:%:oci_pull_policy"))) is None
    assert c.db.scalar(select(AuditEvent.id)) is None


def test_csrf_required_and_nonexistent_group_rejected(context):
    c = context
    assert save(c, policy.DEFAULT_POLICY, csrf='bad').status_code == 403
    assert c.client.put(url(c.groups[0]), json=policy.DEFAULT_POLICY).status_code == 403
    assert c.client.get('/api/oci/pull-policy?group_id=99999').status_code == 404
    assert c.client.put('/api/oci/pull-policy?group_id=99999', json=policy.DEFAULT_POLICY,
                        headers={'X-CSRF-Token': 'csrf'}).status_code == 404
    assert c.db.scalar(select(PortalSetting.id).where(PortalSetting.key.like("group:%:oci_pull_policy"))) is None


@pytest.mark.parametrize('operating_mode', ['full', 'replica'])
def test_local_policy_write_keeps_auth_scope_and_csrf_checks_in_both_modes(context, monkeypatch, operating_mode):
    c = context
    monkeypatch.setenv('CATS_MODE', operating_mode)
    c.assignment.group_id = c.groups[0].id
    value = {**policy.DEFAULT_POLICY, 'mode': 'compliance'}
    response = save(c, value)
    assert response.status_code == 200, response.text
    assert policy.policy_for_service(c.db, c.services[0].id) == {**value, 'group_id': c.groups[0].id}
    assert c.client.get(url(c.groups[0])).json()['policy'] == value
    event = c.db.scalar(select(AuditEvent))
    assert event.action == 'oci.group_pull_policy.updated' and event.detail['policy'] == value

    for response in (save(c, policy.DEFAULT_POLICY, c.groups[1]),
                     save(c, policy.DEFAULT_POLICY, csrf='bad'),
                     c.client.put(url(c.groups[0]), json=policy.DEFAULT_POLICY)):
        assert response.status_code == 403, response.text
        # The allowed local endpoint must still apply its own authorization.
        assert response.json().get('code') != 'replica_read_only'
    assert c.client.get(url(c.groups[1])).status_code == 403

    del c.client.app.dependency_overrides[require_user]
    response = c.client.put(url(c.groups[0]), json=policy.DEFAULT_POLICY,
                            headers={'X-CSRF-Token': 'csrf'}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'].startswith('/login')
    assert policy.policy_for_service(c.db, c.services[0].id)['mode'] == 'compliance'
    assert len(c.db.scalars(select(PortalSetting).where(PortalSetting.key.like("group:%:oci_pull_policy"))).all()) == 1
    assert len(c.db.scalars(select(AuditEvent)).all()) == 1


@pytest.mark.parametrize('method,path', [
    ('POST', '/api/oci/pull-policy'), ('PATCH', '/api/oci/pull-policy'),
    ('PUT', '/api/oci/pull-policy/extra'),
])
def test_replica_policy_write_allowlist_remains_exact(context, monkeypatch, method, path):
    monkeypatch.setenv('CATS_MODE', 'replica')
    response = context.client.request(method, path, json=policy.DEFAULT_POLICY,
                                      headers={'X-CSRF-Token': 'csrf'})
    assert response.status_code == 403
    assert response.json()['code'] == 'replica_read_only'
    assert context.db.scalar(select(PortalSetting.id).where(PortalSetting.key.like("group:%:oci_pull_policy"))) is None
    assert context.db.scalar(select(AuditEvent.id)) is None


@pytest.mark.parametrize('suffix', ['', '?group_id=0', '?group_id=-1', '?group_id=abc', '?group_id=1.5'])
def test_group_scope_must_be_an_explicit_positive_integer(context, suffix):
    assert context.client.get('/api/oci/pull-policy' + suffix).status_code == 422
    assert context.client.put('/api/oci/pull-policy' + suffix, json=policy.DEFAULT_POLICY,
                              headers={'X-CSRF-Token': 'csrf'}).status_code == 422


@pytest.mark.parametrize('value', [None, [], {}, False,
    {**policy.DEFAULT_POLICY, 'extra': True},
    {**policy.DEFAULT_POLICY, 'mode': 'either'},
    {**policy.DEFAULT_POLICY, 'mode': True},
    {**policy.DEFAULT_POLICY, 'blocked_severity': 'critical'},
    {**policy.DEFAULT_POLICY, 'blocked_severity': []},
    {**policy.DEFAULT_POLICY, 'require_service_compliant': 'false'},
    {**policy.DEFAULT_POLICY, 'require_service_compliant': 0},
    {**policy.DEFAULT_POLICY, 'max_scan_age_days': True},
    {**policy.DEFAULT_POLICY, 'max_scan_age_days': 0},
    {**policy.DEFAULT_POLICY, 'max_scan_age_days': 3651},
    {**policy.DEFAULT_POLICY, 'max_scan_age_days': 1.5},
    {**policy.DEFAULT_POLICY, 'mode': 'compliance', 'blocked_severity': 'None'},
    {**policy.DEFAULT_POLICY, 'mode': 'both', 'blocked_severity': 'None'},
])
def test_malformed_policy_never_saves(context, value):
    response = save(context, value)
    assert response.status_code == 422, response.text
    assert context.db.scalar(select(PortalSetting.id).where(PortalSetting.key.like("group:%:oci_pull_policy"))) is None


def test_service_compliance_rule_can_be_used_without_severity_threshold(context):
    value = {**policy.DEFAULT_POLICY, 'mode': 'both', 'blocked_severity': 'None',
             'require_service_compliant': True}
    assert save(context, value).status_code == 200


@pytest.mark.parametrize('raw', ['not-json', 'null', '[]', '{}', '{"mode":"compliance"}'])
def test_invalid_retained_policy_fails_closed_and_can_be_repaired(context, raw):
    c = context
    c.db.add(PortalSetting(key=f'group:{c.groups[0].id}:oci_pull_policy', group_id=c.groups[0].id, value=raw))
    c.db.commit()
    with pytest.raises(ValueError, match='policy is invalid'):
        policy.policy_for_service(c.db, c.services[0].id)
    assert c.client.get(url(c.groups[0])).status_code == 409
    assert save(c, policy.DEFAULT_POLICY).status_code == 200
    assert policy.policy_for_service(c.db, c.services[0].id)['mode'] == 'approved_release'
    assert c.db.scalar(select(AuditEvent)).detail['previous_policy'] is None


def test_fresh_group_assignment_and_setting_values_override_loaded_relationships(context):
    c = context
    assert c.services[0].groups[0].id == c.groups[0].id
    value = {**policy.DEFAULT_POLICY, 'mode': 'both', 'blocked_severity': 'High'}
    assert save(c, value, c.groups[1]).status_code == 200
    c.db.execute(update(ServiceGroup).where(ServiceGroup.service_id == c.services[0].id)
                 .values(group_id=c.groups[1].id))
    c.db.flush()
    assert policy.policy_for_service(c.db, c.services[0].id) == {**value, 'group_id': c.groups[1].id}
    row = c.db.scalar(select(PortalSetting).where(PortalSetting.key.like("group:%:oci_pull_policy")))
    value['blocked_severity'] = 'Low'
    c.db.execute(update(PortalSetting).where(PortalSetting.id == row.id)
                 .values(value=json.dumps(value)).execution_options(synchronize_session=False))
    c.db.flush()
    assert policy.policy_for_service(c.db, c.services[0].id)['blocked_severity'] == 'Low'


def test_conflicting_legacy_group_ownership_is_not_resolved_to_less_restrictive_policy(context):
    c = context
    # Legacy databases may predate the unique owning-group constraint.
    c.db.execute(text('DROP TABLE service_groups'))
    c.db.execute(text('CREATE TABLE service_groups (service_id INTEGER, group_id INTEGER)'))
    for group in c.groups[:2]:
        c.db.execute(text('INSERT INTO service_groups (service_id, group_id) VALUES (:service, :group)'),
                     {'service': c.services[0].id, 'group': group.id})
    c.db.flush()
    with pytest.raises(ValueError, match='conflicting owning groups'):
        policy.policy_for_service(c.db, c.services[0].id)


def test_local_rules_do_not_inherit_parent_or_unscoped_publisher_settings(context):
    c = context
    value = {**policy.DEFAULT_POLICY, 'mode': 'compliance'}
    assert save(c, value).status_code == 200
    c.db.add(PortalSetting(key='oci_pull_policy', value=json.dumps(value)))
    c.db.execute(update(ServiceGroup).where(ServiceGroup.service_id == c.services[0].id)
                 .values(group_id=c.groups[2].id))
    c.db.commit()
    assert policy.policy_for_service(c.db, c.services[0].id)['mode'] == 'approved_release'
    assert policy.policy_for_service(c.db, c.services[2].id)['mode'] == 'approved_release'


def test_imported_service_uses_local_group_rule_instead_of_publisher_configuration(context, monkeypatch):
    from app import main
    c = context
    c.db.add(ReplicaRecordMap(service_id=c.services[0].id, table_name='services',
                             source_id=17, local_id=c.services[0].id))
    c.db.commit()
    assert is_imported_service(c.db, c.services[0].id)
    value = {**policy.DEFAULT_POLICY, 'mode': 'both'}
    assert save(c, value).status_code == 200
    monkeypatch.setattr(main, 'configuration_for_service',
                        lambda *args: pytest.fail('Publisher display policy must not replace local pull rules'))
    assert policy.policy_for_service(c.db, c.services[0].id) == {**value, 'group_id': c.groups[0].id}


def test_mismatched_setting_ownership_and_missing_service_deny(context):
    c = context
    c.db.add(PortalSetting(key=f'group:{c.groups[0].id}:oci_pull_policy', group_id=c.groups[1].id,
                          value=json.dumps(policy.DEFAULT_POLICY)))
    c.db.commit()
    with pytest.raises(ValueError, match='invalid owning group'):
        policy.policy_for_service(c.db, c.services[0].id)
    assert c.client.get(url(c.groups[0])).status_code == 409
    assert save(c, policy.DEFAULT_POLICY).status_code == 409
    with pytest.raises(ValueError, match='Service is unavailable'):
        policy.policy_for_service(c.db, 99999)
