"""HTTP boundary tests using real scoped AuthContext and disposable database."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import risk_routes as routes
from app.auth import AuthContext, require_user
from app.database import Base
from app.models import Service, Group
from app.risk_models import RiskAssessment, RiskDecision, RiskPolicyAssignment
from app.durable_jobs import DurableJob
from app.vex_models import VexDocument


def auth(permissions=('service.view',), service_id=1, group=None):
    assignment = SimpleNamespace(role=SimpleNamespace(name='Test role', permissions=list(permissions)),
                                 service_id=service_id, group_id=group.id if group else None, group=group)
    return AuthContext(user=SimpleNamespace(id=None, username='real-reviewer', display_name='Reviewer',
                                            role_assignments=[assignment]),
                       session=SimpleNamespace(csrf_token='csrf'))


@pytest.fixture
def api():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Service(id=1, service_key='one', name='One'), Service(id=2, service_key='two', name='Two'),
                    Group(id=1, name='One group'), Group(id=2, name='Two group')])
        db.commit()
        application = FastAPI()
        application.include_router(routes.router)
        current = {'auth': auth()}
        application.dependency_overrides[require_user] = lambda: current['auth']
        application.dependency_overrides[routes.get_db] = lambda: db
        with TestClient(application) as client:
            yield client, db, current
    engine.dispose()


def post(client, path, payload):
    return client.post('/api/risk' + path, json=payload, headers={'X-CSRF-Token': 'csrf'})


def assessment(db, service_id=1):
    now = datetime.now(timezone.utc)
    item = RiskAssessment(service_id=service_id, as_of=now, valid_until=now + timedelta(days=1),
                          provenance={'configuration': routes.risk.DEFAULT_POLICY}, summary={}, details=[])
    db.add(item)
    db.commit()
    return item


def decision_payload(item, kind='recommendation'):
    return {'assessment_id': item.id, 'kind': kind, 'decision': 'accept', 'reviewer': 'spoofed AO',
            'authority_label': 'spoofed authority', 'mission_impact': 'Limited', 'controls': 'Isolation',
            'justification': 'Evidence reviewed', 'evidence_refs': ['ticket:123'],
            'expires_at': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}


@pytest.mark.parametrize('path', ['/profiles', '/assignments', '/services/one/assess',
                                  '/services/one/decisions', '/sources', '/sources/1/documents', '/sources/1/snapshot', '/sources/1/state'])
@pytest.mark.parametrize('token', [None, 'wrong'])
def test_every_mutation_rejects_missing_or_wrong_csrf(api, path, token):
    client, db, current = api
    current['auth'] = auth(('service.view', 'config.manage', 'risk.authorize'), None)
    headers = {'X-CSRF-Token': token} if token else {}
    response = client.post('/api/risk' + path, json={}, headers=headers)
    assert response.status_code == 403
    assert 'CSRF' in response.json()['detail']
    assert db.scalar(select(func.count()).select_from(RiskDecision)) == 0


def test_service_and_job_visibility_is_scoped(api):
    client, db, current = api
    db.add_all([DurableJob(id='visible', kind='risk_assessment', service_id=1),
                DurableJob(id='hidden', kind='risk_assessment', service_id=2),
                DurableJob(id='other', kind='other_job', service_id=1)])
    db.commit()
    assert [x['service_key'] for x in client.get('/api/risk/services').json()['items']] == ['one']
    assert client.get('/api/risk/services?q=Two').json()['items'] == []
    assert client.get('/api/risk/services/one').status_code == 200
    assert client.get('/api/risk/services/two').status_code == 404
    assert client.get('/api/risk/jobs/visible').status_code == 200
    for key in ('hidden', 'other', 'missing'):
        assert client.get('/api/risk/jobs/' + key).status_code == 404
    current['auth'] = auth((), 1)
    assert client.get('/api/risk/services').status_code == 403


@pytest.mark.parametrize('permission,kind', [('risk.recommend', 'recommendation'),
                                           ('risk.decide', 'delegated_approval'),
                                           ('risk.authorize', 'ao_decision')])
def test_each_authority_role_cannot_impersonate_another(api, permission, kind):
    client, db, current = api
    current['auth'] = auth(('service.view', permission))
    item = assessment(db)
    for other in {'recommendation', 'delegated_approval', 'ao_decision'} - {kind}:
        assert post(client, '/services/one/decisions', decision_payload(item, other)).status_code == 403
    response = post(client, '/services/one/decisions', decision_payload(item, kind))
    assert response.status_code == 200, response.text
    saved = db.get(RiskDecision, response.json()['id'])
    assert saved.created_by == saved.payload['reviewer'] == 'real-reviewer'
    assert saved.payload['authority_label'] == routes.risk.DEFAULT_POLICY['authority_labels'][kind]
    assert db.scalar(select(func.count()).select_from(RiskDecision)) == 1


def test_configuration_manager_has_no_implicit_ao_authority(api):
    client, db, current = api
    current['auth'] = auth(('service.view', 'config.manage'), None)
    assert post(client, '/services/one/decisions', decision_payload(assessment(db), 'ao_decision')).status_code == 403


def test_cross_service_assessment_and_decision_rejected(api):
    client, db, current = api
    current['auth'] = auth(('service.view', 'risk.authorize', 'config.manage'))
    foreign = assessment(db, 2)
    assert post(client, '/services/one/decisions', decision_payload(foreign, 'ao_decision')).status_code == 422
    assert post(client, '/services/two/decisions', decision_payload(foreign, 'ao_decision')).status_code == 404
    assert post(client, '/services/two/assess', {}).status_code == 404


def test_assignment_authority_is_not_transitive_or_global(api):
    client, db, current = api
    policy = routes.risk.create_policy(db, 'Test', {}, 'admin', group_id=1)
    foreign = routes.risk.create_policy(db, 'Foreign', {}, 'admin', group_id=2)
    db.commit()
    current['auth'] = auth(('service.view', 'config.manage'))
    assert client.get('/api/risk/profiles').json()['items'] == []
    assert post(client, '/assignments', {'scope': 'group', 'scope_id': 1, 'policy_id': policy.id}).status_code == 403
    for scope, identity in [('service', 1), ('default', 0)]:
        assert post(client, '/assignments', {'scope': scope, 'scope_id': identity, 'policy_id': policy.id}).status_code == 422
    current['auth'] = auth(('config.manage',), None, db.get(Group, 1))
    assert client.get('/api/risk/capabilities').json()['groups'] == [{'id': 1, 'name': 'One group'}]
    assert [p['id'] for p in client.get('/api/risk/profiles').json()['items']] == [policy.id]
    assert client.get('/api/risk/profiles?group_id=2').status_code == 403
    assert post(client, '/profiles', {'name': 'Other', 'configuration': {}, 'group_id': 2}).status_code == 403
    assert post(client, '/profiles', {'name': 'Copy', 'configuration': {}, 'group_id': 1, 'parent_policy_id': foreign.id}).status_code == 422
    assert post(client, '/profiles', {'name': 'Own', 'configuration': {}, 'group_id': 1}).status_code == 200
    assert post(client, '/assignments', {'scope': 'group', 'scope_id': 1, 'policy_id': foreign.id}).status_code == 422
    assert post(client, '/assignments', {'scope': 'group', 'scope_id': 1, 'policy_id': policy.id}).status_code == 200
    assert post(client, '/assignments', {'scope': 'group', 'scope_id': 2, 'policy_id': foreign.id}).status_code == 403
    assert db.scalar(select(func.count()).select_from(RiskPolicyAssignment)) == 1


@pytest.mark.parametrize('path', ['/sources', '/statements', '/documents/1'])
def test_scoped_manager_cannot_read_global_intelligence_administration(api, path):
    client, db, current = api
    current['auth'] = auth(('service.view', 'config.manage'))
    assert client.get('/api/risk' + path).status_code == 403


def test_trusted_source_configuration_roundtrip(api):
    client, db, current = api
    current['auth'] = auth(('config.manage',), None)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    public_key = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    response = post(client, '/sources', {'name': 'Official', 'trusted': True, 'public_key': public_key,
                    'allowed_hosts': ['security.example.org'], 'trust_reason': 'Reviewed publisher ownership',
                    'authoritative_prefixes': ['pkg:generic/vendor/']})
    assert response.status_code == 200, response.text
    listed = client.get('/api/risk/sources')
    assert listed.status_code == 200, listed.text
    source = listed.json()['items'][0]
    assert source['trusted'] is True
    assert source['enabled'] is True
    assert source['key_configured'] is True
    assert source['health'] == 'empty' and source['latest_issued_at'] is None
    assert source['documents'] == source['statements'] == 0
    assert 'public_key' not in source
    assert source['authoritative_prefixes'] == ['pkg:generic/vendor/']
    assert source['trust_reason'] == 'Reviewed publisher ownership'
    assert all(not item['enabled'] for item in listed.json()['catalog'])


def test_upload_roundtrip_is_unverified_and_requires_global_authority(api):
    client, db, current = api
    current['auth'] = auth(('config.manage',), None)
    source = post(client, '/sources', {'name': 'Uploaded'}).json()
    raw = (Path(__file__).parent / 'fixtures/vex/openvex-official-fixed.json').read_bytes()
    url = '/api/risk/sources/' + str(source['id']) + '/documents'
    response = client.post(url, content=raw, headers={'X-CSRF-Token': 'csrf'})
    assert response.status_code == 200, response.text
    assert response.json()['verification'] != 'verified'
    listed = client.get('/api/risk/sources').json()['items'][0]
    assert listed['documents'] == 1 and listed['statements'] > 0
    assert listed['latest_issued_at'] is not None
    assert listed['key_configured'] is False
    document = client.get('/api/risk/documents/' + str(response.json()['id']))
    assert document.status_code == 200 and document.json()['raw_text'] == raw.decode()
    current['auth'] = auth(('service.view', 'config.manage'))
    assert client.post(url, content=raw, headers={'X-CSRF-Token': 'csrf'}).status_code == 403
    assert db.scalar(select(func.count()).select_from(VexDocument)) == 1


@pytest.mark.parametrize('suffix,limit', [('documents', 4 * 1024 * 1024), ('snapshot', 4 * 1024 * 1024)])
def test_upload_byte_limits_enforced_before_parser(api, suffix, limit):
    client, db, current = api
    current['auth'] = auth(('config.manage',), None)
    response = client.post('/api/risk/sources/1/' + suffix, content=b'x' * (limit + 1),
                           headers={'X-CSRF-Token': 'csrf'})
    assert response.status_code == 413
    assert db.scalar(select(func.count()).select_from(VexDocument)) == 0


def test_assessment_detail_is_scoped_and_missing_ids_are_hidden(api):
    client, db, current = api
    own = assessment(db, 1)
    foreign = assessment(db, 2)
    response = client.get('/api/risk/assessments/' + str(own.id))
    assert response.status_code == 200
    assert response.json()['id'] == own.id and response.json()['service_id'] == 1
    for identity in (foreign.id, 99999):
        assert client.get('/api/risk/assessments/' + str(identity)).status_code == 404
    current['auth'] = auth((), 1)
    assert client.get('/api/risk/assessments/' + str(own.id)).status_code == 404


@pytest.mark.parametrize('enabled', [None, 'false', 0, 1, [], {}])
def test_source_state_requires_real_boolean(api, enabled):
    client, db, current = api
    current['auth'] = auth(('config.manage',), None)
    source = post(client, '/sources', {'name': 'State validation'}).json()
    assert post(client, f"/sources/{source['id']}/state", {'enabled': enabled}).status_code == 422
    assert client.get('/api/risk/sources').json()['items'][0]['enabled'] is True


def test_source_state_requires_global_authority_and_supports_disable_reenable(api):
    client, db, current = api
    current['auth'] = auth(('config.manage',), None)
    source = post(client, '/sources', {'name': 'Toggle'}).json()
    path = f"/sources/{source['id']}/state"
    for permissions in [('service.view',), ('service.view', 'config.manage')]:
        current['auth'] = auth(permissions)
        assert post(client, path, {'enabled': False}).status_code == 403
    current['auth'] = auth(('config.manage',), None)
    for enabled in (False, True):
        response = post(client, path, {'enabled': enabled})
        assert response.status_code == 200, response.text
        assert response.json() == {'id': source['id'], 'enabled': enabled}
        listed = client.get('/api/risk/sources').json()['items'][0]
        assert listed['enabled'] is enabled
        assert listed['health'] == ('untrusted' if enabled else 'disabled')
    assert post(client, '/sources/99999/state', {'enabled': False}).status_code == 404


def test_source_configuration_preserves_explicit_disabled_state(api):
    client, db, current = api
    current['auth'] = auth(('config.manage',), None)
    response = post(client, '/sources', {'name': 'Offline', 'enabled': False})
    assert response.status_code == 200 and response.json()['enabled'] is False
    assert client.get('/api/risk/sources').json()['items'][0]['health'] == 'disabled'
    assert post(client, '/sources', {'name': 'Offline', 'enabled': 'false'}).status_code == 422


def test_source_configuration_rejects_invalid_public_key(api):
    client, db, current = api
    current['auth'] = auth(('config.manage',), None)
    response = post(client, '/sources', {'name': 'Invalid key', 'public_key': 'fake PEM'})
    assert response.status_code == 422
    assert client.get('/api/risk/sources').json()['items'] == []

def test_sources_exposes_package_inventory_only_to_source_managers(api, monkeypatch):
    client, db, current = api
    status = {'status': 'installed', 'version': 'test-package', 'sources': [{'id': 'kev'}]}
    calls = []
    monkeypatch.setattr(routes, 'package_status', lambda session: calls.append(session) or status)
    assert client.get('/api/risk/sources').status_code == 403
    assert calls == []
    current['auth'] = auth(('config.manage',), None)
    response = client.get('/api/risk/sources')
    assert response.status_code == 200
    assert response.json()['embedded_package'] == status
    assert response.json()['items'] == []
    assert calls == [db]


def test_group_service_filter_and_independent_profile_versions(api):
    from app.models import ServiceGroup
    client, db, current = api
    db.add_all([ServiceGroup(service_id=1, group_id=1), ServiceGroup(service_id=2, group_id=2)])
    routes.risk.create_policy(db, 'Same name', {}, 'admin', group_id=2)
    db.commit()
    current['auth'] = auth(('config.manage',), None, db.get(Group, 1))
    response = post(client, '/profiles', {'group_id': 1, 'name': 'Same name', 'configuration': {}})
    assert response.status_code == 200
    assert response.json()['version'] == 1
    assert response.json()['name'] == 'Same name'
    assert [s['id'] for s in client.get('/api/risk/services?group_id=1').json()['items']] == [1]
    assert client.get('/api/risk/services?group_id=2').status_code == 403
    assert client.get('/api/risk/services/one').status_code == 200
    assert client.get('/api/risk/services/two').status_code == 404
    db.add_all([DurableJob(id='own-group-job', kind='risk_assessment', service_id=1),
                DurableJob(id='other-group-job', kind='risk_assessment', service_id=2)])
    db.commit()
    assert client.get('/api/risk/jobs/own-group-job').status_code == 200
    assert client.get('/api/risk/jobs/other-group-job').status_code == 404


def test_risk_policy_page_scope_and_legacy_redirect(api, monkeypatch):
    from app import main
    from fastapi import HTTPException
    client, db, current = api
    manager = auth(('config.manage',), None, db.get(Group, 1))
    monkeypatch.setattr(main, 'page_context', lambda auth, **values: values)
    monkeypatch.setattr(main.templates, 'TemplateResponse', lambda request, name, context: context)
    assert main.risk_policy_page(None, 1, manager, db)['selected_group_id'] == 1
    with pytest.raises(HTTPException) as exc:
        main.risk_policy_page(None, 2, manager, db)
    assert exc.value.status_code == 403
    with pytest.raises(HTTPException) as exc:
        main.risk_policy_page(None, None, auth(('config.manage',), 1), db)
    assert exc.value.status_code == 403
    redirect = main.risk_intelligence_page(None, manager)
    assert redirect.status_code == 307 and redirect.headers['location'] == '/admin/risk-policy'


def test_risk_policy_navigation_flag(api, monkeypatch):
    from app import main
    client, db, current = api
    monkeypatch.setattr(main, 'SessionLocal', lambda: (_ for _ in ()).throw(RuntimeError('no navigation db')))
    for principal, expected in [(auth(('config.manage',), None, db.get(Group, 1)), True),
                                (auth(('config.manage',), 1), False), (auth((), 1), False)]:
        principal.user.id = 1
        principal.session.id = 1
        assert main.page_context(principal)['may_manage_risk_policy'] is expected
