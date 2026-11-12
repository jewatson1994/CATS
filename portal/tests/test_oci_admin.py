from types import SimpleNamespace
import hashlib

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import oci_admin as admin
from app.auth import AuthContext, require_user
from app.database import Base, get_db
from app.models import AuditEvent, Service
from app.oci_models import OCIPrincipal, OCIUpstream
from app.secrets import decrypt_secret


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Service(name='Service', service_key='service'))
        db.commit()
        assignment = SimpleNamespace(role=SimpleNamespace(name='Admin', permissions=['release.destination.manage']),
            service_id=None, group_id=None, group=None)
        auth = AuthContext(user=SimpleNamespace(id=None, username='admin', display_name='Admin', role_assignments=[assignment]),
            session=SimpleNamespace(csrf_token='token'))
        app = FastAPI()
        app.include_router(admin.router)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[require_user] = lambda: auth
        with TestClient(app) as client:
            yield client, db, auth
    engine.dispose()


def post(client, path, value):
    return client.post('/api/oci/' + path, json=value, headers={'X-CSRF-Token': 'token'})


def test_admin_auth_csrf_secret_lifecycle(context):
    client, db, auth = context
    assert client.post('/api/oci/upstreams', json={}).status_code == 403
    upstream = post(client, 'upstreams', dict(name='Registry', endpoint='https://registry.example', username='user', password='sensitive'))
    assert upstream.status_code == 200, upstream.text
    row = db.get(OCIUpstream, upstream.json()['id'])
    assert decrypt_secret(row.password) == 'sensitive' and row.password != 'sensitive'
    assert 'password' not in upstream.json() and 'username' not in upstream.json()
    repository = post(client, 'repositories', dict(public_repository='project/image', service_id=1,
        upstream_id=row.id, upstream_repository='team/image', policy={'max_approval_age_days': 1}))
    assert repository.status_code == 200, repository.text
    assert repository.json()['pull_repository'] == 'project/1/image'
    assert repository.json()['public_repository'] == 'project/image'
    identity = repository.json()['id']
    principal = post(client, 'principals', dict(name='ci', repository_ids=[identity]))
    assert principal.status_code == 200, principal.text
    machine = db.get(OCIPrincipal, principal.json()['id'])
    assert machine.secret_hash == hashlib.sha256(principal.json()['secret'].encode()).hexdigest()
    assert 'secret' not in client.get('/api/oci/principals').json()[0]
    rotated = post(client, f'principals/{machine.id}/rotate', {})
    assert rotated.status_code == 200 and rotated.json()['secret'] != principal.json()['secret']
    assert 'sensitive' not in str([row.detail for row in db.scalars(select(AuditEvent))])
    auth.user.role_assignments[0].service_id = 1
    assert client.get('/api/oci/upstreams').status_code == 403


@pytest.mark.parametrize('data', [dict(name='Bad', endpoint='http://registry.example'),
    dict(name='Bad', endpoint='https://user:password@registry.example'),
    dict(name='Bad', endpoint='https://registry.example', token_realms=['http://tokens.example']),
    dict(name='Bad', endpoint='https://registry.example', redirect_origins=['https://cdn.example/path'])])
def test_unsafe_upstream_configuration_rejected(context, data):
    assert post(context[0], 'upstreams', data).status_code == 422


def test_connection_and_status(context, monkeypatch):
    client, db, auth = context
    upstream = post(client, 'upstreams', dict(name='Registry', endpoint='https://registry.example')).json()
    repository = post(client, 'repositories', dict(public_repository='project/image', service_id=1,
        upstream_id=upstream['id'], upstream_repository='team/image')).json()
    from app.oci_transport import RegistryClient, RegistryError
    monkeypatch.setattr(RegistryClient, 'fetch_manifest', lambda self, repository, reference: (b'{}', 'application/json', 'sha256:' + 'a' * 64))
    path = f"repositories/{repository['id']}/test"
    assert client.post('/api/oci/' + path, json={}).status_code == 403
    result = post(client, path, {'reference': 'v1'}).json()
    assert result['ok'] and result['digest'].startswith('sha256:')
    status = client.get('/api/oci/status/overview').json()
    assert status['available_repositories'] == 1 and status['services'][0]['name'] == 'Service'
    def failed(*args):
        raise RegistryError('sensitive registry error')
    monkeypatch.setattr(RegistryClient, 'fetch_manifest', failed)
    result = post(client, path, {}).json()
    assert not result['ok'] and 'sensitive' not in str(result)


def test_project_mapping_grants_and_connection(context, monkeypatch):
    client, _, _ = context
    upstream = post(client, 'upstreams', dict(name='Registry', endpoint='https://registry.example')).json()
    data = dict(public_repository='approved/*', upstream_repository='platform/*', upstream_id=upstream['id'])
    result = post(client, 'repositories', data)
    assert result.status_code == 200, result.text
    mapping = result.json()
    assert mapping['service_id'] is None
    assert mapping['pull_repository'] == 'approved/<service-id>/*'
    assert client.get('/api/oci/repositories').json() == [mapping]
    assert post(client, 'principals', dict(name='project-reader', repository_ids=[mapping['id']])).status_code == 200

    from app.oci_transport import RegistryClient
    calls = []
    def fetch_manifest(self, repository, reference):
        calls.append((repository, reference))
        return b'{}', 'application/json', 'sha256:' + 'a' * 64
    monkeypatch.setattr(RegistryClient, 'fetch_manifest', fetch_manifest)
    path = f"repositories/{mapping['id']}/test"
    for repository in (None, 'approved/*', 'approved', 'approved-2/api', 'approved/../elsewhere',
                       'platform/api', 'approved/team/api', 'approved/999/team/api', 'approved/01/team/api'):
        assert post(client, path, {'repository': repository}).status_code == 422
    assert calls == []
    assert post(client, path, dict(repository='approved/1/team/api', reference='v1')).json()['ok']
    assert calls == [('platform/team/api', 'v1')]


@pytest.mark.parametrize(('public_name', 'upstream_name', 'service_id'), [
    ('*', '*', None), ('team/*', 'team/image', None), ('team/image', 'team/*', 1),
    ('team/*/api', 'team/*', None), ('team/sub/*', 'other/*', None), ('team/*', 'other/sub/*', None),
    ('team/*', 'other/*', 1), ('team/image', 'other/image', None),
    ('team/2/image', 'other/image', 1), ('team/01/image', 'other/image', 1),
])
def test_invalid_repository_scopes(context, public_name, upstream_name, service_id):
    client, _, _ = context
    upstream = post(client, 'upstreams', dict(name='Registry', endpoint='https://registry.example')).json()
    result = post(client, 'repositories', dict(public_repository=public_name, upstream_repository=upstream_name,
        service_id=service_id, upstream_id=upstream['id']))
    assert result.status_code == 422, result.text


def test_project_scope_changes_require_new_grants(context):
    client, _, _ = context
    registry = post(client, 'upstreams', dict(name='Primary', endpoint='https://registry.example')).json()
    second = post(client, 'upstreams', dict(name='Other', endpoint='https://other.example')).json()
    exact = post(client, 'repositories', dict(public_repository='approved/api', upstream_repository='team/api',
        upstream_id=registry['id'], service_id=1)).json()
    project = post(client, 'repositories', dict(public_repository='approved/*', upstream_repository='team/*',
        upstream_id=registry['id'])).json()
    post(client, 'principals', dict(name='reader', repository_ids=[exact['id']])).raise_for_status()
    def update(mapping, **values):
        return client.put(f"/api/oci/repositories/{mapping['id']}", json=values, headers={'X-CSRF-Token': 'token'})
    assert update(exact, public_repository='new/*', upstream_repository='new/*', service_id=None).status_code == 409
    assert update(project, public_repository='other/*').status_code == 409
    assert update(project, upstream_repository='other/*').status_code == 409
    assert update(project, upstream_id=second['id']).status_code == 409
    assert update(project, public_repository='new/api', upstream_repository='team/api', service_id=1).status_code == 409
    assert client.get('/api/oci/repositories').json() == [exact, project]
    assert client.get('/api/oci/principals').json()[0]['repository_ids'] == [exact['id']]
    assert update(project, policy={'max_scan_age_days': 7}, suspended=True).json()['suspended']


def test_exact_service_route_configuration_and_connection(context, monkeypatch):
    client, db, _ = context
    upstream = post(client, 'upstreams', dict(name='Registry', endpoint='https://registry.example')).json()
    response = post(client, 'repositories', dict(public_repository='cyber-approved/1/team/image',
        service_id=1, upstream_id=upstream['id'], upstream_repository='harbor/team/image'))
    assert response.status_code == 200, response.text
    mapping = response.json()
    assert mapping['pull_repository'] == mapping['public_repository'] == 'cyber-approved/1/team/image'
    from app.oci_transport import RegistryClient
    calls = []
    def fetch(self, repository, reference):
        calls.append((repository, reference))
        return b'{}', 'application/json', 'sha256:' + 'a' * 64
    monkeypatch.setattr(RegistryClient, 'fetch_manifest', fetch)
    path = f"repositories/{mapping['id']}/test"
    assert post(client, path, dict(repository=mapping['pull_repository'], reference='v1')).json()['ok']
    assert calls == [('harbor/team/image', 'v1')]
    assert post(client, path, dict(repository='cyber-approved/2/team/image')).status_code == 422
    assert len(calls) == 1


def test_connection_rejects_inactive_requested_service(context, monkeypatch):
    client, db, _ = context
    upstream = post(client, 'upstreams', dict(name='Registry', endpoint='https://registry.example')).json()
    mapping = post(client, 'repositories', dict(public_repository='approved/*',
        upstream_repository='team/*', upstream_id=upstream['id'])).json()
    db.get(Service, 1).lifecycle_status = 'staged'
    db.commit()
    from app.oci_transport import RegistryClient
    def forbidden(*args):
        raise AssertionError('Inactive services cannot trigger registry connection checks')
    monkeypatch.setattr(RegistryClient, 'fetch_manifest', forbidden)
    assert post(client, f"repositories/{mapping['id']}/test", dict(repository='approved/1/image')).status_code == 422


@pytest.mark.parametrize('repository', ['approved/api', 'approved/0/api', 'approved/01/api',
    'approved/+1/api', 'approved/-1/api', 'approved/1', 'approved/1/',
    'approved/1/../api', 'approved/1/api?service=2', 'approved/999999999999999999999999/api'])
def test_service_route_parser_rejects_ambiguous_or_unbounded_identity(repository):
    from app.oci_models import parse_service_repository
    with pytest.raises(ValueError):
        parse_service_repository(repository)


def test_service_route_helpers_keep_nested_paths_and_signed_mapping_names():
    from app.oci_models import parse_service_repository, service_repository
    assert parse_service_repository('cyber-approved/42/team/nginx') == (42, 'cyber-approved/team/nginx')
    assert service_repository('cyber-approved/team/nginx', 42) == 'cyber-approved/42/team/nginx'
    assert service_repository('cyber-approved/42/team/nginx', 42) == 'cyber-approved/42/team/nginx'
    assert service_repository('services/42/team/nginx', 42) == 'services/42/team/nginx'
    assert service_repository('approved/123', 42) == 'approved/42/123'
    with pytest.raises(ValueError):
        service_repository('cyber-approved/17/team/nginx', 42)
