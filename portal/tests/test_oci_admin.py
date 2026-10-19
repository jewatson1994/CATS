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
