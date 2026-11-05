"""Actual local administration and evidence routes enforce scope and CSRF."""
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from app.auth import require_user
from app.database import get_db
from app.durable_jobs import DurableJob
from app.models import AuditEvent
from app.operating_mode import ReplicaModeMiddleware
from app.replica_integrity import digest, seal_record
from app.replica_models import ReplicaRelease, ReplicaSource
from app import replica_routes
from test_replica_authorization import replica


@pytest.fixture
def api(replica):
    app = FastAPI()
    app.include_router(replica_routes.router)
    app.add_middleware(ReplicaModeMiddleware)
    current = {'auth': None}
    def authentication():
        if current['auth'] is None:
            raise HTTPException(401, 'Authentication required')
        return current['auth']
    def database():
        with replica.sessions() as db:
            yield db
    app.dependency_overrides[require_user] = authentication
    app.dependency_overrides[get_db] = database
    def login(permissions, service_id=None):
        current['auth'] = SimpleNamespace(user=replica.auth.user, csrf_token='csrf',
            has=lambda permission, scope=None: permission in permissions and
                (service_id is None or scope == service_id),
            accessible_service_ids=lambda permission:
                (None if service_id is None else {service_id}) if permission in permissions else set())
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, login=login, current=current, fixture=replica)


def test_replica_admin_and_sync_routes_require_distinct_permissions_and_csrf(api):
    client, fixture = api.client, api.fixture
    headers = {'X-CSRF-Token': 'csrf'}
    payload = dict(name='second source', upstream_id=1, repository='approved/service/releases',
        trusted_publishers=['sha256:' + 'a' * 64])
    assert client.get('/api/replica/sources').status_code == 401
    api.login({'service.view'}, fixture.service_id)
    for url in ('/api/replica/sources', '/api/replica/status'):
        assert client.get(url).status_code == 403
    assert client.post('/api/replica/sources', json=payload, headers=headers).status_code == 403
    assert client.post('/api/replica/sync', json={}, headers=headers).status_code == 403
    api.login({'replica.admin'})
    assert client.post('/api/replica/sources', json=payload).status_code == 403
    created = client.post('/api/replica/sources', json=payload, headers=headers)
    assert created.status_code == 200
    identity = created.json()['id']
    assert 'password' not in created.json() and 'username' not in created.json()
    assert client.put(f'/api/replica/sources/{identity}', json={'enabled': False}).status_code == 403
    assert client.put(f'/api/replica/sources/{identity}', json={'enabled': False}, headers=headers).status_code == 200
    assert client.post('/api/replica/sync', json={}, headers=headers).status_code == 403
    api.login({'replica.sync'})
    assert client.get('/api/replica/sources').status_code == 403
    assert client.get('/api/replica/status').status_code == 200
    assert client.post('/api/replica/sync', json={}).status_code == 403
    assert client.post('/api/replica/sync', json={'source_id': identity}, headers=headers).status_code == 404
    first = client.post('/api/replica/sync', json={'source_id': fixture.source_id}, headers=headers)
    repeated = client.post('/api/replica/sync', json={'source_id': fixture.source_id}, headers=headers)
    assert first.status_code == repeated.status_code == 200
    assert first.json()['jobs'][0]['id'] == repeated.json()['jobs'][0]['id']
    with fixture.sessions() as db:
        assert len(list(db.scalars(select(DurableJob)))) == 1
    # A future evidence-write route must still be blocked before routing.
    assert client.post(f'/api/replica/releases/{fixture.old_id}/context', json={}, headers=headers).json()['code'] == 'replica_read_only'


def test_original_evidence_routes_require_service_and_evidence_scope_and_integrity(api, tmp_path):
    fixture, client = api.fixture, api.client
    raw = b'original authenticated evidence archive'
    archive = tmp_path / 'retained.zip'
    archive.write_bytes(raw)
    import hashlib
    with fixture.sessions() as db:
        release = db.get(ReplicaRelease, fixture.old_id)
        release.evidence_state = {'original': {'assessment': 'unchanged'}}
        release.evidence_state_digest = digest(release.evidence_state)
        release.evidence_path = str(archive)
        release.manifest = {**release.manifest, 'evidence': {'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}}
        release.manifest_digest = digest(release.manifest)
        seal_record(release)
        db.commit()
    path = f'/api/replica/releases/{fixture.old_id}'
    api.login({'service.view'}, fixture.service_id)
    assert len(client.get('/api/replica/releases').json()['releases']) == 2
    assert client.get(path + '/context').status_code == 403
    assert client.get(path + '/evidence').status_code == 403
    api.login({'service.view', 'evidence.view'}, fixture.service_id + 100)
    assert client.get('/api/replica/releases').json() == {'releases': []}
    assert client.get(path + '/context').status_code == 404
    assert client.get(path + '/evidence').status_code == 404
    api.login({'service.view', 'evidence.view'}, fixture.service_id)
    context = client.get(path + '/context')
    assert context.status_code == 200 and context.json()['read_only'] is True
    assert context.json()['original_evidence'] == {'original': {'assessment': 'unchanged'}}
    download = client.get(path + '/evidence')
    assert download.status_code == 200 and download.content == raw
    assert download.headers['cache-control'] == 'private, no-store'
    with fixture.sessions() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == 'replica.evidence.downloaded'))
    archive.write_bytes(b'corrupted archive')
    assert client.get(path + '/evidence').status_code == 409
    with fixture.sessions() as db:
        release = db.get(ReplicaRelease, fixture.old_id)
        release.evidence_state = {'original': {'assessment': 'changed'}}
        db.commit()
    assert client.get(path + '/context').status_code == 409


def test_source_update_locks_and_refreshes_before_preserving_unspecified_fields(replica, monkeypatch):
    auth = SimpleNamespace(user=replica.auth.user)
    with replica.sessions() as db:
        stale = db.get(ReplicaSource, replica.source_id)
        with replica.sessions() as other:
            current = other.get(ReplicaSource, replica.source_id)
            current.repository = 'approved/service/releases'
            current.trusted_publishers = ['sha256:' + 'a' * 64]
            other.commit()
        scalar = db.scalar
        calls = []
        def tracked(statement, *args, **kwargs):
            calls.append(statement)
            return scalar(statement, *args, **kwargs)
        monkeypatch.setattr(db, 'scalar', tracked)
        result = replica_routes.configure(db, auth, {'name': 'renamed'}, stale)
        assert calls[0]._for_update_arg is not None
        assert calls[0].get_execution_options()['populate_existing'] is True
        assert result['repository'] == 'approved/service/releases'
        assert result['trusted_publishers'] == ['sha256:' + 'a' * 64]
        with pytest.raises(HTTPException) as error:
            replica_routes.configure(db, auth, {'repository': 'other/releases'}, stale)
        assert error.value.status_code == 409
