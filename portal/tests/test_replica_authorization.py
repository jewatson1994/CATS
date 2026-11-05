import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from types import SimpleNamespace

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main, oci_proxy as proxy
from app.database import Base
from app.local_cyber_overrides import (LocalCyberOverride, LocalCyberOverrideRevocation,
    applicable_override, authentic, create_override, public, revoke_override)
from app.models import AuditEvent, Service, User
from app.oci_authorization import authorize
from app.oci_models import OCIManifest, OCIPrincipal, OCIRepository, OCIUpstream
from app.replica_integrity import digest as manifest_digest, seal_record
from app.replica_models import ReplicaRelease, ReplicaServiceState, ReplicaSource


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def replica(monkeypatch, tmp_path):
    monkeypatch.setenv('CATS_MODE', 'replica')
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('CATS_OCI_CACHE_DIR', str(tmp_path))
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    timestamp = datetime.now(timezone.utc)
    blob = b'approved replica layer'
    blob_digest = digest(blob)
    raw = json.dumps({'schemaVersion': 2, 'config': {'digest': blob_digest, 'size': len(blob)}, 'layers': []}).encode()
    old = digest(raw)
    new = 'sha256:' + 'b' * 64
    third = 'sha256:' + 'c' * 64
    with sessions() as db:
        user = User(username='local-cyber', display_name='Local Cyber')
        service = Service(service_key='replica-nginx', name='Replicated nginx')
        upstream = OCIUpstream(name='local', endpoint='https://registry.example')
        db.add_all([user, service, upstream]); db.flush()
        source = ReplicaSource(name='approved', upstream_id=upstream.id, repository='releases',
            trusted_publishers=['publisher'], created_by_id=user.id)
        mapping = OCIRepository(public_repository='replica/nginx', upstream_id=upstream.id,
            upstream_repository='team/nginx', service_id=service.id)
        db.add_all([source, mapping]); db.flush()
        state = ReplicaServiceState(service_id=service.id, publisher='publisher', source_service_id='nginx',
            upstream_id=upstream.id, source_id=source.id, high_sequence=2)
        db.add(state)
        releases = []
        for index, artifact_digests in enumerate(([old, third], [new]), 1):
            manifest = {'release': str(index), 'artifacts': artifact_digests}
            row = ReplicaRelease(service_id=service.id, publisher='publisher', source_release_id=str(index),
                sequence=index, manifest=manifest, manifest_digest=manifest_digest(manifest),
                artifacts=[dict(repository='team/nginx', kind='image', digest=value, manifests=[value],
                    blobs=[blob_digest] if value == old else []) for value in artifact_digests],
                evidence_state={}, key_fingerprint='publisher', verified=True, complete=True,
                approved_at=timestamp - timedelta(days=1), expires_at=timestamp + timedelta(days=10),
                source_reference=f'releases@sha256:{str(index) * 64}')
            seal_record(row)
            db.add(row); db.flush()
            releases.append(row)
        state.active_release_id = releases[-1].id
        machine = OCIPrincipal(name='robot', secret_hash=hashlib.sha256(b'secret').hexdigest(),
            repository_ids=[mapping.id], expires_at=timestamp + timedelta(days=1))
        db.add(machine); db.commit()
        values = dict(service_id=service.id, old_id=releases[0].id, new_id=releases[1].id,
            mapping_id=mapping.id, state_id=state.service_id, source_id=source.id, user_id=user.id)
    fixture = SimpleNamespace(sessions=sessions, now=timestamp, old=old, new=new, third=third,
        raw=raw, blob=blob, blob_digest=blob_digest, **values)
    fixture.data = dict(release_id=fixture.old_id, digest=old, denial_condition='superseded',
        mission_impact='Fleet mission continuity', justification='Replacement rollout is incomplete',
        risk_acceptance='Cyber accepts documented residual risk', expires_at=None)
    fixture.auth = SimpleNamespace(user=user, has=lambda permission, service_id=None:
        service_id == fixture.service_id and permission in {'service.view', 'local_override.create',
            'local_override.revoke', 'local_override.view_audit'})
    yield fixture
    engine.dispose()


def grant(fixture, **changes):
    with fixture.sessions() as db:
        row = create_override(db, fixture.auth, fixture.service_id, fixture.data | changes)
        db.commit()
        return row.id


def decision(fixture, value=None, timestamp=None):
    with fixture.sessions() as db:
        return authorize(db, db.get(OCIRepository, fixture.mapping_id), value or fixture.old, timestamp)


def test_active_and_superseded_release_enforcement_requires_no_scan(replica):
    assert decision(replica, replica.new).authorization_source == 'approved_release'
    assert decision(replica).reason == 'release_superseded'
    assert not decision(replica, 'sha256:' + 'd' * 64).allowed


def test_local_freshness_expiry_can_be_overridden_and_revoked(replica):
    with replica.sessions() as db:
        mapping = db.get(OCIRepository, replica.mapping_id)
        mapping.policy = {'max_approval_age_days': 1}
        db.commit()
        assert authorize(db, mapping, replica.new, replica.now).reason == 'release_expired'
        grant = create_override(db, replica.auth, replica.service_id, replica.data | {
            'release_id': replica.new_id, 'digest': replica.new, 'denial_condition': 'expired'}, replica.now)
        db.commit()
        accepted = authorize(db, mapping, replica.new, replica.now)
        assert accepted.allowed and accepted.override_id == grant.id
        assert accepted.approval_status == 'expired'
        revoke_override(db, replica.auth, replica.service_id, grant.id, 'Fresh release deployed')
        db.commit()
        assert authorize(db, mapping, replica.new, replica.now).reason == 'release_expired'


@pytest.mark.parametrize('route_change', [
    {'policy': {}}, {'policy': {'max_approval_age_days': 2}},
    {'policy': {'max_approval_age_days': 1, 'max_scan_age_days': 1}},
    {'policy': {'max_approval_age_days': 1, 'unsupported': 1}},
    {'upstream_repository': 'another/repository'}, {'service_id': None},
    {'enabled': False}, {'suspended': True},
])
def test_override_rejects_unsubstantiated_local_expiry(replica, route_change):
    with replica.sessions() as db:
        mapping = db.get(OCIRepository, replica.mapping_id)
        mapping.policy = {'max_approval_age_days': 1}
        for field, value in route_change.items():
            setattr(mapping, field, value)
        db.commit()
        with pytest.raises(ValueError, match='current release denial'):
            create_override(db, replica.auth, replica.service_id, replica.data | {
                'release_id': replica.new_id, 'digest': replica.new, 'denial_condition': 'expired'}, replica.now)


def test_indefinite_scoped_override_revokes_immediately_and_preserves_history(replica):
    identity = grant(replica)
    assert decision(replica).override_id == identity
    assert not decision(replica, replica.third).allowed
    assert decision(replica, timestamp=replica.now + timedelta(days=1000)).allowed
    with replica.sessions() as db:
        row = db.get(LocalCyberOverride, identity)
        assert row.expires_at is None and authentic(row)
        before = db.get(ReplicaRelease, replica.old_id).manifest_digest
        revoke_override(db, replica.auth, replica.service_id, identity, 'Deployment restored')
        db.commit()
        assert public(db, row)['status'] == 'revoked'
        assert db.get(ReplicaRelease, replica.old_id).manifest_digest == before
        assert db.get(ReplicaServiceState, replica.service_id).active_release_id == replica.new_id
        assert db.get(LocalCyberOverrideRevocation, identity).reason == 'Deployment restored'
    assert not decision(replica).allowed
    with replica.sessions() as db:
        assert {event.action for event in db.scalars(select(AuditEvent))} == {
            'local_override.created', 'local_override.revoked'}


def test_release_wide_override_freezes_exact_inventory(replica):
    identity = grant(replica, digest=None)
    assert decision(replica).override_id == identity
    assert decision(replica, replica.third).override_id == identity
    assert not decision(replica, 'sha256:' + 'e' * 64).allowed


@pytest.mark.parametrize('field,value', [('verified', False), ('complete', False),
    ('manifest', {'forged': True}), ('artifacts', [{'digest': 'sha256:' + 'f' * 64, 'repository': 'team/nginx'}]),
    ('key_fingerprint', 'unknown'), ('integrity_seal', 'broken')])
def test_override_never_bypasses_publisher_or_integrity(replica, field, value):
    grant(replica)
    with replica.sessions() as db:
        db.execute(update(ReplicaRelease).where(ReplicaRelease.id == replica.old_id).values({field: value}))
        db.commit()
    assert not decision(replica).allowed


def test_removed_publisher_or_disabled_source_denies_override(replica):
    grant(replica)
    with replica.sessions() as db:
        db.get(ReplicaSource, replica.source_id).trusted_publishers = []
        db.commit()
    assert not decision(replica).allowed


def test_tampered_local_grant_fails_closed(replica):
    identity = grant(replica)
    with replica.sessions() as db:
        db.execute(update(LocalCyberOverride).where(LocalCyberOverride.id == identity)
            .values(digests=[replica.old, replica.third]))
        db.commit()
    assert not decision(replica).allowed
    assert not decision(replica, replica.third).allowed


def test_expiry_and_revocation_require_explicit_risk_acceptance(replica):
    identity = grant(replica, expires_at=(replica.now + timedelta(hours=1)).isoformat())
    assert decision(replica).override_id == identity
    assert not decision(replica, timestamp=replica.now + timedelta(hours=2)).allowed
    with replica.sessions() as db:
        release = db.get(ReplicaRelease, replica.old_id)
        release.revoked_at = replica.now
        seal_record(release)
        db.commit()
    assert not decision(replica).allowed
    with pytest.raises(ValueError, match='elevated-risk'):
        grant(replica, denial_condition='revoked')
    assert grant(replica, denial_condition='revoked', elevated_risk_acknowledged=True)
    assert decision(replica).allowed


def test_normal_user_cannot_create_or_revoke_and_full_mode_cannot_create(replica, monkeypatch):
    identity = grant(replica)
    reader = SimpleNamespace(user=replica.auth.user, has=lambda permission, service_id=None: permission == 'service.view')
    with replica.sessions() as db:
        with pytest.raises(PermissionError):
            create_override(db, reader, replica.service_id, replica.data)
        with pytest.raises(PermissionError):
            revoke_override(db, reader, replica.service_id, identity, 'reason')
    monkeypatch.setenv('CATS_MODE', 'full')
    with pytest.raises(ValueError, match='replica mode'):
        grant(replica)


def test_grants_cannot_be_mutated_or_deleted(replica):
    identity = grant(replica)
    with replica.sessions() as db:
        db.get(LocalCyberOverride, identity).justification = 'changed'
        with pytest.raises(ValueError, match='immutable'):
            db.flush()
        db.rollback()
        db.delete(db.get(LocalCyberOverride, identity))
        with pytest.raises(ValueError, match='immutable'):
            db.flush()


def test_proxy_digest_tag_tampering_authentication_audit_and_revocation(replica, monkeypatch):
    identity = grant(replica)
    unknown = json.dumps({'schemaVersion': 2, 'config': {'digest': replica.blob_digest,
        'size': len(replica.blob)}, 'layers': [], 'annotations': {'changed': 'yes'}}).encode()
    documents = {replica.old: replica.raw, 'latest': replica.raw, 'substituted': unknown}
    class Transport:
        def fetch_manifest(self, repository, reference):
            raw = documents[reference]
            return raw, 'application/vnd.oci.image.manifest.v1+json', digest(raw)
        def fetch_blob(self, repository, reference, cache):
            return cache.get(reference) or cache.store(reference, io.BytesIO(replica.blob))
    monkeypatch.setattr(proxy, 'SessionLocal', replica.sessions)
    monkeypatch.setattr(proxy, 'client', lambda mapping: Transport())
    client = TestClient(proxy.app)
    path = '/v2/replica/nginx/manifests/'
    assert client.get(path + replica.old).status_code == 401
    client.headers['Authorization'] = 'Basic ' + base64.b64encode(b'robot:secret').decode()
    assert client.get(path + replica.old).status_code == 200
    assert client.get(path + 'latest').status_code == 200
    assert client.get(path + 'substituted').status_code == 403
    assert client.get('/v2/replica/nginx/blobs/' + replica.blob_digest).status_code == 200
    with replica.sessions() as db:
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'local_override.used')).all()
        assert len(events) == 3
        assert all(event.detail['override_id'] == identity and event.detail['release_id'] == replica.old_id for event in events)
        revoke_override(db, replica.auth, replica.service_id, identity, 'Mission restored')
        db.commit()
    assert client.get(path + replica.old).status_code == 403
    assert client.get('/v2/replica/nginx/blobs/' + replica.blob_digest).status_code == 403


def test_tampered_cached_manifest_cannot_be_served_with_override(replica, monkeypatch):
    grant(replica)
    with replica.sessions() as db:
        db.add(OCIManifest(repository_id=replica.mapping_id, digest=replica.old,
            media_type='application/vnd.oci.image.manifest.v1+json', content='{}'))
        db.commit()
    monkeypatch.setattr(proxy, 'SessionLocal', replica.sessions)
    client = TestClient(proxy.app)
    client.headers['Authorization'] = 'Basic ' + base64.b64encode(b'robot:secret').decode()
    assert client.get('/v2/replica/nginx/manifests/' + replica.old).status_code == 502


def test_local_override_api_requires_csrf_and_scoped_cyber_permissions(replica):
    from app.auth import require_user
    from app.database import get_db
    from app.local_cyber_overrides import router
    from app.operating_mode import ReplicaModeMiddleware
    app = FastAPI()
    app.include_router(router)
    app.add_middleware(ReplicaModeMiddleware)
    replica.auth.csrf_token = 'csrf-token'
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
    client = TestClient(app)
    path = '/api/services/replica-nginx/local-overrides'
    assert client.get(path).status_code == 401
    current['auth'] = replica.auth
    assert client.post(path, json=replica.data).status_code == 403
    headers = {'X-CSRF-Token': 'csrf-token'}
    created = client.post(path, json=replica.data, headers=headers)
    assert created.status_code == 200
    identity = created.json()['id']
    assert created.json()['expires_at'] is None
    assert client.get(path).json()['overrides'][0]['status'] == 'active'
    assert client.get(f'{path}/{identity}/uses').json() == {'uses': []}
    current['auth'] = SimpleNamespace(user=replica.auth.user, csrf_token='csrf-token',
        has=lambda permission, service_id=None: permission == 'service.view' and service_id == replica.service_id)
    assert client.get(path).status_code == 200
    assert client.post(path, json=replica.data, headers=headers).status_code == 403
    assert client.get(f'{path}/{identity}/uses').status_code == 403
    assert client.post(f'{path}/{identity}/revoke', json={'reason': 'Denied'}, headers=headers).status_code == 403
    current['auth'] = replica.auth
    assert client.post(f'{path}/{identity}/revoke', json={'reason': 'Mission complete'}).status_code == 403
    revoked = client.post(f'{path}/{identity}/revoke', json={'reason': 'Mission complete'}, headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()['status'] == 'revoked'
    assert not decision(replica).allowed


def test_override_cannot_serve_content_when_mandatory_usage_audit_fails(replica, monkeypatch):
    grant(replica)
    class Transport:
        def fetch_manifest(self, repository, reference):
            return replica.raw, 'application/vnd.oci.image.manifest.v1+json', replica.old
    monkeypatch.setattr(proxy, 'SessionLocal', replica.sessions)
    monkeypatch.setattr(proxy, 'client', lambda mapping: Transport())
    original_audit = proxy.record_audit
    def unavailable(db, auth, action, *args, **kwargs):
        if action == 'local_override.used':
            raise SQLAlchemyError('Audit storage unavailable')
        return original_audit(db, auth, action, *args, **kwargs)
    monkeypatch.setattr(proxy, 'record_audit', unavailable)
    client = TestClient(proxy.app)
    client.headers['Authorization'] = 'Basic ' + base64.b64encode(b'robot:secret').decode()
    response = client.get('/v2/replica/nginx/manifests/' + replica.old)
    assert response.status_code == 503
    assert replica.raw not in response.content
    with replica.sessions() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == 'local_override.used')) is None
