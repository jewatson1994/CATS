"""Mixed local and imported OCI authority in the full CATS application."""
from datetime import timedelta
import json
from types import SimpleNamespace

from cryptography.fernet import Fernet
from fastapi import HTTPException
import pytest
from sqlalchemy import delete, select
from starlette.requests import Request

from app import durable_jobs, oci_attestation_inventory, oci_authorization, oci_proxy
from app import replica_routes, replica_sync
from app.cyber_approvals import CyberApproval
from app.imported_services import (imported_service_ids, imported_service_predicate,
    is_imported_service, uses_imported_evidence)
from app.local_cyber_overrides import create_override, revoke_override
from app.models import Service, User
from app.oci_models import OCIRepository
from app.replica_integrity import digest, seal_record
from app.replica_models import ReplicaRecordMap, ReplicaRelease, ReplicaServiceState, ReplicaSource
from test_oci_proxy import project, registry
from test_oci_service_routes import blob, manifest
from test_replica_authorization import decision, grant, replica
from test_replica_import import replica_import, verified
from test_replica_sync import worker


@pytest.fixture
def full_imported(replica, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    return replica


def test_full_mode_mixed_services_share_bytes_without_sharing_authority(project, monkeypatch):
    s = project
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    with s.sessions() as db:
        local_approval = db.get(CyberApproval, s.approvals[s.scanned])
        timestamp = local_approval.decided_at
        mapping = db.get(OCIRepository, s.mapping_id)
        service = Service(service_key='imported-api', name='Imported API')
        importer = User(username='importer', display_name='Importer')
        db.add_all([service, importer]); db.flush()
        source = ReplicaSource(name='source', upstream_id=mapping.upstream_id,
            repository='approved/api/releases', trusted_publishers=['publisher'], created_by_id=importer.id)
        db.add(source); db.flush()
        release = ReplicaRelease(service_id=service.id, publisher='publisher', source_release_id='release-1',
            sequence=1, manifest={'release': 1}, manifest_digest=digest({'release': 1}),
            artifacts=[dict(repository=s.scanned, kind='image', digest=s.image, manifests=[], blobs=[s.blob])],
            evidence_state={}, key_fingerprint='publisher', verified=True, complete=True,
            approved_at=timestamp - timedelta(days=1), expires_at=timestamp + timedelta(days=10),
            source_reference='approved/api/releases@' + s.image)
        seal_record(release)
        db.add(release); db.flush()
        db.add(ReplicaServiceState(service_id=service.id, source_id=source.id,
            upstream_id=mapping.upstream_id, publisher='publisher', source_service_id='imported-api',
            high_sequence=1, active_release_id=release.id))
        imported_id, release_id = service.id, release.id
        db.commit()
        assert imported_service_ids(db) == {imported_id}
        assert imported_service_ids(db, [s.service_ids[s.scanned], imported_id]) == {imported_id}
        assert imported_service_ids(db, []) == set()
        assert set(db.scalars(select(Service.id).where(imported_service_predicate(Service.id)))) == {imported_id}
        assert not uses_imported_evidence(db, s.service_ids[s.scanned])
    local_route = s.routes[s.scanned]
    imported_route = f'cyber-approved/{imported_id}/api'
    assert manifest(local_route, 'latest').status_code == 200
    with pytest.raises(oci_proxy.Denied):
        blob(imported_route, s.blob)
    assert manifest(imported_route, 'latest').status_code == 200
    assert blob(imported_route, s.blob).status_code == 200
    with s.sessions() as db:
        release = db.get(ReplicaRelease, release_id)
        release.revoked_at = timestamp
        seal_record(release)
        db.commit()
    for operation, reference in ((manifest, s.image), (blob, s.blob)):
        with pytest.raises(oci_proxy.Denied):
            operation(imported_route, reference)
        assert operation(local_route, reference).status_code == 200


@pytest.mark.parametrize('retained', ['release', 'map'])
def test_missing_imported_state_never_falls_back_to_local_approval(full_imported, monkeypatch, retained):
    f = full_imported
    with f.sessions() as db:
        db.execute(delete(ReplicaServiceState).where(ReplicaServiceState.service_id == f.service_id))
        if retained == 'map':
            db.execute(delete(ReplicaRelease).where(ReplicaRelease.service_id == f.service_id))
            db.add(ReplicaRecordMap(service_id=f.service_id, table_name='services', source_id=17, local_id=f.service_id))
        db.commit()
        assert is_imported_service(db, f.service_id)
        assert imported_service_ids(db, [f.service_id]) == {f.service_id}
        monkeypatch.setattr(oci_authorization, 'current_execution',
            lambda *args: pytest.fail('Imported service cannot consult local approval evidence'))
        mapping = db.get(OCIRepository, f.mapping_id)
        assert oci_authorization.authorize(db, mapping, f.new).reason == 'replica_service_unavailable'
        assert oci_proxy.resolve_distribution_tag(db, mapping, 'latest') is None
        with pytest.raises(ValueError, match='unavailable'):
            oci_proxy.resolve_distribution_location(db, mapping, f.new)
        assert not oci_authorization.project_tag_allowed(db, mapping, 'latest', f.new)


def test_full_mode_imported_release_overrides_remain_scoped_and_revocable(full_imported):
    f = full_imported
    assert decision(f, f.new).authorization_source == 'approved_release'
    assert decision(f).reason == 'release_superseded'
    override_id = grant(f)
    assert decision(f).override_id == override_id
    with f.sessions() as db:
        local = Service(service_key='local-service', name='Local service')
        db.add(local); db.commit()
        with pytest.raises(ValueError, match='only for imported services'):
            create_override(db, f.auth, local.id, f.data)
        revoke_override(db, f.auth, f.service_id, override_id, 'Replacement deployed')
        db.commit()
    assert not decision(f).allowed


@pytest.mark.parametrize('change', ['expired', 'revoked', 'untrusted', 'disabled_source'])
def test_full_mode_imported_authority_rechecks_validity_and_trust(full_imported, change):
    f = full_imported
    assert decision(f, f.new).allowed
    with f.sessions() as db:
        release = db.get(ReplicaRelease, f.new_id)
        if change == 'expired':
            release.expires_at = f.now - timedelta(seconds=1)
        elif change == 'revoked':
            release.revoked_at = f.now
        elif change == 'untrusted':
            db.get(ReplicaSource, f.source_id).trusted_publishers = []
        else:
            db.get(ReplicaSource, f.source_id).enabled = False
        seal_record(release)
        db.commit()
    assert not decision(f, f.new).allowed


def test_full_mode_imported_attestation_uses_the_imported_release(full_imported):
    f = full_imported
    object_digest = 'sha256:' + 'e' * 64
    descriptor = dict(digest=object_digest, size=11, blobs=[], receipts=[])
    with f.sessions() as db:
        release = db.get(ReplicaRelease, f.new_id)
        release.artifacts = [{**item, 'reference': 'registry.example/team/nginx@' + item['digest'],
                              'attestation': descriptor} for item in release.artifacts]
        seal_record(release)
        db.commit()
        mapping = db.get(OCIRepository, f.mapping_id)
        approval = oci_authorization.authorize(db, mapping, f.new)
        assert approval.allowed
        assert oci_attestation_inventory.inventory(db, mapping, f.new, approval) == descriptor
        assert oci_attestation_inventory.candidate_subjects(db, mapping, object_digest) == {f.new}
        assert oci_proxy.resolve_distribution_location(db, mapping, f.new) == 'team/nginx'


def test_full_mode_source_administration_retains_permission_boundaries(full_imported):
    f = full_imported
    admin = SimpleNamespace(has=lambda permission, scope=None: permission == 'replica.admin',
        accessible_service_ids=lambda permission: set())
    reader = SimpleNamespace(has=lambda permission, scope=None: permission == 'service.view',
        accessible_service_ids=lambda permission: {f.service_id} if permission == 'service.view' else set())
    with f.sessions() as db:
        assert replica_routes.sources(admin, db)['sources'][0]['id'] == f.source_id
        assert replica_routes.status(admin, db)['mode'] == 'full'
        with pytest.raises(HTTPException) as forbidden:
            replica_routes.sources(reader, db)
        assert forbidden.value.status_code == 403
        assert {r['id'] for r in replica_routes.releases(auth=reader, db=db)['releases']} == {f.old_id, f.new_id}
        assert replica_routes.releases(auth=admin, db=db)['releases'] == []


def immediate(coroutine):
    """Drive request handlers whose in-memory request body performs no external IO."""
    try:
        coroutine.send(None)
    except StopIteration as finished:
        return finished.value
    finally:
        coroutine.close()
    raise AssertionError('Handler unexpectedly suspended on external IO')


def json_request(payload, csrf=None):
    async def receive():
        return {'type': 'http.request', 'body': json.dumps(payload).encode(), 'more_body': False}
    headers = [] if csrf is None else [(b'x-csrf-token', csrf.encode())]
    return Request({'type': 'http', 'method': 'POST', 'path': '/', 'headers': headers}, receive)


def test_full_mode_source_mutations_retain_csrf_and_idempotent_sync(full_imported):
    f = full_imported
    admin = SimpleNamespace(user=f.auth.user, csrf_token='token',
        has=lambda permission, scope=None: permission == 'replica.admin')
    syncer = SimpleNamespace(user=f.auth.user, csrf_token='token',
        has=lambda permission, scope=None: permission == 'replica.sync')
    payload = dict(name='another source', upstream_id=1, repository='approved/api/releases',
        trusted_publishers=['sha256:' + 'a' * 64])
    with f.sessions() as db:
        with pytest.raises(HTTPException) as missing_csrf:
            immediate(replica_routes.create_source(json_request(payload), admin, db))
        assert missing_csrf.value.status_code == 403
        created = immediate(replica_routes.create_source(json_request(payload, 'token'), admin, db))
        with pytest.raises(HTTPException) as missing_permission:
            immediate(replica_routes.synchronize(json_request({}, 'token'), admin, db))
        assert missing_permission.value.status_code == 403
        for csrf in (None, 'wrong'):
            with pytest.raises(HTTPException) as denied:
                immediate(replica_routes.synchronize(json_request({'source_id': created['id']}, csrf), syncer, db))
            assert denied.value.status_code == 403
        first = immediate(replica_routes.synchronize(json_request({'source_id': created['id']}, 'token'), syncer, db))
        repeated = immediate(replica_routes.synchronize(json_request({'source_id': created['id']}, 'token'), syncer, db))
        assert first['jobs'][0]['id'] == repeated['jobs'][0]['id']


def test_full_mode_signed_sync_imports_and_replays_without_starting_local_work(replica_import, monkeypatch):
    f = replica_import
    monkeypatch.setenv('CATS_MODE', 'full')
    incoming = verified(f)
    sessions = worker(f, monkeypatch, incoming)
    replica_sync.schedule_due(sessions)
    pending = durable_jobs.claim([replica_sync.KIND], 'full-mode-worker', sessions)
    assert pending is not None
    durable_jobs.execute(pending, replica_sync.sync, sessions)
    f.db.expire_all()
    imported = f.db.scalar(select(ReplicaServiceState))
    assert imported is not None and imported.high_sequence == 1
    assert not is_imported_service(f.db, 51)
    assert is_imported_service(f.db, imported.service_id)
    mapping = f.db.scalar(select(OCIRepository).where(OCIRepository.service_id == imported.service_id))
    assert oci_authorization.authorize(f.db, mapping, incoming['artifacts'][0]['digest']).allowed
    replica_sync.enqueue(f.db, f.source)
    f.db.commit()
    replay = durable_jobs.claim([replica_sync.KIND], 'full-mode-worker', sessions)
    durable_jobs.execute(replay, replica_sync.sync, sessions)
    f.db.expire_all()
    assert len(list(f.db.scalars(select(ReplicaRelease)))) == 1
    assert f.db.get(durable_jobs.DurableJob, replay.id).result['unchanged'] == 1
