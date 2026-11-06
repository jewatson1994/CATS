"""Replica reconstruction tests use strict foreign keys and verified-format fixtures.

Cryptographic registry verification is exercised by portable-release tests; these
tests cover the transaction consumer and its faithful, inert evidence projection.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cryptography.fernet import Fernet
import pytest
from sqlalchemy import Boolean, DateTime, Integer, JSON, create_engine, event, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import models as m, service_transfer as transfer
from app.database import Base
from app.oci_models import OCIRepository, OCIUpstream
from app.replica_authorization import authorize, ensure_repository_mappings, release_denial
from app.replica_import import ReplicaImportError, _projection, reconcile
from app.replica_integrity import verify_record
from app.replica_models import ReplicaEvent, ReplicaRecordMap, ReplicaRelease, ReplicaServiceState, ReplicaSource


def engine():
    result = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    @event.listens_for(result, 'connect')
    def foreign_keys(connection, _):
        connection.execute('PRAGMA foreign_keys=ON')
    Base.metadata.create_all(result)
    return result


@pytest.fixture
def replica_import(monkeypatch, tmp_path):
    monkeypatch.setenv('CATS_MODE', 'replica')
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('CATS_REPLICA_STORAGE', str(tmp_path / 'evidence'))
    source_engine, local_engine = engine(), engine()
    with Session(source_engine, expire_on_commit=False) as origin, Session(local_engine, expire_on_commit=False) as db:
        timestamp = datetime.now(timezone.utc)
        author = m.User(username='upstream-author', display_name='Upstream Author', password_hash='!')
        origin.add(author)
        service = m.Service(service_key='portable-service', name='Portable Service')
        origin.add(service)
        origin.flush()
        version = m.ServiceVersion(service_id=service.id, version='1.0', created_at=timestamp)
        origin.add(version)
        origin.flush()
        service.current_version_id = version.id
        payload = {'execution_id': 'upstream-scan-1', 'scanned_at': timestamp.isoformat(),
            'complete': True, 'fixable_only': False,
            'service': {'id': service.service_key, 'name': service.name, 'version': '1.0'}}
        execution = m.Execution(execution_key='upstream-scan-1', service_id=service.id,
            service_version_id=version.id, scanned_at=timestamp, complete=True, raw_payload=payload)
        origin.add(execution)
        origin.flush()
        # Occupy local IDs to expose accidental source-ID retention.
        local_user = m.User(id=41, username='local-importer', display_name='Local Importer', password_hash='!')
        db.add_all([local_user, m.Service(id=51, service_key='unrelated', name='Unrelated')])
        upstream = OCIUpstream(name='registry', endpoint='https://registry.example')
        db.add(upstream)
        db.flush()
        db.add(m.ServiceArtifact(id=61, service_id=51, artifact_type='helm_chart', artifact_name='unrelated'))
        db.flush()
        source = ReplicaSource(name='approved', upstream_id=upstream.id, repository='approved/service',
            trusted_publishers=['trusted-publisher'], created_by_id=local_user.id)
        db.add(source)
        db.commit()
        yield SimpleNamespace(origin=origin, db=db, source=source, service=service,
            execution=execution, author=author, user=local_user, now=timestamp)
    source_engine.dispose()
    local_engine.dispose()


def verified(fixture, sequence=1, *, expires_at=None, artifacts=None):
    fixture.origin.flush()
    previous = fixture.db.scalar(select(ReplicaRelease).order_by(ReplicaRelease.sequence.desc()))
    manifest = {'approved_at': (fixture.now - timedelta(days=1)).isoformat(),
        'expires_at': expires_at.isoformat() if expires_at else None,
        'portable': {'format': 'cats-replica-release-v1', 'service_uuid': fixture.service.service_key,
            'release_uuid': f'release-{sequence}', 'release_sequence': sequence, 'kind': 'release',
            'supersedes_release_uuid': previous.source_release_id if previous else None}}
    return {'manifest': manifest, 'verified': True, 'complete': True,
        'key_fingerprint': 'trusted-publisher', 'reference': 'approved/service@sha256:' + 'a' * 64,
        'state': {'records': transfer.snapshot(fixture.origin, fixture.service),
            'actors': {'users': [{'id': fixture.author.id, 'username': fixture.author.username}]},
            'activity': [{'action': 'upstream.reviewed'}],
            'extension': {'approval_context': {'source_execution_id': fixture.execution.id}}},
        'evidence': f'complete verified evidence {sequence}'.encode(),
        'artifacts': artifacts or [{'repository': 'images/application', 'digest': 'sha256:' + 'a' * 64,
            'kind': 'image', 'manifests': [], 'blobs': []}]}


def test_all_evidence_domains_remap_foreign_keys_and_preserve_assessments(replica_import):
    f = replica_import
    parents = {'services': f.service.id, 'service_versions': f.service.current_version_id,
        'executions': f.execution.id, 'users': f.author.id}
    for model in transfer.MODELS[3:]:
        values = {}
        for column in model.__table__.columns:
            if column.name == 'id' or column.nullable or column.default is not None:
                continue
            if column.foreign_keys:
                parent = next(iter(column.foreign_keys)).column.table.name
                values[column.name] = parents[parent]
            elif isinstance(column.type, DateTime): values[column.name] = f.now
            elif isinstance(column.type, Boolean): values[column.name] = True
            elif isinstance(column.type, Integer): values[column.name] = 1
            elif isinstance(column.type, JSON): values[column.name] = {}
            else: values[column.name] = 'test'
        if model is m.RemediationExecution:
            values.update(finding_type='vulnerability', finding_id=parents['findings'], status='running')
        if model is m.PatchExecution:
            values.update(status='queued')
        if model is m.ServiceArtifact:
            values.update(source_reference=f.execution.execution_key)
        if model is m.DeploymentValidationRun:
            values.update(execution_id=f.execution.id, artifact_revision_id=parents['service_artifact_revisions'],
                artifact_reference=f'artifact:{parents["service_artifacts"]}:r1',
                status='RUNNING', cluster_name='upstream-cluster', cleanup_status='PENDING')
        row = model(**values)
        f.origin.add(row)
        f.origin.flush()
        parents[model.__tablename__] = row.service_id if model is m.ServiceMetadata else row.id
        if model is m.ServiceArtifact:
            row.source_metadata = {'definition_artifact_id': row.id, 'components': [{'chart_artifact_id': row.id}]}
    incoming = verified(f)
    untouched = deepcopy(incoming['state'])
    result = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    assert incoming['state'] == untouched
    service = f.db.get(m.Service, result['service_id'])
    assert service.id != f.service.id
    assert service.assessment_status == 'assessed'
    maps = {(row.table_name, row.source_id): row.local_id for row in f.db.scalars(select(ReplicaRecordMap))}
    local_execution = f.db.get(m.Execution, maps['executions', f.execution.id])
    assert local_execution.complete is True
    assert local_execution.raw_payload == f.execution.raw_payload
    assert local_execution.service_id == service.id
    assert local_execution.service_version_id == service.current_version_id
    for name, source_id in parents.items():
        if name in {'services', 'users'}:
            continue
        local = f.db.get(transfer.TABLES[name], maps[name, source_id])
        assert local is not None, name
        if hasattr(local, 'service_id'):
            assert local.service_id == service.id, name
    remediation = f.db.get(m.RemediationExecution, maps['remediation_executions', parents['remediation_executions']])
    assert remediation.finding_id == maps['findings', parents['findings']]
    assert remediation.status == 'failed'
    assert remediation.requested_by_id == f.user.id
    assert f.db.scalar(select(m.PatchExecution)).status == 'failed'
    assert f.db.scalar(select(m.DependencyWatchlistEntry)).enabled is False
    validation = f.db.scalar(select(m.DeploymentValidationRun))
    assert validation.cluster_name is None
    assert validation.cleanup_status == 'NOT_STARTED'
    assert validation.status == 'NOT_ATTEMPTED'
    artifact = f.db.get(m.ServiceArtifact, maps['service_artifacts', parents['service_artifacts']])
    assert artifact.source_reference == local_execution.execution_key
    assert artifact.id != parents['service_artifacts']
    assert artifact.source_metadata['definition_artifact_id'] == artifact.id
    assert artifact.source_metadata['components'][0]['chart_artifact_id'] == artifact.id
    assert validation.artifact_reference == f'artifact:{artifact.id}:r1'
    provenance = f.db.scalars(select(m.ServiceTransferProvenance)).all()
    assert any(row.detail.get('actors') == untouched['actors'] for row in provenance)
    release = f.db.get(ReplicaRelease, result['release_id'])
    assert verify_record(release)
    assert release.evidence_state == untouched
    assert f.db.get(ReplicaServiceState, service.id).active_execution_id == local_execution.id
    assert f.db.scalar(select(ReplicaEvent)).kind == 'release'


def test_complete_snapshot_replaces_23_of_100_images_and_keeps_history(replica_import):
    """Synthetic verified manifests: exact 100/23 inventories, no registry claim."""
    f = replica_import
    images = [m.ServiceImage(service_id=f.service.id, image_reference=f'registry/app-{i}:1',
        image_digest='sha256:' + f'{i:064x}', scan_status='completed') for i in range(100)]
    f.origin.add_all(images)
    def inventory():
        return [{'repository': image.image_reference.split(':')[0], 'digest': image.image_digest,
            'kind': 'image', 'manifests': [], 'blobs': []} for image in f.origin.scalars(
                select(m.ServiceImage).where(m.ServiceImage.lifecycle_status == 'active'))]
    original_inventory = inventory()
    incoming = verified(f, artifacts=original_inventory)
    historical_evidence = deepcopy(incoming['state'])
    first = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    def decision(artifact):
        mapping = f.db.scalar(select(OCIRepository).where(OCIRepository.service_id == first['service_id'],
            OCIRepository.upstream_repository == artifact['repository']))
        return authorize(f.db, mapping, artifact['digest'], now=f.now)
    assert len(original_inventory) == 100
    assert all(decision(artifact).allowed for artifact in original_inventory)
    original_maps = {row.source_id: row.local_id for row in f.db.scalars(
        select(ReplicaRecordMap).where(ReplicaRecordMap.table_name == 'service_images'))}
    for image in images[:23]:
        image.lifecycle_status = 'superseded'
        f.origin.add(m.ServiceImage(service_id=f.service.id, image_reference=image.image_reference.replace(':1', ':2'),
            image_digest='sha256:' + f'{1000 + image.id:064x}', replacement_of_id=image.id,
            scan_status='completed'))
    f.service.manual_version = '2.0'
    replacement_inventory = inventory()
    next_release = verified(f, 2, artifacts=replacement_inventory)
    assert len(replacement_inventory) == 100
    unchanged = {row['digest'] for row in original_inventory} & {row['digest'] for row in replacement_inventory}
    assert len(unchanged) == 77
    # Missing replicated content cannot move any active membership or evidence.
    with pytest.raises(ReplicaImportError, match='verification'):
        reconcile(f.db, f.source, {**next_release, 'complete': False}, now=f.now)
    f.db.rollback()
    assert f.db.get(ReplicaServiceState, first['service_id']).active_release_id == first['release_id']
    assert all(decision(artifact).allowed for artifact in original_inventory)
    assert f.db.get(ReplicaRelease, first['release_id']).evidence_state == historical_evidence
    second = reconcile(f.db, f.source, next_release, now=f.now)
    f.db.commit()
    assert first['service_id'] == second['service_id']
    assert f.db.scalar(select(func.count()).select_from(m.Service).where(
        m.Service.service_key == f.service.service_key)) == 1
    assert all(decision(artifact).allowed for artifact in replacement_inventory)
    for artifact in original_inventory:
        result = decision(artifact)
        assert result.allowed is (artifact['digest'] in unchanged)
        assert result.reason == ('active_approved_release' if artifact['digest'] in unchanged else 'release_superseded')
    assert f.db.scalar(select(func.count()).select_from(m.ServiceImage).where(
        m.ServiceImage.service_id == first['service_id'], m.ServiceImage.lifecycle_status == 'active')) == 100
    assert f.db.scalar(select(func.count()).select_from(m.ServiceImage).where(
        m.ServiceImage.service_id == first['service_id'])) == 123
    for source_id, local_id in original_maps.items():
        assert f.db.get(m.ServiceImage, local_id) is not None
    state = f.db.get(ReplicaServiceState, first['service_id'])
    assert state.active_release_id == second['release_id']
    assert release_denial(f.db.get(ReplicaRelease, first['release_id']), state, f.now) == 'superseded'
    assert f.db.get(ReplicaRelease, first['release_id']).evidence_state == historical_evidence
    assert f.db.get(ReplicaRelease, second['release_id']).evidence_state['records']['services'][0]['manual_version'] == '2.0'


def test_duplicate_import_restores_missing_archive_but_rejects_changed_retained_state(replica_import):
    from pathlib import Path
    f = replica_import
    incoming = verified(f)
    first = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    retained = f.db.get(ReplicaRelease, first['release_id'])
    Path(retained.evidence_path).unlink()
    assert reconcile(f.db, f.source, incoming, now=f.now)['status'] == 'unchanged'
    f.db.commit()
    assert Path(retained.evidence_path).read_bytes() == incoming['evidence']
    assert f.db.get(ReplicaServiceState, first['service_id']).active_release_id == first['release_id']
    damaged = deepcopy(retained.evidence_state)
    damaged['records']['services'][0]['name'] = 'Changed locally'
    retained.evidence_state = damaged
    f.db.flush()
    with pytest.raises(ReplicaImportError, match='integrity'):
        reconcile(f.db, f.source, incoming, now=f.now)
    f.db.rollback()


def test_replay_collision_rollback_and_incomplete_import_do_not_move_active_release(replica_import):
    f = replica_import
    incoming = verified(f, 2)
    first = reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    assert reconcile(f.db, f.source, incoming, now=f.now)['status'] == 'unchanged'
    f.db.commit()
    cases = [(verified(f, 1), 'Rollback'),
        ({**deepcopy(incoming), 'manifest': {**incoming['manifest'], 'tampered': True}}, 'collision'),
        ({**verified(f, 3), 'complete': False}, 'verification')]
    for bad, message in cases:
        with pytest.raises(ReplicaImportError, match=message):
            reconcile(f.db, f.source, bad, now=f.now)
        f.db.rollback()
        assert f.db.get(ReplicaServiceState, first['service_id']).active_release_id == first['release_id']
        assert f.db.scalar(select(func.count()).select_from(ReplicaRelease)) == 1
        assert f.db.scalar(select(func.count()).select_from(ReplicaEvent)) == 1


def test_newest_expired_release_supersedes_previous_without_granting_pulls(replica_import):
    f = replica_import
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    second = reconcile(f.db, f.source, verified(f, 2, expires_at=f.now - timedelta(hours=1)), now=f.now)
    f.db.commit()
    state = f.db.get(ReplicaServiceState, first['service_id'])
    assert state.active_release_id == second['release_id']
    assert release_denial(f.db.get(ReplicaRelease, first['release_id']), state, f.now) == 'superseded'
    assert release_denial(f.db.get(ReplicaRelease, second['release_id']), state, f.now) == 'expired'


def test_partial_projection_failure_rolls_back_every_record_and_pointer(replica_import):
    f = replica_import
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    broken = verified(f, 2)
    broken['state']['records']['services'][0]['name'] = 'Must roll back'
    broken['state']['records']['executions'][0]['service_id'] = 99999
    with pytest.raises(ValueError):
        reconcile(f.db, f.source, broken, now=f.now)
    f.db.rollback()
    assert f.db.get(m.Service, first['service_id']).name == 'Portable Service'
    assert f.db.get(ReplicaServiceState, first['service_id']).active_release_id == first['release_id']


def test_failure_after_projection_rolls_back_activation_and_changed_evidence(replica_import, monkeypatch):
    from app import replica_import as importer
    f = replica_import
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    f.service.name = 'New service name'
    f.origin.add(m.ServiceImage(service_id=f.service.id, image_reference='registry/new:1'))
    def fail(_release):
        raise RuntimeError('simulated failure after projection')
    monkeypatch.setattr(importer, 'seal_record', fail)
    with pytest.raises(RuntimeError, match='after projection'):
        reconcile(f.db, f.source, verified(f, 2), now=f.now)
    f.db.rollback()
    assert f.db.get(m.Service, first['service_id']).name == 'Portable Service'
    assert f.db.get(ReplicaServiceState, first['service_id']).active_release_id == first['release_id']
    assert f.db.scalar(select(func.count()).select_from(m.ServiceImage)) == 0
    assert f.db.scalar(select(func.count()).select_from(ReplicaRelease)) == 1
    assert f.db.scalar(select(func.count()).select_from(ReplicaEvent)) == 1


def test_signed_revocation_is_durable_and_tampered_revocation_cannot_restore_trust(replica_import):
    f = replica_import
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    incoming = verified(f, 2)
    incoming['manifest']['portable'].update(kind='revocation', target_release_uuid='release-1')
    incoming['manifest'].update(revoked_at=f.now.isoformat(), reason='Withdrawn by publisher')
    assert reconcile(f.db, f.source, incoming, now=f.now)['status'] == 'revoked'
    f.db.commit()
    release = f.db.get(ReplicaRelease, first['release_id'])
    state = f.db.get(ReplicaServiceState, first['service_id'])
    assert release_denial(release, state, f.now) == 'revoked'
    assert verify_record(release)
    assert state.high_sequence == 2
    assert reconcile(f.db, f.source, incoming, now=f.now)['status'] == 'unchanged'
    release.revoked_at = None
    assert not verify_record(release)


def test_missing_current_items_retire_projection_but_preserve_release_snapshot(replica_import):
    f = replica_import
    f.origin.add(m.ServiceImage(service_id=f.service.id, image_reference='registry/removed:1'))
    finding = m.Finding(service_id=f.service.id, cve='CVE-2026-1234', severity='High',
        first_seen=f.now, episode_started=f.now, last_seen=f.now)
    f.origin.add(finding)
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    incoming = verified(f, 2)
    incoming['state']['records']['service_images'] = []
    incoming['state']['records']['findings'] = []
    reconcile(f.db, f.source, incoming, now=f.now)
    f.db.commit()
    assert f.db.scalar(select(m.ServiceImage)).lifecycle_status == 'superseded'
    assert f.db.scalar(select(m.Finding)).active is False
    old = f.db.get(ReplicaRelease, first['release_id'])
    assert old.evidence_state['records']['service_images'][0]['lifecycle_status'] == 'active'
    assert old.evidence_state['records']['findings'][0]['active'] is True


def test_untrusted_publisher_and_other_source_cannot_rebind_service(replica_import):
    f = replica_import
    bad = verified(f)
    bad['key_fingerprint'] = 'unknown-publisher'
    with pytest.raises(ReplicaImportError, match='not trusted'):
        reconcile(f.db, f.source, bad, now=f.now)
    f.db.rollback()
    first = reconcile(f.db, f.source, verified(f), now=f.now)
    f.db.commit()
    other = ReplicaSource(name='other', upstream_id=f.source.upstream_id, repository='approved/other',
        trusted_publishers=f.source.trusted_publishers, created_by_id=f.user.id)
    f.db.add(other)
    f.db.commit()
    with pytest.raises(ReplicaImportError, match='another configured replica source'):
        reconcile(f.db, other, verified(f, 2), now=f.now)
    f.db.rollback()
    assert f.db.get(ReplicaServiceState, first['service_id']).source_id == f.source.id


def test_routes_are_service_bound_idempotent_and_preserve_suspension(replica_import):
    f = replica_import
    result = reconcile(f.db, f.source, verified(f), now=f.now)
    state = f.db.get(ReplicaServiceState, result['service_id'])
    artifacts = verified(f)['artifacts']
    routes = ensure_repository_mappings(f.db, state, artifacts)
    route = routes[0]
    route.suspended = True
    f.db.flush()
    again = ensure_repository_mappings(f.db, state, artifacts)
    assert again[0].id == route.id
    assert again[0].suspended is True
    assert route.public_repository == f'services/{state.service_id}/images/application'
    assert route.upstream_repository == 'images/application'
    assert route.service_id == state.service_id
    assert route.upstream_id == state.upstream_id
    route.service_id = 51
    f.db.flush()
    with pytest.raises(ValueError, match='conflicts'):
        ensure_repository_mappings(f.db, state, artifacts)
