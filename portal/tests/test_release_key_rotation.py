"""Key continuity uses real cryptographic signatures; registry transport is separate."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import release_key_rotation as rotation, signing
from app.cyber_approvals import CyberApproval
from app.replica_authorization import trusted_release
from app.replica_import import reconcile, ReplicaImportError
from app.replica_models import (ReleasePublicationSequence, ReplicaPublisherTrust,
                               ReplicaRelease, ReplicaServiceState, ReplicaSource)
from app.secrets import encrypt_secret, decrypt_secret
from test_replica_import import replica_import, verified


@pytest.fixture
def rotation_keys(replica_import, monkeypatch):
    def sign(certificate, configuration):
        key = serialization.load_pem_private_key(base64.b64decode(decrypt_secret(configuration['private_key'])), None)
        return base64.b64encode(key.sign(rotation.canonical(certificate), ec.ECDSA(hashes.SHA256()))).decode()
    def verify(content, signature, public):
        try:
            serialization.load_pem_public_key(public.encode()).verify(base64.b64decode(signature, validate=True), content, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError) as exc:
            raise ValueError('Publisher key transition signature verification failed') from exc
    monkeypatch.setattr(rotation, '_sign', sign)
    monkeypatch.setattr(rotation, '_verify', verify)
    result = []
    for _ in range(3):
        key = ec.generate_private_key(ec.SECP256R1())
        public, fingerprint = signing.public_key(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        result.append(dict(enabled=True, public_key=public, fingerprint=fingerprint,
            private_key=encrypt_secret(base64.b64encode(private).decode()), password=''))
    f = replica_import
    f.source.trusted_publishers = [result[0]['fingerprint']]
    f.origin.add(ReleasePublicationSequence(service_id=f.service.id, sequence=1))
    f.origin.flush()
    return result


def event(fixture, configuration, sequence):
    result = verified(fixture, sequence)
    result['manifest']['signing_fingerprint'] = configuration['fingerprint']
    result['manifest'].update(rotation.manifest_identity({signing.SETTING: json.dumps(configuration)}, fixture.service.service_key, sequence))
    result.update(rotation.verify_identity(result['manifest'], configuration['public_key'].encode(), fixture.source.trusted_publishers))
    return result


def test_authenticated_repeated_rotation_preserves_service_history_and_pin(replica_import, rotation_keys):
    f = replica_import
    first, second, third = rotation_keys
    baseline = event(f, first, 1)
    reconcile(f.db, f.source, baseline)
    original = f.db.scalar(select(ReplicaServiceState))
    original_id = original.service_id
    second = rotation.prepare_configuration(f.origin, first, second)
    reconcile(f.db, f.source, event(f, second, 2))
    f.origin.get(ReleasePublicationSequence, f.service.id).sequence = 2
    third = rotation.prepare_configuration(f.origin, second, third)
    reconcile(f.db, f.source, event(f, third, 3))
    releases = f.db.scalars(select(ReplicaRelease).order_by(ReplicaRelease.sequence)).all()
    state = f.db.get(ReplicaServiceState, original_id)
    assert [r.service_id for r in releases] == [original_id] * 3
    assert [r.publisher for r in releases] == [first['fingerprint']] * 3
    assert [r.key_fingerprint for r in releases] == [item['fingerprint'] for item in (first, second, third)]
    assert state.high_sequence == 3 and state.active_release_id == releases[-1].id
    assert all(trusted_release(f.db, release, state, f.now) for release in releases)
    assert reconcile(f.db, f.source, baseline)['status'] == 'unchanged'
    f.source.trusted_publishers = [third['fingerprint']]
    f.db.flush()
    assert not any(trusted_release(f.db, release, state, f.now) for release in releases)
    with pytest.raises(ValueError, match='trust anchor'):
        rotation.verify_identity(event_manifest(third, f.service.service_key, 4), third['public_key'].encode(), [third['fingerprint']])


def event_manifest(configuration, service, sequence):
    return {'portable': {'service_uuid': service, 'release_sequence': sequence},
        **rotation.manifest_identity({signing.SETTING: json.dumps(configuration)}, service, sequence)}


def test_disconnected_bootstrap_and_new_service_use_original_pin(replica_import, rotation_keys):
    f = replica_import
    first, second, third = rotation_keys
    second = rotation.prepare_configuration(f.origin, first, second)
    f.origin.get(ReleasePublicationSequence, f.service.id).sequence = 2
    third = rotation.prepare_configuration(f.origin, second, third)
    reconcile(f.db, f.source, event(f, third, 3))
    trust = f.db.get(ReplicaPublisherTrust, (f.source.id, first['fingerprint']))
    assert trust.generation == 2 and rotation.verify_trust(trust)
    manifest = event_manifest(third, 'new-after-rotation', 1)
    assert rotation.verify_identity(manifest, third['public_key'].encode(), [first['fingerprint']])['publisher_root'] == first['fingerprint']


def test_retired_key_cannot_create_release_or_revocation_even_with_larger_sequence(replica_import, rotation_keys):
    f = replica_import
    first, second, _ = rotation_keys
    reconcile(f.db, f.source, event(f, first, 1))
    second = rotation.prepare_configuration(f.origin, first, second)
    reconcile(f.db, f.source, event(f, second, 2))
    for kind in ('release', 'revocation'):
        stale = event(f, first, 100)
        stale['manifest']['portable']['kind'] = kind
        with pytest.raises(ValueError, match='cannot authorize this service sequence'):
            reconcile(f.db, f.source, stale)
    assert f.db.scalar(select(ReplicaServiceState)).high_sequence == 2


def test_cutover_is_bound_to_each_service_and_cannot_be_forged(replica_import, rotation_keys):
    f = replica_import
    first, second, _ = rotation_keys
    second = rotation.prepare_configuration(f.origin, first, second)
    manifest = event_manifest(second, f.service.service_key, 2)
    manifest['portable']['release_sequence'] = 1
    with pytest.raises(ValueError, match='sequence'):
        rotation.verify_identity(manifest, second['public_key'].encode(), [first['fingerprint']])
    forged = deepcopy(second['signing_key_chain'])
    forged[0]['certificate']['service_cutovers'][f.service.service_key] = 1
    with pytest.raises(ValueError, match='signature'):
        rotation.validate_chain(forged)
    # A certificate with a different predecessor key has no authority here.
    forged = deepcopy(second['signing_key_chain'])
    forged[0]['certificate']['publisher_root'] = second['fingerprint']
    with pytest.raises(ValueError, match='anchor'):
        rotation.validate_chain(forged)


@pytest.mark.parametrize('field', ['from_signature', 'to_signature'])
def test_both_authorization_and_new_key_possession_are_required(replica_import, rotation_keys, field):
    first, second, _ = rotation_keys
    second = rotation.prepare_configuration(replica_import.origin, first, second)
    forged = deepcopy(second['signing_key_chain'])
    forged[0][field] = base64.b64encode(b'wrong signature').decode()
    with pytest.raises(ValueError, match='signature'):
        rotation.validate_chain(forged)


@pytest.mark.parametrize('malformed', [{'publisher_root': 'sha256:' + '0' * 64}, {'signing_key_chain': None}, {'signing_key_chain': {}}])
def test_legacy_configuration_cannot_claim_unproven_root(replica_import, rotation_keys, malformed):
    first, second, _ = rotation_keys
    first = {**first, **malformed}
    settings = {signing.SETTING: json.dumps(first)}
    with pytest.raises(ValueError, match='continuity'):
        rotation.prepare_configuration(replica_import.origin, first, second)
    with pytest.raises(ValueError, match='continuity'):
        rotation.manifest_identity(settings, replica_import.service.service_key, 1)
    with pytest.raises(ValueError, match='continuity'):
        rotation.authorized_successor(settings, first['fingerprint'])


def test_chain_reordering_reuse_limits_and_trust_tampering_fail_closed(replica_import, rotation_keys):
    f = replica_import
    first, second, third = rotation_keys
    second = rotation.prepare_configuration(f.origin, first, second)
    f.origin.get(ReleasePublicationSequence, f.service.id).sequence = 2
    third = rotation.prepare_configuration(f.origin, second, third)
    with pytest.raises(ValueError, match='order'):
        rotation.validate_chain(list(reversed(third['signing_key_chain'])))
    with pytest.raises(ValueError, match='limit'):
        rotation.validate_chain(third['signing_key_chain'] * 17)
    with pytest.raises(ValueError, match='reused'):
        rotation.prepare_configuration(f.origin, third, first)
    reconcile(f.db, f.source, event(f, third, 3))
    release = f.db.scalar(select(ReplicaRelease))
    state = f.db.get(ReplicaServiceState, release.service_id)
    trust = f.db.get(ReplicaPublisherTrust, (f.source.id, first['fingerprint']))
    trust.generation = 1
    assert not trusted_release(f.db, release, state, f.now)
    with pytest.raises(ValueError, match='integrity'):
        reconcile(f.db, f.source, event(f, third, 4))


def test_failed_projection_rolls_back_key_advance_and_source_identity(replica_import, rotation_keys, monkeypatch):
    f = replica_import
    first, second, _ = rotation_keys
    reconcile(f.db, f.source, event(f, first, 1))
    f.db.commit()
    second = rotation.prepare_configuration(f.origin, first, second)
    successor = event(f, second, 2)
    def fail(*args):
        raise ValueError('Projection failed')
    monkeypatch.setattr('app.replica_import._projection', fail)
    with pytest.raises(ValueError, match='Projection failed'):
        reconcile(f.db, f.source, successor)
    f.db.rollback()
    trust = f.db.get(ReplicaPublisherTrust, (f.source.id, first['fingerprint']))
    assert trust.generation == 0 and rotation.verify_trust(trust)
    assert f.db.scalar(select(ReplicaServiceState)).high_sequence == 1


def test_missing_trust_record_cannot_reset_rotated_publisher(replica_import, rotation_keys):
    f = replica_import
    first, second, _ = rotation_keys
    reconcile(f.db, f.source, event(f, first, 1))
    second = rotation.prepare_configuration(f.origin, first, second)
    reconcile(f.db, f.source, event(f, second, 2))
    f.db.delete(f.db.get(ReplicaPublisherTrust, (f.source.id, first['fingerprint'])))
    f.db.flush()
    for configuration in (first, second):
        with pytest.raises(ValueError, match='continuity record is missing'):
            reconcile(f.db, f.source, event(f, configuration, 100))
    assert f.db.get(ReplicaPublisherTrust, (f.source.id, first['fingerprint'])) is None
    assert f.db.scalar(select(ReplicaServiceState)).high_sequence == 2


def test_missing_legacy_trust_record_and_new_source_can_bootstrap(replica_import, rotation_keys):
    f = replica_import
    first, second, _ = rotation_keys
    reconcile(f.db, f.source, event(f, first, 1))
    f.db.delete(f.db.get(ReplicaPublisherTrust, (f.source.id, first['fingerprint'])))
    f.db.flush()
    assert reconcile(f.db, f.source, event(f, first, 2))['status'] == 'activated'
    f.origin.get(ReleasePublicationSequence, f.service.id).sequence = 2
    second = rotation.prepare_configuration(f.origin, first, second)
    successor = event(f, second, 3)
    successor['manifest']['portable']['supersedes_release_uuid'] = 'release-2'
    reconcile(f.db, f.source, successor)
    other = ReplicaSource(name='other source', upstream_id=f.source.upstream_id,
        repository='other/release', trusted_publishers=[first['fingerprint']],
        created_by_id=f.source.created_by_id)
    f.db.add(other)
    f.db.flush()
    identity = rotation.verify_identity(event_manifest(second, 'other-service', 1),
        second['public_key'].encode(), other.trusted_publishers)
    trust = rotation.reconcile_trust(f.db, other, identity, 'other-service', 1)
    assert trust.generation == 1 and rotation.verify_trust(trust)


@pytest.mark.parametrize('publication,revoked,status', [({}, False, 'queued'), ({}, False, 'failed'),
    ({'revocation': {'status': 'queued'}}, True, 'published'), ({'revocation': {'status': 'failed'}}, True, 'published')])
def test_rotation_does_not_strand_reserved_publications(replica_import, rotation_keys, publication, revoked, status):
    f = replica_import
    first, second, _ = rotation_keys
    f.origin.add(CyberApproval(service_id=f.service.id, source_execution_id=f.execution.id,
        variant='original', status='approved', publish_status=status,
        snapshot={'portable_release': {'release_sequence': 1}, 'signing_fingerprint': first['fingerprint']},
        snapshot_digest='sha256:' + 'a' * 64, publication=publication, revoked_at=f.now if revoked else None))
    f.origin.flush()
    with pytest.raises(ValueError, match='Complete or retry'):
        rotation.prepare_configuration(f.origin, first, second)


def test_current_successor_can_revoke_old_release(replica_import, rotation_keys):
    f = replica_import
    first, second, _ = rotation_keys
    reconcile(f.db, f.source, event(f, first, 1))
    second = rotation.prepare_configuration(f.origin, first, second)
    settings = {signing.SETTING: json.dumps(second)}
    assert rotation.authorized_successor(settings, first['fingerprint'])
    revoked = event(f, second, 2)
    revoked['manifest']['portable'].update(kind='revocation', target_release_uuid='release-1')
    revoked['manifest'].update(revoked_at=f.now.isoformat(), reason='Publisher revocation')
    assert reconcile(f.db, f.source, revoked)['status'] == 'revoked'
    assert f.db.scalar(select(ReplicaRelease)).revoked_at is not None


def test_cold_bootstrap_of_older_service_respects_retained_cutover(replica_import, rotation_keys):
    from app.models import Service
    f = replica_import
    first, second, _ = rotation_keys
    older_service = Service(service_key='older-service', name='Older Service')
    f.origin.add(older_service)
    f.origin.flush()
    f.origin.add(ReleasePublicationSequence(service_id=older_service.id, sequence=1))
    f.origin.flush()
    historical = deepcopy(event(f, first, 1))
    historical['manifest']['portable'].update(service_uuid=older_service.service_key,
        release_uuid='older-service-release-1', supersedes_release_uuid=None)
    historical['state']['records']['services'][0]['service_key'] = older_service.service_key
    historical['state']['records']['executions'][0]['raw_payload']['service']['id'] = older_service.service_key
    second = rotation.prepare_configuration(f.origin, first, second)
    reconcile(f.db, f.source, event(f, second, 2))
    imported = reconcile(f.db, f.source, historical)
    state = f.db.get(ReplicaServiceState, imported['service_id'])
    release = f.db.get(ReplicaRelease, state.active_release_id)
    assert state.high_sequence == 1 and trusted_release(f.db, release, state, f.now)
    assert f.db.get(ReplicaPublisherTrust, (f.source.id, first['fingerprint'])).generation == 1
    stale = deepcopy(historical)
    stale['manifest']['portable'].update(release_sequence=2, release_uuid='older-service-release-2')
    with pytest.raises(ValueError, match='cannot authorize this service sequence'):
        reconcile(f.db, f.source, stale)


def test_concurrent_imports_cannot_regress_persisted_chain(replica_import, rotation_keys, tmp_path):
    f = replica_import
    first, second, third = rotation_keys
    reconcile(f.db, f.source, event(f, first, 1))
    second = rotation.prepare_configuration(f.origin, first, second)
    successor = event(f, second, 2)
    f.origin.get(ReleasePublicationSequence, f.service.id).sequence = 2
    third = rotation.prepare_configuration(f.origin, second, third)
    latest = event(f, third, 3)
    latest['manifest']['portable']['supersedes_release_uuid'] = 'release-2'
    source_id = f.source.id
    f.db.commit()
    filename = tmp_path / 'concurrent-import.db'
    with sqlite3.connect(filename) as target:
        with f.db.get_bind().connect() as connection:
            connection.connection.driver_connection.backup(target)
    engine = create_engine('sqlite:///' + str(filename), connect_args={'timeout': 10})
    barrier = Barrier(2)
    def import_event(value):
        with Session(engine) as db:
            source = db.get(ReplicaSource, source_id)
            retained = db.get(ReplicaPublisherTrust, (source_id, first['fingerprint']))
            assert retained.generation == 0
            barrier.wait(timeout=5)
            try:
                reconcile(db, source, value)
                db.commit()
                return 'imported'
            except ReplicaImportError as exc:
                db.rollback()
                assert 'Rollback rejected' in str(exc)
                return 'stale'
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(import_event, (successor, latest)))
    assert outcomes[1] == 'imported'
    with Session(engine) as db:
        trust = db.get(ReplicaPublisherTrust, (source_id, first['fingerprint']))
        state = db.scalar(select(ReplicaServiceState))
        assert trust.generation == 2 and rotation.verify_trust(trust)
        assert state.high_sequence == 3
        assert db.get(ReplicaRelease, state.active_release_id).key_fingerprint == third['fingerprint']
    engine.dispose()


def test_standalone_offline_verifier_accepts_only_authenticated_original_pin(replica_import, rotation_keys):
    from app.cyber_release_publication import OFFLINE_SCRIPT
    f = replica_import
    first, second, third = rotation_keys
    second = rotation.prepare_configuration(f.origin, first, second)
    f.origin.get(ReleasePublicationSequence, f.service.id).sequence = 2
    third = rotation.prepare_configuration(f.origin, second, third)
    namespace = {'__name__': 'offline_verifier_test'}
    exec(compile(OFFLINE_SCRIPT, '<offline-verifier>', 'exec'), namespace)
    calls = []
    def verify_command(args):
        calls.append(args)
        public = Path(args[args.index('--key') + 1]).read_text()
        signature = Path(args[args.index('--signature') + 1]).read_text()
        rotation._verify(Path(args[-1]).read_bytes(), signature, public)
        return b''
    namespace['run'] = verify_command
    manifest = event(f, third, 3)['manifest']
    namespace['verify_publisher'](manifest, third['public_key'], first['fingerprint'])
    assert len(calls) == 4
    for mutation in ('wrong_pin', 'wrong_signer', 'forged_cutover', 'wrong_possession', 'reordered', 'old_sequence'):
        forged = deepcopy(manifest)
        pin, public = first['fingerprint'], third['public_key']
        if mutation == 'wrong_pin': pin = third['fingerprint']
        if mutation == 'wrong_signer': public = second['public_key']
        if mutation == 'forged_cutover': forged['signing_key_chain'][0]['certificate']['service_cutovers'][f.service.service_key] = 1
        if mutation == 'wrong_possession': forged['signing_key_chain'][1]['to_signature'] = base64.b64encode(b'wrong').decode()
        if mutation == 'reordered': forged['signing_key_chain'].reverse()
        if mutation == 'old_sequence': forged['portable']['release_sequence'] = 2
        with pytest.raises(ValueError):
            namespace['verify_publisher'](forged, public, pin)


def test_concurrent_key_replacements_cannot_fork_persisted_identity(rotation_keys, tmp_path):
    from app.database import Base
    from app.models import PortalSetting
    first, second, third = rotation_keys
    engine = create_engine('sqlite:///' + str(tmp_path / 'rotation.db'), connect_args={'timeout': 10})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(PortalSetting(key=signing.SETTING, value=json.dumps(first)))
        db.commit()
    barrier = Barrier(2)
    def replace(candidate):
        with Session(engine) as db:
            barrier.wait(timeout=5)
            try:
                configured = rotation.prepare_configuration(db, first, candidate)
                row = db.scalar(select(PortalSetting).where(PortalSetting.key == signing.SETTING))
                row.value = json.dumps(configured)
                db.commit()
                return 'saved'
            except ValueError as exc:
                db.rollback()
                assert 'configuration changed' in str(exc)
                return 'stale'
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(replace, (second, third)))
    assert sorted(outcomes) == ['saved', 'stale']
    with Session(engine) as db:
        current = json.loads(db.scalar(select(PortalSetting.value)))
        assert len(current['signing_key_chain']) == 1
        assert rotation.validate_chain(current['signing_key_chain'])[0] == first['fingerprint']
