"""Opt-in PostgreSQL concurrency checks in disposable UUID schemas."""
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Barrier

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import release_key_rotation as rotation, signing
from app.models import PortalSetting
from app.replica_import import reconcile, ReplicaImportError
from app.replica_models import (
    ReleasePublicationSequence, ReplicaPublisherTrust, ReplicaRelease,
    ReplicaServiceState, ReplicaSource,
)
import test_release_key_rotation as rotation_tests
from test_replica_postgres import postgres_engines, postgres_replica


@pytest.fixture
def postgres_rotation_keys(postgres_replica, monkeypatch):
    return rotation_tests.rotation_keys.__wrapped__(postgres_replica, monkeypatch)


@pytest.mark.parametrize('existing_trust', [True, False], ids=['retained-root', 'first-import'])
def test_concurrent_successor_imports_preserve_latest_trust_and_release(
        postgres_replica, postgres_rotation_keys, existing_trust):
    fixture = postgres_replica
    first, second, third = postgres_rotation_keys
    if existing_trust:
        reconcile(fixture.db, fixture.source, rotation_tests.event(fixture, first, 1))
    second = rotation.prepare_configuration(fixture.origin, first, second)
    successor = rotation_tests.event(fixture, second, 2)
    fixture.origin.get(ReleasePublicationSequence, fixture.service.id).sequence = 2
    third = rotation.prepare_configuration(fixture.origin, second, third)
    latest = rotation_tests.event(fixture, third, 3)
    # C may follow B or arrive first as a complete snapshot.
    latest['manifest']['portable']['supersedes_release_uuid'] = 'release-2'
    source_id = fixture.source.id
    fixture.db.commit()
    engine = fixture.db.get_bind()
    start = Barrier(2)

    def import_release(incoming):
        with Session(engine) as db:
            db.execute(text("SET LOCAL statement_timeout = '15s'"))
            source = db.get(ReplicaSource, source_id)
            # Keep pre-lock objects alive to exercise refresh of cached rows.
            prior_trust = db.get(ReplicaPublisherTrust, (source_id, first['fingerprint']))
            prior_state = db.scalar(select(ReplicaServiceState))
            assert (prior_trust is not None) == existing_trust
            assert (prior_state is not None) == existing_trust
            start.wait(timeout=10)
            try:
                result = reconcile(db, source, incoming, now=fixture.now)
                db.commit()
                return result['status']
            except ReplicaImportError as exc:
                db.rollback()
                assert 'Rollback rejected' in str(exc)
                return 'stale'

    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [executor.submit(import_release, value) for value in (successor, latest)]
        outcomes = [future.result(timeout=30) for future in pending]
    assert outcomes[0] in ('activated', 'stale')
    assert outcomes[1] == 'activated'
    with Session(engine) as db:
        trust = db.get(ReplicaPublisherTrust, (source_id, first['fingerprint']))
        assert trust.generation == 2
        assert trust.current_fingerprint == third['fingerprint']
        assert trust.key_chain == third['signing_key_chain']
        assert rotation.verify_trust(trust)
        states = list(db.scalars(select(ReplicaServiceState)))
        assert len(states) == 1
        state = states[0]
        assert state.publisher == first['fingerprint'] and state.high_sequence == 3
        active = db.get(ReplicaRelease, state.active_release_id)
        assert active.source_release_id == 'release-3'
        assert active.key_fingerprint == third['fingerprint']
        assert active.publisher == first['fingerprint']


def test_concurrent_key_replacement_rejects_stale_fork(
        postgres_replica, postgres_rotation_keys):
    fixture = postgres_replica
    first, second, third = postgres_rotation_keys
    fixture.origin.add(PortalSetting(key=signing.SETTING, value=json.dumps(first)))
    fixture.origin.commit()
    engine = fixture.origin.get_bind()
    start = Barrier(2)

    def replace_key(candidate):
        with Session(engine) as db:
            db.execute(text("SET LOCAL statement_timeout = '15s'"))
            row = db.scalar(select(PortalSetting).where(PortalSetting.key == signing.SETTING))
            previous = json.loads(row.value)
            assert previous['fingerprint'] == first['fingerprint']
            start.wait(timeout=10)
            try:
                configured = rotation.prepare_configuration(db, previous, candidate)
                row.value = json.dumps(configured)
                db.commit()
                return 'saved', candidate['fingerprint']
            except ValueError as exc:
                db.rollback()
                assert 'Signing configuration changed' in str(exc)
                return 'stale', candidate['fingerprint']

    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [executor.submit(replace_key, candidate) for candidate in (second, third)]
        outcomes = [future.result(timeout=30) for future in pending]
    assert sorted(status for status, _ in outcomes) == ['saved', 'stale']
    winner = next(fingerprint for status, fingerprint in outcomes if status == 'saved')
    with Session(engine) as db:
        current = json.loads(db.scalar(select(PortalSetting.value).where(PortalSetting.key == signing.SETTING)))
        assert current['fingerprint'] == winner
        assert current['publisher_root'] == first['fingerprint']
        chain = current['signing_key_chain']
        assert len(chain) == 1
        assert rotation.validate_chain(chain) == (first['fingerprint'], [first['fingerprint'], winner])
        assert chain[0]['certificate']['service_cutovers'][fixture.service.service_key] == 2
