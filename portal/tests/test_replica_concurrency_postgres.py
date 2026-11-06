"""Real PostgreSQL row-lock boundaries for concurrent local override revocation."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

from app import oci_proxy as proxy
from app.local_cyber_overrides import lock_for_use, revoke_override
from app.models import AuditEvent
from app.oci_models import OCIPrincipal, OCIRepository
from app.oci_authorization import authorize
from app.replica_import import reconcile
from app.replica_models import ReplicaEvent, ReplicaRelease, ReplicaServiceState, ReplicaSource
from sqlalchemy.orm import sessionmaker
import test_replica_authorization as authorization
from test_replica_import import verified
from test_replica_postgres import postgres_engines, postgres_replica


@pytest.fixture
def postgres_override(postgres_engines, monkeypatch, tmp_path):
    monkeypatch.setattr(authorization, 'create_engine', lambda *args, **kwargs: postgres_engines())
    fixture = authorization.replica.__wrapped__(monkeypatch, tmp_path)
    try:
        yield next(fixture)
    finally:
        fixture.close()


def test_revocation_serializes_with_final_pull_audit_and_invalidates_stale_decision(postgres_override):
    fixture = postgres_override
    identity = authorization.grant(fixture)
    ready = Event()
    proceed = Event()

    def concurrent_pull():
        with fixture.sessions() as db:
            mapping = db.get(OCIRepository, fixture.mapping_id)
            machine = db.scalar(select(OCIPrincipal))
            prior = authorize(db, mapping, fixture.old)
            assert prior.allowed and prior.override_id == identity
            proxy.remember_decision(db, mapping, fixture.old, prior)
            db.execute(text("SET LOCAL lock_timeout = '250ms'"))
            ready.set()
            assert proceed.wait(10)
            # The revoker holds the grant row lock. Even a previously allowed
            # request must wait; a lock timeout cannot become a successful pull.
            with pytest.raises(OperationalError) as error:
                proxy.audit(db, machine, mapping, fixture.old, 'allowed')
            assert (getattr(error.value.orig, 'sqlstate', None) or getattr(error.value.orig, 'pgcode', None)) == '55P03'
            db.rollback()

    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(concurrent_pull)
        assert ready.wait(10)
        with fixture.sessions() as revoker:
            revoke_override(revoker, fixture.auth, fixture.service_id, identity, 'Mission ended')
            revoker.flush()
            proceed.set()
            pending.result(timeout=10)
            revoker.commit()
    assert not authorization.decision(fixture).allowed
    with fixture.sessions() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == 'local_override.used')) is None


def test_pull_lock_precedes_revocation_and_next_request_is_denied(postgres_override):
    fixture = postgres_override
    identity = authorization.grant(fixture)
    with fixture.sessions() as pull:
        lock_for_use(pull, identity)
        def revoke_during_pull():
            with fixture.sessions() as revoker:
                revoker.execute(text("SET LOCAL lock_timeout = '250ms'"))
                with pytest.raises(OperationalError) as error:
                    revoke_override(revoker, fixture.auth, fixture.service_id, identity, 'Mission ended')
                assert (getattr(error.value.orig, 'sqlstate', None) or getattr(error.value.orig, 'pgcode', None)) == '55P03'
                revoker.rollback()
        with ThreadPoolExecutor(max_workers=1) as executor:
            executor.submit(revoke_during_pull).result(timeout=10)
        pull.commit()
    with fixture.sessions() as revoker:
        revoke_override(revoker, fixture.auth, fixture.service_id, identity, 'Mission ended')
        revoker.commit()
    assert not authorization.decision(fixture).allowed


def test_concurrent_sync_commits_only_one_service_and_activation(postgres_replica):
    fixture = postgres_replica
    incoming = verified(fixture)
    source_id = fixture.source.id
    fixture.db.commit()
    sessions = sessionmaker(fixture.db.get_bind(), expire_on_commit=False)
    start = Barrier(2)
    def import_release():
        with sessions() as db:
            source = db.get(ReplicaSource, source_id)
            start.wait(timeout=10)
            result = reconcile(db, source, incoming, now=fixture.now)
            db.commit()
            return result
    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = [executor.submit(import_release) for _ in range(2)]
        results = [future.result(timeout=20) for future in pending]
    assert sorted(result['status'] for result in results) == ['activated', 'unchanged']
    fixture.db.expire_all()
    states = list(fixture.db.scalars(select(ReplicaServiceState)))
    releases = list(fixture.db.scalars(select(ReplicaRelease)))
    assert len(states) == len(releases) == 1
    assert states[0].active_release_id == releases[0].id and states[0].high_sequence == 1
    assert len(list(fixture.db.scalars(select(ReplicaEvent)))) == 1
    assert len(list(fixture.db.scalars(select(AuditEvent).where(AuditEvent.action == 'replica.activated')))) == 1
