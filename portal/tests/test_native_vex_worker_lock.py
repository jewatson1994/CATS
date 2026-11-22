"""Durable VEX work waits for a catalog writer while genuine failures retain their cooldown."""
from datetime import timedelta
from unittest.mock import Mock

from psycopg import errors
import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app import database, durable_jobs as jobs, intelligence_generation as generation, native_vex_worker as worker
from app.native_vex_models import VexDispositionEvaluation as Evaluation, VexDispositionService as State
from test_native_vex import db, setup


@pytest.fixture
def work(db, monkeypatch):
    service, _, _, _ = setup(db)
    service_id = service.id
    factory = sessionmaker(bind=db.get_bind())
    monkeypatch.setattr(worker, 'SessionLocal', factory)
    # Freeze the job clock so the test can advance eligibility without sleeping.
    clock = [jobs.now() + timedelta(seconds=1)]
    monkeypatch.setattr(jobs, 'now', lambda: clock[0])
    monkeypatch.setattr(worker, 'utcnow', lambda: clock[0])
    db.rollback()
    return service_id, factory, clock


@pytest.mark.parametrize('driver_error', [errors.QueryCanceled, errors.LockNotAvailable, errors.AdminShutdown])
def test_fence_driver_failure_through_durable_worker(db, work, monkeypatch, driver_error):
    service_id, factory, clock = work
    job = jobs.submit(db, kind='native_vex', service_id=service_id,
                      payload={'service_id': service_id}, max_attempts=1)
    job_id = job.id
    db.close()
    engine = Mock()
    engine.dialect.name = 'postgresql'
    connection = engine.connect.return_value
    with monkeypatch.context() as m:
        m.setattr(database, 'INTELLIGENCE_SEPARATE', True)
        m.setattr(generation, '_engine', lambda session: engine)
        m.setattr(generation, 'current_generation', lambda session: 'committed-token')

        def catalog_read(conn, lock=False):
            if lock:
                try:
                    raise driver_error('simulated PostgreSQL diagnostic')
                except driver_error as exc:
                    raise OperationalError('SELECT token FOR SHARE', None, exc) from exc
            return 'committed-token'

        m.setattr(generation, '_read', catalog_read)
        claimed = jobs.claim(('native_vex',), 'risk-worker', factory)
        jobs.execute(claimed, worker.handler, factory)
        connection.close.assert_called_once()

    with factory() as session:
        row = session.get(jobs.DurableJob, job_id)
        assert row.lease_token is None and row.lease_until is None
        assert session.get(State, service_id).evaluation_id is None
        assert session.scalar(select(Evaluation.id)) is None
        if driver_error is errors.AdminShutdown:
            assert row.status == 'failed' and row.attempts == 1
            assert row.completed_at is not None and row.error
            assert row.result['diagnostic']['technical']['exceptions'][0]['type'] == 'GenerationUnavailable'
        else:
            assert row.status == 'queued' and row.attempts == 0
            assert row.available_at.replace(tzinfo=clock[0].tzinfo) > clock[0]
            assert row.stage == 'Waiting for the intelligence catalog lock'
            assert row.completed_at is None and row.error is None
            assert 'diagnostic' not in row.result
    assert worker.maintenance(factory) == 0
    if driver_error is errors.AdminShutdown:
        clock[0] += timedelta(hours=2)
        assert worker.maintenance(factory) == 1
        return

    assert jobs.claim(('native_vex',), 'early-worker', factory) is None
    clock[0] += timedelta(minutes=2)
    retry = jobs.claim(('native_vex',), 'risk-worker', factory)
    assert retry.id == job_id and retry.lease_token != claimed.lease_token
    jobs.execute(retry, worker.handler, factory)
    with factory() as session:
        row = session.get(jobs.DurableJob, job_id)
        assert row.status == 'completed' and row.attempts == 1
        assert row.lease_token is None and row.lease_until is None
        assert session.get(State, service_id).evaluation_id == row.result['evaluation_id']
        assert session.scalar(select(Evaluation.service_id)) == service_id


@pytest.mark.parametrize(('driver_error', 'cancelled', 'admissions'), [
    (errors.QueryCanceled, False, 1),
    (errors.LockNotAvailable, False, 1),
    (errors.AdminShutdown, False, 0),
    (errors.QueryCanceled, True, 0),
])
def test_admission_after_legacy_fence_diagnostic(db, work, driver_error, cancelled, admissions):
    service_id, factory, _ = work
    previous = jobs.submit(db, kind='native_vex', service_id=service_id,
                           payload={'service_id': service_id}, max_attempts=1)
    previous_id = previous.id
    db.close()

    def legacy_handler(ctx, payload):
        try:
            try:
                raise driver_error('legacy driver message')
            except driver_error as exc:
                raise OperationalError('SELECT token FOR SHARE', None, exc) from exc
        except OperationalError as exc:
            raise generation.GenerationUnavailable('Intelligence generation fence is unavailable') from exc

    jobs.execute(jobs.claim(('native_vex',), 'legacy-worker', factory), legacy_handler, factory)
    with factory() as session:
        row = session.get(jobs.DurableJob, previous_id)
        original = row.result['diagnostic']
        exceptions = original['technical']['exceptions']
        assert [entry['type'] for entry in exceptions] == ['GenerationUnavailable', 'OperationalError', driver_error.__name__]
        if cancelled:
            row.status = 'cancelled'
            session.commit()
    assert worker.maintenance(factory) == admissions
    assert worker.maintenance(factory) == 0
    with factory() as session:
        assert session.get(jobs.DurableJob, previous_id).result['diagnostic'] == original
        replacements = list(session.scalars(select(jobs.DurableJob).where(jobs.DurableJob.id != previous_id)))
        assert len(replacements) == admissions
        assert all(row.service_id == service_id and row.status == 'queued' for row in replacements)
