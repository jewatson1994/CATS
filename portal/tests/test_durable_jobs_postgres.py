"""Opt-in real PostgreSQL lease test; all rows live in a disposable schema."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import os
import uuid
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from test_portal import Base
from app.durable_jobs import DurableJob, JobContext, LeaseLost, claim, now, recover, submit


@pytest.mark.skipif(not os.getenv('CATS_TEST_POSTGRES_URL'), reason='Requires a disposable PostgreSQL connection')
def test_real_postgres_concurrent_claim_and_lease_recovery():
    engine = create_engine(os.environ['CATS_TEST_POSTGRES_URL'])
    schema = 'cats_job_test_' + uuid.uuid4().hex
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    # Raw trigger/function DDL is not rewritten by schema_translate_map.
    # Scope every connection so both SQLAlchemy and that DDL use this schema.
    isolated = create_engine(os.environ['CATS_TEST_POSTGRES_URL'],
                             connect_args={'options': f'-c search_path={schema}'})
    sessions = sessionmaker(bind=isolated, expire_on_commit=False)
    try:
        Base.metadata.create_all(isolated)
        with sessions() as db:
            original = submit(db, kind='test', payload={}, dedupe_key='same-source')
        with ThreadPoolExecutor(max_workers=8) as pool:
            owners = list(pool.map(lambda i: claim(('test',), str(i), sessions), range(8)))
        owners = [row for row in owners if row]
        assert len(owners) == 1
        stale = JobContext(owners[0], sessions)
        stale.checkpoint({'receipt': 'immutable'})
        with sessions() as db:
            row = db.get(DurableJob, original.id)
            row.lease_until = now() - timedelta(seconds=1)
            db.commit()
            recover(db, ('test',))
            row.available_at = now() - timedelta(seconds=1)
            db.commit()
        replacement = claim(('test',), 'replacement', sessions)
        assert replacement and replacement.attempts == 2
        assert replacement.result['receipt'] == 'immutable'
        diagnostic = replacement.result['diagnostic']
        assert diagnostic['code'] == 'worker_lease_expired'
        assert diagnostic['correlation_id'] == original.correlation_id
        assert diagnostic['resource']['job_id'] == original.id
        assert diagnostic['status'] == 'queued' and diagnostic['retryable'] is True
        assert diagnostic['context']['attempts'] == 1
        assert diagnostic['context']['max_attempts'] == original.max_attempts
        assert diagnostic['resolution']
        with pytest.raises(LeaseLost):
            stale.finish({'stale': True})
        JobContext(replacement, sessions).finish({'complete': True})
        with sessions() as db:
            completed = db.get(DurableJob, original.id)
            assert completed.status == 'completed'
            assert completed.result['receipt'] == 'immutable'
            assert completed.result['complete'] is True
            assert completed.result['diagnostic']['error_id'] == diagnostic['error_id']
            assert 'stale' not in completed.result
    finally:
        isolated.dispose()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
