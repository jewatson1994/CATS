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
    isolated = engine.execution_options(schema_translate_map={None: schema})
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
        assert replacement.result == {'receipt': 'immutable'}
        with pytest.raises(LeaseLost):
            stale.finish({'stale': True})
        JobContext(replacement, sessions).finish({'complete': True})
        with sessions() as db:
            assert db.get(DurableJob, original.id).status == 'completed'
    finally:
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
