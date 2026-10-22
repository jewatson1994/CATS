"""PostgreSQL job admission race; uses only the disposable lifecycle database."""
import json
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from sqlalchemy import create_engine, event, select, func
from sqlalchemy.orm import sessionmaker
from app.durable_jobs import DurableJob, submit
from app.models import Service


def main(root):
    engine = create_engine(os.environ['DATABASE_URL'])
    sessions = sessionmaker(engine, expire_on_commit=False)
    waiting = Event()
    key = 'acceptance-concurrent-admission'
    def contender():
        with sessions() as db:
            connection = db.connection()
            def before_execute(conn, cursor, statement, parameters, context, many):
                if 'pg_advisory_xact_lock' in statement:
                    waiting.set()
            event.listen(connection, 'before_cursor_execute', before_execute)
            service = Service(service_key='concurrent-admission', name='Admission transaction preserved')
            db.add(service)
            row = submit(db, kind='acceptance', payload={}, dedupe_key=key, commit=False)
            db.commit()
            return row.id, service.id
    with sessions() as first, ThreadPoolExecutor(max_workers=1) as pool:
        row = submit(first, kind='acceptance', payload={}, dedupe_key=key, commit=False)
        future = pool.submit(contender)
        try:
            assert waiting.wait(15), 'Contender did not reach admission lock'
        finally:
            first.commit()
        other_id, service_id = future.result(timeout=20)
        assert other_id == row.id
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(DurableJob).where(DurableJob.dedupe_key == key)) == 1
        assert db.get(Service, service_id) is not None
        job = db.get(DurableJob, other_id)
        job.status = 'complete'
        db.commit()
    (root / 'concurrency-results.json').write_text(json.dumps({'same_job': True, 'single_row': True, 'surrounding_transaction_preserved': True}))
    engine.dispose()
