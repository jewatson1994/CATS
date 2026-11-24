"""Isolated-process coverage for the polling worker's ORM and storage setup."""
import os
from pathlib import Path
import subprocess
import sys


def _worker_probe():
    from datetime import datetime, timezone
    from sqlalchemy import event
    from app import durable_jobs, models, polling_worker, replica_import, replica_sync
    from app.database import Base, SessionLocal, engine

    def verify_startup(kinds, handler, *, maintenance, **kwargs):
        Base.metadata.create_all(engine)
        maintenance()
        assert kinds == (replica_sync.KIND,) and handler == replica_sync.sync
        assert durable_jobs.claim(kinds, 'probe') is None
        with SessionLocal() as db:
            service = models.Service(service_key='worker-test', name='Worker test')
            db.add(service)
            db.flush()
            scan = models.Execution(execution_key='worker-scan', service_id=service.id,
                                    scanned_at=datetime.now(timezone.utc), complete=True, raw_payload={})
            db.add(scan)
            db.commit()
            assert db.get(models.ExecutionSummary, scan.id).payload_digest == scan.payload_digest
        listeners = sys.modules['app.dependency_queries']
        assert event.contains(models.FindingObservation, 'after_insert', listeners._invalidate_observation_projection)
        evidence = Path(replica_import._retain(b'test evidence'))
        assert evidence.parent == Path(os.environ['CATS_REMEDIATION_JOB_ROOT']) / 'approved-releases' / 'replica'
        assert evidence.read_bytes() == b'test evidence'
        assert 'app.main' not in sys.modules

    durable_jobs.run_worker = verify_startup
    polling_worker.main()


def test_standalone_worker_registers_evidence_writers_without_web_startup(tmp_path):
    portal = Path(__file__).resolve().parents[1]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('CATS_', 'INTELLIGENCE_'))}
    env.update(DATABASE_URL='sqlite://', CATS_MODE='replica', PYTHONPATH=str(portal),
               CATS_REMEDIATION_JOB_ROOT=str(tmp_path / 'jobs'))
    result = subprocess.run([sys.executable, __file__], cwd=portal, env=env,
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr


def test_concurrent_sqlite_source_admissions_share_one_job(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from app import durable_jobs, replica_sync
    from app.database import Base
    from app.models import User
    from app.oci_models import OCIUpstream
    from app.replica_models import ReplicaSource

    engine = create_engine(f"sqlite:///{(tmp_path / 'polling.db').as_posix()}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as db:
        user = User(username='poll', display_name='Poll', password_hash='!')
        upstream = OCIUpstream(name='test', endpoint='https://registry.example')
        db.add_all((user, upstream))
        db.flush()
        source = ReplicaSource(name='source', upstream_id=upstream.id, repository='approved/service',
                               created_by_id=user.id)
        db.add(source)
    start = Barrier(2)
    def manual_request():
        with sessions.begin() as db:
            configured_source = db.get(ReplicaSource, source.id)
            start.wait(timeout=5)
            return replica_sync.enqueue(db, configured_source).id

    with ThreadPoolExecutor(max_workers=2) as pool:
        requests = [pool.submit(manual_request) for _ in range(2)]
        job_ids = [request.result(timeout=10) for request in requests]
    with sessions() as db:
        assert job_ids[0] == job_ids[1] == db.scalars(select(durable_jobs.DurableJob.id)).one()
    engine.dispose()


if __name__ == '__main__':
    _worker_probe()
