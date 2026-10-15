"""Durable approval worker boundaries, with publication side effects isolated."""
from contextlib import contextmanager
import hashlib
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import cyber_approvals as approvals, cyber_release_publication as publication, delivery_execution
from app.database import Base
from app.durable_jobs import DurableJob, JobError
from app.models import Execution, Service, utcnow


@pytest.fixture
def worker(tmp_path, monkeypatch):
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(approvals, 'root', lambda: tmp_path)
    monkeypatch.setattr(approvals, 'record_audit', lambda *args, **kwargs: None)
    monkeypatch.setattr(approvals.signing, 'configuration', lambda settings: {'fingerprint': 'trusted-key'})
    @contextmanager
    def lock(*args):
        yield True
    monkeypatch.setattr(delivery_execution, 'delivery_lock', lock)
    with factory() as db:
        service = Service(service_key='worker-service', name='Worker service')
        destination = approvals.ApprovedReleaseDestination(name='Approved', endpoint='https://approved.example', namespace='team')
        db.add_all([service, destination])
        db.flush()
        execution = Execution(service_id=service.id, execution_key='worker-scan', scanned_at=utcnow(), complete=True, raw_payload={})
        db.add(execution)
        db.flush()
        frozen = {**approvals.public_destination(destination), 'ca_digest': hashlib.sha256(b'').hexdigest()}
        snapshot = {'destination': frozen, 'signing_fingerprint': 'trusted-key'}
        row = approvals.CyberApproval(release_key='worker-release', service_id=service.id,
            source_execution_id=execution.id, destination_id=destination.id, variant='current_service',
            status='approved', publish_status='queued', snapshot=snapshot, snapshot_digest=approvals.digest(snapshot),
            destination=frozen, decision_rationale='Reviewed evidence', decided_by_id=1, decided_at=utcnow(), job_id='job-1')
        db.add_all([row, DurableJob(id='job-1', kind='cyber_release_publish', status='running')])
        db.commit()
        identity, destination_id = row.id, destination.id
    folder = tmp_path / 'worker-release' / 'publications'
    folder.mkdir(parents=True)
    bundle = folder / 'bundle.zip'
    bundle.write_bytes(b'verified bundle content')
    receipt = {'status': 'published', 'verification_status': 'verified', 'signature_status': 'verified',
               'bundle_path': str(bundle), 'bundle_digest': publication.file_digest(bundle)}
    context = SimpleNamespace(session_factory=factory, job=SimpleNamespace(id='job-1'),
                              check=lambda: None, stage=lambda *args: None)
    calls = []
    def publish(db, row, destination, checkpoint):
        calls.append(destination)
        checkpoint(receipt)
        return receipt
    monkeypatch.setattr(publication, 'publish', publish)
    yield SimpleNamespace(factory=factory, ctx=context, identity=identity, destination_id=destination_id,
                          receipt=receipt, calls=calls, bundle=bundle)
    engine.dispose()


def state(worker):
    with worker.factory() as db:
        row = db.get(approvals.CyberApproval, worker.identity)
        return row.publish_status, dict(row.publication)


def test_worker_persists_only_complete_verified_release(worker):
    result = approvals.publish_job(worker.ctx, {'approval_id': worker.identity})
    assert result['approval_id'] == worker.identity
    assert state(worker) == ('published', worker.receipt)
    assert worker.calls[0]['endpoint'] == 'https://approved.example'


@pytest.mark.parametrize('drift', ['snapshot', 'endpoint', 'namespace', 'ca', 'disabled', 'scope', 'key'])
def test_worker_rejects_frozen_identity_or_destination_drift(worker, monkeypatch, drift):
    with worker.factory() as db:
        row = db.get(approvals.CyberApproval, worker.identity)
        destination = db.get(approvals.ApprovedReleaseDestination, worker.destination_id)
        if drift == 'snapshot':
            row.snapshot = {**row.snapshot, 'changed': True}
        elif drift == 'key':
            monkeypatch.setattr(approvals.signing, 'configuration', lambda settings: {'fingerprint': 'replacement-key'})
        elif drift == 'ca':
            destination.ca_pem = 'replacement CA'
        elif drift == 'disabled':
            destination.enabled = False
        elif drift == 'scope':
            destination.group_ids = [999]
        else:
            setattr(destination, drift, 'https://other.example' if drift == 'endpoint' else 'other')
        db.commit()
    with pytest.raises(JobError):
        approvals.publish_job(worker.ctx, {'approval_id': worker.identity})
    assert state(worker)[0] == 'failed'
    assert not worker.calls


@pytest.mark.parametrize('invalid', ['status', 'verification_status', 'signature_status', 'bundle_digest', 'outside', 'missing'])
def test_worker_rejects_incomplete_or_untrusted_final_receipt(worker, invalid, tmp_path):
    if invalid == 'outside':
        outside = tmp_path / 'outside.zip'
        outside.write_bytes(worker.bundle.read_bytes())
        worker.receipt['bundle_path'] = str(outside)
    elif invalid == 'missing':
        worker.bundle.unlink()
    else:
        worker.receipt[invalid] = 'invalid'
    with pytest.raises(JobError):
        approvals.publish_job(worker.ctx, {'approval_id': worker.identity})
    assert state(worker)[0] == 'failed'


def test_worker_preserves_partial_artifact_receipts_without_raw_error(worker, monkeypatch):
    partial = {'status': 'publishing', 'artifacts': [{'digest': 'sha256:retained'}]}
    def fail(db, row, destination, checkpoint):
        checkpoint(partial)
        raise RuntimeError('credential=secret must stay private')
    monkeypatch.setattr(publication, 'publish', fail)
    with pytest.raises(JobError):
        approvals.publish_job(worker.ctx, {'approval_id': worker.identity})
    status, receipt = state(worker)
    assert status == receipt['status'] == 'failed'
    assert receipt['artifacts'] == partial['artifacts']
    assert 'secret' not in receipt['error']


def test_worker_rejects_stale_job_without_touching_new_attempt(worker):
    worker.ctx.job.id = 'stale-job'
    with pytest.raises(JobError):
        approvals.publish_job(worker.ctx, {'approval_id': worker.identity})
    assert state(worker) == ('queued', {})
    assert not worker.calls


@pytest.mark.parametrize('job_status', ['failed', 'cancelled', 'completed', 'missing'])
def test_reconcile_terminal_worker_without_completed_release(worker, job_status):
    with worker.factory() as db:
        job = db.get(DurableJob, 'job-1')
        if job_status == 'missing':
            db.delete(job)
        else:
            job.status = job_status
        db.commit()
        approvals.reconcile_jobs(db)
    assert state(worker)[0] == 'failed'
