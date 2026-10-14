"""Helpers that explicitly drive the durable worker in legacy workflow tests."""
from sqlalchemy import select
from app import main, durable_jobs, remediation_worker


def drain_plan(db, response):
    if response.get('status') != 'completed':
        job = durable_jobs.claim(('remediation_plan',), 'test-worker', main.SessionLocal)
        assert job is not None
        ctx = durable_jobs.JobContext(job, main.SessionLocal)
        result = remediation_worker.handle(ctx, job.payload)
        ctx.finish(result)
        db.expire_all()
    row = db.get(durable_jobs.DurableJob, response['job_id'])
    return row.result['plan']


def completed_plan(service_key, *, db, auth, **scope):
    return drain_plan(db, main.remediation_plan(service_key, db=db, auth=auth, **scope))


def inline_record_worker(monkeypatch):
    """Focused legacy tests exercise orchestration inline; queue tests run real claims."""
    original = main.remediation_jobs.enqueue_record
    def enqueue(db, record, kind, attempt_id=None, requested_by_id=None):
        job = original(db, record, kind, attempt_id, requested_by_id)
        function = {"remediation_execute": main._run_remediation_job,
                    "remediation_validate": main._run_retained_remediation_validation,
                    "remediation_deliver": main._run_delivery_attempt}[kind]
        function(attempt_id or record.id)
        return job
    monkeypatch.setattr(main.remediation_jobs, "enqueue_record", enqueue)
