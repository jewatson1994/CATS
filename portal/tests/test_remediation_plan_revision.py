"""Persisted previews and approvals must not outlive their planner semantics."""
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import main, durable_jobs, remediation_jobs, remediation_worker
from app.models import RemediationExecution
from remediation_job_helpers import completed_plan
from test_remediation_workflow_routes import workflow, start


def test_upgrade_invalidates_cached_plan_but_current_preview_reuses_it(workflow, monkeypatch):
    db, service, source, auth, _, _ = workflow
    old = completed_plan(service.service_key, db=db, auth=auth)
    cached = main.remediation_plan(service.service_key, db=db, auth=auth)
    assert cached['status'] == 'completed'
    monkeypatch.setattr(remediation_jobs, 'PLAN_REVISION', remediation_jobs.PLAN_REVISION + 1)
    fresh = main.remediation_plan(service.service_key, db=db, auth=auth)
    assert fresh['status'] == 'queued'
    assert fresh['job_id'] != cached['job_id']
    assert main.remediation_plan(service.service_key, db=db, auth=auth)['job_id'] == fresh['job_id']
    with pytest.raises(HTTPException, match='review and confirm a new plan') as error:
        remediation_jobs.confirmed_plan(db, service, source.id, old['plan_digest'], None, None)
    assert error.value.status_code == 409
    new = completed_plan(service.service_key, db=db, auth=auth)
    assert new['planner_revision'] == remediation_jobs.PLAN_REVISION
    assert remediation_jobs.confirmed_plan(db, service, source.id, new['plan_digest'], None, None)[1] == new


@pytest.mark.parametrize('missing_revision', [False, True])
def test_old_queued_preview_fails_with_review_guidance(workflow, monkeypatch, missing_revision):
    db, service, _, auth, _, _ = workflow
    main.remediation_plan(service.service_key, db=db, auth=auth)
    job = durable_jobs.claim(('remediation_plan',), 'test', main.SessionLocal)
    payload = dict(job.payload)
    if missing_revision:
        payload.pop('planner_revision')
    else:
        monkeypatch.setattr(remediation_jobs, 'PLAN_REVISION', remediation_jobs.PLAN_REVISION + 1)
    monkeypatch.setattr(main, '_retained_remediation_plan', lambda *_: pytest.fail('Stale planner ran'))
    with pytest.raises(durable_jobs.JobError, match='planner has changed'):
        remediation_worker.handle(durable_jobs.JobContext(job, main.SessionLocal), payload)


@pytest.mark.parametrize('missing_revision', [False, True])
def test_old_confirmation_cannot_execute_or_retry(workflow, monkeypatch, missing_revision):
    db, service, _, auth, submitted, _ = workflow
    start(workflow)
    record = db.scalar(select(RemediationExecution))
    if missing_revision:
        inputs = dict(record.workflow_inputs)
        inputs.pop('planner_revision')
        record.workflow_inputs = inputs
        db.commit()
    else:
        monkeypatch.setattr(remediation_jobs, 'PLAN_REVISION', remediation_jobs.PLAN_REVISION + 1)
    monkeypatch.setattr(main, '_retained_remediation_plan', lambda *_: pytest.fail('Stale confirmation rebuilt'))
    monkeypatch.setattr(main, '_run_remediation_image_patches', lambda *_: pytest.fail('Stale confirmation patched'))
    monkeypatch.setattr(main, '_cleanup_completed_remediations', lambda *_: None)
    main._run_remediation_job(record.id)
    db.refresh(record)
    assert record.status == 'failed'
    assert record.failure_reason == f'Remediation failed during snapshot: {remediation_jobs.PLAN_REVIEW_REQUIRED}'
    with pytest.raises(HTTPException, match='review and confirm a new plan') as error:
        main.retry_remediation(service.service_key, record.job_key, csrf_token='token', db=db, auth=auth)
    assert error.value.status_code == 409
    assert len(submitted) == 1
