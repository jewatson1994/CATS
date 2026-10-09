"""Confirmation binds the complete retained source and its image inventory."""
from copy import deepcopy
from datetime import timedelta
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import main
from app.models import Execution, Finding, FindingObservation, RemediationExecution
from app.remediation import plan_digest
from test_remediation_workflow_routes import workflow


def observation(workflow, *, execution=None, image='registry.example/app:1'):
    db, service, source, _, _, _ = workflow
    now = main.utcnow()
    finding = Finding(service_id=service.id, cve=f'CVE-test-{uuid.uuid4().hex}', severity='High',
                      first_seen=now, last_seen=now, episode_started=now)
    db.add(finding)
    db.flush()
    row = FindingObservation(finding_id=finding.id, execution_id=(execution or source).id,
                             image=image, image_digest='sha256:' + 'a' * 64, evidence={})
    db.add(row)
    db.commit()
    return finding, row


def confirm(workflow, preview):
    db, service, execution, auth, _, _ = workflow
    return main.start_remediation(service.service_key, csrf_token='token', remediation_mode='automated',
        decisions='{}', plan_digest=preview['plan_digest'], source_execution_id=execution.id,
        confirmed='yes', submission_key=str(uuid.uuid4()), db=db, auth=auth)


def test_plan_and_worker_share_supplemental_image_inventory_and_digest(workflow, monkeypatch):
    db, service, execution, auth, _, _ = workflow
    observation(workflow)
    original = deepcopy(execution.raw_payload)
    preview = main.remediation_plan(service.service_key, db=db, auth=auth)
    _, worker_plan = main._retained_remediation_plan(db, service, execution, job_key='R-different-job')
    assert [row['original'] for row in preview['images']] == ['registry.example/app:1']
    assert preview['images'] == worker_plan['images']
    assert preview['plan_digest'] == plan_digest(worker_plan)
    assert execution.raw_payload == original
    confirm(workflow, preview)
    job = db.scalar(select(RemediationExecution))
    reached = []
    def patch(_db, _record, _service, plan):
        reached.extend(row['original'] for row in plan['images'])
        raise RuntimeError('Stop after verifying the approved image inventory')
    monkeypatch.setattr(main, '_run_remediation_image_patches', patch)
    monkeypatch.setattr(main, '_cleanup_completed_remediations', lambda _db: None)
    main._run_remediation_job(job.id)
    assert reached == ['registry.example/app:1']
    db.expire_all()
    assert 'patch_images' in job.failure_reason


@pytest.mark.parametrize('change', ['source_file', 'unmapped_image', 'observed_digest', 'metadata'])
def test_source_changes_after_review_reject_confirmation(workflow, change):
    db, service, execution, auth, submitted, _ = workflow
    _, observed = observation(workflow)
    execution.raw_payload = {**execution.raw_payload, 'source_files': {'README.txt': 'approved content'}}
    db.commit()
    preview = main.remediation_plan(service.service_key, db=db, auth=auth)
    if change == 'source_file':
        execution.raw_payload = {**execution.raw_payload, 'source_files': {'README.txt': 'changed content'}}
    elif change == 'unmapped_image':
        observation(workflow, image='registry.example/unapproved:2')
    elif change == 'observed_digest':
        observed.image_digest = 'sha256:' + 'b' * 64
    else:
        execution.raw_payload = {**execution.raw_payload, 'source_metadata': {'changed': True}}
    db.commit()
    with pytest.raises(HTTPException) as error:
        confirm(workflow, preview)
    assert error.value.status_code == 409
    assert not submitted
    assert db.scalar(select(RemediationExecution)) is None


@pytest.mark.parametrize('change', ['source_file', 'unmapped_image', 'observed_digest'])
def test_source_changes_after_confirmation_stop_before_any_patch(workflow, monkeypatch, change):
    db, service, execution, auth, _, _ = workflow
    _, observed = observation(workflow)
    execution.raw_payload = {**execution.raw_payload, 'source_files': {'README.txt': 'approved content'}}
    db.commit()
    preview = main.remediation_plan(service.service_key, db=db, auth=auth)
    confirm(workflow, preview)
    job = db.scalar(select(RemediationExecution))
    if change == 'source_file':
        execution.raw_payload = {**execution.raw_payload, 'source_files': {'README.txt': 'changed content'}}
    elif change == 'unmapped_image':
        observation(workflow, image='registry.example/unapproved:2')
    else:
        observed.image_digest = 'sha256:' + 'b' * 64
    db.commit()
    patched = []
    monkeypatch.setattr(main, '_run_remediation_image_patches', lambda *_: patched.append(True))
    monkeypatch.setattr(main, '_cleanup_completed_remediations', lambda _db: None)
    main._run_remediation_job(job.id)
    db.expire_all()
    assert not patched
    assert job.status == 'failed'
    assert job.failure_reason == 'Remediation failed during snapshot: ValueError'


def test_vulnerability_scope_rejects_finding_absent_from_chosen_execution(workflow):
    db, service, execution, auth, _, _ = workflow
    older = Execution(service_id=service.id, execution_key='older-source',
                      scanned_at=execution.scanned_at - timedelta(days=1), complete=True, raw_payload={})
    db.add(older)
    db.commit()
    finding, _ = observation(workflow, execution=older)
    with pytest.raises(HTTPException) as error:
        main.remediation_plan(service.service_key, db=db, auth=auth,
                              finding_type='vulnerability', finding_id=finding.id)
    assert error.value.status_code == 422
    _, retained = main._retained_remediation_plan(db, service, older, 'vulnerability', finding.id)
    assert retained['images'][0]['original'] == 'registry.example/app:1'


def test_source_hash_is_stable_for_json_key_order(workflow):
    db, service, execution, _, _, _ = workflow
    execution.raw_payload = {'source_files': {'a.txt': 'a', 'b.txt': 'b'}, 'artifact_type': 'helm'}
    _, first = main._retained_remediation_plan(db, service, execution)
    execution.raw_payload = {'artifact_type': 'helm', 'source_files': {'b.txt': 'b', 'a.txt': 'a'}}
    _, second = main._retained_remediation_plan(db, service, execution)
    assert first['source_digest'] == second['source_digest']
    assert plan_digest(first) == plan_digest(second)
