"""Candidate validation choices and delivery stay independent and serialized."""
import pytest
from fastapi import HTTPException

from app import main
from app.models import RemediationExecution
from app.remediation_delivery import DeliveryAttempt, candidate_provenance
from test_remediation_workflow_routes import workflow, candidate


def pending_candidate(workflow):
    row = candidate(workflow)
    row.verification_status = 'not_verified'
    row.validation_results = {'checks': {'static': {'status': 'PASS'}}}
    row.workflow_inputs = {'workflow_version': 2, 'service': {'id': 'demo', 'version': 'source-version'}}
    workflow[0].commit()
    return row


def skip(workflow, row, service_key=None):
    db, service, _, auth, _, _ = workflow
    return main.skip_remediation_validation(service_key or service.service_key, row.job_key,
                                           csrf_token='token', db=db, auth=auth)


def validate(workflow, row, service_key=None):
    db, service, _, auth, _, _ = workflow
    return main.validate_remediation_candidate(service_key or service.service_key, row.job_key,
                                              csrf_token='token', db=db, auth=auth)


def test_validation_skip_defaults_to_required(workflow, monkeypatch):
    monkeypatch.delenv('CATS_REMEDIATION_REQUIRE_VALIDATION', raising=False)
    row = pending_candidate(workflow)
    with pytest.raises(HTTPException) as error:
        skip(workflow, row)
    assert error.value.status_code == 409
    assert row.verification_status == 'not_verified'
    assert 'validation_skipped' not in row.workflow_inputs
    assert not workflow[4]


def test_optional_skip_persists_actor_digest_and_preserves_candidate(workflow, monkeypatch):
    monkeypatch.setenv('CATS_REMEDIATION_REQUIRE_VALIDATION', 'false')
    db, _, _, auth, submitted, _ = workflow
    row = pending_candidate(workflow)
    original = row.artifact_digest, row.source_version_id, row.status, row.remediation_status
    response = skip(workflow, row)
    db.expire_all()
    saved = db.get(RemediationExecution, row.id)
    assert response.status_code == 303
    assert saved.verification_status == 'skipped'
    assert saved.workflow_inputs['validation_skipped']['actor_id'] == auth.user.id
    assert saved.workflow_inputs['validation_skipped']['artifact_digest'] == saved.artifact_digest
    assert saved.workflow_inputs['validation_skipped']['at']
    assert saved.validation_results['deployment']['status'] == 'SKIPPED'
    assert saved.validation_results['checks']['static']['status'] == 'PASS'
    assert (saved.artifact_digest, saved.source_version_id, saved.status, saved.remediation_status) == original
    assert main._remediation_delivery_policy(db, saved)['publish_allowed'] is True
    assert candidate_provenance(saved)['validation_skipped'] is True
    assert not submitted


@pytest.mark.parametrize('verification,evidence', [
    ('failed', {'status': 'FAILED'}),
    ('not_verified', {'status': 'PARTIALLY_VERIFIED'}),
    ('unavailable', {'status': 'UNAVAILABLE', 'cleanup_status': 'UNKNOWN'}),
    ('queued', {}), ('running', {}), ('verified', {'status': 'VERIFIED'}),
])
def test_optional_skip_rejects_failed_active_completed_or_unknown_cleanup(workflow, monkeypatch, verification, evidence):
    monkeypatch.setenv('CATS_REMEDIATION_REQUIRE_VALIDATION', 'false')
    row = pending_candidate(workflow)
    row.verification_status = verification
    row.validation_results = {'deployment': evidence}
    workflow[0].commit()
    with pytest.raises(HTTPException) as error:
        skip(workflow, row)
    assert error.value.status_code == 409
    assert row.verification_status == verification
    assert 'validation_skipped' not in row.workflow_inputs
    assert not workflow[4]


@pytest.mark.parametrize('operation', [skip, validate])
def test_validation_routes_cannot_select_other_service_candidate(workflow, monkeypatch, operation):
    monkeypatch.setenv('CATS_REMEDIATION_REQUIRE_VALIDATION', 'false')
    row = pending_candidate(workflow)
    with pytest.raises(HTTPException) as error:
        operation(workflow, row, service_key='another-service')
    assert error.value.status_code == 404
    assert row.verification_status == 'not_verified'
    assert not workflow[4]


@pytest.mark.parametrize('delivery_status', ['queued', 'running', 'staged', 'publishing'])
@pytest.mark.parametrize('operation', [skip, validate])
def test_validation_choices_reject_active_delivery(workflow, monkeypatch, delivery_status, operation):
    monkeypatch.setenv('CATS_REMEDIATION_REQUIRE_VALIDATION', 'false')
    db, _, _, auth, submitted, _ = workflow
    row = pending_candidate(workflow)
    db.add(DeliveryAttempt(remediation_id=row.id, actor_id=auth.user.id,
        content_digest=row.artifact_digest, status=delivery_status, destination={'type': 'oci'}))
    db.commit()
    with pytest.raises(HTTPException) as error:
        operation(workflow, row)
    assert error.value.status_code == 409
    assert row.verification_status == 'not_verified'
    assert not submitted


def test_validation_queues_existing_candidate_and_clears_prior_skip(workflow, monkeypatch):
    monkeypatch.setenv('CATS_REMEDIATION_REQUIRE_VALIDATION', 'false')
    db, _, _, _, submitted, _ = workflow
    row = pending_candidate(workflow)
    skip(workflow, row)
    digest = row.artifact_digest
    response = validate(workflow, row)
    assert response.status_code == 303
    assert row.verification_status == 'queued'
    assert row.artifact_digest == digest
    assert 'validation_skipped' not in row.workflow_inputs
    assert submitted == [(main._run_retained_remediation_validation, row.id)]
    with pytest.raises(HTTPException) as error:
        validate(workflow, row)
    assert error.value.status_code == 409
    assert len(submitted) == 1


def test_validation_worker_claims_queued_candidate_once(workflow, monkeypatch):
    db, _, _, _, _, _ = workflow
    row = pending_candidate(workflow)
    row.verification_status = 'queued'
    db.commit()
    calls = []
    monkeypatch.setattr(main, '_validate_retained_remediation', lambda _db, saved: calls.append((saved.id, saved.verification_status)))
    main._run_retained_remediation_validation(row.id)
    main._run_retained_remediation_validation(row.id)
    db.expire_all()
    assert calls == [(row.id, 'running')]
    assert db.get(RemediationExecution, row.id).verification_status == 'running'


@pytest.mark.parametrize('verification', ['running', 'verified', 'failed', 'unavailable', 'skipped'])
def test_validation_worker_ignores_nonqueued_candidate(workflow, monkeypatch, verification):
    row = pending_candidate(workflow)
    row.verification_status = verification
    workflow[0].commit()
    calls = []
    monkeypatch.setattr(main, '_validate_retained_remediation', lambda *_: calls.append(True))
    main._run_retained_remediation_validation(row.id)
    workflow[0].expire_all()
    assert row.verification_status == verification
    assert not calls
