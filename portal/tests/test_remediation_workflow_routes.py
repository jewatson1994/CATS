import hashlib
import json
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session, sessionmaker
from app import main
from app.database import Base
from app.models import Service, User, Execution, RemediationExecution
from app.remediation_delivery import DeliveryAttempt


def test_candidate_configuration_scan_uses_only_rendered_manifest(monkeypatch, tmp_path):
    (tmp_path / 'remediated-manifests.yaml').write_text('apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n')
    calls = []
    monkeypatch.setattr(main.shutil, 'which', lambda name: 'trivy' if name == 'trivy' else None)
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps({'SchemaVersion':2,'Results':[]}), stderr='')
    monkeypatch.setattr(main.subprocess, 'run', run)
    plan = {'before':{'resource_identities':[]}, 'after':{}, 'images':[]}
    validation = {'checks':{}, 'required_checks':['trivy_config_rescan']}
    main._validate_materialized_candidate(tmp_path, {}, plan, validation)
    assert calls[0][-1] == str(tmp_path / '.cats-rendered.yaml')
    assert (tmp_path / '.cats-config-scan.json').is_file()
    assert plan['after']['configuration_findings'] == 0


def test_candidate_configuration_scan_without_render_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(main.shutil, 'which', lambda name: 'trivy' if name == 'trivy' else None)
    validation = {'checks':{}, 'required_checks':['trivy_config_rescan']}
    result = main._validate_materialized_candidate(tmp_path, {}, {'before':{},'after':{},'images':[]}, validation)
    assert result['status'] == 'FAIL'
    assert result['checks']['trivy_config_rescan']['status'] == 'FAIL'


@pytest.fixture
def workflow(monkeypatch, tmp_path):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    user = User(username='manager', display_name='Manager', password_hash='unused')
    service = Service(service_key='demo', name='Demo')
    db.add_all([user, service]); db.flush()
    execution = Execution(service_id=service.id, execution_key='source', scanned_at=main.utcnow(), complete=True, raw_payload={'artifact_type':'helm'})
    db.add(execution); db.commit()
    auth = SimpleNamespace(user=user)
    submitted = []
    monkeypatch.setattr(main, 'check_csrf', lambda *_: None)
    monkeypatch.setattr(main, 'remediation_enabled', lambda _: True)
    monkeypatch.setattr(main, 'cleanup_remediation_artifacts', lambda *_: {'over_quota':False})
    monkeypatch.setattr(main, 'record_audit', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(main, '_remediation_audit', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(main, 'REMEDIATION_JOB_ROOT', tmp_path)
    monkeypatch.setattr(main, 'SessionLocal', factory)
    monkeypatch.setattr(main, 'get_global_configuration', lambda _: {})
    monkeypatch.setattr(main, 'REMEDIATION_WORKERS', SimpleNamespace(submit=lambda *args: submitted.append(args)))
    destination = {'id':'1','name':'Harbor','endpoint':'https://registry.example','namespace':'apps','scope':'service'}
    monkeypatch.setattr(main.service_oci, 'resolve_destination', lambda _db, _service, selected, _global: {**destination, 'id':selected})
    yield db, service, execution, auth, submitted, tmp_path
    db.close(); engine.dispose()


def start(workflow, **override):
    db, service, execution, auth, _, _ = workflow
    preview = main.remediation_plan(service.service_key, db=db, auth=auth)
    args = dict(service_key=service.service_key, csrf_token='token', remediation_mode='automated',
        decisions='{}', plan_digest=preview['plan_digest'], source_execution_id=execution.id,
        output_mode='bundle', destination_id='', verify_runtime='no', db=db, auth=auth)
    args.update(override)
    return main.start_remediation(**args)


def candidate(workflow):
    db, service, execution, auth, _, root = workflow
    path = root / 'R1' / 'candidate.zip'; path.parent.mkdir(); path.write_bytes(b'retained content')
    row = RemediationExecution(job_key='R1', service_id=service.id, requested_by_id=auth.user.id,
        source_execution_id=execution.id, revision_number=1, status='complete', remediation_status='partial',
        artifact_path=str(path), artifact_digest='sha256:'+hashlib.sha256(path.read_bytes()).hexdigest())
    db.add(row); db.commit()
    return row


def test_plan_start_binds_source_and_persists_workflow(workflow):
    db, _, execution, _, submitted, _ = workflow
    response = start(workflow, output_mode='oci', destination_id='1', verify_runtime='yes')
    assert response.status_code == 303
    row = db.scalar(select(RemediationExecution))
    assert row.source_execution_id == execution.id and row.revision_number == 1
    assert row.workflow_inputs['requested_delivery'] == 'oci'
    assert row.workflow_inputs['verify_runtime'] is True
    assert submitted == [(main._run_remediation_job, row.id)]


@pytest.mark.parametrize('override', [{'plan_digest':'changed'}, {'source_execution_id':999}])
def test_stale_plan_never_queues(workflow, override):
    with pytest.raises(HTTPException) as error: start(workflow, **override)
    assert error.value.status_code == 409
    assert not workflow[4]


def test_invalid_decisions_never_queue(workflow):
    with pytest.raises(HTTPException) as error: start(workflow, decisions=json.dumps({'foreign':{'action':'proposed'}}))
    assert error.value.status_code == 422
    assert not workflow[4]


def test_redelivery_retains_r1_and_history_without_remediation(workflow, monkeypatch):
    db, service, _, auth, submitted, _ = workflow
    row = candidate(workflow)
    monkeypatch.setattr(main, '_run_remediation_job', lambda *_: pytest.fail('Delivery reran remediation'))
    first = main._queue_delivery(db,row,auth.user.id,'oci','1')
    first.status='failed'; first.result={'error':'Authentication'}; db.commit()
    response = main.redeliver_remediation(service.service_key,row.job_key,'token','oci','2','no',db,auth)
    assert response.status_code == 303
    assert db.scalar(select(func.count(RemediationExecution.id))) == 1
    attempts = db.scalars(select(DeliveryAttempt).order_by(DeliveryAttempt.id)).all()
    assert len(attempts) == 2 and attempts[0].result == {'error':'Authentication'}
    assert [attempt.destination['id'] for attempt in attempts] == ['1','2']
    assert all(attempt.remediation_id == row.id and attempt.content_digest == row.artifact_digest for attempt in attempts)
    assert all(task[0] == main._run_delivery_attempt for task in submitted)
    assert row.revision_number == 1 and row.remediation_status == 'partial'


def test_download_instead_reuses_retained_r1_without_worker(workflow):
    db, service, _, auth, submitted, _ = workflow
    row = candidate(workflow)
    response = main.redeliver_remediation(service.service_key,row.job_key,'token','bundle','','no',db,auth)
    assert response.headers['location'].endswith('/R1/candidate.zip')
    assert db.scalar(select(DeliveryAttempt)).status == 'download_ready'
    assert not submitted and db.scalar(select(func.count(RemediationExecution.id))) == 1


def test_delivery_requires_retained_integrity_and_rejects_concurrent_attempts(workflow):
    db, _, _, auth, _, _ = workflow
    row = candidate(workflow)
    main._queue_delivery(db,row,auth.user.id,'oci','1')
    with pytest.raises(HTTPException) as error:
        main._queue_delivery(db,row,auth.user.id,'oci','2')
    assert error.value.status_code == 409
    from pathlib import Path
    Path(row.artifact_path).write_bytes(b'tampered candidate')
    with pytest.raises(HTTPException) as error:
        main._queue_delivery(db,row,auth.user.id,'bundle')
    assert error.value.status_code == 409
    assert db.scalar(select(func.count(DeliveryAttempt.id))) == 1


def test_delivery_route_cannot_select_candidate_from_another_service(workflow):
    db, _, _, auth, _, _ = workflow
    row = candidate(workflow)
    with pytest.raises(HTTPException) as error:
        main.redeliver_remediation('other-service',row.job_key,'token','oci','1','no',db,auth)
    assert error.value.status_code == 404
    assert db.scalar(select(func.count(DeliveryAttempt.id))) == 0


def test_worker_retains_staged_delivery_but_rejects_publication_when_verification_fails(workflow, monkeypatch):
    from app.models import ServiceVersion
    db, service, _, auth, _, _ = workflow
    row = candidate(workflow)
    version = ServiceVersion(service_id=service.id, version='retained-oci-1.0')
    db.add(version); db.flush(); row.source_version_id = version.id; db.commit()
    attempt = main._queue_delivery(db,row,auth.user.id,'oci','1',True)
    result = {'materialized_digest':'sha256:'+'b'*64, 'artifact_identities':[{'kind':'helm','digest':'sha256:'+'c'*64}]}
    monkeypatch.setattr(main,'deliver',lambda *_: (result,'materialized.zip'))
    from app import remediation_verification
    def unavailable(record, retained, configuration, root):
        assert retained['service'] == {'id': service.service_key, 'version': version.version}
        assert attempt.status == 'staged'
        raise RuntimeError('sandbox offline')
    monkeypatch.setattr(remediation_verification,'verify_delivery',unavailable)
    main._run_delivery_attempt(attempt.id)
    db.expire_all()
    assert attempt.status == 'validation_failed' and attempt.artifact_path == 'materialized.zip'
    assert row.delivery_status == 'validation_failed' and row.remediation_status == 'partial'
    assert row.verification_status == 'verification_unavailable'
    assert attempt.result['materialized_digest'] == result['materialized_digest']
    assert row.validation_results['artifact_identities'][0]['verification']['status'] == 'verification_unavailable'
    assert attempt.completed_at is not None


def test_delivery_failure_is_sanitized_and_content_survives(workflow, monkeypatch):
    db, _, _, auth, _, _ = workflow
    row = candidate(workflow)
    attempt = main._queue_delivery(db,row,auth.user.id,'oci','1')
    monkeypatch.setattr(main,'deliver',lambda *_: (_ for _ in ()).throw(RuntimeError('password=SECRET')))
    main._run_delivery_attempt(attempt.id)
    db.expire_all()
    assert attempt.status == 'failed' and 'SECRET' not in json.dumps(attempt.result)
    assert row.remediation_status == 'partial' and row.revision_number == 1
    assert main.retained_candidate(row,workflow[5]).is_file()


@pytest.mark.parametrize('mode', ['standard-bundle', 'offline-bundle'])
def test_final_bundle_worker_validates_exact_bytes_and_releases_only_verified(workflow, monkeypatch, mode):
    from app import remediation_bundles, validator_client
    from app.models import ServiceVersion
    from app.deployment_bundle import file_digest
    db, service, _, auth, submitted, root = workflow
    row = candidate(workflow)
    version = ServiceVersion(service_id=service.id, version='retained-1.0')
    db.add(version); db.flush()
    row.source_version_id = version.id
    db.commit()
    attempt = main._queue_delivery(db, row, auth.user.id, mode)
    assert attempt.status == 'queued' and submitted[-1] == (main._run_delivery_attempt, attempt.id)
    final = root / row.job_key / f'delivery-{attempt.id}.zip'
    final.write_bytes(b'exact final delivery')
    identity = {'id': service.service_key, 'version': version.version}
    result = {'materialized_digest': file_digest(final), 'validation_type': mode, 'service': identity}
    monkeypatch.setattr(remediation_bundles, 'assemble', lambda *args, configuration: (result, str(final)))
    requests = []
    def validate(configuration, request, *, artifact_path):
        requests.append((request, artifact_path))
        return {'status': 'VERIFIED', 'artifact_digest': file_digest(artifact_path), 'service': identity,
                'validation_type': mode, 'request_id': request['request_id'], 'cleanup_status': 'COMPLETE',
                'helm_result': {'install': 'PASS', 'release_status': 'DEPLOYED', 'execution_mode': 'HELM', 'helm_release_verified': True},
                'offlineVerified': mode == 'offline-bundle',
                'network_evidence': {'external_access_observed': False}}
    monkeypatch.setattr(validator_client, 'validate', validate)
    main._run_delivery_attempt(attempt.id)
    db.expire_all()
    assert attempt.status == 'download_ready'
    assert requests[0][1] == str(final)
    assert requests[0][0]['artifact']['digest'] == result['materialized_digest']
    assert attempt.result['verification']['network_evidence'] == {'external_access_observed': False}
    assert row.validation_results['final_delivery_validations'][0]['attempt_id'] == attempt.id
    response = main.remediation_delivery_bundle(service.service_key, row.job_key, attempt.id, db, auth)
    assert str(response.path) == str(final)
    final.write_bytes(b'mutated final')
    with pytest.raises(HTTPException) as failure:
        main.remediation_delivery_bundle(service.service_key, row.job_key, attempt.id, db, auth)
    assert failure.value.status_code == 409


def test_final_bundle_missing_validator_fails_closed_preserving_evidence(workflow, monkeypatch):
    from app import remediation_bundles, validator_client
    from app.models import ServiceVersion
    from app.deployment_bundle import file_digest
    db, service, _, auth, _, root = workflow
    row = candidate(workflow)
    version = ServiceVersion(service_id=service.id, version='1.0')
    db.add(version); db.flush(); row.source_version_id = version.id; db.commit()
    attempt = main._queue_delivery(db, row, auth.user.id, 'standard-bundle')
    final = root / row.job_key / f'delivery-{attempt.id}.zip'
    final.write_bytes(b'final')
    monkeypatch.setattr(remediation_bundles, 'assemble', lambda *args, configuration: ({'materialized_digest': file_digest(final)}, str(final)))
    monkeypatch.setattr(validator_client, 'validate', lambda *args, **kwargs: (_ for _ in ()).throw(ValueError('missing config')))
    main._run_delivery_attempt(attempt.id)
    db.expire_all()
    assert attempt.status == 'validation_failed'
    assert attempt.result['verification']['status'] == 'COULD_NOT_VALIDATE'
    assert attempt.result['download_url'] is None
    with pytest.raises(HTTPException) as failure:
        main.remediation_delivery_bundle(service.service_key, row.job_key, attempt.id, db, auth)
    assert failure.value.status_code == 404


def test_bundle_preparation_failure_preserves_safe_diagnostics(workflow, monkeypatch):
    from app import remediation_bundles
    from app.models import ServiceVersion
    db, service, _, auth, _, root = workflow
    row = candidate(workflow)
    version = ServiceVersion(service_id=service.id, version='1.0')
    db.add(version); db.flush(); row.source_version_id = version.id; db.commit()
    attempt = main._queue_delivery(db, row, auth.user.id, 'offline-bundle')
    def fail(*args, **kwargs):
        raise ValueError('Missing dependency common from https://user:SECRET@registry.example/charts?token=TOKEN')
    monkeypatch.setattr(remediation_bundles, 'assemble', fail)
    main._run_delivery_attempt(attempt.id)
    db.expire_all()
    assert attempt.status == 'failed'
    diagnostic = root / row.job_key / f'delivery-{attempt.id}-diagnostics.json'
    evidence = json.dumps(attempt.result) + diagnostic.read_text()
    assert 'Missing dependency common' in evidence
    assert 'SECRET' not in evidence and 'TOKEN' not in evidence
    assert main.retained_candidate(row, root).is_file()


@pytest.mark.parametrize('policies', [{}, {'ubuntu': {'mode': 'default'}}])
@pytest.mark.parametrize('source_registry', [None, {'endpoint': 'https://registry.example'}])
@pytest.mark.parametrize('worker_failure', [False, True])
def test_remediation_uses_image_defined_default_repositories(workflow, monkeypatch, policies, source_registry, worker_failure):
    db, service, _, _, _, root = workflow
    row = candidate(workflow)
    row.output_mode = 'bundle'
    monkeypatch.setattr(main, 'PATCH_JOB_ROOT', root / 'patches')
    monkeypatch.setattr(main, 'configuration_for_service', lambda *_: {'repository_policies': json.dumps(policies)})
    monkeypatch.setattr(main, '_configured_registry_for_image', lambda *_: source_registry)
    monkeypatch.setattr(main, '_portal_signing_material', lambda *_: ({}, {}))
    monkeypatch.setattr(main, '_audit_signing_request', lambda *_: None)
    calls = []
    def run(job_key, credentials):
        config = json.loads((root / 'patches' / job_key / 'job-config.json').read_text())
        calls.append(config)
        assert credentials['CATS_PATCH_SOURCE_USERNAME'] == ''
        assert credentials['CATS_PATCH_SOURCE_PASSWORD'] == ''
    monkeypatch.setattr(main, '_run_patch_job', run)
    outcome = {'status': 'failed', 'error': 'Source registry unavailable'} if worker_failure else {'result': {'reason': 'Package repository unavailable', 'patch_status': 'FAILED'}}
    monkeypatch.setattr(main, '_load_patch_job', lambda *_: outcome)
    plan = {'images': [{'original': 'ubuntu:latest'}]}
    main._run_remediation_image_patches(db, row, service, plan)
    assert len(calls) == 1
    assert calls[0]['require_repository_policy'] is False
    assert calls[0]['repository_policies'] == policies
    assert calls[0]['source_image'] == 'ubuntu:latest'
    assert plan['images'][0]['patch_status'] == 'FAILED'
    assert plan['images'][0]['reason'] == ('Source registry unavailable' if worker_failure else 'Package repository unavailable')
