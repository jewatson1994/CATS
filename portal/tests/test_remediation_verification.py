from types import SimpleNamespace
from zipfile import ZipFile
import pytest
from app import remediation_verification as verification
from app.deployment_bundle import file_digest

DIGEST = 'sha256:' + 'a' * 64
SERVICE = {'id': 'test-service', 'version': '1.0.0'}


def candidate(tmp_path):
    folder = tmp_path / 'r1'
    folder.mkdir()
    artifact = folder / 'delivery-1.zip'
    with ZipFile(artifact, 'w') as archive:
        archive.writestr('lineage.json', '{}')
    return SimpleNamespace(job_key='r1', service=SimpleNamespace(service_key='test-service')), {
        'artifact_path': str(artifact), 'materialized_digest': file_digest(artifact), 'service': dict(SERVICE),
        'artifact_identities': [{'kind': 'helm', 'identity_type': 'oci_manifest',
                                 'reference': 'registry/team/api@' + DIGEST, 'digest': DIGEST}]}


def evidence(request, status='VERIFIED'):
    return {'status': status, 'request_id': request['request_id'], 'artifact_digest': request['artifact']['digest'],
            'service': request['service'], 'validation_type': 'oci', 'checks': {'rollout': 'passed'}}


def test_validates_exact_oci_identity_and_retains_evidence(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    calls = []
    def remote(config, request):
        calls.append(request)
        return evidence(request)
    monkeypatch.setattr(verification, 'run_remote', remote)
    observed = verification.verify_delivery(record, result, {'endpoint': 'https://sandbox.example'}, tmp_path)
    assert observed['status'] == 'verified'
    assert calls[0]['schema_version'] == 'cats.validation/v2'
    assert calls[0]['artifact'] == {'reference': 'oci://registry/team/api@' + DIGEST, 'digest': DIGEST}
    assert calls[0]['service'] == SERVICE
    assert 'source_files' not in calls[0]['artifact']
    assert observed['results'][0]['result']['checks'] == {'rollout': 'passed'}


@pytest.mark.parametrize('field,value', [('request_id', 'b' * 32), ('request_id', None), ('artifact_digest', 'sha256:' + 'b' * 64),
    ('service', {'id': 'other', 'version': '1.0.0'}), ('validation_type', 'helm-chart')])
def test_rejects_mismatched_remote_identity(tmp_path, monkeypatch, field, value):
    record, result = candidate(tmp_path)
    monkeypatch.setattr(verification, 'run_remote', lambda config, request: {**evidence(request), field: value})
    assert verification.verify_delivery(record, result, {'endpoint': 'x'}, tmp_path)['status'] == 'not_verified'


def test_all_charts_must_verify(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    result['artifact_identities'].append({**result['artifact_identities'][0], 'reference': 'registry/team/worker@' + DIGEST})
    calls = []
    def remote(config, request):
        calls.append(request)
        return evidence(request, 'VERIFIED' if len(calls) == 1 else 'FAILED')
    monkeypatch.setattr(verification, 'run_remote', remote)
    observed = verification.verify_delivery(record, result, {'endpoint': 'x'}, tmp_path)
    assert observed['status'] == 'not_verified'
    assert observed['remote_status'] == 'FAILED'
    assert len(observed['results']) == 2
    assert calls[0]['request_id'] != calls[1]['request_id']


@pytest.mark.parametrize('invalid', ['mutable', 'service', 'digest', 'unsafe_archive'])
def test_invalid_local_identity_never_submits(tmp_path, monkeypatch, invalid):
    record, result = candidate(tmp_path)
    if invalid == 'mutable':
        result['artifact_identities'][0]['reference'] = 'registry/team/api:latest'
    elif invalid == 'service':
        result['service']['version'] = ''
    elif invalid == 'digest':
        result['materialized_digest'] = DIGEST
    else:
        with ZipFile(result['artifact_path'], 'a') as archive:
            archive.writestr('../escape', 'x')
        result['materialized_digest'] = file_digest(result['artifact_path'])
    monkeypatch.setattr(verification, 'run_remote', lambda *args: pytest.fail('must not submit'))
    assert verification.verify_delivery(record, result, {'endpoint': 'x'}, tmp_path)['status'] == 'not_verified'


def test_missing_validator_fails_closed(tmp_path):
    record, result = candidate(tmp_path)
    observed = verification.verify_delivery(record, result, {}, tmp_path)
    assert observed['status'] == 'verification_unavailable'
    assert observed['remote_status'] == 'COULD_NOT_VALIDATE'


def test_persisted_source_version_must_match(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    record._sa_instance_state = object()
    record.source_version_id, record.service_id = 10, 20
    monkeypatch.setattr(verification, 'object_session', lambda item: SimpleNamespace(
        get=lambda model, identity: SimpleNamespace(service_id=20, version='different-version')))
    monkeypatch.setattr(verification, 'run_remote', lambda *args: pytest.fail('must not submit'))
    assert verification.verify_delivery(record, result, {'endpoint': 'x'}, tmp_path)['status'] == 'not_verified'


def test_delivery_changed_during_validation_is_not_verified(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    def remote(config, request):
        with ZipFile(result['artifact_path'], 'a') as archive:
            archive.writestr('changed', 'x')
        return evidence(request)
    monkeypatch.setattr(verification, 'run_remote', remote)
    assert verification.verify_delivery(record, result, {'endpoint': 'x'}, tmp_path)['status'] == 'not_verified'


def test_archive_outside_owned_job_is_rejected(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    record.job_key = 'another-job'
    monkeypatch.setattr(verification, 'run_remote', lambda *args: pytest.fail('must not submit'))
    assert verification.verify_delivery(record, result, {'endpoint': 'x'}, tmp_path)['status'] == 'not_verified'


def test_remote_exception_is_sanitized(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    def remote(*args):
        raise ValueError('private-secret')
    monkeypatch.setattr(verification, 'run_remote', remote)
    observed = verification.verify_delivery(record, result, {'endpoint': 'x'}, tmp_path)
    assert observed['status'] == 'not_verified'
    assert 'private-secret' not in str(observed)
