import base64
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from app import validator_api as api, validator_client as client


def declaration(kind='helm-chart', data=b'final artifact'):
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    return {'schema_version': 'cats.validation/v2', 'request_id': '1' * 32,
            'validation_type': kind, 'service': {'id': 'svc', 'version': '2'},
            'artifact': {'reference': 'oci://example.test/chart@' + digest if kind == 'oci' else 'final.tgz', 'digest': digest},
            'deployment': {'type': 'helm'}}


@pytest.fixture
def worker(monkeypatch, tmp_path):
    monkeypatch.setattr(api, 'STATE_DIR', tmp_path)
    monkeypatch.setenv('CATS_VALIDATOR_CLIENT_FINGERPRINTS', 'a' * 64)
    calls = []
    monkeypatch.setattr(api, 'EXECUTOR', SimpleNamespace(submit=lambda *args: calls.append(args)))
    api.JOBS.clear()
    async def wrapper(scope, receive, send):
        scope['validator_peer_sha256'] = 'a' * 64
        await api.app(scope, receive, send)
    with TestClient(wrapper, base_url='https://testserver') as connection:
        yield connection, calls, tmp_path
    api.JOBS.clear()


def test_binary_submission_persists_identity_and_job_binding(worker):
    connection, calls, root = worker
    package = declaration()
    response = connection.post('/api/v2/validations', content=b'final artifact', headers={
        'Content-Type': 'application/octet-stream', 'X-CATS-Declaration': base64.urlsafe_b64encode(json.dumps(package).encode()).decode()})
    assert response.status_code == 202
    submitted = response.json()
    job = submitted['validation_id']
    for key, value in api._request_identity(package).items():
        assert submitted[key] == value
        assert json.loads((root / (job + '.json')).read_text())[key] == value
        assert connection.get('/api/v2/validations/' + job).json()[key] == value
    assert calls[0][3].read_bytes() == b'final artifact'
    cancelled = connection.post('/api/v2/validations/' + job + '/cancel').json()
    assert cancelled['request_id'] == package['request_id']
    assert cancelled['cancel_requested'] is True
    api._execute(job, package, calls[0][3])
    assert api.JOBS[job]['result']['validation_id'] == job
    assert api.JOBS[job]['result']['request_id'] == package['request_id']
    assert not calls[0][3].exists()


def test_bad_digest_removes_upload_and_does_not_dispatch(worker):
    connection, calls, root = worker
    package = declaration(data=b'other')
    response = connection.post('/api/v2/validations', content=b'final artifact', headers={
        'Content-Type': 'application/octet-stream', 'X-CATS-Declaration': base64.urlsafe_b64encode(json.dumps(package).encode()).decode()})
    assert response.status_code == 422
    assert not calls and not list(root.glob('upload-*'))


def test_binary_required_and_oci_json_allowed(worker):
    connection, calls, root = worker
    assert connection.post('/api/v2/validations', json=declaration()).status_code == 422
    response = connection.post('/api/v2/validations', json=declaration('oci'))
    assert response.status_code == 202
    assert calls[0][3] is None


@pytest.mark.parametrize('stage,field', [('submission', 'request_id'), ('poll', 'service'), ('result', 'request_id'), ('result', 'validation_id'), ('result', 'artifact_reference')])
def test_client_rejects_swapped_evidence(monkeypatch, tmp_path, stage, field):
    package = declaration('oci')
    job = '2' * 32
    identity = api._request_identity(package)
    submitted = {**identity, 'validation_id': job, 'status': 'QUEUED'}
    result = {**identity, 'validation_id': job, 'status': 'VERIFIED', 'cleanup_status': 'COMPLETE'}
    state = {**identity, 'validation_id': job, 'status': 'VERIFIED', 'phase': 'COMPLETE', 'result': result}
    target = submitted if stage == 'submission' else state if stage == 'poll' else result
    target[field] = 'different'
    responses = iter([submitted, state])
    monkeypatch.setattr(client, '_client_context', lambda *args: object())
    monkeypatch.setattr(client, '_request', lambda *args, **kwargs: next(responses))
    with pytest.raises(ValueError):
        client.validate({'endpoint': 'https://example.test'}, package)


def test_restart_retains_request_binding(worker, monkeypatch):
    connection, calls, root = worker
    package = declaration('oci')
    job = connection.post('/api/v2/validations', json=package).json()['validation_id']
    api.JOBS.clear()
    monkeypatch.setattr(api, 'cleanup_stale_clusters', lambda *args, **kwargs: {'failed': []})
    api.recover()
    result = api.JOBS[job]['result']
    assert result['request_id'] == package['request_id']
    assert result['artifact'] == package['artifact']
    assert result['validation_id'] == job
    assert result['reason_category'] == 'WORKER_RESTARTED'


def test_safe_result_preserves_bounded_evidence_without_logs():
    safe = api._safe_result({'status': 'VERIFIED', 'reason_category': 'SUCCESS',
        'offlineVerified': True, 'helm': {'status': 'PASS', 'dependencies_vendored': True, 'stderr': 'secret'},
        'network': {'isolated': True, 'external_image_pulls': 0, 'secret': 'credential'},
        'images': {'loaded': ['example/image:1'], 'logs': ['secret']}, 'reason': 'secret'})
    assert safe['offlineVerified'] is True
    assert safe['helm'] == {'status': 'PASS', 'dependencies_vendored': True}
    assert safe['network'] == {'isolated': True, 'external_image_pulls': 0}
    assert safe['images'] == {'loaded': ['example/image:1']}
    assert 'secret' not in json.dumps(safe)


@pytest.mark.parametrize('mismatch', [False, True])
def test_dispatch_checks_engine_identity(worker, monkeypatch, mismatch):
    import sys
    connection, calls, root = worker
    package = declaration('oci')
    job = connection.post('/api/v2/validations', json=package).json()['validation_id']
    evidence = {**api._request_identity(package), 'status': 'VERIFIED', 'reason_category': 'SUCCESS',
                'cleanup_status': 'COMPLETE', 'offlineVerified': False}
    if mismatch:
        evidence['request_id'] = '9' * 32
    class Engine:
        def __init__(self, *args, **kwargs):
            pass
        def validate(self, request, **kwargs):
            assert request == package and kwargs['job_id'] == job
            return evidence
    monkeypatch.setitem(sys.modules, 'app.schrodinger_validation', SimpleNamespace(SchrodingerValidator=Engine))
    api._execute(job, package)
    result = api.JOBS[job]['result']
    assert result['status'] == ('ERROR' if mismatch else 'VERIFIED')
    assert result['request_id'] == package['request_id']
    assert result['validation_id'] == job


def test_restart_cleans_interrupted_artifact_upload(worker, monkeypatch):
    connection, calls, root = worker
    package = declaration()
    response = connection.post('/api/v2/validations', content=b'final artifact', headers={
        'Content-Type': 'application/octet-stream', 'X-CATS-Declaration': base64.urlsafe_b64encode(json.dumps(package).encode()).decode()})
    assert response.status_code == 202
    upload = calls[0][3]
    api.JOBS.clear()
    monkeypatch.setattr(api, 'cleanup_stale_clusters', lambda *args, **kwargs: {'failed': []})
    api.recover()
    assert not upload.exists()
    assert api.JOBS[response.json()['validation_id']]['result']['request_id'] == package['request_id']
