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
    monkeypatch.setenv('CATS_MANAGED_VALIDATOR_ID', 'managed-123')
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
                'cleanup_status': 'COMPLETE', 'offlineVerified': False,
                'helm_result': {'install': 'PASS', 'release_status': 'DEPLOYED', 'execution_mode': 'HELM', 'helm_release_verified': True}}
    evidence.pop('validator_id', None)
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


def test_client_cancellation_sent_once_waits_for_terminal_cleanup(monkeypatch):
    package=declaration('oci');job='2'*32;identity=api._request_identity(package)
    submitted={**identity,'validation_id':job,'status':'QUEUED'}
    running={**identity,'validation_id':job,'status':'RUNNING','phase':'CLEANUP'}
    result={**identity,'validation_id':job,'status':'CANCELLED','cleanup_status':'COMPLETE'}
    terminal={**identity,'validation_id':job,'status':'CANCELLED','phase':'COMPLETE','result':result}
    polls=iter([running,running,terminal]);calls=[]
    def request(url,context,*args,**kwargs):
        calls.append(url)
        if url.endswith('/cancel'):return {'cancel_requested':True}
        if url.endswith('/validations'):return submitted
        return next(polls)
    monkeypatch.setattr(client,'_client_context',lambda *args:object())
    monkeypatch.setattr(client,'_request',request)
    monkeypatch.setattr(client.time,'sleep',lambda seconds:None)
    assert client.validate({'endpoint':'https://validator.test'},package,cancel_requested=lambda:True)==result
    assert len([url for url in calls if url.endswith('/cancel')])==1
    assert len([url for url in calls if url.endswith(job)])==3


@pytest.mark.parametrize('stage', ['submission', 'poll', 'result'])
@pytest.mark.parametrize('received', [None, 'wrong-validator'])
def test_client_requires_expected_managed_identity(monkeypatch, stage, received):
    package = declaration('oci')
    identity = {**api._request_identity(package), 'validator_id': 'managed-123'}
    job = '2' * 32
    submitted = {**identity, 'validation_id': job, 'status': 'QUEUED'}
    result = {**identity, 'validation_id': job, 'status': 'FAILED', 'cleanup_status': 'COMPLETE'}
    state = {**identity, 'validation_id': job, 'status': 'FAILED', 'phase': 'COMPLETE', 'result': result}
    target = submitted if stage == 'submission' else state if stage == 'poll' else result
    if received is None:
        target.pop('validator_id')
    else:
        target['validator_id'] = received
    responses = iter([submitted, state])
    monkeypatch.setattr(client, '_client_context', lambda *args: object())
    monkeypatch.setattr(client, '_request', lambda *args, **kwargs: next(responses))
    with pytest.raises(ValueError):
        client.validate({'endpoint': 'https://example.test', 'expected_validator_id': 'managed-123'}, package)


@pytest.mark.parametrize('field,value', [('install', 'FAIL'), ('release_status', 'UNKNOWN'), ('execution_mode', None), ('execution_mode', 'PREFLIGHTED_MANIFEST_APPLY'), ('helm_release_verified', False), ('helm_release_verified', 1)])
def test_client_rejects_unproven_verified_helm(monkeypatch, tmp_path, field, value):
    package = declaration()
    identity = api._request_identity(package)
    job = '2' * 32
    helm = {'install': 'PASS', 'release_status': 'DEPLOYED', 'execution_mode': 'HELM', 'helm_release_verified': True}
    helm[field] = value
    result = {**identity, 'validation_id': job, 'status': 'VERIFIED', 'cleanup_status': 'COMPLETE', 'helm_result': helm}
    responses = iter([{**identity, 'validation_id': job, 'status': 'QUEUED'},
                      {**identity, 'validation_id': job, 'status': 'VERIFIED', 'phase': 'COMPLETE', 'result': result}])
    monkeypatch.setattr(client, '_client_context', lambda *args: object())
    monkeypatch.setattr(client, '_request', lambda *args, **kwargs: next(responses))
    with pytest.raises(ValueError, match='Helm release'):
        client.validate({'endpoint': 'https://example.test'}, package, artifact_path=tmp_path / 'chart.zip')


@pytest.mark.parametrize('verified', [False, True])
def test_api_requires_real_helm_release(worker, monkeypatch, verified):
    import sys
    connection, calls, root = worker
    package = declaration()
    job = '3' * 32
    api.JOBS[job] = {'validation_id': job, 'status': 'QUEUED', 'phase': 'QUEUED', 'request': package}
    evidence = {key: value for key, value in api._request_identity(package).items() if key != 'validator_id'}
    evidence.update(status='VERIFIED', cleanup_status='COMPLETE',
                    helm_result={'install': 'PASS', 'release_status': 'DEPLOYED',
                                 'execution_mode': 'HELM', 'helm_release_verified': verified})
    class Engine:
        def __init__(self, *args, **kwargs):
            pass
        def validate(self, *args, **kwargs):
            return evidence
    monkeypatch.setitem(sys.modules, 'app.schrodinger_validation', SimpleNamespace(SchrodingerValidator=Engine))
    api._execute(job, package, root / 'chart.zip')
    result = api.JOBS[job]['result']
    assert result['status'] == ('VERIFIED' if verified else 'ERROR')
    assert result['validator_id'] == 'managed-123'


def test_client_accepts_bound_not_verified_terminal(monkeypatch):
    package = declaration('oci')
    identity = api._request_identity(package)
    job = '4' * 32
    result = {**identity, 'validation_id': job, 'status': 'NOT_VERIFIED', 'cleanup_status': 'FAILED'}
    responses = iter([{**identity, 'validation_id': job, 'status': 'QUEUED'}, {**identity, 'validation_id': job, 'status': 'NOT_VERIFIED', 'phase': 'COMPLETE', 'result': result}])
    monkeypatch.setattr(client, '_client_context', lambda *args: object())
    monkeypatch.setattr(client, '_request', lambda *args, **kwargs: next(responses))
    assert client.validate({'endpoint': 'https://validator.test'}, package) == result


@pytest.mark.parametrize('field', ['validator_id', 'service', 'artifact_digest', 'status', 'validation_id'])
def test_upload_contract_error_reports_only_mismatched_fields(monkeypatch, field):
    package = declaration('oci')
    submitted = {**api._request_identity(package), 'validator_id': 'managed-123',
                 'validation_id': '2' * 32, 'status': 'QUEUED'}
    submitted[field] = 'sensitive-response-content'
    monkeypatch.setattr(client, '_client_context', lambda *args: object())
    monkeypatch.setattr(client, '_request', lambda *args, **kwargs: submitted)
    with pytest.raises(client.ContractError) as caught:
        client.validate({'endpoint': 'https://validator.test', 'expected_validator_id': 'managed-123'}, package)
    assert caught.value.fields == (field,)
    assert caught.value.stage == 'upload acknowledgment'
    assert 'sensitive-response-content' not in str(caught.value)


def test_external_dependency_reason_distinguishes_cluster_evidence_failure():
    reason = "The ephemeral cluster stopped responding before CATS could collect workload evidence."
    safe = api._safe_result({"status": "COULD_NOT_VALIDATE", "reason_category": "EXTERNAL_DEPENDENCY", "reason": reason})
    assert safe["reason"] == reason
    safe = api._safe_result({"status": "PARTIALLY_VERIFIED", "reason_category": "EXTERNAL_DEPENDENCY", "reason": "secret command output"})
    assert "secret" not in safe["reason"]
    assert "external dependency" in safe["reason"]


def test_safe_result_identifies_unmet_capabilities_without_submitted_values():
    safe = api._safe_result({"status": "PARTIALLY_VERIFIED", "reason_category": "EXTERNAL_DEPENDENCY",
        "reason": "The chart installed and workloads became Ready, but these required capabilities could not be fully validated: HPA / Metrics API.",
        "capability_preflight": [
            {"capability": "HPA / Metrics API", "required": True, "status": "UNEXERCISED", "explanation": "secret output"},
            {"capability": "secret submitted value", "required": True, "status": "FAILED"}]})
    assert safe["workload_readiness"] == "PASS"
    assert safe["capability_preflight"] == [{"capability": "HPA / Metrics API", "required": True, "status": "UNEXERCISED"}]
    assert "HPA / Metrics API: unexercised" in safe["reason"]
    assert "secret" not in str(safe)


def test_safe_result_retains_redacted_startup_messages():
    safe = api._safe_result({'status': 'ERROR', 'diagnostics': {'runtime_evidence': {
        'collection_status': 'COLLECTED',
        'pods': [{'name': 'demo', 'phase': 'Pending', 'containers': [
            {'name': 'app', 'state': 'waiting', 'reason': 'CrashLoopBackOff',
             'message': 'container has runAsNonRoot and image will run as root; token=secret', 'exit_code': 1, 'restarts': 3, 'ready': False, 'logs': 'secret'}]}],
        'events': [{'reason': 'FailedScheduling', 'condition': 'INSUFFICIENT_CPU',
                    'involvedObject': {'name': 'demo'}, 'message': '0/1 nodes available: insufficient cpu; password=secret'}]}}})
    evidence = safe['diagnostics']['runtime_evidence']
    assert evidence['pods'][0]['containers'][0]['reason'] == 'CrashLoopBackOff'
    assert evidence['pods'][0]['containers'][0]['exit_code'] == 1
    assert evidence['events'][0]['condition'] == 'INSUFFICIENT_CPU'
    assert 'runAsNonRoot' in evidence['pods'][0]['containers'][0]['message']
    assert 'insufficient cpu' in evidence['events'][0]['message']
    assert 'secret' not in json.dumps(safe)


def test_startup_message_redaction_and_bounds():
    from app.runtime_diagnostics import startup_message
    message = startup_message("Failed pulling https://user:secret@example.com/image?token=secret Authorization=secret Bearer secret")
    assert "secret" not in message
    assert "Failed pulling" in message
    assert "runAsNonRoot" in startup_message("container has runAsNonRoot and image will run as root")
    assert len(startup_message("x" * 3000)) < 2050
    assert startup_message(None) == ""
