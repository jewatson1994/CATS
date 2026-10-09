import json
import threading
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import candidate_worker, main, patch_service


def request(attempt='a' * 32):
    return {'attempt_id': attempt, 'remediation_job_id': 'retained-remediation',
            'files': {'pod.yaml': 'apiVersion: v1\nkind: Pod\nmetadata: {name: api}\n'},
            'helm_values_files': [], 'plan': {'before': {}, 'after': {}, 'images': []},
            'validation': {'checks': {}, 'required_checks': ['trivy_config_rescan']}}


@pytest.mark.parametrize('path', ['../secret', '/secret', 'C:/secret', 'dir\\secret', '.cats-rendered.yaml'])
def test_worker_rejects_unconfined_sources(path):
    payload = request()
    payload['files'] = {path: 'secret'}
    with pytest.raises(ValueError):
        candidate_worker.validate_request(payload)


def test_worker_missing_scanner_never_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(candidate_worker.shutil, 'which', lambda _: None)
    result = candidate_worker.execute(request(), tmp_path / 'result.json')
    assert result['validation']['status'] == 'FAIL'
    assert result['validation']['checks']['trivy_config_rescan']['status'] == 'FAIL'
    assert result['input_digest'] == candidate_worker.request_digest(request())
    assert not list(tmp_path.glob('candidate-*'))


@pytest.mark.parametrize('expected', [['Pod/other'], ['Pod/api', 'Pod/api'], ['team/Pod/api']])
def test_worker_requires_expected_resource_identities(tmp_path, monkeypatch, expected):
    payload = request()
    payload['render_only'] = True
    payload['plan']['before']['resource_identities'] = expected
    monkeypatch.setattr(candidate_worker.shutil, 'which', lambda _: None)
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['expected_resources']['status'] == 'FAIL'


def test_empty_render_cannot_reuse_planning_checks(tmp_path, monkeypatch):
    payload = request()
    payload['files'] = {'empty.yaml': ''}
    payload['render_only'] = True
    payload['validation']['checks'] = {
        name: {'status': 'PASS'} for name in ('yaml_parsing', 'expected_resources', 'kubernetes_schema')}
    monkeypatch.setattr(candidate_worker.shutil, 'which', lambda _: None)
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['yaml_parsing']['status'] == 'FAIL'


@pytest.mark.parametrize('count,status', [(1, 'PASS'), (2, 'FAIL')])
def test_helm_resource_counts_allow_verification_release_names(tmp_path, monkeypatch, count, status):
    payload = request()
    payload['files'] = {'Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n'}
    payload['render_only'] = True
    payload['plan']['before']['resource_identities'] = ['Pod/original-release'] * count
    monkeypatch.setattr(candidate_worker.shutil, 'which', lambda tool: 'helm' if tool == 'helm' else None)
    monkeypatch.setattr(candidate_worker.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=request()['files']['pod.yaml']))
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['expected_resources']['status'] == status


@pytest.mark.parametrize('report', ['{}', 'not-json', '{"SchemaVersion":2,"Results":[]}'])
def test_worker_evidence_requires_completed_json(tmp_path, monkeypatch, report):
    monkeypatch.setattr(candidate_worker.shutil, 'which', lambda tool: 'trivy' if tool == 'trivy' else None)
    monkeypatch.setattr(candidate_worker.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=report))
    result = candidate_worker.execute(request(), tmp_path / 'result.json')
    assert result['validation']['status'] == ('PASS' if 'SchemaVersion' in report else 'FAIL')


def test_portal_consumes_only_exact_worker_attempt(tmp_path, monkeypatch):
    (tmp_path / 'pod.yaml').write_text(request()['files']['pod.yaml'])
    monkeypatch.setattr(main, 'PATCH_WORKER_URL', 'http://worker')
    monkeypatch.setattr(main, 'PATCH_WORKER_TOKEN', 'private-token')
    calls, received = [], {}
    def remote(path, method='GET', payload=None):
        calls.append(method)
        if method == 'POST':
            received.update(payload)
            return {'status': 'running'}
        if method == 'DELETE':
            return {}
        return {'status': 'complete', 'attempt_id': received['attempt_id'],
                'remediation_job_id': received['remediation_job_id'],
                'input_digest': candidate_worker.request_digest(received),
                'validation': {'status': 'PASS'}, 'after': {'configuration_findings': 0},
                'rendered': 'kind: Pod', 'config_scan': '{}'}
    monkeypatch.setattr(main, '_patch_worker_request', remote)
    monkeypatch.setattr(main.subprocess, 'run', lambda *a, **k: pytest.fail('Portal must never execute scanner'))
    plan = {'before': {}, 'after': {}, 'images': []}
    assert main._validate_materialized_candidate(tmp_path, {}, plan, request()['validation'])['status'] == 'PASS'
    assert plan['after']['configuration_findings'] == 0
    assert calls == ['POST', 'GET', 'DELETE']


@pytest.mark.parametrize('mismatch', ['attempt_id', 'input_digest', 'remediation_job_id', 'failed'])
def test_portal_rejects_mismatched_or_failed_worker(tmp_path, monkeypatch, mismatch):
    monkeypatch.setattr(main, 'PATCH_WORKER_URL', 'http://worker')
    monkeypatch.setattr(main, 'PATCH_WORKER_TOKEN', 'secret')
    payloads = []
    def remote(path, method='GET', payload=None):
        if method == 'POST':
            payloads.append(payload)
            return {}
        if method == 'DELETE':
            return {}
        sent = payloads[0]
        result = {'status': 'complete', 'attempt_id': sent['attempt_id'],
                  'remediation_job_id': sent['remediation_job_id'],
                  'input_digest': candidate_worker.request_digest(sent), 'validation': {'status': 'PASS'}}
        result['status' if mismatch == 'failed' else mismatch] = 'failed' if mismatch == 'failed' else 'wrong'
        return result
    monkeypatch.setattr(main, '_patch_worker_request', remote)
    with pytest.raises(RuntimeError, match='mismatched evidence'):
        main._validate_materialized_candidate(tmp_path, {}, {}, request()['validation'])


@pytest.mark.parametrize('token', ['', 'wrong', None])
def test_candidate_api_authentication_required(tmp_path, monkeypatch, token):
    monkeypatch.setattr(patch_service, 'TOKEN', token or '')
    monkeypatch.setattr(patch_service, 'JOB_ROOT', tmp_path)
    for operation in (lambda: patch_service.start_candidate_verification('a' * 32, request(), None),
                      lambda: patch_service.candidate_verification_status('a' * 32, None)):
        with pytest.raises(HTTPException) as error:
            operation()
        assert error.value.status_code == 403



def test_candidate_api_enforces_capacity_and_restart_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(patch_service, 'TOKEN', 'secret')
    monkeypatch.setattr(patch_service, 'JOB_ROOT', tmp_path)
    slots = threading.BoundedSemaphore(1)
    slots.acquire()
    monkeypatch.setattr(patch_service, 'CANDIDATE_SLOTS', slots)
    with pytest.raises(HTTPException) as error:
        patch_service.start_candidate_verification('a' * 32, request(), 'secret')
    assert error.value.status_code == 503
    root, _, _ = patch_service._candidate_paths('a' * 32)
    root.mkdir(parents=True)
    assert patch_service.candidate_verification_status('a' * 32, 'secret')['status'] == 'failed'
    assert patch_service.cleanup_candidate_verification('a' * 32, 'secret')['status'] == 'removed'
    assert not root.exists()


def test_isolated_worker_process_keeps_attempt_identity_and_fails_closed(tmp_path):
    payload = request()
    config, result = tmp_path / 'request.json', tmp_path / 'result.json'
    config.write_text(json.dumps(payload))
    environment = {**os.environ, 'PATH': ''}
    completed = subprocess.run([sys.executable, '-m', 'app.candidate_worker', str(config), str(result)],
                               env=environment, capture_output=True, timeout=20)
    assert completed.returncode == 0
    evidence = json.loads(result.read_text())
    assert evidence['attempt_id'] == payload['attempt_id']
    assert evidence['input_digest'] == candidate_worker.request_digest(payload)
    assert evidence['validation']['status'] == 'FAIL'
    assert not list(tmp_path.glob('candidate-*'))


def test_portal_missing_worker_configuration_has_no_local_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'PATCH_WORKER_URL', '')
    monkeypatch.setattr(main, 'PATCH_WORKER_TOKEN', '')
    monkeypatch.setattr(main.subprocess, 'run', lambda *a, **k: pytest.fail('must not execute locally'))
    with pytest.raises(RuntimeError, match='not configured'):
        main._validate_materialized_candidate(tmp_path, {}, {}, request()['validation'])
