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
    def unavailable(*args, **kwargs):
        raise candidate_worker.RendererError('Required isolated scanner is unavailable')
    monkeypatch.setattr(candidate_worker, 'scan_configuration', unavailable)
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
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['expected_resources']['status'] == 'FAIL'


def test_empty_render_cannot_reuse_planning_checks(tmp_path, monkeypatch):
    payload = request()
    payload['files'] = {'empty.yaml': ''}
    payload['render_only'] = True
    payload['validation']['checks'] = {
        name: {'status': 'PASS'} for name in ('yaml_parsing', 'expected_resources', 'kubernetes_schema')}
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['yaml_parsing']['status'] == 'FAIL'


@pytest.mark.parametrize('count,status', [(1, 'PASS'), (2, 'FAIL')])
def test_helm_resource_counts_allow_verification_release_names(tmp_path, monkeypatch, count, status):
    payload = request()
    payload['files'] = {'Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n'}
    payload['render_only'] = True
    payload['plan']['before']['resource_identities'] = ['Pod/original-release'] * count
    monkeypatch.setattr(candidate_worker, 'isolated_runner', lambda *args, **kwargs: {'stdout': ''})
    monkeypatch.setattr(candidate_worker, 'helm_template', lambda *args, **kwargs:
                        {'stdout': request()['files']['pod.yaml']})
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['expected_resources']['status'] == status


@pytest.mark.parametrize('report', ['{}', 'not-json', '{"SchemaVersion":2,"Results":[]}'])
def test_worker_evidence_requires_completed_json(tmp_path, monkeypatch, report):
    def scan(source, report_path, **kwargs):
        assert source.name == '.cats-rendered.yaml'
        report_path.write_text(report)
        return json.loads(report)
    monkeypatch.setattr(candidate_worker, 'scan_configuration', scan)
    result = candidate_worker.execute(request(), tmp_path / 'result.json')
    assert result['validation']['status'] == ('PASS' if 'SchemaVersion' in report else 'FAIL')
    assert bool(result['config_scan']) == ('SchemaVersion' in report)


@pytest.mark.parametrize('per_chart', [False, True])
def test_portal_consumes_only_exact_worker_attempt(tmp_path, monkeypatch, per_chart):
    (tmp_path / 'pod.yaml').write_text(request()['files']['pod.yaml'])
    (tmp_path / 'Chart.yaml').write_text('apiVersion: v2\nname: api\nversion: 1.0.0\n')
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
    settings = {'release': 'retained', 'namespace': 'production'}
    payload = ({'service_overview': {'helm_render_settings': [{'chart_root': '.', **settings}]}}
               if per_chart else {'render_settings': settings})
    assert main._validate_materialized_candidate(tmp_path, payload, plan, request()['validation'])['status'] == 'PASS'
    if per_chart:
        assert received['service_overview'] == payload['service_overview']
    else:
        assert received['render_settings'] == settings
    assert plan['after']['configuration_findings'] == 0
    assert calls == ['POST', 'GET', 'DELETE']


def test_candidate_preserves_each_retained_instance_of_same_chart(tmp_path, monkeypatch):
    payload = request()
    payload['render_only'] = True
    payload['files'] = {'chart/Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n',
        'blue.yaml': 'color: blue\n', 'green.yaml': 'color: green\n'}
    instances = [{'chart_root': 'chart', 'release': color, 'namespace': color + '-ns',
                  'values': [color + '.yaml'], 'set': ['replicas=' + str(index)], 'include_crds': False}
                 for index, color in enumerate(('blue', 'green'), 1)]
    payload['service_overview'] = {'helm_render_settings': instances}
    payload['plan']['before']['resource_identities'] = ['blue-ns/Pod/blue', 'green-ns/Pod/green']
    calls = []
    monkeypatch.setattr(candidate_worker, 'isolated_runner', lambda *args, **kwargs: {'stdout': ''})
    def render(chart, **kwargs):
        calls.append(kwargs)
        return {'stdout': f"apiVersion: v1\nkind: Pod\nmetadata: {{name: {kwargs['release']}, namespace: {kwargs['namespace']}}}\n"}
    monkeypatch.setattr(candidate_worker, 'helm_template', render)
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['expected_resources']['status'] == 'PASS'
    assert [(call['release'], call['namespace'], call['set_values']) for call in calls] == [
        ('blue', 'blue-ns', ['replicas=1']), ('green', 'green-ns', ['replicas=2'])]
    assert [call['values'][0].name for call in calls] == ['blue.yaml', 'green.yaml']


def test_candidate_renders_repository_chart_and_explicit_nested_chart(tmp_path, monkeypatch):
    payload = request()
    payload['render_only'] = True
    roots = ['charts/api', 'charts/api/charts/common']
    payload['files'] = {root + '/Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n' for root in roots}
    payload['service_overview'] = {'helm_render_settings': [
        {'chart_root': root, 'release': 'release-' + str(index)} for index, root in enumerate(roots)]}
    payload['plan']['before']['resource_identities'] = ['default/Pod/release-0', 'default/Pod/release-1']
    calls = []
    monkeypatch.setattr(candidate_worker, 'isolated_runner', lambda *args, **kwargs: {'stdout': ''})
    def render(chart, **kwargs):
        calls.append(chart.relative_to(kwargs['source_root']).as_posix())
        return {'stdout': f"apiVersion: v1\nkind: Pod\nmetadata: {{name: {kwargs['release']}, namespace: default}}\n"}
    monkeypatch.setattr(candidate_worker, 'helm_template', render)
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert calls == roots
    assert result['validation']['checks']['expected_resources']['status'] == 'PASS'


@pytest.mark.parametrize('instances,global_settings', [([], None), ([{'chart_root': 'missing'}], None),
    ([{'chart_root': 'chart'}], {'release': 'other'}), ([{'chart_root': 'chart', 'values': ['absent.yaml']}], None)])
def test_retained_render_instances_never_fall_back_to_defaults(instances, global_settings):
    payload = request()
    payload['files'] = {'chart/Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n'}
    payload['service_overview'] = {'helm_render_settings': instances}
    payload['render_settings'] = global_settings
    with pytest.raises(ValueError):
        candidate_worker.validate_request(payload)


def test_ingest_retains_render_settings_and_unavailable_provenance():
    from app.schemas import ExecutionPayload
    payload = {'execution_id': 'scan', 'scanned_at': '2026-11-05T00:00:00Z', 'complete': True,
        'fixable_only': True, 'service': {'id': 'demo', 'name': 'Demo', 'version': '1'},
        'render_settings': {'release': 'retained', 'namespace': 'production'}}
    assert ExecutionPayload(**payload).model_dump()['render_settings'] == payload['render_settings']
    payload.pop('render_settings')
    payload['service_overview'] = {'helm_render_settings': [{'chart_root': '__unretained__/chart',
        'values': ['__unretained__/secret-values.yaml']}]}
    assert ExecutionPayload(**payload).service_overview == payload['service_overview']


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


def test_candidate_retains_render_inputs_in_shared_actions(tmp_path, monkeypatch):
    payload = request()
    payload['render_only'] = True
    payload['files'].update({'chart/Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n',
                             'values/prod.yaml': 'replicas: 2\n'})
    payload['render_settings'] = {'release': 'original', 'namespace': 'production',
        'values': ['values/prod.yaml'], 'set': ['service.enabled=true'], 'include_crds': False}
    calls = []
    def lint(tool, args, cwd, **kwargs):
        assert tool == 'helm' and args[0] == 'lint'
        assert args[args.index('--namespace') + 1] == 'production'
        assert args[args.index('--set-string') + 1] == 'service.enabled=true'
        assert args[args.index('--values') + 1] == str(cwd / 'values/prod.yaml')
        assert 'env' not in kwargs
        calls.append('lint')
        return {'stdout': ''}
    def render(chart, **kwargs):
        assert chart == kwargs['source_root'] / 'chart'
        assert kwargs['release'] == 'original' and kwargs['namespace'] == 'production'
        assert kwargs['values'] == [kwargs['source_root'] / 'values/prod.yaml']
        assert kwargs['set_values'] == ['service.enabled=true']
        assert kwargs['include_crds'] is False and 'env' not in kwargs
        calls.append('template')
        return {'stdout': request()['files']['pod.yaml']}
    monkeypatch.setattr(candidate_worker, 'isolated_runner', lint)
    monkeypatch.setattr(candidate_worker, 'helm_template', render)
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['helm_template']['status'] == 'PASS'
    assert calls == ['lint', 'template']


def test_candidate_render_failure_never_retries_with_weakened_values(tmp_path, monkeypatch):
    payload = request()
    payload['render_only'] = True
    payload['files'] = {'Chart.yaml': 'apiVersion: v2\nname: api\nversion: 1.0.0\n'}
    calls = []
    def unavailable(*args, **kwargs):
        calls.append((args, kwargs))
        raise candidate_worker.RendererError('Unavailable isolation')
    monkeypatch.setattr(candidate_worker, 'isolated_runner', unavailable)
    monkeypatch.setattr(candidate_worker, 'helm_template', unavailable)
    result = candidate_worker.execute(payload, tmp_path / 'result.json')
    assert result['validation']['checks']['helm_lint']['status'] == 'FAIL'
    assert result['validation']['checks']['helm_template']['status'] == 'FAIL'
    assert len(calls) == 2
    assert 'allowInsecureImages' not in str(calls)


@pytest.mark.parametrize('configured,supplied', [('', None), ('', ''), ('', 'some-token'),
                                               ('secret', None), ('secret', ''), ('secret', 'wrong')])
def test_every_patch_endpoint_requires_configured_authentication(tmp_path, monkeypatch, configured, supplied):
    monkeypatch.setattr(patch_service, 'TOKEN', configured)
    monkeypatch.setattr(patch_service, 'JOB_ROOT', tmp_path)
    operations = [lambda: patch_service.start_patch_job('test', {'config': {'job_id': 'test'}}, supplied),
                  lambda: patch_service.patch_job_status('test', supplied),
                  lambda: patch_service.cancel_patch_job('test', supplied)]
    for operation in operations:
        with pytest.raises(HTTPException) as error:
            operation()
        assert error.value.status_code == 403
    assert not list(tmp_path.iterdir())


def test_candidate_launch_has_no_worker_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(patch_service, 'TOKEN', 'secret')
    monkeypatch.setattr(patch_service, 'JOB_ROOT', tmp_path)
    monkeypatch.setattr(patch_service, 'CANDIDATE_PROCESSES', {})
    monkeypatch.setattr(patch_service, 'CANDIDATE_SLOTS', threading.BoundedSemaphore(1))
    monkeypatch.setattr(patch_service.threading, 'Thread', lambda **kwargs: SimpleNamespace(start=lambda: None))
    for key in ('CATS_PATCH_WORKER_TOKEN', 'CATS_SIGNING_PRIVATE_KEY', 'CATS_PATCH_SOURCE_PASSWORD',
                'CATS_PATCH_DEST_PASSWORD', 'AWS_SECRET_ACCESS_KEY', 'HELM_REGISTRY_CONFIG',
                'DOCKER_CONFIG', 'DATABASE_URL', 'HTTPS_PROXY', 'UNRELATED_SECRET'):
        monkeypatch.setenv(key, 'sensitive-marker')
    monkeypatch.setenv('TRIVY_CACHE_DIR', '/opt/catscan/trivy-cache')
    captured = {}
    def spawn(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(patch_service.subprocess, 'Popen', spawn)
    assert patch_service.start_candidate_verification('a' * 32, request(), 'secret')['status'] == 'running'
    assert 'sensitive-marker' not in captured['env'].values()
    assert captured['env']['TRIVY_CACHE_DIR'] == '/opt/catscan/trivy-cache'
    assert captured['env']['DATABASE_URL'] == 'sqlite://'


def test_image_status_alone_cannot_establish_scan_evidence():
    image = {'candidate': 'local/image:patched', 'patch_status': 'PATCHED', 'artifact_sha256': 'sha256:' + 'a' * 64}
    checks = {}
    candidate_worker._image_scan_check({'images': [image]}, checks)
    assert checks['vulnerability_rescan']['status'] == 'UNAVAILABLE'
    image['scan_evidence'] = {'status': 'complete', 'candidate_digest': image['artifact_sha256'],
        'before': {'sha256': 'sha256:' + 'b' * 64, 'sbom_digest': 'sha256:' + 'c' * 64},
        'after': {'sha256': 'sha256:' + 'd' * 64, 'sbom_digest': 'sha256:' + 'e' * 64}}
    candidate_worker._image_scan_check({'images': [image]}, checks)
    assert checks['vulnerability_rescan']['status'] == 'PASS'
    image['scan_evidence']['candidate_digest'] = 'sha256:' + 'f' * 64
    candidate_worker._image_scan_check({'images': [image]}, checks)
    assert checks['vulnerability_rescan']['status'] == 'UNAVAILABLE'
