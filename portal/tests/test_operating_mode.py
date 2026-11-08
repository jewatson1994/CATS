"""The replica boundary must remain closed as authoritative APIs evolve."""
import asyncio
import os
import subprocess
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml

from app import operating_mode as mode
from app.auth import AuthContext, SYSTEM_ROLES


@pytest.mark.parametrize('method,path', [
    ('POST', '/api/services/example/findings'),
    ('POST', '/services/example/edit'),
    ('POST', '/api/services/example/approvals'),
    ('DELETE', '/api/services/example'),
    ('PATCH', '/api/replica/sources/1'),
    ('POST', '/api/future-authoritative-endpoint'),
    ('POST', '/api/oci/upstreams/1/unrecognized-operation'),
    ('POST', '/api/services/example/local-overrides/1/edit'),
    ('POST', '/admin/configuration/signing'),
    ('POST', '/admin/configuration/scan-settings'),
    ('POST', '/api/public/scan'),
    ('POST', '/api/public/patch'),
    ('POST', '/admin/services/stage'),
    ('POST', '/admin/services/example'),
    ('POST', '/services/example/remediate'),
    ('POST', '/services/example/scan-schedule'),
    ('POST', '/services/example/images/1/replace'),
    ('POST', '/services/example/missing-evidence/remove'),
    ('POST', '/services/example/mitigations'),
    ('POST', '/findings/1/exceptions'),
    ('POST', '/api/services/example/risk-assessments'),
    ('POST', '/api/services/example/risk-decisions'),
    ('POST', '/api/cyber-approvals/1/decide'),
    ('GET', '/api/public/jobs/scan-1/results'),
    ('GET', '/api/public/patch-jobs/patch-1/results'),
    ('GET', '/services/example/exports/findings.xlsx'),
    ('GET', '/exports/services.xlsx'), ('GET', '/poam/export.xlsx'),
    ('GET', '/scan'), ('GET', '/patch'), ('GET', '/discovery'),
    ('GET', '/risk-intelligence'), ('GET', '/admin/validators'),
])
def test_replica_rejects_authoritative_and_unknown_operations(monkeypatch, method, path):
    monkeypatch.setenv('CATS_MODE', 'replica')
    assert not mode.request_available(method, path)
    monkeypatch.setenv('CATS_MODE', 'full')
    assert mode.request_available(method, path)


@pytest.mark.parametrize('method,path', [
    ('GET', '/services/example'), ('GET', '/api/services/example/findings'),
    ('GET', '/approved-releases'), ('GET', '/auth/oidc/callback'),
    ('POST', '/login'), ('POST', '/logout'), ('POST', '/account/password'),
    ('POST', '/admin/users'), ('POST', '/admin/roles'),
    ('POST', '/admin/configuration/oidc'), ('POST', '/admin/configuration/trusted-certificates'),
    ('POST', '/api/replica/sync'), ('POST', '/api/replica/sources'),
    ('PUT', '/api/replica/sources/1'), ('POST', '/api/oci/upstreams'),
    ('PUT', '/api/oci/repositories/1'), ('POST', '/api/oci/principals/1/rotate'),
    ('POST', '/api/services/example/local-overrides'),
    ('POST', '/api/services/example/local-overrides/1/revoke'),
])
def test_replica_permits_only_read_and_identified_local_routes(monkeypatch, method, path):
    monkeypatch.setenv('CATS_MODE', 'replica')
    assert mode.request_available(method, path)


def test_default_and_invalid_mode(monkeypatch):
    monkeypatch.delenv('CATS_MODE', raising=False)
    assert mode.mode() == 'full'
    monkeypatch.setenv('CATS_MODE', 'replcia')
    with pytest.raises(RuntimeError, match='CATS_MODE'):
        mode.ReplicaModeMiddleware(None)


def test_http_boundary_prevents_any_handler_side_effect(monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'replica')
    app, writes = FastAPI(), []
    app.add_middleware(mode.ReplicaModeMiddleware)

    @app.post('/future-api')
    def future():
        writes.append('authoritative')

    @app.post('/api/replica/sync')
    def local():
        writes.append('local')
        return {'ok': True}

    with TestClient(app) as client:
        response = client.post('/future-api')
        assert response.status_code == 403
        assert response.json()['code'] == 'replica_read_only'
        assert response.headers['cache-control'] == 'no-store'
        assert writes == []
        assert client.post('/api/replica/sync').status_code == 200
        assert writes == ['local']


def context(permissions, service_id=None):
    assignment = SimpleNamespace(role=SimpleNamespace(name='Explicit role', permissions=permissions),
        role_id=1, service_id=service_id, group_id=None, group=None)
    return AuthContext(SimpleNamespace(role_assignments=[assignment]), SimpleNamespace(csrf_token='test'))


def test_mode_denies_authoritative_permissions_even_for_existing_roles(monkeypatch):
    admin = context(['service.view', 'service.edit', 'replica.admin', 'local_override.create'])
    monkeypatch.setenv('CATS_MODE', 'full')
    assert admin.has('service.edit', 7)
    monkeypatch.setenv('CATS_MODE', 'replica')
    assert not admin.has('service.edit', 7)
    assert admin.accessible_service_ids('service.edit') == set()
    assert admin.has('service.view', 7)
    assert admin.has('replica.admin')
    assert context(['local_override.create'], service_id=7).has('local_override.create', 7)
    assert not context(['local_override.create'], service_id=7).has('local_override.create', 8)
    assert not context(['replica.admin'], service_id=7).has('replica.admin', 7)
    assert not any(p.startswith('local_override.') for p in SYSTEM_ROLES['Administrator'])
    assert 'local_override.create' in SYSTEM_ROLES['Local Cyber']


def test_replica_lifespan_skips_intelligence_scanning_and_validation(monkeypatch):
    from app import main, replica_sync
    monkeypatch.setenv('CATS_MODE', 'replica')
    steps = []

    @asynccontextmanager
    async def replica():
        steps.append('start')
        yield
        steps.append('stop')

    def forbidden(*args, **kwargs):
        pytest.fail('An assessment worker or intelligence installer started in replica mode')

    monkeypatch.setattr(replica_sync, 'replica_lifespan', replica)
    monkeypatch.setattr(main.validator_management, 'recover_operations', forbidden)
    monkeypatch.setattr(main, '_start_read_model_maintenance', forbidden)
    monkeypatch.setattr(main.DEPLOYMENT_VALIDATION_WORKERS, 'submit', forbidden)
    monkeypatch.setattr(main.scan_protocol, 'maintenance', forbidden)
    from app import embedded_intelligence
    monkeypatch.setattr(embedded_intelligence, 'install_package', forbidden)

    async def run():
        async with main.app_lifespan(main.app):
            assert steps == ['start']
    asyncio.run(run())
    assert steps == ['start', 'stop']


@pytest.mark.parametrize('operating_mode,blocked', [('replica', True), ('full', True), ('full', False)])
def test_portal_import_only_requires_assessment_storage_in_full_mode(tmp_path, operating_mode, blocked):
    # A fresh interpreter exercises actual module initialization in both modes.
    # A file in place of the parent makes storage unavailable on every OS.
    parent = tmp_path / 'assessment'
    if blocked:
        parent.write_text('Assessment storage is unavailable')
    roots = {f'CATS_{name}_JOB_ROOT': str(parent / name.lower())
             for name in ('PUBLIC', 'PATCH', 'REMEDIATION')}
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('CATS_', 'INTELLIGENCE_'))}
    env.update(roots, CATS_MODE=operating_mode, DATABASE_URL='sqlite://',
               CATS_BOOTSTRAP_USERNAME='admin', CATS_BOOTSTRAP_PASSWORD='test-password-long',
               CATS_DEPLOYMENT_VALIDATION_ENABLED='false')
    result = subprocess.run([sys.executable, '-c', 'import app.main'], env=env,
                            cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, timeout=60)
    if operating_mode == 'full' and blocked:
        assert result.returncode != 0
        assert repr(str(parent))[1:-1] in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        if operating_mode == 'full':
            assert all(Path(path).is_dir() for path in roots.values())
        else:
            assert parent.is_file()


@pytest.mark.parametrize('compose_path,expected_services', [
    ('compose.replica.yaml', {'db', 'portal', 'oci-proxy'}),
    ('templates/compose.replica.yaml', {'db', 'portal', 'oci-proxy', 'nginx'}),
])
def test_replica_compose_has_no_assessment_infrastructure(compose_path, expected_services):
    root = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((root / compose_path).read_text())
    assert set(compose['services']) == expected_services
    assert 'docker.sock' not in str(compose)
    for name in ('portal', 'oci-proxy'):
        service = compose['services'][name]
        assert service['environment']['CATS_MODE'] == 'replica'
        assert service['environment']['CATS_DEPLOYMENT_VALIDATION_ENABLED'] == 'false'
        assert 'INTELLIGENCE_DATABASE_URL' not in service['environment']
        assert service['depends_on']['db']['condition'] == 'service_healthy'
    assert set(compose['services']['portal']['depends_on']) == {'db'}


def test_initial_replica_synchronization_does_not_block_portal(monkeypatch):
    from app import replica_sync
    monkeypatch.setenv('CATS_REPLICA_SYNC_ENABLED', 'true')
    started, finish, completed = threading.Event(), threading.Event(), threading.Event()

    def slow_initial_sync():
        started.set()
        finish.wait(5)
        completed.set()

    monkeypatch.setattr(replica_sync, 'schedule_due', slow_initial_sync)
    monkeypatch.setattr(replica_sync.jobs, 'claim', lambda *args: None)

    @asynccontextmanager
    async def lifespan(_app):
        async with replica_sync.replica_lifespan():
            yield

    app = FastAPI(lifespan=lifespan)

    @app.get('/health')
    def health():
        return {'status': 'ok'}

    with TestClient(app) as client:
        try:
            assert started.wait(2)
            assert not completed.is_set()
            assert client.get('/health').json() == {'status': 'ok'}
            assert not completed.is_set()
        finally:
            finish.set()
    assert completed.is_set()
