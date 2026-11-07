"""Readiness must expose dependency failure while liveness remains independent."""
from contextlib import contextmanager
import json
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError, TimeoutError
import yaml

from app import main


@pytest.mark.parametrize('failure', [None,
    OperationalError('SELECT 1', {}, Exception('private-host password=secret')),
    TimeoutError('pool contains private connection details')])
def test_readiness_checks_database_and_redacts_failures(monkeypatch, failure):
    calls = []

    @contextmanager
    def session():
        class Database:
            def execute(self, query):
                calls.append(str(query))
                if failure:
                    raise failure
        try:
            yield Database()
        finally:
            calls.append('closed')

    monkeypatch.setattr(main, 'SessionLocal', session)
    ready = main.readiness()
    assert ready.status_code == (503 if failure else 200)
    assert json.loads(ready.body) == {'status': 'unavailable' if failure else 'ready'}
    assert ready.headers['cache-control'] == 'no-store'
    assert calls == ['SELECT 1', 'closed']
    assert main.health() == {'status': 'ok'}
    assert calls == ['SELECT 1', 'closed']
    assert any(route.path == '/readyz' for route in main.app.routes)


@pytest.mark.parametrize('compose_path', [
    'compose.replica.yaml', 'templates/compose.replica.yaml',
])
def test_standalone_replica_health_uses_database_readiness(compose_path):
    compose = yaml.safe_load((Path(__file__).resolve().parents[2] / compose_path).read_text())
    probe = compose['services']['portal']['healthcheck']['test'][-1]
    assert ':8000/readyz' in probe
    assert '/health' not in probe


def test_deployment_replica_keeps_backends_private_and_verifies_tls_health():
    root = Path(__file__).resolve().parents[2]
    services = yaml.safe_load((root / 'templates/compose.replica.yaml').read_text())['services']
    assert {name for name, service in services.items() if service.get('ports')} == {'nginx'}
    for name, cert_dir in [('portal', '/app/certs'), ('oci-proxy', '/app/oci-certs')]:
        service = services[name]
        assert service.get('network_mode') != 'host'
        command = service['command']
        assert '--no-proxy-headers' in command
        assert command[command.index('--ssl-certfile') + 1] == f'{cert_dir}/tls.crt'
        assert command[command.index('--ssl-keyfile') + 1] == f'{cert_dir}/tls.key'
        cert_mount = next(mount for mount in service['volumes']
                          if isinstance(mount, dict) and mount.get('target') == cert_dir)
        assert cert_mount['read_only'] is True
        assert cert_mount['bind']['create_host_path'] is False
        probe = service['healthcheck']['test']
        assert probe[:2] == ['CMD', 'curl']
        assert '--fail' in probe
        assert not {'--insecure', '-k'}.intersection(probe)
        assert probe[probe.index('--cacert') + 1] == f'{cert_dir}/tls.crt'
        hostname_and_port = probe[-1].removeprefix('https://').rsplit('/', 1)[0]
        assert probe[-1].startswith('https://')
        assert probe[probe.index('--resolve') + 1] == f'{hostname_and_port}:127.0.0.1'
