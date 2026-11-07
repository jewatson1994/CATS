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


def test_standalone_replica_health_uses_database_readiness():
    compose = yaml.safe_load((Path(__file__).resolve().parents[2] / 'compose.replica.yaml').read_text())
    probe = compose['services']['portal']['healthcheck']['test'][-1]
    assert 'http://127.0.0.1:8000/readyz' in probe
    assert '/health' not in probe
