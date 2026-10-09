"""HTTP worker protocol and real ingestion, with only scanner binaries stood in."""
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import select

from test_scan_worker_coordination import database
from app import main, scan_control, scan_protocol, scan_worker
from app.models import Execution, Finding, Service


def test_http_claim_transfer_worker_execution_and_real_service_ingest(database, monkeypatch, tmp_path):
    monkeypatch.setattr(main, 'SessionLocal', database)
    monkeypatch.setattr(scan_protocol, 'SessionLocal', database)
    monkeypatch.setattr(main, 'PUBLIC_JOB_ROOT', tmp_path / 'portal')
    main.PUBLIC_JOB_ROOT.mkdir()
    monkeypatch.setattr(scan_worker, 'ROOT', tmp_path / 'worker')
    scan_worker.ROOT.mkdir()
    token = 'integration-credential-' + '7' * 40
    monkeypatch.setenv('CATS_SCAN_WORKER_TOKEN', token)
    monkeypatch.setenv('CATS_SCAN_WORKER_ID', 'integration-worker')
    monkeypatch.delenv('CATS_SCAN_WORKER_CREDENTIALS', raising=False)
    monkeypatch.setenv('CATS_DEPLOYMENT_VALIDATION_ENABLED', 'false')
    monkeypatch.setattr(scan_worker.shutil, 'which', lambda tool: None)
    scan_worker.STOP.clear()
    with database() as db:
        service = Service(id=2, service_key='http-worker-service', name='HTTP Worker Service', manual_version='v1')
        db.add(service); db.commit()
        service_id = service.id
    job_id = main._start_public_scan('registry.invalid/app:1', ingest_service_id='http-worker-service', owner_user_id=17)
    headers = {'Authorization': 'Bearer ' + token, 'X-Worker-ID': 'integration-worker'}
    browser = TestClient(main.app)
    control = TestClient(scan_control.app)
    claim_response = control.post('/internal/scan-worker/claim', json={'worker_id': 'integration-worker'}, headers=headers)
    assert claim_response.status_code == 200
    claim = claim_response.json()
    assert claim['job_id'] == job_id

    class ScannerStandIn:
        returncode = 0
        def __init__(self, command, **kwargs):
            output = Path(command[-1])
            (output / 'scan-summary.json').write_text(json.dumps({'status': 'complete', 'images': 1, 'findings': 1}), encoding='utf-8')
            result = {'schema_version': '1.0', 'execution_id': 'scanner-placeholder',
                'scanned_at': datetime.now(timezone.utc).isoformat(), 'complete': True,
                'service': {'id': 'http-worker-service', 'name': 'HTTP Worker Service', 'version': 'v1'},
                'findings': [{'cve': 'CVE-2026-1212', 'severity': 'High', 'image': 'registry.invalid/app:1',
                              'package': 'openssl', 'fixed_version': '9.9', 'evidence': {'description': 'Scanner stand-in evidence'}}]}
            (output / 'portal-result.json').write_text(json.dumps(result), encoding='utf-8')
        def poll(self): return 0
    monkeypatch.setattr(scan_worker.subprocess, 'Popen', ScannerStandIn)

    class ResponseAdapter:
        def __init__(self, response): self.response = response
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def json(self): return self.response.json()
        def iter_content(self, size): yield self.response.content
    worker = scan_worker.Worker.__new__(scan_worker.Worker)
    worker.worker_id = 'integration-worker'
    def request(method, suffix, **kwargs):
        kwargs.pop('timeout', None); kwargs.pop('stream', None)
        request_headers = {**headers, **kwargs.pop('headers', {})}
        if 'data' in kwargs: kwargs['content'] = kwargs.pop('data').read()
        response = control.request(method, '/internal/scan-worker' + suffix, headers=request_headers, **kwargs)
        response.raise_for_status()
        return ResponseAdapter(response)
    worker.request = request
    worker._execute(claim, None)
    scan_protocol.ingest_one()
    with database() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == 'public:' + job_id))
        assert execution is not None
        assert execution.service_id == service_id
        assert db.scalar(select(Finding).where(Finding.service_id == service_id, Finding.cve == 'CVE-2026-1212')) is not None
        first_execution_id = execution.id
    # A coordinator replay cannot duplicate the real service execution.
    scan_protocol.ingest_one()
    with database() as db:
        executions = list(db.scalars(select(Execution).where(Execution.execution_key == 'public:' + job_id)))
        assert [execution.id for execution in executions] == [first_execution_id]
    job = main.PUBLIC_JOBS[job_id]
    assert job['status'] == 'complete' and job['ingested'] is True
    assert (main.PUBLIC_JOB_ROOT / job_id / 'output' / 'worker-provenance.json').exists()
    main.app.dependency_overrides[main.optional_user] = lambda: SimpleNamespace(user=SimpleNamespace(id=17), has=lambda permission, service: False)
    try:
        status = browser.get('/api/public/jobs/' + job_id)
        assert status.status_code == 200
        assert 'owner_user_id' not in status.json()
        assert status.json()['status'] == 'complete'
    finally:
        main.app.dependency_overrides.clear()
        browser.close()
        control.close()
