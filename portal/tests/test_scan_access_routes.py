"""Exercise authorization at the HTTP boundary before scan evidence is read."""
import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")

import pytest
from fastapi.testclient import TestClient
from app import main, scan_access


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "PUBLIC_JOBS", {})
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path)
    main.app.dependency_overrides[main.optional_user] = lambda: None
    main.app.dependency_overrides[main.get_db] = lambda: None
    browser = TestClient(main.app)
    yield browser
    browser.close()
    main.app.dependency_overrides.clear()


def owned_job():
    job = {"job_id": "a" * 32, "owner_user_id": 4, "status": "complete",
           "access_token_hash": "secret", "log_tail": "private registry output",
           "definition_context": {"password": "secret"}, "summary": {"images": 2}}
    main.PUBLIC_JOBS[job["job_id"]] = job
    return job


@pytest.mark.parametrize("suffix", ["", "/results", "/results/view", "/logs",
    "/overview.html", "/artifacts", "/sboms", "/export.xlsx", "/results-export"])
def test_every_evidence_endpoint_requires_job_access(client, suffix):
    job = owned_job()
    response = client.get(f"/api/public/jobs/{job['job_id']}{suffix}")
    assert response.status_code == 403
    assert "private registry output" not in response.text


@pytest.mark.parametrize("page", ["scan", "sbom"])
def test_browser_job_pages_require_access(client, page):
    job = owned_job()
    assert client.get(f"/{page}?job_id={job['job_id']}").status_code == 403


def test_cancel_requires_access(client):
    job = owned_job()
    assert client.post(f"/api/public/jobs/{job['job_id']}/cancel").status_code == 403
    assert main.PUBLIC_JOBS[job['job_id']]['status'] == 'complete'


def test_owner_status_and_results_project_only_safe_fields(client):
    job = owned_job()
    main.app.dependency_overrides[main.optional_user] = lambda: SimpleNamespace(
        user=SimpleNamespace(id=4), has=lambda permission, service: False)
    for suffix in ("", "/results"):
        response = client.get(f"/api/public/jobs/{job['job_id']}{suffix}")
        assert response.status_code == 200
        assert response.json()['summary']['images'] == 2
        assert not {'owner_user_id', 'access_token_hash', 'log_tail', 'definition_context'} & response.json().keys()


def test_anonymous_capability_works_in_header_and_cookie_but_is_job_specific(client, monkeypatch):
    monkeypatch.setenv('CATS_SCAN_ALLOW_ANONYMOUS', 'true')
    first = {'job_id': 'a' * 32, 'status': 'running'}
    token = scan_access.issue_access(first)
    main.PUBLIC_JOBS[first['job_id']] = first
    second = {'job_id': 'b' * 32, 'status': 'running'}
    scan_access.issue_access(second)
    main.PUBLIC_JOBS[second['job_id']] = second
    headers = {'X-Scan-Access-Token': token}
    assert client.get(f"/api/public/jobs/{first['job_id']}", headers=headers).status_code == 200
    assert client.get(f"/api/public/jobs/{second['job_id']}", headers=headers).status_code == 403
    client.cookies.set(scan_access.cookie_name(first['job_id']), token)
    assert client.get(f"/api/public/jobs/{first['job_id']}").status_code == 200


def test_anonymous_api_admission_is_disabled_by_default(client, monkeypatch):
    monkeypatch.delenv('CATS_SCAN_ALLOW_ANONYMOUS', raising=False)
    calls = []
    monkeypatch.setattr(main, '_start_public_scan', lambda *args, **kwargs: calls.append(kwargs))
    assert client.post('/api/public/jobs', json={'images': 'app:latest'}).status_code == 401
    assert calls == []


def test_opt_in_api_passes_capability_to_durable_job_and_returns_it_once(client, monkeypatch):
    monkeypatch.setenv('CATS_SCAN_ALLOW_ANONYMOUS', 'true')
    monkeypatch.setattr(main, 'get_global_configuration', lambda db: {})
    calls = []
    def start(*args, **kwargs):
        calls.append(kwargs)
        return 'a' * 32
    monkeypatch.setattr(main, '_start_public_scan', start)
    response = client.post('/api/public/jobs', json={'images': 'app:latest'})
    assert response.status_code == 200
    assert len(response.json()['access_token']) >= 32
    assert calls[0]['capability_token'] == response.json()['access_token']
    assert calls[0]['owner_user_id'] is None
