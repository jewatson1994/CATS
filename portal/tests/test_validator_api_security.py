import json
import base64
import hashlib
import sys

import pytest
from fastapi.testclient import TestClient

from app import validator_api as api


def modern_request(digest):
    return {"schema_version": "cats.validation/v2", "request_id": "1" * 32, "validation_type": "helm-chart",
            "service": {"id": "test-service", "version": "1"},
            "artifact": {"reference": "chart.zip", "digest": digest}, "deployment": {"type": "helm"}}


def test_modern_upload_integrity_and_owner(client_factory, monkeypatch):
    submitted = []
    monkeypatch.setattr(api.EXECUTOR, "submit", lambda *args: submitted.append(args))
    payload = b"retained exact artifact"
    declaration = modern_request("sha256:" + hashlib.sha256(payload).hexdigest())
    headers = {"content-type": "application/octet-stream",
               "x-cats-declaration": base64.urlsafe_b64encode(json.dumps(declaration).encode()).decode()}
    with client_factory("a" * 64) as client:
        response = client.post("/api/v2/validations", content=payload, headers=headers)
        assert response.status_code == 202
        job = response.json()["validation_id"]
        path = submitted[0][3]
        assert path.read_bytes() == payload
        assert api.JOBS[job]["request_identity"]["service"] == declaration["service"]
        assert client.post("/api/v2/validations", content=b"changed", headers=headers).status_code == 422
    with client_factory("b" * 64) as client:
        assert client.get(f"/api/v1/validations/{job}").status_code == 404
    path.unlink(missing_ok=True)


def test_modern_cancel_preserves_identity_and_cleans_upload(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "STATE_DIR", tmp_path)
    package = modern_request("sha256:" + "a" * 64)
    path = tmp_path / "upload.zip"
    path.write_bytes(b"artifact")
    job = "9" * 32
    api.JOBS[job] = {"validation_id": job, "cancel_requested": True}
    api._execute(job, package, path)
    result = api.JOBS[job]["result"]
    assert result["status"] == "CANCELLED"
    assert result["service"] == package["service"]
    assert result["artifact_digest"] == package["artifact"]["digest"]
    assert not path.exists()


@pytest.fixture
def client_factory(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "STATE_DIR", tmp_path)
    monkeypatch.setenv("CATS_VALIDATOR_CLIENT_FINGERPRINTS", "a" * 64 + "," + "b" * 64)
    api.JOBS.clear()
    api.RUNNING.clear()
    def make(identity):
        async def wrapper(scope, receive, send):
            if identity:
                scope["validator_peer_sha256"] = identity
            await api.app(scope, receive, send)
        return TestClient(wrapper, base_url="https://testserver")
    yield make
    api.JOBS.clear()


def test_headers_cannot_authenticate(client_factory):
    with client_factory(None) as client:
        assert client.get("/health", headers={"x-client-cert": "a" * 64}).status_code == 403
    with client_factory("c" * 64) as client:
        assert client.get("/health").status_code == 403


def test_job_owner_isolation(client_factory):
    job = "1" * 32
    api.JOBS[job] = {"validation_id": job, "client_identity": "a" * 64,
                     "status": "QUEUED", "cancel_requested": False}
    with client_factory("b" * 64) as client:
        assert client.get(f"/api/v1/validations/{job}").status_code == 404
        assert client.post(f"/api/v1/validations/{job}/cancel").status_code == 404
    assert not api.JOBS[job]["cancel_requested"]


def test_bounded_and_strict_upload(client_factory, monkeypatch):
    monkeypatch.setattr(api, "MAX_REQUEST_BYTES", 1024)
    with client_factory("a" * 64) as client:
        assert client.post("/api/v1/validations", content="x").status_code == 415
        assert client.post("/api/v1/validations", content=iter([b"x" * 600, b"x" * 600]),
                           headers={"content-type": "application/json"}).status_code == 413
        assert client.post("/api/v1/validations", content='{"x":1,"x":2}',
                           headers={"content-type": "application/json"}).status_code == 422


def test_output_and_command_deadline(monkeypatch):
    monkeypatch.setattr(api, "MAX_OUTPUT_BYTES", 4096)
    job = "2" * 32
    api.JOBS[job] = {}
    run = api._runner(job, ["PREFLIGHT"])
    result = run([sys.executable, "-c", "print('x'*100000)"], timeout=5)
    assert result.returncode == 125
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 4096
    result = run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)
    assert result.returncode == 124


def test_cancelled_queue_has_terminal_result(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "STATE_DIR", tmp_path)
    job = "3" * 32
    api.JOBS[job] = {"validation_id": job, "cancel_requested": True}
    api._execute(job, {})
    assert api.JOBS[job]["result"]["cleanup_status"] == "NOT_REQUIRED"
    assert api.JOBS[job]["result"]["status"] == "CANCELLED"


def test_restart_cleanup_is_strict_and_job_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "STATE_DIR", tmp_path)
    api.JOBS.clear()
    job = "4" * 32
    (tmp_path / f"{job}.json").write_text(json.dumps({"validation_id": job, "status": "RUNNING"}))
    workspace = tmp_path / "workspaces"
    owned = workspace / f"cats-deployment-{job}-abc"
    owned.mkdir(parents=True)
    unrelated = workspace / "unrelated"
    unrelated.mkdir()
    def cleanup(names, *, config):
        assert config.strict_sandbox_policy
        return {"failed": []}
    monkeypatch.setattr(api, "cleanup_stale_clusters", cleanup)
    api.recover()
    assert not owned.exists()
    assert unrelated.exists()
    assert api.JOBS[job]["result"]["cleanup_status"] == "COMPLETE"
