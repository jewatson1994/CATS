import re

import pytest
from fastapi.testclient import TestClient
from app import validator_admin as admin
from app.validator_settings import read_settings, execution_settings, fingerprints


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CATS_VALIDATOR_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("CATS_VALIDATOR_ADMIN_PASSWORD", "long-test-password-123")
    monkeypatch.setenv("CATS_VALIDATOR_CLIENT_FINGERPRINTS", "a" * 64)
    admin.SESSIONS.clear()
    admin.ATTEMPTS.clear()
    with TestClient(admin.app, base_url="https://validator.test") as value:
        yield value


def login(client):
    response = client.post("/login", data={"username": "admin", "password": "long-test-password-123"})
    assert response.status_code == 200
    return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)


def test_local_login_password_is_hashed(client):
    assert "long-test-password-123" not in str(read_settings())
    login(client)
    assert "HttpOnly" in str(client.cookies) or client.cookies.get(admin.COOKIE)
    assert client.get("http://validator.test/").status_code == 403


def test_settings_require_authentication_and_csrf(client):
    assert client.post("/settings", data={"csrf": "invalid"}).status_code == 401
    login(client)
    assert client.post("/settings", data={"csrf": "invalid"}).status_code == 403


def test_live_mode_and_fingerprint_settings(client):
    csrf = login(client)
    response = client.post("/settings", data={"csrf": csrf, "execution_mode": "permissive", "client_fingerprints": "b" * 64, "allow_network_egress": "true", "require_local_images": "false"})
    assert response.status_code == 200
    assert execution_settings()["execution_mode"] == "permissive"
    assert fingerprints() == "b" * 64


def test_invalid_ca_is_rejected(client):
    csrf = login(client)
    response = client.post("/settings", data={"csrf": csrf, "execution_mode": "strict", "client_fingerprints": "a" * 64, "ca_bundle": "invalid", "allow_network_egress": "false", "require_local_images": "true"})
    assert response.status_code == 422


def test_readiness_requires_local_login(client, monkeypatch):
    from app import validator_api
    monkeypatch.setattr(validator_api, "health", lambda: {"ready": True})
    assert client.post("/readiness", data={"csrf": "invalid"}).status_code == 401
    csrf = login(client)
    response = client.post("/readiness", data={"csrf": csrf})
    assert response.status_code == 200
    assert 'true' in response.text


@pytest.mark.parametrize("mode", ["strict", "permissive"])
def test_worker_applies_saved_mode(client, monkeypatch, tmp_path, mode):
    from app import validator_api as api
    from app.validator_settings import write_settings
    settings = read_settings()
    settings.update(execution_mode=mode, allow_network_egress=True, require_local_images=False)
    write_settings(settings)
    monkeypatch.setattr(api, "STATE_DIR", tmp_path)
    class Engine:
        def __init__(self, config, runner):
            assert config.strict_sandbox_policy == (mode == "strict")
            assert config.permissive_workloads == (mode == "permissive")
            assert config.allow_network_egress == (mode == "permissive")
            assert config.require_local_images == (mode == "strict")
        def validate_artifact(self, artifact, progress_callback):
            return {"status": "VERIFIED", "cleanup_status": "COMPLETE"}
    monkeypatch.setattr(api, "KindDeploymentValidator", Engine)
    job = "9" * 32
    api.JOBS[job] = {"validation_id": job}
    try:
        api._execute(job, {"artifact": {"source_files": {}}, "manifest": {"timeout_seconds": 60}})
        assert api.JOBS[job]["status"] == "VERIFIED"
    finally:
        api.JOBS.pop(job, None)
