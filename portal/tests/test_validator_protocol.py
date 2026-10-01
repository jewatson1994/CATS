import ssl

import pytest
from fastapi.testclient import TestClient

from app.validator_protocol import SCHEMA_VERSION, validate_package
from app import validator_api


@pytest.fixture
def authenticated_app(monkeypatch, tmp_path):
    fingerprint = "a" * 64
    monkeypatch.setenv("CATS_VALIDATOR_CLIENT_FINGERPRINTS", fingerprint)
    monkeypatch.setattr(validator_api, "STATE_DIR", tmp_path)
    async def wrapper(scope, receive, send):
        if scope["type"] == "http":
            scope["validator_peer_sha256"] = fingerprint
        await validator_api.app(scope, receive, send)
    return wrapper


def package():
    return {"schema_version": SCHEMA_VERSION,
            "manifest": {"service_key": "test-service", "timeout_seconds": 600},
            "artifact": {"source_files": {"Chart.yaml": "name: test\nversion: 1.0.0\n"},
                         "values_files": [], "declared_resources": []}}


def test_versioned_package_rejects_unsafe_paths_and_schema():
    assert validate_package(package()) == package()
    invalid = package(); invalid["schema_version"] = "unknown"
    with pytest.raises(ValueError): validate_package(invalid)
    invalid = package(); invalid["artifact"]["source_files"] = {"../../private": "secret"}
    with pytest.raises(ValueError): validate_package(invalid)
    invalid = package(); invalid["artifact"]["source_files"] = {"C:\\private": "secret"}
    with pytest.raises(ValueError): validate_package(invalid)


def test_validator_api_requires_tls_and_rejects_invalid_package(authenticated_app):
    with TestClient(validator_api.app, base_url="http://testserver") as client:
        assert client.get("/health").status_code == 403
    with TestClient(authenticated_app, base_url="https://testserver") as client:
        assert client.post("/api/v1/validations", json={"schema_version": "unknown"}).status_code == 422
        assert client.get("/health").json()["schema_version"] == SCHEMA_VERSION


def test_server_launcher_requires_certificate_key_and_client_ca(monkeypatch):
    from validator_server import tls_configuration
    for name in ("CATS_VALIDATOR_SERVER_CERT", "CATS_VALIDATOR_SERVER_KEY", "CATS_VALIDATOR_CLIENT_CA"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError): tls_configuration()


@pytest.mark.parametrize(("engine_status", "api_status"), [
    ("VERIFIED", "VERIFIED"), ("PARTIALLY_VERIFIED", "FAILED"),
    ("COULD_NOT_VALIDATE", "ERROR")])
def test_async_result_classification_and_secret_suppression(tmp_path, monkeypatch, engine_status, api_status, authenticated_app):
    import time
    monkeypatch.setattr(validator_api, "STATE_DIR", tmp_path)
    validator_api.JOBS.clear()
    class FakeValidator:
        def __init__(self, config, runner=None):
            pass
        def validate_artifact(self, artifact, progress_callback=None):
            progress_callback("CLEANING_UP")
            return {"status": engine_status, "phase": "COMPLETE", "cleanup_status": "COMPLETE",
                    "reason_category": "TEST", "diagnostics": {"secret": "private-key-value"},
                    "resource_summary": {"ready": 1}}
    monkeypatch.setattr(validator_api, "KindDeploymentValidator", FakeValidator)
    with TestClient(authenticated_app, base_url="https://testserver") as client:
        submitted = client.post("/api/v1/validations", json=package())
        assert submitted.status_code == 202
        job_id = submitted.json()["validation_id"]
        for _ in range(100):
            response = client.get(f"/api/v1/validations/{job_id}")
            if response.json()["status"] == api_status:
                break
            time.sleep(0.01)
        assert response.json()["status"] == api_status
        assert response.json()["result"]["cleanup_status"] == "COMPLETE"
        assert "private-key-value" not in response.text
