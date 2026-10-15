import json
from pathlib import Path

import pytest

from app.scan_registry_auth import RegistryConfigurationError, load_registry_credentials
from test_scan_worker_coordination import worker_harness


def test_absent_credentials_allow_anonymous_pulls(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    assert load_registry_credentials() == {}


def test_valid_credentials_are_preserved_without_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    credentials = {"auths": {"harbor.example": {"auth": "private-value"}}}
    (tmp_path / "config.json").write_text(json.dumps(credentials), encoding="utf-8")
    assert load_registry_credentials() == credentials
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("content", [b'{private-value', b'[]', b'{"auths": "private-value"}', b'\xff'])
def test_invalid_configuration_has_safe_error(tmp_path, monkeypatch, content):
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    (tmp_path / "config.json").write_bytes(content)
    with pytest.raises(RegistryConfigurationError) as error:
        load_registry_credentials()
    assert "config.json" in str(error.value)
    assert "private-value" not in str(error.value)


def test_unreadable_credentials_explain_host_permissions(monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("private-value")
    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(RegistryConfigurationError) as error:
        load_registry_credentials()
    assert "CATS_SCAN_REGISTRY_AUTH_SOURCE" in str(error.value)
    assert "700" in str(error.value) and "600" in str(error.value)
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize("valid", [True, False])
def test_preflight_checks_access_without_starting_worker(tmp_path, monkeypatch, capsys, valid):
    from app import scan_worker
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    (tmp_path / "config.json").write_text('{}' if valid else 'private-value', encoding="utf-8")
    monkeypatch.setattr(scan_worker.sys, "argv", ["scan_worker", "--check-registry-auth"])
    def unexpected():
        pytest.fail("Preflight must not initialize or start the worker")
    monkeypatch.setattr(scan_worker, "initialize", unexpected)
    assert scan_worker.main() == (0 if valid else 1)
    output = capsys.readouterr()
    assert "private-value" not in output.out + output.err
    assert ("passed" in output.out) if valid else ("config.json" in output.err)


def test_service_scan_reports_preparation_error_before_scanner(worker_harness, monkeypatch):
    scan_worker, worker, job, _, calls, uploaded, processes, _, _ = worker_harness
    job["job"]["credential_policy"] = "service"
    def denied():
        raise RegistryConfigurationError("Registry credentials are unreadable; check host permissions.")
    monkeypatch.setattr(scan_worker, "load_registry_credentials", denied)
    with pytest.raises(RegistryConfigurationError):
        worker.execute(job)
    assert not processes and not uploaded
    failures = [kwargs["json"] for _, suffix, kwargs in calls if suffix.endswith("/failure")]
    assert len(failures) == 1
    assert failures[0]["category"] == "registry_authorization"
    assert "check host permissions" in failures[0]["reason"]
    assert "Scan preparation failed" in failures[0]["log_tail"]


def test_public_scan_does_not_read_service_credentials(worker_harness, monkeypatch):
    scan_worker, worker, job, _, _, uploaded, processes, _, _ = worker_harness
    def unexpected():
        pytest.fail("Public scans must not read service credentials")
    monkeypatch.setattr(scan_worker, "load_registry_credentials", unexpected)
    worker.execute(job)
    assert processes and uploaded
