"""Worker credentials and privileged filesystem processing boundaries."""
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from datetime import datetime, timedelta, timezone

from app import scan_artifacts, scan_runtime, scan_worker
from test_scan_worker_coordination import worker_harness


def test_scanner_environment_cannot_bypass_scoped_registry_auth():
    secret_keys = ["DOCKER_AUTH_CONFIG", "REGISTRY_AUTH_FILE", "GOOGLE_APPLICATION_CREDENTIALS",
                   "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "HELM_REPOSITORY_CONFIG"]
    source = {key: "unscoped credentials" for key in secret_keys}
    source["PATH"] = "scanner tools"
    assert scan_runtime.sanitized_environment(source) == {"PATH": "scanner tools"}


@pytest.mark.parametrize("line", ['{"access_token":"secret-value"}',
                                  '{"password": "secret-value"}',
                                  'registry replied Bearer secret-value'])
def test_worker_logs_redact_quoted_and_standalone_credentials(line):
    assert "secret-value" not in scan_worker.redact(line)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_control_transport_never_forwards_attempt_credentials(monkeypatch, status):
    monkeypatch.setenv("CATS_SCAN_WORKER_TOKEN", "a" * 40)
    worker = scan_worker.Worker()
    response = Mock(status_code=status)
    worker.session.request = Mock(return_value=response)
    with pytest.raises(requests.HTTPError, match="redirects are forbidden"):
        worker.request("PUT", "/job/attempt/results", headers={"X-Attempt-Token": "private"},
                       data=b"private evidence", allow_redirects=True)
    assert worker.session.request.call_args.kwargs["allow_redirects"] is False
    response.close.assert_called_once()
    worker.session.close()


@pytest.mark.parametrize("uid", ["0", "-1", "4294967295"])
def test_scanner_cannot_receive_privileged_or_invalid_uid(monkeypatch, uid):
    monkeypatch.setattr(scan_worker, "os", SimpleNamespace(
        name="posix", geteuid=lambda: 0, getenv=lambda key, default=None: uid))
    worker = object.__new__(scan_worker.Worker)
    worker._execute = Mock()
    with pytest.raises(ValueError, match="unprivileged positive UID"):
        worker.execute({})
    worker._execute.assert_not_called()


def test_nonroot_broker_cannot_silently_share_identity(monkeypatch):
    monkeypatch.setattr(scan_worker, "os", SimpleNamespace(name="posix", geteuid=lambda: 10001))
    worker = object.__new__(scan_worker.Worker)
    worker._execute = Mock()
    with pytest.raises(ValueError, match="isolate scanner identities"):
        worker.execute({})
    worker._execute.assert_not_called()


def test_running_scanner_checks_lease_expiry_between_heartbeats(worker_harness, monkeypatch):
    _, worker, job, _, _, uploaded, processes, _, request = worker_harness

    def short_lease(method, suffix, **kwargs):
        if suffix.endswith("/heartbeat"):
            return SimpleNamespace(json=lambda: {"lease_until": (
                datetime.now(timezone.utc) + timedelta(seconds=0.2)).isoformat()})
        return request(method, suffix, **kwargs)

    monkeypatch.setattr(worker, "request", short_lease)
    with pytest.raises(RuntimeError, match="lease lost"):
        worker.execute(job)
    assert processes and processes[0].poll() is not None
    assert not uploaded


def test_packing_rejects_hardlinked_files_before_reading(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    private = tmp_path / "private"
    private.write_text("private content")
    os.link(private, source / "report.json")
    with pytest.raises(ValueError, match="hard links"):
        scan_artifacts.pack(source, tmp_path / "evidence.tar", {})
    assert not (tmp_path / "evidence.tar").exists()


def test_reclaim_unlinks_hardlinks_without_changing_external_ownership(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    private = tmp_path / "private"
    private.write_text("private content")
    link = source / "report.json"
    os.link(private, link)
    chown = Mock()
    monkeypatch.setattr(scan_runtime, "os", SimpleNamespace(
        name="posix", geteuid=lambda: 0, chown=chown, walk=os.walk))
    with pytest.raises(ValueError, match="hard links"):
        scan_runtime.reclaim(source, reject_links=True)
    assert not link.exists()
    assert private.read_text() == "private content"
    assert all(call.args[0] != link for call in chown.call_args_list)


def test_worker_rejects_scanner_hardlinks_before_provenance_write(worker_harness, tmp_path, monkeypatch):
    module, worker, job, _, calls, uploaded, _, _, _ = worker_harness
    private = tmp_path / "private.json"
    private.write_text("private content")

    def scanner(command, **kwargs):
        output = Path(command[-1])
        os.link(private, output / "worker-provenance.json")
        return SimpleNamespace(poll=lambda: 0, returncode=0, pid=987654321)

    monkeypatch.setattr(module.subprocess, "Popen", scanner)
    with pytest.raises(ValueError, match="hard links"):
        worker.execute(job)
    assert private.read_text() == "private content"
    assert not uploaded
    assert any(suffix.endswith("/failure") for _, suffix, _ in calls)


def test_worker_pins_custom_sources_without_exposing_broker_configuration(worker_harness, monkeypatch):
    module, worker, job, _, _, _, _, _, _ = worker_harness
    monkeypatch.setenv("CATS_SCAN_GRYPE_SOURCE", "custom-grype")
    monkeypatch.setenv("CATS_SCAN_TRIVY_SOURCE", "custom-trivy")
    snapshots = []

    def pin(environment, directory):
        snapshots.append(dict(environment))
        return {}

    def scanner(command, **kwargs):
        snapshots.append(dict(kwargs["env"]))
        return SimpleNamespace(poll=lambda: 0, returncode=0, pid=987654321)

    monkeypatch.setattr(module, "pin_databases", pin)
    monkeypatch.setattr(module.subprocess, "Popen", scanner)
    worker.execute(job)
    assert snapshots[0]["CATS_SCAN_GRYPE_SOURCE"] == "custom-grype"
    assert snapshots[0]["CATS_SCAN_TRIVY_SOURCE"] == "custom-trivy"
    assert not any(key.startswith("CATS_SCAN_") for key in snapshots[1])
