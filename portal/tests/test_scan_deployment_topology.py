"""Validate both shipped deployment topologies without a Docker daemon."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENTS = (ROOT / "compose.yaml", ROOT / "templates/compose.main.yaml")


@pytest.fixture(params=DEPLOYMENTS, ids=("canonical", "main-template"))
def deployment(request):
    return yaml.safe_load(request.param.read_text(encoding="utf-8"))


def test_internal_control_listener_and_network_connectivity(deployment):
    services = deployment["services"]
    portal, control, worker = (services[name] for name in ("portal", "portal-control", "scan-worker"))
    assert deployment["networks"]["scan_control"]["internal"] is True
    assert "default" in portal["networks"]
    assert "scan_control" in portal["networks"]
    assert set(control["networks"]) == {"default", "scan_control"}
    assert set(worker["networks"]) == {"scan_control", "scan_egress"}
    assert "ports" not in control and "ports" not in worker
    assert "app.scan_control:app" in control["command"]
    assert control["command"][-1] == "8001"
    assert worker["environment"]["CATS_SCAN_PORTAL_URL"] == "http://portal-control:8001"
    assert worker["depends_on"]["portal-control"]["condition"] == "service_healthy"
    assert control["environment"] == portal["environment"]
    assert control["volumes"] == portal["volumes"]
    assert portal["ports"] == ["${CATS_PORT:-8080}:8000"]


def test_scanner_identity_and_disk_backed_temporary_storage(deployment):
    worker = deployment["services"]["scan-worker"]
    assert worker["user"] == "0:0"
    assert worker["cap_drop"] == ["ALL"]
    assert set(worker["cap_add"]) == {"SETUID", "SETGID", "CHOWN", "KILL"}
    assert worker["read_only"] is True
    assert worker["security_opt"] == ["no-new-privileges:true"]
    assert worker["environment"]["CATS_SCAN_SCANNER_UID"] == "10002"
    assert worker["environment"]["CATS_SCAN_SCANNER_GID"] == "10002"
    assert worker["environment"]["TMPDIR"] == "/var/lib/cats-scan/tmp"
    assert "scan_jobs:/var/lib/cats-scan" in worker["volumes"]
    assert not any("docker.sock" in str(volume) for volume in worker["volumes"])
    assert "DATABASE_URL" not in worker["environment"]
    auth = next(volume for volume in worker["volumes"] if isinstance(volume, dict))
    assert auth["target"] == "/run/cats-scan-control/registry-auth"
    assert worker["environment"]["DOCKER_CONFIG"] == auth["target"]
    assert auth["read_only"] is True
    assert auth["bind"]["create_host_path"] is False
    assert worker["healthcheck"]["test"][-1] == "--readiness"
    assert worker["restart"] == "unless-stopped"
    assert worker["environment"]["CATS_SCAN_CONCURRENCY"] == "${CATS_SCAN_CONCURRENCY:-2}"


def test_required_worker_settings_are_equivalent():
    documents = [yaml.safe_load(path.read_text(encoding="utf-8")) for path in DEPLOYMENTS]
    workers = [document["services"]["scan-worker"] for document in documents]
    for key in ("environment", "networks", "volumes", "healthcheck", "cap_add", "tmpfs"):
        assert workers[0][key] == workers[1][key], key


def test_environment_examples_match_worker_concurrency_default():
    for path in (ROOT / ".env.example", ROOT / "portal/.env.example", ROOT / "templates/main.env.example"):
        assert "CATS_SCAN_CONCURRENCY=2" in path.read_text(encoding="utf-8").splitlines()
