"""Validate both shipped deployment topologies without a Docker daemon."""
from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENTS = (ROOT / "templates/compose.local.yaml", ROOT / "templates/compose.main.yaml")


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
    public_only = {"CATS_DISCOVERY_GITLAB_SOURCES", "CATS_DISCOVERY_GITLAB_CA_FILE",
                   "CATS_PUBLIC_URL", "SESSION_COOKIE_SECURE"}
    assert {key: value for key, value in control["environment"].items() if key not in public_only} == {
        key: value for key, value in portal["environment"].items() if key not in public_only}
    if "nginx" in services:
        assert "ports" not in portal and "ports" not in services["oci-proxy"]
        assert services["nginx"]["ports"] == ["443:8443"]
        assert portal["environment"]["SESSION_COOKIE_SECURE"] == "true"
        assert control["volumes"] == [mount for mount in portal["volumes"]
                                      if not isinstance(mount, dict) or mount["target"] != "/app/certs"]
        # TLS private keys belong only to the backend that serves that hostname.
        for name, service in services.items():
            cert_mounts = [mount["target"] for mount in service.get("volumes", [])
                           if isinstance(mount, dict) and mount["target"] in ("/app/certs", "/app/oci-certs")]
            assert cert_mounts == {"portal": ["/app/certs"], "oci-proxy": ["/app/oci-certs"]}.get(name, [])
    else:
        assert control["volumes"] == portal["volumes"]
        assert portal["ports"] == ["${CATS_PORT:-8080}:8000"]


def test_scanner_identity_and_disk_backed_temporary_storage(deployment, request):
    worker = deployment["services"]["scan-worker"]
    assert worker["user"] == "0:0"
    assert worker["cap_drop"] == ["ALL"]
    assert set(worker["cap_add"]) == {"SETUID", "SETGID", "CHOWN", "KILL"}
    assert worker["read_only"] is True
    assert worker["security_opt"][0] == "no-new-privileges:true"
    assert len(worker["security_opt"]) == 2
    seccomp = worker["security_opt"][1].removeprefix("seccomp=")
    compose = request.node.callspec.params["deployment"]
    project_directory = ROOT if compose == DEPLOYMENTS[0] else compose.parent
    assert (project_directory / seccomp).resolve() == ROOT / "deploy/discovery-seccomp.json"
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
    assert "app.scan_worker --readiness &&" in worker["healthcheck"]["test"][-1]
    assert "app.rendering --probe" in worker["healthcheck"]["test"][-1]
    assert worker["restart"] == "unless-stopped"
    assert worker["environment"]["CATS_SCAN_CONCURRENCY"] == "${CATS_SCAN_CONCURRENCY:-2}"


def test_required_worker_settings_are_equivalent():
    documents = [yaml.safe_load(path.read_text(encoding="utf-8")) for path in DEPLOYMENTS]
    workers = [document["services"]["scan-worker"] for document in documents]
    # Local commands explicitly use the checkout as their project directory;
    # the HTTPS template resolves its default host paths from templates/.
    for compose, worker in zip(DEPLOYMENTS, workers):
        project_directory = ROOT if compose == DEPLOYMENTS[0] else compose.parent
        auth = next(mount for mount in worker["volumes"] if isinstance(mount, dict))
        match = re.fullmatch(r"\$\{CATS_SCAN_REGISTRY_AUTH_SOURCE:-([^}]+)\}", auth["source"])
        assert match
        auth["source"] = str((project_directory / match.group(1)).resolve())
    for key in ("environment", "networks", "volumes", "healthcheck", "cap_add", "tmpfs"):
        assert workers[0][key] == workers[1][key], key


def test_environment_examples_match_worker_concurrency_default():
    for path in (ROOT / "templates/local.env.example", ROOT / "portal/.env.example", ROOT / "templates/main.env.example"):
        assert "CATS_SCAN_CONCURRENCY=2" in path.read_text(encoding="utf-8").splitlines()
