"""Security contract shared by the shipped worker deployment topologies."""
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKERS = ("discovery-worker", "scan-worker", "patch-worker", "remediation-worker")


@pytest.mark.parametrize("path", ["compose.yaml", "templates/compose.main.yaml"])
def test_every_action_worker_has_setup_policy_and_runtime_probe(path):
    services = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))["services"]
    for name in WORKERS:
        service = services[name]
        assert service["security_opt"] == [
            "no-new-privileges:true", "seccomp=./deploy/discovery-seccomp.json"]
        assert not service.get("privileged", False)
        assert "SYS_ADMIN" not in service.get("cap_add", [])
        probe = " ".join(service["healthcheck"]["test"])
        assert "app.rendering" in probe and "--probe" in probe
        assert service["healthcheck"]["timeout"] == "15s"
    discovery = services["discovery-worker"]
    assert discovery["user"] == "10003:10003"
    assert discovery["cap_drop"] == ["ALL"]
    assert discovery["read_only"] is True
    assert not any("docker.sock" in str(mount) for mount in discovery["volumes"])
    for name in ("scan-worker", "patch-worker"):
        assert "security_grype_db:/opt/catscan/grype-db:ro" in services[name]["volumes"]
        assert "security_trivy_db:/opt/catscan/trivy-cache:ro" in services[name]["volumes"]
    # The common background-worker anchor must not grant native-tool setup or
    # advertise renderer health for unrelated services.
    for name in ("security-data-worker", "risk-worker", "export-worker", "provisioning-worker"):
        assert "seccomp=./deploy/discovery-seccomp.json" not in services[name].get("security_opt", [])
        assert "app.rendering" not in " ".join(services[name].get("healthcheck", {}).get("test", []))
    for service in services.values():
        for mount in service.get("tmpfs", []):
            if str(mount).startswith("/tmp:"):
                assert "mode=1777" in mount


def test_apparmor_overlay_is_scoped_and_preserves_seccomp():
    overlay = yaml.safe_load((ROOT / "deploy/compose.worker-apparmor.yaml").read_text())
    assert set(overlay["services"]) == set(WORKERS)
    for service in overlay["services"].values():
        # A single appended item preserves base options without duplicate keys.
        assert service == {"security_opt": ["apparmor=cats-worker-actions"]}
    profile = (ROOT / "deploy/cats-worker-actions.apparmor").read_text()
    assert "profile cats-worker-actions" in profile
    assert "unconfined" not in profile.replace("peer=unconfined", "")
    assert "deny /{,oldroot/}proc/sys/** wklx," in profile
    assert "deny /{,oldroot/}sys/** wklx," in profile
    # Bubblewrap setup needs propagation and mounts only under its temporary root.
    assert "mount options=(rw,rslave,silent) -> /," in profile
    assert "\n  mount," not in profile


def test_standalone_scanner_builds_shared_actions_from_root_context():
    scanner = yaml.safe_load((ROOT / "cats-scanner/compose.yaml").read_text())["services"]["catscan"]
    assert scanner["build"]["context"] == ".."
    assert scanner["build"]["dockerfile"] == "cats-scanner/Dockerfile"
    assert "seccomp=../deploy/discovery-seccomp.json" in scanner["security_opt"]
    dockerfile = (ROOT / "cats-scanner/Dockerfile").read_text()
    assert "portal/app/rendering.py portal/app/scan_runtime.py" in dockerfile
    assert "portal/app/scanner_actions.py portal/app/scanner_inputs.py /app/app/" in dockerfile
    assert "COPY scanning-main/scripts /opt/cats/scanning/scripts" in dockerfile
    assert "ENV PYTHONPATH=/app CATS_SCANNING_ROOT=/opt/cats/scanning" in dockerfile
    assert "verify-worker-tools.py" in dockerfile
    assert "ARG SYFT_VERSION=1.31.0" in dockerfile
    assert "ARG GRYPE_VERSION=0.98.0" in dockerfile
    ignore = (ROOT / "cats-scanner/Dockerfile.dockerignore").read_text().splitlines()
    assert "**" in ignore
    assert "!portal/app/rendering.py" in ignore
