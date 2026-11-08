"""Single-image qualification and disposable replica smoke deployment contracts."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stack = load("single_image_nginx_stack", ROOT / "portal/tests/nginx_acceptance_stack.py")
smoke = load("replica_image_smoke", ROOT / "scripts/verify-replica-image.py")


def test_acceptance_defaults_to_one_image_and_one_build(tmp_path):
    # A replica Dockerfile is deliberately absent: the supported path uses only
    # the full image, including when callers choose a different full-image tag.
    (tmp_path / "cats-image").mkdir()
    (tmp_path / "cats-image/Dockerfile.all-in-one").touch()
    (tmp_path / "compose.yaml").touch()
    _, args = stack.parse_args(["--repo", str(tmp_path), "--workspace", str(tmp_path / "workspace"),
                               "--full-image", "cats:qualification", "--provision", "--build"])
    calls = []
    stack.prepare_images(SimpleNamespace(run=lambda *args: calls.append(args)), args)
    assert args.replica_image == "cats:qualification"
    assert [label for label, _ in calls] == ["build-full", "inspect-full"]
    assert calls[0][1][-3:] == ["--tag", "cats:qualification", str(tmp_path)]


def test_explicit_replica_override_is_inspected_but_never_built(tmp_path):
    calls = []
    args = SimpleNamespace(build=True, repo=tmp_path, scanner_base="scanner:test",
                           full_image="cats:full", replica_image="cats:comparison")
    stack.prepare_images(SimpleNamespace(run=lambda *args: calls.append(args)), args)
    assert [label for label, _ in calls] == ["build-full", "inspect-full", "inspect-replica"]
    assert calls[-1][1] == ["image", "inspect", "cats:comparison"]


@pytest.fixture
def resolved_compose():
    services = {"db": {"image": "postgres:16", "volumes": [
        {"type": "volume", "source": "replica_db", "target": "/var/lib/postgresql/data"}]}}
    for name, (application, port) in smoke.APPLICATIONS.items():
        services[name] = {
            "image": "cats:test", "entrypoint": [],
            "command": ["uvicorn", application, "--host", "0.0.0.0", "--port", str(port), "--no-proxy-headers"],
            "environment": {"CATS_MODE": "replica", "CATS_DEPLOYMENT_VALIDATION_ENABLED": "false"},
            "ports": [{"target": port, "published": str(port)}],
            "networks": {"default": None}, "restart": "unless-stopped",
            "volumes": [{"type": "volume", "source": "replica_evidence", "target": "/var/lib/cats"}],
        }
    return {"services": services, "volumes": {"replica_db": {"name": "real-site-db"},
                                               "replica_evidence": {"name": "real-site-evidence"}},
            "networks": {"default": {"name": "real-site-network"}}}


def test_smoke_preserves_real_startup_and_isolates_all_resources(resolved_compose):
    original = copy.deepcopy(resolved_compose)
    actual = smoke.isolated_config(resolved_compose, image="cats:test", project="test-project")
    assert resolved_compose == original
    for name in smoke.APPLICATIONS:
        assert actual["services"][name]["command"] == original["services"][name]["command"]
    assert all("ports" not in service for service in actual["services"].values())
    assert actual["networks"] == {"default": {"name": "test-project_default", "internal": True}}
    assert actual["volumes"]["replica_db"] == {"name": "test-project_replica_db"}
    assert actual["volumes"]["replica_evidence"] == {"name": "test-project_replica_evidence"}


@pytest.mark.parametrize("field,value", [
    ("image", "cats-replica:other"),
    ("entrypoint", None),
    ("command", ["python", "-m", "app.scan_worker"]),
    ("environment", {"CATS_MODE": "full", "CATS_DEPLOYMENT_VALIDATION_ENABLED": "false"}),
    ("privileged", True),
    ("volumes", [{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}]),
])
def test_smoke_rejects_wrong_mode_commands_images_and_host_access(resolved_compose, field, value):
    resolved_compose["services"]["portal"][field] = value
    with pytest.raises(ValueError):
        smoke.isolated_config(resolved_compose, image="cats:test", project="test-project")


def test_failed_startup_still_removes_disposable_project(monkeypatch, resolved_compose, capsys):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "config" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps(resolved_compose), "")
        return subprocess.CompletedProcess(command, 1 if "up" in command else 0, "", "startup failed" if "up" in command else "")

    monkeypatch.setattr(smoke.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="startup failed"):
        smoke.run_smoke("cats:test", ROOT, 1)
    assert calls[-1][-3:] == ["down", "--volumes", "--remove-orphans"]
    assert calls[-1][calls[-1].index("--project-name") + 1].startswith("cats-replica-smoke-")
    capsys.readouterr()
