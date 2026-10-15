"""Payload diagnostics identify the operation without leaking Docker output."""
import errno
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from app import validator_release_recipe as recipe
from app.managed_validator_bootstrap import BootstrapError


@pytest.mark.parametrize("error,reason", [
    (subprocess.CalledProcessError(17, ["docker", "secret"], output="secret", stderr="secret"), "exit code 17"),
    (subprocess.TimeoutExpired(["docker", "secret"], 1800, output="secret", stderr="secret"), "timed out"),
    (OSError(errno.ENOSPC, "secret"), "OS error 28"),
])
def test_operation_failure_is_safe_and_actionable(monkeypatch, error, reason):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(recipe.subprocess, "run", fail)
    with pytest.raises(BootstrapError) as caught:
        recipe.run(["docker", "build", "secret"], check=True,
                   failure_message="cannot build the isolated Kind node; check buildx")
    message = str(caught.value)
    assert "cannot build the isolated Kind node" in message
    assert reason in message
    assert "secret" not in message


def test_run_preserves_bounds_and_success(monkeypatch):
    def run(command, **kwargs):
        assert kwargs == {"check": True, "capture_output": True, "timeout": 1800}
        return SimpleNamespace(stdout="ok")
    monkeypatch.setattr(recipe.subprocess, "run", run)
    assert recipe.run(["docker", "tag"], check=True, failure_message="tag failed").stdout == "ok"


@pytest.mark.parametrize("output", ["secret", "null", "{}", "[]", "[null]", '[{"Id":"secret"}]'])
def test_invalid_inspection_reports_safe_error(monkeypatch, output):
    monkeypatch.setattr(recipe, "run", lambda *a, **kw: SimpleNamespace(stdout=output))
    with pytest.raises(BootstrapError, match="valid local image identity") as caught:
        recipe.inspect("local-image")
    assert "secret" not in str(caught.value)


def test_isolated_build_failure_names_the_step(monkeypatch):
    monkeypatch.setattr(recipe, "inspect", lambda ref: {"Id": "sha256:" + "a" * 64})
    directories = []
    def run(command, **kwargs):
        if command[1] == "build":
            directories.extend([Path(kwargs["env"]["BUILDX_CONFIG"]), Path(command[-1])])
            assert all(path.is_dir() for path in directories)
            raise subprocess.CalledProcessError(1, command, stderr="secret")
        return SimpleNamespace(stdout="    docker_host_ip=$(ip -4 route show default | cut -d' ' -f3)")
    monkeypatch.setattr(recipe.subprocess, "run", run)
    with pytest.raises(BootstrapError, match="cannot build the isolated Kind node") as caught:
        recipe.isolated_node_image("local-node")
    assert "secret" not in str(caught.value)
    assert directories and all(not path.exists() for path in directories)


def test_buildx_state_is_writable_separate_and_preserves_registry_auth(monkeypatch, tmp_path):
    auth = tmp_path / "registry-auth"
    auth.mkdir()
    credentials = auth / "config.json"
    credentials.write_text('{"auths": {}}')
    monkeypatch.setenv("DOCKER_CONFIG", str(auth))
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("BUILDX_CONFIG", str(auth / "buildx"))
    original_env = dict(os.environ)
    image_id = "sha256:" + "a" * 64
    monkeypatch.setattr(recipe, "inspect", lambda ref: {"Id": image_id})
    builds = []

    def run(command, **kwargs):
        if command[1] == "build":
            env = kwargs["env"]
            state, context = Path(env["BUILDX_CONFIG"]), Path(command[-1])
            assert state.is_dir() and not state.is_relative_to(context)
            assert state != auth / "buildx"
            assert {k: v for k, v in env.items() if k != "BUILDX_CONFIG"} == {
                k: v for k, v in original_env.items() if k != "BUILDX_CONFIG"
            }
            (state / "activity").write_text("builder state")
            Path(command[command.index("--iidfile") + 1]).write_text(image_id)
            builds.append((state, context))
        return SimpleNamespace(stdout="    docker_host_ip=$(ip -4 route show default | cut -d' ' -f3)")

    monkeypatch.setattr(recipe.subprocess, "run", run)
    for _ in range(2):
        tag, row = recipe.isolated_node_image("local-node")
        assert tag == "cats-kind-isolated:" + "a" * 64
        assert row["Id"] == image_id
    assert len(builds) == 2 and builds[0][0] != builds[1][0]
    assert all(not path.exists() for paths in builds for path in paths)
    assert list(auth.iterdir()) == [credentials]
    assert credentials.read_text() == '{"auths": {}}'
    assert dict(os.environ) == original_env
