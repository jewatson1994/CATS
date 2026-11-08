"""Resolve real Compose settings so image migration cannot start the wrong role."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ("compose.replica.yaml", "templates/compose.replica.yaml")


def resolve_compose(tmp_path, compose_file, image_settings):
    docker = shutil.which("docker")
    if not docker:
        pytest.skip("Docker CLI is required for Compose interpolation; no daemon is used")
    values = {
        "POSTGRES_PASSWORD": "compose-test-only",
        "CATS_BOOTSTRAP_PASSWORD": "compose-test-only",
        "CATS_CONFIG_ENCRYPTION_KEY": "compose-test-only",
        "CATS_PORTAL_HOSTNAME": "portal.example.test",
        "CATS_OCI_HOSTNAME": "oci.example.test",
        # Replica Compose must enforce its role even if a reused .env says full.
        "CATS_MODE": "full",
        **image_settings,
    }
    env_file = tmp_path / "replica.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CATS_", "COMPOSE_", "POSTGRES_"))}
    return subprocess.run(
        [docker, "compose", "--env-file", str(env_file), "-f", str(ROOT / compose_file),
         "config", "--format", "json", "--no-path-resolution"],
        env=environment, capture_output=True, text=True, timeout=30,
    )


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
@pytest.mark.parametrize("settings,expected", [
    ({"CATS_IMAGE": "cats:shared"}, "cats:shared"),
    ({"CATS_REPLICA_IMAGE": "cats:existing"}, "cats:existing"),
    ({"CATS_IMAGE": "cats:shared", "CATS_REPLICA_IMAGE": "cats:existing"}, "cats:shared"),
    ({"CATS_IMAGE": "", "CATS_REPLICA_IMAGE": "cats:existing"}, "cats:existing"),
])
def test_shared_image_and_legacy_settings_keep_replica_isolated(tmp_path, compose_file, settings, expected):
    result = resolve_compose(tmp_path, compose_file, settings)
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    assert set(services) == ({"portal", "oci-proxy", "db", "nginx"}
                             if compose_file.startswith("templates/") else {"portal", "oci-proxy", "db"})
    for name, module in (("portal", "app.main:app"), ("oci-proxy", "app.oci_proxy:app")):
        service = services[name]
        assert service["image"] == expected
        assert "build" not in service
        # The unified image entrypoint launches full roles, so explicitly bypass it.
        assert service["entrypoint"] == []
        assert service["command"][:2] == ["uvicorn", module]
        assert "--no-proxy-headers" in service["command"]
        assert service["environment"]["CATS_MODE"] == "replica"
        assert service["environment"]["CATS_DEPLOYMENT_VALIDATION_ENABLED"] == "false"
        assert not any("docker.sock" in str(volume) for volume in service.get("volumes", []))
        assert not service.get("privileged", False)


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_missing_shared_image_fails_before_starting(tmp_path, compose_file):
    result = resolve_compose(tmp_path, compose_file, {})
    assert result.returncode != 0
    assert "Set CATS_IMAGE" in result.stderr
