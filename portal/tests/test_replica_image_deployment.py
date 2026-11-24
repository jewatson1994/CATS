"""Resolve real Compose settings so image migration cannot start the wrong role."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ("templates/compose.replica.external-ingress.yaml", "templates/compose.replica.yaml")


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
    assert services["portal"]["environment"]["CATS_IMAGE"] == expected
    expected_services = {"portal", "oci-proxy", "db", "polling-worker", "replica-audit-reporter", "component-log-collector"}
    if compose_file == "templates/compose.replica.yaml":
        expected_services.add("nginx")
    assert set(services) == expected_services
    assert services["replica-audit-reporter"]["image"] == expected
    assert services["component-log-collector"]["image"] == expected
    worker = services["polling-worker"]
    assert worker["image"] == expected
    assert worker["entrypoint"] == [] and worker["command"] == ["python", "-m", "app.polling_worker"]
    assert worker["environment"]["CATS_MODE"] == "replica"
    assert not worker.get("ports")
    assert {(v["type"], v.get("source"), v["target"]) for v in worker["volumes"]} == {
        ("volume", "replica_evidence", "/var/lib/cats"), ("volume", None, "/var/cache/cats-polling")
    }
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


@pytest.mark.parametrize("variants", [("main",), ("local",), ("local", "local-nginx"),
                                      ("replica",), ("replica.external-ingress",)])
def test_shipped_services_send_component_logs_only_to_their_own_local_socket(variants, tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Requires Docker Compose CLI")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CATS_", "COMPOSE_", "POSTGRES_"))}
    environment.update(CATS_IMAGE="cats:qualification", CATS_PORTAL_HOSTNAME="portal.test", CATS_OCI_HOSTNAME="oci.test",
        POSTGRES_PASSWORD="compose-test", CATS_BOOTSTRAP_PASSWORD="compose-test", CATS_CONFIG_ENCRYPTION_KEY="compose-test",
        CATS_PATCH_WORKER_TOKEN="compose-test", CATS_SCAN_WORKER_TOKEN="compose-test", PIPELINE_API_TOKEN="compose-test",
        CATS_COMPONENT_LOG_SOCKET_DIR="/run/cats-test-socket", CATS_AUDIT_HQ_TOKEN="dedicated-hq-token")
    env_file = tmp_path / "compose.env"
    env_file.write_text("", encoding="utf-8")
    args = ["docker", "compose", "--env-file", str(env_file), "--project-name", "test-forwarding"]
    for name in variants:
        args.extend(["--file", str(ROOT / "templates" / f"compose.{name}.yaml")])
    result = subprocess.run(args + ["config", "--format", "json", "--no-path-resolution"],
                            env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    for name, service in services.items():
        if name == "component-log-collector":
            assert service["image"] == "cats:qualification"
            assert service["logging"]["driver"] == "local"
            assert not service.get("ports")
            mount = next(m for m in service["volumes"] if m["target"] == "/run/cats-log-input")
            assert mount["source"].replace("\\", "/").endswith("/run/cats-test-socket")
        else:
            assert service["logging"]["driver"] == "fluentd", name
            options = service["logging"]["options"]
            assert options["fluentd-address"] == "unix:///run/cats-test-socket/ingest.sock"
            assert options["fluentd-async"] == options["fluentd-request-ack"] == "true"
            assert options["tag"] == "cats.compose"
            assert "com.docker.compose.service" in options["labels"]
        if name != "replica-audit-reporter":
            assert "CATS_AUDIT_HQ_TOKEN" not in service.get("environment", {})
