"""Managed Kind pin regression tests; no live Docker daemon or registry."""
import json
import subprocess
from types import SimpleNamespace
import pytest
from app.deployment_validation import ValidationConfig
from app.managed_validator_bootstrap import BootstrapError
from app.managed_validator_release import configured_node_pin
from app import validator_on_demand as demand, validator_release_recipe as recipe

PIN = "harbor.internal/kindest/node:v1.35.0@sha256:" + "c" * 64
IMAGE_ID = "sha256:" + "b" * 64

@pytest.mark.parametrize("override", [None, "", "  ", PIN])
def test_expected_pin_defaults_and_override(monkeypatch, override):
    monkeypatch.delenv("CATS_DEPLOYMENT_KIND_NODE_IMAGE", raising=False)
    if override is not None:
        monkeypatch.setenv("CATS_DEPLOYMENT_KIND_NODE_IMAGE", override)
    assert configured_node_pin() == (PIN if override == PIN else ValidationConfig.kind_node_image)

@pytest.mark.parametrize("pin", ["harbor.internal/node:latest", "sha256:" + "b" * 64,
                                  "node@sha256:abc", "node@sha256:" + "A" * 64])
def test_managed_pin_requires_repository_digest(monkeypatch, pin):
    monkeypatch.setenv("CATS_DEPLOYMENT_KIND_NODE_IMAGE", pin)
    with pytest.raises(BootstrapError, match="CATS_DEPLOYMENT_KIND_NODE_IMAGE.*immutable"):
        configured_node_pin()

@pytest.mark.parametrize("pin", [ValidationConfig.kind_node_image, PIN])
@pytest.mark.parametrize("cached", [False, True])
def test_digest_verified_for_default_and_custom_mirror(monkeypatch, pin, cached):
    source = "harbor.internal/mirror/node@" + pin.split("@")[1]
    monkeypatch.setenv("CATS_PROVISIONING_INTERNAL_REGISTRIES", "harbor.internal")
    calls = []
    def docker(*args):
        calls.append(args)
        if args == ("image", "inspect", pin) and not cached:
            raise BootstrapError("missing")
        return json.dumps([{"Id": IMAGE_ID, "Architecture": "amd64", "Os": "linux", "RepoDigests": [source]}])
    monkeypatch.setattr(demand, "docker", docker)
    assert demand.resolve_image(pin, source)["Id"] == IMAGE_ID
    assert (("pull", source) in calls) is (not cached)
    assert all(call != ("pull", pin) for call in calls)

def test_mismatched_mirror_rejected_before_cache_or_pull(monkeypatch):
    monkeypatch.setenv("CATS_PROVISIONING_INTERNAL_REGISTRIES", "harbor.internal")
    monkeypatch.setattr(demand, "docker", lambda *args: pytest.fail("must reject before Docker"))
    with pytest.raises(BootstrapError, match="CATS_DEPLOYMENT_KIND_NODE_IMAGE.*CATS_PROVISIONING_NODE_SOURCE"):
        demand.resolve_image(PIN, "harbor.internal/node@sha256:" + "d" * 64)

@pytest.mark.parametrize("source", ["public.example/node@sha256:" + "c" * 64,
                                    "docker.io/node@sha256:" + "c" * 64, "harbor.internal/node:latest"])
def test_custom_pin_cannot_bypass_approved_sources(monkeypatch, source):
    monkeypatch.setenv("CATS_PROVISIONING_INTERNAL_REGISTRIES", "harbor.internal,docker.io")
    monkeypatch.setattr(demand, "docker", lambda *args: pytest.fail("must reject before Docker"))
    with pytest.raises(BootstrapError, match="approved internal"):
        demand.resolve_image(PIN, source)

@pytest.mark.parametrize("cached", [False, True])
def test_wrong_inspected_digest_rejected_even_after_pull(monkeypatch, cached):
    monkeypatch.setenv("CATS_PROVISIONING_INTERNAL_REGISTRIES", "harbor.internal")
    pulled = []
    def docker(*args):
        if args[0] == "pull":
            pulled.append(args[1])
            return ""
        if not cached and not pulled:
            raise BootstrapError("missing")
        return json.dumps([{"Id": IMAGE_ID, "Architecture": "amd64", "Os": "linux",
                            "RepoDigests": ["harbor.internal/node@sha256:" + "d" * 64]}])
    monkeypatch.setattr(demand, "docker", docker)
    with pytest.raises(BootstrapError, match="matching immutable repository digest"):
        demand.resolve_image(PIN, PIN)

def test_tool_probes_use_exact_runtime_and_node(monkeypatch):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        assert command[command.index("--network") + 1] == "none" and kwargs["check"]
        return SimpleNamespace(stdout="kind v0.31.0 go1.25.5 linux/amd64" if command[-1] == "version" else "v1.35.0")
    monkeypatch.setattr(recipe, "run", run)
    assert recipe.validate_node_tools("sha256:" + "a" * 64, IMAGE_ID, PIN) == ("v0.31.0", "v1.35.0")
    assert calls[0][-2] == "sha256:" + "a" * 64
    assert calls[1][-5] == "kubeadm" and calls[1][-4] == IMAGE_ID

@pytest.mark.parametrize("output", ["not-kind secret", "kind v0.31.0 go1.25.5 linux/amd64"])
def test_unusable_node_tools_have_safe_actionable_error(monkeypatch, output):
    monkeypatch.setattr(recipe, "run", lambda *args, **kwargs: SimpleNamespace(stdout=output))
    with pytest.raises(BootstrapError, match="CATS_DEPLOYMENT_KIND_NODE_IMAGE") as caught:
        recipe.validate_node_tools("cats", IMAGE_ID, PIN)
    assert "secret" not in str(caught.value)

def test_probe_execution_failure_has_safe_actionable_error(monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["docker"], stderr="secret")
    monkeypatch.setattr(recipe, "run", fail)
    with pytest.raises(BootstrapError, match="bundled Kind/node tools") as caught:
        recipe.validate_node_tools("cats", IMAGE_ID, PIN)
    assert "secret" not in str(caught.value)

def test_version_tag_must_match_node(monkeypatch):
    outputs = iter(["kind v0.31.0 go1.25.5 linux/amd64", "v1.34.0"])
    monkeypatch.setattr(recipe, "run", lambda *args, **kwargs: SimpleNamespace(stdout=next(outputs)))
    with pytest.raises(BootstrapError, match="version tag.*kubeadm"):
        recipe.validate_node_tools("cats", IMAGE_ID, PIN)

def test_incompatible_isolated_entrypoint_is_actionable():
    with pytest.raises(BootstrapError, match="CATS_DEPLOYMENT_KIND_NODE_IMAGE"):
        recipe.patch_isolated_entrypoint("changed upstream entrypoint")
    anchor = "    docker_host_ip=$(ip -4 route show default | cut -d' ' -f3)"
    assert "ip -4 route add default dev eth0" in recipe.patch_isolated_entrypoint(anchor)
