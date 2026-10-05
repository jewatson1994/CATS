import importlib.util
from pathlib import Path
import pytest
from app.managed_validator_release import assert_selftest, selftest_request


def entrypoint():
    path = Path(__file__).resolve().parents[2] / "cats-image/cats-entrypoint.py"
    spec = importlib.util.spec_from_file_location("cats_entrypoint", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hq_refuses_host_socket():
    with pytest.raises(RuntimeError, match="HQ must not mount"):
        entrypoint().command({"CATS_ROLE": "hq"}, socket_present=True)
    assert "app.main:app" in entrypoint().command({}, socket_present=False)


def test_validator_only_server_and_tools(monkeypatch):
    module = entrypoint()
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/" + name)
    assert module.command({"CATS_ROLE": "validator"}, socket_present=True)[-1] == "/app/validator_server.py"
    with pytest.raises(RuntimeError, match="requires"):
        module.command({"CATS_ROLE": "validator"}, socket_present=False)
    monkeypatch.setattr(module.shutil, "which", lambda name: None if name == "kind" else name)
    with pytest.raises(RuntimeError, match="kind"):
        module.command({"CATS_ROLE": "validator"}, socket_present=True)


def test_selftest_is_v2_runtime_upload(tmp_path):
    release = {"_directory": str(tmp_path), "cats_image": {"image_id": "sha256:" + "a" * 64}, "selftest": {"file": "selftest.zip", "sha256": "sha256:" + "b" * 64}}
    request, path = selftest_request(release)
    assert request["validation_type"] == "helm-chart"
    assert request["schema_version"] == "cats.validation/v2"
    assert path == tmp_path / "selftest.zip"


@pytest.mark.parametrize("result", [{"ready": True}, {"status": "VERIFIED", "cleanup_status": "FAILED"}, {"status": "VERIFIED", "cleanup_status": "COMPLETE", "helm_result": {"install": "PASS", "release_status": "DEPLOYED", "execution_mode": "PREFLIGHTED_MANIFEST_APPLY"}}])
def test_health_or_partial_runtime_cannot_pass(result):
    with pytest.raises(ValueError, match="Self-test failed"):
        assert_selftest(result)


def test_actual_runtime_complete_passes():
    result = {"status": "VERIFIED", "cleanup_status": "COMPLETE", "helm_result": {"install": "PASS", "release_status": "DEPLOYED"}, "resource_summary": {"pods": {"expected": 1, "ready": 1}}}
    assert assert_selftest(result) == result


@pytest.mark.parametrize("pods", [{}, {"expected": 1, "ready": 0}, {"expected": 0, "ready": 0}])
def test_selftest_requires_observed_ready_workload(pods):
    with pytest.raises(ValueError):
        assert_selftest({"status": "VERIFIED", "cleanup_status": "COMPLETE", "helm_result": {"install": "PASS", "release_status": "DEPLOYED"}, "resource_summary": {"pods": pods}})


def test_compose_keeps_socket_out_of_hq_and_preserves_worker():
    import yaml
    root = Path(__file__).resolve().parents[2]
    for filename in ('compose.yaml', 'templates/compose.main.yaml'):
        services = yaml.safe_load((root / filename).read_text(encoding='utf-8-sig'))['services']
        assert not any('docker.sock' in str(volume) for volume in services['portal']['volumes'])
        assert any('docker.sock' in str(volume) for volume in services['patch-worker']['volumes'])
        assert services['patch-worker']['entrypoint'] == []
        assert services['patch-worker']['command'][1] == 'app.patch_service:app'

def test_selftest_diagnostics_do_not_expose_remote_errors():
    result = {"status": "ERROR", "cleanup_status": "FAILED", "error": "secret-password", "helm_result": {"install": "secret-password"}}
    with pytest.raises(ValueError) as caught:
        assert_selftest(result)
    message = str(caught.value)
    assert "Helm installation did not pass" in message
    assert "workload was not observed ready" in message
    assert "cleanup was not confirmed complete" in message
    assert "secret-password" not in message


def test_selftest_reports_known_failure_category():
    with pytest.raises(ValueError, match="Kind cluster creation failed"):
        assert_selftest({"status": "ERROR", "reason_category": "KIND_CREATION_FAILURE"})


def test_selftest_does_not_echo_unknown_category():
    with pytest.raises(ValueError) as caught:
        assert_selftest({"status": "ERROR", "reason_category": "secret-password"})
    assert "secret-password" not in str(caught.value)
