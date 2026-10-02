import hashlib
from types import SimpleNamespace
from zipfile import ZipFile
import pytest
from app import remediation_verification as verification

DIGEST = "sha256:" + "a" * 64
IMAGE = "registry/team/api@" + DIGEST


def candidate(tmp_path):
    folder = tmp_path / "r1"
    folder.mkdir()
    artifact = folder / "delivery-1.zip"
    with ZipFile(artifact, "w") as bundle:
        bundle.writestr("candidate/api/Chart.yaml", "name: api\nversion: 1.0.0\n")
        bundle.writestr("candidate/api/templates/pod.yaml", "kind: Pod\nmetadata: {name: api}\nspec:\n  containers:\n  - name: api\n    image: " + IMAGE)
        bundle.writestr("candidate/api/charts/dependency/Chart.yaml", "name: dependency\nversion: 1.0.0\n")
    result = {"artifact_path": str(artifact), "materialized_digest": "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "artifact_identities": [{"kind": "image", "reference": IMAGE, "digest": DIGEST, "identity_type": "oci_manifest"}]}
    return SimpleNamespace(job_key="r1", service=SimpleNamespace(service_key="test-service")), result


@pytest.mark.parametrize("mutable", [False, True])
def test_remote_verification_receives_complete_assembled_candidate(tmp_path, monkeypatch, mutable):
    record, result = candidate(tmp_path)
    calls, packages = [], []
    monkeypatch.setattr(verification.shutil, "which", lambda name: name)
    def render(args, **kwargs):
        calls.append(args)
        assert args[1] == "template"
        image = "registry/api:mutable" if mutable else IMAGE
        return SimpleNamespace(returncode=0, stdout="kind: Pod\nmetadata: {name: api}\nspec:\n  containers:\n  - name: api\n    image: " + image)
    monkeypatch.setattr(verification.subprocess, "run", render)
    def remote(_config, package):
        packages.append(package)
        return {"status": "VERIFIED", "diagnostics": "secret must not escape"}
    monkeypatch.setattr(verification, "run_remote", remote)
    observed = verification.verify_delivery(record, result, {"endpoint": "https://sandbox.example"}, tmp_path)
    assert len(calls) == 1  # Dependencies render as part of the root chart.
    assert observed["artifact_digest"] == result["materialized_digest"]
    if mutable:
        assert observed["status"] == "not_verified"
        assert not packages
    else:
        assert observed["status"] == "verified"
        assert packages[0]["artifact"]["reference"] == result["materialized_digest"]
        assert len(packages[0]["artifact"]["source_files"]) == 3
        assert packages[0]["manifest"]["referenced_images"] == [IMAGE]
        assert packages[0]["artifact"]["declared_resources"][0]["kind"] == "Pod"
        assert "secret" not in str(observed)


def test_unavailable_sandbox_is_optional(tmp_path):
    record, result = candidate(tmp_path)
    assert verification.verify_delivery(record, result, {}, tmp_path)["status"] == "verification_unavailable"


def test_verification_uses_ordered_retained_values(tmp_path, monkeypatch):
    from pathlib import Path
    record, result = candidate(tmp_path)
    overrides = ["overrides/base.yaml", "overrides/service.yaml"]
    with ZipFile(result["artifact_path"], "a") as bundle:
        for index, name in enumerate(overrides):
            bundle.writestr("candidate/" + name, f"replicas: {index + 2}\n")
    result["materialized_digest"] = "sha256:" + hashlib.sha256(Path(result["artifact_path"]).read_bytes()).hexdigest()
    result["values_files"] = overrides
    monkeypatch.setattr(verification.shutil, "which", lambda name: name)
    def render(args, **kwargs):
        paths = [args[index + 1] for index, value in enumerate(args) if value == "--values"]
        assert [Path(path).name for path in paths] == ["base.yaml", "service.yaml"]
        assert all(Path(path).is_file() for path in paths)
        return SimpleNamespace(returncode=0, stdout="kind: Pod\nspec:\n  containers:\n  - image: " + IMAGE)
    monkeypatch.setattr(verification.subprocess, "run", render)
    def remote(_config, package):
        assert package["artifact"]["values_files"] == overrides
        return {"status": "VERIFIED"}
    monkeypatch.setattr(verification, "run_remote", remote)
    assert verification.verify_delivery(record, result, {"endpoint": "https://sandbox.example"}, tmp_path)["status"] == "verified"


def test_verification_rejects_values_path_escape(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    result["values_files"] = ["../secret.yaml"]
    monkeypatch.setattr(verification, "run_remote", lambda *a: pytest.fail("must not submit"))
    assert verification.verify_delivery(record, result, {"endpoint": "https://sandbox.example"}, tmp_path)["status"] == "not_verified"


def test_digest_mismatch_never_submits_candidate(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    result["materialized_digest"] = DIGEST
    monkeypatch.setattr(verification, "run_remote", lambda *a: pytest.fail("must not submit"))
    assert verification.verify_delivery(record, result, {"endpoint": "https://sandbox.example"}, tmp_path)["status"] == "not_verified"


def test_remote_exception_is_sanitized(tmp_path, monkeypatch):
    record, result = candidate(tmp_path)
    monkeypatch.setattr(verification.shutil, "which", lambda name: name)
    monkeypatch.setattr(verification.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0,
        stdout="kind: Pod\nmetadata: {name: api}\nspec:\n  containers:\n  - image: " + IMAGE))
    def remote(*args):
        raise ValueError("secret-key")
    monkeypatch.setattr(verification, "run_remote", remote)
    observed = verification.verify_delivery(record, result, {"endpoint": "https://sandbox.example"}, tmp_path)
    assert observed["status"] == "not_verified"
    assert "secret-key" not in str(observed)
