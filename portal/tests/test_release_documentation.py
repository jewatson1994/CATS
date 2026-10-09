"""Release documentation caching, immutable downloads and publication receipts."""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from app import release_documentation as documentation
from app import release_oci
from app.deployment_bundle import file_digest
from app.models import PortalSetting, Service
from app.purpose_exports import default_template
from test_release_exports import source  # Shared isolated database and exact source scan.


UNSIGNED = ({"signing_enabled": False}, {})


@pytest.fixture
def candidate(source, tmp_path):
    db, record = source
    root = tmp_path / "candidates"
    directory = root / record.job_key
    directory.mkdir(parents=True)
    path = directory / "candidate.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("source/Chart.yaml", "apiVersion: v2\nname: sample\nversion: 1.0\n")
        archive.writestr("source/templates/deployment.yaml", "kind: Deployment\nmetadata:\n  name: sample\n")
    record.service = db.get(Service, record.service_id)
    record.artifact_path = str(path)
    record.artifact_digest = "sha256:" + sha256(path.read_bytes()).hexdigest()
    record.verification_status = "verified"
    record.workflow_inputs = {}
    artifacts = [{"kind": "chart", "reference": "registry.example/sample@sha256:" + "a" * 64,
                  "digest": "sha256:" + "a" * 64, "identity_type": "oci_manifest"}]
    auth = SimpleNamespace(has=lambda permission, service_id: permission == "service.export")
    return db, record, auth, root, artifacts


def _prepare(candidate, *, mode="oci", artifacts=None, signing=UNSIGNED):
    db, record, auth, root, original_artifacts = candidate
    return documentation.prepare(db, record, auth, root,
        original_artifacts if artifacts is None else artifacts, mode, signing)


def test_prepare_real_archive_binds_candidate_documentation_and_source(candidate):
    _, record, _, root, artifacts = candidate
    files, receipt = _prepare(candidate)
    assert receipt["status"] == "ready"
    assert receipt["signing"]["status"] == "unsigned"
    assert set(files) == {"documentation.zip", "release-manifest.json", "VERIFY.txt"}
    manifest = json.loads(files["release-manifest.json"].read_bytes())
    assert manifest == receipt["manifest"]
    assert manifest["documentation"]["digest"] == file_digest(files["documentation.zip"])
    assert manifest["snapshot"]["source_execution_id"] == record.source_execution_id
    assert manifest["snapshot"]["source_version_id"] == record.source_version_id
    assert manifest["snapshot"]["remediation"]["candidate_digest"] == record.artifact_digest
    assert manifest["artifacts"] == artifacts
    with ZipFile(files["documentation.zip"]) as archive:
        raw = json.loads(archive.read("raw-scan-evidence.json"))
        assert raw["findings"][0]["cve"] == "CVE-OLD"
        assert "helm_source_files" not in raw
    assert documentation.retained_files(record, root, receipt) == files
    assert {name: file_digest(path) for name, path in files.items()} == receipt["files"]


def test_unchanged_preparation_reuses_exact_bytes_without_regeneration(candidate, monkeypatch):
    files, receipt = _prepare(candidate)
    original = {name: (path.read_bytes(), path.stat().st_mtime_ns) for name, path in files.items()}
    def unexpected_generation(*args, **kwargs):
        pytest.fail("Cached documentation must not regenerate")
    monkeypatch.setattr(documentation, "write_documentation", unexpected_generation)
    monkeypatch.setattr(documentation, "sign_release_manifest", unexpected_generation)
    again, next_receipt = _prepare(candidate)
    assert next_receipt == receipt and again == files
    assert {name: (path.read_bytes(), path.stat().st_mtime_ns) for name, path in again.items()} == original


def test_delivery_mode_or_artifact_change_revises_manifest_and_reuses_snapshot(candidate):
    original_files, original = _prepare(candidate)
    bundle_files, bundle = _prepare(candidate, mode="offline-bundle")
    replacement = [{"kind": "chart", "reference": "registry.example/sample@sha256:" + "b" * 64,
                    "digest": "sha256:" + "b" * 64, "identity_type": "oci_manifest"}]
    revised_files, revised = _prepare(candidate, artifacts=replacement)
    assert len({original["revision"], bundle["revision"], revised["revision"]}) == 3
    assert original_files["documentation.zip"] == bundle_files["documentation.zip"] == revised_files["documentation.zip"]
    assert original_files["release-manifest.json"].read_bytes() == documentation.canonical(original["manifest"])
    assert revised["manifest"]["artifacts"] == replacement


def test_template_or_candidate_validation_change_creates_new_snapshot(candidate):
    db, record, _, _, _ = candidate
    original_files, original = _prepare(candidate)
    columns = default_template("ppsm")
    columns[0]["heading"] = "New configured heading"
    db.add(PortalSetting(key="purpose_export_template:ppsm", value=json.dumps(columns)))
    db.flush()
    template_files, template_receipt = _prepare(candidate)
    record.validation_results = {"deployment": {"run_key": "replacement-validation", "status": "FAILED"}}
    validation_files, validation_receipt = _prepare(candidate)
    assert len({original_files["documentation.zip"], template_files["documentation.zip"],
                validation_files["documentation.zip"]}) == 3
    assert original["sha256"] != template_receipt["sha256"]
    assert validation_receipt["manifest"]["snapshot"]["remediation"]["validation"]["status"] == "FAILED"


@pytest.mark.parametrize("name", ["documentation.zip", "release-manifest.json", "VERIFY.txt"])
def test_altered_retained_files_are_rejected_for_download(candidate, name):
    _, record, _, root, _ = candidate
    files, receipt = _prepare(candidate)
    files[name].write_bytes(files[name].read_bytes() + b" altered")
    with pytest.raises(ValueError, match="integrity mismatch"):
        documentation.retained_files(record, root, receipt)
    if name != "VERIFY.txt":
        with pytest.raises(ValueError, match="integrity mismatch|manifest mismatch"):
            _prepare(candidate)


@pytest.mark.parametrize("storage_key", ["../outside", "/absolute/path", "a" * 64 + "/../" + "b" * 64])
def test_download_rejects_unsafe_storage_identity(candidate, storage_key):
    _, record, _, root, _ = candidate
    with pytest.raises(ValueError, match="Invalid retained release identity"):
        documentation.retained_files(record, root, {"storage_key": storage_key})


def test_missing_export_permission_fails_before_creating_documentation(candidate):
    db, record, _, root, artifacts = candidate
    with pytest.raises(PermissionError, match="Service export"):
        documentation.prepare(db, record, SimpleNamespace(has=lambda *args: False), root,
                              artifacts, "oci", UNSIGNED)
    assert not (root / record.job_key / "release-documentation").exists()


def test_tampered_candidate_is_rejected_before_generation(candidate):
    _, record, _, root, _ = candidate
    from pathlib import Path
    Path(record.artifact_path).write_bytes(b"changed candidate")
    with pytest.raises(ValueError, match="candidate integrity mismatch"):
        _prepare(candidate)
    assert not (root / record.job_key / "release-documentation").exists()


@pytest.mark.parametrize("artifacts", [[], [{"kind": "chart", "digest": "mutable-tag"}]])
def test_manifest_requires_immutable_deployable_identities(candidate, artifacts):
    with pytest.raises(ValueError, match="immutable SHA-256|deployable artifact identities"):
        _prepare(candidate, artifacts=artifacts)


@pytest.mark.parametrize("result,message", [
    ({"status": "verification_failed"}, "signature verification failed"),
    ({"status": "unsigned"}, "Mandatory release signing did not complete"),
])
def test_required_signing_fails_closed(candidate, monkeypatch, result, message):
    monkeypatch.setattr(documentation, "sign_release_manifest", lambda *args: result)
    with pytest.raises(ValueError, match=message):
        _prepare(candidate, signing=({"signing_enabled": True, "signing_fingerprint": "test-key"}, {}))


def test_cached_signed_release_is_verified_on_reuse(candidate, monkeypatch):
    signing = ({"signing_enabled": True, "signing_fingerprint": "test-key"}, {})
    def sign(manifest, directory, material):
        (directory / "release-manifest.sig").write_bytes(b"fake signature for mock verification")
        (directory / "release-public-key.pem").write_bytes(b"fake public key for mock verification")
        return {"status": "signed", "key_fingerprint": "test-key"}
    monkeypatch.setattr(documentation, "sign_release_manifest", sign)
    files, receipt = _prepare(candidate, signing=signing)
    assert {"release-manifest.sig", "release-public-key.pem"} <= files.keys()
    calls = []
    def verify(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "verified"}
    monkeypatch.setattr(documentation, "verify_release_manifest", verify)
    assert _prepare(candidate, signing=signing)[1] == receipt
    assert len(calls) == 1 and calls[0][1]["expected_fingerprint"] == "test-key"
    monkeypatch.setattr(documentation, "verify_release_manifest", lambda *args, **kwargs: {"status": "verification_failed"})
    with pytest.raises(ValueError, match="Retained release signature verification failed"):
        _prepare(candidate, signing=signing)


def test_publication_checkpoints_partial_results_and_retry_replaces_each_subject(candidate, monkeypatch):
    _, _, _, _, artifacts = candidate
    second = {"kind": "image", "reference": "registry.example/second@sha256:" + "c" * 64,
              "digest": "sha256:" + "c" * 64, "identity_type": "oci_manifest"}
    files, receipt = _prepare(candidate, artifacts=[*artifacts, second])
    environments, calls, checkpoints = [], [], []
    @contextmanager
    def environment(destination):
        environments.append(destination)
        yield {"DOCKER_CONFIG": "ephemeral-test-config"}
    monkeypatch.setattr(documentation, "registry_environment", environment)
    def partial(files_arg, subject, env):
        assert files_arg == files
        assert env == {"DOCKER_CONFIG": "ephemeral-test-config"}
        calls.append(subject)
        return {"subject": subject, "status": "published" if subject == artifacts[0]["reference"] else "verification_failed"}
    monkeypatch.setattr(release_oci, "publish_documentation", partial)
    def checkpoint(value):
        checkpoints.append(deepcopy(value))
    with pytest.raises(ValueError, match="publication or retrieval verification failed"):
        documentation.publish(files, receipt, {"name": "test destination"}, checkpoint)
    assert calls == [artifacts[0]["reference"], second["reference"]]
    assert [item["status"] for item in checkpoints] == ["publishing", "failed"]
    failed = checkpoints[-1]
    assert failed["publications"][0]["status"] == "published"
    assert failed["publications"][1]["status"] == "verification_failed"
    assert receipt["publications"] == []  # No mutation of caller's retained input.
    monkeypatch.setattr(release_oci, "publish_documentation", lambda files, subject, env:
                        {"subject": subject, "status": "published"})
    result = documentation.publish(files, failed, {"name": "test destination"}, checkpoint)
    assert result["status"] == "published"
    assert len(result["publications"]) == 2
    assert {item["subject"] for item in result["publications"]} == set(calls)
    assert all(item["status"] == "published" for item in result["publications"])
    assert checkpoints[-1]["status"] == "published"
    assert len(environments) == 2


def test_publication_requires_oci_subject(candidate, monkeypatch):
    artifacts = [{"kind": "source", "digest": "sha256:" + "d" * 64, "identity_type": "file"}]
    files, receipt = _prepare(candidate, artifacts=artifacts)
    monkeypatch.setattr(documentation, "registry_environment", lambda *args: pytest.fail("Registry must not be contacted"))
    with pytest.raises(ValueError, match="No immutable OCI subject"):
        documentation.publish(files, receipt, {}, lambda *args: pytest.fail("No publication checkpoint expected"))


def test_changed_remediation_summary_and_validation_rows_revise_snapshot(candidate):
    from app.models import DeploymentValidationRun
    db, record, _, _, _ = candidate
    original_files, original = _prepare(candidate)
    original_bytes = original_files["documentation.zip"].read_bytes()
    record.validation_results = {**record.validation_results,
        "summary_of_changes": {"charts": [{"path": "sample", "original_version": "1", "remediated_version": "2"}]}}
    _, changed = _prepare(candidate)
    assert changed["storage_key"] != original["storage_key"]
    run = DeploymentValidationRun(run_key="source-validation", service_id=record.service_id,
        execution_id=record.source_execution_id, status="RUNNING")
    db.add(run); db.flush()
    _, running = _prepare(candidate)
    run.status = "PASSED"; db.flush()
    passed_files, passed = _prepare(candidate)
    assert len({changed["storage_key"], running["storage_key"], passed["storage_key"]}) == 3
    assert original_files["documentation.zip"].read_bytes() == original_bytes
    with ZipFile(passed_files["documentation.zip"]) as archive:
        assert json.loads(archive.read("candidate-validation.json"))[0]["status"] == "PASSED"


def test_failed_receipt_publication_leaves_no_partial_json(tmp_path, monkeypatch):
    target = tmp_path / "snapshot.json"
    replace = documentation.os.replace
    def fail_replace(*args):
        raise OSError("simulated interrupted receipt publication")
    monkeypatch.setattr(documentation.os, "replace", fail_replace)
    with pytest.raises(OSError):
        documentation._write(target, {"digest": "test"})
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []
    monkeypatch.setattr(documentation.os, "replace", replace)
    documentation._write(target, {"digest": "test"})
    assert json.loads(target.read_bytes()) == {"digest": "test"}
