from copy import deepcopy
import hashlib
import io
import json
import tarfile
from types import SimpleNamespace
import uuid
from zipfile import ZipFile

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import main
from remediation_job_helpers import completed_plan
from app.candidate_worker import validate_request
from app.models import RemediationExecution
from app.remediation import candidate_files
from app.remediation_delivery import retained_candidate
from app.remediation_safety import (SourceSafetyError, approved_payload, assert_chart_archive_safe,
                                    assert_sources_safe, protect_plan, source_diagnostics)
from test_remediation_workflow_routes import workflow


@pytest.mark.parametrize("name,content", [
    ("credentials.json", "{}"), ("secrets/README.md", "Instructions for secret references"),
    (".env", "PORT=8080\nTOKEN=${EXTERNAL_TOKEN}\n"),
    ("values.yaml", 'password: ""\ntoken: null\nclientSecret: replace-me\napiKey: false\n'),
    ("values.yaml", 'token: {valueFrom: {secretKeyRef: {name: auth, key: token}}}\n'),
    ("secret.yaml", 'kind: Secret\nstringData:\n  token: {{ .Values.token | default "" | quote }}\n'),
    ("secret.yaml", 'kind: Secret\nstringData:\n  token: "${TOKEN}"\n  password: <password>\n'),
    ("secret.yaml", 'kind: Secret\nstringData:\n  token: |\n    {{ .Values.token | quote }}\n'),
])
def test_content_not_filenames_decides_safety(name, content):
    assert_sources_safe({name: content})


@pytest.mark.parametrize("content,reason", [
    ('kind: Secret\ndata: {auth: c2Vuc2l0aXZl}\n', "literal_secret_data"),
    ('kind: Secret\nstringData:\n  arbitrary: |\n    sensitive-content\n', "literal_secret_data"),
    ('kind: Secret\nstringData:\n  token: {{ .Values.token | default "sensitive-content" }}\n', "literal_secret_data"),
    ('kind: Secret\nstringData:\n  token: |\n    {{ "sensitive-content" }}\n', "literal_secret_data"),
    ('token: sensitive-content\n', "literal_credential"),
    ('db_password: sensitive-content\n', "literal_credential"),
    ('password: {value: sensitive-content}\n', "literal_secret_data"),
    ('token: [sensitive-content]\n', "literal_secret_data"),
    ('kind: Secret\nstringData:\n  auth: {{ printf "sensitive-content%s" .Values.foo }}\n', "literal_secret_data"),
    ('kind: Secret\nstringData:\n  auth: {{ printf `sensitive-content%s` .Values.foo }}\n', "literal_secret_data"),
    ('kind: Secret\nstringData:\n  auth: {{ coalesce "" "sensitive-content" .Values.foo }}\n', "literal_secret_data"),
    ('-----BEGIN RSA PRIVATE KEY-----\nsensitive-content\n', "private_key"),
])
def test_structured_diagnostics_never_include_values(content, reason):
    rows = source_diagnostics({"app/Chart.yaml": "name: app\nversion: 1.0.0\n", "app/values.yaml": content})
    assert any(row["reason"] == reason for row in rows)
    assert rows[0]["chart"] == "app" and rows[0]["file"] == "app/values.yaml"
    assert rows[0]["path"] and rows[0]["resolution"]
    assert "sensitive-content" not in json.dumps(rows) and "c2Vuc2l0aXZl" not in json.dumps(rows)


def multi_chart():
    return {"good/Chart.yaml": "name: good\nversion: 1.0.0\n", "good/values.yaml": "replicas: 1\n",
            "bad/Chart.yaml": "name: bad\nversion: 1.0.0\n", "bad/values.yaml": "password: sensitive-content\n"}


def test_excludes_whole_chart_only_after_explicit_choice_and_preserves_evidence():
    files = multi_chart()
    payload = {"helm_source_files": files}
    original = deepcopy(payload)
    plan = {"configuration_changes": [{"source_mapping": {"values_file": "bad/values.yaml"}, "original_value": "sensitive-content"},
                                      {"source_mapping": {"values_file": "good/values.yaml"}, "editable": True}],
            "images": [{"original": "app:1", "source_mapping": {"values_file": "bad/values.yaml"}}]}
    protect_plan(plan, files)
    assert plan["configuration_changes"][0]["editable"] is False
    assert plan["configuration_changes"][1]["editable"] is True
    assert plan["images"][0]["source_mapping"] == {"ambiguous": True}
    with pytest.raises(ValueError, match="Explicitly confirm"):
        approved_payload(payload, plan["source_safety"], [])
    candidate = approved_payload(payload, plan["source_safety"], ["bad"])
    assert set(candidate["helm_source_files"]) == {"good/Chart.yaml", "good/values.yaml"}
    assert payload == original


def test_nested_dependency_requires_excluding_parent():
    files = {"app/Chart.yaml": "name: app", "app/charts/dependency/Chart.yaml": "name: dependency",
             "app/charts/dependency/values.yaml": "token: sensitive-content"}
    assert protect_plan({}, files)["source_safety"]["blocked_charts"] == ["app"]


def test_plan_endpoint_and_confirm_allow_independent_patch_work(workflow, monkeypatch):
    db, service, execution, auth, _, _ = workflow
    execution.raw_payload = {**execution.raw_payload, "helm_source_files": multi_chart(),
        "findings": [{"image": "registry.example/app:1", "cve": "CVE-test"}]}
    db.commit()
    original = deepcopy(execution.raw_payload)
    preview = completed_plan(service.service_key, db=db, auth=auth)
    assert preview["source_safety"]["blocked_charts"] == ["bad"]
    assert "sensitive-content" not in json.dumps(preview)
    args = dict(csrf_token="token", remediation_mode="automated", decisions="{}", plan_digest=preview["plan_digest"],
                source_execution_id=execution.id, confirmed="yes", submission_key=str(uuid.uuid4()), db=db, auth=auth)
    with pytest.raises(HTTPException) as error:
        main.start_remediation(service.service_key, **args)
    assert error.value.status_code == 422 and error.value.detail["code"] == "source_review_required"
    main.start_remediation(service.service_key, excluded_charts='["bad"]', **args)
    record = db.scalar(select(RemediationExecution))
    reached = []
    def patches(_db, _record, _service, plan):
        reached.extend(plan["_source_files"])
        assert plan["images"][0]["original"] == "registry.example/app:1"
        raise RuntimeError("Stop after independent patch entry")
    monkeypatch.setattr(main, "_run_remediation_image_patches", patches)
    monkeypatch.setattr(main, "_cleanup_completed_remediations", lambda _db: None)
    main._run_remediation_job(record.id)
    assert set(reached) == {"good/Chart.yaml", "good/values.yaml"}
    db.expire_all()
    assert execution.raw_payload == original
    assert record.workflow_inputs["approved_plan"]["source_safety"]["partial"] is True


def test_candidate_worker_and_download_share_protection(tmp_path):
    files = {"values.yaml": "password: sensitive-content"}
    with pytest.raises(SourceSafetyError):
        candidate_files({"source_files": files}, {})
    with pytest.raises(SourceSafetyError):
        validate_request({"files": files})
    directory = tmp_path / "r1"
    directory.mkdir()
    path = directory / "candidate.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("candidate/values.yaml", files["values.yaml"])
    record = SimpleNamespace(job_key="r1", artifact_path=str(path), artifact_digest="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest())
    with pytest.raises(SourceSafetyError):
        retained_candidate(record, tmp_path)


def test_packaged_oci_chart_is_inspected():
    buffer = io.BytesIO()
    content = b"kind: Secret\nstringData: {password: sensitive-content}\n"
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        entry = tarfile.TarInfo("app/templates/config.yaml")
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))
    with pytest.raises(SourceSafetyError):
        assert_chart_archive_safe(buffer.getvalue())


def test_final_delivery_chart_and_external_values_are_inspected(tmp_path):
    from app.remediation_safety import assert_candidate_safe
    for name in ("app/values.yaml", "overrides.yaml", "rendered.yaml"):
        path = tmp_path / "delivery.zip"
        with ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"deployment": {"chartPath": "app", "valuesFiles": ["overrides.yaml"]}}))
            archive.writestr(name, "password: sensitive-content")
        with pytest.raises(SourceSafetyError):
            assert_candidate_safe(path)


def test_invalid_candidate_archive_returns_sanitized_safety_failure(tmp_path):
    from app.remediation_safety import assert_candidate_safe
    path = tmp_path / "candidate.zip"
    path.write_bytes(b"not-a-zip-sensitive-content")
    with pytest.raises(SourceSafetyError) as error:
        assert_candidate_safe(path)
    assert "sensitive-content" not in str(error.value)
    assert error.value.diagnostics[0]["reason"] == "unsupported_source_archive"


def test_large_scan_evidence_does_not_exhaust_source_inspection_budget(tmp_path, monkeypatch):
    from app import remediation_safety as safety
    monkeypatch.setattr(safety, "MAX_CANDIDATE_SOURCE_BYTES", 128)
    path = tmp_path / "candidate.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("documentation/scan/grype-full-before.json", "x" * 256)
        archive.writestr("documentation/sbom.json", "x" * 256)
        archive.writestr("candidate/values.yaml", "replicas: 1")
    safety.assert_candidate_safe(path)
    # Oversized evidence must never bypass the source secret check.
    with ZipFile(path, "a") as archive:
        archive.writestr("candidate/secrets.yaml", "password: sensitive-content")
    with pytest.raises(SourceSafetyError):
        safety.assert_candidate_safe(path)


def test_candidate_source_still_has_a_bounded_inspection_budget(tmp_path, monkeypatch):
    from app import remediation_safety as safety
    monkeypatch.setattr(safety, "MAX_CANDIDATE_SOURCE_BYTES", 128)
    path = tmp_path / "candidate.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("candidate/values.yaml", "#" * 129)
    with pytest.raises(SourceSafetyError) as error:
        safety.assert_candidate_safe(path)
    assert error.value.diagnostics[0]["reason"] == "source_inspection_limit"


@pytest.mark.parametrize("manifest,content", [([], b"safe"), ({"deployment": []}, b"safe"),
    ({"deployment": {"valuesFiles": 42}}, b"safe"), ({}, b"\xffsensitive-content")])
def test_uninspectable_candidate_returns_sanitized_safety_failure(tmp_path, manifest, content):
    from app.remediation_safety import assert_candidate_safe
    path = tmp_path / "candidate.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("candidate/values.yaml", content)
    with pytest.raises(SourceSafetyError) as error:
        assert_candidate_safe(path)
    assert error.value.diagnostics[0]["reason"] == "unsupported_source_archive"
    assert "sensitive-content" not in str(error.value)
