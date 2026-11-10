"""Scanner failures identify their stage without disclosing input or cache paths."""
import errno
import json

import pytest

from app import rendering, scanner_actions as actions
from app.scanner_errors import scanner_failure_detail


SECRET = "SCANNER_STAGE_SECRET_CANARY_8f31"


@pytest.fixture(autouse=True)
def stub_packaged_intelligence_startup():
    # These action tests only need the standard-library scanner implementation.
    pass


@pytest.fixture
def inputs(tmp_path):
    sbom = tmp_path / "inventory.json"
    sbom.write_text('{"artifacts":[],"source":{"type":"directory"}}')
    database = tmp_path / ("database-" + SECRET)
    database.mkdir()
    (database / "vulnerability.db").write_bytes(b"retained database")
    return sbom, database


def assert_safe_failure(error, reason, stage, tmp_path):
    assert error.scanner_stage == stage
    detail = scanner_failure_detail(error)
    assert f"[{reason}]" in detail
    assert "Scanner stage: " in detail
    assert SECRET not in detail
    assert str(tmp_path) not in detail
    assert "Scanner stderr" not in detail


@pytest.mark.parametrize("failure_errno,reason", [
    (errno.ENOSPC, "disk_space_exhausted"),
    (errno.EACCES, "file_access_denied"),
])
def test_database_copy_failure_preserves_cause_before_native_execution(
        inputs, tmp_path, monkeypatch, failure_errno, reason):
    sbom, database = inputs
    copied = []
    monkeypatch.setattr(rendering, "PLATFORM", "linux")
    monkeypatch.setattr(rendering, "_effective_uid", lambda: 10002)
    monkeypatch.setattr(rendering, "_execute", lambda *args, **kwargs: pytest.fail("Scanner must not start"))

    def fail_copy(source, destination, **kwargs):
        copied.append(source)
        raise OSError(failure_errno, SECRET, str(source))

    # Exercise real copytree: its normal OSError aggregation loses errno.
    monkeypatch.setattr(rendering.shutil, "copy2", fail_copy)
    report = tmp_path / "report.json"
    with pytest.raises(rendering.RendererError) as caught:
        actions.scan_sbom(sbom, report, database=database)

    assert len(copied) == 1
    assert not report.exists()
    assert not report.with_suffix(".binding").exists()
    assert_safe_failure(caught.value, reason, "database_staging", tmp_path)


def test_malformed_provenance_is_classified_before_native_execution(inputs, tmp_path, monkeypatch):
    sbom, database = inputs
    sbom.with_suffix(".provenance").write_text('{"private":"' + SECRET)
    monkeypatch.setattr(actions, "offline_runner", lambda *args, **kwargs: pytest.fail("Scanner must not start"))

    with pytest.raises(rendering.RendererError) as caught:
        actions.scan_sbom(sbom, tmp_path / "report.json", database=database)

    assert_safe_failure(caught.value, "invalid_scanner_input", "input_validation", tmp_path)


def test_database_change_between_fixed_and_full_scans_discards_pair(inputs, tmp_path, monkeypatch):
    sbom, database = inputs
    fixed, full = tmp_path / "fixed.json", tmp_path / "full.json"
    outputs = (fixed, full, fixed.with_suffix(".binding"), full.with_suffix(".binding"))
    for output in outputs:
        output.write_text("stale evidence")
    calls = []

    def run(tool, args, cwd, **kwargs):
        calls.append("--only-fixed" in args)
        return {"stdout": json.dumps({"matches": []}), "version": "test-grype"}

    original_scan = actions.scan_sbom

    def change_between_passes(*args, **kwargs):
        report = original_scan(*args, **kwargs)
        if kwargs["only_fixed"]:
            (database / "vulnerability.db").write_bytes(b"replacement database")
        return report

    monkeypatch.setattr(actions, "offline_runner", run)
    monkeypatch.setattr(actions, "scan_sbom", change_between_passes)
    with pytest.raises(rendering.RendererError) as caught:
        actions.scan_sbom_evidence(sbom, fixed, full, database=database)

    assert calls == [True, False]
    assert not any(path.exists() for path in outputs)
    assert_safe_failure(caught.value, "scanner_database_changed", "evidence_validation", tmp_path)


def test_unexpected_evidence_error_reports_stage_without_exception_text(inputs, tmp_path, monkeypatch):
    sbom, database = inputs
    monkeypatch.setattr(actions, "offline_runner", lambda *args, **kwargs: {
        "stdout": '{"matches":[]}', "version": "test-grype"})

    def unexpected_validation_failure(*args, **kwargs):
        raise ValueError(f"Unexpected private evidence {SECRET} at {tmp_path}")

    monkeypatch.setattr(actions, "_json_output", unexpected_validation_failure)
    with pytest.raises(ValueError) as caught:
        actions.scan_sbom(sbom, tmp_path / "report.json", database=database)

    assert_safe_failure(caught.value, "scanner_failed", "evidence_validation", tmp_path)


def test_unknown_stage_label_is_not_published():
    error = ValueError(SECRET)
    error.scanner_stage = SECRET

    detail = scanner_failure_detail(error)

    assert "[scanner_failed]" in detail
    assert "Scanner stage:" not in detail
    assert SECRET not in detail
