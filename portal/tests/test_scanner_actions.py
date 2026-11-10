"""Behavior and isolation contracts for shared Scan/Patch scanner actions."""
import importlib.util
import json
from pathlib import Path

import pytest

from app import scanner_actions as actions
from app.patch_worker import retained_scan_evidence


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    database = tmp_path / "database"
    database.mkdir()
    (database / "vulnerability.db").write_bytes(b"retained database")
    sbom = tmp_path / "inventory.json"
    sbom.write_text('{"artifacts":[],"source":{"type":"directory"}}')
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(database))
    return sbom, database


def test_scan_cli_and_patch_action_consume_identical_frozen_inventory_and_policy(inputs, tmp_path, monkeypatch):
    sbom, database = inputs
    calls = []
    original = sbom.read_bytes()
    for key in ("CATS_PATCH_SOURCE_PASSWORD", "DATABASE_URL", "AWS_SECRET_ACCESS_KEY", "DOCKER_CONFIG"):
        monkeypatch.setenv(key, "never-visible-to-tool")
    def run(tool, arguments, cwd, **options):
        calls.append((tool, arguments, options))
        assert (cwd / "inventory.json").read_bytes() == original
        assert cwd != sbom.parent
        assert (cwd / "scanner.yaml").read_text() == "{}\n"
        assert list(options["writable"]) == [database]
        assert "never-visible-to-tool" not in json.dumps(options["environment"])
        assert options["environment"]["GRYPE_DB_AUTO_UPDATE"] == "false"
        return {"stdout": '{"matches":[]}', "version": "test-grype"}
    monkeypatch.setattr(actions, "offline_runner", run)
    actions.scan_sbom(sbom, tmp_path / "patch.json")
    script = Path(__file__).parents[2] / "scanning-main/scripts/scan-sbom.py"
    spec = importlib.util.spec_from_file_location("scan_cli", script)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    assert cli.scan(sbom, tmp_path / "scan.json") == 0
    assert calls[0] == calls[1]
    assert "--only-fixed" not in calls[2][1]
    assert (tmp_path / "patch.binding").read_bytes() == (tmp_path / "scan.binding").read_bytes()
    assert json.loads((tmp_path / "full/scan.binding").read_bytes())["only_fixed"] is False


def test_binding_uses_consumed_bytes_and_rejects_database_drift(inputs, tmp_path, monkeypatch):
    sbom, database = inputs
    original = sbom.read_bytes()
    report = tmp_path / "report.json"
    def run(tool, arguments, cwd, **options):
        assert (cwd / "inventory.json").read_bytes() == original
        sbom.write_bytes(original + b"\n")
        return {"stdout": '{"matches":[]}', "version": "test"}
    monkeypatch.setattr(actions, "offline_runner", run)
    actions.scan_sbom(sbom, report)
    assert json.loads(report.with_suffix(".binding").read_text())["sbom_digest"] == actions.digest(original)
    def corrupt(*args, **kwargs):
        (database / "vulnerability.db").write_bytes(b"changed")
        return {"stdout": '{"matches":[]}', "version": "test"}
    monkeypatch.setattr(actions, "offline_runner", corrupt)
    with pytest.raises(actions.RendererError, match="database changed") as failure:
        actions.scan_sbom(sbom, report)
    assert failure.value.reason == "scanner_database_changed"
    assert not report.exists() and not report.with_suffix(".binding").exists()


@pytest.mark.parametrize("configured,expected", [(None, "true"), ("true", "true"), ("false", "false")])
def test_database_age_policy_preserves_explicit_offline_release_setting(inputs, tmp_path, monkeypatch, configured, expected):
    sbom, database = inputs
    environment = {"GRYPE_DB_CACHE_DIR": str(database), "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "240h"}
    if configured is not None:
        environment["GRYPE_DB_VALIDATE_AGE"] = configured
    def run(tool, args, cwd, **options):
        assert options["environment"]["GRYPE_DB_VALIDATE_AGE"] == expected
        assert options["environment"]["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] == "240h"
        assert options["environment"]["GRYPE_DB_VALIDATE_BY_HASH_ON_START"] == "true"
        return {"stdout": '{"matches":[]}', "version": "test"}
    monkeypatch.setattr(actions, "offline_runner", run)
    report = tmp_path / "report.json"
    actions.scan_sbom(sbom, report, environment=environment)
    assert json.loads(report.with_suffix(".binding").read_text())["scanner_database_age_policy"] == {
        "validate": expected == "true", "max_allowed_built_age": "240h"}


def test_invalid_database_age_policy_fails_before_scanner(inputs, tmp_path, monkeypatch):
    sbom, database = inputs
    monkeypatch.setattr(actions, "offline_runner", lambda *args, **kwargs: pytest.fail("Scanner must not run"))
    with pytest.raises(actions.RendererError, match="age policy") as failure:
        actions.scan_sbom(sbom, tmp_path / "report.json", environment={
            "GRYPE_DB_CACHE_DIR": str(database), "GRYPE_DB_VALIDATE_AGE": "arbitrary-value"})
    assert failure.value.reason == "scanner_database_policy_invalid"


@pytest.mark.parametrize("payload", ["invalid-json", '{"not-a-native-sbom":[]}'])
def test_invalid_sbom_has_actionable_reason_before_scanner(inputs, tmp_path, monkeypatch, payload):
    sbom, _ = inputs
    sbom.write_text(payload)
    monkeypatch.setattr(actions, "offline_runner", lambda *args, **kwargs: pytest.fail("Scanner must not run"))
    with pytest.raises(actions.RendererError) as failure:
        actions.scan_sbom(sbom, tmp_path / "report.json")
    assert failure.value.reason == "invalid_scanner_input"


def test_unavailable_database_has_actionable_reason_before_scanner(inputs, tmp_path, monkeypatch):
    sbom, database = inputs
    (database / "vulnerability.db").unlink()
    monkeypatch.setattr(actions, "offline_runner", lambda *args, **kwargs: pytest.fail("Scanner must not run"))
    with pytest.raises(actions.RendererError) as failure:
        actions.scan_sbom(sbom, tmp_path / "report.json")
    assert failure.value.reason == "scanner_database_unavailable"


@pytest.mark.parametrize("payload", ["invalid-json", '{"missing-matches":[]}'])
def test_invalid_evidence_is_classified_and_not_retained(inputs, tmp_path, monkeypatch, payload):
    sbom, _ = inputs
    report = tmp_path / "report.json"
    monkeypatch.setattr(actions, "offline_runner", lambda *args, **kwargs: {"stdout": payload, "version": "test"})
    with pytest.raises(actions.RendererError) as failure:
        actions.scan_sbom(sbom, report)
    assert failure.value.reason == "invalid_scanner_evidence"
    assert not report.exists() and not report.with_suffix(".binding").exists()


def test_fixed_selection_and_full_evidence_use_same_native_sbom(inputs, tmp_path, monkeypatch):
    sbom, _ = inputs
    calls = []
    def run(tool, args, cwd, **options):
        calls.append(args)
        return {"stdout": json.dumps({"matches": [] if "--only-fixed" in args else [{"vulnerability": {"fix": {"state": "not-fixed"}}}]}),
                "version": "test"}
    monkeypatch.setattr(actions, "offline_runner", run)
    fixed = actions.scan_sbom(sbom, tmp_path / "fixed.json")
    full = actions.scan_sbom(sbom, tmp_path / "full.json", only_fixed=False)
    assert fixed["matches"] == [] and len(full["matches"]) == 1
    assert [arg for arg in calls[0] if arg != "--only-fixed"] == calls[1]
    assert json.loads((tmp_path / "fixed.binding").read_text())["sbom_digest"] == json.loads((tmp_path / "full.binding").read_text())["sbom_digest"]


@pytest.mark.parametrize("kind", ["dir", "docker-archive", "oci-archive"])
def test_inventory_always_includes_image_catalogers(tmp_path, monkeypatch, kind):
    source = tmp_path / "source"
    source.mkdir() if kind == "dir" else source.write_bytes(b"image")
    def run(tool, args, cwd, **options):
        assert tool == "syft"
        assert args[args.index("--override-default-catalogers") + 1] == "image"
        assert not options.get("writable")
        assert options["environment"] == {"SYFT_CHECK_FOR_APP_UPDATE": "false"}
        return {"stdout": '{"artifacts":[]}', "version": "test"}
    monkeypatch.setattr(actions, "offline_runner", run)
    actions.inventory(source, tmp_path / "inventory.json", source_type=kind)


@pytest.mark.parametrize("name", ["deployment.yaml", "Dockerfile", "Dockerfile.production", "compose.yaml"])
def test_configuration_action_preserves_filename_and_original_lineage(tmp_path, monkeypatch, name):
    source = tmp_path / name
    source.write_text("kind: Pod\n")
    def run(tool, args, cwd, **options):
        assert args[-1] == "/inputs/" + name
        assert "--skip-check-update" in args
        assert "--disable-telemetry" in args
        assert "--config" in args
        assert options["read_only"] == {source: "/inputs/" + name}
        assert "environment" not in options
        return {"stdout": json.dumps({"Results": [{"Target": "/inputs/" + name, "Misconfigurations": []}]}), "version": "test"}
    monkeypatch.setattr(actions, "offline_runner", run)
    report = actions.scan_configuration(source, tmp_path / "report.json", cache=tmp_path / "missing-cache")
    assert report["Results"][0]["Target"] == source.as_posix()


def test_receipt_requires_report_and_inventory_bindings_on_both_sides(inputs, tmp_path, monkeypatch):
    sbom, _ = inputs
    monkeypatch.setattr(actions, "offline_runner", lambda *args, **kwargs: {"stdout": '{"matches":[]}', "version": "test"})
    for label in ("before", "after"):
        retained = tmp_path / f"sbom-{label}.json"
        retained.write_bytes(sbom.read_bytes())
        actions.scan_sbom(retained, tmp_path / f"grype-full-{label}.json", only_fixed=False)
    receipt = retained_scan_evidence(tmp_path, "a" * 64)
    assert receipt["status"] == "complete" and receipt["candidate_digest"] == "sha256:" + "a" * 64
    (tmp_path / "grype-full-after.json").write_text('{"matches":[{"tampered":true}]}')
    assert retained_scan_evidence(tmp_path, "a" * 64)["status"] == "incomplete"


def test_scanner_failure_discards_stale_reports(inputs, tmp_path, monkeypatch):
    sbom, _ = inputs
    report = tmp_path / "result.json"
    report.write_text('{"matches":[]}')
    report.with_suffix(".binding").write_text('{"stale":true}')
    def fail(*args, **kwargs):
        raise actions.RendererError("isolated scanner failed")
    monkeypatch.setattr(actions, "offline_runner", fail)
    with pytest.raises(actions.RendererError):
        actions.scan_sbom(sbom, report)
    assert not report.exists() and not report.with_suffix(".binding").exists()


def test_full_evidence_failure_discards_entire_pair(inputs, tmp_path, monkeypatch):
    sbom, _ = inputs
    fixed, full = tmp_path / "fixed.json", tmp_path / "full.json"
    def run(tool, args, cwd, **options):
        if "--only-fixed" not in args:
            raise actions.RendererError("Full evidence failed")
        return {"stdout": '{"matches":[]}', "version": "test"}
    monkeypatch.setattr(actions, "offline_runner", run)
    with pytest.raises(actions.RendererError, match="Full evidence failed"):
        actions.scan_sbom_evidence(sbom, fixed, full)
    assert not any(path.exists() for path in (fixed, full, fixed.with_suffix(".binding"), full.with_suffix(".binding")))
