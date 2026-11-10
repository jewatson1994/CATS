"""Scanner adapters publish sanitized native diagnostics and retain no partial evidence."""
import errno
import importlib.util
from pathlib import Path

import pytest

from app import scanner_actions as actions
from app.scanner_errors import ScannerDiagnostic


SECRET = "private-registry-password-canary"


def load_cli(name):
    path = Path(__file__).parents[2] / "scanning-main/scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


@pytest.mark.parametrize("script", ["scan-sbom", "scanner-action"])
@pytest.mark.parametrize("error,code", [
    (actions.RendererError(SECRET, reason="process_creation_failed"), "process_creation_failed"),
    (actions.RendererError(SECRET, infrastructure=True), "isolation_unavailable"),
    (actions.RendererError(SECRET, reason=SECRET), "scanner_failed"),
    (OSError(errno.ENOSPC, SECRET, SECRET), "disk_space_exhausted"),
    (OSError(errno.EAGAIN, SECRET, SECRET), "process_creation_failed"),
    (ValueError(SECRET), "scanner_failed"),
])
def test_cli_reports_only_allowlisted_details(script, error, code, tmp_path, monkeypatch, capsys):
    cli = load_cli(script)

    def fail(*args, **kwargs):
        raise error

    source, destination = tmp_path / "input.json", tmp_path / "report.json"
    if script == "scan-sbom":
        monkeypatch.setattr(cli, "scan_sbom_evidence", fail)
        status = cli.scan(source, destination)
    else:
        monkeypatch.setattr(cli, "inventory", fail)
        monkeypatch.setattr("sys.argv", [script, "inventory", str(source), str(destination)])
        status = cli.main()
    output = capsys.readouterr()
    assert status == 2
    assert "no completed evidence was retained" in output.err
    assert f"[{code}]" in output.err
    assert SECRET not in output.err
    assert output.out == ""


@pytest.mark.parametrize("script", ["scan-sbom", "scanner-action"])
def test_cli_includes_sanitized_native_error_and_exit_code(script, tmp_path, monkeypatch, capsys):
    cli = load_cli(script)

    def fail(*args, **kwargs):
        raise actions.RendererError("Offline tool failed", reason="scanner_failed", scanner_diagnostic=ScannerDiagnostic(
            "grype", 7, f"unsupported schema version 99; token={SECRET}"))

    source, destination = tmp_path / "input.json", tmp_path / "report.json"
    if script == "scan-sbom":
        monkeypatch.setattr(cli, "scan_sbom_evidence", fail)
        status = cli.scan(source, destination)
    else:
        monkeypatch.setattr(cli, "inventory", fail)
        monkeypatch.setattr("sys.argv", [script, "inventory", str(source), str(destination)])
        status = cli.main()
    output = capsys.readouterr()
    assert status == 2
    assert "unsupported schema version 99" in output.err
    assert "Scanner: grype; exit code 7." in output.err
    assert SECRET not in output.err
    assert output.out == ""


def test_full_scan_failure_removes_pair_and_reports_safe_reason(tmp_path, monkeypatch, capsys):
    database = tmp_path / "database"
    database.mkdir()
    (database / "vulnerability.db").write_bytes(b"retained database")
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(database))
    sbom = tmp_path / "inventory.json"
    sbom.write_text('{"artifacts":[],"source":{"type":"directory"}}')
    fixed, full = tmp_path / "report.json", tmp_path / "full/report.json"
    full.parent.mkdir()
    outputs = (fixed, fixed.with_suffix(".binding"), full, full.with_suffix(".binding"))
    for path in outputs:
        path.write_text("stale evidence")

    def run(tool, args, cwd, **options):
        if "--only-fixed" not in args:
            assert fixed.exists() and fixed.with_suffix(".binding").exists()
            raise actions.RendererError(SECRET, reason="process_creation_failed", scanner_diagnostic=ScannerDiagnostic(
                "grype", -6, f"runtime/cgo: pthread_create failed: Resource temporarily unavailable; token={SECRET}"))
        return {"stdout": '{"matches":[]}', "version": "test"}

    monkeypatch.setattr(actions, "offline_runner", run)
    assert load_cli("scan-sbom").scan(sbom, fixed) == 2
    assert not any(path.exists() for path in outputs)
    output = capsys.readouterr().err
    assert "[process_creation_failed]" in output
    assert "Scanner: grype; signal 6." in output
    assert "pthread_create failed: Resource temporarily unavailable" in output
    assert SECRET not in output
