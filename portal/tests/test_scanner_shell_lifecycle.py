"""Exercise the standalone runner with real Bash processes and isolated phases."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scanning-main" / "scripts"
PHASES = {
    "prepare_inputs": "prepare-inputs.sh",
    "generate_sboms": "generate-sboms.sh",
    "scan_sboms": "scan-sboms.sh",
    "configuration_scan": "scan-configurations.sh",
    "report_results": "report.sh",
    "report_to_portal": "report-to-portal.sh",
    "results_assembly": "assemble-results.sh",
}


@pytest.fixture
def bash():
    # Windows' bash launcher may select WSL, which cannot run this checkout.
    executable = (Path("C:/Program Files/Git/bin/bash.exe") if os.name == "nt"
                  else Path(shutil.which("bash") or "/nonexistent"))
    if not executable.is_file():
        pytest.skip("Git Bash (Windows) or Bash (POSIX) is required")
    return str(executable)


def write_script(path, body):
    path.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8", newline="\n")


@pytest.fixture
def scan_fixture(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copyfile(SCRIPTS / "run-scan.sh", scripts / "run-scan.sh")
    for phase, filename in PHASES.items():
        write_script(scripts / filename, f"echo phase-{phase}\ntouch ran-{phase}\nexit 0")
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    return scripts, inputs, output


def run_scan(bash, fixture):
    scripts, inputs, output = fixture
    env = os.environ.copy()
    env.update(CATS_JOB_MODE="scan", HELM_SCAN_ENABLED="false",
               TRIVY_CONFIG_SCAN_ENABLED="false",
               TRIVY_IMAGE_CONFIG_SCAN_ENABLED="false",
               DOCKLE_IMAGE_CONFIG_SCAN_ENABLED="false")
    result = subprocess.run([bash, "-c", 'export PATH="/usr/bin:/bin:$PATH"; exec bash "$@"', "scanner-test", "scripts/run-scan.sh",
                             "../inputs", "output"], cwd=scripts.parent,
                            capture_output=True, text=True, env=env, timeout=30)
    return result, output


def assert_failed(output):
    assert (output / "scan-status.txt").read_text().strip() == "failed"
    assert json.loads((output / "scan-summary.json").read_text())["status"] == "failed"
    return json.loads((output / "scan-failure.json").read_text())


def test_child_syntax_error_prevents_all_phases(bash, scan_fixture):
    scripts, _, _ = scan_fixture
    write_script(scripts / "scan-configurations.sh", "if then\nexit 0")
    result, output = run_scan(bash, scan_fixture)
    assert result.returncode != 0
    assert_failed(output)
    assert not list(output.glob("ran-*"))
    assert "scan-configurations.sh" in result.stdout + result.stderr + "\n".join(
        p.read_text() for p in output.glob("*.log"))


def test_child_crlf_prevents_all_phases(bash, scan_fixture):
    scripts, _, _ = scan_fixture
    (scripts / "scan-configurations.sh").write_bytes(b"#!/usr/bin/env bash\r\nexit 0\r\n")
    result, output = run_scan(bash, scan_fixture)
    assert result.returncode != 0
    assert_failed(output)
    assert not list(output.glob("ran-*"))


@pytest.mark.parametrize("phase,exit_code", [
    ("prepare_inputs", 23), ("configuration_scan", 47),
    ("report_to_portal", 31), ("results_assembly", 19),
])
def test_required_phase_failure_preserves_exit_and_stops_downstream(bash, scan_fixture, phase, exit_code):
    scripts, _, _ = scan_fixture
    write_script(scripts / PHASES[phase], f"echo fatal-{phase}\nexit {exit_code}")
    result, output = run_scan(bash, scan_fixture)
    assert result.returncode != 0
    failure = assert_failed(output)
    assert failure["phase"] == phase
    assert failure["exit_code"] == exit_code
    state = json.loads((output / f"phase-{phase}.json").read_text())
    assert state["status"] == "failed"
    assert state["exit_code"] == exit_code
    assert f"fatal-{phase}" in (output / f"{phase}.log").read_text()
    downstream = list(PHASES)[list(PHASES).index(phase) + 1:]
    for next_phase in downstream:
        assert not (output / f"ran-{next_phase}").exists()
        assert not (output / f"phase-{next_phase}.json").exists()
    if phase == "configuration_scan":
        assert (output / "prepare_inputs.log").exists()


@pytest.mark.parametrize("filename,phase", [
    ("extract-helm-images.sh", "prepare_inputs"),
    ("scan-configurations.sh", "configuration_scan"),
])
def test_missing_sourced_helpers_fail_real_phase(bash, scan_fixture, filename, phase):
    scripts, _, _ = scan_fixture
    shutil.copyfile(SCRIPTS / filename, scripts / filename)
    if phase == "prepare_inputs":
        write_script(scripts / PHASES[phase], 'bash "$(dirname "$0")/extract-helm-images.sh"')
    result, output = run_scan(bash, scan_fixture)
    assert result.returncode != 0
    failure = assert_failed(output)
    assert failure["phase"] == phase
    assert failure["exit_code"] != 0
    assert "helm-render-helpers.sh" in (output / f"{phase}.log").read_text()
    assert not (output / "ran-results_assembly").exists()


def test_zero_exit_skipped_phases_remain_successful(bash, scan_fixture):
    scripts, _, _ = scan_fixture
    for filename in PHASES.values():
        write_script(scripts / filename, "echo 'SKIPPED: no applicable input'\nexit 0")
    result, output = run_scan(bash, scan_fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output / "scan-status.txt").read_text().strip() == "complete"
    assert not (output / "scan-failure.json").exists()
    for phase in PHASES:
        assert json.loads((output / f"phase-{phase}.json").read_text())["status"] == "complete"


def test_real_disabled_configuration_scan_is_not_fatal(bash, scan_fixture):
    scripts, _, _ = scan_fixture
    for name in ("scan-configurations.sh", "helm-render-helpers.sh", "helm-dependency-helpers.sh"):
        shutil.copyfile(SCRIPTS / name, scripts / name)
    # Stub JSON formatting only; run the actual configuration skip lifecycle.
    write_script(scripts / "jq", 'if [ "$1" = "length" ]; then echo 0; else echo "{}"; fi')
    original = (scripts / "scan-configurations.sh").read_text()
    (scripts / "scan-configurations.sh").write_text(
        original.replace("set -uo pipefail", 'set -uo pipefail\njq() { bash "$SCRIPT_DIRECTORY/jq" "$@"; }'),
        encoding="utf-8", newline="\n")
    result, output = run_scan(bash, scan_fixture)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "scanning are disabled" in (output / "configuration_scan.log").read_text()
    assert not (output / "scan-failure.json").exists()


def test_helper_runtime_failure_is_fatal(bash, scan_fixture):
    scripts, _, _ = scan_fixture
    shutil.copyfile(SCRIPTS / "scan-configurations.sh", scripts / "scan-configurations.sh")
    write_script(scripts / "helm-render-helpers.sh", "echo helper-runtime-error >&2\nreturn 7")
    result, output = run_scan(bash, scan_fixture)
    assert result.returncode != 0
    assert assert_failed(output)["phase"] == "configuration_scan"
    assert "helper-runtime-error" in (output / "configuration_scan.log").read_text()


def test_tracked_runtime_shell_scripts_have_lf_and_valid_syntax(bash):
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                             check=True).stdout.decode().split("\0")
    checked = []
    for name in filter(None, tracked):
        path = ROOT / name
        if not path.is_file():
            continue
        content = path.read_bytes()
        first_line = content.split(b"\n", 1)[0]
        if path.suffix != ".sh" and not (
                first_line.startswith(b"#!") and
                (b"bash" in first_line or first_line.rstrip().endswith(b"/sh"))):
            continue
        checked.append(name)
        assert b"\r" not in content, f"{name} contains CR bytes; shell scripts require LF"
        result = subprocess.run([bash, "-n", path.as_posix()], capture_output=True, text=True)
        assert result.returncode == 0, f"{name}: {result.stderr}"
    assert checked, "No tracked shell scripts were checked"


def test_assembly_rejects_fatal_scan_without_creating_import(tmp_path):
    (tmp_path / "scan-failure.json").write_text('{"phase":"prepare_inputs"}')
    result = subprocess.run([sys.executable, str(SCRIPTS / "assemble-results.py"),
                             "--root", str(tmp_path)], capture_output=True, text=True)
    assert result.returncode != 0
    assert "required scanner phase failed" in result.stderr
    assert not (tmp_path / "results-export.tar.gz").exists()


def test_portal_fatal_scan_preserves_diagnostics_and_blocks_ingest(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from app import main

    job_id = "fatal-shell-test"
    output = tmp_path / job_id / "output"
    trust = tmp_path / job_id / "input" / ".cats-trust"
    trust.mkdir(parents=True)
    (trust / "ca-bundle.pem").write_text("test trust")
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setattr(main, "PUBLIC_JOBS", {job_id: {"ingest_service_id": "service"}})
    monkeypatch.setattr(main, "PUBLIC_PROCESSES", {})
    def update(key, **values):
        main.PUBLIC_JOBS[key].update(values)
    monkeypatch.setattr(main, "_public_job_update", update)
    def process(*args, **kwargs):
        (output / "scan-failure.json").write_text('{"phase":"configuration_scan","exit_code":47}')
        (output / "configuration_scan.log").write_text("fatal helper error")
        # Even a leftover result must not be ingested.
        (output / "portal-result.json").write_text("{}")
        return SimpleNamespace(poll=lambda: 47, returncode=47)
    monkeypatch.setattr(main.subprocess, "Popen", process)
    monkeypatch.setattr(main, "SessionLocal", lambda: pytest.fail("Fatal scan attempted automatic ingest"))
    main._run_public_scan(job_id, "")
    state = main.PUBLIC_JOBS[job_id]
    assert state["status"] == "error"
    assert "configuration_scan" in state["error"] and "47" in state["error"]
    assert (output / "worker.log").exists()
    assert (output / "configuration_scan.log").read_text() == "fatal helper error"
    assert not trust.exists()
    with pytest.raises(HTTPException) as exc:
        main.ingest_public_scan(job_id, "service", None,
                                SimpleNamespace(accessible_service_ids=lambda _: None))
    assert exc.value.status_code == 409
