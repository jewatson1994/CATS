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


@pytest.mark.parametrize("worker_tmp", [True, False])
@pytest.mark.parametrize("failed_stage", ["none", "acquire", "convert", "identity"])
def test_registry_acquisition_preserves_identity_and_stages_locally(bash, tmp_path, worker_tmp, failed_stage):
    (tmp_path / "service.yml").write_text("service: nginx\n")
    (tmp_path / "images.yml").write_text("images: [nginx:1.27.0-alpine]\n")
    # Exercise the real phase, replacing network acquisition and inventory only.
    # Skopeo's default is /var/tmp; TMPDIR alone does not select its layer staging.
    wrapper = r'''
export PATH="/usr/bin:/bin:$PATH"
export CATS_IMAGE_SOURCE=daemonless CI_PROJECT_DIR="$PWD"
export DOCKER_CONFIG="$PWD/acquisition credentials" FAILED_STAGE="$3"
mkdir -p "$DOCKER_CONFIG"
printf '{}\n' > "$DOCKER_CONFIG/config.json"
if [ "$2" = worker ]; then
  export TMPDIR="$PWD/job temporary files"
else
  unset TMPDIR
fi
skopeo() {
  printf '%s\n' "$@" >> skopeo-args.txt
  printf '\n' >> skopeo-args.txt
  [ "$1" = --tmpdir ] && [ "$3" = copy ] && [ -d "$2" ] || return 23
  printf 'acquired layer\n' > "$2/acquired-layer"
  if [[ "${@: -2:1}" == docker://* ]]; then
    [ "$FAILED_STAGE" != acquire ] || return 24
  else
    [ "$FAILED_STAGE" != convert ] || return 25
  fi
}
yq() {
  [ "$1" = -e ] || printf '["nginx:1.27.0-alpine"]\n'
}
jq() {
  if [ "$1" = -er ]; then
    cat >/dev/null
    printf 'nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
  else
    cat >/dev/null
    printf 'nginx:1.27.0-alpine\n'
  fi
}
python3() {
  if [[ "$1" == */scanner-action.py ]]; then
    printf '%s\n' "$@" > inventory-args.txt
    printf '{"source":{"metadata":{}}}\n' > "$4"
  elif [[ "$1" == */sbom_identity.py ]]; then
    [ "$FAILED_STAGE" != identity ] || return 26
    printf '{"image_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n'
  fi
}
source "$1"
'''
    result = subprocess.run(
        [bash, "-c", wrapper, "scanner-test", str(SCRIPTS / "generate-sboms.sh"),
         "worker" if worker_tmp else "standalone", failed_stage], cwd=tmp_path,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [call.splitlines() for call in (tmp_path / "skopeo-args.txt").read_text().strip().split("\n\n")]
    arguments = calls[0]
    assert arguments[0] == "--tmpdir"
    assert arguments[2] == "copy"
    assert arguments[3] == "--preserve-digests"
    assert arguments[4] == "--src-authfile"
    assert arguments[-2] == "docker://nginx:1.27.0-alpine"
    assert arguments[-1].startswith("oci-archive:")
    staging = arguments[1].replace("\\", "/")
    assert ("/job temporary files/cats-acquire." if worker_tmp else "/.cats-images/image.") in staging
    assert not list(tmp_path.rglob("acquired-layer"))
    assert not list(tmp_path.rglob("cats-acquire.*"))
    if failed_stage in {"acquire", "identity"}:
        assert len(calls) == 1
    else:
        assert len(calls) == 2
        # Configuration tools consume a local derivative of these exact bytes.
        # No credentials, registry transport, or second tag resolution occurs.
        assert calls[1][:3] == arguments[:3]
        assert calls[1][3] == arguments[-1]
        assert calls[1][4].startswith("docker-archive:")
        assert len(calls[1]) == 5
    if failed_stage != "none":
        assert (tmp_path / "skipped_images.txt").read_text().strip() == "nginx:1.27.0-alpine"
        assert not (tmp_path / "image-sources.tsv").read_text()
        assert not list((tmp_path / "sboms").glob("*.json"))
        return
    inventory = (tmp_path / "inventory-args.txt").read_text().splitlines()
    assert inventory[2] == arguments[-1].removeprefix("oci-archive:")
    assert inventory[-2:] == ["--source-type", "oci-archive"]
    assert (tmp_path / "sboms/nginx-1.27.0-alpine.digest").read_text().strip() == "nginx@sha256:" + "a" * 64
    assert not (tmp_path / "skipped_images.txt").read_text().strip()
    assert "nginx:1.27.0-alpine\tdocker-archive:" in (tmp_path / "image-sources.tsv").read_text()


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


@pytest.mark.parametrize("legacy_flag", [None, "true"])
def test_portal_scanner_execution_is_disabled_by_default(monkeypatch, legacy_flag):
    from app import main
    if legacy_flag is None:
        monkeypatch.delenv("CATS_ENABLE_LEGACY_PORTAL_SCANNER", raising=False)
    else:
        monkeypatch.setenv("CATS_ENABLE_LEGACY_PORTAL_SCANNER", legacy_flag)
    monkeypatch.setattr(main.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("portal launched scanner"))
    with pytest.raises(RuntimeError, match="dedicated scan-worker"):
        main._run_public_scan("disabled-job", "")
