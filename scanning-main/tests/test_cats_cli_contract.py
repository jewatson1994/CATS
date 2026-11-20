"""Contract checks for the image-owned GitLab scanner interface.

These tests intentionally inspect the source rather than executing the shell
CLI: the CLI is executed inside the versioned CATS image, while the repository
test job may run on a minimal Python image without Docker or Bash tooling.
"""

import json
from pathlib import Path
import runpy
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "cats"
PIPELINE = ROOT / ".gitlab-ci.yml"
TEMPLATES = ROOT / "templates"
IMAGE_DOCKERFILE = ROOT.parent / "cats-image" / "Dockerfile.all-in-one"


def test_cli_exposes_stable_commands_and_artifact_contract():
    text = CLI.read_text(encoding="utf-8")
    for command in (
        "cats version",
        "cats prepare --source SOURCE_DIR --output OUTPUT_DIR",
        "cats evaluate --source PREPARED_DIR --output RESULTS_DIR",
        "cats patch --input EVALUATION_DIR --output PATCH_DIR",
        "cats push assessment --input PORTAL_RESULT_JSON",
        "cats submit (--reference REGISTRY_REFERENCE | --file ARTIFACT)",
        "cats push patch --input PATCH_RESULT_JSON",
        "portal-result.json",
        "evaluation.json",
    ):
        assert command in text
    assert "--source) source=" in text


def test_pipeline_is_thin_and_image_owned():
    text = PIPELINE.read_text(encoding="utf-8")
    assert "cats version" in text
    assert "registry.example.invalid/security/cats-tool:latest" in text
    assert 'TRIVY_SKIP_CHECK_UPDATE: "true"' in text
    assert 'SYFT_CHECK_FOR_APP_UPDATE: "false"' in text
    assert 'TRIVY_IMAGE_CONFIG_SCAN_ENABLED: "false"' in text
    assert "git clone" not in text
    # Scanner implementation must not be reintroduced into YAML.
    for tool in ("grype ", "syft ", "trivy ", "helm ", "copa "):
        assert tool not in text


def test_new_templates_only_dispatch_to_cli():
    expected = {
        "cats_preparation.yml": ("stage: cats_preparation", "cats prepare "),
        "cats_evaluation.yml": ("stage: cats_evaluation", "cats evaluate "),
        "cats_push.yml": ("stage: cats_push", "cats push assessment "),
        "cats_patch.yml": ("stage: cats_patch", "cats patch "),
        "cats_patch_push.yml": ("stage: cats_patch_push", "cats push patch "),
    }
    for name, markers in expected.items():
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        for marker in markers:
            assert marker in text
        assert "git clone" not in text


def test_bundled_image_installs_the_cli():
    text = IMAGE_DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY scanning-main/scripts/cats /usr/local/bin/cats" in text
    assert "chmod 0755 /usr/local/bin/cats" in text


def test_submit_sends_the_same_project_contract_for_refs_and_streamed_files(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(CLI.parent))
    submit = runpy.run_path(str(CLI.with_name("submit-artifact.py")))["main"]
    token = "cats_project_example-test-credential"
    monkeypatch.setenv("CATS_PORTAL_URL", "https://portal.example/")
    monkeypatch.setenv("CATS_PROJECT_TOKEN", token)
    monkeypatch.setenv("CATS_PORTAL_CA_FILE", "root.pem")
    requests = []

    def curl(command, **kwargs):
        assert command[-1] == "https://portal.example/api/v1/artifact-submissions"
        assert command[command.index("--cacert") + 1] == "root.pem"
        assert kwargs["input"] == f"Authorization: Bearer {token}\nIdempotency-Key: example:42\n".encode()
        assert token not in " ".join(command) and "CATS_PROJECT_TOKEN" not in kwargs["env"]
        requests.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", curl)
    assert submit(["--reference", "registry.example/team/web:2", "--version", "2", "--key", "example:42"]) == 0
    assert json.loads(requests[-1][requests[-1].index("--data-binary") + 1]) == {
        "reference": "registry.example/team/web:2", "version": "2"}
    chart = tmp_path / "my chart.tgz"
    chart.write_bytes(b"chart fixture")
    assert submit(["--file", str(chart), "--kind", "helm-chart", "--key", "example:42"]) == 0
    assert "--form" in requests[-1] and "kind=helm-chart" in requests[-1]
    for args in (["--reference", "img", "--key", "two\nheaders"], ["--file", str(tmp_path), "--key", "example:42"]):
        with pytest.raises(SystemExit):
            submit(args)
    assert len(requests) == 2


def test_push_scopes_assessment_delivery_and_preserves_legacy_destinations(tmp_path, monkeypatch):
    assert 'exec python3 "$SCRIPT_DIR/push_result.py" "$kind" "$input"' in CLI.read_text()
    push = runpy.run_path(str(CLI.with_name("push_result.py")))["main"]
    result = tmp_path / "scan result.json"
    result.write_text("{}")
    project = "cats_project_scanner-test-only"
    legacy = "legacy-test-only"
    for key in ("CATS_PATCH_PUSH_URL", "CATS_ASSESSMENT_PUSH_URL", "CATS_PORTAL_CA_FILE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CATS_PROJECT_TOKEN", project)
    monkeypatch.setenv("CATS_PORTAL_TOKEN", legacy)
    monkeypatch.setenv("CATS_PORTAL_URL", "https://cats.example/portal/")
    monkeypatch.setenv("CATS_PORTAL_CA_CERT", "internal-ca.pem")
    requests = []

    def curl(command, **kwargs):
        assert all(secret not in " ".join(command) for secret in (legacy, project))
        assert not {"CATS_PORTAL_TOKEN", "CATS_PROJECT_TOKEN"}.intersection(kwargs["env"])
        assert command[command.index("--data-binary") + 1] == "@" + str(result)
        assert command[command.index("--cacert") + 1] == "internal-ca.pem"
        requests.append((command, kwargs["input"]))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", curl)
    endpoint = "https://cats.example/portal/api/v1/pipeline-results"
    assert push(["assessment", str(result)]) == 0
    command, header = requests[-1]
    assert command[-1] == endpoint and header == f"Authorization: Bearer {project}\n".encode()
    assert command[command.index("--proto") + 1] == "=https"
    assert command[command.index("--max-redirs") + 1] == "0"
    monkeypatch.setenv("CATS_ASSESSMENT_PUSH_URL", "https://another.example/evidence")
    with pytest.raises(SystemExit):
        push(["assessment", str(result)])
    monkeypatch.setenv("CATS_ASSESSMENT_PUSH_URL", endpoint)
    monkeypatch.setenv("CATS_PORTAL_URL", "http://cats.example")
    with pytest.raises(SystemExit):
        push(["assessment", str(result)])
    assert push(["patch", str(result)]) == 0
    assert len(requests) == 1
    monkeypatch.setenv("CATS_PATCH_PUSH_URL", "https://integration.example/patch")
    assert push(["patch", str(result)]) == 0
    assert requests[-1][0][-1] == "https://integration.example/patch"
    assert requests[-1][1] == f"Authorization: Bearer {legacy}\n".encode()
    monkeypatch.delenv("CATS_PROJECT_TOKEN")
    monkeypatch.setenv("CATS_ASSESSMENT_PUSH_URL", "https://integration.example/assessment")
    assert push(["assessment", str(result)]) == 0
    assert requests[-1][0][-1] == "https://integration.example/assessment"
    monkeypatch.setenv("CATS_PORTAL_TOKEN", project)
    with pytest.raises(SystemExit):
        push(["patch", str(result)])
    with pytest.raises(SystemExit):
        push(["assessment", str(result)])
    assert len(requests) == 3


def test_active_scanner_scripts_do_not_depend_on_repository_checkout():
    active = (
        "prepare-inputs.sh",
        "scan-configurations.sh",
        "report-to-portal.sh",
        "assemble-results.sh",
    )
    for name in active:
        text = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "git clone" not in text


def test_offline_trivy_checks_status_reports_embedded_fallback():
    text = (ROOT / "scripts" / "scan-configurations.sh").read_text(encoding="utf-8")
    assert 'if is_true "$TRIVY_SKIP_CHECK_UPDATE"; then' in text
    assert 'if [ -d "${TRIVY_CACHE_DIR}/policy/content" ]; then' in text
    assert 'checks_mode="cached"' in text
    assert 'checks_mode="embedded_fallback"' in text
    assert 'trivy_checks: {mode: $checks_mode}' in text
