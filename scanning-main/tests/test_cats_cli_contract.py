"""Contract checks for the image-owned GitLab scanner interface.

These tests intentionally inspect the source rather than executing the shell
CLI: the CLI is executed inside the versioned CATS image, while the repository
test job may run on a minimal Python image without Docker or Bash tooling.
"""

from pathlib import Path


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
