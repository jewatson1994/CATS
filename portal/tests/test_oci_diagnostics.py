"""OCI Helm acquisition must preserve useful, credential-safe evidence."""

import subprocess
from unittest.mock import patch

import pytest

from app import main
from app.oci_diagnostics import OciPullFailure
from app.helm_sources import oci_pull_arguments
from app.service_definitions import parse_definition


REF = "oci://registry.example.invalid/charts/redis:28.1.0"


def test_oci_latest_omits_version_flag_but_exact_version_stays_pinned():
    assert oci_pull_arguments(REF) == [
        "oci://registry.example.invalid/charts/redis", "--version", "28.1.0"
    ]
    assert oci_pull_arguments("oci://registry.example.invalid/charts/redis:latest") == [
        "oci://registry.example.invalid/charts/redis"
    ]


def test_oci_latest_downloader_uses_helm_version_resolution():
    commands = []

    def fake_run(command, **_):
        commands.append(command)
        destination = command[command.index("--destination") + 1]
        from pathlib import Path
        (Path(destination) / "redis-28.1.0.tgz").write_bytes(b"chart")
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch.object(main.shutil, "which", return_value="helm"), \
         patch.object(main, "check_space"), \
         patch.object(main.subprocess, "run", side_effect=fake_run):
        archives = main._download_oci_chart("oci://registry.example.invalid/charts/redis:latest")
    try:
        assert commands[0][:3] == ["helm", "pull", "oci://registry.example.invalid/charts/redis"]
        assert "--version" not in commands[0]
        assert archives[0][1] == "redis-28.1.0.tgz"
    finally:
        from app.helm_downloads import close_downloads
        close_downloads(archives)


@pytest.mark.parametrize(("output", "category"), [
    ("manifest unknown", "chart_reference_not_found"),
    ("tag not found", "version_not_found"),
    ("unauthorized", "authentication_denied"),
    ("x509: certificate signed by unknown authority", "tls_trust_failure"),
    ("lookup registry.example.invalid: no such host", "dns_network_failure"),
    ("context deadline exceeded", "timeout"),
    ("TOOMANYREQUESTS", "registry_rate_limit"),
    ("invalid reference", "malformed_reference"),
    ("unexpected failure", "unknown_acquisition_failure"),
])
def test_classification_and_sanitized_output(output, category):
    failure = OciPullFailure(REF, exit_code=7, stderr=f"{output}; Authorization: Bearer secret-token")
    assert failure.diagnostic["failure_category"] == category
    assert failure.diagnostic["helm_exit_code"] == 7
    assert failure.diagnostic["attempted_reference"] == REF
    assert "secret-token" not in str(failure.diagnostic)
    assert "Authorization" not in str(failure.diagnostic)


def test_oci_downloader_keeps_safe_command_and_failure_code():
    result = subprocess.CompletedProcess([], 2, "", "tag not found; token=private-value")
    with patch.object(main.shutil, "which", return_value="helm"), \
         patch.object(main, "check_space"), \
         patch.object(main.subprocess, "run", return_value=result):
        with pytest.raises(OciPullFailure) as raised:
            main._download_oci_chart(REF)
    diagnostic = raised.value.diagnostic
    assert diagnostic["failure_category"] == "version_not_found"
    assert diagnostic["helm_command"][:5] == ["helm", "pull", "oci://registry.example.invalid/charts/redis", "--version", "28.1.0"]
    assert diagnostic["helm_exit_code"] == 2
    assert "private-value" not in str(diagnostic)


def test_oci_downloader_success_retains_archive(tmp_path):
    def fake_run(command, **_):
        destination = command[command.index("--destination") + 1]
        from pathlib import Path
        (Path(destination) / "redis-28.1.0.tgz").write_bytes(b"chart")
        return subprocess.CompletedProcess(command, 0, "", "")
    with patch.object(main.shutil, "which", return_value="helm"), \
         patch.object(main, "check_space"), \
         patch.object(main.subprocess, "run", side_effect=fake_run):
        archives = main._download_oci_chart(REF)
    try:
        assert len(archives) == 1
        assert archives[0][1] == "redis-28.1.0.tgz"
        assert archives[0][0].read() == b"chart"
    finally:
        from app.helm_downloads import close_downloads
        close_downloads(archives)


def test_duplicate_aliases_keep_separate_submitted_identity():
    source = """services:
  nginx-primary:
    sourceType: oci
    ociRepo: {url: 'oci://registry.example.invalid/charts/nginx', repoName: nginx, tag: 1.2.3}
  nginx-secondary:
    sourceType: oci
    ociRepo: {url: 'oci://registry.example.invalid/charts/nginx', repoName: nginx, tag: 1.2.3}
"""
    components = parse_definition(source, "singularity")["components"]
    assert [c["logical_name"] for c in components] == ["nginx-primary", "nginx-secondary"]
    assert [c["reference"] for c in components] == ["oci://registry.example.invalid/charts/nginx:1.2.3"] * 2
