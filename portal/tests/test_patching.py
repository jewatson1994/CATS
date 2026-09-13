from __future__ import annotations

import io
import json
import os
import runpy
import sys
import tarfile
from pathlib import Path

import pytest

from app import main as portal_main, patch_service, patch_worker
from app.main import _patch_worker_values
from app.patching import (
    PATCH_PHASES, advance_patch_stages, initial_patch_stages,
    certificate_cleanup_script, certificate_trust_script, compare_reports, copa_command, copa_native_report, grype_archive_source, normalize_package_manager, package_ecosystem, package_manager_probe_script, patched_reference,
    redact, registry_host, repository_cleanup_script, repository_overlay_script,
    run_command, safe_job_config, validate_image_archive,
)


def test_patch_stage_state_preserves_successes_failures_and_not_reached():
    stages = initial_patch_stages("download")
    stages = advance_patch_stages(stages, "acquiring_image", "running", "download")
    stages = advance_patch_stages(stages, "scanning_source", "running", "download")
    stages = advance_patch_stages(stages, "patching_image", "running", "download")
    stages = advance_patch_stages(stages, "scanning_patched", "running", "download")
    stages = advance_patch_stages(stages, "scanning_patched", "failed", "download")
    assert [stages[phase]["status"] for phase in PATCH_PHASES[:4]] == ["success"] * 4
    assert stages["scanning_patched"]["status"] == "failed"
    assert stages["preparing_output"] == {"status": "skipped", "reason": "not_reached"}
    assert stages["pushing_image"]["status"] == "skipped"
    assert stages["completed"] == {"status": "skipped", "reason": "not_reached"}


def test_patch_stage_state_marks_download_push_skipped_and_push_mode_success():
    download = initial_patch_stages("download")
    assert download["pushing_image"] == {"status": "skipped", "reason": "not_applicable"}
    push = initial_patch_stages("push")
    push = advance_patch_stages(push, "pushing_image", "running", "push")
    push = advance_patch_stages(push, "completed", "complete", "push")
    assert push["pushing_image"]["status"] == "success"
    assert push["completed"]["status"] == "success"


@pytest.mark.parametrize("failed_phase", PATCH_PHASES[1:-1])
def test_each_terminal_failure_preserves_prior_and_marks_later_not_reached(failed_phase: str):
    mode = "push" if failed_phase in {"pushing_image", "signing_image"} else "download"
    stages = initial_patch_stages(mode)
    for phase in PATCH_PHASES[1:PATCH_PHASES.index(failed_phase) + 1]:
        stages = advance_patch_stages(stages, phase, "running", mode)
    stages = advance_patch_stages(stages, failed_phase, "failed", mode)
    index = PATCH_PHASES.index(failed_phase)
    assert all(stages[phase]["status"] == "success" for phase in PATCH_PHASES[:index])
    assert stages[failed_phase]["status"] == "failed"
    for phase in PATCH_PHASES[index + 1:]:
        expected_reason = "not_applicable" if mode == "download" and phase in {"pushing_image", "signing_image"} else "not_reached"
        assert stages[phase] == {"status": "skipped", "reason": expected_reason}


def grype_report(ids: list[tuple[str, str, list[str]]]) -> dict:
    return {
        "distro": {"name": "alpine", "version": "3.20"},
        "matches": [{
            "vulnerability": {"id": cve, "severity": "High", "fix": {"versions": fixes}},
            "artifact": {"name": package, "version": "1.0", "type": "apk"},
        } for cve, package, fixes in ids],
    }


def make_image_tar(path: Path, *, oci: bool = False) -> None:
    with tarfile.open(path, "w") as bundle:
        if oci:
            manifest_blob = b'{"schemaVersion":2,"config":{},"layers":[]}'
            digest = __import__("hashlib").sha256(manifest_blob).hexdigest()
            files = {
                "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
                "index.json": json.dumps({"schemaVersion": 2, "manifests": [{"digest": f"sha256:{digest}"}]}).encode(),
                f"blobs/sha256/{digest}": manifest_blob,
            }
        else:
            files = {
                "manifest.json": b'[{"Config":"config.json","RepoTags":["test:latest"],"Layers":["layer/layer.tar"]}]',
                "config.json": b"{}", "layer/layer.tar": _empty_layer_tar(),
            }
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))


def _empty_layer_tar() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w"):
        pass
    return output.getvalue()


def test_archive_validation_registry_and_safe_metadata(tmp_path: Path):
    docker_tar = tmp_path / "image.tar"
    make_image_tar(docker_tar)
    assert validate_image_archive(docker_tar) == "docker"
    oci_tar = tmp_path / "oci.tar"
    make_image_tar(oci_tar, oci=True)
    assert validate_image_archive(oci_tar) == "oci"
    assert grype_archive_source(docker_tar, "docker").startswith("docker-archive:")
    with pytest.raises(ValueError, match="Expected a docker"):
        validate_image_archive(oci_tar, expected_format="docker")
    bad = tmp_path / "bad.tar"
    make_image_tar(bad)
    with tarfile.open(bad, "w"):
        pass
    with pytest.raises(ValueError, match="not a Docker or OCI"):
        validate_image_archive(bad)
    assert registry_host("nginx:1.27") == "docker.io"
    assert registry_host("registry.example:5000/team/api:1") == "registry.example:5000"
    safe = safe_job_config({"source_image": "nginx:1.27", "registry_password": "secret", "api_token": "token"})
    assert safe == {"source_image": "nginx:1.27"}


def test_grype_native_copa_and_before_after_comparison(tmp_path: Path):
    before = grype_report([("CVE-1", "openssl", ["2.0"]), ("CVE-2", "busybox", ["1.1"]), ("CVE-3", "libc", [])])
    after = grype_report([("CVE-2", "busybox", ["1.1"]), ("CVE-3", "libc", [])])
    native = copa_native_report(before, "amd64")
    assert native["apiVersion"] == "v1alpha1"
    assert [item["vulnerabilityID"] for item in native["updates"]] == ["CVE-1", "CVE-2"]
    report = tmp_path / "copa.json"
    command = copa_command("docker.io/library/alpine:3.20", report, "3.20-cats-patched")
    assert command == [
        "copa", "patch", "--image", "docker.io/library/alpine:3.20",
        "--report", str(report), "--scanner", "native", "--tag", "3.20-cats-patched",
        "--loader", "docker", "--timeout", "30m",
    ]
    comparison = compare_reports(before, after)
    assert comparison["vulnerabilities_before"] == 3
    assert comparison["vulnerabilities_after"] == 2
    assert comparison["vulnerabilities_removed"] == 1
    assert comparison["vulnerabilities_remaining"] == 2
    assert comparison["could_not_be_patched"] == 1
    assert comparison["removed"][0]["id"] == "CVE-1"


def test_worker_status_identifier_is_not_forwarded_as_duplicate_job_argument():
    values, result = _patch_worker_values({
        "job_id": "job-123",
        "status": "complete",
        "phase": "completed",
        "result": {"vulnerabilities_before": 2},
    })
    assert values == {"status": "complete", "phase": "completed"}
    assert result == {"vulnerabilities_before": 2}


def test_reference_and_secret_redaction():
    ref, tag = patched_reference("registry.example/team/api:2.1")
    assert ref == "registry.example/team/api:2.1-cats-patched"
    assert tag == "2.1-cats-patched"
    message = redact("password=hunter2 Authorization: bearer-token", ("hunter2", "bearer-token"))
    assert "hunter2" not in message and "bearer-token" not in message


def test_repository_policy_scripts_are_manager_specific_and_restore_originals():
    apt = repository_overlay_script("apt")
    assert "/etc/apt/sources.list" in apt and "cats-original-apt" in apt
    assert "/etc/yum.repos.d" in repository_overlay_script("dnf")
    assert "/etc/apk/repositories" in repository_overlay_script("apk")
    cleanup = repository_cleanup_script("apt")
    assert "rm -f /etc/apt/sources.list" in cleanup
    assert "cats-original-apt" in cleanup
    with pytest.raises(ValueError):
        repository_overlay_script("unknown")


@pytest.mark.parametrize(("tls", "packages", "tls_flag", "package_flag"), [
    (True, True, False, False), (True, False, False, True),
    (False, True, True, False), (False, False, True, True),
])
def test_repository_controls_are_scoped_per_manager(tls, packages, tls_flag, package_flag):
    apt = repository_overlay_script("apt", tls, packages, "job-a")
    apk = repository_overlay_script("apk", tls, packages, "job-a")
    assert ("Verify-Peer" in apt) is (not tls)
    assert ("[trusted=yes]" in apt) is False  # package exception is encoded in the deb file
    assert ("--no-check-certificate" in apk) is tls_flag
    assert ("--allow-untrusted" in apk) is package_flag
    assert "/etc/job-a-original-apt" in apt
    assert "/etc/job-a-original-apk" in apk
    assert "/tmp/job-a-apk-path" in repository_cleanup_script("apk", tls, packages, "job-a")


def test_ca_cleanup_is_collision_safe_and_preserves_source_artifacts():
    script = certificate_trust_script("apt", "job-a")
    cleanup = certificate_cleanup_script("apt", "job-a")
    assert "original-anchor" in script and "no-anchor" in script
    assert "original-bundle" in script and "merged-bundle" in cleanup
    assert "/tmp/job-a-state" in cleanup
    assert certificate_cleanup_script("apt", "job-b") != cleanup


def test_trusted_ca_scripts_cover_supported_target_families():
    apk = certificate_trust_script("apk")
    apt = certificate_trust_script("apt")
    dnf = certificate_trust_script("dnf")
    assert "update-ca-certificates" in apk
    assert "/usr/local/share/ca-certificates" in apt
    assert "update-ca-trust" in dnf
    assert "/tmp/cats-patch-ca-bundle.pem" in apk
    assert "/tmp/cats-custom-ca.pem" in apk
    assert apk.index("/etc/ssl/certs/ca-certificates.crt") < apk.index("apk add --no-cache ca-certificates")
    assert apt.index("/etc/ssl/certs/ca-certificates.crt") < apt.index("apt-get update")
    assert dnf.index("/etc/pki/tls/certs/ca-bundle.crt") < dnf.index("microdnf install")
    for script in (apk, apt, dnf):
        assert "--no-check-certificate" not in script
        assert "http://" not in script
    assert "cats-trusted-ca.crt" in certificate_cleanup_script("apk")
    assert "cats-trusted-ca.crt" in certificate_cleanup_script("dnf")
    assert "/tmp/cats-patch-ca-bundle.pem" in certificate_cleanup_script("apk")
    assert "/tmp/cats-patch-ca-bundle.pem" in certificate_cleanup_script("dnf")


def test_trusted_ca_bootstrap_keeps_tls_verification_for_private_mirrors():
    """The temporary derivative must seed trust before package-manager I/O."""
    for manager, first_network_operation in (("apk", "apk add"), ("apt", "apt-get update"), ("dnf", "microdnf install")):
        script = certificate_trust_script(manager)
        assert script.index("cp /tmp/cats-patch-ca-bundle.pem") < script.index(first_network_operation)
        assert "ca-certificates" in script
        assert "insecure" not in script.lower()


def test_tls_error_is_prioritized_over_downstream_package_resolution(monkeypatch):
    monkeypatch.setattr("app.patching.shutil.which", lambda *_args, **_kwargs: "/usr/bin/copa")
    completed = __import__("subprocess").CompletedProcess(
        ["copa"], 1, "", "TLS: server certificate not trusted\nca-certificates (no such package)"
    )
    monkeypatch.setattr("app.patching.subprocess.run", lambda *_args, **_kwargs: completed)
    with pytest.raises(RuntimeError, match="Repository TLS trust failure"):
        run_command(["copa"], env={"PATH": "/usr/bin"}, log=lambda _message: None, timeout=1)


def test_package_manager_probe_stops_after_first_supported_command():
    probe = package_manager_probe_script()
    assert "exit 0" in probe and "exit 1" in probe
    assert normalize_package_manager("apt-get") == "apt"
    assert normalize_package_manager("microdnf") == "dnf"
    assert normalize_package_manager("yum") == "dnf"
    assert package_ecosystem("apt-get") == "deb"
    assert package_ecosystem("apk") == "apk"
    assert package_ecosystem("dnf") == "rpm"


def test_copa_native_report_filters_non_os_packages_for_detected_ecosystem():
    report = {
        "distro": {"name": "debian", "version": "12"},
        "matches": [
            {"vulnerability": {"id": "CVE-DEB", "fix": {"versions": ["2"]}}, "artifact": {"name": "openssl", "version": "1", "type": "deb"}},
            {"vulnerability": {"id": "CVE-GO", "fix": {"versions": ["2"]}}, "artifact": {"name": "golang.org/x/sys", "version": "1", "type": "go-module"}},
        ],
    }
    assert [item["name"] for item in copa_native_report(report, ecosystem="deb")["updates"]] == ["openssl"]


def test_compare_reports_classifies_patch_outcomes():
    before = grype_report([("CVE-1", "openssl", ["2.0"])])
    assert compare_reports(before, grype_report([]))["patch_status"] == "PATCHED"
    assert compare_reports(grype_report([]), grype_report([]))["patch_status"] == "NO_APPLICABLE_FIXES"


def test_unsupported_target_with_trusted_ca_reports_explicit_capability_error(monkeypatch, tmp_path: Path):
    config = {
        "job_id": "job-unsupported", "source_mode": "oci", "source_image": "registry.example/ubuntu:latest",
        "output_mode": "download", "trusted_ca_certificates": [{"pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}],
    }
    code, output, state, _ = run_worker(monkeypatch, tmp_path, config, grype_report([]), grype_report([]), source_credentials=("", ""))
    result = json.loads((output / "patch-result.json").read_text(encoding="utf-8"))
    assert code == 0 and state["status"] == "complete"
    assert result["status"] == "unsupported"
    assert "No supported package-management command" in result["reason"]


def run_worker(
    monkeypatch, tmp_path: Path, config: dict, before: dict, after: dict,
    fail_on: str = "", source_credentials: tuple[str, str] = ("source-user", "super-secret"),
    destination_credentials: tuple[str, str] = ("destination-user", "destination-secret"),
    corrupt_archive: bool = False, push_digest: str = "",
):
    output = tmp_path / "output"
    config_path = tmp_path / "job-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    calls: list[tuple[list[str], str | None]] = []

    def fake_run(command, *, env, log, timeout, stdin=None, stdout_path=None):
        calls.append((list(command), stdin))
        if fail_on and (command[0] == fail_on or fail_on in " ".join(command)):
            raise RuntimeError(f"{fail_on} failed with password=super-secret")
        stdout = ""
        if command[:2] == ["docker", "load"]:
            stdout = "Loaded image: uploaded:test\n"
        elif command[:2] == ["docker", "push"] and push_digest:
            stdout = f"patched: digest: {push_digest} size: 1234\n"
        elif command[:3] == ["docker", "image", "inspect"]:
            stdout = "amd64\n"
        elif command[:3] == ["docker", "run", "--rm"] and "cat" in command and "/etc/os-release" in command and any("alpine" in part for part in command):
            stdout = "ID=alpine\nVERSION_ID=3.20\n"
        elif command[:3] == ["docker", "run", "--rm"] and any("for tool" in part for part in command) and any("alpine" in part for part in command):
            stdout = "apk\n"
        elif command[0] == "grype" and stdout_path:
            report = before if "before" in stdout_path.name else after
            stdout_path.write_text(json.dumps(report), encoding="utf-8")
        elif command[:2] == ["docker", "save"]:
            archive_path = Path(command[command.index("--output") + 1])
            archive_path.write_bytes(b"not an image archive") if corrupt_archive else make_image_tar(archive_path)
        return __import__("subprocess").CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(patch_worker, "run_command", fake_run)
    monkeypatch.setattr(sys, "argv", ["patch_worker", str(config_path), str(output)])
    monkeypatch.setenv("CATS_PATCH_SOURCE_USERNAME", source_credentials[0])
    monkeypatch.setenv("CATS_PATCH_SOURCE_PASSWORD", source_credentials[1])
    monkeypatch.setenv("CATS_PATCH_DEST_USERNAME", destination_credentials[0])
    monkeypatch.setenv("CATS_PATCH_DEST_PASSWORD", destination_credentials[1])
    code = patch_worker.main()
    state = json.loads((output / "patch-state.json").read_text(encoding="utf-8"))
    return code, output, state, calls


def test_public_oci_to_download_worker_flow(monkeypatch, tmp_path: Path):
    config = {"job_id": "job1", "source_mode": "oci", "source_image": "docker.io/library/alpine:3.20", "output_mode": "download"}
    before = grype_report([("CVE-1", "openssl", ["2.0"]), ("CVE-2", "busybox", ["1.1"])])
    after = grype_report([("CVE-2", "busybox", ["1.1"])])
    code, output, state, calls = run_worker(
        monkeypatch, tmp_path, config, before, after, source_credentials=("", ""),
    )
    assert code == 0 and state["status"] == "complete" and state["phase"] == "completed"
    assert state["stages"]["queued"]["status"] == "success"
    assert state["stages"]["patching_image"]["status"] == "success"
    assert state["stages"]["pushing_image"] == {"status": "skipped", "reason": "not_applicable"}
    assert state["stages"]["completed"]["status"] == "success"
    assert validate_image_archive(output / "patched-image.tar", expected_format="docker") == "docker"
    result = json.loads((output / "patch-result.json").read_text(encoding="utf-8"))
    assert result["vulnerabilities_before"] == 2 and result["vulnerabilities_removed"] == 1
    assert any(command[:2] == ["docker", "pull"] for command, _ in calls)
    assert not any(command[:2] == ["docker", "login"] for command, _ in calls)
    grype_calls = [command for command, _ in calls if command and command[0] == "grype"]
    assert len(grype_calls) == 2 and all("--only-fixed" in command for command in grype_calls)
    assert grype_calls[0][1] == "docker:docker.io/library/alpine:3.20"
    assert grype_calls[1][1].startswith("dir:")
    assert not any(runtime in grype_calls[1][1] for runtime in ("docker-archive:", "docker:", "podman:", "containerd:", "registry:"))
    assert any(command[:2] == ["docker", "load"] and "patched-image.tar" in " ".join(command) for command, _ in calls)
    assert result["validated_source"] == "flattened-rootfs"
    assert result["artifact_validation"] == "docker-load"
    assert any(command[0] == "copa" and "--scanner" in command for command, _ in calls)
    phases = [json.loads(line)["phase"] for line in (output / "patch-events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert phases == [
        "acquiring_image", "scanning_source", "patching_image",
        "scanning_patched", "preparing_output", "completed",
    ]
    trust_copies = [command for command, _ in calls if command[:2] == ["docker", "cp"]]
    assert any("cats-patch-ca-bundle.pem" in " ".join(command) for command in trust_copies)
    assert not any("cats-custom-ca.pem" in " ".join(command) for command in trust_copies)


def test_private_ca_and_internal_mirror_reach_target_before_copa(monkeypatch, tmp_path: Path):
    config = {
        "job_id": "job-private-ca", "source_mode": "oci",
        "source_image": "docker.io/library/alpine:3.20", "output_mode": "download",
        "trusted_ca_certificates": [{"pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}],
        "repository_policies": {"alpine": {"mode": "custom", "url": "https://mirror.example.invalid/alpine/v3.20/main"}},
    }
    code, output, state, calls = run_worker(
        monkeypatch, tmp_path, config, grype_report([("CVE-1", "openssl", ["2"])]) , grype_report([]), source_credentials=("", ""),
    )
    assert code == 0 and state["status"] == "complete"
    rendered = [" ".join(command) for command, _ in calls]
    custom_copy = next(index for index, command in enumerate(rendered) if "cats-custom-ca.pem" in command and "docker cp" in command)
    trust_install = next(index for index, command in enumerate(rendered) if "docker exec" in command and "cats-patch-ca-bundle.pem" in command)
    repository_copy = next(index for index, command in enumerate(rendered) if "docker cp" in command and "cats-repository" in command)
    copa = next(index for index, command in enumerate(rendered) if command.startswith("copa patch"))
    assert custom_copy < trust_install < repository_copy < copa
    durable_text = (output / "patch-state.json").read_text(encoding="utf-8") + (output / "patch.log").read_text(encoding="utf-8")
    assert "BEGIN CERTIFICATE" not in durable_text and "MIIB" not in durable_text


def test_uploaded_tar_to_independent_oci_destination(monkeypatch, tmp_path: Path):
    archive = tmp_path / "uploaded.tar"
    make_image_tar(archive)
    config = {
        "job_id": "job2", "source_mode": "upload", "archive_path": str(archive),
        "output_mode": "push", "destination_image": "registry.example/approved/api:patched",
    }
    before = grype_report([("CVE-1", "openssl", ["2.0"])])
    after = grype_report([])
    code, output, state, calls = run_worker(monkeypatch, tmp_path, config, before, after)
    assert code == 0 and state["status"] == "complete"
    logins = [(command, stdin) for command, stdin in calls if command[:2] == ["docker", "login"]]
    assert logins[-1][0][2] == "registry.example"
    assert "destination-secret" not in logins[-1][0]
    assert logins[-1][1] == "destination-secret\n"
    assert any(command[:2] == ["docker", "push"] for command, _ in calls)
    post_scan = next(index for index, (command, _) in enumerate(calls) if command and command[0] == "grype" and command[1].startswith("dir:"))
    destination_tag = next(index for index, (command, _) in enumerate(calls) if command[:2] == ["docker", "tag"] and command[-1] == config["destination_image"])
    assert post_scan < destination_tag
    assert calls[destination_tag][0][2].startswith("cats-canonical-")
    assert not any(path.name == "docker-config" for path in output.rglob("docker-config"))


def test_failed_job_redacts_and_cleans_credentials(monkeypatch, tmp_path: Path):
    config = {"job_id": "job3", "source_mode": "oci", "source_image": "private.example/api:1", "output_mode": "download"}
    code, output, state, _ = run_worker(monkeypatch, tmp_path, config, grype_report([]), grype_report([]), fail_on="grype")
    assert code == 1 and state["status"] == "failed" and state["phase"] == "scanning_source"
    assert state["failed_stage"] == "scanning_source"
    assert state["stages"]["acquiring_image"]["status"] == "success"
    assert state["stages"]["scanning_source"]["status"] == "failed"
    assert state["stages"]["patching_image"]["reason"] == "not_reached"
    assert "super-secret" not in state["error"]
    assert "super-secret" not in (output / "patch.log").read_text(encoding="utf-8")
    assert not any(path.name == "docker-config" for path in output.rglob("docker-config"))


def test_corrupt_materialized_artifact_fails_patched_scan_stage(monkeypatch, tmp_path: Path):
    config = {"job_id": "job-corrupt", "source_mode": "oci", "source_image": "docker.io/library/alpine:3.20", "output_mode": "download"}
    code, output, state, _ = run_worker(
        monkeypatch, tmp_path, config, grype_report([("CVE-1", "openssl", ["2"])]) , grype_report([]),
        source_credentials=("", ""), corrupt_archive=True,
    )
    assert code == 1 and state["failed_stage"] == "scanning_patched"
    assert state["stages"]["patching_image"]["status"] == "success"
    assert "materialization failure" in state["error"].lower()


def test_post_patch_rootfs_scan_failure_never_falls_back_to_image_sources(monkeypatch, tmp_path: Path):
    config = {"job_id": "job-postscan", "source_mode": "oci", "source_image": "docker.io/library/alpine:3.20", "output_mode": "download"}
    code, _, state, calls = run_worker(
        monkeypatch, tmp_path, config, grype_report([("CVE-1", "openssl", ["2"])]) , grype_report([]),
        fail_on="dir:", source_credentials=("", ""),
    )
    assert code == 1 and state["failed_stage"] == "scanning_patched"
    assert state["stages"]["patching_image"]["status"] == "success"
    target = next(command[1] for command, _ in calls if command and command[0] == "grype" and command[1].startswith("dir:"))
    assert all(scheme not in target for scheme in ("docker-archive:", "docker:", "podman:", "containerd:", "registry:"))


def test_output_archive_must_complete_docker_load_round_trip(monkeypatch, tmp_path: Path):
    config = {"job_id": "job-load-check", "source_mode": "oci", "source_image": "docker.io/library/alpine:3.20", "output_mode": "download"}
    code, _, state, calls = run_worker(
        monkeypatch, tmp_path, config, grype_report([("CVE-1", "openssl", ["2"])]) , grype_report([]),
        fail_on="docker load --input", source_credentials=("", ""),
    )
    assert code == 1 and state["failed_stage"] == "scanning_patched"
    assert any(command[:2] == ["docker", "load"] and "patched-image.tar" in " ".join(command) for command, _ in calls)
    assert not any(command[0] == "grype" and command[1].startswith("dir:") for command, _ in calls)


def test_push_failure_keeps_validated_download_and_fails_push_stage(monkeypatch, tmp_path: Path):
    config = {"job_id": "job-push-fail", "source_mode": "oci", "source_image": "docker.io/library/alpine:3.20", "output_mode": "push", "destination_image": "registry.example/team/alpine:patched"}
    code, output, state, _ = run_worker(
        monkeypatch, tmp_path, config, grype_report([("CVE-1", "openssl", ["2"])]) , grype_report([]), fail_on="docker push",
    )
    result = json.loads((output / "patch-result.json").read_text(encoding="utf-8"))
    assert code == 1 and state["failed_stage"] == "pushing_image"
    assert state["stages"]["preparing_output"]["status"] == "success"
    assert state["stages"]["pushing_image"]["status"] == "failed"
    assert state["stages"]["completed"] == {"status": "skipped", "reason": "not_reached"}
    assert result["artifact_available"] is True and result["delivery_status"] == "failed"


def test_stage_snapshot_survives_memory_loss_and_refresh(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(portal_main, "PATCH_JOB_ROOT", tmp_path)
    portal_main.PATCH_JOBS.clear()
    job_id = "refreshjob"
    portal_main.PATCH_JOBS[job_id] = {
        "job_id": job_id, "status": "queued", "phase": "queued",
        "output_mode": "download", "stages": initial_patch_stages("download"),
    }
    for phase in ("acquiring_image", "scanning_source", "patching_image", "scanning_patched"):
        portal_main._patch_job_update(job_id, status="running", phase=phase)
    portal_main._patch_job_update(job_id, status="failed", phase="scanning_patched")
    expected = dict(portal_main.PATCH_JOBS[job_id]["stages"])
    portal_main.PATCH_JOBS.clear()
    restored = portal_main._load_patch_job(job_id)
    assert restored["status"] == "failed" and restored["stages"] == expected
    assert restored["stages"]["patching_image"]["status"] == "success"


def test_worker_service_removes_ephemeral_job_inputs(monkeypatch, tmp_path: Path):
    class FinishedProcess:
        def wait(self):
            return 0

    job_root = tmp_path / "jobs"
    input_root = job_root / "job4" / "input"
    input_root.mkdir(parents=True)
    (input_root / "uploaded-image.tar").write_bytes(b"temporary-image")
    config_path = job_root / "job4" / "job-config.json"
    config_path.write_text('{"source_image":"private.example/api:1"}', encoding="utf-8")
    secrets = ["source-secret", "destination-secret"]

    monkeypatch.setattr(patch_service, "JOB_ROOT", job_root)
    patch_service.PROCESSES["job4"] = FinishedProcess()
    patch_service._watch("job4", patch_service.PROCESSES["job4"], secrets)

    assert secrets == ["", ""]
    assert not input_root.exists()
    assert not config_path.exists()
    assert "job4" not in patch_service.PROCESSES
