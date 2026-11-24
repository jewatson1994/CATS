import json
from pathlib import Path

import pytest

from app.scan_registry_auth import RegistryConfigurationError, load_registry_credentials
from test_scan_worker_coordination import worker_harness


def test_absent_credentials_allow_anonymous_pulls(tmp_path, monkeypatch):
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    assert load_registry_credentials() == {}


def test_valid_credentials_are_preserved_without_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    credentials = {"auths": {"harbor.example": {"auth": "private-value"}}}
    (tmp_path / "config.json").write_text(json.dumps(credentials), encoding="utf-8")
    assert load_registry_credentials() == credentials
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("content", [b'{private-value', b'[]', b'{"auths": "private-value"}', b'\xff'])
def test_invalid_configuration_has_safe_error(tmp_path, monkeypatch, content):
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    (tmp_path / "config.json").write_bytes(content)
    with pytest.raises(RegistryConfigurationError) as error:
        load_registry_credentials()
    assert "config.json" in str(error.value)
    assert "private-value" not in str(error.value)


def test_unreadable_credentials_explain_host_permissions(monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("private-value")
    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(RegistryConfigurationError) as error:
        load_registry_credentials()
    assert "CATS_SCAN_REGISTRY_AUTH_SOURCE" in str(error.value)
    assert "700" in str(error.value) and "600" in str(error.value)
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize("valid", [True, False])
def test_preflight_checks_access_without_starting_worker(tmp_path, monkeypatch, capsys, valid):
    from app import scan_worker
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path))
    (tmp_path / "config.json").write_text('{}' if valid else 'private-value', encoding="utf-8")
    monkeypatch.setattr(scan_worker.sys, "argv", ["scan_worker", "--check-registry-auth"])
    def unexpected():
        pytest.fail("Preflight must not initialize or start the worker")
    monkeypatch.setattr(scan_worker, "initialize", unexpected)
    assert scan_worker.main() == (0 if valid else 1)
    output = capsys.readouterr()
    assert "private-value" not in output.out + output.err
    assert ("passed" in output.out) if valid else ("config.json" in output.err)


def test_service_scan_reports_preparation_error_before_scanner(worker_harness, monkeypatch):
    scan_worker, worker, job, _, calls, uploaded, processes, _, _ = worker_harness
    job["job"]["credential_policy"] = "service"
    def denied():
        raise RegistryConfigurationError("Registry credentials are unreadable; check host permissions.")
    monkeypatch.setattr(scan_worker, "load_registry_credentials", denied)
    with pytest.raises(RegistryConfigurationError):
        worker.execute(job)
    assert not processes and not uploaded
    failures = [kwargs["json"] for _, suffix, kwargs in calls if suffix.endswith("/failure")]
    assert len(failures) == 1
    assert failures[0]["category"] == "registry_authorization"
    assert "check host permissions" in failures[0]["reason"]
    assert "Scan preparation failed" in failures[0]["log_tail"]


def test_public_scan_does_not_read_service_credentials(worker_harness, monkeypatch):
    scan_worker, worker, job, _, _, uploaded, processes, _, _ = worker_harness
    def unexpected():
        pytest.fail("Public scans must not read service credentials")
    monkeypatch.setattr(scan_worker, "load_registry_credentials", unexpected)
    worker.execute(job)
    assert processes and uploaded


@pytest.mark.parametrize("prefix", ["registry.example", "*.example/platform", "registry.example/*", "ubuntu/library",
                                    "https://registry.example/platform", "registry.example/platform:latest",
                                    "user:pass@registry.example/platform", "registry.example:99999/platform"])
def test_invalid_topic_prefix_fails_closed(prefix, monkeypatch):
    from app.scan_registry_auth import topic_registry_prefixes
    monkeypatch.setenv("CATS_TOPIC_SCAN_REGISTRY_PREFIXES", prefix)
    with pytest.raises(RegistryConfigurationError, match="CATS_TOPIC_SCAN_REGISTRY_PREFIXES"):
        topic_registry_prefixes()


def test_topic_broker_scopes_aliases_ports_and_all_repositories_on_each_host(tmp_path, monkeypatch):
    from app.scan_registry_auth import topic_auth_entries, topic_credential_hosts
    first = "registry.example/platform/payments@sha256:" + "a" * 64
    second = "docker.io/team/api:1.0"
    images = [first, second, "busybox:latest", "other.example:5000/allowed/image:v2",
              "registry.example:443/platform-private/tool", "unknown.example/a/b"]
    monkeypatch.setenv("CATS_TOPIC_SCAN_REGISTRY_PREFIXES",
                       "registry.example/platform,docker.io/team,other.example:5000/allowed")
    (tmp_path / "images.txt").write_text("\n".join(images) + "\n")
    payload = {"job_kind": "scan", "image_list": "\n".join(images)}
    allowed = topic_credential_hosts({"job": payload, "topic_intake_verified": True}, tmp_path)
    assert allowed == {"other.example:5000"}
    creds = {"auths": {host: {"auth": host} for host in
              ("registry.example", "https://index.docker.io/v1/", "unknown.example",
               "other.example:5000", "https://other.example:5000/private", "http://other.example:5000")},
             "credsStore": "other", "credHelpers": {"unlisted.example": "helper"}}
    assert topic_auth_entries(creds, allowed) == {"other.example:5000": {"auth": "other.example:5000"}}
    monkeypatch.setenv("CATS_TOPIC_SCAN_REGISTRY_PREFIXES", "docker.io/library")
    alias = "registry-1.docker.io/busybox:latest"
    (tmp_path / "images.txt").write_text(alias + "\n")
    payload["image_list"] = alias
    assert not topic_credential_hosts({"job": payload, "topic_intake_verified": True}, tmp_path)
    # Docker Hub's config key and image-reference aliases use the same denial boundary.
    assert topic_auth_entries(creds, {"docker.io"}) == {"https://index.docker.io/v1/": {"auth": "https://index.docker.io/v1/"}}


@pytest.mark.parametrize("failure", ["unverified", "changed-inputs", "chart", "archive", "component", "compose"])
def test_topic_registry_credentials_require_bound_image_only_inputs(failure, tmp_path, monkeypatch):
    from app.scan_registry_auth import topic_credential_hosts
    ref = "registry.example/platform/payments:1"
    claim = {"topic_intake_verified": True, "job": {"job_kind": "scan", "image_list": ref}}
    monkeypatch.setenv("CATS_TOPIC_SCAN_REGISTRY_PREFIXES", "registry.example/platform")
    (tmp_path / "images.txt").write_text(ref if failure != "changed-inputs" else "registry.example/other:1")
    if failure == "unverified":
        claim["topic_intake_verified"] = False
    if failure == "chart":
        claim["job"]["chart_url"] = "oci://registry.example/outside/chart"
    if failure == "archive":
        (tmp_path / "image-archives").mkdir()
    if failure == "component":
        claim["job"]["definition_component"] = {"reference": "registry.example/outside"}
    if failure == "compose":
        claim["job"]["compose_enabled"] = True
    with pytest.raises(RegistryConfigurationError, match="Topic scan"):
        topic_credential_hosts(claim, tmp_path)


@pytest.mark.parametrize("opt_in", [True, False])
def test_topic_worker_uses_broker_auth_only_after_opt_in(worker_harness, tmp_path, monkeypatch, opt_in):
    from app import scan_artifacts
    scan_worker, worker, job, _, _, uploaded, _, _, _ = worker_harness
    ref = "registry.example/platform/payments:7"
    job["topic_intake_verified"] = True
    job["job"].update(credential_policy="topic", job_kind="scan", image_list=ref)
    inputs = tmp_path / "worker-input-source"
    (inputs / "charts" / "values.yaml").unlink()
    (inputs / "charts").rmdir()
    (inputs / "images.txt").write_text(ref + "\n")
    archive = tmp_path / "worker-input.tar.gz"
    scan_artifacts.pack(inputs, archive, {"job_id": job["job_id"]})
    job["input_digest"] = scan_artifacts.digest(archive)
    monkeypatch.setenv("CATS_TOPIC_SCAN_REGISTRY_PREFIXES", "registry.example/platform" if opt_in else "")
    reads = []
    def credentials():
        reads.append(True)
        return {"auths": {"registry.example": {"auth": "reader"}, "other.example": {"auth": "excluded"}}}
    monkeypatch.setattr(scan_worker, "load_registry_credentials", credentials)
    original = scan_worker.subprocess.Popen
    observed = []
    def capture(args, **kwargs):
        config = Path(kwargs["env"]["DOCKER_CONFIG"]) / "config.json"
        observed.append(json.loads(config.read_text()) if config.exists() else {})
        return original(args, **kwargs)
    monkeypatch.setattr(scan_worker.subprocess, "Popen", capture)
    worker.execute(job)
    assert uploaded and observed == ([{"auths": {"registry.example": {"auth": "reader"}}}] if opt_in else [{}])
    assert len(reads) == int(opt_in)
