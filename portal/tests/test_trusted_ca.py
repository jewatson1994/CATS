import os
from pathlib import Path

from app.trusted_ca import additional_pem, ephemeral_trust, write_additive_bundle


def test_additional_pem_is_deterministic_and_deduplicated():
    first = {"fingerprint": "b", "pem": "-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----"}
    second = {"fingerprint": "a", "pem": "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----"}
    value = additional_pem([first, second, first])
    assert value.index("\nA\n") < value.index("\nB\n")
    assert value.count("\nB\n") == 1


def test_ephemeral_trust_adds_system_roots_sets_consumers_and_cleans_up(monkeypatch, tmp_path: Path):
    system = tmp_path / "system.pem"
    system.write_text("SYSTEM ROOT\n", encoding="utf-8")
    monkeypatch.setattr("app.trusted_ca._system_bundle", lambda: system)
    cert = {"fingerprint": "abc", "pem": "-----BEGIN CERTIFICATE-----\nCUSTOM\n-----END CERTIFICATE-----"}
    with ephemeral_trust([cert]) as (bundle, env):
        assert bundle is not None and bundle.is_file()
        text = bundle.read_text(encoding="utf-8")
        assert "SYSTEM ROOT" in text and "CUSTOM" in text
        assert env["SSL_CERT_FILE"] == env["REQUESTS_CA_BUNDLE"] == str(bundle)
        assert env["NODE_EXTRA_CA_CERTS"] == str(bundle)
        folder = bundle.parent
    assert not folder.exists()


def test_ephemeral_trust_without_custom_ca_preserves_default_environment():
    with ephemeral_trust([]) as (bundle, env):
        assert bundle is None and env == {}


def test_write_additive_bundle_uses_private_permissions(monkeypatch, tmp_path: Path):
    system = tmp_path / "system.pem"
    system.write_text("SYSTEM\n", encoding="utf-8")
    monkeypatch.setattr("app.trusted_ca._system_bundle", lambda: system)
    output = write_additive_bundle(tmp_path / "private" / "bundle.pem", [{
        "fingerprint": "x", "pem": "-----BEGIN CERTIFICATE-----\nCUSTOM\n-----END CERTIFICATE-----",
    }])
    assert output and output.is_file()
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600


def test_oci_helm_pull_receives_additive_ca_file_and_environment(monkeypatch):
    from app import main

    observed = {}
    monkeypatch.setattr(main.shutil, "which", lambda name: "/usr/local/bin/helm")

    def run(command, **kwargs):
        observed.update(command=command, env=kwargs["env"])
        destination = Path(command[command.index("--destination") + 1])
        (destination / "chart.tgz").write_bytes(b"archive")
        return type("Completed", (), {"returncode": 0, "stderr": "", "stdout": ""})()

    monkeypatch.setattr(main.subprocess, "run", run)
    archives = main._download_oci_chart("oci://registry.example/team/chart", [{
        "fingerprint": "x", "pem": "-----BEGIN CERTIFICATE-----\nCUSTOM\n-----END CERTIFICATE-----",
    }])
    assert archives == [(b"archive", "chart.tgz")]
    ca_path = observed["command"][observed["command"].index("--ca-file") + 1]
    assert observed["env"]["SSL_CERT_FILE"] == ca_path
    assert not Path(ca_path).exists()
