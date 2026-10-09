"""Offline release signature checks, including real local cryptography."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import release_signing, signing


@pytest.fixture
def release(tmp_path):
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(json.dumps({"documentation": {"sha256": "a" * 64},
                                    "artifacts": [{"image": "registry.example/app@sha256:" + "b" * 64}]}))
    return manifest, tmp_path / "output"


@pytest.fixture
def crypto_cli(monkeypatch):
    """Use actual ECDSA for the unavailable CLI; assert the offline command contract."""
    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())
    public, fingerprint = signing.public_key(pem)
    calls, key_paths = [], []
    monkeypatch.setattr(release_signing.shutil, "which", lambda _: "cosign")
    monkeypatch.setenv("COSIGN_REPOSITORY", "must-not-use")
    monkeypatch.setenv("COSIGN_PASSWORD", "inherited-secret")
    monkeypatch.setenv("CATS_SIGNING_PRIVATE_KEY", "inherited-key")

    def command(args, env):
        calls.append(args)
        assert "COSIGN_REPOSITORY" not in env and "CATS_SIGNING_PRIVATE_KEY" not in env
        key = Path(args[args.index("--key") + 1])
        data = Path(args[-1]).read_bytes()
        if args[1] == "sign-blob":
            assert "--tlog-upload=false" in args and "--yes" in args
            assert env["COSIGN_PASSWORD"] == "test-password"
            key_paths.append(key)
            loaded = serialization.load_pem_private_key(key.read_bytes(), None)
            signature = loaded.sign(data, ec.ECDSA(hashes.SHA256()))
            Path(args[args.index("--output-signature") + 1]).write_bytes(base64.b64encode(signature))
        else:
            assert args[1] == "verify-blob"
            assert "--offline" in args and "--insecure-ignore-tlog=true" in args
            assert "COSIGN_PASSWORD" not in env
            assert all(not path.exists() for path in key_paths)
            loaded = serialization.load_pem_public_key(key.read_bytes())
            signature = Path(args[args.index("--signature") + 1]).read_bytes()
            loaded.verify(base64.b64decode(signature, validate=True), data, ec.ECDSA(hashes.SHA256()))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(signing, "_command", command)
    config = {"signing_enabled": True, "signing_public_key": public, "signing_fingerprint": fingerprint}
    credentials = {signing.SECRET_ENV[0]: base64.b64encode(private_pem).decode(),
                   signing.SECRET_ENV[1]: "test-password"}
    return (config, credentials), calls, key_paths


def test_sign_and_verify_exact_manifest_bytes(release, crypto_cli):
    manifest, output = release
    material, calls, key_paths = crypto_cli
    result = release_signing.sign_release_manifest(manifest, output, material)
    assert result["status"] == "signed" and result["signature_status"] == "verified"
    assert result["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert result["key_fingerprint"] == material[0]["signing_fingerprint"]
    assert [args[1] for args in calls] == ["sign-blob", "verify-blob"]
    assert sorted(path.name for path in output.iterdir()) == ["release-manifest.sig", "release-public-key.pem"]
    assert all(not path.parent.exists() for path in key_paths)
    verification = release_signing.verify_release_manifest(manifest, output / result["signature_file"],
                                                         output / result["public_key_file"], result["key_fingerprint"])
    assert verification["status"] == "verified"


@pytest.mark.parametrize("tamper", ["manifest", "documentation_digest", "signature", "public_key", "fingerprint"])
def test_verification_rejects_tampering(release, crypto_cli, tamper):
    manifest, output = release
    material, _, _ = crypto_cli
    result = release_signing.sign_release_manifest(manifest, output, material)
    signature, public = output / result["signature_file"], output / result["public_key_file"]
    fingerprint = result["key_fingerprint"]
    if tamper == "manifest":
        manifest.write_bytes(manifest.read_bytes().replace(b"registry.example", b"attacker.example"))
    elif tamper == "documentation_digest":
        manifest.write_bytes(manifest.read_bytes().replace(b"a" * 64, b"c" * 64))
    elif tamper == "signature":
        signature.write_bytes(base64.b64encode(b"invalid-signature"))
    elif tamper == "public_key":
        public.write_bytes(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    else:
        fingerprint = "sha256:" + "0" * 64
    assert release_signing.verify_release_manifest(manifest, signature, public, fingerprint)["status"] == "verification_failed"


def test_signer_rejects_private_and_public_key_mismatch(release, crypto_cli):
    manifest, output = release
    material, _, key_paths = crypto_cli
    other_public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem, fingerprint = signing.public_key(other_public)
    material[0].update(signing_public_key=pem, signing_fingerprint=fingerprint)
    assert release_signing.sign_release_manifest(manifest, output, material)["status"] == "verification_failed"
    assert not output.exists()
    assert all(not path.parent.exists() for path in key_paths)


def test_disabled_signing_does_not_access_keys_or_files(tmp_path, monkeypatch):
    monkeypatch.setattr(release_signing.shutil, "which", lambda _: pytest.fail("No tool needed"))
    result = release_signing.sign_release_manifest(tmp_path / "missing.json", tmp_path / "output", ({}, {}))
    assert result["status"] == "unsigned"
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("failure", ["sign-blob", "verify-blob", "missing-tool", "bad-fingerprint", "changed-manifest"])
def test_signing_failure_is_safe_and_retains_no_output(release, crypto_cli, monkeypatch, failure):
    manifest, output = release
    material, _, key_paths = crypto_cli
    command = signing._command

    def fail(args, env):
        if args[1] == failure:
            if args[1] == "sign-blob":
                key_paths.append(Path(args[args.index("--key") + 1]))
            raise subprocess.CalledProcessError(1, args, stderr="test-password PRIVATE-KEY")
        result = command(args, env)
        if failure == "changed-manifest" and args[1] == "verify-blob":
            manifest.write_bytes(b"changed")
        return result

    monkeypatch.setattr(signing, "_command", fail)
    if failure == "missing-tool":
        monkeypatch.setattr(release_signing.shutil, "which", lambda _: None)
    if failure == "bad-fingerprint":
        material[0]["signing_fingerprint"] = "sha256:" + "0" * 64
    result = release_signing.sign_release_manifest(manifest, output, material)
    assert result["status"] == "verification_failed"
    assert "test-password" not in json.dumps(result) and "PRIVATE-KEY" not in json.dumps(result)
    assert not output.exists() or not list(output.iterdir())
    assert all(not path.parent.exists() for path in key_paths)


@pytest.mark.parametrize("filename", [release_signing.PUBLIC_KEY_FILENAME, release_signing.SIGNATURE_FILENAME])
def test_partial_orphan_is_recreated_after_verification(release, crypto_cli, filename):
    manifest, output = release
    material, calls, _ = crypto_cli
    output.mkdir()
    (output / filename).write_bytes(b"interrupted-write")
    result = release_signing.sign_release_manifest(manifest, output, material)
    assert result["status"] == "signed"
    assert [args[1] for args in calls] == ["sign-blob", "verify-blob"]
    assert release_signing.verify_release_manifest(manifest, output / result["signature_file"],
        output / result["public_key_file"], result["key_fingerprint"])["status"] == "verified"


def test_complete_orphan_is_reverified_without_rewriting_or_loading_private_key(release, crypto_cli):
    manifest, output = release
    material, calls, _ = crypto_cli
    original = release_signing.sign_release_manifest(manifest, output, material)
    retained = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in output.iterdir()}
    calls.clear()
    result = release_signing.sign_release_manifest(manifest, output, (material[0], {}))
    assert result["status"] == "signed"
    assert result["manifest_sha256"] == original["manifest_sha256"]
    assert [args[1] for args in calls] == ["verify-blob"]
    assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in output.iterdir()} == retained


@pytest.mark.parametrize("tamper", ["manifest", "signature", "public_key", "current_key"])
def test_complete_tampered_or_untrusted_orphan_is_rejected_and_preserved(release, crypto_cli, tamper):
    manifest, output = release
    material, calls, _ = crypto_cli
    assert release_signing.sign_release_manifest(manifest, output, material)["status"] == "signed"
    if tamper == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    elif tamper == "signature":
        (output / release_signing.SIGNATURE_FILENAME).write_bytes(b"invalid")
    else:
        public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        if tamper == "public_key":
            (output / release_signing.PUBLIC_KEY_FILENAME).write_bytes(public)
        else:
            pem, fingerprint = signing.public_key(public)
            material[0].update(signing_public_key=pem, signing_fingerprint=fingerprint)
    retained = {path: path.read_bytes() for path in output.iterdir()}
    calls.clear()
    assert release_signing.sign_release_manifest(manifest, output, material)["status"] == "verification_failed"
    assert {path: path.read_bytes() for path in output.iterdir()} == retained
    assert all(args[1] == "verify-blob" for args in calls)


def test_partial_receipted_signature_is_preserved(release, crypto_cli):
    manifest, output = release
    material, calls, _ = crypto_cli
    output.mkdir()
    public = output / release_signing.PUBLIC_KEY_FILENAME
    public.write_bytes(b"historical-public-key")
    (output / "signing.json").write_text('{"status":"signed"}')
    retained = {path: path.read_bytes() for path in output.iterdir()}
    assert release_signing.sign_release_manifest(manifest, output, material)["status"] == "verification_failed"
    assert {path: path.read_bytes() for path in output.iterdir()} == retained
    assert not calls


def test_partial_orphan_is_preserved_if_replacement_verification_fails(release, crypto_cli, monkeypatch):
    manifest, output = release
    material, _, _ = crypto_cli
    output.mkdir()
    public = output / release_signing.PUBLIC_KEY_FILENAME
    public.write_bytes(b"interrupted-write")
    command = signing._command

    def fail_verification(args, env):
        if args[1] == "verify-blob":
            raise ValueError("verification failed")
        return command(args, env)

    monkeypatch.setattr(signing, "_command", fail_verification)
    assert release_signing.sign_release_manifest(manifest, output, material)["status"] == "verification_failed"
    assert public.read_bytes() == b"interrupted-write"
    assert not (output / release_signing.SIGNATURE_FILENAME).exists()


REAL_COSIGN = os.getenv("CATS_TEST_COSIGN") or shutil.which("cosign")


@pytest.mark.skipif(not REAL_COSIGN, reason="Cosign not installed; set CATS_TEST_COSIGN to test encrypted Cosign keys")
def test_real_cosign_encrypted_key_roundtrip(release, tmp_path, monkeypatch):
    monkeypatch.setattr(release_signing.shutil, "which", lambda _: REAL_COSIGN)
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    env = signing.clean_environment(dict(os.environ))
    env["COSIGN_PASSWORD"] = "temporary-test-password"
    prefix = tmp_path / "encrypted-key"
    subprocess.run([REAL_COSIGN, "generate-key-pair", "--output-key-prefix", str(prefix)], env=env,
                   check=True, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    private = prefix.with_suffix(".key").read_bytes()
    assert b"ENCRYPTED" in private
    saved = signing.store_keys(private, prefix.with_suffix(".pub").read_bytes(), env["COSIGN_PASSWORD"], True)
    material = signing.job_material({signing.SETTING: json.dumps(saved)}, "push")
    manifest, output = release
    result = release_signing.sign_release_manifest(manifest, output, material)
    assert result["status"] == "signed"
    signature, public = output / result["signature_file"], output / result["public_key_file"]
    assert release_signing.verify_release_manifest(manifest, signature, public, saved["fingerprint"])["status"] == "verified"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    assert release_signing.verify_release_manifest(manifest, signature, public, saved["fingerprint"])["status"] == "verification_failed"
