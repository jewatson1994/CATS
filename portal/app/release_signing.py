"""Detached, offline signatures for release manifests, using portal signing keys.

The caller constructs the manifest (including documentation and artifact digests).
This module signs its exact bytes and never sends key material to patch workers.
"""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import signing

SIGNATURE_FILENAME = "release-manifest.sig"
PUBLIC_KEY_FILENAME = "release-public-key.pem"
FAILURE_REASON = "Release signature creation or offline verification failed. Check the signing key and local Cosign installation."


def _verify(cosign: str, manifest: Path, signature: Path, public: Path) -> None:
    signing._command([
        cosign, "verify-blob", "--key", str(public), "--signature", str(signature),
        "--insecure-ignore-tlog=true", "--offline", str(manifest),
    ], signing.clean_environment(dict(os.environ)))


def _signed_metadata(content: bytes, fingerprint: str) -> dict:
    return {"status": "signed", "signature_status": "verified", "key_fingerprint": fingerprint,
            "manifest_sha256": hashlib.sha256(content).hexdigest(),
            "signature_file": SIGNATURE_FILENAME, "public_key_file": PUBLIC_KEY_FILENAME,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "generator": "cosign", "transparency_log": False}


def verify_release_manifest(
    manifest_path: str | Path, signature_path: str | Path, public_key_path: str | Path,
    expected_fingerprint: str | None = None,
) -> dict:
    """Verify locally; pin expected_fingerprint to an independently trusted key.

Without a pinned fingerprint, verification proves only that the supplied key
signed the manifest, not the identity of the release publisher.
"""
    try:
        cosign = shutil.which("cosign")
        if not cosign:
            raise ValueError("Cosign unavailable")
        manifest, signature, public = map(Path, (manifest_path, signature_path, public_key_path))
        pem, fingerprint = signing.public_key(public.read_bytes())
        if expected_fingerprint is not None and fingerprint != expected_fingerprint:
            raise ValueError("Fingerprint mismatch")
        # Snapshot all inputs so the digest and reported key identify exactly
        # the bytes checked by Cosign, even if caller-owned files change.
        with tempfile.TemporaryDirectory(prefix="cats-release-verify-") as folder:
            root = Path(folder)
            content = manifest.read_bytes()
            (root / "manifest.json").write_bytes(content)
            (root / "manifest.sig").write_bytes(signature.read_bytes())
            (root / "public.pem").write_text(pem, encoding="utf-8")
            _verify(cosign, root / "manifest.json", root / "manifest.sig", root / "public.pem")
        return {"status": "verified", "key_fingerprint": fingerprint,
                "manifest_sha256": hashlib.sha256(content).hexdigest(),
                "generator": "cosign", "transparency_log": False}
    except Exception:
        # Tool output and exceptions can contain secrets. Keep them private.
        return {"status": "verification_failed", "reason": FAILURE_REASON}


def sign_release_manifest(
    manifest_path: str | Path, output_dir: str | Path,
    signing_material: tuple[dict, dict],
) -> dict:
    """Sign a release using the tuple returned by signing.job_material(..., 'push').

Only a verified detached signature and public key are written to output_dir.
The private key lives in a temporary directory and is deleted before verification.
Output names are relative basenames for embedding in release download metadata.
Complete existing outputs are reused only after verification against the current
key. An incomplete pair can be recreated when no signing.json receipt exists.
"""
    config, credentials = signing_material
    if config.get("signing_enabled") is not True:
        return {"status": "unsigned", "reason": "Release signing is not configured."}

    published: list[Path] = []
    try:
        cosign = shutil.which("cosign")
        if not cosign:
            raise ValueError("Cosign unavailable")
        source, destination = Path(manifest_path), Path(output_dir)
        content = source.read_bytes()
        pem, fingerprint = signing.public_key(config["signing_public_key"].encode())
        if fingerprint != config["signing_fingerprint"]:
            raise ValueError("Fingerprint mismatch")
        if any(path.is_symlink() for path in (destination, *destination.parents)):
            raise ValueError("Unsafe signing output path")
        targets = [destination / name for name in (SIGNATURE_FILENAME, PUBLIC_KEY_FILENAME)]
        if any(path.is_symlink() or (path.exists() and not path.is_file()) for path in targets):
            raise ValueError("Unsafe signing output file")
        retained = {path: path.read_bytes() for path in targets if path.exists()}
        if len(retained) == 2:
            verified = verify_release_manifest(source, *targets, expected_fingerprint=fingerprint)
            if (verified.get("status") != "verified"
                    or verified.get("manifest_sha256") != hashlib.sha256(content).hexdigest()
                    or source.read_bytes() != content
                    or any(path.read_bytes() != data for path, data in retained.items())):
                raise ValueError("Retained signature verification failed")
            return _signed_metadata(content, fingerprint)
        receipt = destination / "signing.json"
        if receipt.exists() or receipt.is_symlink():
            raise ValueError("Receipted signing outputs are incomplete")
        private = base64.b64decode(credentials[signing.SECRET_ENV[0]], validate=True)
        if not private or len(private) > signing.MAX_KEY_BYTES:
            raise ValueError("Invalid signing key")

        with tempfile.TemporaryDirectory(prefix="cats-release-sign-") as folder:
            root = Path(folder)
            key, public = root / "cosign.key", root / PUBLIC_KEY_FILENAME
            manifest, signature = root / "manifest.json", root / SIGNATURE_FILENAME
            manifest.write_bytes(content)
            public.write_text(pem, encoding="utf-8")
            # Create with restrictive permissions from the outset on POSIX.
            descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(private)
            env = signing.clean_environment(dict(os.environ))
            env["COSIGN_PASSWORD"] = credentials.get(signing.SECRET_ENV[1], "")
            try:
                signing._command([
                    cosign, "sign-blob", "--yes", "--key", str(key),
                    "--tlog-upload=false", "--output-signature", str(signature), str(manifest),
                ], env)
            finally:
                key.unlink(missing_ok=True)
                env.pop("COSIGN_PASSWORD", None)
            _verify(cosign, manifest, signature, public)
            if source.read_bytes() != content:
                raise ValueError("Manifest changed while signing")
            detached = signature.read_bytes()
            if not detached:
                raise ValueError("Empty signature")
            destination.mkdir(parents=True, exist_ok=True)
            # Only incomplete, unreceipted outputs may be replaced, and only
            # after the replacement signature has independently verified.
            if receipt.exists() or receipt.is_symlink():
                raise ValueError("Signing receipt appeared during signing")
            if any(path.exists() or path.is_symlink() for path in targets if path not in retained):
                raise ValueError("Signing outputs appeared during signing")
            for target, data in retained.items():
                if target.is_symlink() or target.read_bytes() != data:
                    raise ValueError("Signing outputs changed during signing")
                target.unlink()
            for name, data in ((SIGNATURE_FILENAME, detached), (PUBLIC_KEY_FILENAME, pem.encode())):
                target = destination / name
                with target.open("xb") as stream:
                    published.append(target)
                    stream.write(data)
        return _signed_metadata(content, fingerprint)
    except Exception:
        for target in published:
            target.unlink(missing_ok=True)
        return {"status": "verification_failed", "reason": FAILURE_REASON}
