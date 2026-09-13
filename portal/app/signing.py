"""Portal-owned, local-key signing. Secrets never belong in patch job files."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .secrets import decrypt_secret, encrypt_secret

SETTING = "image_signing"
MAX_KEY_BYTES = 32 * 1024
SECRET_ENV = ("CATS_SIGNING_PRIVATE_KEY", "CATS_SIGNING_PASSWORD")


def configuration(settings: dict) -> dict:
    try:
        value = json.loads(settings.get(SETTING) or "{}")
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (TypeError, ValueError) as exc:
        raise ValueError("Image signing configuration is invalid; an administrator must repair it.") from exc


def public_metadata(settings: dict) -> dict:
    try:
        value = configuration(settings)
    except ValueError:
        return {"enabled": True, "configured": False, "error": "Signing configuration is invalid. Upload a key pair to repair it; publishing is blocked."}
    return {"enabled": value.get("enabled") is True, "configured": bool(value.get("private_key")),
            "fingerprint": value.get("fingerprint", ""), "updated_at": value.get("updated_at", "")}


def public_key(pem: bytes) -> tuple[str, str]:
    key = serialization.load_pem_public_key(pem)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    normalized = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return normalized, "sha256:" + hashlib.sha256(der).hexdigest()


def clean_environment(env: dict) -> dict:
    # Do not let inherited Cosign configuration redirect signatures or select
    # another identity. Only our local keys and destination registry are used.
    return {k: v for k, v in env.items() if not k.startswith(("COSIGN_", "CATS_SIGNING_"))}


def _command(args: list[str], env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(args, env=env, capture_output=True, text=True, timeout=180, check=True,
                          stdin=subprocess.DEVNULL)


def validate_keys(private: bytes, supplied_public: bytes, password: str) -> tuple[str, str]:
    if not private or len(private) > MAX_KEY_BYTES or len(supplied_public) > MAX_KEY_BYTES:
        raise ValueError("Upload a Cosign private key and public key, each no larger than 32 KiB.")
    if not private.lstrip().startswith((b"-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----", b"-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----", b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----")):
        raise ValueError("Upload a PEM Cosign private key file.")
    cosign = shutil.which("cosign")
    if not cosign:
        raise ValueError("Cosign is unavailable in the portal image. Rebuild with the signing tool installed.")
    try:
        with tempfile.TemporaryDirectory(prefix="cats-key-check-") as folder:
            key = Path(folder) / "cosign.key"
            key.write_bytes(private)
            key.chmod(0o600)
            env = clean_environment(dict(os.environ))
            env["COSIGN_PASSWORD"] = password
            derived = _command([cosign, "public-key", "--key", str(key)], env).stdout.encode()
            normalized, fingerprint = public_key(derived)
            if supplied_public and public_key(supplied_public)[1] != fingerprint:
                raise ValueError("The uploaded public key does not match the private key.")
            return normalized, fingerprint
    except ValueError:
        raise
    except Exception as exc:
        # Tool errors can contain sensitive input; never return their output.
        raise ValueError("Unable to unlock the Cosign key. Check the private key and password.") from exc


def store_keys(private: bytes, supplied_public: bytes, password: str, enabled: bool) -> dict:
    pem, fingerprint = validate_keys(private, supplied_public, password)
    return {"enabled": enabled, "private_key": encrypt_secret(base64.b64encode(private).decode()),
            "password": encrypt_secret(password) if password else "", "public_key": pem,
            "fingerprint": fingerprint, "updated_at": datetime.now(timezone.utc).isoformat()}


def job_material(settings: dict, output_mode: str) -> tuple[dict, dict]:
    if output_mode != "push":
        return {}, {}
    value = configuration(settings)
    if value.get("enabled") is not True:
        return {}, {}
    try:
        private = decrypt_secret(value["private_key"])
        pem, fingerprint = public_key(value["public_key"].encode())
        if not private or fingerprint != value["fingerprint"]:
            raise ValueError()
        password = decrypt_secret(value["password"]) if value.get("password") else ""
    except Exception as exc:
        raise ValueError("Signing keys could not be loaded. An administrator must repair Configuration before publishing.") from exc
    return {"signing_enabled": True, "signing_public_key": pem, "signing_fingerprint": fingerprint}, {
        SECRET_ENV[0]: private, SECRET_ENV[1]: password}


def sign_and_verify(reference: str, config: dict, credentials: dict, env: dict) -> dict:
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", reference or "") or reference.startswith("-"):
        raise RuntimeError("Signing requires the immutable digest returned by the registry push.")
    cosign = shutil.which("cosign")
    if not cosign:
        raise RuntimeError("Image signing is required but Cosign is unavailable in the patch worker.")
    try:
        with tempfile.TemporaryDirectory(prefix="cats-sign-") as folder:
            key, pub = Path(folder) / "cosign.key", Path(folder) / "cosign.pub"
            key.write_bytes(base64.b64decode(credentials[SECRET_ENV[0]], validate=True))
            key.chmod(0o600)
            pem, fingerprint = public_key(config["signing_public_key"].encode())
            if fingerprint != config["signing_fingerprint"]:
                raise ValueError("Fingerprint mismatch")
            pub.write_text(pem, encoding="utf-8")
            signing_env = clean_environment(env)
            signing_env["COSIGN_PASSWORD"] = credentials.get(SECRET_ENV[1], "")
            _command([cosign, "sign", "--yes", "--key", str(key), "--tlog-upload=false", reference], signing_env)
            key.unlink()
            signing_env.pop("COSIGN_PASSWORD", None)
            _command([cosign, "verify", "--key", str(pub), "--insecure-ignore-tlog=true", "--offline", reference], signing_env)
            version = _command([cosign, "version", "--json"], signing_env)
            try:
                generator_version = json.loads(version.stdout).get("gitVersion", "unknown")
            except (ValueError, AttributeError):
                generator_version = "unknown"
            return {"signature_status": "verified", "signature": {"image": reference, "key_fingerprint": fingerprint,
                    "verified_at": datetime.now(timezone.utc).isoformat(), "generator": "cosign",
                    "generator_version": generator_version, "transparency_log": False}}
    except Exception as exc:
        raise RuntimeError("The image was pushed, but Cosign signing or signature verification failed. Check the signing key and registry signature-write permissions.") from exc
