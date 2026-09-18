"""Administrative trust and package repository configuration helpers.

The values are intentionally plain, non-secret policy metadata. Repository
credentials are never accepted by these helpers; callers must keep them as
ephemeral job inputs.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509


_PEM_CERTIFICATE_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)
_PRIVATE_KEY_RE = re.compile(rb"-----BEGIN [^-]*PRIVATE KEY-----")

OS_DEFINITIONS = {
    "ubuntu": {"name": "Ubuntu", "package_manager": "apt"},
    "debian": {"name": "Debian", "package_manager": "apt"},
    "rhel": {"name": "RHEL", "package_manager": "dnf"},
    "rocky": {"name": "Rocky Linux", "package_manager": "dnf"},
    "almalinux": {"name": "AlmaLinux", "package_manager": "dnf"},
    "centos": {"name": "CentOS", "package_manager": "dnf"},
    "fedora": {"name": "Fedora", "package_manager": "dnf"},
    "alpine": {"name": "Alpine", "package_manager": "apk"},
}
PACKAGE_MANAGERS = {"apt", "dnf", "apk"}


def validate_os_definition(os_id: str, display_name: str, package_manager: str) -> tuple[bool, str]:
    key = (os_id or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", key):
        return False, "OS identifier must use lowercase letters, numbers, dot, underscore, or hyphen"
    if not (display_name or "").strip():
        return False, "OS display name is required"
    if package_manager not in PACKAGE_MANAGERS:
        return False, "Unsupported package manager"
    return True, "Valid"


def parse_json(value: str | None, fallback):
    try:
        parsed = json.loads(value or "")
        return parsed if isinstance(parsed, type(fallback)) else fallback
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def _der_bytes(value: bytes | bytearray | str) -> bytes:
    """Normalize DER returned by parsers that use bytes or hexadecimal text."""
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("Certificate DER data is invalid") from exc
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        # Some parser implementations return the hexadecimal representation as
        # bytes; recognize that form without corrupting binary DER bytes.
        try:
            encoded = raw.decode("ascii")
        except UnicodeDecodeError:
            return raw
        if encoded and len(encoded) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", encoded):
            try:
                return bytes.fromhex(encoded)
            except ValueError as exc:
                raise ValueError("Certificate DER data is invalid") from exc
        return raw
    raise ValueError("Certificate DER data is invalid")


def certificate_metadata(pem: bytes | str) -> dict:
    """Validate one PEM certificate and return non-sensitive display metadata."""
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    if not isinstance(pem, (bytes, bytearray)):
        raise ValueError("Certificate must be PEM encoded")
    pem = bytes(pem)
    if _PRIVATE_KEY_RE.search(pem):
        raise ValueError("Private keys are not accepted as trusted CA certificates")
    try:
        text = pem.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Certificate must be PEM encoded text") from exc
    if "BEGIN CERTIFICATE" not in text or "END CERTIFICATE" not in text:
        raise ValueError("Certificate must be PEM encoded")
    try:
        der = ssl.PEM_cert_to_DER_cert(text)
    except (ValueError, ssl.SSLError) as exc:
        raise ValueError("Certificate is not a valid PEM certificate") from exc
    der_bytes = _der_bytes(der)
    decoded = ssl._ssl._test_decode_cert  # type: ignore[attr-defined]
    # Decode through a temporary file because the stdlib decoder is path based.
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as fh:
        fh.write(pem); path = fh.name
    try:
        try:
            info = decoded(path)
        except (ValueError, ssl.SSLError, OSError) as exc:
            raise ValueError("Certificate is not a valid X.509 certificate") from exc
    finally:
        os.unlink(path)
    subject = ", ".join("=".join(pair) for part in info.get("subject", ()) for pair in part)
    issuer = ", ".join("=".join(pair) for part in info.get("issuer", ()) for pair in part)
    return {
        "fingerprint": hashlib.sha256(der_bytes).hexdigest(),
        "subject": subject or "Unknown",
        "issuer": issuer or "Unknown",
        "not_before": info.get("notBefore", ""),
        "not_after": info.get("notAfter", ""),
        "kind": "root" if subject and subject == issuer else "intermediate",
        "pem": text,
    }


def certificate_bundle_metadata(payload: bytes | str) -> list[dict]:
    """Validate every certificate in a PEM file, returning individual rows."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("Certificate bundle must be PEM encoded")
    payload = bytes(payload)
    if _PRIVATE_KEY_RE.search(payload):
        raise ValueError("Private keys are not accepted as trusted CA certificates")
    matches = list(_PEM_CERTIFICATE_RE.finditer(payload))
    if not matches:
        if b"BEGIN CERTIFICATE" in payload or b"END CERTIFICATE" in payload:
            raise ValueError("Certificate bundle contains a malformed certificate block")
        raise ValueError("Certificate bundle must contain one or more PEM certificates")
    remainder = _PEM_CERTIFICATE_RE.sub(b"", payload)
    if remainder.strip():
        raise ValueError("Certificate bundle contains non-certificate or malformed content")
    metadata = []
    for match in matches:
        # Validate every block before the caller persists any of them. A single
        # malformed block therefore rejects the entire upload atomically.
        item = certificate_metadata(match.group(0))
        try:
            certificate = x509.load_pem_x509_certificate(match.group(0))
            constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        except (ValueError, x509.ExtensionNotFound) as exc:
            raise ValueError("Trusted certificates must be X.509 CA certificates") from exc
        if not constraints.ca:
            raise ValueError("Trusted certificates must have CA basic constraints")
        metadata.append(item)
    return metadata


def merge_certificate_metadata(existing: list[dict], uploaded: list[dict]) -> list[dict]:
    """Append only new certificate fingerprints, preserving existing rows."""
    merged = list(existing)
    known = {item.get("fingerprint") for item in merged if isinstance(item, dict)}
    for item in uploaded:
        fingerprint = item.get("fingerprint") if isinstance(item, dict) else None
        if fingerprint and fingerprint not in known:
            merged.append(item)
            known.add(fingerprint)
    return merged


def policy_bool(value, default: bool = True) -> bool:
    """Decode persisted/form policy booleans without turning explicit false on."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def normalize_policy(policy: dict | None) -> dict:
    policy = policy if isinstance(policy, dict) else {}
    return {
        "mode": str(policy.get("mode") or "default").lower(),
        "url": str(policy.get("url") or ""),
        "verify_tls": policy_bool(policy.get("verify_tls"), True),
        "verify_packages": policy_bool(policy.get("verify_packages"), True),
    }


def validate_policy(os_id: str, mode: str, url: str = "", verify_tls=True, verify_packages=True) -> tuple[bool, str]:
    if not os_id.strip():
        return False, "OS identifier is required"
    if mode not in {"default", "custom"}:
        return False, "Repository mode must be Default or Custom"
    if mode == "custom":
        if not url.strip() or not url.strip().lower().startswith(("http://", "https://")):
            return False, "Custom repository URL must use HTTP or HTTPS"
    if not isinstance(policy_bool(verify_tls, None), bool) or not isinstance(policy_bool(verify_packages, None), bool):
        return False, "Repository verification settings are invalid"
    return True, "Valid"


def resolve_policy(os_id: str, policies: dict) -> dict:
    policy = policies.get(os_id.lower(), {}) if isinstance(policies, dict) else {}
    return normalize_policy(policy)


def test_repository(url: str, ca_bundle: str | None = None, timeout: int = 10) -> tuple[bool, str]:
    if not url:
        return False, "No repository URL configured"
    context = ssl.create_default_context()
    if ca_bundle:
        if "BEGIN CERTIFICATE" in ca_bundle:
            context.load_verify_locations(cadata=ca_bundle)
        else:
            context.load_verify_locations(cafile=ca_bundle)
    try:
        request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "CATS repository validator"})
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            if response.status >= 400:
                return False, f"Repository returned HTTP {response.status}"
        return True, "Repository reachable"
    except urllib.error.HTTPError as exc:
        return False, f"Repository returned HTTP {exc.code}"
    except ssl.SSLError:
        return False, "TLS verification failed"
    except urllib.error.URLError as exc:
        return False, f"Repository could not be reached: {exc.reason}"
    except TimeoutError:
        return False, "Repository connection timed out"


def write_repository_config(policy: dict, root: Path, os_id: str, manager: str) -> Path | None:
    """Write an ephemeral package-manager override for a patch workspace."""
    policy = normalize_policy(policy)
    if policy["mode"] != "custom" or not policy["url"]:
        return None
    root.mkdir(parents=True, exist_ok=True)
    url = policy["url"].rstrip("/")
    if manager == "apt":
        options = " [trusted=yes]" if not policy["verify_packages"] else ""
        path = root / "cats.list"; path.write_text(f"deb{options} {url} stable main\n", encoding="utf-8")
    elif manager == "dnf":
        path = root / "cats.repo"; path.write_text(
            f"[cats]\nname=CATS\nbaseurl={url}\nenabled=1\ngpgcheck={int(policy['verify_packages'])}\nsslverify={int(policy['verify_tls'])}\n",
            encoding="utf-8",
        )
    elif manager == "apk":
        path = root / "repositories"; path.write_text(url + "\n", encoding="utf-8")
    else:
        raise ValueError(f"Unsupported package manager: {manager}")
    return path
