"""Ephemeral, additive trust bundles for outbound CATS tooling."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import ssl
import tempfile
from typing import Iterator, Mapping, Sequence


def additional_pem(certificates: Sequence[Mapping[str, object]] | None) -> str:
    """Return deterministic, de-duplicated administrator CA certificates."""
    rows: dict[str, str] = {}
    for item in certificates or ():
        pem = str(item.get("pem") or "").strip()
        fingerprint = str(item.get("fingerprint") or "").strip().lower()
        if pem and "BEGIN CERTIFICATE" in pem:
            rows[fingerprint or pem] = pem
    return "\n".join(rows[key] for key in sorted(rows)) + ("\n" if rows else "")


def _system_bundle() -> Path:
    candidates = [
        ssl.get_default_verify_paths().cafile,
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ]
    for value in candidates:
        if value and Path(value).is_file():
            return Path(value)
    try:
        import certifi
        value = Path(certifi.where())
        if value.is_file():
            return value
    except Exception:
        pass
    raise RuntimeError("System CA bundle is unavailable")


def write_additive_bundle(destination: Path, certificates: Sequence[Mapping[str, object]] | None) -> Path | None:
    """Write a private system-plus-admin bundle, or return None when unused."""
    custom = additional_pem(certificates)
    if not custom:
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    baseline = _system_bundle().read_text(encoding="utf-8")
    destination.write_text(baseline.rstrip() + "\n" + custom, encoding="utf-8")
    try:
        destination.chmod(0o600)
    except OSError:
        pass
    return destination


@contextmanager
def ephemeral_trust(certificates: Sequence[Mapping[str, object]] | None) -> Iterator[tuple[Path | None, dict[str, str]]]:
    """Yield an additive CA path and environment, then remove all material."""
    custom = additional_pem(certificates)
    if not custom:
        yield None, {}
        return
    with tempfile.TemporaryDirectory(prefix="cats-trust-") as folder:
        root = Path(folder)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
        bundle = write_additive_bundle(root / "ca-bundle.pem", certificates)
        assert bundle is not None
        value = str(bundle)
        yield bundle, {
            "SSL_CERT_FILE": value,
            "REQUESTS_CA_BUNDLE": value,
            "CURL_CA_BUNDLE": value,
            "GIT_SSL_CAINFO": value,
            "AWS_CA_BUNDLE": value,
            "NODE_EXTRA_CA_CERTS": value,
        }
