"""CATS client for the versioned mTLS deployment validator API."""

from __future__ import annotations

import json
from pathlib import Path
import ssl
import tempfile
import time
import urllib.parse
import urllib.request

from .secrets import decrypt_secret
from .validator_protocol import SCHEMA_VERSION, validate_package


TERMINAL = {"VERIFIED", "PARTIALLY_VERIFIED", "COULD_NOT_VALIDATE", "FAILED", "ERROR", "CANCELLED", "TIMED_OUT"}


def _client_context(configuration: dict, directory: Path) -> ssl.SSLContext:
    ca = str(configuration.get("ca_certificate") or "")
    certificate = str(configuration.get("client_certificate") or "")
    encrypted_key = str(configuration.get("client_key") or "")
    if not ca or not certificate or not encrypted_key:
        raise ValueError("Validator mTLS CA, client certificate, and key are required")
    key = decrypt_secret(encrypted_key)
    context = ssl.create_default_context(cadata=ca)
    cert_path = directory / "client-cert.pem"
    key_path = directory / "client-key.pem"
    cert_path.write_text(certificate, encoding="utf-8")
    key_path.write_text(key, encoding="utf-8")
    key_path.chmod(0o600)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def _endpoint(configuration: dict) -> str:
    endpoint = str(configuration.get("endpoint") or "").rstrip("/")
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Validator endpoint must be a credential-free HTTPS URL")
    return endpoint


def _request(url: str, context: ssl.SSLContext, body: dict | None = None) -> dict:
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=payload, method="POST" if payload is not None else "GET",
        headers={"Content-Type": "application/json"} if payload is not None else {})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("Validator redirected; configure its final endpoint explicitly")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect)
    with opener.open(request, timeout=30) as response:
        result = response.read(8 * 1024 * 1024 + 1)
    if len(result) > 8 * 1024 * 1024:
        raise ValueError("Validator response exceeds size limit")
    return json.loads(result)


def health(configuration: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="cats-validator-client-") as root:
        context = _client_context(configuration, Path(root))
        return _request(_endpoint(configuration) + "/health", context)


def validate(configuration: dict, package: dict, progress_callback=None) -> dict:
    validate_package(package)
    endpoint = _endpoint(configuration)
    with tempfile.TemporaryDirectory(prefix="cats-validator-client-") as root:
        context = _client_context(configuration, Path(root))
        submitted = _request(endpoint + "/api/v1/validations", context, package)
        if submitted.get("schema_version") != SCHEMA_VERSION or not submitted.get("validation_id"):
            raise ValueError("Validator returned an incompatible response")
        job_id = str(submitted["validation_id"])
        deadline = time.monotonic() + package["manifest"]["timeout_seconds"] + 120
        last_phase = None
        while time.monotonic() < deadline:
            state = _request(endpoint + "/api/v1/validations/" + urllib.parse.quote(job_id, safe=""), context)
            if state.get("phase") != last_phase:
                last_phase = state.get("phase")
                if progress_callback and last_phase:
                    progress_callback(last_phase)
            if state.get("status") in TERMINAL:
                result = state.get("result") or {}
                if result.get("status") != state.get("status"):
                    raise ValueError("Validator terminal status and result disagree")
                return result
            time.sleep(2)
        raise TimeoutError("Validator did not return a terminal result before the deadline")
