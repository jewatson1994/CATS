"""CATS client for the versioned mTLS deployment validator API."""

from __future__ import annotations

import json
import base64
import os
import re
from pathlib import Path
import ssl
import tempfile
import time
import urllib.parse
import urllib.request

from .secrets import decrypt_secret
from .validator_protocol import SCHEMA_VERSION, validate_package, validate_request, strict_json_loads


TERMINAL = {"NOT_VERIFIED", "VERIFIED", "PARTIALLY_VERIFIED", "COULD_NOT_VALIDATE", "FAILED", "ERROR", "CANCELLED", "TIMED_OUT"}


class ContractError(ValueError):
    """Report known contract field names without exposing response content."""

    def __init__(self, stage: str, fields: list[str]):
        self.stage = stage
        self.fields = tuple(sorted(set(fields)))
        super().__init__(f"Validator {stage} contract mismatch: {', '.join(self.fields)}")


def _client_context(configuration: dict, directory: Path) -> ssl.SSLContext:
    ca = str(configuration.get("ca_certificate") or "")
    certificate = str(configuration.get("client_certificate") or "")
    encrypted_key = str(configuration.get("client_key") or "")
    if not ca or not certificate or not encrypted_key:
        raise ValueError("Validator mTLS CA, client certificate, and key are required")
    key = decrypt_secret(encrypted_key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca)
    cert_path = directory / "client-cert.pem"
    key_path = directory / "client-key.pem"
    cert_path.write_text(certificate, encoding="utf-8")
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(key)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def _endpoint(configuration: dict) -> str:
    endpoint = str(configuration.get("endpoint") or "").rstrip("/")
    parsed = urllib.parse.urlparse(endpoint)
    if any(ord(c) < 33 or ord(c) == 127 for c in endpoint) or "\\" in endpoint or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or "%" in parsed.netloc:
        raise ValueError("Validator endpoint must be a credential-free HTTPS URL")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Invalid validator endpoint port") from exc
    return endpoint


def _request(url: str, context: ssl.SSLContext, body: dict | None = None, *, artifact_path=None, declaration=None) -> dict:
    payload = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    if artifact_path is not None:
        path = Path(artifact_path)
        def chunks():
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    yield chunk
        payload = chunks()
        headers = {"Content-Type": "application/octet-stream", "Content-Length": str(path.stat().st_size),
                   "X-CATS-Declaration": base64.urlsafe_b64encode(json.dumps(declaration).encode()).decode()}
    request = urllib.request.Request(url, data=payload, method="POST" if payload is not None else "GET",
        headers=headers)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("Validator redirected; configure its final endpoint explicitly")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect)
    with opener.open(request, timeout=600 if artifact_path is not None else 30) as response:
        result = response.read(8 * 1024 * 1024 + 1)
    if len(result) > 8 * 1024 * 1024:
        raise ValueError("Validator response exceeds size limit")
    parsed = strict_json_loads(result)
    if not isinstance(parsed, dict):
        raise ValueError("Validator response must be an object")
    return parsed


def health(configuration: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="cats-validator-client-") as root:
        context = _client_context(configuration, Path(root))
        return _request(_endpoint(configuration) + "/health", context)


def validate(configuration: dict, package: dict, progress_callback=None, *, artifact_path=None, cancel_requested=None, state_callback=None, resume_validation_id=None) -> dict:
    modern = package.get("schema_version") == "cats.validation/v2"
    (validate_request if modern else validate_package)(package)
    schema = package["schema_version"]
    identity = ({"schema_version": schema, "request_id": package["request_id"],
                 "validation_type": package["validation_type"], "service": package["service"],
                 "artifact_digest": package["artifact"]["digest"],
                 "artifact_reference": package["artifact"].get("reference"),
                 "artifact": {"reference": package["artifact"].get("reference"), "digest": package["artifact"]["digest"]}} if modern else {})
    expected_validator_id = configuration.get("expected_validator_id")
    if modern and expected_validator_id is not None:
        if not isinstance(expected_validator_id, str) or not expected_validator_id.strip():
            raise ValueError("Expected validator identity must be a non-empty string")
        identity["validator_id"] = expected_validator_id
    def bound(value):
        return all(key in value and value[key] == expected for key, expected in identity.items())
    if modern and ((package["validation_type"] == "oci") != (artifact_path is None)):
        raise ValueError("Binary artifacts require an upload; OCI references require a declaration")
    endpoint = _endpoint(configuration)
    with tempfile.TemporaryDirectory(prefix="cats-validator-client-") as root:
        context = _client_context(configuration, Path(root))
        if resume_validation_id is not None:
            if not modern or not re.fullmatch(r"[0-9a-f]{32}", str(resume_validation_id)):
                raise ValueError("Invalid retained validation job identity")
            job_id = resume_validation_id
        else:
            submitted = (_request(endpoint + "/api/v2/validations", context, artifact_path=artifact_path, declaration=package)
                         if modern and artifact_path is not None else
                         _request(endpoint + ("/api/v2/validations" if modern else "/api/v1/validations"), context, package))
            mismatches = [key for key, expected in identity.items() if key not in submitted or submitted[key] != expected]
            if submitted.get("schema_version") != schema:
                mismatches.append("schema_version")
            if not isinstance(submitted.get("validation_id"), str) or not re.fullmatch(r"[0-9a-f]{32}", submitted["validation_id"]):
                mismatches.append("validation_id")
            if submitted.get("status") != "QUEUED":
                mismatches.append("status")
            if mismatches:
                raise ContractError("upload acknowledgment", mismatches)
            job_id = str(submitted["validation_id"])
            if state_callback:
                state_callback(submitted)
        deadline = time.monotonic() + package.get("manifest", {}).get("timeout_seconds", 600) + 120
        last_phase = None
        cancellation_sent = False
        while time.monotonic() < deadline:
            if cancel_requested and cancel_requested() and not cancellation_sent:
                _request(endpoint + ("/api/v2/validations/" if modern else "/api/v1/validations/") + job_id + "/cancel", context, {})
                cancellation_sent = True
            state = _request(endpoint + ("/api/v2/validations/" if modern else "/api/v1/validations/") + urllib.parse.quote(job_id, safe=""), context)
            if not bound(state) or state.get("schema_version") != schema or state.get("validation_id") != job_id or state.get("status") not in TERMINAL | {"QUEUED", "RUNNING"}:
                raise ValueError("Validator returned an incompatible job state")
            phase = state.get("phase")
            if not isinstance(phase, str) or not re.fullmatch(r"[A-Z][A-Z_]{0,79}", phase):
                raise ValueError("Validator returned an invalid phase")
            if state_callback:
                state_callback(state)
            if state.get("phase") != last_phase:
                last_phase = state.get("phase")
                if progress_callback and last_phase:
                    progress_callback(last_phase)
            if state.get("status") in TERMINAL:
                result = state.get("result")
                if not isinstance(result, dict) or result.get("status") != state.get("status") or result.get("cleanup_status") not in {"COMPLETE", "FAILED", "NOT_REQUIRED"}:
                    raise ValueError("Validator terminal status and result disagree")
                if modern and (not bound(result) or result.get("validation_id") != job_id):
                    raise ValueError("Validator returned evidence for a different artifact or service version")
                if modern and package["validation_type"] == "helm-chart" and result.get("status") == "VERIFIED":
                    helm = result.get("helm_result") or {}
                    if not isinstance(helm, dict) or helm.get("install") != "PASS" or helm.get("release_status") != "DEPLOYED" or helm.get("execution_mode") != "HELM" or helm.get("helm_release_verified") is not True:
                        raise ValueError("Validator did not verify a successful Helm release")
                return result
            time.sleep(2)
        try:
            _request(endpoint + ("/api/v2/validations/" if modern else "/api/v1/validations/") + job_id + "/cancel", context, {})
        except Exception:
            # Remote failure cannot weaken TLS or make cleanup completion certain.
            pass
        raise TimeoutError("Validator did not return a terminal result before the deadline; cleanup must be verified")
