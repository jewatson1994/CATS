import asyncio
import hashlib
import ssl
from types import SimpleNamespace

import pytest

from app.validator_protocol import SCHEMA_VERSION, validate_package, strict_json_loads
from app import validator_client
from validator_server import MutualTLSH11Protocol


def package():
    return {"schema_version": SCHEMA_VERSION, "manifest": {"service_key": "test-service"},
            "artifact": {"source_files": {"Chart.yaml": "name: test"}}}


@pytest.mark.parametrize("field", [None, "service", "artifact_digest", "validation_type"])
def test_modern_client_binds_terminal_evidence(tmp_path, monkeypatch, field):
    request = {"schema_version": "cats.validation/v2", "request_id": "1" * 32, "validation_type": "helm-chart",
               "service": {"id": "test-service", "version": "1"},
               "artifact": {"reference": "chart.zip", "digest": "sha256:" + "a" * 64},
               "deployment": {"type": "helm"}}
    job = "a" * 32
    identity = {"schema_version": request["schema_version"], "request_id": request["request_id"],
                "validation_type": request["validation_type"], "service": request["service"],
                "artifact": request["artifact"], "artifact_reference": request["artifact"]["reference"],
                "artifact_digest": request["artifact"]["digest"]}
    result = {**identity, "validation_id": job, "status": "VERIFIED", "cleanup_status": "COMPLETE",
              "helm_result": {"install": "PASS", "release_status": "DEPLOYED",
                              "execution_mode": "HELM", "helm_release_verified": True}}
    if field:
        result[field] = "wrong"
    calls = []
    def transport(url, context, *args, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("/api/v2/validations"):
            return {**identity, "validation_id": job, "status": "QUEUED"}
        return {**identity, "validation_id": job,
                "status": "VERIFIED", "phase": "COMPLETE", "result": result}
    monkeypatch.setattr(validator_client, "_client_context", lambda *args: None)
    monkeypatch.setattr(validator_client, "_request", transport)
    path = tmp_path / "chart.zip"
    path.write_bytes(b"chart")
    if field:
        with pytest.raises(ValueError, match="different artifact or service version"):
            validator_client.validate({"endpoint": "https://validator"}, request, artifact_path=path)
    else:
        assert validator_client.validate({"endpoint": "https://validator"}, request, artifact_path=path) == result
    assert calls[0][1]["artifact_path"] == path


@pytest.mark.parametrize("path", ["", ".", "./Chart.yaml", "foo//bar", "foo/", "foo/../bar", "foo\\bar", "a\x00b", "a\nb", "a:b"])
def test_rejects_noncanonical_paths(path):
    value = package()
    value["artifact"]["source_files"] = {path: "text"}
    with pytest.raises(ValueError):
        validate_package(value)


@pytest.mark.parametrize("field,value", [("timeout_seconds", True), ("referenced_images", None),
                                        ("required_capabilities", False), ("unexpected", "x")])
def test_strict_manifest(field, value):
    payload = package()
    payload["manifest"][field] = value
    with pytest.raises(ValueError):
        validate_package(payload)


def test_bounds_all_package_data_and_strict_json():
    payload = package()
    payload["artifact"]["declared_resources"] = [{"large": "x" * 3000}]
    with pytest.raises(ValueError):
        validate_package(payload, max_bytes=1000)
    for text in ('{"key":1,"key":2}', '{"key":NaN}'):
        with pytest.raises(ValueError):
            strict_json_loads(text)


def test_transport_identity_comes_from_actual_ssl_peer(monkeypatch):
    from uvicorn.protocols.http.h11_impl import H11Protocol
    monkeypatch.setattr(H11Protocol, "connection_made", lambda self, transport: None)
    captured = {}
    async def app(scope, receive, send):
        captured.update(scope)
    protocol = object.__new__(MutualTLSH11Protocol)
    protocol.app = app
    peer = SimpleNamespace(getpeercert=lambda binary_form: b"actual-peer")
    transport = SimpleNamespace(get_extra_info=lambda key: peer)
    protocol.connection_made(transport)
    asyncio.run(protocol.app({"validator_peer_sha256": "forged"}, None, None))
    assert captured["validator_peer_sha256"] == hashlib.sha256(b"actual-peer").hexdigest()


def test_client_trust_uses_only_explicit_ca_and_private_key(tmp_path, monkeypatch):
    calls = {}
    class Context:
        def __init__(self, protocol):
            calls["protocol"] = protocol
        def load_verify_locations(self, **kwargs):
            calls["ca"] = kwargs
        def load_cert_chain(self, certificate, key):
            calls["key"] = key
    monkeypatch.setattr(validator_client.ssl, "SSLContext", Context)
    monkeypatch.setattr(validator_client, "decrypt_secret", lambda value: "PRIVATE KEY")
    validator_client._client_context({"ca_certificate": "CA", "client_certificate": "CERT", "client_key": "encrypted"}, tmp_path)
    assert calls["protocol"] == ssl.PROTOCOL_TLS_CLIENT
    assert calls["ca"] == {"cadata": "CA"}


@pytest.mark.parametrize("endpoint", ["http://host", "https://user:pass@host", "https://host\n", "https://host\\evil", "https://host:bad", "https://host?x=y"])
def test_client_rejects_unsafe_endpoint(endpoint):
    with pytest.raises(ValueError):
        validator_client._endpoint({"endpoint": endpoint})


def test_client_rejects_result_identifier_injection(tmp_path, monkeypatch):
    monkeypatch.setattr(validator_client, "_client_context", lambda *args: None)
    monkeypatch.setattr(validator_client, "_request", lambda *args: {"schema_version": SCHEMA_VERSION, "status": "QUEUED", "validation_id": "../health"})
    with pytest.raises(ValueError):
        validator_client.validate({"endpoint": "https://validator"}, package())


def test_request_disables_proxy_and_redirects(monkeypatch):
    import urllib.request
    handlers = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return b'{"ok":true}'
    class Opener:
        def open(self, request, timeout): return Response()
    def build(*items):
        handlers.extend(items)
        return Opener()
    monkeypatch.setattr(urllib.request, "build_opener", build)
    assert validator_client._request("https://validator/health", None) == {"ok": True}
    assert handlers[0].proxies == {}
    redirect = handlers[2]()
    with pytest.raises(ValueError):
        redirect.redirect_request(None, None, 302, "redirect", {}, "https://other")


@pytest.mark.parametrize("change", [
    {"validation_id": "b" * 32}, {"schema_version": "old"}, {"status": "UNKNOWN"},
    {"phase": "unsafe\nphase"}, {"result": []},
    {"result": {"status": "VERIFIED", "cleanup_status": "PENDING"}},
])
def test_client_rejects_invalid_result_state(monkeypatch, change):
    job_id = "a" * 32
    state = {"schema_version": SCHEMA_VERSION, "validation_id": job_id, "status": "VERIFIED",
             "phase": "COMPLETE", "result": {"status": "VERIFIED", "cleanup_status": "COMPLETE"}}
    state.update(change)
    responses = iter([{"schema_version": SCHEMA_VERSION, "validation_id": job_id, "status": "QUEUED"}, state])
    monkeypatch.setattr(validator_client, "_client_context", lambda *args: None)
    monkeypatch.setattr(validator_client, "_request", lambda *args: next(responses))
    with pytest.raises(ValueError):
        validator_client.validate({"endpoint": "https://validator"}, package())
