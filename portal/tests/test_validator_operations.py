import hashlib
import http.client
from types import SimpleNamespace

import pytest

from app import validator_api as api, validator_client, validator_operations as operations
from fastapi.testclient import TestClient


def test_operation_routes_require_authenticated_peer(monkeypatch):
    monkeypatch.setenv("CATS_VALIDATOR_CLIENT_FINGERPRINTS", "a" * 64)
    with TestClient(api.app, base_url="https://testserver") as client:
        for path in ("/api/v1/self-tests", "/api/v1/identity/csr", "/api/v1/identity/certificate"):
            assert client.post(path, json={}).status_code == 403


def test_self_test_uses_existing_engine_and_requires_complete_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "STATE_DIR", tmp_path)
    monkeypatch.setenv("CATS_KIND_NODE_IMAGE", "kindest/node@sha256:" + "a" * 64)
    monkeypatch.setattr(operations, "self_test_artifact", lambda job: object())
    result = {"status": "VERIFIED", "cleanup_status": "COMPLETE",
              "offline": {"network_isolated": True, "external_image_pulls": 0, "external_chart_fetches": 0},
              "helm_result": {"install": "PASS", "release_status": "DEPLOYED"}}
    class Engine:
        def __init__(self, config, runner):
            assert config.strict_sandbox_policy and config.require_local_images
            assert not config.allow_network_egress
        def validate_artifact(self, artifact, progress_callback):
            progress_callback("CLEANING_UP")
            return result
    monkeypatch.setattr(operations, "KindDeploymentValidator", Engine)
    for cleanup, cancelled, expected in (("COMPLETE", False, "PASSED"), ("FAILED", False, "FAILED"), ("COMPLETE", True, "CANCELLED")):
        job = "e" * 32
        api.JOBS[job] = {"validation_id": job, "cancel_requested": cancelled}
        result["cleanup_status"] = cleanup
        operations.execute_self_test(job)
        assert api.JOBS[job]["status"] == expected
        assert api.JOBS[job]["result"]["cleanup_status"] == cleanup
        assert job not in api.RUNNING
    api.JOBS.pop(job)


def test_tls_pin_is_checked_before_http_request(monkeypatch):
    import urllib.request
    events = []
    class Socket:
        def getpeercert(self, binary_form):
            events.append("peer")
            return b"wrong-server"
    def connect(connection):
        events.append("connect")
        connection.sock = Socket()
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", connect)
    monkeypatch.setattr(http.client.HTTPSConnection, "close", lambda connection: events.append("closed"))
    def do_open(handler, connection_type, request, **kwargs):
        connection = connection_type("validator", context=None)
        connection.connect()
        events.append("sent")
    monkeypatch.setattr(urllib.request.HTTPSHandler, "do_open", do_open)
    context = SimpleNamespace(cats_server_fingerprint="a" * 64)
    with pytest.raises(ValueError, match="differs from enrolled identity"):
        validator_client._request("https://validator/api/v1/identity/certificate", context, {"certificate": "secret"})
    assert events == ["connect", "peer", "closed"]


def test_health_rejects_another_enrolled_identity(monkeypatch):
    monkeypatch.setattr(validator_client, "_client_context", lambda *args: None)
    monkeypatch.setattr(validator_client, "_request", lambda *args: {
        "validator_id": "different", "protocol_versions": ["cats.validation/v2"]})
    with pytest.raises(ValueError, match="identity or protocol"):
        validator_client.health({"endpoint": "https://validator", "expected_validator_id": "enrolled"})


def test_rotation_uses_local_key_and_persists_live_reload(monkeypatch, tmp_path):
    import json
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    monkeypatch.setattr(api, "STATE_DIR", tmp_path)
    monkeypatch.setenv("CATS_VALIDATOR_ID", "validator-one")
    monkeypatch.setenv("CATS_VALIDATOR_HOST", "validator.example")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("CATS_VALIDATOR_CLIENT_CA", str(ca_path))
    csr = x509.load_pem_x509_csr(operations.create_csr("owner")["csr"].encode())
    leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(name)
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
    reloads = []
    monkeypatch.setattr(operations, "TLS_RELOAD", lambda certificate, key: reloads.append((certificate, key)))
    body = {"certificate": leaf.public_bytes(serialization.Encoding.PEM).decode()}
    with pytest.raises(ValueError, match="another authenticated client"):
        operations.install_certificate(body, "other")
    result = operations.install_certificate(body, "owner")
    assert result["certificate_fingerprint"] == leaf.fingerprint(hashes.SHA256()).hex()
    current = json.loads((tmp_path / "identity" / "current.json").read_text())
    assert reloads == [(current["certificate"], current["key"])]
    assert not (tmp_path / "identity" / "pending.json").exists()
    assert "PRIVATE KEY" not in json.dumps(result)


@pytest.mark.parametrize("tamper", [None, "changed", "extra", "missing", "symlink", "oversized"])
def test_self_test_artifact_verifies_exact_payload(monkeypatch, tmp_path, tamper):
    import json
    root = tmp_path / "payload"
    chart = root / "chart"
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text("name: self-test\nversion: 1.0.0\n")
    (root / "image.tar").write_bytes(b"local-image")
    manifest = {"chart": "chart", "archive": "image.tar", "image": "example@sha256:" + "a" * 64,
                "sha256": {"chart/Chart.yaml": hashlib.sha256((chart / "Chart.yaml").read_bytes()).hexdigest(),
                           "image.tar": hashlib.sha256(b"local-image").hexdigest()}}
    (root / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setenv("CATS_VALIDATOR_SELF_TEST_DIR", str(root))
    if tamper == "changed":
        (root / "image.tar").write_bytes(b"tampered")
    elif tamper == "extra":
        (root / "extra").write_bytes(b"undeclared")
    elif tamper == "missing":
        (root / "image.tar").unlink()
    elif tamper == "oversized":
        (root / "manifest.json").write_bytes(b"x" * (1024 * 1024 + 1))
    elif tamper == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"local-image")
        (root / "image.tar").unlink()
        try:
            (root / "image.tar").symlink_to(target)
        except OSError:
            pytest.skip("Windows account cannot create symlinks")
    if tamper:
        with pytest.raises((ValueError, FileNotFoundError)):
            operations.self_test_artifact("a" * 32)
    else:
        artifact = operations.self_test_artifact("a" * 32)
        assert artifact.offline and artifact.require_helm_lifecycle
        assert artifact.expected_images == [manifest["image"]]


def test_cancel_self_test_uses_authenticated_existing_job_route(monkeypatch):
    calls = []
    monkeypatch.setattr(validator_client, "_operation", lambda *args: calls.append(args) or {"cancel_requested": True})
    job = "a" * 32
    assert validator_client.self_test_cancel({}, job)["cancel_requested"]
    assert calls == [({}, "/api/v1/validations/" + job + "/cancel", {})]
    with pytest.raises(ValueError):
        validator_client.self_test_cancel({}, "../health")
