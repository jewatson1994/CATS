import hashlib
import ssl
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

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


@pytest.mark.parametrize("peer", ["enrolled", "another-validator", "wrong-hostname", "untrusted-client"])
def test_mtls_checks_enrollment_and_hostname_before_http_request(monkeypatch, tmp_path, peer):
    from cryptography.fernet import Fernet
    from app.managed_validator_pki import create_identity

    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    host = "wrong.example" if peer == "wrong-hostname" else "127.0.0.1"
    identity = create_identity("enrolled", host, "https://" + host)
    foreign = create_identity("another", "127.0.0.1", "https://127.0.0.1")
    server_identity = foreign if peer == "another-validator" else identity
    configuration = dict(identity["configuration"])
    if peer == "untrusted-client":
        configuration.update(client_certificate=foreign["configuration"]["client_certificate"],
                             client_key=foreign["configuration"]["client_key"])
    deployment = server_identity["deployment"]
    certificate = tmp_path / "server.pem"
    key = tmp_path / "server-key.pem"
    certificate.write_text(deployment["validator_certificate"])
    key.write_text(deployment["validator_key"])
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)
    server_context.load_verify_locations(cadata=deployment["client_ca"])
    server_context.verify_mode = ssl.CERT_REQUIRED
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    class Server(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            try:
                return server_context.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise

    # Real loopback TLS: no mocked connection or certificate verification.
    with Server(("127.0.0.1", 0), Handler) as server:
        server.timeout = 5
        worker = threading.Thread(target=server.handle_request, daemon=True)
        worker.start()
        try:
            context = validator_client._client_context(configuration, tmp_path)
            url = "https://127.0.0.1:" + str(server.server_port) + "/protected"
            if peer == "enrolled":
                assert validator_client._request(url, context, {"certificate": "secret"}) == {}
            else:
                with pytest.raises((urllib.error.URLError, ssl.SSLError)) as error:
                    validator_client._request(url, context, {"certificate": "secret"})
                reason = error.value.reason if isinstance(error.value, urllib.error.URLError) else error.value
                assert isinstance(reason, ssl.SSLError)
                if peer != "untrusted-client":
                    assert isinstance(reason, ssl.SSLCertVerificationError)
        finally:
            worker.join(timeout=6)
        assert not worker.is_alive()
    assert received == ([("/protected", b'{"certificate": "secret"}')] if peer == "enrolled" else [])


def test_health_rejects_another_enrolled_identity(monkeypatch):
    from app.managed_validators import health_checked, BootstrapError

    monkeypatch.setattr(validator_client, "_client_context", lambda *args: None)
    monkeypatch.setattr(validator_client, "_request", lambda *args: {
        "validator_id": "different", "ready": True, "request_schema_versions": ["cats.validation/v2"]})
    with pytest.raises(BootstrapError, match="identity verification failed"):
        health_checked({"endpoint": "https://validator", "expected_validator_id": "enrolled"}, "enrolled")


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


def test_cancel_self_test_uses_authenticated_v2_job_and_waits_for_cleanup(monkeypatch, tmp_path):
    declaration = {"schema_version": "cats.validation/v2", "request_id": "b" * 32,
                   "validation_type": "helm-chart", "service": {"id": "selftest", "version": "1"},
                   "artifact": {"reference": "selftest.zip", "digest": "sha256:" + "c" * 64},
                   "deployment": {"type": "helm"}}
    job = "a" * 32
    identity = {key: declaration[key] for key in ("schema_version", "request_id", "validation_type", "service", "artifact")}
    identity.update(artifact_digest=declaration["artifact"]["digest"], artifact_reference="selftest.zip",
                    validator_id="enrolled", validation_id=job)
    result = dict(identity, status="CANCELLED", cleanup_status="COMPLETE")
    states = iter([dict(identity, status="RUNNING", phase="CLEANING_UP"),
                   dict(identity, status="CANCELLED", phase="CANCELLED", result=result)])
    context = object()
    calls = []
    artifact = tmp_path / "selftest.zip"
    artifact.write_bytes(b"fixture")
    monkeypatch.setattr(validator_client, "_client_context", lambda *args: context)
    monkeypatch.setattr(validator_client.time, "sleep", lambda seconds: None)

    def request(url, actual_context, body=None, **kwargs):
        assert actual_context is context
        calls.append((url, body))
        if url.endswith("/cancel"):
            assert body == {}
            return {"cancel_requested": True}
        if url.endswith("/" + job):
            return next(states)
        assert kwargs == {"artifact_path": artifact, "declaration": declaration}
        return dict(identity, status="QUEUED")

    monkeypatch.setattr(validator_client, "_request", request)
    configuration = {"endpoint": "https://validator", "expected_validator_id": "enrolled"}
    phases = []
    assert validator_client.validate(configuration, declaration, phases.append, artifact_path=artifact,
                                     cancel_requested=lambda: True) == result
    endpoint = "https://validator/api/v2/validations"
    assert [url for url, body in calls] == [endpoint, endpoint + "/" + job + "/cancel",
                                           endpoint + "/" + job, endpoint + "/" + job]
    assert phases == ["CLEANING_UP", "CANCELLED"]
    calls.clear()
    with pytest.raises(ValueError, match="Invalid retained validation job identity"):
        validator_client.validate(configuration, declaration, artifact_path=artifact, resume_validation_id="../health")
    assert calls == []
