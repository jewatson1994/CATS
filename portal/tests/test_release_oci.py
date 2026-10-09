"""Exercise the distribution protocol against a disposable, authenticated TLS registry."""
import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import ssl
from threading import Thread
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from app import release_oci as oci


@pytest.fixture
def files(tmp_path):
    contents = {"documentation.zip": b"retained documentation archive",
                "release-manifest.json": b'{"release":"test"}',
                "release-manifest.sig": b"detached signature",
                "release-public-key.pem": b"public key",
                "VERIFY.txt": b"Verify manifest and archive before use."}
    for name, data in contents.items():
        (tmp_path / name).write_bytes(data)
    return {name: tmp_path / name for name in contents}


@pytest.fixture
def registry(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated test registry")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "ca.pem", tmp_path / "tls.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    auth = "Basic " + base64.b64encode(b"approved-user:secret-password").decode()
    subject_bytes = oci._json({"schemaVersion": 2, "mediaType": oci.MANIFEST_TYPE,
                               "config": {"mediaType": "example", "size": 2, "digest": oci._digest(b"{}")}, "layers": []})
    subject_digest = oci._digest(subject_bytes)
    state = SimpleNamespace(blobs={}, manifests={subject_digest: subject_bytes}, tags={}, referrers=True,
                            reject_subject=False, corrupt_blob=False, requests=[], bearer=False,
                            token_realm=None, upload_location=None, corrupt_manifest=False,
                            fail_manifest=False, auth=auth, subject_digest=subject_digest)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body=b"", **headers):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            for name, value in headers.items():
                self.send_header(name.replace("_", "-"), value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def route(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            authorization = self.headers.get("Authorization")
            state.requests.append((self.command, self.path, authorization))
            if path == "/token":
                if authorization != auth:
                    self.respond(403)
                    return
                assert parse_qs(parsed.query)["scope"] == ["repository:approved/release:pull,push"]
                self.respond(200, b'{"token":"isolated-token"}')
                return
            required = "Bearer isolated-token" if state.bearer else auth
            if authorization != required:
                realm = state.token_realm or state.base + "/token"
                self.respond(401, WWW_Authenticate=f'Bearer realm="{realm}",service="test",scope="repository:unrelated:push"')
                return
            if "/blobs/uploads/" in path:
                if self.command == "POST":
                    self.respond(202, Location=state.upload_location or "/v2/approved/release/blobs/uploads/test?state=preserved")
                elif self.command == "PUT":
                    query = parse_qs(parsed.query)
                    assert query["state"] == ["preserved"]
                    content = self.rfile.read(int(self.headers["Content-Length"]))
                    digest = query["digest"][0]
                    assert oci._digest(content) == digest
                    state.blobs[digest] = content
                    self.respond(201)
                return
            if "/blobs/" in path:
                digest = path.rsplit("/", 1)[1]
                if digest not in state.blobs:
                    self.respond(404)
                else:
                    content = state.blobs[digest]
                    if state.corrupt_blob and self.command == "GET":
                        content = b"!" * len(content)
                    self.respond(200, content)
                return
            if "/manifests/" in path:
                reference = path.rsplit("/", 1)[1]
                if self.command == "PUT":
                    content = self.rfile.read(int(self.headers["Content-Length"]))
                    document = json.loads(content)
                    if state.fail_manifest:
                        self.respond(503, b"secret registry debug information")
                    elif state.reject_subject and "subject" in document:
                        self.respond(400)
                    else:
                        digest = oci._digest(content)
                        state.manifests[digest] = content
                        state.tags[reference] = digest
                        self.respond(201, Docker_Content_Digest=digest)
                else:
                    digest = state.tags.get(reference, reference)
                    content = state.manifests.get(digest)
                    if content is None:
                        self.respond(404)
                    elif state.corrupt_manifest:
                        self.respond(200, b"{}", Content_Type=oci.MANIFEST_TYPE)
                    else:
                        self.respond(200, content, Content_Type=oci.MANIFEST_TYPE)
                return
            if "/referrers/" in path:
                if state.referrers:
                    descriptors = [{"digest": digest} for digest, body in state.manifests.items()
                                   if json.loads(body).get("subject", {}).get("digest") == subject_digest]
                    self.respond(200, oci._json({"schemaVersion": 2, "mediaType": oci.INDEX_TYPE, "manifests": descriptors}))
                else:
                    self.respond(404)
                return
            self.respond(404)

        do_GET = do_HEAD = do_POST = do_PUT = route

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    state.host = f"127.0.0.1:{server.server_port}"
    state.base = "https://" + state.host
    state.subject = state.host + "/approved/release@" + subject_digest
    config = tmp_path / "docker"
    config.mkdir()
    (config / "config.json").write_text(json.dumps({"auths": {state.host: {"auth": auth[6:]}}}))
    state.env = {"SSL_CERT_FILE": str(cert_path), "DOCKER_CONFIG": str(config)}
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_publish_and_retrieve_referrer_with_signatures_and_immutable_digest(registry, files):
    client = oci._Client(registry.host, "approved/release", registry.env)
    assert client.manifest(registry.subject_digest)[1]["digest"] == registry.subject_digest
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "published", result
    assert result["association_mode"] == "oci_referrers"
    assert result["publication_status"] == "published"
    assert result["verification_status"] == "verified"
    assert result["reference"] == registry.host + "/approved/release@" + result["digest"]
    assert {row["annotations"]["org.opencontainers.image.title"] for row in result["files"]} == set(files)
    retrieved = oci.verify_documentation(result["reference"], registry.subject, registry.env)
    assert retrieved["status"] == "verified"
    assert retrieved["revision"] == result["revision"]
    for row in result["files"]:
        name = row["annotations"]["org.opencontainers.image.title"]
        assert registry.blobs[row["digest"]] == files[name].read_bytes()


@pytest.mark.parametrize("reject_subject", [False, True])
def test_compatibility_tag_is_deterministic_and_revisions_coexist(registry, files, reject_subject):
    registry.referrers = False
    registry.reject_subject = reject_subject
    result = oci.publish_documentation(files, registry.subject, registry.env)
    repeated = oci.publish_documentation(dict(reversed(list(files.items()))), registry.subject, registry.env)
    assert result["status"] == "published", result
    assert result["association_mode"] == "compatibility_tag"
    assert repeated["reference"] == result["reference"]
    assert repeated["compatibility_reference"] == result["compatibility_reference"]
    document = json.loads(registry.manifests[result["digest"]])
    assert document["annotations"][oci.SUBJECT_ANNOTATION] == registry.subject
    assert ("subject" in document) != reject_subject
    files["documentation.zip"].write_bytes(b"new documentation revision")
    revised = oci.publish_documentation(files, registry.subject, registry.env)
    assert revised["status"] == "published"
    assert revised["reference"] != result["reference"]
    assert revised["revision"] != result["revision"]
    assert len(registry.tags) == 2
    assert oci.verify_documentation(result["reference"], registry.subject, registry.env)["status"] == "verified"


def test_bearer_authentication_uses_only_approved_repository_scope(registry, files):
    registry.bearer = True
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "published", result
    assert any(path.startswith("/token?") for _, path, _ in registry.requests)


def test_unapproved_bearer_realm_does_not_receive_credentials(registry, files):
    registry.bearer = True
    registry.token_realm = "https://unapproved.invalid/token"
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "failed"
    assert len(registry.requests) == 1
    assert "secret-password" not in json.dumps(result)


def test_cross_host_upload_location_is_rejected(registry, files):
    registry.upload_location = "https://unapproved.invalid/receive-secret"
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "failed"
    assert not registry.blobs
    assert not registry.tags


def test_tampered_blob_preserves_published_identity_as_unverified(registry, files):
    registry.corrupt_blob = True
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "failed"
    assert result["publication_status"] == "published"
    assert result["verification_status"] == "failed"
    assert result["digest"] in registry.manifests
    registry.corrupt_blob = False
    retry = oci.publish_documentation(files, registry.subject, registry.env)
    assert retry["status"] == "published"
    assert retry["reference"] == result["reference"]


def test_bad_subject_manifest_digest_fails_before_upload(registry, files):
    registry.corrupt_manifest = True
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "failed"
    assert not registry.blobs


def test_ca_is_required_and_credentials_and_registry_errors_stay_private(registry, files):
    no_ca = {"DOCKER_CONFIG": registry.env["DOCKER_CONFIG"]}
    result = oci.publish_documentation(files, registry.subject, no_ca)
    assert result["status"] == "failed"
    assert not registry.requests
    registry.fail_manifest = True
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "failed"
    assert result["publication_status"] == "failed"
    assert registry.blobs
    assert "debug information" not in json.dumps(result)
    assert "secret-password" not in json.dumps(result)


@pytest.mark.parametrize("reference", ["registry.example/team:latest", "http://registry.example/team@sha256:" + "a" * 64,
                                       "user:secret@registry.example/team@sha256:" + "a" * 64,
                                       "registry.example/../team@sha256:" + "a" * 64])
def test_untrusted_mutable_or_malformed_subject_is_rejected(files, reference):
    assert oci.publish_documentation(files, reference, {})["status"] == "failed"


def test_unsafe_names_and_private_key_material_rejected_before_network(registry, files):
    files["../private.key"] = files["release-public-key.pem"]
    assert oci.publish_documentation(files, registry.subject, registry.env)["status"] == "failed"
    del files["../private.key"]
    files["release-public-key.pem"].write_bytes(b"-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----\nsecret")
    assert oci.publish_documentation(files, registry.subject, registry.env)["status"] == "failed"
    assert not registry.requests


def test_retrieval_rejects_cross_repository_and_wrong_subject(registry, files):
    result = oci.publish_documentation(files, registry.subject, registry.env)
    wrong_repository = registry.host + "/different/release@" + result["digest"]
    assert oci.verify_documentation(wrong_repository, registry.subject, registry.env)["status"] == "failed"
    wrong_subject = registry.host + "/approved/release@sha256:" + "a" * 64
    assert oci.verify_documentation(result["reference"], wrong_subject, registry.env)["status"] == "failed"


def test_configured_publication_size_limit_has_metadata_allowance(registry, files):
    env = {**registry.env, "CATS_RELEASE_DOC_MAX_BYTES": "1024"}
    assert oci._size_limit(env) == 1024 + 2 * 1024 * 1024
    files["documentation.zip"].write_bytes(b"x" * (oci._size_limit(env) + 1))
    assert oci.publish_documentation(files, registry.subject, env)["status"] == "failed"
    assert not registry.requests
    assert oci.publish_documentation(files, registry.subject, {**env, "CATS_RELEASE_DOC_MAX_BYTES": "0"})["status"] == "failed"
