"""Exercise the distribution protocol against a disposable, authenticated TLS registry."""
import base64
from datetime import datetime, timedelta, timezone
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from io import BytesIO
import ssl
from threading import Thread
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from app import release_oci as oci
from test_release_exports import source


@pytest.fixture
def files(tmp_path):
    contents = {"documentation.zip": b"retained documentation archive",
                "release-manifest.json": b'{"release":"test"}',
                "release-manifest.sig": b"detached signature",
                "documentation.zip.sig": b"detached archive signature",
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
                            fail_manifest=False, auth=auth, subject_digest=subject_digest,
                            redirects={}, same_origin_redirect=None, blob_redirect=False,
                            storage_requests=[], storage_hosts=[], storage_redirects={}, storage_body=None,
                            storage_challenge=False, storage_corrupt_blob=False)

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
            redirect = state.redirects.get((self.command, path))
            if redirect:
                status, location = redirect
                headers = {"Location": location} if location is not None else {}
                self.respond(status, b"private redirect debug information", **headers)
                return
            if state.same_origin_redirect and path.startswith("/v2/"):
                self.respond(state.same_origin_redirect, Location="/redirected" + self.path)
                return
            if path.startswith("/redirected/"):
                path = path[len("/redirected"):]
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
                elif state.blob_redirect and self.command in ("GET", "HEAD"):
                    self.respond(307, Location=state.storage_base + "/objects/" + digest + state.storage_query)
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

    class StorageHandler(Handler):
        def route(self):
            parsed = urlsplit(self.path)
            state.storage_requests.append((self.command, self.path, self.headers.get("Authorization")))
            state.storage_hosts.append(self.headers.get("Host"))
            redirect = state.storage_redirects.get((self.command, parsed.path))
            if redirect:
                status, location = redirect
                self.respond(status, Location=location)
            elif state.storage_challenge:
                self.respond(401, WWW_Authenticate=f'Bearer realm="{state.base}/token",service="test"')
            else:
                digest = parsed.path.rsplit("/", 1)[1]
                content = state.storage_body if state.storage_body is not None else state.blobs.get(digest)
                if content is None:
                    self.respond(404)
                    return
                if state.storage_corrupt_blob:
                    content = b"!" * len(content)
                self.respond(200, content)

        do_GET = do_HEAD = do_POST = do_PUT = route

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    storage = ThreadingHTTPServer(("127.0.0.1", 0), StorageHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    storage.socket = context.wrap_socket(storage.socket, server_side=True)
    state.host = f"127.0.0.1:{server.server_port}"
    state.base = "https://" + state.host
    state.storage_base = f"https://127.0.0.1:{storage.server_port}"
    state.storage_query = "?signature=opaque%2Bsignature%2Fvalue%3D&key=a%26b"
    state.subject = state.host + "/approved/release@" + subject_digest
    config = tmp_path / "docker"
    config.mkdir()
    (config / "config.json").write_text(json.dumps({"auths": {state.host: {"auth": auth[6:]}}}))
    state.env = {"SSL_CERT_FILE": str(cert_path), "DOCKER_CONFIG": str(config)}
    threads = [Thread(target=lambda item=item: item.serve_forever(poll_interval=0.01), daemon=True)
               for item in (server, storage)]
    for thread in threads:
        thread.start()
    try:
        yield state
    finally:
        for item, thread in zip((server, storage), threads):
            item.shutdown()
            item.server_close()
            thread.join(timeout=5)


def test_export_all_with_large_manifest_can_be_attached_and_retrieved(registry, files, source):
    from app.models import ServiceMetadata
    from app.release_exports import write_documentation
    from app.service_transfer import parse_service

    db, record = source
    db.add(ServiceMetadata(service_id=record.service_id, values={
        f"api_key_{index:04d}_{'x' * 80}": "sensitive" for index in range(1000)}))
    db.flush()
    auth = SimpleNamespace(has=lambda permission, service_id: True,
                           user=SimpleNamespace(username="exporter"))
    write_documentation(db, record, auth, files["documentation.zip"])
    with ZipFile(files["documentation.zip"]) as archive:
        bundle_bytes = archive.read("cats-service.zip")
        with ZipFile(BytesIO(bundle_bytes)) as bundle:
            assert bundle.getinfo("manifest.json").file_size > 65536
        assert len(parse_service(bundle_bytes)[0]["redactions"]) >= 1000
    # Release metadata is a blob too, and also accepts more than 64 KiB.
    files["release-manifest.json"].write_text(json.dumps({"inventory": ["entry" * 30] * 600}))
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "published", result
    assert oci.verify_documentation(result["reference"], registry.subject, registry.env)["status"] == "verified"
    for row in result["files"]:
        name = row["annotations"]["org.opencontainers.image.title"]
        assert registry.blobs[row["digest"]] == files[name].read_bytes()


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


@pytest.mark.parametrize("status", [307, 308])
def test_same_origin_redirects_preserve_publication_methods_bodies_and_auth(registry, files, status):
    registry.same_origin_redirect = status
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "published", result
    assert oci.verify_documentation(result["reference"], registry.subject, registry.env)["status"] == "verified"
    redirected = [(method, path, auth) for method, path, auth in registry.requests
                  if path.startswith("/redirected/")]
    assert {method for method, _, _ in redirected} == {"GET", "HEAD", "POST", "PUT"}
    assert all(auth == registry.auth for _, _, auth in registry.requests)
    for row in result["files"]:
        name = row["annotations"]["org.opencontainers.image.title"]
        assert registry.blobs[row["digest"]] == files[name].read_bytes()


def test_upload_location_is_relative_to_redirected_post_response(registry):
    path = "/v2/approved/release/blobs/uploads/"
    registry.redirects[("POST", path)] = (307, "/redirected" + path)
    registry.upload_location = "test?state=preserved"
    client = oci._Client(registry.host, "approved/release", registry.env)
    content = b"upload body survives the redirect"
    descriptor = client.upload(content, "application/octet-stream")
    assert registry.blobs[descriptor["digest"]] == content
    put_paths = [path for method, path, _ in registry.requests if method == "PUT"]
    assert len(put_paths) == 1
    assert put_paths[0].startswith("/redirected/v2/approved/release/blobs/uploads/test?")


@pytest.mark.parametrize("status", [301, 302, 303])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_safe_read_redirects_preserve_method(registry, status, method):
    source = "/v2/approved/release/manifests/" + registry.subject_digest
    registry.redirects[(method, source)] = (status, "/redirected" + source)
    client = oci._Client(registry.host, "approved/release", registry.env)
    response, _, content = client.request(method, registry.base + source)
    assert response == 200
    assert content == (registry.manifests[registry.subject_digest] if method == "GET" else b"")
    assert [row[0] for row in registry.requests] == [method, method]


@pytest.mark.parametrize("bearer", [False, True])
def test_approved_blob_storage_redirect_preserves_query_and_strips_auth(registry, files, bearer):
    registry.bearer = bearer
    registry.blob_redirect = True
    env = {**registry.env, "CATS_OCI_BLOB_REDIRECT_ORIGINS":
           f" https://unused.invalid , {registry.storage_base} "}
    result = oci.publish_documentation(files, registry.subject, env)
    assert result["status"] == "published", result
    assert oci.verify_documentation(result["reference"], registry.subject, env)["status"] == "verified"
    # Existing blob HEAD checks follow the same storage policy as verification GETs.
    client = oci._Client(registry.host, "approved/release", env)
    assert client.upload(b"{}", "application/vnd.oci.empty.v1+json")["digest"] == oci._digest(b"{}")
    assert {method for method, _, _ in registry.storage_requests} == {"GET", "HEAD"}
    assert all(auth is None for _, _, auth in registry.storage_requests)
    assert set(registry.storage_hosts) == {urlsplit(registry.storage_base).netloc}
    assert all(path.endswith(registry.storage_query) for _, path, _ in registry.storage_requests)
    expected_auth = "Bearer isolated-token" if bearer else registry.auth
    assert any(auth == expected_auth for _, path, auth in registry.requests if "/blobs/" in path)


@pytest.mark.parametrize("target_kind", ["unapproved", "http", "userinfo", "fragment"])
def test_unsafe_blob_redirect_targets_are_rejected_before_contact(registry, target_kind):
    digest = oci._digest(b"blob")
    source = "/v2/approved/release/blobs/" + digest
    target = registry.storage_base + "/objects/" + digest + "?secret=signed-storage-secret"
    if target_kind == "http":
        target = target.replace("https://", "http://", 1)
    elif target_kind == "userinfo":
        target = target.replace("https://", "https://user:secret-password@", 1)
    elif target_kind == "fragment":
        target += "#private-fragment"
    env = dict(registry.env)
    if target_kind != "unapproved":
        env["CATS_OCI_BLOB_REDIRECT_ORIGINS"] = registry.storage_base
    registry.redirects[("GET", source)] = (307, target)
    client = oci._Client(registry.host, "approved/release", env)
    with pytest.raises(oci._RegistryError) as error:
        client.request("GET", registry.base + source)
    assert error.value.status == 307
    assert not registry.storage_requests
    assert len(registry.requests) == 1
    assert all(secret not in str(error.value) for secret in
               ("secret-password", "signed-storage-secret", "private-fragment", "debug information", target))


@pytest.mark.parametrize("path", ["manifests/{digest}", "referrers/{digest}",
                                  "blobs/uploads/", "blobs/not-a-digest"])
def test_approved_storage_origin_cannot_receive_non_blob_reads(registry, path):
    source = "/v2/approved/release/" + path.format(digest=registry.subject_digest)
    registry.redirects[("GET", source)] = (307, registry.storage_base + "/objects/blob")
    env = {**registry.env, "CATS_OCI_BLOB_REDIRECT_ORIGINS": registry.storage_base}
    client = oci._Client(registry.host, "approved/release", env)
    with pytest.raises(oci._RegistryError) as error:
        client.request("GET", registry.base + source)
    assert error.value.status == 307
    assert not registry.storage_requests


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT"])
def test_cross_origin_redirect_never_forwards_request_bodies(registry, method):
    source = "/v2/approved/release/blobs/" + oci._digest(b"blob")
    registry.redirects[(method, source)] = (307, registry.storage_base + "/objects/blob")
    env = {**registry.env, "CATS_OCI_BLOB_REDIRECT_ORIGINS": registry.storage_base}
    client = oci._Client(registry.host, "approved/release", env)
    with pytest.raises(oci._RegistryError) as error:
        client.request(method, registry.base + source, body=b"private upload content")
    assert error.value.status == 307
    assert not registry.storage_requests


@pytest.mark.parametrize("status", [301, 302, 303])
@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_method_changing_redirects_reject_writes(registry, status, method):
    source = "/v2/approved/release/blobs/uploads/"
    registry.redirects[(method, source)] = (status, "/redirected" + source)
    client = oci._Client(registry.host, "approved/release", registry.env)
    with pytest.raises(oci._RegistryError) as error:
        client.request(method, registry.base + source, body=b"private upload content")
    assert error.value.status == status
    assert len(registry.requests) == 1
    assert not registry.blobs


@pytest.mark.parametrize("location", [None, "/redirect-loop"])
def test_missing_location_and_redirect_loop_are_bounded(registry, location):
    registry.redirects[("GET", "/redirect-loop")] = (307, location)
    client = oci._Client(registry.host, "approved/release", registry.env)
    with pytest.raises(oci._RegistryError) as error:
        client.request("GET", registry.base + "/redirect-loop")
    assert error.value.status == 307
    assert len(registry.requests) <= 6
    assert "debug information" not in str(error.value)


@pytest.mark.parametrize("redirect_count", [5, 6])
def test_redirect_chain_allows_five_hops_and_rejects_six(registry, redirect_count):
    source = "/v2/approved/release/manifests/" + registry.subject_digest
    paths = [source, *[f"/hop/{index}" for index in range(1, redirect_count)], "/redirected" + source]
    for start, target in zip(paths, paths[1:]):
        registry.redirects[("GET", start)] = (307, target)
    client = oci._Client(registry.host, "approved/release", registry.env)
    if redirect_count == 5:
        assert client.request("GET", registry.base + source)[2] == registry.manifests[registry.subject_digest]
    else:
        with pytest.raises(oci._RegistryError) as error:
            client.request("GET", registry.base + source)
        assert error.value.status == 307
    assert len(registry.requests) == 6


@pytest.mark.parametrize("redirect_back", [False, True])
def test_storage_cannot_trigger_registry_authentication(registry, redirect_back):
    digest = oci._digest(b"blob")
    source = "/v2/approved/release/blobs/" + digest
    target = "/objects/" + digest
    registry.redirects[("GET", source)] = (307, registry.storage_base + target)
    if redirect_back:
        registry.storage_redirects[("GET", target)] = (307, registry.base + "/redirected" + source)
    else:
        registry.storage_challenge = True
    env = {**registry.env, "CATS_OCI_BLOB_REDIRECT_ORIGINS": registry.storage_base}
    client = oci._Client(registry.host, "approved/release", env)
    with pytest.raises(oci._RegistryError) as error:
        client.request("GET", registry.base + source)
    assert error.value.status == 401
    assert all(auth is None for _, _, auth in registry.storage_requests)
    assert not any(path.startswith("/token") for _, path, _ in registry.requests)
    if redirect_back:
        assert registry.requests[-1] == ("GET", "/redirected" + source, None)


def test_redirected_blob_digest_verification_preserves_unverified_publication(registry, files):
    registry.blob_redirect = True
    registry.storage_corrupt_blob = True
    env = {**registry.env, "CATS_OCI_BLOB_REDIRECT_ORIGINS": registry.storage_base}
    result = oci.publish_documentation(files, registry.subject, env)
    assert result["status"] == "failed"
    assert result["publication_status"] == "published"
    assert result["verification_status"] == "failed"
    assert result["digest"] in registry.manifests
    registry.storage_corrupt_blob = False
    assert oci.verify_documentation(result["reference"], registry.subject, env)["status"] == "verified"


def test_redirected_blob_keeps_response_size_limit(registry):
    content = b"expected blob"
    digest = oci._digest(content)
    registry.blobs[digest] = content
    registry.blob_redirect = True
    registry.storage_body = content + b"extra bytes"
    env = {**registry.env, "CATS_OCI_BLOB_REDIRECT_ORIGINS": registry.storage_base}
    client = oci._Client(registry.host, "approved/release", env)
    with pytest.raises(ValueError, match="size limit"):
        client.request("GET", client.api + "/blobs/" + digest, limit=len(content))
    assert len(registry.storage_requests) == 1


def test_cyber_release_graph_retains_and_verifies_redirected_content(registry, tmp_path):
    from app import cyber_release_publication as publication

    registry.blobs[oci._digest(b"{}")] = b"{}"
    registry.same_origin_redirect = 307
    registry.blob_redirect = True
    env = {**registry.env, "CATS_OCI_BLOB_REDIRECT_ORIGINS": registry.storage_base}
    client = oci._Client(registry.host, "approved/release", env)
    transport = publication._Transport(tmp_path / "offline-layout", env)
    descriptor = transport.graph(client, registry.subject_digest, target=client)
    assert descriptor["digest"] == registry.subject_digest
    for digest, content in ((registry.subject_digest, registry.manifests[registry.subject_digest]),
                            (oci._digest(b"{}"), b"{}")):
        assert (transport.blobs / digest[7:]).read_bytes() == content
    assert any(method == "PUT" and path.startswith("/redirected/v2/approved/release/manifests/")
               for method, path, _ in registry.requests)
    assert {method for method, _, _ in registry.storage_requests} == {"GET", "HEAD"}
    assert all(auth is None for _, _, auth in registry.storage_requests)


def test_redirect_discards_host_and_proxy_credentials_added_by_urllib(monkeypatch):
    content = b"storage bytes"
    digest = oci._digest(content)
    client = oci._Client("registry.example", "approved/release",
                         {"CATS_OCI_BLOB_REDIRECT_ORIGINS": "https://storage.example"})
    client.basic = "Basic registry-credential"
    captured = []

    class Response:
        status = 200
        headers = Message()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return content[:limit]

    def open_request(request, timeout):
        captured.append({key.lower(): value for key, value in request.header_items()})
        if len(captured) == 1:
            # HTTP/proxy handlers modify the Request before raising a redirect.
            request.add_unredirected_header("Host", "registry.example")
            request.add_unredirected_header("Proxy-Authorization", "Basic private-proxy-credential")
            headers = Message()
            headers["Location"] = "https://storage.example/objects/" + digest
            raise oci.urllib.error.HTTPError(request.full_url, 307, "Redirect", headers, BytesIO())
        return Response()

    monkeypatch.setattr(client.opener, "open", open_request)
    assert client.request("GET", client.api + "/blobs/" + digest)[2] == content
    assert captured[0]["authorization"] == client.basic
    assert len(captured) == 2
    assert not {"authorization", "proxy-authorization", "host"}.intersection(captured[1])


def test_unapproved_bearer_realm_does_not_receive_credentials(registry, files):
    registry.bearer = True
    registry.token_realm = "https://unapproved.invalid/token"
    result = oci.publish_documentation(files, registry.subject, registry.env)
    assert result["status"] == "failed"
    assert len(registry.requests) == 1
    assert "secret-password" not in json.dumps(result)


@pytest.mark.parametrize("allowlisted", [False, True])
def test_cross_host_upload_location_is_rejected(registry, files, allowlisted):
    registry.upload_location = registry.storage_base + "/receive-secret"
    env = dict(registry.env)
    if allowlisted:
        env["CATS_OCI_BLOB_REDIRECT_ORIGINS"] = registry.storage_base
    result = oci.publish_documentation(files, registry.subject, env)
    assert result["status"] == "failed"
    assert not registry.blobs
    assert not registry.tags
    assert not registry.storage_requests


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
