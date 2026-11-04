"""Copy an approved image from a redirecting TLS registry into a separate registry."""
import json
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

from cryptography.fernet import Fernet
import pytest

from app import cyber_release_publication as publication, release_oci
from app.secrets import encrypt_secret
from test_cyber_release_publication import publication_environment, publish
from test_release_oci import registry as source_registry, tls_registry


@pytest.fixture
def destination_registry(tmp_path_factory):
    with tls_registry(tmp_path_factory.mktemp("destination-registry")) as registry:
        yield registry


def test_worker_retries_redirected_image_copy_after_storage_origin_approval(
        source_registry, destination_registry, tmp_path, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("CATS_OCI_BLOB_REDIRECT_ORIGINS", raising=False)
    env = publication_environment(tmp_path, monkeypatch, in_memory_registry=False)
    source_registry.blobs.update(env.source.data["blobs"])
    source_registry.manifests.update(env.source.data["manifests"])
    source_registry.blob_redirect = True
    source_registry.bearer = True
    source_registry.token_scope = "repository:source/image:pull"

    credentials = {"username": "approved-user", "password": encrypt_secret("secret-password")}
    source_settings = {"endpoint": source_registry.base, **credentials,
                       "ca_pem": Path(source_registry.env["SSL_CERT_FILE"]).read_text()}
    env.db.scalars = lambda query: [SimpleNamespace(key="oci_registries", value=json.dumps([source_settings]))]
    snapshot = env.approval.snapshot
    image = snapshot["artifacts"][0]
    digest = image["digest"]
    image["reference"] = source_registry.host + "/source/image@" + digest
    snapshot["artifacts"] = [image]
    snapshot["destination"]["endpoint"] = destination_registry.base
    env.destination = {**snapshot["destination"], **credentials, "name": "Destination",
                       "ca_pem": Path(destination_registry.env["SSL_CERT_FILE"]).read_text()}
    env.approval.snapshot_digest = release_oci._digest(publication.canonical(snapshot))

    checkpoints = []
    with pytest.raises(publication.PublicationError) as denied:
        publish(env, checkpoints)
    failed = denied.value.receipt
    diagnostic = failed["diagnostic"]
    assert failed["status"] == "failed"
    assert diagnostic.get("http_status") == 307, diagnostic
    assert diagnostic["registry_origin"] == source_registry.base
    assert diagnostic["redirect_origin"] == source_registry.storage_base
    assert diagnostic["operation"] == "GET blob"
    assert diagnostic["redirect_reason"] == "unapproved_blob_origin"
    assert not source_registry.storage_requests
    assert not destination_registry.requests

    env.approval.publication = failed
    monkeypatch.setenv("CATS_OCI_BLOB_REDIRECT_ORIGINS", source_registry.storage_base)
    receipt = publish(env, checkpoints)
    artifact, = receipt["artifacts"]
    assert receipt["status"] == "published"
    assert artifact["digest"] == artifact["source_digest"] == digest
    assert artifact["verification_status"] == "verified"
    assert destination_registry.manifests[digest] == source_registry.manifests[digest]
    assert any(method == "GET" and "/blobs/" in path and auth == "Bearer isolated-token"
               for method, path, auth in source_registry.requests)
    storage_reads = {("GET", "/objects/" + key + source_registry.storage_query, None)
                     for key in source_registry.blobs}
    assert set(source_registry.storage_requests) == storage_reads

    with ZipFile(receipt["bundle_path"]) as bundle:
        for key, content in source_registry.blobs.items():
            assert release_oci._digest(content) == key
            assert destination_registry.blobs[key] == content
            assert bundle.read("oci/blobs/sha256/" + key[7:]) == content
        persisted = [publication.canonical(checkpoints), *(bundle.read(name) for name in bundle.namelist())]
    for data in persisted:
        assert b"/objects/" not in data
        assert b"opaque%2Bsignature" not in data
        assert b"secret-password" not in data
        assert source_registry.auth.encode() not in data
