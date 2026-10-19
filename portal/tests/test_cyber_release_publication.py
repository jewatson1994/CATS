"""Real OCI content graphs and signatures with registry/Cosign processes isolated."""
import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from types import SimpleNamespace
from zipfile import ZipFile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from app import cyber_release_publication as publication
from app import release_oci, signing, release_validity


def descriptor(content, media_type="application/octet-stream"):
    return {"digest": release_oci._digest(content), "size": len(content), "mediaType": media_type}


@pytest.fixture
def environment(tmp_path, monkeypatch):
    stores = {}

    class Registry:
        def __init__(self, host, repository, env=None):
            self.api = f"https://{host}/v2/{repository}"
            self.data = stores.setdefault((host, repository), {"manifests": {}, "blobs": {}})

        def upload(self, content, media_type):
            item = descriptor(content, media_type)
            self.data["blobs"][item["digest"]] = content
            return item

        def request(self, method, url, *, body=None, media_type=None, limit=None):
            endpoint = url[len(self.api) + 1:]
            kind, digest = endpoint.split("/", 1)
            if method == "PUT":
                self.data[kind][digest] = body
                return 201, None, b""
            content = self.data[kind][digest]
            return 200, SimpleNamespace(get_content_type=lambda: release_oci.MANIFEST_TYPE), content

    monkeypatch.setattr(release_oci, "_Client", Registry)
    monkeypatch.setattr(publication.shutil, "which", lambda name: name)

    @contextmanager
    def registry_environment(destination, certificates=()):
        yield {}
    monkeypatch.setattr(publication, "registry_environment", registry_environment)
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pem, fingerprint = signing.public_key(public)
    config = {"signing_enabled": True, "signing_public_key": pem, "signing_fingerprint": fingerprint}
    credentials = {"CATS_SIGNING_PRIVATE_KEY": base64.b64encode(private_pem).decode()}
    monkeypatch.setattr(signing, "job_material", lambda settings, mode: (config, credentials))

    def sign(content):
        return base64.b64encode(private.sign(content, ec.ECDSA(hashes.SHA256()))).decode()

    def command(args, env=None, **kwargs):
        operation = args[1]
        if operation == "sign-blob":
            Path(args[args.index("--output-signature") + 1]).write_text(sign(Path(args[-1]).read_bytes()))
        elif operation == "verify-blob":
            try:
                content = Path(args[-1]).read_bytes()
                signature = base64.b64decode(Path(args[args.index("--signature") + 1]).read_bytes())
                private.public_key().verify(signature, content, ec.ECDSA(hashes.SHA256()))
            except Exception as exc:
                raise subprocess.CalledProcessError(1, args) from exc
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr(signing, "_command", command)
    monkeypatch.setattr(subprocess, "run", command)

    def sign_and_verify(reference, config, credentials, env):
        host, repository, digest = release_oci._reference(reference)
        client = Registry(host, repository)
        payload = publication.canonical({"critical": {"image": {"docker-manifest-digest": digest}}, "optional": config.get("approval_annotations", {})})
        layer = client.upload(payload, "application/vnd.dev.cosign.simplesigning.v1+json")
        layer["annotations"] = {"dev.cosignproject.cosign/signature": sign(payload)}
        content = publication.canonical({"schemaVersion": 2, "mediaType": release_oci.MANIFEST_TYPE,
                                         "config": client.upload(b"{}", "application/vnd.oci.empty.v1+json"), "layers": [layer]})
        client.data["manifests"]["sha256-" + digest[7:] + ".sig"] = content
        client.data["manifests"][release_oci._digest(content)] = content
        return {"signature_status": "verified", "signature": {"key_fingerprint": fingerprint}}
    monkeypatch.setattr(signing, "sign_and_verify", sign_and_verify)
    source = Registry("source.example", "app")
    layer = source.upload(b"actual container filesystem bytes", "application/vnd.oci.image.layer.v1.tar")
    image_config = source.upload(b'{"architecture":"amd64"}', "application/vnd.oci.image.config.v1+json")
    content = publication.canonical({"schemaVersion": 2, "mediaType": release_oci.MANIFEST_TYPE,
                                     "config": image_config, "layers": [layer]})
    digest = release_oci._digest(content)
    source.data["manifests"][digest] = content
    evidence = tmp_path / "evidence.zip"
    with ZipFile(evidence, "w") as archive:
        archive.writestr("findings.json", '{"findings":[]}')
    chart = tmp_path / "chart.tgz"
    with tarfile.open(chart, "w:gz") as archive:
        data = b"apiVersion: v2\nname: sample\nversion: 1.0.0\n"
        member = tarfile.TarInfo("sample/Chart.yaml")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    snapshot = {"evidence": {"path": str(evidence), "digest": publication.file_digest(evidence)},
                "artifacts": [{"kind": "image", "reference": "source.example/app@" + digest, "digest": digest},
                              {"kind": "chart", "path": str(chart), "digest": publication.file_digest(chart)}]}
    destination = {"id": "saved:3", "endpoint": "https://approved.example", "namespace": "team"}
    decided_at = datetime.now(timezone.utc)
    snapshot.update(destination=destination, signing_fingerprint=fingerprint, approval_validity=release_validity.new_validity(decided_at))
    approval = SimpleNamespace(id=7, release_key="approval-123", snapshot=snapshot,
                               snapshot_digest=release_oci._digest(publication.canonical(snapshot)),
                               status="approved", decided_by_id=2, decided_at=decided_at,
                               decision_rationale="Reviewed retained findings and accepted release", revoked_at=None)
    db = SimpleNamespace(scalars=lambda query: [])
    return SimpleNamespace(approval=approval, destination=destination, db=db, stores=stores,
                           fingerprint=fingerprint, source=source, layer=layer, Registry=Registry)


def publish(env, checkpoints):
    return publication.publish(env.db, env.approval, env.destination, checkpoints.append)


def test_complete_release_contains_actual_oci_graph_and_offline_verified_signatures(environment, tmp_path):
    checkpoints = []
    receipt = publish(environment, checkpoints)
    assert receipt["status"] == "published"
    assert all(row["status"] == "publishing" for row in checkpoints[:-1])
    assert receipt["bundle_digest"] == publication.file_digest(receipt["bundle_path"])
    assert receipt["artifacts"][0]["digest"] == environment.approval.snapshot["artifacts"][0]["digest"]
    assert receipt["manifest"]["approval"]["decided_by_id"] == 2
    assert receipt["manifest"]["approval"]["decision_rationale"] == environment.approval.decision_rationale
    assert "path" not in receipt["manifest"]["snapshot"]["artifacts"][1]
    assert str(tmp_path) not in json.dumps(receipt["manifest"])
    output = tmp_path / "unpacked"
    with ZipFile(receipt["bundle_path"]) as bundle:
        bundle.extractall(output)
        assert {"evidence.zip", "evidence.zip.sig", "transport.sig", "release-manifest.sig", "verify-import.py"}.issubset(bundle.namelist())
        assert all("PRIVATE KEY" not in bundle.read(name).decode(errors="ignore") for name in bundle.namelist())
    assert (output / "oci" / "blobs" / "sha256" / environment.layer["digest"][7:]).read_bytes() == b"actual container filesystem bytes"
    publication.verify_local(output, environment.fingerprint)
    (output / "oci" / "blobs" / "sha256" / environment.layer["digest"][7:]).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="content verification"):
        publication.verify_local(output, environment.fingerprint)


@pytest.mark.parametrize("failure", ["evidence", "snapshot", "signing", "registry", "offline", "revoked", "destination", "key"])
def test_never_published_on_incomplete_operation(environment, monkeypatch, failure):
    if failure == "evidence":
        Path(environment.approval.snapshot["evidence"]["path"]).write_bytes(b"changed")
    elif failure == "snapshot":
        environment.approval.snapshot["artifacts"] = []
    elif failure == "signing":
        monkeypatch.setattr(signing, "job_material", lambda *args: ({"signing_enabled": False}, {}))
    elif failure == "registry":
        environment.source.data["blobs"][environment.layer["digest"]] = b"corrupt"
    elif failure == "revoked":
        environment.approval.revoked_at = datetime.now(timezone.utc)
    elif failure == "destination":
        environment.destination = {**environment.destination, "namespace": "other-team"}
    elif failure == "key":
        environment.approval.snapshot["signing_fingerprint"] = "sha256:" + "0" * 64
        environment.approval.snapshot_digest = release_oci._digest(publication.canonical(environment.approval.snapshot))
    else:
        monkeypatch.setattr(publication, "verify_local", lambda *args: (_ for _ in ()).throw(ValueError("broken")))
    checkpoints = []
    with pytest.raises(publication.PublicationError):
        publish(environment, checkpoints)
    assert checkpoints[-1]["status"] == "failed"
    assert not any(row["status"] == "published" or row.get("bundle_path") for row in checkpoints)


def test_offline_verifier_rejects_wrong_trust_and_evidence_tamper(environment, tmp_path):
    receipt = publish(environment, [])
    output = tmp_path / "unpacked"
    with ZipFile(receipt["bundle_path"]) as archive:
        archive.extractall(output)
    with pytest.raises(ValueError, match="trusted fingerprint"):
        publication.verify_local(output, "sha256:" + "0" * 64)
    (output / "evidence.zip").write_bytes(b"changed")
    with pytest.raises(subprocess.CalledProcessError):
        publication.verify_local(output, environment.fingerprint)


def test_copy_preserves_multi_platform_index(environment, tmp_path):
    source = environment.source
    original = environment.approval.snapshot["artifacts"][0]["digest"]
    content = source.data["manifests"][original]
    second = json.loads(content)
    second["config"] = source.upload(b'{"architecture":"arm64"}', "application/vnd.oci.image.config.v1+json")
    second_content = publication.canonical(second)
    second_digest = release_oci._digest(second_content)
    source.data["manifests"][second_digest] = second_content
    index = publication.canonical({"schemaVersion": 2, "mediaType": release_oci.INDEX_TYPE,
                                   "manifests": [{**descriptor(content, release_oci.MANIFEST_TYPE),
                                                  "platform": {"os": "linux", "architecture": "amd64"}},
                                                 {**descriptor(second_content, release_oci.MANIFEST_TYPE),
                                                  "platform": {"os": "linux", "architecture": "arm64"}}]})
    digest = release_oci._digest(index)
    source.data["manifests"][digest] = index
    target = environment.Registry("destination.example", "multi")
    transport = publication._Transport(tmp_path / "layout", {})
    result = transport.graph(source, digest, target)
    assert result["digest"] == digest
    assert target.data["manifests"][digest] == index
    assert target.data["manifests"][original] == content
    assert target.data["manifests"][second_digest] == second_content
    assert target.data["blobs"] == source.data["blobs"]


def test_chart_bytes_preserved_and_helm_media_types(environment):
    receipt = publish(environment, [])
    artifact = receipt["artifacts"][1]
    host, repository, digest = release_oci._reference(artifact["reference"])
    target = environment.stores[(host, repository)]
    manifest = json.loads(target["manifests"][digest])
    assert manifest["config"]["mediaType"] == "application/vnd.cncf.helm.config.v1+json"
    layer = manifest["layers"][0]
    assert layer["mediaType"] == "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
    assert layer["digest"] == environment.approval.snapshot["artifacts"][1]["digest"]
    assert target["blobs"][layer["digest"]] == Path(environment.approval.snapshot["artifacts"][1]["path"]).read_bytes()


@pytest.mark.parametrize("corrupt", [False, True])
def test_offline_import_retrieves_and_checks_every_blob(environment, tmp_path, monkeypatch, corrupt):
    receipt = publish(environment, [])
    output = tmp_path / "importable"
    with ZipFile(receipt["bundle_path"]) as archive:
        archive.extractall(output)
    namespace = {"__name__": "test_import", "__file__": str(output / "verify-import.py")}
    exec(compile(publication.OFFLINE_SCRIPT, namespace["__file__"], "exec"), namespace)
    original_run = namespace["run"]
    entries = json.loads((output / "oci" / "index.json").read_bytes())["manifests"]
    index = {item["annotations"]["org.opencontainers.image.ref.name"]: item for item in entries}
    imported, checked = {}, set()

    def run(args):
        if args[:2] == ["cosign", "verify-blob"]:
            return original_run(args)
        if args[:2] == ["cosign", "verify"]:
            return b"verified"
        if args[:2] == ["oras", "cp"]:
            imported[args[-1]] = index[args[-2].rsplit(":", 1)[-1]]["digest"]
            return b""
        if args[:3] == ["oras", "manifest", "fetch"]:
            digest = args[-1].split("@", 1)[1] if "@" in args[-1] else imported[args[-1]]
            return (output / "oci" / "blobs" / "sha256" / digest[7:]).read_bytes()
        if args[:3] == ["oras", "blob", "fetch"]:
            digest = args[-1].split("@", 1)[1]
            checked.add(digest)
            return b"corrupt" if corrupt else (output / "oci" / "blobs" / "sha256" / digest[7:]).read_bytes()
        raise AssertionError(args)

    namespace["run"] = run
    monkeypatch.setattr(sys, "argv", ["verify-import.py", "--fingerprint", environment.fingerprint,
                                      "--destination", "offline.example/team/approved"])
    if corrupt:
        with pytest.raises(ValueError, match="Imported OCI layer"):
            namespace["main"]()
    else:
        namespace["main"]()
        assert environment.layer["digest"] in checked
        assert len(imported) == 2 * len(json.loads((output / "transport.json").read_bytes())["artifacts"])


def test_source_credentials_and_trust_are_host_scoped_and_temporary(tmp_path, monkeypatch):
    credentials = tmp_path / "source-auth.json"
    credentials.write_text(json.dumps({"auths": {"source.example": {"auth": "user:secret"}}}))
    @contextmanager
    def material(settings):
        yield {"image_auth_file": str(credentials), "helm_ca_file": "admin-ca.pem",
               "image_registries": [{"endpoint": "https://source.example", "ca_file": "source-ca.pem"},
                                     {"endpoint": "https://other.example", "ca_file": "other-ca.pem"}]}
    monkeypatch.setattr(publication, "configured_material", material)
    with publication._source_environments({}) as (base, sources):
        config = Path(base["DOCKER_CONFIG"]) / "config.json"
        assert config.read_bytes() == credentials.read_bytes()
        assert base["SSL_CERT_FILE"] == "admin-ca.pem"
        assert sources["source.example"]["SSL_CERT_FILE"] == "source-ca.pem"
        assert sources["other.example"]["SSL_CERT_FILE"] == "other-ca.pem"
    assert not config.exists()


@pytest.mark.parametrize('retry', [False, True])
def test_tag_only_image_is_resolved_signed_and_retry_keeps_first_digest(environment, monkeypatch, tmp_path, retry):
    item = environment.approval.snapshot['artifacts'][0]
    original = item['digest']
    environment.source.data['manifests']['latest'] = environment.source.data['manifests'][original]
    item.update(reference='source.example/app:latest', digest=None, resolve_at_publication=True)
    environment.approval.snapshot_digest = release_oci._digest(publication.canonical(environment.approval.snapshot))
    checkpoints = []
    if retry:
        original_graph = publication._Transport.graph
        monkeypatch.setattr(publication._Transport, 'graph', lambda *a, **k: (_ for _ in ()).throw(ValueError('registry unavailable')))
        with pytest.raises(publication.PublicationError) as failure:
            publish(environment, checkpoints)
        environment.approval.publication = failure.value.receipt
        assert environment.approval.publication['resolved_images']['0'] == original
        environment.source.data['manifests']['latest'] = b'tag now points to different bytes'
        monkeypatch.setattr(publication._Transport, 'graph', original_graph)
    receipt = publish(environment, checkpoints)
    artifact = receipt['artifacts'][0]
    assert artifact['digest'] == original
    assert artifact['identity_resolution'] == 'publication'
    assert artifact['scan_identity_retained'] is False
    assert artifact['signature']
    output = tmp_path / 'tag-offline'
    with ZipFile(receipt['bundle_path']) as bundle:
        bundle.extractall(output)
    publication.verify_local(output, environment.fingerprint)


def test_retained_image_archive_is_published_and_signed_by_destination_digest(environment, monkeypatch, tmp_path):
    archive = tmp_path / 'candidate-image.tar'
    archive.write_bytes(b'fixture retained docker archive')
    source_digest = environment.approval.snapshot['artifacts'][0]['digest']
    environment.approval.snapshot['artifacts'][0] = {'kind':'image', 'reference':'local/candidate:patched',
        'path':str(archive), 'digest':publication.file_digest(archive), 'format':'docker-archive'}
    environment.approval.snapshot_digest = release_oci._digest(publication.canonical(environment.approval.snapshot))
    original_command = subprocess.run
    def command(args, **kwargs):
        if args[:2] != ['skopeo', 'copy']:
            return original_command(args, **kwargs)
        assert args[-2] == 'docker-archive:' + str(archive)
        destination = args[-1].removeprefix('docker://').rsplit(':', 1)[0]
        host, repository = destination.split('/', 1)
        target = environment.Registry(host, repository)
        target.data['manifests'].update(environment.source.data['manifests'])
        target.data['blobs'].update(environment.source.data['blobs'])
        Path(args[args.index('--digestfile') + 1]).write_text(source_digest)
        return SimpleNamespace(stdout=b'')
    monkeypatch.setattr(subprocess, 'run', command)
    @contextmanager
    def destination_env(destination, certificates=()):
        yield {'DOCKER_CONFIG':str(tmp_path)}
    monkeypatch.setattr(publication, 'registry_environment', destination_env)
    receipt = publish(environment, [])
    assert receipt['artifacts'][0]['source_digest'] == publication.file_digest(archive)
    assert receipt['artifacts'][0]['digest'] == source_digest
    assert receipt['artifacts'][0]['signature']


@pytest.mark.parametrize('reference', ['https://registry.example/a:1', 'a@@sha256:'+'a'*64, 'a//b:1', 'a:', 'a b'])
def test_tag_reference_rejects_malformed_values(reference):
    with pytest.raises(ValueError):
        publication.image_source(reference)


@pytest.mark.parametrize('reference,expected', [('nginx', ('docker.io','library/nginx','latest')),
    ('team/app:1', ('docker.io','team/app','1')), ('localhost:5000/team/app:2', ('localhost:5000','team/app','2'))])
def test_tag_reference_normalizes_registry_repository_and_tag(reference, expected):
    assert publication.image_source(reference) == expected


def test_offline_expiry_rejects_import_before_copy_and_tampering_fails_signature(environment, tmp_path, monkeypatch):
    from datetime import timedelta
    receipt = publish(environment, [])
    output = tmp_path / 'expiry-import'
    with ZipFile(receipt['bundle_path']) as archive:
        archive.extractall(output)
    namespace = {'__name__':'test_expiry', '__file__':str(output / 'verify-import.py')}
    exec(compile(publication.OFFLINE_SCRIPT, namespace['__file__'], 'exec'), namespace)
    manifest = json.loads((output / 'release-manifest.json').read_bytes())
    end = datetime.fromisoformat(manifest['approval']['expires_at'])
    start = datetime.fromisoformat(manifest['approval']['approved_at'])
    assert end - start == timedelta(days=manifest['approval']['validity_days'])
    assert namespace['approval_window'](manifest, start)['io.cats.approval.expires-at'] == end.isoformat()
    with pytest.raises(ValueError, match='expired'):
        namespace['approval_window'](manifest, end)
    with pytest.raises(ValueError, match='not yet valid'):
        namespace['approval_window'](manifest, start - timedelta(seconds=1))
    class ExpiredClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return end
    namespace['datetime'] = ExpiredClock
    original = namespace['run']
    calls = []
    def run(args):
        calls.append(args)
        return original(args)
    namespace['run'] = run
    monkeypatch.setattr(sys, 'argv', ['verify-import.py', '--fingerprint', environment.fingerprint,
                                     '--destination', 'offline.example/approved'])
    with pytest.raises(ValueError, match='expired'):
        namespace['main']()
    assert not any(args[0] == 'oras' for args in calls)
    # Expiry is covered by the real signed manifest, not editable import metadata.
    manifest['approval']['expires_at'] = (end + timedelta(days=90)).isoformat()
    (output / 'release-manifest.json').write_bytes(publication.canonical(manifest))
    with pytest.raises(subprocess.CalledProcessError):
        publication.verify_local(output, environment.fingerprint)


def test_offline_requires_same_signed_expiry_on_every_artifact(environment, tmp_path, monkeypatch):
    original = signing.sign_and_verify
    def sign_without_window(reference, config, credentials, env):
        return original(reference, {**config, 'approval_annotations':{}}, credentials, env)
    monkeypatch.setattr(signing, 'sign_and_verify', sign_without_window)
    with pytest.raises(publication.PublicationError):
        publish(environment, [])


def test_publication_rejects_legacy_approval_without_registry_writes(environment):
    environment.approval.snapshot.pop('approval_validity')
    environment.approval.snapshot_digest = release_oci._digest(publication.canonical(environment.approval.snapshot))
    with pytest.raises(publication.PublicationError):
        publish(environment, [])
    assert not any(host == 'approved.example' for host, _ in environment.stores)

@pytest.mark.parametrize('exception,expected', [
    (release_oci._RegistryError(403), 'Registry access was denied'),
    (PermissionError('secret /private/key.pem'), 'mount ownership'),
    (subprocess.CalledProcessError(7, ['tool', 'secret'], stderr=b'secret'), 'tool exited'),
    (ValueError('secret'), 'Unexpected publication error'),
])
def test_publication_failure_retains_safe_stage_and_cause(environment, monkeypatch, exception, expected):
    def fail(*args, **kwargs):
        raise exception
    monkeypatch.setattr(publication._Transport, 'graph', fail)
    checkpoints = []
    with pytest.raises(publication.PublicationError) as caught:
        publish(environment, checkpoints)
    receipt = caught.value.receipt
    assert receipt == checkpoints[-1]
    assert receipt['diagnostic']['stage'] == 'Transferring and verifying artifact 1 of 2'
    assert expected in receipt['diagnostic']['cause']
    assert 'secret' not in json.dumps(receipt)
    if isinstance(exception, release_oci._RegistryError):
        assert receipt['diagnostic']['http_status'] == 403
    if isinstance(exception, subprocess.CalledProcessError):
        assert receipt['diagnostic']['exit_code'] == 7


def test_missing_evidence_has_specific_safe_cause(environment):
    Path(environment.approval.snapshot['evidence']['path']).unlink()
    with pytest.raises(publication.PublicationError) as caught:
        publish(environment, [])
    assert caught.value.receipt['diagnostic'] == {
        'stage': 'Checking retained evidence', 'cause': 'Frozen release evidence is missing or changed'}


def test_worker_publication_passes_current_admin_trust_to_destination(environment, monkeypatch):
    certificates = [{'pem': 'portal-root'}, {'pem': 'portal-intermediate'}]
    environment.db.scalars = lambda query: [SimpleNamespace(
        key='trusted_ca_certificates', value=json.dumps(certificates))]
    seen = []

    @contextmanager
    def destination_env(destination, supplied):
        seen.append(deepcopy(supplied))
        yield {}

    monkeypatch.setattr(publication, 'registry_environment', destination_env)
    assert publish(environment, [])['status'] == 'published'
    certificates[1]['pem'] = 'rotated-intermediate'
    assert publish(environment, [])['status'] == 'published'
    assert seen == [[{'pem': 'portal-root'}, {'pem': 'portal-intermediate'}], certificates]
