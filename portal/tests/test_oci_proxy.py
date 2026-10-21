import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import oci_proxy as proxy
from app.database import Base
from app.models import Service
from app.oci_models import OCIPrincipal, OCIRepository, OCIUpstream


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def setup(monkeypatch, tmp_path):
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    blob = b'abcdefghij'
    blob_digest = digest(blob)
    raw = json.dumps({'schemaVersion': 2, 'config': {'digest': blob_digest, 'size': len(blob)}, 'layers': []}).encode()
    image = digest(raw)
    documents = {image: raw, 'latest': raw}
    allowed = {image}
    class Transport:
        def fetch_manifest(self, repository, reference):
            if reference not in documents:
                raise proxy.RegistryError('Missing', 404)
            content = documents[reference]
            return content, 'application/vnd.oci.image.manifest.v1+json', digest(content)
        def fetch_blob(self, repository, reference, cache):
            import io
            return cache.get(reference) or cache.store(reference, io.BytesIO(blob))
        def referrers(self, repository, reference):
            return {'manifests': []}
    with sessions() as db:
        service = Service(service_key='proxy', name='Proxy')
        upstream = OCIUpstream(name='upstream', endpoint='https://registry.example')
        db.add_all([service, upstream]); db.flush()
        mapping = OCIRepository(public_repository='project/image', service_id=service.id,
            upstream_id=upstream.id, upstream_repository='team/image')
        db.add(mapping); db.flush()
        machine = OCIPrincipal(name='robot', secret_hash=hashlib.sha256(b'secret').hexdigest(),
            repository_ids=[mapping.id], expires_at=datetime.now(timezone.utc) + timedelta(days=1))
        db.add(machine); db.commit()
        machine_id, mapping_id = machine.id, mapping.id
    monkeypatch.setattr(proxy, 'SessionLocal', sessions)
    monkeypatch.setattr(proxy, 'client', lambda mapping: Transport())
    monkeypatch.setattr(proxy, 'authorize', lambda db, mapping, value: SimpleNamespace(
        allowed=value in allowed and mapping.enabled and not mapping.suspended, reason='test_denied'))
    monkeypatch.setenv('CATS_OCI_CACHE_DIR', str(tmp_path))
    client = TestClient(proxy.app)
    client.headers['Authorization'] = 'Basic ' + base64.b64encode(b'robot:secret').decode()
    yield SimpleNamespace(client=client, image=image, blob=blob_digest, allowed=allowed,
                          documents=documents, sessions=sessions, machine_id=machine_id, mapping_id=mapping_id)
    engine.dispose()


def test_pull_head_range_and_cache_revocation(setup):
    s = setup
    path = '/v2/project/image/'
    assert s.client.get(path + 'blobs/' + s.blob).status_code == 403
    response = s.client.get(path + 'manifests/latest')
    assert response.status_code == 200
    assert response.headers['Docker-Content-Digest'] == s.image
    assert s.client.head(path + 'manifests/' + s.image).content == b''
    response = s.client.get(path + 'blobs/' + s.blob, headers={'Range': 'bytes=2-5'})
    assert response.status_code == 206 and response.content == b'cdef'
    assert response.headers['Content-Range'] == 'bytes 2-5/10'
    assert s.client.get(path + 'blobs/' + s.blob, headers={'Range': 'bytes=-3'}).content == b'hij'
    assert s.client.get(path + 'blobs/' + s.blob, headers={'Range': 'bytes=15-'}).status_code == 416
    assert s.client.head(path + 'blobs/' + s.blob).headers['Content-Length'] == '10'
    s.allowed.clear()
    assert s.client.get(path + 'blobs/' + s.blob).status_code == 403
    assert s.client.get(path + 'manifests/' + s.image).status_code == 403


def test_machine_expiry_grants_and_disable(setup):
    s = setup
    assert s.client.get('/v2/').status_code == 200
    assert s.client.get('/v2/', headers={'Authorization': ''}).status_code == 401
    assert s.client.get('/v2/', headers={'Authorization': 'Basic !!!'}).status_code == 401
    with s.sessions() as db:
        machine = db.get(OCIPrincipal, s.machine_id)
        machine.repository_ids = []
        db.commit()
    assert s.client.get('/v2/project/image/manifests/latest').status_code == 403
    with s.sessions() as db:
        db.get(OCIPrincipal, s.machine_id).enabled = False
        db.commit()
    assert s.client.get('/v2/').status_code == 401


def test_tag_reassignment_and_index_child_denied(setup):
    s = setup
    path = '/v2/project/image/manifests/'
    assert s.client.get(path + 'latest').status_code == 200
    changed = json.dumps({'schemaVersion': 2, 'config': {'digest': s.blob, 'size': 10}, 'layers': [], 'annotations': {'changed': 'yes'}}).encode()
    s.documents['latest'] = changed
    assert s.client.get(path + 'latest').status_code == 403
    index = json.dumps({'schemaVersion': 2, 'manifests': [{'digest': digest(changed), 'size': len(changed)}]}).encode()
    s.documents[digest(changed)] = changed
    s.documents['multi'] = index
    s.allowed.add(digest(index))
    assert s.client.get(path + 'multi').status_code == 403
    s.allowed.add(digest(changed))
    assert s.client.get(path + 'multi').status_code == 200
    s.allowed.remove(digest(changed))
    assert s.client.get(path + digest(index)).status_code == 403


@pytest.mark.parametrize('header', ['bytes=-0', 'bytes=4-2', 'bytes=0-1,4-5', 'garbage'])
def test_invalid_ranges(header):
    with pytest.raises(proxy.Denied):
        proxy.byte_range(header, 10)


def test_untrusted_subject_artifact_cannot_grant_blob_access(setup, monkeypatch):
    s = setup
    transport = proxy.client(None)
    artifact = json.dumps({'schemaVersion': 2, 'subject': {'digest': s.image,
        'size': len(s.documents[s.image])}, 'config': {'digest': s.blob, 'size': 10},
        'layers': [], 'artifactType': 'application/untrusted'}).encode()
    artifact_digest = digest(artifact)
    s.documents[artifact_digest] = artifact
    transport.referrers = lambda *args: {'manifests': [{'digest': artifact_digest,
        'size': len(artifact), 'artifactType': 'application/untrusted'}]}
    monkeypatch.setattr(proxy, 'client', lambda mapping: transport)
    response = s.client.get('/v2/project/image/referrers/' + s.image)
    assert response.status_code == 200
    assert response.json()['manifests'] == []
    assert s.client.get('/v2/project/image/manifests/' + artifact_digest).status_code == 403
    assert s.client.get('/v2/project/image/blobs/' + s.blob).status_code == 403


def test_revocation_during_upstream_manifest_fetch(setup, monkeypatch):
    s = setup
    transport = proxy.client(None)
    fetch = transport.fetch_manifest
    def revoke(*args):
        result = fetch(*args)
        s.allowed.clear()
        return result
    transport.fetch_manifest = revoke
    monkeypatch.setattr(proxy, 'client', lambda mapping: transport)
    assert s.client.get('/v2/project/image/manifests/latest').status_code == 403


@pytest.fixture
def signed_tag(setup, monkeypatch):
    from app import release_revisions as revisions
    s = setup
    replacement = json.dumps({'schemaVersion': 2, 'config': {'digest': s.blob, 'size': 10},
        'layers': [], 'annotations': {'revision': 'patched'}}).encode()
    target = digest(replacement)
    s.documents[target] = replacement
    s.allowed.add(target)
    with s.sessions() as db:
        mapping = db.get(OCIRepository, s.mapping_id)
        binding = dict(repository_id=mapping.id, public_repository=mapping.public_repository,
            tag='latest', artifact_id=7, digest=target, upstream_id=mapping.upstream_id,
            endpoint=mapping.upstream.endpoint, upstream_repository=mapping.upstream_repository)
        db.add(revisions.ServiceActiveRelease(service_id=mapping.service_id, revision_id=None))
        db.commit()
    active = SimpleNamespace(id=71, manifest=dict(distribution_bindings=[binding],
        artifacts=[dict(id=7, digest=target)]))
    monkeypatch.setattr(revisions, 'active_revision', lambda *a: active)
    return s, active, binding, target


def test_signed_tag_uses_active_digest_and_never_substitutes_digest_pull(signed_tag):
    s, active, binding, target = signed_tag
    response = s.client.get('/v2/project/image/manifests/latest')
    assert response.status_code == 200
    assert response.headers['Docker-Content-Digest'] == target
    # The mutable upstream tag still points at the original image.
    assert digest(s.documents['latest']) == s.image
    direct = s.client.get('/v2/project/image/manifests/' + s.image)
    assert direct.status_code == 200
    assert direct.headers['Docker-Content-Digest'] == s.image


def test_unbound_tag_and_changed_location_fail_closed(signed_tag):
    s, active, binding, target = signed_tag
    assert s.client.get('/v2/project/image/manifests/other').status_code == 403
    with s.sessions() as db:
        db.get(OCIRepository, s.mapping_id).upstream_repository = 'other/image'
        db.commit()
    assert s.client.get('/v2/project/image/manifests/latest').status_code == 403


def test_revision_switch_during_fetch_denies_response(signed_tag, monkeypatch):
    from app import release_revisions as revisions
    s, active, binding, target = signed_tag
    changed = SimpleNamespace(id=active.id + 1, manifest=active.manifest)
    calls = []
    def current(*args):
        calls.append(1)
        return active if len(calls) == 1 else changed
    monkeypatch.setattr(revisions, 'active_revision', current)
    assert s.client.get('/v2/project/image/manifests/latest').status_code == 403
    assert len(calls) == 2
