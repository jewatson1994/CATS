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
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.database import Base
from app.execution_summaries import payload_digest
from app.models import Execution, Service
from app.oci_models import OCIPrincipal, OCIRepository, OCIUpstream
from app.release_validity import new_validity


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def registry(monkeypatch, tmp_path):
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    blob = b'abcdefghij'
    blob_digest = digest(blob)
    raw = json.dumps({'schemaVersion': 2, 'config': {'digest': blob_digest, 'size': len(blob)}, 'layers': []}).encode()
    image = digest(raw)
    documents = {image: raw, 'latest': raw}
    fetches = []
    allowed = {image}
    class Transport:
        def fetch_manifest(self, repository, reference):
            fetches.append((repository, reference))
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
    upstream_client = proxy.client
    monkeypatch.setattr(proxy, 'SessionLocal', sessions)
    monkeypatch.setattr(proxy, 'client', lambda mapping: Transport())
    monkeypatch.setenv('CATS_OCI_CACHE_DIR', str(tmp_path))
    client = TestClient(proxy.app)
    client.headers['Authorization'] = 'Basic ' + base64.b64encode(b'robot:secret').decode()
    yield SimpleNamespace(client=client, image=image, blob=blob_digest, allowed=allowed,
                          documents=documents, fetches=fetches, sessions=sessions, machine_id=machine_id, mapping_id=mapping_id,
                          upstream_client=upstream_client)
    engine.dispose()


@pytest.fixture
def setup(registry, monkeypatch):
    monkeypatch.setattr(proxy, 'authorize', lambda db, mapping, value: SimpleNamespace(
        allowed=value in registry.allowed and mapping.enabled and not mapping.suspended, reason='test_denied'))
    return registry


@pytest.fixture
def project(registry):
    s = registry
    s.scanned = 'cyber-approved/api'
    s.published = 'cyber-approved/release-b/image-0'
    s.approvals = {}
    now = datetime.now(timezone.utc)
    with s.sessions() as db:
        mapping = db.get(OCIRepository, s.mapping_id)
        mapping.public_repository = mapping.upstream_repository = 'cyber-approved/*'
        mapping.service_id = None
        for repository in (s.scanned, s.published):
            service = Service(service_key=repository.split('/')[-1], name=repository)
            db.add(service)
            db.flush()
            destination = f'registry.example/{repository}@{s.image}'
            source = destination if repository == s.scanned else f'build.example/team/base@{s.image}'
            payload = {'service_overview': {'images': [{'image': source, 'digest': s.image}]}}
            execution = Execution(service_id=service.id, execution_key=service.service_key,
                scanned_at=now, complete=True, scan_scope='service', raw_payload=payload)
            db.add(execution)
            db.flush()
            artifact = dict(kind='image', reference=source, digest=s.image)
            snapshot = dict(service_id=service.id, source_execution_id=execution.id,
                source_version_id=None, source_payload_digest=payload_digest(payload),
                approval_validity=new_validity(now), artifacts=[artifact])
            approval = CyberApproval(service_id=service.id, source_execution_id=execution.id,
                variant='current', status='approved', snapshot=snapshot,
                snapshot_digest=snapshot_digest(snapshot), decided_at=now)
            db.add(approval)
            db.flush()
            if repository == s.published:
                published = [dict(artifact, reference=destination, source_digest=s.image,
                    scan_identity_retained=True, identity_resolution='retained-evidence',
                    verification_status='verified')]
                approval.publish_status = 'published'
                approval.publication = dict(status='published', verification_status='verified',
                    signature_status='verified', artifacts=published, manifest=dict(approval_id=approval.id,
                        snapshot_digest=approval.snapshot_digest, artifacts=published))
            s.approvals[repository] = approval.id
        db.commit()
    return s


def test_project_grant_rechecks_approval_and_isolates_repository_graphs(project):
    s = project
    scanned = f'/v2/{s.scanned}/'
    published = f'/v2/{s.published}/'
    response = s.client.get(scanned + 'manifests/latest')
    assert response.status_code == 200 and response.headers['Docker-Content-Digest'] == s.image
    assert (s.scanned, 'latest') in s.fetches
    assert s.client.get(scanned + 'blobs/' + s.blob).content == b'abcdefghij'

    # Both services approved identical bytes. A blob link and manifest cache entry
    # in the first repository must not grant either object in the second.
    assert s.client.get(published + 'blobs/' + s.blob).status_code == 403
    response = s.client.get(published + 'manifests/' + s.image)
    assert response.status_code == 200 and response.headers['Docker-Content-Digest'] == s.image
    assert (s.published, s.image) in s.fetches
    assert s.client.get(published + 'blobs/' + s.blob).content == b'abcdefghij'
    assert s.client.get(published + 'referrers/' + s.image).status_code == 200

    with s.sessions() as db:
        db.get(CyberApproval, s.approvals[s.published]).revoked_at = datetime.now(timezone.utc)
        db.commit()
    for route in ('manifests/' + s.image, 'blobs/' + s.blob, 'referrers/' + s.image):
        assert s.client.get(published + route).status_code == 403
    assert s.client.head(scanned + 'blobs/' + s.blob).status_code == 200


def test_project_grant_requires_exact_evidence_and_project_boundary(project):
    s = project
    raw = json.dumps({'schemaVersion': 2, 'config': {'digest': s.blob, 'size': 10},
        'layers': [], 'annotations': {'unreviewed': 'true'}}).encode()
    s.documents['latest'] = s.documents[digest(raw)] = raw
    for reference in ('latest', digest(raw)):
        assert s.client.get(f'/v2/{s.scanned}/manifests/{reference}').status_code == 403
    assert s.client.get(f'/v2/cyber-approved/other/manifests/{s.image}').status_code in (403, 404)
    for outside in ('cyber-approved', 'cyber-approved-extra/api', 'elsewhere/api'):
        assert s.client.get(f'/v2/{outside}/manifests/{s.image}').status_code == 404
        assert (outside, s.image) not in s.fetches


def test_project_grant_denies_ambiguous_owner_after_cache_warmup(project):
    s = project
    path = f'/v2/{s.scanned}/'
    assert s.client.get(path + 'manifests/' + s.image).status_code == 200
    with s.sessions() as db:
        first = db.get(CyberApproval, s.approvals[s.scanned])
        second = db.get(CyberApproval, s.approvals[s.published])
        second.snapshot = dict(second.snapshot, artifacts=first.snapshot['artifacts'])
        second.snapshot_digest = snapshot_digest(second.snapshot)
        db.commit()
    for route in ('manifests/' + s.image, 'blobs/' + s.blob, 'referrers/' + s.image):
        assert s.client.get(path + route).status_code == 403


def test_project_grant_cannot_bypass_exact_mapping_or_removed_grant(project):
    s = project
    with s.sessions() as db:
        project_mapping = db.get(OCIRepository, s.mapping_id)
        service = db.get(CyberApproval, s.approvals[s.scanned]).service_id
        exact = OCIRepository(public_repository=s.scanned, upstream_repository=s.scanned,
            upstream_id=project_mapping.upstream_id, service_id=service)
        db.add(exact)
        db.commit()
        exact_id = exact.id
    path = f'/v2/{s.scanned}/manifests/{s.image}'
    assert s.client.get(path).status_code == 403
    with s.sessions() as db:
        db.get(OCIPrincipal, s.machine_id).repository_ids = [exact_id]
        db.commit()
    assert s.client.get(path).status_code == 200
    assert s.client.get(f'/v2/{s.published}/manifests/{s.image}').status_code == 403
    with s.sessions() as db:
        db.get(OCIPrincipal, s.machine_id).repository_ids = [exact_id, s.mapping_id]
        db.get(OCIRepository, exact_id).suspended = True
        db.commit()
    assert s.client.get(path).status_code == 403


def test_project_grant_rejects_unbound_tags_for_revision_managed_service(project, monkeypatch):
    from app import release_revisions as revisions
    s = project
    with s.sessions() as db:
        approval = db.get(CyberApproval, s.approvals[s.scanned])
        service_id = approval.service_id
        db.add(revisions.ServiceActiveRelease(service_id=service_id, revision_id=None))
        db.commit()
    active = SimpleNamespace(id=71, approval_id=s.approvals[s.scanned],
        manifest=dict(distribution_bindings=[], artifacts=[]))
    monkeypatch.setattr(revisions, 'active_revision', lambda db, identity, *args:
        active if identity == service_id else None)
    assert s.client.get(f'/v2/{s.scanned}/manifests/{s.image}').status_code == 200
    assert s.client.get(f'/v2/{s.scanned}/manifests/latest').status_code == 403


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


def test_upstream_robot_credentials_are_separate_from_machine_login(setup, monkeypatch):
    from cryptography.fernet import Fernet
    from app.secrets import encrypt_secret

    s = setup
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    upstream_username, upstream_password = 'robot$cyber-approved+pull', 'harbor-robot-secret'
    machine_username, machine_password = 'cats-machine', 'cats-machine-secret'
    with s.sessions() as db:
        upstream = db.get(OCIRepository, s.mapping_id).upstream
        upstream.endpoint = 'https://harbor.example'
        upstream.username = encrypt_secret(upstream_username)
        upstream.password = encrypt_secret(upstream_password)
        machine = db.get(OCIPrincipal, s.machine_id)
        machine.name = machine_username
        machine.secret_hash = hashlib.sha256(machine_password.encode()).hexdigest()
        db.commit()

    transport = proxy.client(None)
    configurations = []
    def capture_client(configuration):
        configurations.append(configuration)
        return transport
    monkeypatch.setattr(proxy, 'RegistryClient', capture_client)
    monkeypatch.setattr(proxy, 'client', s.upstream_client)
    def basic(username, password):
        return 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode()

    s.client.headers['Authorization'] = basic(machine_username, machine_password)
    path = '/v2/project/image/'
    assert s.client.get(path + 'manifests/latest').status_code == 200
    assert s.client.get(path + 'blobs/' + s.blob).content == b'abcdefghij'
    assert len(configurations) == 2
    for configuration in configurations:
        assert configuration['endpoint'] == 'https://harbor.example'
        assert configuration['username'] == upstream_username
        assert configuration['password'] == upstream_password
        assert machine_username not in configuration.values()
        assert machine_password not in configuration.values()

    harbor_credentials = {'Authorization': basic(upstream_username, upstream_password)}
    assert s.client.get('/v2/', headers=harbor_credentials).status_code == 401
    assert s.client.get(path + 'manifests/latest', headers=harbor_credentials).status_code == 401
    assert len(configurations) == 2


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


def test_signed_cross_repository_routes_manifest_blob_and_referrers(signed_tag, monkeypatch):
    s, active, binding, target = signed_tag
    original = binding['upstream_repository']
    binding['mapping_upstream_repository'] = original
    binding['upstream_repository'] = 'patched/replacement'
    transport = proxy.client(None)
    calls = []
    for method in ('fetch_manifest', 'fetch_blob', 'referrers'):
        operation = getattr(transport, method)
        def traced(repository, *args, operation=operation, method=method):
            calls.append((method, repository))
            assert repository == 'patched/replacement'
            return operation(repository, *args)
        setattr(transport, method, traced)
    monkeypatch.setattr(proxy, 'client', lambda mapping: transport)
    assert s.client.get('/v2/project/image/manifests/latest').status_code == 200
    assert s.client.get('/v2/project/image/manifests/' + target).status_code == 200
    assert s.client.get('/v2/project/image/blobs/' + s.blob).status_code == 200
    assert s.client.get('/v2/project/image/referrers/' + target).status_code == 200
    assert ('fetch_blob', 'patched/replacement') in calls
    assert ('referrers', 'patched/replacement') in calls
    with s.sessions() as db:
        assert db.get(OCIRepository, s.mapping_id).upstream_repository == original
        db.get(OCIRepository, s.mapping_id).upstream_repository = 'mutated/path'
        db.commit()
    assert s.client.get('/v2/project/image/manifests/latest').status_code == 403
    assert s.client.get('/v2/project/image/manifests/' + target).status_code == 403
    assert s.client.get('/v2/project/image/blobs/' + s.blob).status_code == 403
