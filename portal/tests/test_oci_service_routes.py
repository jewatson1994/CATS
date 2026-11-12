"""Service-bound adjudication through synchronous registry request handlers."""
import base64
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from starlette.requests import Request

from app import oci_proxy as proxy
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.execution_summaries import payload_digest
from app.models import AuditEvent, Execution, Service, ServiceArchiveEvent
from app.oci_models import OCIPrincipal, OCIRepository
from test_oci_proxy import project, registry, setup, signed_tag
from test_replica_authorization import replica, grant, decision


def request(method='GET'):
    return Request({'type': 'http', 'method': method, 'path': '/',
        'headers': [(b'authorization', b'Basic ' + base64.b64encode(b'robot:secret'))]})


def manifest(repository, reference):
    return proxy.get_manifest(repository, reference, request())


def blob(repository, digest):
    return proxy.get_blob(repository, digest, request('HEAD'))


def referrers(repository, digest):
    return proxy.referrers(repository, digest, request())


def test_same_registry_bytes_require_the_requested_services_own_approval(project):
    s = project
    first = s.routes[s.scanned]
    second = f'cyber-approved/{s.service_ids[s.published]}/api'
    assert manifest(first, 'latest').status_code == 200
    assert blob(first, s.blob).status_code == 200
    for operation, reference in ((manifest, s.image), (blob, s.blob), (referrers, s.image)):
        with pytest.raises(proxy.Denied):
            operation(second, reference)
    with s.sessions() as db:
        original = db.get(CyberApproval, s.approvals[s.scanned])
        approval = db.get(CyberApproval, s.approvals[s.published])
        execution = db.get(Execution, approval.source_execution_id)
        execution.raw_payload = db.get(Execution, original.source_execution_id).raw_payload
        approval.snapshot = dict(approval.snapshot, artifacts=original.snapshot['artifacts'],
            source_payload_digest=payload_digest(execution.raw_payload))
        approval.snapshot_digest = snapshot_digest(approval.snapshot)
        db.commit()
    with pytest.raises(proxy.Denied):
        blob(second, s.blob)
    assert manifest(second, s.image).status_code == 200
    assert blob(second, s.blob).status_code == 200
    with s.sessions() as db:
        db.get(CyberApproval, s.approvals[s.published]).revoked_at = datetime.now(timezone.utc)
        db.commit()
    for operation, reference in ((manifest, s.image), (blob, s.blob), (referrers, s.image)):
        with pytest.raises(proxy.Denied):
            operation(second, reference)
        assert operation(first, reference).status_code == 200


@pytest.mark.parametrize('repository', ['project/image', 'project/0/image', 'project/01/image',
    'project/+1/image', 'project/-1/image', 'project/service/image', 'project/1',
    'project/1/', 'project/999999999999999999999999999999/image', 'project/999/image'])
def test_missing_invalid_or_unknown_service_never_reaches_upstream(setup, repository):
    with pytest.raises(proxy.Denied):
        manifest(repository, 'latest')
    assert setup.fetches == []


def test_exact_mapping_mismatch_cannot_fall_back_to_valid_legacy_alias(setup):
    s = setup
    with s.sessions() as db:
        original = db.get(OCIRepository, s.mapping_id)
        other = Service(service_key='other', name='Other')
        db.add(other)
        db.flush()
        exact = OCIRepository(public_repository='project/1/image', service_id=other.id,
            upstream_id=original.upstream_id, upstream_repository=original.upstream_repository)
        db.add(exact)
        db.flush()
        db.get(OCIPrincipal, s.machine_id).repository_ids = [original.id, exact.id]
        db.commit()
    with pytest.raises(proxy.Denied, match='different service'):
        manifest('project/1/image', 'latest')
    assert s.fetches == []


@pytest.mark.parametrize('state', ['staged', 'archived'])
def test_service_retirement_denies_warm_manifest_blob_and_referrers(project, state):
    s = project
    repository = s.routes[s.scanned]
    assert manifest(repository, s.image).status_code == 200
    assert blob(repository, s.blob).status_code == 200
    with s.sessions() as db:
        service = db.get(Service, s.service_ids[s.scanned])
        if state == 'archived':
            db.add(ServiceArchiveEvent(service_id=service.id, action='archive',
                reason='Service retired', performed_by='Cyber'))
        else:
            service.lifecycle_status = state
        db.commit()
    for operation, reference in ((manifest, s.image), (blob, s.blob), (referrers, s.image)):
        with pytest.raises(proxy.Denied, match='not active'):
            operation(repository, reference)


def test_scoped_alias_preserves_signed_mapping_identity(signed_tag):
    s, active, binding, target = signed_tag
    response = manifest('project/1/image', 'latest')
    assert response.status_code == 200
    assert response.headers['Docker-Content-Digest'] == target
    assert binding['public_repository'] == 'project/image'
    with s.sessions() as db:
        assert db.get(OCIRepository, s.mapping_id).public_repository == 'project/image'
    with pytest.raises(proxy.Denied):
        manifest('project/image', 'latest')


def test_scoped_project_tag_preserves_signed_logical_repository(project, monkeypatch):
    from app import release_revisions as revisions
    s = project
    service_id = s.service_ids[s.scanned]
    with s.sessions() as db:
        db.add(revisions.ServiceActiveRelease(service_id=service_id, revision_id=None))
        mapping = db.get(OCIRepository, s.mapping_id)
        binding = dict(repository_id=mapping.id, public_repository=s.scanned, tag='latest',
            artifact_id=7, digest=s.image, upstream_id=mapping.upstream_id,
            endpoint=mapping.upstream.endpoint, upstream_repository=s.scanned,
            mapping_upstream_repository=mapping.upstream_repository,
            mapping_public_repository=mapping.public_repository)
        db.commit()
    active = SimpleNamespace(id=71, approval_id=s.approvals[s.scanned],
        manifest=dict(distribution_bindings=[], artifacts=[]))
    monkeypatch.setattr(revisions, 'active_revision', lambda db, identity, *args:
        active if identity == service_id else None)
    assert manifest(s.routes[s.scanned], s.image).status_code == 200
    with pytest.raises(proxy.Denied):
        manifest(s.routes[s.scanned], 'latest')
    active.manifest = dict(distribution_bindings=[binding], artifacts=[dict(id=7, digest=s.image)])
    assert manifest(s.routes[s.scanned], 'latest').status_code == 200
    assert binding['public_repository'] == s.scanned


def test_mapping_service_reassignment_during_fetch_cannot_deliver(setup, monkeypatch):
    s = setup
    with s.sessions() as db:
        other = Service(service_key='other', name='Other')
        db.add(other)
        db.commit()
        other_id = other.id
    transport = proxy.client(None)
    fetch = transport.fetch_manifest
    def reassign(repository, reference):
        result = fetch(repository, reference)
        with s.sessions() as db:
            db.get(OCIRepository, s.mapping_id).service_id = other_id
            db.commit()
        return result
    transport.fetch_manifest = reassign
    monkeypatch.setattr(proxy, 'client', lambda mapping: transport)
    with pytest.raises(proxy.Denied):
        manifest('project/1/image', 'latest')
    with s.sessions() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == 'oci.pull')
            .order_by(AuditEvent.id.desc()))
        assert event.detail['request_repository'] == 'project/1/image'
        assert event.detail['service_id'] == 1
        assert event.detail['mapped_service_id'] == other_id


def test_admin_exposes_consumer_route_without_changing_mapping_identity(registry):
    from app import oci_admin
    from fastapi import HTTPException
    with registry.sessions() as db:
        mapping = db.get(OCIRepository, registry.mapping_id)
        assert oci_admin.public(mapping)['pull_repository'] == 'project/1/image'
        assert oci_admin.public(mapping)['public_repository'] == 'project/image'
        with pytest.raises(HTTPException) as denied:
            oci_admin._save_repository(db, mapping, {'public_repository': 'project/2/image'})
        assert denied.value.status_code == 422
        assert mapping.public_repository == 'project/image'


def test_numeric_image_name_is_not_mistaken_for_service_segment(setup):
    s = setup
    with s.sessions() as db:
        mapping = db.get(OCIRepository, s.mapping_id)
        mapping.public_repository = 'project/123'
        db.commit()
    assert manifest('project/1/123', 'latest').status_code == 200
    assert s.fetches == [('team/image', 'latest')]
    with pytest.raises(proxy.Denied):
        manifest('project/123', 'latest')


@pytest.mark.parametrize('state', ['staged', 'archived'])
def test_replica_service_lifecycle_precedes_approval_and_override(replica, state):
    grant(replica)
    assert decision(replica, replica.new).allowed
    assert decision(replica).allowed
    with replica.sessions() as db:
        service = db.get(Service, replica.service_id)
        if state == 'archived':
            db.add(ServiceArchiveEvent(service_id=service.id, action='archive',
                reason='Service retired', performed_by='Cyber'))
        else:
            service.lifecycle_status = state
        db.commit()
    assert decision(replica, replica.new).reason == 'service_inactive'
    assert decision(replica).reason == 'service_inactive'
