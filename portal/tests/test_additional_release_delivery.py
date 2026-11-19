"""Approved release fan-out, authority, verification and retry isolation."""
import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import additional_release_delivery as additional, cyber_approvals as approvals
from app import cyber_release_publication as publication, portable_release, release_oci
from app.durable_jobs import DurableJob, JobError
from app.service_oci import ServiceOCIDestination
from test_cyber_approvals import PERMISSIONS, auth, db, request
from test_cyber_approval_worker import worker
from test_cyber_release_publication import environment, publish


def target(service_id=1, **overrides):
    return ServiceOCIDestination(**{'service_id': service_id, 'name': 'Service registry',
        'endpoint': 'https://service.example', 'namespace': 'managed', **overrides})


def submit(db, actor, target_id):
    return asyncio.run(approvals.request_approval(request({'service_key': 'one',
        'additional_destination_id': target_id}), db, actor))


def test_selection_is_service_scoped_and_independent_of_cyber_default(db):
    db.add_all([target(password='encrypted-private'), target(2)])
    db.commit()
    manager = auth(permissions=(*PERMISSIONS, 'service.edit'))
    assert additional.options(db, 1) == [{'id': '1', 'name': 'Service registry', 'endpoint': 'https://service.example', 'namespace': 'managed'}]
    with pytest.raises(HTTPException) as denied:
        submit(db, auth(), '1')
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as foreign:
        submit(db, manager, '2')
    assert foreign.value.status_code == 422
    result = submit(db, manager, '1')
    assert result['destination']['endpoint'] == 'https://registry.example'
    assert result['additional_destination']['endpoint'] == 'https://service.example'
    assert result['snapshot']['additional_destination'] == result['additional_destination']
    assert 'encrypted-private' not in str(result)
    assert result['additional_deliveries'] == []
    assert not list(db.scalars(select(DurableJob)))


def test_api_cannot_replace_eligible_cyber_default(db):
    default = db.get(approvals.ApprovedReleaseDestination, 1)
    default.is_default = True
    alternate = approvals.ApprovedReleaseDestination(name='Second Cyber destination', endpoint='https://second.example')
    db.add_all([alternate, target()])
    db.commit()
    actor = auth(permissions=(*PERMISSIONS, 'service.edit'))
    data = {'service_key': 'one', 'destination_id': alternate.id, 'additional_destination_id': '1'}
    with pytest.raises(HTTPException, match='Cyber default') as blocked:
        asyncio.run(approvals.request_approval(request(data), db, actor))
    assert blocked.value.status_code == 422
    default.enabled = False
    db.commit()
    assert asyncio.run(approvals.request_approval(request(data), db, actor))['destination']['id'] == alternate.id


def test_optional_target_cannot_be_an_alias_for_primary(db):
    db.add(target(endpoint='https://REGISTRY.example:443', namespace='approved'))
    db.commit()
    with pytest.raises(HTTPException, match='different from the Cyber'):
        submit(db, auth(permissions=(*PERMISSIONS, 'service.edit')), '1')


def prepare(worker):
    with worker.factory() as session:
        row = session.get(approvals.CyberApproval, worker.identity)
        other = target(row.service_id)
        session.add(other)
        session.flush()
        row.snapshot = {**row.snapshot, 'additional_destination': additional.freeze_target(session,
            auth(permissions=(*PERMISSIONS, 'service.edit')), row.service_id, str(other.id), row.destination)}
        row.snapshot_digest = approvals.digest(row.snapshot)
        session.commit()
    approvals.publish_job(worker.ctx, {'approval_id': worker.identity})
    with worker.factory() as session:
        row = session.get(approvals.CyberApproval, worker.identity)
        entry = session.get(additional.AdditionalReleaseDelivery, (row.id, 'release'))
        assert row.publish_status == 'published'
        assert row.job_id != entry.job_id and entry.status == 'queued'
        worker.ctx.job.id = entry.job_id
        return session.get(DurableJob, entry.job_id).payload


@pytest.mark.parametrize('failure', ['endpoint', 'namespace', 'ca', 'wrong-service', 'copy', 'revoked', 'expired'])
def test_secondary_failure_preserves_verified_primary_and_fences_retries(worker, monkeypatch, failure):
    payload = prepare(worker)
    def copy(*args):
        if failure != 'copy':
            pytest.fail('Frozen destination and validity must be checked before registry access')
        raise RuntimeError('SECRET_TOKEN')
    monkeypatch.setattr(additional, '_copy', copy)
    with worker.factory() as session:
        row = session.get(approvals.CyberApproval, worker.identity)
        entry = session.scalar(select(ServiceOCIDestination))
        if failure == 'endpoint':
            entry.endpoint = 'https://elsewhere.example'
        elif failure == 'namespace':
            entry.namespace = 'different'
        elif failure == 'ca':
            entry.ca_pem = 'different'
        elif failure == 'wrong-service':
            entry.service_id += 1
        elif failure == 'revoked':
            row.revoked_at = datetime.now(timezone.utc)
        elif failure == 'expired':
            row.snapshot = {**row.snapshot, 'approval_validity': {}}
            row.snapshot_digest = approvals.digest(row.snapshot)
        session.commit()
    with pytest.raises(JobError) as failed:
        approvals.publish_job(worker.ctx, payload)
    assert 'SECRET_TOKEN' not in str(failed.value)
    with worker.factory() as session:
        row = session.get(approvals.CyberApproval, worker.identity)
        delivery = session.get(additional.AdditionalReleaseDelivery, (row.id, 'release'))
        assert row.publish_status == 'published' and row.publication == worker.receipt
        assert delivery.status == 'failed'
        if failure in ('revoked', 'expired'):
            with pytest.raises(HTTPException) as blocked:
                approvals.retry_additional(row.id, 'release', request(), session, auth())
            assert blocked.value.status_code == 409
            return
        result = approvals.retry_additional(row.id, 'release', request(), session, auth())
        assert result['additional_deliveries'][0]['status'] == 'queued'
        assert row.job_id == 'job-1' and delivery.job_id != worker.ctx.job.id
        with pytest.raises(HTTPException) as duplicate:
            approvals.retry_additional(row.id, 'release', request(), session, auth())
        assert duplicate.value.status_code == 409
    with pytest.raises(JobError, match='unavailable'):
        approvals.publish_job(worker.ctx, payload)


def test_additional_queue_full_preserves_primary(worker, monkeypatch):
    ordinary = additional.submit
    def full(*args, **kwargs):
        if kwargs['payload'].get('additional_delivery'):
            raise HTTPException(429, 'queue full')
        return ordinary(*args, **kwargs)
    monkeypatch.setattr(additional, 'submit', full)
    with worker.factory() as session:
        row = session.get(approvals.CyberApproval, worker.identity)
        row.snapshot = {**row.snapshot, 'additional_destination': {'id': '1'}}
        row.snapshot_digest = approvals.digest(row.snapshot)
        session.commit()
    approvals.publish_job(worker.ctx, {'approval_id': worker.identity})
    with worker.factory() as session:
        row = session.get(approvals.CyberApproval, worker.identity)
        delivery = session.get(additional.AdditionalReleaseDelivery, (row.id, 'release'))
        assert row.publish_status == 'published' and delivery.status == 'failed'
        assert 'queue is full' in delivery.error


def test_copy_verifies_same_signed_release_evidence_and_revocation_on_second_registry(environment, monkeypatch):
    receipt = publish(environment, [])
    source = {**environment.destination, 'password': 'cyber credential'}
    target = {'endpoint': 'https://service.example', 'namespace': 'managed', 'password': 'service credential'}
    @contextmanager
    def scoped(destination, certificates):
        yield {'credential': destination['password']}
    monkeypatch.setattr(additional, 'registry_environment', scoped)
    registry = release_oci._Client
    class ScopedRegistry(registry):
        def __init__(self, host, repository, env, *, pull_only=False):
            assert env['credential'] == ('cyber credential' if host == 'approved.example' else 'service credential')
            assert host == 'service.example' or pull_only
            super().__init__(host, repository, env, pull_only=pull_only)
            self.repository = repository
    monkeypatch.setattr(release_oci, '_Client', ScopedRegistry)
    def copy(item):
        return additional._copy(environment.approval, item, source, target, [], lambda **kwargs: None)
    for _ in range(2):
        ref = copy(receipt)
        assert ref == receipt['release']['reference'].replace('approved.example/team/', 'service.example/managed/')
        verified = portable_release.fetch_release(ref, {'credential': 'service credential'}, [environment.fingerprint], repository_prefix='managed')
        assert verified['evidence'] == Path(environment.approval.snapshot['evidence']['path']).read_bytes()
        assert verified['manifest'] == receipt['manifest'] and len(verified['artifacts']) == 2
    artifact = receipt['artifacts'][0]
    _, repository, _ = release_oci._reference(artifact['reference'])
    secondary = environment.stores['service.example', repository.replace('team/', 'managed/', 1)]['manifests']
    source_tags = environment.stores['approved.example', repository]['manifests']
    signature = artifact['signature']
    for tags in (source_tags, secondary):
        tags[signature['tag']] = b'newer signature alias'
    assert copy(receipt) == ref
    assert secondary[signature['tag']] == b'newer signature alias'
    assert release_oci._digest(secondary[signature['retention_tag']]) == signature['digest']
    # The verified primary event is independently retained and signed in the same discovery repository.
    monkeypatch.setattr(release_oci, '_Client', registry)
    approval = environment.approval
    approval.revoked_at = datetime.now(timezone.utc)
    approval.revocation_reason = 'Withdraw release'
    metadata = {**approval.snapshot['portable_release'], 'kind': 'revocation', 'release_sequence': 2,
                'release_uuid': 'withdraw-test', 'target_release_uuid': str(approval.id), 'revoked_by_id': 2,
                'revoked_at': approval.revoked_at.isoformat(), 'reason': approval.revocation_reason}
    revocation = publication.publish_revocation(environment.db, approval, environment.destination, metadata, lambda _: None)
    monkeypatch.setattr(release_oci, '_Client', ScopedRegistry)
    ref = copy(revocation)
    verified = portable_release.fetch_release(ref, {'credential': 'service credential'}, [environment.fingerprint])
    assert verified['portable_release'] == metadata and verified['revoked_at'] == approval.revoked_at


def test_incomplete_additional_copy_never_exposes_discovery_tag(environment, monkeypatch):
    receipt = publish(environment, [])
    monkeypatch.setattr(additional, 'registry_environment', publication.registry_environment)
    release = receipt['release']
    host, repo, _ = release_oci._reference(release['reference'])
    del environment.stores[host, repo]['blobs'][environment.approval.snapshot['evidence']['digest']]
    with pytest.raises(release_oci._RegistryError):
        additional._copy(environment.approval, receipt, environment.destination,
                         {'endpoint': 'https://service.example', 'namespace': 'managed'}, [], lambda **kwargs: None)
    assert not any(host == 'service.example' for host, repo in environment.stores)
