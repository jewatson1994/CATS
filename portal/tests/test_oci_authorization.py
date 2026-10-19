from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import main, oci_authorization as auth
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.database import Base
from app.execution_summaries import payload_digest
from app.models import Execution, Service
from app.release_validity import new_validity

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
DIGEST = 'sha256:' + 'a' * 64
CANONICAL_VIEW = main.service_view


@pytest.fixture
def context(monkeypatch):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key='oci', name='OCI')
        db.add(service)
        db.flush()
        execution = Execution(service_id=service.id, execution_key='oci-scan',
            scanned_at=NOW, complete=True, scan_scope='service', raw_payload={})
        db.add(execution)
        db.flush()
        snapshot = dict(service_id=service.id, source_execution_id=execution.id,
            source_version_id=None, source_payload_digest=payload_digest({}),
            approval_validity=new_validity(NOW), artifacts=[dict(kind='image',
                reference='registry.example/team/image@' + DIGEST, digest=DIGEST)])
        approval = CyberApproval(service_id=service.id, source_execution_id=execution.id,
            variant='current', status='approved', snapshot=snapshot,
            snapshot_digest=snapshot_digest(snapshot), decided_at=NOW)
        db.add(approval)
        db.commit()
        mapping = SimpleNamespace(service_id=service.id, enabled=True, suspended=False,
            policy={}, upstream_repository='team/image', upstream=SimpleNamespace(
                endpoint='https://registry.example', enabled=True))
        monkeypatch.setattr(main, 'service_view', lambda *args: dict(incomplete=False, compliant=True))
        yield db, mapping, approval, execution
    engine.dispose()


def test_exact_approved_digest(context):
    db, mapping, approval, execution = context
    decision = auth.authorize(db, mapping, DIGEST, NOW)
    assert decision == auth.AuthorizationDecision(True, 'approved', approval.id, execution.id)
    assert not auth.authorize(db, mapping, 'latest', NOW).allowed
    assert not auth.authorize(db, mapping, 'sha256:' + 'b' * 64, NOW).allowed


@pytest.mark.parametrize('change', ['revoked', 'expired', 'incomplete', 'changed_payload', 'changed_snapshot', 'repository', 'registry', 'suspended', 'stale'])
def test_fail_closed(context, change):
    db, mapping, approval, execution = context
    now = NOW
    if change == 'revoked': approval.revoked_at = NOW
    if change == 'expired': now += timedelta(days=90)
    if change == 'incomplete': execution.complete = False
    if change == 'changed_payload': execution.raw_payload = {'changed': True}
    if change == 'changed_snapshot': approval.snapshot_digest = 'sha256:' + '0' * 64
    if change == 'repository': mapping.upstream_repository = 'other/image'
    if change == 'registry': mapping.upstream.endpoint = 'https://other.example'
    if change == 'suspended': mapping.suspended = True
    if change == 'stale':
        mapping.policy = {'max_scan_age_days': 1}
        now += timedelta(days=1)
    db.commit()
    assert not auth.authorize(db, mapping, DIGEST, now).allowed


def test_new_scan_cannot_reuse_approval(context):
    db, mapping, approval, execution = context
    db.add(Execution(service_id=mapping.service_id, execution_key='new',
        scanned_at=NOW + timedelta(seconds=1), complete=True, raw_payload={}))
    db.commit()
    assert auth.authorize(db, mapping, DIGEST, NOW + timedelta(seconds=2)).reason == 'digest_not_approved'


def test_canonical_policy_is_live(context, monkeypatch):
    db, mapping, _, _ = context
    monkeypatch.setattr(main, 'service_view', lambda *args: dict(incomplete=False, compliant=False))
    assert auth.authorize(db, mapping, DIGEST, NOW).reason == 'service_noncompliant'


def test_cross_service_approval_is_not_reused(context):
    db, mapping, approval, _ = context
    other = Service(service_key='other', name='Other')
    db.add(other)
    db.flush()
    approval.service_id = other.id
    db.commit()
    assert auth.authorize(db, mapping, DIGEST, NOW).reason == 'digest_not_approved'


@pytest.mark.parametrize('changes', [{'digest': None, 'reference': 'registry.example/team/image:latest'},
    {'resolve_at_publication': True}, {'format': 'docker-archive'}])
def test_mutable_or_archive_evidence_does_not_authorize(changes):
    artifact = dict(kind='image', reference='registry.example/team/image@' + DIGEST, digest=DIGEST)
    artifact.update(changes)
    assert not auth._artifact_matches({'artifacts': [artifact]}, 'registry.example/team/image', DIGEST)


def test_real_deadline_and_service_scoped_exception(context, monkeypatch):
    from app.models import Finding, ExceptionRecord
    db, mapping, _, _ = context
    monkeypatch.setattr(main, 'service_view', CANONICAL_VIEW)
    monkeypatch.setattr(main, 'configuration_for_service', lambda *args: {
        **main.CONFIG_DEFAULTS, 'compliance_mode': 'raw', 'overdue_days': '1', 'raw_due_rules': '[]'})
    start = NOW - timedelta(days=1)
    finding = Finding(service_id=mapping.service_id, cve='CVE-2026-1234', severity='High',
        first_seen=start, episode_started=start, last_seen=NOW)
    other = Service(service_key='excepted-other', name='Other')
    db.add_all([finding, other])
    db.flush()
    unrelated = Finding(service_id=other.id, cve=finding.cve, severity='High',
        first_seen=start, episode_started=start, last_seen=NOW)
    db.add(unrelated)
    db.flush()
    exception = ExceptionRecord(finding_id=unrelated.id, justification='Test', approved_by='Cyber',
        starts_at=start, expires_at=NOW + timedelta(days=1))
    db.add(exception)
    db.commit()
    assert auth.authorize(db, mapping, DIGEST, NOW).reason == 'service_noncompliant'
    exception.finding_id = finding.id
    db.commit()
    assert auth.authorize(db, mapping, DIGEST, NOW).allowed
    assert auth.authorize(db, mapping, DIGEST, NOW + timedelta(days=1)).reason == 'service_noncompliant'


def test_temporary_distribution_window_cannot_extend_approval(context):
    db, mapping, _, _ = context
    mapping.policy = {'max_approval_age_days': 1}
    assert auth.authorize(db, mapping, DIGEST, NOW).allowed
    assert auth.authorize(db, mapping, DIGEST, NOW + timedelta(days=1)).reason == 'approval_window_elapsed'


def test_pinned_chart_digest():
    artifact = dict(kind='chart', reference='registry.example/team/chart@' + DIGEST, digest=DIGEST)
    assert auth._artifact_matches({'artifacts': [artifact]}, 'registry.example/team/chart', DIGEST)
    artifact['path'] = '/chart.tgz'
    assert not auth._artifact_matches({'artifacts': [artifact]}, 'registry.example/team/chart', DIGEST)


def test_published_chart_requires_verified_source_binding(context):
    import copy
    db, mapping, approval, _ = context
    source_digest = 'sha256:' + 'b' * 64
    snapshot = copy.deepcopy(approval.snapshot)
    snapshot['artifacts'] = [dict(kind='chart', name='chart', path='/chart.tgz', digest=source_digest)]
    approval.snapshot = snapshot
    approval.snapshot_digest = snapshot_digest(snapshot)
    artifact = dict(kind='chart', reference='registry.example/team/image@' + DIGEST,
        digest=DIGEST, source_digest=source_digest, scan_identity_retained=True,
        identity_resolution='retained-evidence', verification_status='verified')
    receipt = dict(status='published', verification_status='verified', signature_status='verified',
        artifacts=[artifact], manifest=dict(approval_id=approval.id,
            snapshot_digest=approval.snapshot_digest, artifacts=[artifact]))
    approval.publish_status = 'published'
    approval.publication = receipt
    db.commit()
    assert auth.authorize(db, mapping, DIGEST, NOW).allowed
    receipt = copy.deepcopy(receipt)
    receipt['artifacts'][0]['source_digest'] = DIGEST
    approval.publication = receipt
    db.commit()
    assert not auth.authorize(db, mapping, DIGEST, NOW).allowed
