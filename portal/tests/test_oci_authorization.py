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


@pytest.fixture
def revision_context(context, monkeypatch):
    from app import release_revisions as revisions
    db, mapping, legacy, execution = context
    snapshot = dict(legacy.snapshot, release_revision=dict(artifact_ids=[1], base_revision_id=None))
    approval = CyberApproval(service_id=mapping.service_id, source_execution_id=execution.id,
        variant='current', status='approved', snapshot=snapshot,
        snapshot_digest=snapshot_digest(snapshot), decided_at=NOW)
    db.add(approval)
    db.flush()
    revision = revisions.ReleaseRevision(approval_id=approval.id, service_id=mapping.service_id,
        manifest={}, manifest_digest=snapshot_digest({}))
    db.add(revision)
    db.flush()
    state = revisions.ReleaseRevisionState(revision_id=revision.id, decision='approved')
    pointer = revisions.ServiceActiveRelease(service_id=mapping.service_id, revision_id=revision.id)
    db.add_all([state, pointer])
    db.commit()
    # Gateway tests isolate pointer enforcement; signature/artifact/expiry checks
    # have dedicated release_revision coverage and are invoked through this hook.
    monkeypatch.setattr(revisions, 'validate_activation', lambda *a: None)
    return db, mapping, legacy, approval, revision, state, pointer


def test_gateway_uses_only_active_revision(revision_context):
    db, mapping, legacy, approval, revision, state, pointer = revision_context
    decision = auth.authorize(db, mapping, DIGEST, NOW)
    assert decision.allowed
    assert decision.approval_id == approval.id


@pytest.mark.parametrize('restriction', ['suspended', 'revoked', 'missing_pointer', 'missing_state', 'unverified'])
def test_gateway_never_falls_back_to_legacy_approval(revision_context, monkeypatch, restriction):
    from app import release_revisions as revisions
    db, mapping, legacy, approval, revision, state, pointer = revision_context
    if restriction in {'suspended', 'revoked'}:
        setattr(state, restriction, True)
    elif restriction == 'missing_pointer':
        db.delete(pointer)
    elif restriction == 'missing_state':
        db.delete(state)
    else:
        def invalid(*args):
            raise ValueError('Signature or current artifact eligibility failed')
        monkeypatch.setattr(revisions, 'validate_activation', invalid)
    db.commit()
    result = auth.authorize(db, mapping, DIGEST, NOW)
    assert not result.allowed
    assert result.reason == 'active_revision_unavailable'
    assert legacy.status == 'approved'


def test_old_digest_cannot_use_legacy_approval_after_revision_switch(revision_context):
    db, mapping, legacy, approval, revision, state, pointer = revision_context
    new_digest = 'sha256:' + 'd' * 64
    snapshot = dict(approval.snapshot, artifacts=[dict(kind='image',
        reference='registry.example/team/image@' + new_digest, digest=new_digest)])
    approval.snapshot = snapshot
    approval.snapshot_digest = snapshot_digest(snapshot)
    db.commit()
    assert not auth.authorize(db, mapping, DIGEST, NOW).allowed
    assert auth.authorize(db, mapping, new_digest, NOW).approval_id == approval.id


def test_missing_revision_record_cannot_authorize_as_legacy(context):
    db, mapping, approval, _ = context
    approval.snapshot = dict(approval.snapshot, release_revision=dict(artifact_ids=[1], base_revision_id=None))
    approval.snapshot_digest = snapshot_digest(approval.snapshot)
    db.commit()
    assert auth.authorize(db, mapping, DIGEST, NOW).reason == 'active_revision_unavailable'


def test_cross_repository_location_requires_active_signed_binding(context, monkeypatch):
    db, mapping, approval, execution = context
    revisions = auth.release_revisions
    mapping.id, mapping.upstream_id, mapping.public_repository = 1, 2, 'public/stable'
    retained = dict(kind='image', reference='registry.example/patched/image@' + DIGEST, digest=DIGEST)
    approval.snapshot = dict(approval.snapshot, artifacts=[retained])
    approval.snapshot_digest = snapshot_digest(approval.snapshot)
    db.add(revisions.ServiceActiveRelease(service_id=mapping.service_id, revision_id=None))
    db.commit()
    binding = dict(repository_id=1, upstream_id=2, public_repository='public/stable',
        endpoint=mapping.upstream.endpoint, mapping_upstream_repository='team/image',
        upstream_repository='patched/image', tag='stable', artifact_id=7, digest=DIGEST)
    active = SimpleNamespace(approval_id=approval.id, manifest=dict(
        artifacts=[dict(id=7, digest=DIGEST)], distribution_bindings=[binding]))
    monkeypatch.setattr(revisions, 'active_revision', lambda *a: active)
    assert auth.authorize(db, mapping, DIGEST, NOW).allowed
    binding['upstream_repository'] = 'unapproved/image'
    assert not auth.authorize(db, mapping, DIGEST, NOW).allowed
    binding['upstream_repository'] = 'patched/image'
    mapping.upstream_repository = 'mutated/image'
    assert auth.authorize(db, mapping, DIGEST, NOW).reason == 'signed_distribution_location_changed'
    mapping.upstream_repository = 'team/image'
    monkeypatch.setattr(revisions, 'active_revision', lambda *a: None)
    assert auth.authorize(db, mapping, DIGEST, NOW).reason == 'active_revision_unavailable'


@pytest.mark.parametrize('change', [None, 'assessment_bytes', 'assessment_hash', 'proposal', 'source_bytes', 'platform', 'reference', 'expired', 'inputs', 'snapshot_inventory', 'chain', 'chain_source_bytes', 'chain_cycle', 'chain_manifest', 'chain_assessment'])
def test_amendment_payload_remains_separate_and_integrity_bound(monkeypatch, change):
    import copy
    from app import proposal_scans
    from app.proposal_assessments import ProposalAssessment
    from app.artifact_catalog import GlobalArtifact
    service = SimpleNamespace(id=1, service_key='test', current_version_id=2)
    execution = SimpleNamespace(id=3, raw_payload={'original': True})
    raw = dict(service={'id': 'test'}, complete=True, fixable_only=True, scan_scope='service',
        scanned_at=NOW.isoformat(), service_overview={'images': [dict(image='registry.example/patched@'+DIGEST,
        digest=DIGEST, platform='linux/amd64', media_type='manifest')]})
    assessment = SimpleNamespace(id=4, proposal_id=5, execution_key='proposal:scan', raw_payload=raw, digest=payload_digest(raw))
    proposal = SimpleNamespace(id=5, service_id=1, base_revision_id=6, intent={'release_revision': {'artifact_ids': [8]}})
    base_snapshot = dict(source_version_id=2, source_payload_digest=payload_digest(execution.raw_payload))
    base_approval = SimpleNamespace(id=7, source_execution_id=3, snapshot=base_snapshot, snapshot_digest=snapshot_digest(base_snapshot))
    base = SimpleNamespace(id=6, service_id=1, approval_id=7)
    artifact = SimpleNamespace(digest=DIGEST, platform='linux/amd64', media_type='manifest')
    snapshot = dict(amendment_proposal_id=5, proposal_assessment_id=4, proposal_assessment_digest=assessment.digest,
        source_payload_digest=assessment.digest, artifacts=[dict(kind='image', reference='registry.example/patched@'+DIGEST,
        digest=DIGEST, platform='linux/amd64', media_type='manifest')])
    approval = SimpleNamespace(id=9, snapshot=snapshot)
    active = SimpleNamespace(approval_id=9, manifest={'base_revision_id': 6, 'artifacts':[dict(digest=DIGEST,platform='linux/amd64',media_type='manifest')]})
    rows = {(ProposalAssessment,4):assessment,(auth.release_revisions.ReleaseAmendmentProposal,5):proposal,
        (auth.release_revisions.ReleaseRevision,6):base,(CyberApproval,7):base_approval,(GlobalArtifact,8):artifact}
    db=SimpleNamespace(get=lambda cls, identity, **kwargs: rows.get((cls,identity)))
    monkeypatch.setattr(proposal_scans,'require_assessment_dispatch',lambda *args: None)
    monkeypatch.setattr(proposal_scans,'latest_dispatch',lambda *args: SimpleNamespace(payload={'evidence_inputs_token':'ok','proposal_inputs_token':'ok'}))
    monkeypatch.setattr(proposal_scans,'evidence_inputs_token',lambda *args: 'bad' if change=='inputs' else 'ok')
    monkeypatch.setattr(proposal_scans,'proposal_inputs_token',lambda *args: 'ok')
    if change=='assessment_bytes': raw['tampered']=True
    if change=='assessment_hash': snapshot['proposal_assessment_digest']='changed'
    if change=='proposal': assessment.proposal_id=99
    if change=='source_bytes': execution.raw_payload={'changed':True}
    if change=='platform': artifact.platform='linux/arm64'
    if change=='reference': snapshot['artifacts'][0]['reference']='registry.example/other@'+DIGEST
    if change=='snapshot_inventory': snapshot['artifacts'][0]['digest']='sha256:'+'b'*64
    if change and change.startswith('chain'):
        # A second amendment retains the first revision and assessment, while
        # the oldest revision still binds the unchanged original scan bytes.
        oldest = SimpleNamespace(id=16, service_id=1, approval_id=17)
        oldest_approval = copy.deepcopy(base_approval)
        oldest_approval.id = 17
        prior_proposal = copy.deepcopy(proposal)
        prior_proposal.id, prior_proposal.base_revision_id = 15, 16
        prior_assessment = copy.deepcopy(assessment)
        prior_assessment.id, prior_assessment.proposal_id = 14, 15
        prior_snapshot = copy.deepcopy(snapshot)
        prior_snapshot.update(amendment_proposal_id=15, proposal_assessment_id=14, source_version_id=2)
        base_approval.snapshot = prior_snapshot
        base_approval.snapshot_digest = snapshot_digest(prior_snapshot)
        base.manifest = dict(base_revision_id=16, artifacts=copy.deepcopy(active.manifest['artifacts']))
        base.manifest_digest = snapshot_digest(base.manifest)
        rows.update({(auth.release_revisions.ReleaseRevision,16):oldest,
            (CyberApproval,17):oldest_approval,
            (auth.release_revisions.ReleaseAmendmentProposal,15):prior_proposal,
            (ProposalAssessment,14):prior_assessment})
        if change=='chain_source_bytes': execution.raw_payload={'changed':True}
        if change=='chain_manifest': base.manifest['tampered']=True
        if change=='chain_assessment': prior_assessment.raw_payload['tampered']=True
        if change=='chain_cycle':
            prior_proposal.base_revision_id=6
            base.manifest['base_revision_id']=6
            base.manifest_digest=snapshot_digest(base.manifest)
    now=NOW+timedelta(days=2) if change=='expired' else NOW
    assert auth._payload_evidence_matches(db,approval,execution,service,active,now) is (change in (None, 'chain'))
