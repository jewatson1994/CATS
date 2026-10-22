from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app import main, proposal_assessments as assessments, release_revisions as revisions
from app.database import Base
from app.models import Service, ServiceVersion, Execution
from app.schemas import ExecutionPayload
from app.artifact_catalog import register_artifact, ArtifactRecommendation


@pytest.fixture
def case():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key='proposal', name='Proposal')
        db.add(service); db.flush()
        version = ServiceVersion(service_id=service.id, version='active')
        db.add(version); db.flush(); service.current_version_id = version.id
        source = Execution(service_id=service.id, service_version_id=version.id,
            execution_key='baseline', scanned_at=datetime.now(timezone.utc), complete=True, raw_payload={})
        db.add(source); db.flush()
        approval = revisions.CyberApproval(service_id=service.id, source_execution_id=source.id,
            variant='current_service', status='approved', snapshot={}, snapshot_digest='test')
        db.add(approval); db.flush()
        revision = revisions.ReleaseRevision(approval_id=approval.id, service_id=service.id,
            manifest={}, manifest_digest='test')
        db.add(revision); db.flush()
        artifact = register_artifact(db, digest='sha256:'+'a'*64,
            media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
        rec = ArtifactRecommendation(service_id=service.id, source_artifact_id=artifact.id, target_artifact_id=artifact.id)
        db.add(rec); db.flush()
        proposal = revisions.ReleaseAmendmentProposal(service_id=service.id, recommendation_id=rec.id,
            base_revision_id=revision.id, intent={'release_revision': {'artifact_ids': [artifact.id]},
                'previous_artifacts': [{'reference': 'registry.example/app@'+artifact.digest, 'digest':artifact.digest, 'platform':artifact.platform, 'media_type':artifact.media_type}]})
        db.add_all([proposal, revisions.ServiceActiveRelease(service_id=service.id, revision_id=revision.id)])
        db.commit()
        payload = dict(execution_id='proposed-scan', scanned_at=datetime.now(timezone.utc).isoformat(),
            complete=True, fixable_only=True, artifact_type='image',
            service=dict(id='proposal', name='Proposal', version='proposed'),
            sbom_components=[{'name':'package','version':'2'}],
            service_overview={'images':[{'image':'registry.example/app@'+artifact.digest,'digest':artifact.digest, 'platform':artifact.platform, 'media_type':artifact.media_type}]})
        yield db, service, proposal, payload
    engine.dispose()


def test_isolated_retention_and_freeze_preserve_active_state(case, tmp_path):
    from app.cyber_approval_evidence import freeze
    db, service, proposal, payload = case
    version = service.current_version_id
    row = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(payload))
    assert assessments.retain(db, proposal.id, ExecutionPayload.model_validate(payload)).id == row.id
    ready = assessments.assess(db, service, proposal.id)
    assert ready['ready'], ready['blockers']
    frozen = freeze(db, service, SimpleNamespace(), ready, tmp_path)
    assert frozen['evidence_scope'] == 'proposed-service-scan'
    assert frozen['version'] == 'proposed'
    assert frozen['proposal_assessment_id'] == row.id
    assert service.current_version_id == version
    assert len(list(db.scalars(select(Execution)))) == 1
    assert db.get(revisions.ServiceActiveRelease, service.id).revision_id == proposal.base_revision_id


@pytest.mark.parametrize('mutation', ['inventory', 'incomplete', 'service', 'skip', 'reference', 'platform', 'future', 'past'])
def test_bad_or_cross_service_scan_rejected(case, mutation):
    db, service, proposal, payload = case
    if mutation == 'inventory': payload['service_overview']['images'][0]['digest'] = 'sha256:'+'b'*64
    if mutation == 'incomplete': payload['complete'] = False
    if mutation == 'service': payload['service']['id'] = 'other'
    if mutation == 'reference': payload['service_overview']['images'][0]['image'] = 'other.example/app@'+'sha256:'+'a'*64
    if mutation == 'platform': payload['service_overview']['images'][0]['platform'] = 'linux/arm64'
    if mutation == 'future': payload['scanned_at'] = '2999-01-01T00:00:00+00:00'
    if mutation == 'past': payload['scanned_at'] = '2000-01-01T00:00:00+00:00'
    if mutation == 'skip': payload['skipped_images'] = ['missing']
    with pytest.raises(ValueError):
        assessments.retain(db, proposal.id, ExecutionPayload.model_validate(payload))
    assert list(db.scalars(select(assessments.ProposalAssessment))) == []


def test_immutable_evidence_and_stale_base(case):
    db, service, proposal, payload = case
    row = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(payload))
    changed = dict(payload, execution_id='different')
    newer = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(changed))
    assert newer.id != row.id
    assert assessments.latest(db, proposal.id).id == newer.id
    with pytest.raises(ValueError, match='different evidence'):
        assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, service_overview={})))
    db.get(revisions.ServiceActiveRelease, service.id).revision_id = None
    db.flush()
    with pytest.raises(ValueError, match='no longer active'):
        assessments.assess(db, service, proposal.id)


def test_duplicate_digest_platform_inventory_rejected(case):
    db, service, proposal, payload = case
    artifact = register_artifact(db, digest='sha256:'+'a'*64,
        media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/arm64')
    # Stand-in persisted malformed inventory, simulating a same-digest multi-platform proposal.
    from unittest.mock import patch
    invalid = SimpleNamespace(id=proposal.id, base_revision_id=proposal.base_revision_id,
        intent=dict(proposal.intent, release_revision={'artifact_ids':
            proposal.intent['release_revision']['artifact_ids'] + [artifact.id]}))
    with patch.object(assessments, 'proposal', return_value=invalid):
        with pytest.raises(ValueError, match='Ambiguous'):
            assessments.retain(db, proposal.id, ExecutionPayload.model_validate(payload))


def test_proposal_scan_inventory_and_isolated_ingest(case, tmp_path):
    import json
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    inputs = proposal_scans.inventory(db, proposal)
    persist_scan(db, service, proposal, dispatch, inputs)
    assert inputs[0]['scan_reference'].endswith('@'+inputs[0]['digest'])
    (tmp_path/'portal-result.json').write_text(json.dumps(payload))
    before = service.current_version_id
    retained = proposal_scans.ingest(db, 'isolated-job', {
        'proposal_context': {'proposal_id': proposal.id, 'dispatch_id': dispatch.id, 'inputs': inputs},
        'ingest_service_id': service.service_key, 'ingest_service_version': 'proposed',
        'returncode':0}, tmp_path)
    assert retained.execution_key == 'proposal:isolated-job'
    assert service.current_version_id == before
    assert len(list(db.scalars(select(Execution)))) == 1


def test_proposal_scan_rejects_missing_platform_evidence(case, tmp_path):
    import json
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    inputs = proposal_scans.inventory(db, proposal)
    persist_scan(db, service, proposal, dispatch, inputs)
    del payload['service_overview']['images'][0]['platform']
    (tmp_path/'portal-result.json').write_text(json.dumps(payload))
    with pytest.raises(ValueError, match='platform'):
        proposal_scans.ingest(db, 'isolated-job', {
            'proposal_context': {'proposal_id':proposal.id,'dispatch_id':dispatch.id,'inputs':inputs},
            'ingest_service_id':service.service_key,'ingest_service_version':'proposed','returncode':0}, tmp_path)
    assert list(db.scalars(select(assessments.ProposalAssessment))) == []


def test_proposal_scan_enqueue_is_transactional_and_deduplicated(case):
    from app import proposal_scans
    db, service, proposal, payload = case
    first = proposal_scans.enqueue(db, proposal, None)
    second = proposal_scans.enqueue(db, proposal, None)
    assert first.id == second.id
    assert first.kind == 'proposal_assessment'
    assert first.payload == {'proposal_id': proposal.id, 'generation': 1,
        'evidence_inputs_token': proposal_scans.evidence_inputs_token(db, service.id),
        'proposal_inputs_token': proposal_scans.proposal_inputs_token(db, proposal)}


def test_legacy_assessment_remains_readable_when_versions_added(case):
    db, service, proposal, payload = case
    raw = ExecutionPayload.model_validate(payload).model_dump(mode='json')
    legacy = assessments.LegacyProposalAssessment(proposal_id=proposal.id,
        execution_key=payload['execution_id'], raw_payload=raw, digest=assessments.payload_digest(raw))
    db.add(legacy); db.flush()
    assert assessments.latest(db, proposal.id) is legacy
    assert assessments.retain(db, proposal.id, ExecutionPayload.model_validate(payload)) is legacy
    fresh = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, execution_id='fresh')))
    assert assessments.latest(db, proposal.id) is fresh
    assert db.get(assessments.LegacyProposalAssessment, legacy.id).raw_payload == raw

@pytest.mark.parametrize('declared_key', ['container_images', 'declared_images'])
def test_proposal_scan_rejects_declared_identity_fallback(case, tmp_path, declared_key):
    import json
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    inputs = proposal_scans.inventory(db, proposal)
    persist_scan(db, service, proposal, dispatch, inputs)
    payload['service_overview'][declared_key] = payload['service_overview'].pop('images')
    (tmp_path / 'portal-result.json').write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        proposal_scans.ingest(db, 'isolated-job', {
            'proposal_context': {'proposal_id': proposal.id, 'dispatch_id': dispatch.id, 'inputs': inputs},
            'ingest_service_id': service.service_key, 'ingest_service_version': 'proposed',
            'returncode': 0}, tmp_path)
    assert assessments.latest(db, proposal.id) is None


def test_new_dispatch_invalidates_older_results(case, tmp_path):
    from app import proposal_scans
    db, service, proposal, payload = case
    first = proposal_scans.enqueue(db, proposal, None)
    second = proposal_scans.enqueue(db, proposal, None, fresh=True)
    assert second.payload['generation'] == 2
    assert proposal_scans.latest_dispatch(db, proposal.id).id == second.id
    assert proposal_scans.enqueue(db, proposal, None).id == second.id
    with pytest.raises(ValueError, match='superseded'):
        proposal_scans.ingest(db, 'old-scan', {
            'proposal_context': {'proposal_id': proposal.id, 'dispatch_id': first.id},
            'ingest_service_id': service.service_key}, tmp_path)
    proposal_scans.require_current_dispatch(db, proposal.id, second.id)
    assert assessments.latest(db, proposal.id) is None


def persist_scan(db, service, proposal, dispatch, inputs, identity='isolated-job'):
    from app.scan_coordination import ScanJob
    row = ScanJob(id=identity, status='complete', available_at=datetime.now(timezone.utc),
        service_key=service.service_key, payload={'proposal_context': {
            'proposal_id': proposal.id, 'dispatch_id': dispatch.id, 'inputs': inputs}})
    db.add(row)
    db.flush()
    return row


def test_new_dispatch_blocks_retained_evidence_and_unbound_execution(case):
    from app import proposal_scans
    db, service, proposal, payload = case
    assessments.retain(db, proposal.id, ExecutionPayload.model_validate(payload))
    dispatch = proposal_scans.enqueue(db, proposal, None)
    with pytest.raises(ValueError, match='latest persisted scan'):
        assessments.assess(db, service, proposal.id)
    with pytest.raises(ValueError, match='latest persisted scan'):
        assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, execution_id='forged')))
    inputs = proposal_scans.inventory(db, proposal)
    persist_scan(db, service, proposal, dispatch, inputs)
    evidence = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, execution_id='proposal:isolated-job')))
    assert assessments.assess(db, service, proposal.id)['ready']
    proposal_scans.enqueue(db, proposal, None, fresh=True)
    with pytest.raises(ValueError, match='latest persisted scan'):
        assessments.assess(db, service, proposal.id, assessment=evidence)


def test_maintenance_refreshes_expired_evidence_once(case, monkeypatch):
    from datetime import timedelta
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    dispatch.status = 'completed'
    persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    evidence = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, execution_id='proposal:isolated-job')))
    monkeypatch.setattr(proposal_scans, 'freshness_deadline', lambda raw: datetime.now(timezone.utc)-timedelta(seconds=1))
    with pytest.raises(ValueError, match='expired'):
        assessments.assess(db, service, proposal.id)
    proposal_scans.maintenance(db)
    newer = proposal_scans.latest_dispatch(db, proposal.id)
    assert newer.id != dispatch.id
    assert newer.payload['generation'] == 2
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == newer.id


def test_changed_evidence_inputs_schedule_reassessment(case, monkeypatch):
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    dispatch.status = 'completed'
    persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, execution_id='proposal:isolated-job')))
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == dispatch.id
    monkeypatch.setattr(proposal_scans, 'evidence_inputs_token', lambda db, service_id: 'changed')
    with pytest.raises(ValueError, match='inputs changed'):
        assessments.assess(db, service, proposal.id)
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id != dispatch.id


@pytest.mark.parametrize('status', ['queued', 'running', 'failed', 'completed'])
def test_changed_inputs_refresh_without_retained_evidence(case, monkeypatch, status):
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    dispatch.status = status
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == dispatch.id
    monkeypatch.setattr(proposal_scans, 'evidence_inputs_token', lambda db, service_id: 'new-policy')
    proposal_scans.maintenance(db)
    newer = proposal_scans.latest_dispatch(db, proposal.id)
    assert newer.id != dispatch.id
    assert newer.payload['generation'] == 2
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == newer.id
    with pytest.raises(ValueError, match='superseded'):
        proposal_scans.require_current_dispatch(db, proposal.id, dispatch.id)
    assert assessments.latest(db, proposal.id) is None


@pytest.mark.parametrize('inherited', [False, True])
def test_effective_risk_policy_invalidates_proposal_once(case, inherited):
    from app import proposal_scans
    from app.models import Group, ServiceGroup
    from app.risk_profiles import create_policy, assign_policy
    db, service, proposal, payload = case
    parent, child, unrelated = Group(name='risk-parent'), Group(name='risk-child'), Group(name='unrelated')
    db.add_all([parent, child, unrelated]); db.flush()
    child.parent_id = parent.id
    db.add(ServiceGroup(service_id=service.id, group_id=child.id)); db.flush()
    owner = parent if inherited else child
    policy = create_policy(db, 'Initial', {}, 'admin', group_id=owner.id)
    assign_policy(db, 'group', owner.id, policy.id, 'admin')
    dispatch = proposal_scans.enqueue(db, proposal, None)
    dispatch.status = 'completed'
    persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, execution_id='proposal:isolated-job')))
    other = create_policy(db, 'Other', {'epss_weight': 25}, 'admin', group_id=unrelated.id)
    assign_policy(db, 'group', unrelated.id, other.id, 'admin')
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == dispatch.id
    replacement = create_policy(db, 'Changed', {'epss_weight': 20}, 'admin', group_id=owner.id)
    assign_policy(db, 'group', owner.id, replacement.id, 'admin')
    with pytest.raises(ValueError, match='inputs changed'):
        assessments.assess(db, service, proposal.id)
    proposal_scans.maintenance(db)
    newer = proposal_scans.latest_dispatch(db, proposal.id)
    assert newer.id != dispatch.id
    assert newer.payload['generation'] == 2
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == newer.id


def test_maintenance_skips_concurrently_superseded_base(case, monkeypatch):
    from app import proposal_scans
    db, service, row, payload = case
    dispatch = proposal_scans.enqueue(db, row, None)
    db.commit()
    def superseded(*args):
        raise assessments.InactiveProposalBase('Amendment base is no longer active')
    monkeypatch.setattr(assessments, 'proposal', superseded)
    monkeypatch.setattr(proposal_scans, 'evidence_inputs_token', lambda *args: 'changed')
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, row.id).id == dispatch.id


def test_proposal_refreshes_cached_active_pointer(case):
    from sqlalchemy import update
    db, service, row, payload = case
    pointer = db.scalar(select(revisions.ServiceActiveRelease).where(
        revisions.ServiceActiveRelease.service_id == service.id))
    original = db.get(revisions.ReleaseRevision, row.base_revision_id)
    previous = db.get(revisions.CyberApproval, original.approval_id)
    approval = revisions.CyberApproval(service_id=service.id,
        source_execution_id=previous.source_execution_id, variant='current_service',
        status='approved', snapshot={}, snapshot_digest='other')
    db.add(approval); db.flush()
    other = revisions.ReleaseRevision(service_id=service.id,
        approval_id=approval.id, manifest={}, manifest_digest='other')
    db.add(other)
    db.flush()
    db.execute(update(revisions.ServiceActiveRelease).where(
        revisions.ServiceActiveRelease.service_id == service.id).values(
        revision_id=other.id).execution_options(synchronize_session=False))
    assert pointer.revision_id == row.base_revision_id
    with pytest.raises(assessments.InactiveProposalBase):
        assessments.proposal(db, row.id, service.id)


@pytest.mark.parametrize('error', [ValueError('invalid date'), KeyError('scanned_at'), TypeError('invalid date type')])
def test_maintenance_recovers_unusable_freshness_once(case, monkeypatch, error):
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    dispatch.status = 'completed'
    persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    evidence = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(
        dict(payload, execution_id='proposal:isolated-job')))
    def invalid_freshness(raw):
        raise error
    monkeypatch.setattr(proposal_scans, 'freshness_deadline', invalid_freshness)
    proposal_scans.maintenance(db)
    newer = proposal_scans.latest_dispatch(db, proposal.id)
    assert newer.id != dispatch.id
    assert newer.payload['generation'] == 2
    # Dispatcher completion is not scanner completion. Historical evidence
    # must not cause an endless sequence of replacement scan requests.
    newer.status = 'completed'
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == newer.id
    assert assessments.latest(db, proposal.id).id == evidence.id

@pytest.mark.parametrize('relevant', [False, True])
def test_validation_changes_refresh_only_affected_proposal(case, relevant):
    from app import proposal_scans
    from app.models import DeploymentValidationRun
    db, service, proposal, payload = case
    reference = proposal.intent['previous_artifacts'][0]['reference']
    run = DeploymentValidationRun(run_key='validation-token-test', service_id=service.id,
        artifact_reference=reference if relevant else 'registry.example/unrelated@sha256:' + 'b'*64,
        status='VERIFIED', phase='COMPLETED')
    db.add(run); db.flush()
    dispatch = proposal_scans.enqueue(db, proposal, None)
    dispatch.status = 'completed'
    persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    assessments.retain(db, proposal.id, ExecutionPayload.model_validate(dict(payload, execution_id='proposal:isolated-job')))
    run.status = 'FAILED'
    db.flush()
    if relevant:
        with pytest.raises(ValueError, match='inputs changed'):
            assessments.assess(db, service, proposal.id)
    proposal_scans.maintenance(db)
    newer = proposal_scans.latest_dispatch(db, proposal.id)
    if relevant:
        assert newer.id != dispatch.id
        assert newer.payload['generation'] == 2
        with pytest.raises(ValueError, match='superseded'):
            proposal_scans.require_current_dispatch(db, proposal.id, dispatch.id)
    else:
        assert newer.id == dispatch.id
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == newer.id


@pytest.mark.parametrize('pending', [False, True])
def test_cancelled_dispatch_rejects_evidence_and_does_not_refresh(case, monkeypatch, pending):
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    dispatch.status = 'completed'
    persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    retained = assessments.retain(db, proposal.id, ExecutionPayload.model_validate(
        dict(payload, execution_id='proposal:isolated-job')))
    dispatch.cancel_requested = pending
    if not pending:
        dispatch.status = 'cancelled'
    db.flush()
    with pytest.raises(ValueError, match='cancelled'):
        proposal_scans.require_current_dispatch(db, proposal.id, dispatch.id)
    with pytest.raises(ValueError, match='cancelled'):
        assessments.assess(db, service, proposal.id)
    monkeypatch.setattr(proposal_scans, 'evidence_inputs_token', lambda *args: 'changed')
    proposal_scans.maintenance(db)
    assert proposal_scans.latest_dispatch(db, proposal.id).id == dispatch.id
    assert assessments.latest(db, proposal.id).id == retained.id
    replacement = proposal_scans.enqueue(db, proposal, None, fresh=True)
    assert replacement.payload['generation'] == 2
    proposal_scans.require_current_dispatch(db, proposal.id, replacement.id)


@pytest.mark.parametrize('status', ['cancelled', 'error', 'incomplete'])
def test_unsuccessful_bound_scan_cannot_supply_review_evidence(case, status):
    from app import proposal_scans
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    scan = persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    scan.status = status
    db.flush()
    with pytest.raises(ValueError, match='latest persisted scan'):
        assessments.retain(db, proposal.id, ExecutionPayload.model_validate(
            dict(payload, execution_id='proposal:isolated-job')))
    assert assessments.latest(db, proposal.id) is None


@pytest.mark.parametrize('target', ['dispatch', 'scan'])
def test_cached_scan_state_cannot_bypass_concurrent_cancellation(case, target):
    from sqlalchemy import update
    from app import proposal_scans
    from app.durable_jobs import DurableJob
    from app.scan_coordination import ScanJob
    db, service, proposal, payload = case
    dispatch = proposal_scans.enqueue(db, proposal, None)
    scan = persist_scan(db, service, proposal, dispatch, proposal_scans.inventory(db, proposal))
    assessments.retain(db, proposal.id, ExecutionPayload.model_validate(
        dict(payload, execution_id='proposal:isolated-job')))
    # Simulate a concurrent persisted change while this session still holds
    # the formerly acceptable dispatch and scanner objects.
    if target == 'dispatch':
        db.execute(update(DurableJob).where(DurableJob.id == dispatch.id)
            .values(cancel_requested=True).execution_options(synchronize_session=False))
        assert not dispatch.cancel_requested
        message = 'cancelled'
    else:
        db.execute(update(ScanJob).where(ScanJob.id == scan.id)
            .values(status='cancelled').execution_options(synchronize_session=False))
        assert scan.status == 'complete'
        message = 'latest persisted scan'
    with pytest.raises(ValueError, match=message):
        assessments.assess(db, service, proposal.id)
