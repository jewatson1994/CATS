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
    with pytest.raises(ValueError, match='different evidence'):
        assessments.retain(db, proposal.id, ExecutionPayload.model_validate(changed))
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
