"""Real split PostgreSQL proposal contracts; scanner payloads are synthetic.

Uses the opt-in, isolated two-database fixture from the split runtime suite.
No scanner process is launched by these persistence/approval checks.
"""
from datetime import datetime, timezone
import pytest
from app import release_revisions as revisions
from app.models import Service, ServiceVersion, Execution
from app.artifact_catalog import register_artifact, ArtifactRecommendation
from test_split_intelligence_postgres import splitdb
import test_proposal_assessments as cases


@pytest.fixture
def case(splitdb):
    db = splitdb
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
    return db, service, proposal, payload


@pytest.mark.parametrize('scenario', [
    cases.test_immutable_evidence_and_stale_base,
    cases.test_proposal_scan_enqueue_is_transactional_and_deduplicated,
    cases.test_legacy_assessment_remains_readable_when_versions_added,
    cases.test_new_dispatch_blocks_retained_evidence_and_unbound_execution,
    cases.test_proposal_refreshes_cached_active_pointer,
])
def test_split_proposal_contracts(case, scenario):
    scenario(case)


@pytest.mark.parametrize('scenario', [
    cases.test_isolated_retention_and_freeze_preserve_active_state,
    cases.test_proposal_scan_inventory_and_isolated_ingest,
    cases.test_proposal_scan_rejects_missing_platform_evidence,
    cases.test_new_dispatch_invalidates_older_results,
])
def test_split_proposal_evidence(case, tmp_path, scenario):
    scenario(case, tmp_path)


@pytest.mark.parametrize('inherited', [False, True])
def test_split_real_policy_change_reassesses_once(case, inherited):
    cases.test_effective_risk_policy_invalidates_proposal_once(case, inherited)


@pytest.mark.parametrize('relevant', [False, True])
def test_split_real_validation_change_reassesses(case, relevant):
    cases.test_validation_changes_refresh_only_affected_proposal(case, relevant)


@pytest.mark.parametrize('mutation', ['inventory', 'incomplete', 'service', 'skip', 'reference', 'platform', 'future', 'past'])
def test_split_invalid_scan_rejected(case, mutation):
    cases.test_bad_or_cross_service_scan_rejected(case, mutation)


@pytest.mark.parametrize('target', ['scan', 'dispatch'])
def test_split_cached_cancellation(case, target):
    cases.test_cached_scan_state_cannot_bypass_concurrent_cancellation(case, target)
