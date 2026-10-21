"""Isolated scanner evidence for immutable release amendment inventory."""
from types import SimpleNamespace
from datetime import datetime, timezone
import json
from sqlalchemy import ForeignKey, JSON, String, select, event
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import Service, Execution
from .execution_summaries import payload_digest
from .release_revisions import ReleaseAmendmentProposal, ServiceActiveRelease, ReleaseRevision, CyberApproval, _immutable


class ProposalAssessment(Base):
    __tablename__ = 'proposal_assessments'
    id: Mapped[int] = mapped_column(primary_key=True)
    proposal_id: Mapped[int] = mapped_column(ForeignKey('release_amendment_proposals.id'), unique=True)
    execution_key: Mapped[str] = mapped_column(String(240), unique=True)
    raw_payload: Mapped[dict] = mapped_column(JSON)
    digest: Mapped[str] = mapped_column(String(64))


event.listen(ProposalAssessment, 'before_update', _immutable)
event.listen(ProposalAssessment, 'before_delete', _immutable)


def proposal(db, identity, service_id):
    row = db.get(ReleaseAmendmentProposal, identity)
    pointer = db.scalar(select(ServiceActiveRelease).where(
        ServiceActiveRelease.service_id == service_id).with_for_update())
    if row is None or row.service_id != service_id:
        raise ValueError('Amendment proposal unavailable')
    if pointer is None or pointer.revision_id != row.base_revision_id:
        raise ValueError('Amendment base is no longer active')
    return row


def retain(db, identity, payload):
    """Only called behind the existing authenticated pipeline boundary."""
    service = db.scalar(select(Service).where(Service.service_key == payload.service.id))
    if service is None or service.lifecycle_status != 'active':
        raise ValueError('An active existing service is required')
    row = proposal(db, identity, service.id)
    if not payload.fixable_only or not payload.complete or payload.scan_scope != 'service' or payload.skipped_images or payload.skipped_charts:
        raise ValueError('A complete whole-service fixable assessment without skipped inputs is required')
    raw = payload.model_dump(mode='json')
    existing = db.scalar(select(ProposalAssessment).where(ProposalAssessment.proposal_id == row.id))
    if existing:
        if existing.raw_payload != raw:
            raise ValueError('Proposal assessment already retained with different evidence')
        return existing
    assessment = ProposalAssessment(proposal_id=row.id, execution_key=payload.execution_id,
        raw_payload=raw, digest=payload_digest(raw))
    # Validate all existing publication evidence checks before retaining the result.
    result = assess(db, service, row.id, assessment=assessment)
    if not result['ready']:
        raise ValueError('; '.join(result['blockers']))
    db.add(assessment)
    db.flush()
    return assessment


def assess(db, service, identity, *, assessment=None):
    from .schemas import ExecutionPayload
    from .cyber_approval_evidence import readiness
    from .artifact_catalog import GlobalArtifact
    row = proposal(db, identity, service.id)
    assessment = assessment or db.scalar(select(ProposalAssessment).where(ProposalAssessment.proposal_id == identity))
    if assessment is None or assessment.digest != payload_digest(assessment.raw_payload):
        raise ValueError('Retained proposal assessment is missing or corrupt')
    payload = ExecutionPayload.model_validate(assessment.raw_payload)
    base = db.get(ReleaseRevision, row.base_revision_id)
    approval = db.get(CyberApproval, base.approval_id)
    source = db.get(Execution, approval.source_execution_id)
    if source is None:
        raise ValueError('Base approval source evidence is unavailable')
    from .release_validity import utc
    if payload.service.id != service.service_key or utc(payload.scanned_at) <= utc(approval.decided_at or source.scanned_at):
        raise ValueError('Proposal assessment must follow its base approval and match its service')
    if utc(payload.scanned_at) > datetime.now(timezone.utc):
        raise ValueError('Future-dated proposal evidence is not accepted')
    execution = SimpleNamespace(id=source.id, service_version_id=source.service_version_id,
        scanned_at=payload.scanned_at, complete=payload.complete, scan_scope='service',
        raw_payload=json.loads(json.dumps(assessment.raw_payload)), payload_digest=assessment.digest)
    result = readiness(db, service, _proposal_execution=execution)
    artifacts = [db.get(GlobalArtifact, i) for i in row.intent['release_revision']['artifact_ids']]
    if any(a is None for a in artifacts) or len({a.digest for a in artifacts}) != len(artifacts):
        raise ValueError('Ambiguous proposed digest/platform inventory is unsupported')
    expected = {a.digest for a in artifacts}
    actual = {a.get('digest') for a in result['artifacts']}
    if expected != actual or any(a.get('resolve_at_publication') for a in result['artifacts']):
        result['blockers'].append('Assessment inventory must exactly match every immutable proposed artifact digest')
    # Preserve each requested reference, not merely the set of resulting digests.
    previous = row.intent.get('previous_artifacts') or approval.snapshot.get('artifacts') or []
    source_id = row.intent.get('source_artifact_id')
    source_artifact = db.get(GlobalArtifact, source_id) if source_id else None
    target_id = row.intent.get('target_artifact_id')
    target_artifact = db.get(GlobalArtifact, target_id) if target_id else None
    expected_refs = {}
    for item in previous:
        digest = item.get('digest')
        if source_artifact and target_artifact and digest == source_artifact.digest:
            digest = target_artifact.digest
        for reference in item.get('source_references') or [item.get('reference')]:
            if not reference or reference in expected_refs and expected_refs[reference] != digest:
                raise ValueError('Ambiguous original requested reference mapping')
            expected_refs[reference] = digest
    images = payload.service_overview.get('images') or payload.service_overview.get('container_images') or []
    actual_refs = {}
    by_digest = {a.digest: a for a in artifacts}
    for item in images:
        if not isinstance(item, dict):
            raise ValueError('Explicit image identity and platform evidence is required')
        reference = item.get('image') or item.get('reference')
        digest = item.get('digest') or item.get('image_digest')
        artifact = by_digest.get(digest)
        if (not reference or artifact is None or item.get('platform') != artifact.platform
                or item.get('media_type') != artifact.media_type
                or reference in actual_refs):
            raise ValueError('Proposed image reference, platform or media type does not match its inventory')
        actual_refs[reference] = digest
    if not expected_refs or actual_refs != expected_refs:
        result['blockers'].append('Assessment must preserve every original requested reference with its proposed digest')
    result.update(ready=not result['blockers'], proposal_id=identity,
        proposal_assessment_id=assessment.id, proposal_assessment_digest=assessment.digest,
        version=payload.service.version)
    return result
