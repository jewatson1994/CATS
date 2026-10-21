"""Immutable release revisions over existing CyberApproval decisions.

All functions participate in the caller's transaction. No function commits.
The existing approval snapshot must contain ``release_revision`` with
``artifact_ids`` and ``base_revision_id`` before that snapshot is approved.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from sqlalchemy import ForeignKey, JSON, String, Text, event, select, update
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .cyber_approvals import CyberApproval, digest, root
from . import release_signing, release_validity

PURPOSE = 'cats.approved-release-revision.v1'


class ReleaseRevision(Base):
    __tablename__ = 'release_revisions'
    id: Mapped[int] = mapped_column(primary_key=True)
    approval_id: Mapped[int] = mapped_column(ForeignKey('cyber_approvals.id'), unique=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    base_revision_id: Mapped[int | None] = mapped_column(ForeignKey('release_revisions.id'))
    manifest: Mapped[dict] = mapped_column(JSON)
    manifest_digest: Mapped[str] = mapped_column(String(80))


class ReleaseRevisionState(Base):
    __tablename__ = 'release_revision_states'
    revision_id: Mapped[int] = mapped_column(ForeignKey('release_revisions.id'), primary_key=True)
    decision: Mapped[str] = mapped_column(String(24), default='proposed')
    suspended: Mapped[bool] = mapped_column(default=False)
    revoked: Mapped[bool] = mapped_column(default=False)
    reason: Mapped[str] = mapped_column(Text, default='')
    version: Mapped[int] = mapped_column(default=0)


class ServiceActiveRelease(Base):
    __tablename__ = 'service_active_releases'
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), primary_key=True)
    revision_id: Mapped[int | None] = mapped_column(ForeignKey('release_revisions.id'))
    version: Mapped[int] = mapped_column(default=0)


@event.listens_for(ReleaseRevision, 'before_update')
@event.listens_for(ReleaseRevision, 'before_delete')
def _immutable(*args):
    raise ValueError('Release revisions are immutable')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def _permission(auth, service_id, action):
    if not auth.has('service.view', service_id) or not auth.has(action, service_id):
        raise PermissionError('Release permission denied')


def _approval(db, identity):
    row = db.scalar(select(CyberApproval).where(CyberApproval.id == identity)
                    .with_for_update().execution_options(populate_existing=True))
    if row is None or digest(row.snapshot) != row.snapshot_digest:
        raise ValueError('Approval evidence unavailable or changed')
    return row


def _manifest(db, approval):
    from .artifact_catalog import GlobalArtifact, ServiceArtifactAssignment
    specification = approval.snapshot.get('release_revision')
    if (not isinstance(specification, dict) or not {'artifact_ids', 'base_revision_id'} <= set(specification)
            or set(specification) - {'artifact_ids', 'base_revision_id', 'distribution_bindings'}):
        raise ValueError('Revision specification must be retained in the approval snapshot')
    ids = specification['artifact_ids']
    if (not isinstance(ids, list) or not ids or any(type(i) is not int or i < 1 for i in ids)
            or len(ids) != len(set(ids))):
        raise ValueError('Revision requires unique artifact identities')
    base_id = specification['base_revision_id']
    if base_id is not None:
        if type(base_id) is not int:
            raise ValueError('Invalid base revision')
        base = db.get(ReleaseRevision, base_id)
        if base is None or base.service_id != approval.service_id:
            raise ValueError('Base revision belongs to another service')
    artifacts = []
    for identity in sorted(ids):
        artifact = db.get(GlobalArtifact, identity)
        if artifact is None or db.scalar(select(ServiceArtifactAssignment).where(
                ServiceArtifactAssignment.service_id == approval.service_id,
                ServiceArtifactAssignment.artifact_id == identity)) is None:
            raise ValueError('Artifact unavailable in this service')
        artifacts.append(dict(id=artifact.id, digest=artifact.digest,
                              media_type=artifact.media_type, platform=artifact.platform))
    if {a['digest'] for a in artifacts} != {a.get('digest') for a in approval.snapshot.get('artifacts', [])}:
        raise ValueError('Revision inventory differs from retained approval evidence')
    return dict(purpose=PURPOSE, schema_version=1, approval_id=approval.id,
                release_key=approval.release_key, service_id=approval.service_id,
                snapshot_digest=approval.snapshot_digest, base_revision_id=base_id,
                approval_validity=approval.snapshot.get('approval_validity'),
                signing_fingerprint=approval.snapshot.get('signing_fingerprint'),
                artifacts=artifacts,
                distribution_bindings=_distribution_bindings(db, approval, artifacts, specification.get('distribution_bindings', [])))


def propose(db, auth, approval_id, *, decision_context=False):
    approval = _approval(db, approval_id)
    _permission(auth, approval.service_id, 'approval.decide' if decision_context else 'approval.request')
    if approval.status not in {'approved', 'denied'} or approval.revoked_at:
        raise ValueError('Approval cannot support a proposal')
    manifest = _manifest(db, approval)
    row = ReleaseRevision(approval_id=approval.id, service_id=approval.service_id,
                          base_revision_id=manifest['base_revision_id'], manifest=manifest,
                          manifest_digest=digest(manifest))
    db.add(row)
    db.flush()
    db.add(ReleaseRevisionState(revision_id=row.id))
    # A unique service primary key also serializes first-pointer creation.
    if db.get(ServiceActiveRelease, approval.service_id) is None:
        db.add(ServiceActiveRelease(service_id=approval.service_id))
    db.flush()
    return row


def _rows(db, auth, revision_id):
    revision = db.get(ReleaseRevision, revision_id, populate_existing=True)
    if revision is None:
        raise ValueError('Revision unavailable')
    _permission(auth, revision.service_id, 'approval.decide')
    state = db.scalar(select(ReleaseRevisionState).where(
        ReleaseRevisionState.revision_id == revision_id).with_for_update()
        .execution_options(populate_existing=True))
    if state is None:
        raise ValueError('Revision state unavailable')
    return revision, state


def _change_state(db, state, expected_version, **values):
    result = db.execute(update(ReleaseRevisionState).where(
        ReleaseRevisionState.revision_id == state.revision_id,
        ReleaseRevisionState.version == expected_version).values(
            **values, version=expected_version + 1))
    if result.rowcount != 1:
        raise ValueError('Revision changed; reload before retrying')


def decide(db, auth, revision_id, expected_version):
    """Reflect an existing Cyber decision; never create a second approval decision."""
    revision, state = _rows(db, auth, revision_id)
    if state.decision != 'proposed':
        raise ValueError('Proposal has already been decided')
    approval = _approval(db, revision.approval_id)
    if approval.status not in {'approved', 'denied'} or approval.revoked_at:
        raise ValueError('Complete the existing Cyber approval decision first')
    if _manifest(db, approval) != revision.manifest:
        raise ValueError('Revision evidence changed')
    _change_state(db, state, expected_version, decision=approval.status)


def manifest_directory(revision):
    """Server-owned publication destination; never accept a request-supplied path."""
    return root() / 'revisions' / str(revision.id)


def validate_activation(db, revision, now=None):
    from .artifact_catalog import artifact_eligibility
    approval = _approval(db, revision.approval_id)
    if approval.status != 'approved' or approval.revoked_at or not approval.decided_by_id:
        raise ValueError('Cyber approval is not current')
    release_validity.require_current(approval, now)
    if digest(revision.manifest) != revision.manifest_digest or _manifest(db, approval) != revision.manifest:
        raise ValueError('Revision evidence changed')
    for artifact in revision.manifest['artifacts']:
        if artifact_eligibility(db, artifact['id'], service_id=revision.service_id).get('eligible') is not True:
            raise ValueError('Artifact lacks trusted release eligibility evidence')
    fingerprint = approval.snapshot.get('signing_fingerprint')
    if not isinstance(fingerprint, str) or not fingerprint.startswith('sha256:'):
        raise ValueError('Trusted signing fingerprint missing')
    folder = manifest_directory(revision)
    paths = [folder / name for name in ('release-manifest.json', 'release-manifest.sig', 'release-public-key.pem')]
    if any(p.is_symlink() for path in paths for p in (path, *path.parents)):
        raise ValueError('Unsafe release signature path')
    expected = canonical(revision.manifest)
    try:
        if paths[0].read_bytes() != expected:
            raise ValueError('Manifest bytes differ')
        verification = release_signing.verify_release_manifest(*paths, expected_fingerprint=fingerprint)
        if (verification.get('status') != 'verified' or verification.get('manifest_sha256') != hashlib.sha256(expected).hexdigest()):
            raise ValueError('Manifest signature not verified')
    except OSError as exc:
        raise ValueError('Signed revision manifest unavailable') from exc


def activate(db, auth, revision_id, expected_pointer_version, now=None):
    revision, state = _rows(db, auth, revision_id)
    if state.decision != 'approved' or state.suspended or state.revoked:
        raise ValueError('Revision is not active-eligible')
    pointer = db.scalar(select(ServiceActiveRelease).where(
        ServiceActiveRelease.service_id == revision.service_id).with_for_update()
        .execution_options(populate_existing=True))
    if pointer is None or pointer.revision_id != revision.base_revision_id:
        raise ValueError('Active release changed; propose a new amendment')
    validate_activation(db, revision, now)
    result = db.execute(update(ServiceActiveRelease).where(
        ServiceActiveRelease.service_id == revision.service_id,
        ServiceActiveRelease.version == expected_pointer_version).values(
            revision_id=revision.id, version=expected_pointer_version + 1))
    if result.rowcount != 1:
        raise ValueError('Active release changed; reload before retrying')


def restrict(db, auth, revision_id, expected_version, action, reason):
    """Suspension/revocation remain separate from immutable decision and expiry."""
    revision, state = _rows(db, auth, revision_id)
    if action not in {'suspend', 'revoke'} or not str(reason).strip():
        raise ValueError('Restriction and reason required')
    _change_state(db, state, expected_version,
                  **{'suspended' if action == 'suspend' else 'revoked': True}, reason=str(reason))


def publish_manifest(db, approval, signing_material):
    """Sign the frozen revision with the existing publication worker's key."""
    revision = db.scalar(select(ReleaseRevision).where(ReleaseRevision.approval_id == approval.id))
    if revision is None:
        raise ValueError('Approved revision is unavailable')
    if _manifest(db, approval) != revision.manifest or digest(revision.manifest) != revision.manifest_digest:
        raise ValueError('Revision evidence changed')
    folder = manifest_directory(revision)
    if any(p.is_symlink() for p in (folder, *folder.parents)):
        raise ValueError('Unsafe revision publication destination')
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'release-manifest.json'
    content = canonical(revision.manifest)
    if path.is_symlink():
        raise ValueError('Unsafe revision manifest')
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError('Retained revision manifest differs')
    else:
        with path.open('xb') as stream:
            stream.write(content)
    result = release_signing.sign_release_manifest(path, folder, signing_material)
    if result.get('signature_status') != 'verified':
        raise ValueError('Revision signature verification failed')
    return result


def active_revision(db, service_id, now=None):
    """Resolve live authority; a retained pointer alone never grants distribution."""
    pointer = db.get(ServiceActiveRelease, service_id, populate_existing=True)
    if pointer is None or pointer.revision_id is None:
        return None
    revision = db.get(ReleaseRevision, pointer.revision_id, populate_existing=True)
    state = db.get(ReleaseRevisionState, pointer.revision_id, populate_existing=True)
    if (revision is None or revision.service_id != service_id or state is None
            or state.decision != 'approved' or state.suspended or state.revoked):
        return None
    try:
        validate_activation(db, revision, now)
    except (ValueError, OSError, TypeError, KeyError):
        return None
    return revision



def _distribution_bindings(db, approval, artifacts, requested):
    """Resolve location from scoped registry configuration and retained scan identity."""
    from .oci_models import OCIRepository
    from .cyber_approval_evidence import _identity, _repository_identity
    if not isinstance(requested, list) or len(requested) > 512:
        raise ValueError('Invalid distribution bindings')
    inventory = {item['id']: item for item in artifacts}
    result, seen = [], set()
    for item in requested:
        if (not isinstance(item, dict) or set(item) != {'repository_id', 'tag', 'artifact_id'}
                or type(item['repository_id']) is not int or type(item['artifact_id']) is not int
                or not isinstance(item['tag'], str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', item['tag'])):
            raise ValueError('Binding requires repository, tag and artifact identity')
        if re.fullmatch(r'sha256-[0-9a-f]{64}\.sig', item['tag']):
            raise ValueError('Signature tags are reserved')
        mapping = db.get(OCIRepository, item['repository_id'], populate_existing=True)
        artifact = inventory.get(item['artifact_id'])
        if (mapping is None or mapping.service_id != approval.service_id or artifact is None
                or not mapping.enabled or mapping.suspended or not mapping.upstream.enabled):
            raise ValueError('Binding repository or artifact unavailable in this service')
        repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + mapping.upstream_repository
        matched = False
        for retained in approval.snapshot.get('artifacts', []):
            try:
                reference, retained_digest = _identity(retained.get('reference'), retained.get('digest'))
                if (retained_digest == artifact['digest'] and not retained.get('resolve_at_publication')
                        and not retained.get('path') and _repository_identity(reference) == _repository_identity(repository)):
                    matched = True
            except (ValueError, TypeError):
                continue
        if not matched:
            raise ValueError('Distribution location is not bound to retained artifact evidence')
        key = (mapping.public_repository, item['tag'])
        if key in seen:
            raise ValueError('Duplicate distribution tag binding')
        seen.add(key)
        result.append(dict(repository_id=mapping.id, public_repository=mapping.public_repository,
            tag=item['tag'], artifact_id=artifact['id'], digest=artifact['digest'],
            upstream_id=mapping.upstream_id, endpoint=mapping.upstream.endpoint,
            upstream_repository=mapping.upstream_repository))
    return sorted(result, key=lambda value: (value['public_repository'], value['tag']))


def resolve_distribution_tag(db, mapping, tag, now=None):
    """Return a signed pin for managed tags; legacy mappings retain upstream resolution."""
    managed = (db.get(ServiceActiveRelease, mapping.service_id, populate_existing=True) is not None
        or db.scalar(select(ReleaseRevision.id).where(ReleaseRevision.service_id == mapping.service_id).limit(1)) is not None)
    if not managed:
        return None
    revision = active_revision(db, mapping.service_id, now)
    if revision is None:
        raise ValueError('Active release revision is unavailable')
    for binding in revision.manifest.get('distribution_bindings', []):
        if binding.get('public_repository') != mapping.public_repository or binding.get('tag') != tag:
            continue
        expected = dict(repository_id=mapping.id, upstream_id=mapping.upstream_id,
            endpoint=mapping.upstream.endpoint, upstream_repository=mapping.upstream_repository)
        if (not mapping.enabled or mapping.suspended or not mapping.upstream.enabled
                or any(binding.get(key) != value for key, value in expected.items())
                or not any(a['id'] == binding.get('artifact_id') and a['digest'] == binding.get('digest')
                           for a in revision.manifest['artifacts'])):
            raise ValueError('Signed distribution location changed')
        return dict(binding, revision_id=revision.id)
    raise ValueError('Tag is not bound in the active release revision')


class ReleaseAmendmentProposal(Base):
    """Selection intent only; evidence and approval are supplied by the existing workflow."""
    __tablename__ = 'release_amendment_proposals'
    id: Mapped[int] = mapped_column(primary_key=True)
    recommendation_id: Mapped[int] = mapped_column(ForeignKey('artifact_recommendations.id'), unique=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    base_revision_id: Mapped[int] = mapped_column(ForeignKey('release_revisions.id'))
    intent: Mapped[dict] = mapped_column(JSON)


event.listen(ReleaseAmendmentProposal, 'before_update', _immutable)
event.listen(ReleaseAmendmentProposal, 'before_delete', _immutable)


def propose_recommendation(db, auth, recommendation):
    _permission(auth, recommendation.service_id, 'approval.request')
    existing = db.scalar(select(ReleaseAmendmentProposal).where(
        ReleaseAmendmentProposal.recommendation_id == recommendation.id))
    if existing:
        return existing
    pointer = db.scalar(select(ServiceActiveRelease).where(
        ServiceActiveRelease.service_id == recommendation.service_id).with_for_update())
    if pointer is None:
        return None  # Services without revisions retain proposed selection behavior.
    if pointer.revision_id is None:
        raise ValueError('An active release revision is required for an amendment')
    base = active_revision(db, recommendation.service_id)
    if base is None or base.id != pointer.revision_id:
        raise ValueError('Active release is unavailable')
    ids = [item['id'] for item in base.manifest['artifacts']]
    if recommendation.source_artifact_id not in ids or recommendation.target_artifact_id in ids:
        raise ValueError('Recommendation does not replace an artifact in the active inventory')
    from .artifact_catalog import GlobalArtifact
    target = db.get(GlobalArtifact, recommendation.target_artifact_id)
    # A recommendation is retained server-side selection intent. Receiving-service
    # assignment and validation may follow proposal; activation still requires both.
    if target is None:
        raise ValueError('Recommended artifact is unavailable')
    approval = _approval(db, base.approval_id)
    bindings = [dict(repository_id=item['repository_id'], tag=item['tag'],
        artifact_id=recommendation.target_artifact_id if item['artifact_id'] == recommendation.source_artifact_id else item['artifact_id'])
        for item in base.manifest.get('distribution_bindings', [])]
    intent = dict(release_revision=dict(base_revision_id=base.id,
        artifact_ids=[recommendation.target_artifact_id if identity == recommendation.source_artifact_id else identity for identity in ids],
        distribution_bindings=bindings),
        previous_artifacts=approval.snapshot.get('artifacts', []),
        source_artifact_id=recommendation.source_artifact_id,
        target_artifact_id=target.id, target_digest=target.digest,
        posture_status='requires_fresh_service_assessment',
        assessment_readiness=dict(status='blocked', code='proposed_assessment_required',
            message='A separate assessment of the proposed inventory is required before Cyber review.',
            next_action='Submit a complete proposed inventory scan to the authenticated amendment-assessments pipeline endpoint.',
            automatic_assessment_available=False))
    row = ReleaseAmendmentProposal(recommendation_id=recommendation.id,
        service_id=recommendation.service_id, base_revision_id=base.id,
        intent=json.loads(canonical(intent)))
    db.add(row)
    db.flush()
    return row


def amendment_specification(db, auth, identity, service_id):
    _permission(auth, service_id, 'approval.request')
    row = db.get(ReleaseAmendmentProposal, identity)
    pointer = db.scalar(select(ServiceActiveRelease).where(
        ServiceActiveRelease.service_id == service_id).with_for_update())
    if row is None or row.service_id != service_id:
        raise ValueError('Amendment proposal unavailable')
    if pointer is None or pointer.revision_id != row.base_revision_id:
        raise ValueError('Active release changed; propose a new amendment')
    return json.loads(canonical(row.intent['release_revision']))


def amendment_readiness(db, auth, identity, service_id):
    """Live diagnostics only: never infer proposed posture from source scan counters."""
    specification = amendment_specification(db, auth, identity, service_id)
    from .artifact_catalog import artifact_eligibility, ServiceArtifactAssignment
    artifacts = []
    for artifact_id in specification['artifact_ids']:
        assignment = db.scalar(select(ServiceArtifactAssignment).where(
            ServiceArtifactAssignment.service_id == service_id,
            ServiceArtifactAssignment.artifact_id == artifact_id))
        evidence = artifact_eligibility(db, artifact_id, service_id=service_id)
        artifacts.append(dict(artifact_id=artifact_id, assigned=assignment is not None,
            eligible=bool(evidence.get('eligible')) and assignment is not None,
            reasons=list(evidence.get('reasons', [])) + ([] if assignment else ['service_assignment_missing'])))
    from .proposal_assessments import assess
    from .models import Service
    assessment = None
    assessment_blockers = []
    try:
        assessment = assess(db, db.get(Service, service_id), identity)
        assessment_blockers = assessment['blockers']
    except ValueError as exc:
        assessment_blockers = [str(exc)]
    return dict(proposal_id=identity, ready_for_cyber_review=bool(assessment and assessment['ready']),
        automatic_assessment_available=False, active_release_changed=False,
        blockers=[dict(code='proposed_assessment_required', message=message,
            next_action='Submit the complete exact proposed inventory scan through the authenticated amendment-assessments pipeline endpoint.') for message in assessment_blockers],
        assessment_id=assessment.get('proposal_assessment_id') if assessment else None,
        artifacts=artifacts,
        required_steps=['Associate the selected artifact with this service.',
            'Complete retained runtime validation for this service and exact artifact digest.',
            'Retain a complete assessment of the proposed inventory separately from current posture.',
            'Request Cyber review, publish its signed manifest, then explicitly activate.'])
