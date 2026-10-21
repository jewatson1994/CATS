"""Live, fail-closed distribution decisions over existing CATS evidence."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy import select

from .cyber_approvals import CyberApproval, digest as snapshot_digest
from .cyber_approval_evidence import DIGEST, _identity, _repository_identity
from .execution_summaries import payload_digest
from .models import Service
from .release_validity import require_current, utc
from .service_evidence import current_execution
from . import release_revisions


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    approval_id: int | None = None
    execution_id: int | None = None


def _artifact_matches(snapshot, repository, digest):
    for artifact in snapshot.get('artifacts', []):
        if not isinstance(artifact, dict) or artifact.get('kind') not in {'image', 'chart'}:
            continue
        # Archive hashes and tags resolved during publication are not scan evidence.
        if artifact.get('resolve_at_publication') or artifact.get('format') == 'docker-archive' or artifact.get('path'):
            continue
        try:
            reference, retained = _identity(artifact.get('reference'), artifact.get('digest'))
            if retained == digest and _repository_identity(reference) == _repository_identity(repository):
                return True
        except ValueError:
            continue
    return False


def _published_artifact_matches(approval, repository, digest):
    """Bridge retained package hashes to the verified published OCI manifest.

    Publication is an existing Cyber-approved operation, not a new approval.
    Its receipt binds the source artifact to the verified manifest digest.
    """
    receipt = approval.publication or {}
    if (approval.publish_status != 'published' or receipt.get('status') != 'published'
            or receipt.get('verification_status') != 'verified' or receipt.get('signature_status') != 'verified'):
        return False
    manifest = receipt.get('manifest') or {}
    if (manifest.get('snapshot_digest') != approval.snapshot_digest or manifest.get('approval_id') != approval.id
            or manifest.get('artifacts') != receipt.get('artifacts')):
        return False
    originals = approval.snapshot.get('artifacts', [])
    for index, artifact in enumerate(receipt.get('artifacts', [])):
        if not isinstance(artifact, dict) or index >= len(originals):
            continue
        source = originals[index]
        if (not isinstance(source, dict) or not DIGEST.fullmatch(str(source.get('digest', '')))
                or artifact.get('kind') != source.get('kind') or artifact.get('source_digest') != source.get('digest')
                or artifact.get('scan_identity_retained') is not True or artifact.get('verification_status') != 'verified'
                or artifact.get('identity_resolution') != 'retained-evidence'):
            continue
        if _artifact_matches({'artifacts': [artifact]}, repository, digest):
            return True
    return False


def authorize(db, mapping, digest, now=None):
    """Reevaluate each pull; callers must separately enforce principal mapping grants.

    Mapping policy supports optional positive integers ``max_scan_age_days``
    and ``max_approval_age_days`` to shorten existing approval authority.
    Vulnerability thresholds, deadlines and exceptions always come from the
    existing service policy; mapping policy cannot weaken those rules.
    """
    now = utc(now or datetime.now(timezone.utc))
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return AuthorizationDecision(False, 'invalid_digest')
    if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
        return AuthorizationDecision(False, 'mapping_disabled')
    service = db.get(Service, mapping.service_id, populate_existing=True)
    if service is None:
        return AuthorizationDecision(False, 'service_unavailable')
    from .main import configuration_for_service, service_lifecycle, service_view
    if service_lifecycle(service) != 'active':
        return AuthorizationDecision(False, 'service_inactive')
    execution = current_execution(db, service)
    if execution is None:
        return AuthorizationDecision(False, 'scan_missing')
    def deny(reason, approval=None):
        return AuthorizationDecision(False, reason, approval.id if approval else None, execution.id)
    if not execution.complete:
        return deny('scan_incomplete')
    policy = mapping.policy or {}
    if not isinstance(policy, dict):
        return deny('invalid_policy')
    if set(policy) - {'max_scan_age_days', 'max_approval_age_days'}:
        return deny('invalid_policy')
    approval_age = policy.get('max_approval_age_days')
    if approval_age is not None and (type(approval_age) is not int or not 1 <= approval_age <= 3650):
        return deny('invalid_policy')
    max_age = policy.get('max_scan_age_days')
    if max_age is not None:
        if type(max_age) is not int or not 1 <= max_age <= 3650:
            return deny('invalid_policy')
        if now >= utc(execution.scanned_at) + timedelta(days=max_age):
            return deny('scan_stale')
    if utc(execution.scanned_at) > now:
        return deny('scan_not_yet_valid')
    # Refresh relationship graphs so reused sessions cannot retain expired or
    # revoked exception state, findings, or newly arrived scan evidence.
    db.expire(service)
    for finding in [*service.findings, *service.policy_findings]:
        db.refresh(finding)
        for exception in finding.exceptions:
            db.refresh(exception)
    view = service_view(service, now, configuration_for_service(db, service))
    if view['incomplete']:
        return deny('scan_incomplete')
    if not view['compliant']:
        return deny('service_noncompliant')
    repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + mapping.upstream_repository
    # Once a service enters revision distribution, historical approvals cannot
    # bypass a missing, suspended, revoked, expired or unverifiable pointer.
    # A proposed amendment does not replace the previously active revision.
    revision_managed = (db.get(release_revisions.ServiceActiveRelease, service.id, populate_existing=True) is not None
        or db.scalar(select(release_revisions.ReleaseRevision.id).where(release_revisions.ReleaseRevision.service_id == service.id).limit(1)) is not None)
    active = release_revisions.active_revision(db, service.id, now) if revision_managed else None
    if revision_managed and active is None:
        return deny('active_revision_unavailable')
    approvals = db.scalars(select(CyberApproval).where(
        CyberApproval.service_id == service.id,
        CyberApproval.source_execution_id == execution.id,
    ).order_by(CyberApproval.id.desc()).execution_options(populate_existing=True))
    for approval in approvals:
        if revision_managed and approval.id != active.approval_id:
            continue
        snapshot = approval.snapshot
        if isinstance(snapshot, dict) and 'release_revision' in snapshot and not revision_managed:
            # Missing revision records are not a reason to fall back to legacy.
            return deny('active_revision_unavailable', approval)
        if not isinstance(snapshot, dict) or not (_artifact_matches(snapshot, repository, digest)
                or _published_artifact_matches(approval, repository, digest)):
            continue
        # A newer decision on these exact bytes supersedes older authorization.
        if approval.status != 'approved' or approval.revoked_at:
            return deny('approval_not_current', approval)
        if snapshot_digest(snapshot) != approval.snapshot_digest:
            return deny('approval_evidence_changed', approval)
        if (snapshot.get('service_id') != service.id
                or snapshot.get('source_execution_id') != execution.id
                or snapshot.get('source_version_id') != service.current_version_id
                or snapshot.get('source_payload_digest') != payload_digest(execution.raw_payload)):
            return deny('approval_evidence_changed', approval)
        try:
            require_current(approval, now)
        except ValueError:
            return deny('approval_not_current', approval)
        if approval_age is not None and now >= utc(approval.decided_at) + timedelta(days=approval_age):
            return deny('approval_window_elapsed', approval)
        return AuthorizationDecision(True, 'approved', approval.id, execution.id)
    return deny('digest_not_approved')
