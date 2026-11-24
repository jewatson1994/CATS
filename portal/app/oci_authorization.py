"""Group-scoped OCI authorization over approved releases and assessed artifacts."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import Text, cast, or_, select

from .cyber_approvals import CyberApproval, digest as snapshot_digest
from .cyber_approval_evidence import DIGEST, _identity, _registry_path
from .execution_summaries import payload_digest
from .models import Execution, Service
from .release_validity import require_current, utc
from . import release_revisions


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    approval_id: int | None = None
    execution_id: int | None = None
    service_id: int | None = None
    artifact_digest: str | None = None
    release_id: int | None = None
    override_id: int | None = None
    authorization_source: str | None = None
    approval_status: str | None = None
    decision_at: str | None = None
    override_url: str | None = None
    override_status: str | None = None
    effective_policy: dict | None = None


def _artifact_matches(snapshot, repository, digest, *, published=False):
    host = repository.partition('/')[0]
    expected = _registry_path(repository, host, explicit_host=True)
    if not expected:
        return False
    for artifact in snapshot.get('artifacts', []):
        if not isinstance(artifact, dict) or artifact.get('kind') not in {'image', 'chart'}:
            continue
        # Archive hashes and tags resolved during publication are not scan evidence.
        if artifact.get('resolve_at_publication') or artifact.get('format') == 'docker-archive' or artifact.get('path'):
            continue
        try:
            reference, retained = _identity(artifact.get('reference'), artifact.get('digest'))
            if retained == digest and _registry_path(reference, host, explicit_host=published) == expected:
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
        if _artifact_matches({'artifacts': [artifact]}, repository, digest, published=True):
            return True
    return False


def candidate_service_ids(db, mapping, digest):
    """Locate potential owners of concrete upstream bytes; authorize each pull separately."""
    from .imported_services import uses_imported_evidence
    if uses_imported_evidence(db, mapping.service_id):
        from .replica_authorization import candidate_service_ids as replica_candidates
        return replica_candidates(db, mapping, digest)
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return set()
    repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + mapping.upstream_repository
    scanned = CyberApproval.snapshot['artifacts']
    published = CyberApproval.publication['artifacts']
    # Filter the artifact lists in the database, without hydrating scans,
    # approval snapshots or publication receipts for unrelated services.
    query = (select(CyberApproval.service_id, scanned, published)
             .join(Service, Service.id == CyberApproval.service_id)
             .where(or_(cast(scanned, Text).contains(digest),
                        cast(published, Text).contains(digest))))
    owners = set()
    for service_id, source_artifacts, published_artifacts in db.execute(query):
        for artifacts, published_location in ((source_artifacts, False), (published_artifacts, True)):
            if isinstance(artifacts, list) and _artifact_matches(
                    {'artifacts': artifacts}, repository, digest, published=published_location):
                owners.add(service_id)
                break
    return owners


def _runtime_execution_matches(approval, active, execution):
    """Bind a signed candidate to its reviewed aggregate, even after validation observes a newer version."""
    from .runtime_candidate_assessment import aggregate_execution_key

    if active is None or active.approval_id != approval.id or not execution or execution.scan_scope != 'distribution':
        return False
    try:
        snapshot = approval.snapshot
        evidence = snapshot['runtime_evidence']
        receipts = evidence['assessments']
        raw = execution.raw_payload
        return ('distribution' not in snapshot and evidence['ready'] is True
                and type(evidence['candidate_id']) is int and evidence['candidate_id'] > 0
                and isinstance(receipts, list) and bool(receipts) and all(r['status'] == 'complete' for r in receipts)
                and execution.execution_key == aggregate_execution_key(evidence['candidate_id'], receipts)
                and raw['execution_id'] == execution.execution_key and raw['scan_scope'] == 'distribution'
                and raw['complete'] is True and execution.payload_digest == snapshot['source_payload_digest'])
    except (AttributeError, TypeError, KeyError, ValueError):
        return False


def _distribution_execution(db, service, approval):
    """Validate the approved selection and its exact retained scan admission.

    A subsequent scan is evidence for a future Cyber decision, not an implicit
    revocation of an already approved immutable distribution.
    """
    from .discovery_models import DiscoveryConfirmation, DiscoveryDistribution, DiscoveryDistributionScan
    from .scan_coordination import ScanJob
    frozen = approval.snapshot.get('distribution')
    if (not isinstance(frozen, dict) or not isinstance(frozen.get('id'), str)
            or not DIGEST.fullmatch(str(frozen.get('selection_digest', '')))):
        return None
    saved = db.get(DiscoveryDistribution, frozen['id'], populate_existing=True)
    if (saved is None or saved.service_id != service.id or not isinstance(saved.selection, dict)
            or snapshot_digest(saved.selection) != saved.selection_digest):
        return None
    try:
        confirmation = db.get(DiscoveryConfirmation, saved.confirmation_id, populate_existing=True)
        selection = {**saved.selection, 'id': saved.id, 'name': saved.name,
                     'selection_digest': saved.selection_digest}
        execution = db.get(Execution, approval.source_execution_id, populate_existing=True)
        if (confirmation is None or confirmation.service_id != service.id
                or frozen != selection or execution is None or execution.service_id != service.id
                or execution.scan_scope != 'distribution'
                or execution.service_version is None or execution.service_version.service_id != service.id
                or approval.snapshot.get('source_version_id') != execution.service_version_id
                or not isinstance(execution.raw_payload, dict)
                or execution.raw_payload.get('scan_scope') != 'distribution'
                or execution.payload_digest != payload_digest(execution.raw_payload)):
            return None
        if not execution.execution_key.startswith('public:'):
            return None
        scan_id = execution.execution_key.removeprefix('public:')
        admission = db.get(DiscoveryDistributionScan, scan_id, populate_existing=True)
        job = db.get(ScanJob, scan_id, populate_existing=True)
        if (admission is None or admission.distribution_id != saved.id or job is None
                or job.status != 'complete' or job.service_key != service.service_key):
            return None
        provenance = (execution.raw_payload.get('service_overview') or {}).get('definition_provenance') or {}
        for context in (provenance, (job.payload or {}).get('definition_context') or {}):
            if context.get('distribution_id') != saved.id or context.get('selection_digest') != saved.selection_digest:
                return None
        return execution
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def project_tag_allowed(db, mapping, tag, digest, now=None):
    """A revision-managed tag must sign this exact route and its current upstream bytes."""
    from .oci_group_policy import policy_for_service
    try:
        if policy_for_service(db, mapping.service_id)['mode'] == 'compliance':
            # The resolved digest still requires exact, current scan evidence.
            return True
    except ValueError:
        return False
    from .imported_services import uses_imported_evidence
    if uses_imported_evidence(db, mapping.service_id):
        # Tag resolution is never an authorization source on a replica. The
        # resolved manifest digest still must belong to its exact local release.
        return authorize(db, mapping, digest, now).allowed
    try:
        binding = release_revisions.resolve_distribution_tag(db, mapping, tag, now)
    except ValueError:
        return False
    return binding is None or (binding['digest'] == digest
                               and binding['upstream_repository'] == mapping.upstream_repository)


def _payload_evidence_matches(db, approval, execution, service, active, now, _seen=None):
    """Bind amendment evidence to its retained assessment and unchanged base scan."""
    seen = set(_seen or ())
    if approval.id in seen or len(seen) >= 32:
        return False
    seen.add(approval.id)
    snapshot = approval.snapshot
    if snapshot.get('amendment_proposal_id') is None:
        return snapshot.get('source_payload_digest') == payload_digest(execution.raw_payload)
    if active is None or active.approval_id != approval.id:
        return False
    from .proposal_assessments import ProposalAssessment
    from .artifact_catalog import GlobalArtifact
    try:
        proposal = db.get(release_revisions.ReleaseAmendmentProposal, snapshot['amendment_proposal_id'], populate_existing=True)
        assessment = db.get(ProposalAssessment, snapshot['proposal_assessment_id'], populate_existing=True)
        base = db.get(release_revisions.ReleaseRevision, proposal.base_revision_id, populate_existing=True) if proposal else None
        base_approval = db.get(CyberApproval, base.approval_id, populate_existing=True) if base else None
        if (proposal is None or proposal.service_id != service.id or assessment is None
                or assessment.proposal_id != proposal.id or base_approval is None
                or base.service_id != service.id or active.manifest.get('base_revision_id') != base.id
                or base_approval.source_execution_id != execution.id
                or snapshot_digest(base_approval.snapshot) != base_approval.snapshot_digest
                or base_approval.snapshot.get('source_version_id') != execution.service_version_id):
            return False
        # The proposal payload is deliberately separate from current posture.
        # Its base must still bind the original service execution bytes.
        if base_approval.snapshot.get('amendment_proposal_id') is not None:
            if (snapshot_digest(base.manifest) != base.manifest_digest
                    or not _payload_evidence_matches(db, base_approval, execution, service, base, now, seen)):
                return False
        elif base_approval.snapshot.get('source_payload_digest') != payload_digest(execution.raw_payload):
            return False
        if (assessment.digest != payload_digest(assessment.raw_payload)
                or snapshot.get('proposal_assessment_digest') != assessment.digest
                or snapshot.get('source_payload_digest') != assessment.digest):
            return False
        raw = assessment.raw_payload
        if (raw.get('service', {}).get('id') != service.service_key or not raw.get('complete')
                or not raw.get('fixable_only') or raw.get('scan_scope') != 'service'
                or raw.get('skipped_images') or raw.get('skipped_charts')):
            return False
        inventory = proposal.intent['release_revision']['artifact_ids']
        artifacts = [db.get(GlobalArtifact, identity, populate_existing=True) for identity in inventory]
        if not artifacts or any(item is None for item in artifacts):
            return False
        expected = {(item.digest, item.platform, item.media_type) for item in artifacts}
        images = raw.get('service_overview', {}).get('images', [])
        actual = {(item.get('digest'), item.get('platform'), item.get('media_type')) for item in images}
        retained = {item.get('digest') for item in snapshot.get('artifacts', []) if item.get('kind') == 'image'}
        signed = {(item.get('digest'), item.get('platform'), item.get('media_type'))
            for item in active.manifest.get('artifacts', [])}
        if actual != expected or signed != expected or retained != {item[0] for item in expected}:
            return False
        for item in images:
            reference = item.get('image') or item.get('reference')
            if not isinstance(reference, str) or not reference.endswith('@' + item['digest']):
                return False
            if not any(a.get('reference') == reference and a.get('digest') == item['digest']
                    for a in snapshot.get('artifacts', [])):
                return False
        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _authorize_approved_release(db, mapping, digest, now=None):
    """Enforce the Cyber release on every pull, including cached content.

    Live posture and subsequent scans inform the next Cyber review; they do not
    revoke this decision. Signed expiry and explicit release restrictions do.
    Callers separately enforce public/private access and principal grants.
    """
    from .imported_services import uses_imported_evidence
    if uses_imported_evidence(db, mapping.service_id):
        from .replica_authorization import authorize as replica_authorize
        return replica_authorize(db, mapping, digest, now)
    now = utc(now or datetime.now(timezone.utc))
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return AuthorizationDecision(False, 'invalid_digest')
    if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
        return AuthorizationDecision(False, 'mapping_disabled')
    service = db.get(Service, mapping.service_id, populate_existing=True)
    if service is None:
        return AuthorizationDecision(False, 'service_unavailable')
    from .main import service_lifecycle
    db.expire(service, ['archive_events'])
    if service_lifecycle(service) != 'active':
        return AuthorizationDecision(False, 'service_inactive')
    execution = None
    def deny(reason, approval=None):
        return AuthorizationDecision(False, reason, approval.id if approval else None,
                                     execution.id if execution else None)
    from .replica_authorization import repository_policy_error
    # Historical mapping age settings remain readable, but only the release's
    # signed approval period determines expiry. Malformed policy still fails.
    if repository_policy_error(mapping.policy if mapping.policy is not None else {}):
        return deny('invalid_policy')
    repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + mapping.upstream_repository
    # Once a service enters revision distribution, historical approvals cannot
    # bypass a missing, suspended, revoked, expired or unverifiable pointer.
    # A proposed amendment does not replace the previously active revision.
    revision_managed = (db.get(release_revisions.ServiceActiveRelease, service.id, populate_existing=True) is not None
        or db.scalar(select(release_revisions.ReleaseRevision.id).where(release_revisions.ReleaseRevision.service_id == service.id).limit(1)) is not None)
    active = release_revisions.active_revision(db, service.id, now) if revision_managed else None
    if revision_managed and active is None:
        return deny('active_revision_unavailable')
    if active is not None:
        try:
            repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + release_revisions.distribution_location(mapping, active, digest)
        except ValueError:
            return deny('signed_distribution_location_changed')
    approvals = db.scalars(select(CyberApproval).where(
        CyberApproval.service_id == service.id, CyberApproval.status == 'approved',
    ).order_by(CyberApproval.id.desc()).execution_options(populate_existing=True))
    from .oci_lifecycle import _distribution_snapshot
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
        execution = db.get(Execution, approval.source_execution_id, populate_existing=True)
        distribution = _distribution_snapshot(snapshot) or (execution is not None and execution.scan_scope == 'distribution')
        if snapshot.get('evidence_scope') == 'runtime-release-candidate':
            if not _runtime_execution_matches(approval, active, execution):
                return deny('approval_evidence_changed', approval)
        elif distribution:
            execution = _distribution_execution(db, service, approval)
        if execution is None:
            return deny('approval_evidence_changed' if distribution else 'scan_missing', approval)
        if not execution.complete:
            return deny('scan_incomplete', approval)
        if utc(execution.scanned_at) > now:
            return deny('scan_not_yet_valid', approval)
        # A newer approved decision on these bytes supersedes older authority.
        # Keep revoked/expired approvals in this ordering: no historical fallback.
        if approval.status != 'approved' or approval.revoked_at:
            return deny('approval_not_current', approval)
        if snapshot_digest(snapshot) != approval.snapshot_digest:
            return deny('approval_evidence_changed', approval)
        if (snapshot.get('service_id') != service.id
                or execution.service_id != service.id
                or snapshot.get('source_execution_id') != execution.id
                or snapshot.get('source_version_id') != execution.service_version_id
                or (execution.service_version_id is not None and (execution.service_version is None
                    or execution.service_version.service_id != service.id))
                or not _payload_evidence_matches(db, approval, execution, service, active, now)):
            return deny('approval_evidence_changed', approval)
        try:
            require_current(approval, now)
        except ValueError:
            return deny('approval_not_current', approval)
        return AuthorizationDecision(True, 'approved', approval.id, execution.id)
    return deny('digest_not_approved')


def authorize(db, mapping, digest, now=None):
    """Apply the receiving service's owning-group rule on every OCI read."""
    from .oci_group_policy import policy_for_service
    from .imported_services import uses_imported_evidence
    from .replica_authorization import repository_policy_error
    from .main import service_lifecycle
    timestamp = utc(now or datetime.now(timezone.utc))
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return AuthorizationDecision(False, 'invalid_digest')
    if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
        return AuthorizationDecision(False, 'mapping_disabled')
    service = db.get(Service, mapping.service_id, populate_existing=True)
    if service is None:
        return AuthorizationDecision(False, 'service_unavailable')
    db.expire(service, ['archive_events'])
    if service_lifecycle(service) != 'active':
        return AuthorizationDecision(False, 'service_inactive')
    if repository_policy_error(mapping.policy if mapping.policy is not None else {}):
        return AuthorizationDecision(False, 'invalid_policy')
    try:
        policy = policy_for_service(db, service.id)
    except ValueError:
        return AuthorizationDecision(False, 'invalid_group_pull_policy', service_id=service.id,
                                     artifact_digest=digest)
    mode = policy['mode']

    def scoped(decision, **values):
        return replace(decision, service_id=service.id, artifact_digest=digest,
            decision_at=timestamp.isoformat(),
            effective_policy={**(decision.effective_policy or {}), 'group_pull_policy': policy},
            **values)

    approved = None
    if mode in {'approved_release', 'both'}:
        approved = _authorize_approved_release(db, mapping, digest, timestamp)
        if mode == 'approved_release' or not approved.allowed:
            # Preserve the established default response for unowned services.
            if mode == 'approved_release' and policy['group_id'] is None:
                return approved
            return scoped(approved, authorization_source=approved.authorization_source
                          or ('approved_release' if approved.allowed else 'denied'))
    if uses_imported_evidence(db, service.id):
        from .oci_compliance_imported import authorize_imported_compliance
        compliance = authorize_imported_compliance(db, mapping, digest, policy, timestamp)
    else:
        from .oci_compliance import authorize_compliance
        compliance_mapping = mapping
        if mode == 'both':
            active = release_revisions.active_revision(db, service.id, timestamp)
            if active is not None:
                try:
                    repository = release_revisions.distribution_location(mapping, active, digest)
                except ValueError:
                    return scoped(AuthorizationDecision(False, 'signed_distribution_location_changed'))
                from .oci_proxy import EffectiveMapping
                compliance_mapping = EffectiveMapping(mapping, repository)
        compliance = authorize_compliance(db, compliance_mapping, digest, policy, timestamp)
    if mode == 'compliance' or not compliance.allowed:
        return scoped(compliance)
    return scoped(approved, reason='approved_and_compliant',
                  authorization_source='approved_release_and_compliance')
