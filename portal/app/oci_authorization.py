"""Live, fail-closed distribution decisions over existing CATS evidence."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

from sqlalchemy import Text, cast, or_, select

from .cyber_approvals import CyberApproval, digest as snapshot_digest
from .cyber_approval_evidence import DIGEST, _identity, _registry_path
from .execution_summaries import payload_digest
from .models import Execution, Service
from .release_validity import require_current, utc
from .service_evidence import current_execution, current_execution_id_query
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
    from .operating_mode import is_replica
    if is_replica():
        from .replica_authorization import candidate_service_ids as replica_candidates
        return replica_candidates(db, mapping, digest)
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return set()
    repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + mapping.upstream_repository
    scanned = CyberApproval.snapshot['artifacts']
    published = CyberApproval.publication['artifacts']
    # Filter the artifact lists in the database, without hydrating scans,
    # approval snapshots or publication receipts for unrelated services.
    current_scan = current_execution_id_query(Service).correlate(Service).scalar_subquery()
    query = (select(CyberApproval.service_id, scanned, published)
             .join(Service, Service.id == CyberApproval.service_id)
             .join(Execution, Execution.id == CyberApproval.source_execution_id)
             .where(or_(CyberApproval.source_execution_id == current_scan,
                        Execution.scan_scope == 'distribution'),
                    or_(cast(scanned, Text).contains(digest),
                        cast(published, Text).contains(digest))))
    owners = set()
    for service_id, source_artifacts, published_artifacts in db.execute(query):
        for artifacts, published_location in ((source_artifacts, False), (published_artifacts, True)):
            if isinstance(artifacts, list) and _artifact_matches(
                    {'artifacts': artifacts}, repository, digest, published=published_location):
                owners.add(service_id)
                break
    return owners


def _distribution_execution(db, service, approval):
    """A distribution never borrows the baseline scan or an earlier admission."""
    from .cyber_approval_evidence import _distribution_assessment
    from .discovery_models import DiscoveryDistribution
    frozen = approval.snapshot.get('distribution')
    if (not isinstance(frozen, dict) or not isinstance(frozen.get('id'), str)
            or not DIGEST.fullmatch(str(frozen.get('selection_digest', '')))):
        return None
    saved = db.get(DiscoveryDistribution, frozen['id'], populate_existing=True)
    if (saved is None or saved.service_id != service.id or not isinstance(saved.selection, dict)
            or snapshot_digest(saved.selection) != saved.selection_digest):
        return None
    blockers = []
    try:
        selection, execution = _distribution_assessment(db, service, saved.id, blockers)
        if (blockers or frozen != selection or execution is None
                or execution.id != approval.source_execution_id
                or execution.service_version is None or execution.service_version.service_id != service.id
                or approval.snapshot.get('source_version_id') != execution.service_version_id
                or not isinstance(execution.raw_payload, dict)
                or execution.raw_payload.get('scan_scope') != 'distribution'
                or execution.payload_digest != payload_digest(execution.raw_payload)):
            return None
        return execution
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _distribution_policy_ages(db, service, execution, identities):
    """Retain continuous policy episodes without reconciling baseline posture."""
    from .discovery_models import DiscoveryDistributionScan
    from .scan_coordination import ScanJob
    from .main import policy_finding_identity, policy_finding_values
    provenance = execution.raw_payload['service_overview']['definition_provenance']
    retained = Execution.raw_payload['service_overview']['definition_provenance']
    context = ScanJob.payload['definition_context']
    ages = {identity: utc(execution.scanned_at) for identity in identities}
    if not ages:
        return ages
    history = db.execute(select(Execution.scanned_at, Execution.complete,
        Execution.raw_payload['policy_findings']).join(DiscoveryDistributionScan,
        Execution.execution_key == 'public:' + DiscoveryDistributionScan.scan_job_id)
        .join(ScanJob, ScanJob.id == DiscoveryDistributionScan.scan_job_id).where(
        Execution.service_id == service.id, Execution.scan_scope == 'distribution',
        Execution.id != execution.id, ScanJob.status == 'complete', ScanJob.service_key == service.service_key,
        DiscoveryDistributionScan.distribution_id == provenance['distribution_id'],
        retained['distribution_id'].as_string() == provenance['distribution_id'],
        retained['selection_digest'].as_string() == provenance['selection_digest'],
        context['distribution_id'].as_string() == provenance['distribution_id'],
        context['selection_digest'].as_string() == provenance['selection_digest'])
        .order_by(DiscoveryDistributionScan.created_at.desc(), DiscoveryDistributionScan.scan_job_id.desc()))
    pending = set(ages)
    for scanned_at, complete, items in history:
        observed = {policy_finding_identity(policy_finding_values(item)) for item in items or []}
        for identity in pending & observed:
            ages[identity] = min(ages[identity], utc(scanned_at))
        if complete:
            pending &= observed
        if not pending:
            break
    return ages


def _distribution_service(db, service, execution):
    """Project retained findings into the existing live policy evaluator.

    Distribution ingestion intentionally does not reconcile baseline posture.
    Use retained severity/observations, live matching exceptions, and the earlier
    known episode age without changing the actual service or its relationships.
    """
    from .main import policy_finding_identity, policy_finding_values
    payload = execution.raw_payload
    existing = {row.cve: row for row in service.findings}
    policies = {row.identity_key: row for row in service.policy_findings}

    def state(index, row, earlier=None):
        dates = [utc(execution.scanned_at)]
        if row:
            dates.append(utc(row.episode_started))
        if earlier:
            dates.append(utc(earlier))
        return dict(id=index, active=True, exceptions=list(row.exceptions) if row else [],
                    episode_started=min(dates))

    findings = []
    for index, item in enumerate(payload.get('findings') or [], 1):
        evidence = dict(item.get('evidence') or {})
        evidence.setdefault('kev', item.get('kev', False))
        if item.get('epss') is not None:
            evidence.setdefault('epss', item['epss'])
        row = existing.get(item['cve'])
        findings.append(SimpleNamespace(**state(index, row, row.first_seen if row else None),
            cve=item['cve'], severity=item['severity'],
            observations=[SimpleNamespace(id=index, evidence=evidence)]))
    policy_findings = []
    values_by_identity = {policy_finding_identity(values): values
        for item in payload.get('policy_findings') or [] for values in [policy_finding_values(item)]}
    policy_ages = _distribution_policy_ages(db, service, execution, values_by_identity)
    for index, (identity, values) in enumerate(values_by_identity.items(), 1):
        policy_findings.append(SimpleNamespace(**values,
            **state(index, policies.get(identity), policy_ages[identity])))
    return SimpleNamespace(id=service.id, service_key=service.service_key,
        current_version_id=execution.service_version_id, current_version=execution.service_version,
        manual_version=None, executions=[execution], findings=findings, policy_findings=policy_findings,
        poam_entries=[], archive_events=service.archive_events)


def project_tag_allowed(db, mapping, tag, digest, now=None):
    """A revision-managed tag must sign this exact route and its current upstream bytes."""
    from .operating_mode import is_replica
    if is_replica():
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
    from .proposal_scans import (require_assessment_dispatch, freshness_deadline,
        latest_dispatch, evidence_inputs_token, proposal_inputs_token)
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
                or base_approval.snapshot.get('source_version_id') != service.current_version_id):
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
                or snapshot.get('source_payload_digest') != assessment.digest
                or freshness_deadline(assessment.raw_payload) <= now):
            return False
        require_assessment_dispatch(db, proposal, assessment.execution_key)
        dispatch = latest_dispatch(db, proposal.id)
        if dispatch and (dispatch.payload.get('evidence_inputs_token') != evidence_inputs_token(db, service.id)
                or dispatch.payload.get('proposal_inputs_token') != proposal_inputs_token(db, proposal)):
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


def authorize(db, mapping, digest, now=None):
    """Reevaluate each pull; callers must separately enforce principal mapping grants.

    Mapping policy supports optional positive integers ``max_scan_age_days``
    and ``max_approval_age_days`` to shorten existing approval authority.
    Vulnerability thresholds, deadlines and exceptions always come from the
    existing service policy; mapping policy cannot weaken those rules.
    """
    from .operating_mode import is_replica
    if is_replica():
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
    from .main import configuration_for_service, service_lifecycle, service_view
    if service_lifecycle(service) != 'active':
        return AuthorizationDecision(False, 'service_inactive')
    baseline = execution = current_execution(db, service)
    def deny(reason, approval=None):
        return AuthorizationDecision(False, reason, approval.id if approval else None,
                                     execution.id if execution else None)
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
    # Refresh relationship graphs so reused sessions cannot retain expired or
    # revoked exception state, findings, or newly arrived scan evidence.
    db.expire(service)
    for finding in [*service.findings, *service.policy_findings]:
        db.refresh(finding)
        for exception in finding.exceptions:
            db.refresh(exception)
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
    approvals = db.execute(select(CyberApproval, Execution.scan_scope)
        .join(Execution, Execution.id == CyberApproval.source_execution_id).where(
        CyberApproval.service_id == service.id,
        or_(CyberApproval.source_execution_id == (baseline.id if baseline else None),
            Execution.scan_scope == 'distribution'),
    ).order_by(CyberApproval.id.desc()).execution_options(populate_existing=True))
    from .oci_lifecycle import _distribution_snapshot
    for approval, scan_scope in approvals:
        if revision_managed and approval.id != active.approval_id:
            continue
        snapshot = approval.snapshot
        if isinstance(snapshot, dict) and 'release_revision' in snapshot and not revision_managed:
            # Missing revision records are not a reason to fall back to legacy.
            return deny('active_revision_unavailable', approval)
        if not isinstance(snapshot, dict) or not (_artifact_matches(snapshot, repository, digest)
                or _published_artifact_matches(approval, repository, digest)):
            continue
        distribution = _distribution_snapshot(snapshot) or scan_scope == 'distribution'
        execution = _distribution_execution(db, service, approval) if distribution else baseline
        if execution is None:
            return deny('approval_evidence_changed' if distribution else 'scan_missing', approval)
        if not execution.complete:
            return deny('scan_incomplete', approval)
        if max_age is not None and now >= utc(execution.scanned_at) + timedelta(days=max_age):
            return deny('scan_stale', approval)
        if utc(execution.scanned_at) > now:
            return deny('scan_not_yet_valid', approval)
        try:
            subject = _distribution_service(db, service, execution) if distribution else service
            view = service_view(subject, now, configuration_for_service(db, service))
        except (AttributeError, KeyError, TypeError, ValueError):
            return deny('approval_evidence_changed', approval)
        if view['incomplete']:
            return deny('scan_incomplete', approval)
        if not view['compliant']:
            return deny('service_noncompliant', approval)
        # A newer decision on these exact bytes supersedes older authorization.
        if approval.status != 'approved' or approval.revoked_at:
            return deny('approval_not_current', approval)
        if snapshot_digest(snapshot) != approval.snapshot_digest:
            return deny('approval_evidence_changed', approval)
        if (snapshot.get('service_id') != service.id
                or snapshot.get('source_execution_id') != execution.id
                or snapshot.get('source_version_id') != (execution.service_version_id if distribution else service.current_version_id)
                or not _payload_evidence_matches(db, approval, execution, service, active, now)):
            return deny('approval_evidence_changed', approval)
        try:
            require_current(approval, now)
        except ValueError:
            return deny('approval_not_current', approval)
        if approval_age is not None and now >= utc(approval.decided_at) + timedelta(days=approval_age):
            return deny('approval_window_elapsed', approval)
        return AuthorizationDecision(True, 'approved', approval.id, execution.id)
    return deny('digest_not_approved' if baseline else 'scan_missing')
