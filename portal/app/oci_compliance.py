"""Digest-bound OCI compliance decisions from retained local scan evidence.

These rules describe the findings retained by the scanner, including its scan
filters. A clean dashboard or a missing finding alone is never image coverage.
"""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy import Text, cast, select

from .cyber_approval_evidence import DIGEST, _identity, _registry_path, _repository_identity
from .execution_summaries import payload_digest
from .models import Execution, Service
from .release_validity import utc

SEVERITIES = {'Negligible': 0, 'Informational': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


def _path(reference, repository):
    host = repository.partition('/')[0]
    return _registry_path(reference, host)


def _coverage(payload):
    overview = payload.get('service_overview') or {}
    if not isinstance(overview, dict):
        raise ValueError('Invalid scan inventory')
    rows = []
    for value in (overview.get('images', []), overview.get('container_images', []),
                  payload.get('sbom_images', []), payload.get('sbom_components', [])):
        if not isinstance(value, list):
            raise ValueError('Invalid scan inventory')
        rows.extend(value)
    images = []
    for row in rows:
        if isinstance(row, str):
            # ExecutionPayload.sbom_images retains strings. A digest-pinned
            # entry establishes coverage; a mutable tag alone does not.
            reference, retained = row, None
        elif isinstance(row, dict):
            reference = row.get('image') or row.get('reference') or row.get('image_reference')
            retained = row.get('digest') or row.get('image_digest')
        else:
            raise ValueError('Invalid image evidence')
        try:
            images.append(_identity(reference, retained))
        except ValueError:
            # Unresolved inventory cannot establish coverage; a retained exact
            # identity elsewhere in the complete scan may still establish it.
            continue
    return images


def payload_covers_image(payload, repository, digest):
    try:
        expected = _registry_path(repository, repository.partition('/')[0], explicit_host=True)
        return any(pin == digest and _path(reference, repository) == expected
                   for reference, pin in _coverage(payload))
    except (AttributeError, TypeError, ValueError):
        return False


def evaluate_payload(payload, repository, digest, policy, now, *, scanned_at=None):
    """Return a denial reason, or None for covered findings within policy.

    Callers verify the retained payload's integrity and service ownership first.
    Imported callers must supply the original sealed source payload, not the
    locally rewritten execution projection.
    """
    try:
        if (not isinstance(payload, dict) or payload.get('complete') is not True
                or payload.get('skipped_images') or payload.get('skipped_charts')):
            return 'compliance_scan_incomplete'
        if not isinstance(payload.get('findings'), list):
            return 'compliance_evidence_invalid'
        retained_stamp = datetime.fromisoformat(payload['scanned_at'])
        stamp = scanned_at if scanned_at is not None else retained_stamp
        if isinstance(stamp, str):
            stamp = datetime.fromisoformat(stamp)
        stamp, now = utc(stamp), utc(now)
        if stamp != utc(retained_stamp):
            return 'compliance_evidence_invalid'
        if stamp > now:
            return 'compliance_scan_not_yet_valid'
        age = policy.get('max_scan_age_days')
        if age is not None and now >= stamp + timedelta(days=age):
            return 'compliance_scan_stale'
        images = _coverage(payload)
        if not payload_covers_image(payload, repository, digest):
            return 'compliance_image_not_scanned'
        threshold = policy['blocked_severity']
        if threshold == 'None':
            return None
        minimum = SEVERITIES[threshold]
        covered_repositories = {}
        for reference, pin in images:
            covered_repositories.setdefault(_repository_identity(reference), set()).add(pin)
        for finding in payload['findings']:
            if not isinstance(finding, dict):
                return 'compliance_evidence_invalid'
            reference = finding.get('image') or finding.get('image_reference')
            if not isinstance(reference, str) or not reference.strip():
                return 'compliance_evidence_invalid'
            pin = finding.get('image_digest') or finding.get('digest')
            if pin or '@' in reference:
                _, pin = _identity(reference, pin)
                if pin != digest:
                    continue
            else:
                pins = covered_repositories.get(_repository_identity(reference), set())
                if digest not in pins:
                    continue
                if pins != {digest}:
                    # A tag-only finding cannot choose between two scanned
                    # digests, even when the requested alias is unambiguous.
                    return 'compliance_evidence_invalid'
            # An immutable image is the same bytes under every repository
            # alias. Never select a clean alias to hide findings attached to
            # another scanned name for the exact same digest.
            severity = finding.get('severity')
            if severity not in SEVERITIES:
                return 'compliance_evidence_invalid'
            if SEVERITIES[severity] >= minimum:
                return 'compliance_blocked_severity'
        return None
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return 'compliance_evidence_invalid'


def _published_sources(db, service, repository, digest):
    """Verified relocation is identity evidence, never a Cyber approval grant."""
    from .cyber_approvals import CyberApproval, digest as snapshot_digest
    from .oci_authorization import _artifact_matches
    query = select(CyberApproval).where(CyberApproval.service_id == service.id,
        cast(CyberApproval.publication['artifacts'], Text).contains(digest))
    for approval in db.scalars(query.execution_options(populate_existing=True)):
        snapshot = approval.snapshot
        receipt = approval.publication
        manifest = receipt.get('manifest') if isinstance(receipt, dict) else None
        if (not isinstance(snapshot, dict) or snapshot.get('service_id') != service.id
                or snapshot_digest(snapshot) != approval.snapshot_digest
                or not isinstance(manifest, dict)
                or receipt.get('verification_status') != 'verified' or receipt.get('signature_status') != 'verified'
                or manifest.get('approval_id') != approval.id
                or manifest.get('snapshot_digest') != approval.snapshot_digest
                or manifest.get('artifacts') != receipt.get('artifacts')):
            continue
        for source, artifact in zip(snapshot.get('artifacts', []), approval.publication.get('artifacts', [])):
            if (source.get('kind') != 'image' or source.get('path') or source.get('resolve_at_publication')
                    or source.get('format') == 'docker-archive'
                    or artifact.get('source_digest') != source.get('digest')
                    or artifact.get('scan_identity_retained') is not True
                    or artifact.get('verification_status') != 'verified'
                    or artifact.get('identity_resolution') != 'retained-evidence'
                    or not _artifact_matches({'artifacts': [artifact]}, repository, digest, published=True)):
                continue
            reference, pin = _identity(source.get('reference'), source.get('digest'))
            distribution = snapshot.get('distribution')
            yield reference.split('@', 1)[0], pin, distribution.get('id') if isinstance(distribution, dict) else None


def _local_execution(db, service, repository, digest):
    """Newest applicable current-version evidence; incomplete evidence wins too."""
    query = select(Execution).where(Execution.service_id == service.id,
        Execution.service_version_id.is_not_distinct_from(service.current_version_id),
        Execution.scan_scope.in_(('service', 'image'))).order_by(Execution.scanned_at.desc(), Execution.id.desc())
    for execution in db.scalars(query.execution_options(populate_existing=True)):
        if execution.scan_scope == 'service' or not execution.scope_image:
            return execution
        expected = _registry_path(repository, repository.partition('/')[0], explicit_host=True)
        if _path(execution.scope_image, repository) == expected or payload_covers_image(execution.raw_payload, repository, digest):
            return execution
    return None


def _distribution_candidates(db, service, repository, digest, selected_id=None):
    from .cyber_approvals import digest as snapshot_digest
    from .discovery_models import DiscoveryConfirmation, DiscoveryDistribution, DiscoveryDistributionScan
    from .scan_coordination import ScanJob
    query = select(DiscoveryDistribution).where(DiscoveryDistribution.service_id == service.id)
    if selected_id is not None:
        query = query.where(DiscoveryDistribution.id == selected_id)
    expected = _registry_path(repository, repository.partition('/')[0], explicit_host=True)
    for saved in db.scalars(query.execution_options(populate_existing=True)):
        selection = saved.selection
        if not isinstance(selection, dict):
            continue
        if selected_id is None and not any(isinstance(reference, str) and _path(reference, repository) == expected
                                           for reference in selection.get('images', [])):
            continue
        admission = db.scalar(select(DiscoveryDistributionScan).where(
            DiscoveryDistributionScan.distribution_id == saved.id).order_by(
            DiscoveryDistributionScan.created_at.desc(), DiscoveryDistributionScan.scan_job_id.desc()).limit(1))
        if admission is None:
            continue
        confirmation = db.get(DiscoveryConfirmation, saved.confirmation_id, populate_existing=True)
        job = db.get(ScanJob, admission.scan_job_id, populate_existing=True)
        execution = db.scalar(select(Execution).where(Execution.service_id == service.id,
            Execution.execution_key == 'public:' + admission.scan_job_id).execution_options(populate_existing=True))
        error = None
        if (snapshot_digest(selection) != saved.selection_digest or confirmation is None
                or confirmation.service_id != service.id or job is None or job.service_key != service.service_key):
            error = 'compliance_evidence_invalid'
        elif job.status != 'complete' or execution is None:
            error = 'compliance_scan_incomplete'
        else:
            raw = execution.raw_payload
            provenance = (raw.get('service_overview') or {}).get('definition_provenance') or {} if isinstance(raw, dict) else {}
            contexts = (provenance, (job.payload or {}).get('definition_context') or {})
            if (execution.scan_scope != 'distribution' or raw.get('scan_scope') != 'distribution'
                    or any(context.get('distribution_id') != saved.id
                           or context.get('selection_digest') != saved.selection_digest for context in contexts)):
                error = 'compliance_evidence_invalid'
        yield utc(execution.scanned_at if execution is not None else admission.created_at), execution, error


def authorize_compliance(db, mapping, digest, policy, now=None):
    from .oci_authorization import AuthorizationDecision
    from .imported_services import uses_imported_evidence
    from .main import configuration_for_service, service_lifecycle, service_view
    now = utc(now or datetime.now(timezone.utc))
    execution = None

    def decision(reason=None):
        return AuthorizationDecision(reason is None, reason or 'compliant',
            execution_id=execution.id if execution is not None else None,
            service_id=mapping.service_id, artifact_digest=digest,
            authorization_source='compliance', decision_at=now.isoformat(), effective_policy=dict(policy))

    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return decision('invalid_digest')
    if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
        return decision('mapping_disabled')
    if uses_imported_evidence(db, mapping.service_id):
        return decision('compliance_imported_evidence_required')
    service = db.get(Service, mapping.service_id, populate_existing=True)
    if service is None:
        return decision('service_unavailable')
    db.expire(service, ['archive_events'])
    if service_lifecycle(service) != 'active':
        return decision('service_inactive')
    repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + mapping.upstream_repository
    try:
        sources = {(repository, digest, None), *_published_sources(db, service, repository, digest)}
        candidates = []
        for source, pin, distribution_id in sorted(sources, key=lambda item: (item[0], item[1], item[2] or '')):
            if distribution_id is None:
                current = _local_execution(db, service, source, pin)
                if current is not None:
                    # The direct publication repository is not scanned. Its
                    # verified source alias supplies coverage instead.
                    if (len(sources) == 1 or source != repository
                            or payload_covers_image(current.raw_payload, source, pin)):
                        candidates.append((utc(current.scanned_at), current.id, current, None, source, pin))
            for stamp, current, error in _distribution_candidates(db, service, source, pin, distribution_id):
                candidates.append((stamp, current.id if current else 0, current, error, source, pin))
        if not candidates:
            return decision('compliance_image_not_scanned')
        _, _, execution, error, source, pin = max(candidates, key=lambda item: item[:2])
        if error:
            return decision(error)
        if (execution.service_id != service.id or (execution.service_version_id is not None
                and (execution.service_version is None or execution.service_version.service_id != service.id))
                or not isinstance(execution.raw_payload, dict)
                or not execution.payload_digest or execution.payload_digest != payload_digest(execution.raw_payload)
                or (execution.raw_payload.get('service') or {}).get('id') != service.service_key):
            return decision('compliance_evidence_invalid')
        if not execution.complete:
            return decision('compliance_scan_incomplete')
        error = evaluate_payload(execution.raw_payload, source, pin, policy, now, scanned_at=execution.scanned_at)
        if error:
            return decision(error)
        if policy.get('require_service_compliant'):
            db.expire(service)
            for finding in [*service.findings, *service.policy_findings]:
                db.refresh(finding)
                for exception in finding.exceptions:
                    db.refresh(exception)
            view = service_view(service, now, configuration_for_service(db, service))
            if view['incomplete'] or not view['compliant']:
                return decision('service_noncompliant')
        return decision()
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return decision('compliance_evidence_invalid')
