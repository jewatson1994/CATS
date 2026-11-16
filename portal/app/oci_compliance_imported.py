"""Evaluate group pull rules against sealed publisher-captured scan evidence.

An imported execution is rewritten for local display. Only the captured source
execution, authenticated with the verified inventory, can grant compliance pulls.
"""
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .cyber_approval_evidence import DIGEST, _identity, _repository_identity
from .oci_compliance import evaluate_payload, payload_covers_image
from .release_validity import utc


def _captured_execution(release, state):
    from .replica_integrity import digest as evidence_digest

    evidence = release.evidence_state
    if (not isinstance(evidence, dict) or not release.evidence_state_digest
            or evidence_digest(evidence) != release.evidence_state_digest
            or evidence.get('format') != 'cats-replica-service-v1'
            or evidence.get('service_key') != state.source_service_id):
        raise ValueError('Invalid captured evidence')
    services = evidence['records']['services']
    if (not isinstance(services, list) or len(services) != 1
            or services[0]['service_key'] != state.source_service_id):
        raise ValueError('Invalid captured service')
    service = services[0]
    context = evidence['extension']['approval_context']
    execution_id = context['source_execution_id']
    if (type(execution_id) is not int or execution_id <= 0
            or context.get('service_id') != service['id']):
        raise ValueError('Invalid captured assessment identity')
    executions = evidence['records']['executions']
    if not isinstance(executions, list):
        raise ValueError('Invalid captured assessments')
    candidates = [row for row in executions if row['id'] == execution_id]
    if len(candidates) != 1:
        raise ValueError('Captured assessment unavailable or ambiguous')
    execution = candidates[0]
    if (execution['service_id'] != service['id']
            or execution.get('service_version_id') != context.get('source_version_id')
            or execution.get('scan_scope') not in {'service', 'image', 'distribution'}
            or not isinstance(execution.get('raw_payload'), dict)
            or execution['raw_payload'].get('service', {}).get('id') != state.source_service_id):
        raise ValueError('Captured assessment belongs to another service or version')
    # Capture scrubs credentials, local paths and group assignments. Its original
    # execution payload_digest can therefore differ; the sealed evidence hash
    # above authenticates the actual captured payload.
    return execution, evidence['extension'].get('display', {})


def _source_images(artifact, repository):
    """A verified manifest graph binds child requests to a scanned image root."""
    root = artifact['digest']
    if not isinstance(root, str) or not DIGEST.fullmatch(root):
        raise ValueError('Invalid verified image root')
    sources = {(repository, root)}
    if (artifact.get('scan_identity_retained') is True
            and artifact.get('verification_status') == 'verified'
            and artifact.get('identity_resolution') == 'retained-evidence'):
        references = artifact.get('source_references', [])
        if not isinstance(references, list):
            raise ValueError('Invalid retained image references')
        references = list(references)
        if artifact.get('source_reference'):
            references.append(artifact['source_reference'])
        for reference in references:
            pinned, pin = _identity(reference, artifact.get('source_digest'))
            host, path, image = _repository_identity(pinned)
            source_repository = '/'.join(part for part in (host, path, image) if part != '-')
            sources.add((source_repository, pin))
    return sources


def authorize_imported_compliance(db, mapping, digest, policy, now=None):
    from .main import service_lifecycle
    from .models import Service
    from .oci_authorization import AuthorizationDecision
    from .replica_authorization import trusted_release
    from .replica_models import ReplicaRelease, ReplicaServiceState

    timestamp = utc(now or datetime.now(timezone.utc))
    effective_policy = dict(policy, evidence_source='publisher_capture')

    def decision(reason=None):
        # A compliance decision grants image access, never approval attestations
        # or an offline Cyber evidence bundle. Source IDs are foreign identifiers.
        return AuthorizationDecision(reason is None, reason or 'compliant',
            service_id=mapping.service_id, artifact_digest=digest,
            authorization_source='compliance', decision_at=timestamp.isoformat(),
            effective_policy=effective_policy)

    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return decision('invalid_digest')
    if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
        return decision('mapping_disabled')
    service = db.get(Service, mapping.service_id, populate_existing=True)
    state = db.get(ReplicaServiceState, mapping.service_id, populate_existing=True)
    if service is None or state is None or state.upstream_id != mapping.upstream_id:
        return decision('replica_service_unavailable')
    db.expire(service, ['archive_events'])
    if service_lifecycle(service) != 'active':
        return decision('service_inactive')
    release = db.get(ReplicaRelease, state.active_release_id, populate_existing=True) if state.active_release_id else None
    if not trusted_release(db, release, state, timestamp):
        return decision('artifact_not_in_verified_release')
    try:
        artifacts = release.artifacts
        if not isinstance(artifacts, list):
            return decision('compliance_evidence_invalid')
        matches = [item for item in artifacts if item.get('kind') == 'image'
            and item.get('repository') == mapping.upstream_repository
            and (item.get('digest') == digest or digest in item.get('manifests', []))]
        if not matches:
            return decision('artifact_not_in_verified_release')
        execution, display = _captured_execution(release, state)
        if execution.get('complete') is not True:
            return decision('compliance_scan_incomplete')
        payload = execution['raw_payload']
        repository = urlsplit(mapping.upstream.endpoint).netloc + '/' + mapping.upstream_repository
        # Every matching root and every scanned alias must pass. A clean alias
        # cannot hide findings recorded against another alias of the same image.
        for artifact in matches:
            sources = sorted((source, pin) for source, pin in _source_images(artifact, repository)
                             if payload_covers_image(payload, source, pin))
            if not sources:
                return decision('compliance_image_not_scanned')
            for source, pin in sources:
                reason = evaluate_payload(payload, source, pin, policy, timestamp,
                    scanned_at=execution['scanned_at'])
                if reason:
                    return decision(reason)
        if policy.get('require_service_compliant'):
            row = display.get('services_row', {})
            if not isinstance(row, dict) or type(row.get('compliant')) is not bool:
                return decision('compliance_service_evidence_missing')
            if not row['compliant']:
                return decision('service_noncompliant')
        return decision()
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return decision('compliance_evidence_invalid')
