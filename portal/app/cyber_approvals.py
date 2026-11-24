"""Cyber decisions on immutable service evidence and durable approved releases."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text, or_, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column
from .database import Base, get_db
from .models import AuditEvent, Service, Group, User, PortalSetting, RemediationExecution, utcnow
from .auth import AuthContext, require_user, record_audit
from .durable_jobs import DurableJob, submit, JobError
from .service_oci import validate_destination, _csrf
from .secrets import encrypt_secret, decrypt_secret
from . import signing, release_validity, additional_release_delivery as additional
from .imported_services import imported_service_predicate, is_imported_service

router = APIRouter()


def _json_body(schema, examples):
    return {'requestBody': {'required': True, 'content': {'application/json': {
        'schema': schema, 'examples': {name: {'value': body} for name, body in examples.items()}}}}}


SUBMISSION_BODY = _json_body({
    'type': 'object', 'required': ['service_key'],
    'properties': {
        'service_key': {'type': 'string'},
        'variant': {'type': 'string', 'enum': ['current_service', 'cats_remediated'], 'default': 'current_service'},
        'runtime_candidate_id': {'type': 'integer', 'minimum': 1, 'description':
            'Service-scoped runtime candidate. Submit it with the review digest returned by its readiness endpoint.'},
        'review_digest': {'type': 'string', 'pattern': '^sha256:[0-9a-f]{64}$'},
        'remediation_id': {'type': 'integer'}, 'distribution_id': {'type': 'string', 'maxLength': 32},
        'expected_source_execution_id': {'type': 'integer'}, 'amendment_proposal_id': {'type': 'integer'},
        'release_revision': {'type': 'object'}, 'renews_approval_id': {'type': 'integer'},
        'reassessment_event_id': {'type': 'string'}, 'destination_id': {'type': 'integer'},
        'additional_destination_id': {'type': ['string', 'integer']}, 'rationale': {'type': 'string'},
    },
    'dependentRequired': {'runtime_candidate_id': ['review_digest'], 'distribution_id': ['expected_source_execution_id']},
}, {
    'Runtime candidate': {'service_key': 'payments', 'runtime_candidate_id': 12, 'review_digest': 'sha256:' + 'a' * 64},
    'Current service': {'service_key': 'payments', 'variant': 'current_service'},
    'Retained remediation': {'service_key': 'payments', 'variant': 'cats_remediated', 'remediation_id': 31},
    'Saved distribution': {'service_key': 'payments', 'distribution_id': 'mobile', 'expected_source_execution_id': 37},
})

DECISION_BODY = _json_body({
    'type': 'object', 'required': ['decision', 'rationale'],
    'properties': {
        'decision': {'type': 'string', 'enum': ['approved', 'denied', 'returned'],
                     'description': 'Return for changes is available for runtime submissions.'},
        'rationale': {'type': 'string', 'minLength': 3, 'maxLength': 10000},
        'destination_id': {'type': 'integer', 'description': 'Select an eligible destination if the request has none.'},
    },
}, {
    'Approve': {'decision': 'approved', 'rationale': 'Reviewed the retained scan and component inventory.'},
    'Reject': {'decision': 'denied', 'rationale': 'The retained image exceeds the approved risk threshold.'},
    'Return runtime candidate': {'decision': 'returned', 'rationale': 'Provide the missing component assessment.'},
})


class ApprovedReleaseDestination(Base):
    __tablename__ = 'approved_release_destinations'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    endpoint: Mapped[str] = mapped_column(String(500))
    namespace: Mapped[str] = mapped_column(String(300), default='')
    username: Mapped[str] = mapped_column(Text, default='')
    password: Mapped[str] = mapped_column(Text, default='')
    ca_pem: Mapped[str] = mapped_column(Text, default='')
    group_ids: Mapped[list] = mapped_column(JSON, default=list)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    pull_instructions: Mapped[str] = mapped_column(Text, default='')


class CyberApproval(Base):
    __tablename__ = 'cyber_approvals'
    id: Mapped[int] = mapped_column(primary_key=True)
    release_key: Mapped[str] = mapped_column(String(32), unique=True, default=lambda: uuid.uuid4().hex)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    source_execution_id: Mapped[int] = mapped_column(ForeignKey('executions.id'))
    remediation_id: Mapped[int | None] = mapped_column(ForeignKey('remediation_executions.id'))
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    destination_id: Mapped[int | None] = mapped_column(ForeignKey('approved_release_destinations.id'))
    variant: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(24), default='pending', index=True)
    publish_status: Mapped[str] = mapped_column(String(24), default='not_started', index=True)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot_digest: Mapped[str] = mapped_column(String(80))
    destination: Mapped[dict] = mapped_column(JSON, default=dict)
    rationale: Mapped[str] = mapped_column(Text, default='')
    decision_rationale: Mapped[str] = mapped_column(Text, default='')
    publication: Mapped[dict] = mapped_column(JSON, default=dict)
    job_id: Mapped[str | None] = mapped_column(String(32))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str] = mapped_column(Text, default='')


def root():
    from . import main
    return Path(os.getenv('CATS_APPROVED_RELEASE_ROOT', str(main.REMEDIATION_JOB_ROOT / 'approved-releases')))


def digest(value):
    return 'sha256:' + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _permission(auth, permission, service_id=None):
    if not auth.has(permission, service_id):
        raise HTTPException(403, 'Permission denied')


def _service(db, auth, key):
    row = db.scalar(select(Service).where(Service.service_key == key))
    if not row or not auth.has('service.view', row.id):
        raise HTTPException(404, 'Service not found')
    return row


def _record(db, auth, identity):
    row = db.get(CyberApproval, identity)
    if not row or not auth.has('service.view', row.service_id) or not _visible_review(auth, row):
        raise HTTPException(404, 'Approval not found')
    return row


def public_destination(row):
    return {key: getattr(row, key) for key in ('id', 'name', 'endpoint', 'namespace', 'group_ids', 'is_default', 'enabled', 'pull_instructions')} | {
        'credentials_configured': bool(row.password), 'ca_configured': bool(row.ca_pem)}


def _eligible(destination, service):
    return destination.enabled and (not destination.group_ids or bool(set(destination.group_ids) & {group.id for group in service.groups}))


def _eligible_destinations(db, service):
    rows = db.scalars(select(ApprovedReleaseDestination).order_by(
        ApprovedReleaseDestination.is_default.desc(), ApprovedReleaseDestination.id))
    return [row for row in rows if _eligible(row, service)]


def _require_cyber_default(eligible, selected):
    if eligible and eligible[0].is_default and eligible[0].id != selected.id:
        raise HTTPException(422, 'The configured Cyber default is required as the primary release destination')


def _settings(db):
    return {row.key: row.value for row in db.scalars(select(PortalSetting))}


def _signing_ready(db):
    try:
        config = signing.configuration(_settings(db))
        return bool(config.get('enabled') and config.get('private_key') and config.get('public_key') and config.get('fingerprint'))
    except ValueError:
        return False


def _readiness(db, service, variant, remediation_id, distribution_id=None):
    from .cyber_approval_evidence import readiness
    result = readiness(db, service, variant, remediation_id, distribution_id=distribution_id)
    return _with_destinations(db, service, result)


def _with_destinations(db, service, result):
    destinations = [public_destination(row) for row in _eligible_destinations(db, service)]
    notes = list(result.get('review_notes', []))
    if not destinations:
        notes.append('An administrator must configure an approved-release OCI destination before Cyber approves publication.')
    if not _signing_ready(db):
        notes.append('An administrator must enable the CATS signing key before Cyber approves publication.')
    return {**result, 'review_notes': notes, 'destinations': destinations}


def _runtime_candidate(db, service, identity):
    from .runtime_candidates import RuntimeReleaseCandidate
    row = db.get(RuntimeReleaseCandidate, identity) if type(identity) is int else None
    if row is None or row.service_id != service.id:
        raise HTTPException(404, 'Runtime candidate not found')
    return row


def _runtime_assessment(db, service, candidate):
    from .runtime_candidates import assessment_for_review
    try:
        return _with_destinations(db, service, assessment_for_review(db, candidate, service))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None


def _runtime_token(result, candidate):
    from .cyber_approval_evidence import payload_digest
    return digest({'candidate_id': candidate.id, 'version': candidate.version,
                   'previous_approval': candidate.approval_id, 'inventory': candidate.fingerprint,
                   'evidence': result['runtime_evidence'], 'payload': payload_digest(result.get('payload') or {})})


def _historical_inventory(db, candidate):
    from .runtime_candidates import checksum
    if checksum(candidate.inventory) != candidate.fingerprint:
        raise HTTPException(409, 'Retained candidate inventory integrity check failed')
    events = db.scalars(select(AuditEvent).where(
        AuditEvent.target_type == 'runtime_candidate', AuditEvent.target_id == str(candidate.id)
    ).order_by(AuditEvent.created_at, AuditEvent.id))
    return {
        **_public(candidate.inventory), 'revision': candidate.version, 'proposed_version': candidate.proposed_version,
        'fingerprint': candidate.fingerprint, 'created_at': release_validity.utc(candidate.created_at).isoformat(),
        'history': [{'action': event.action, 'recorded_at': release_validity.utc(event.created_at).isoformat(),
                     'actor': event.detail.get('actor_display_name') or event.detail.get('actor_username')
                         or ('Retained account' if event.actor_user_id else 'System'),
                     'detail': {key: event.detail[key] for key in ('job_id', 'reference', 'previous', 'status')
                                if key in event.detail}} for event in events],
    }


def _runtime_manager(auth, service_id):
    return all(auth.has(permission, service_id) for permission in (
        'service.edit', 'service.export', 'approval.request', 'runtime.prepare_release'))


def _runtime_reviewer(auth, service_id):
    return auth.has('approval.decide', service_id) and auth.has('runtime.review_release', service_id)


def can_review_release(auth, approval):
    if not approval.snapshot.get('runtime_evidence'):
        return auth.has('approval.decide', approval.service_id)
    return (_runtime_reviewer(auth, approval.service_id) and auth.user.id is not None
            and auth.user.id != approval.requested_by_id)


def _visible_review(auth, approval):
    return (approval.status == 'approved' or not approval.snapshot.get('runtime_evidence')
            or _runtime_manager(auth, approval.service_id) or _runtime_reviewer(auth, approval.service_id))


def _require_reviewer(auth, approval):
    if not can_review_release(auth, approval):
        raise HTTPException(403, 'Release review permission denied')


def _runtime_revision(db, service, snapshot):
    from .artifact_catalog import GlobalArtifact, ServiceArtifactAssignment, register_artifact, assign_artifact
    from .release_revisions import ServiceActiveRelease
    identities = set()
    for item in snapshot['artifacts']:
        matches = db.scalars(select(GlobalArtifact).join(ServiceArtifactAssignment).where(
            ServiceArtifactAssignment.service_id == service.id, GlobalArtifact.digest == item['digest'])).unique().all()
        known = matches[0] if len(matches) == 1 else None
        artifact = register_artifact(db, digest=item['digest'], reference=item.get('reference'),
            media_type=item.get('media_type') or (known.media_type if known else 'application/octet-stream'),
            platform=item.get('platform') or (known.platform if known else 'unknown'),
            provenance={'runtime_candidate_id': snapshot['runtime_evidence']['candidate_id'],
                        'execution_id': snapshot['source_execution_id']})
        assign_artifact(db, service_id=service.id, artifact_id=artifact.id, role='release')
        identities.add(artifact.id)
    active = db.get(ServiceActiveRelease, service.id)
    return {'artifact_ids': sorted(identities), 'base_revision_id': active.revision_id if active else None}


def _candidate_transition(db, candidate, status, approval_id):
    from .runtime_candidates import RuntimeReleaseCandidate
    change = update(RuntimeReleaseCandidate).where(
        RuntimeReleaseCandidate.id == candidate.id, RuntimeReleaseCandidate.status == candidate.status,
        RuntimeReleaseCandidate.approval_id == candidate.approval_id
    )
    if status == 'submitted':
        change = change.where(RuntimeReleaseCandidate.current.is_(True))
    changed = db.execute(change.values(status=status, approval_id=approval_id)).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, 'Candidate review changed. Reload before continuing.')


@router.get('/api/services/{key}/cyber-approval-readiness')
def readiness_api(key: str, variant: str = 'current_service', remediation_id: int | None = None,
                  distribution_id: str | None = None,
                  db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
                  runtime_candidate_id: int | None = None):
    service = _service(db, auth, key)
    runtime = {}
    if runtime_candidate_id is not None:
        candidate = _runtime_candidate(db, service, runtime_candidate_id)
        if not _runtime_manager(auth, service.id):
            raise HTTPException(403, 'Runtime release preparation permission denied')
        prior = db.get(CyberApproval, candidate.approval_id) if candidate.approval_id else None
        runtime['runtime_candidate'] = {'id': candidate.id, 'revision': candidate.version, 'status': candidate.status,
            'approval_id': candidate.approval_id, 'decision_rationale': prior.decision_rationale if prior else None}
        if not candidate.current and candidate.approval_id is None:
            return {**runtime, 'historical_inventory': _historical_inventory(db, candidate),
                    'ready': False, 'can_request': False, 'service_id': service.id}
        if candidate.status not in ('draft', 'returned'):
            return {**runtime, 'ready': False, 'can_request': False, 'service_id': service.id}
        result = _runtime_assessment(db, service, candidate)
        runtime.update(runtime_evidence=_public(result['runtime_evidence']), review_digest=_runtime_token(result, candidate))
    else:
        result = _readiness(db, service, variant, remediation_id, distribution_id)
    execution = result.get('execution')
    can_select = additional.selectable(auth, service.id)
    return {key: value for key, value in result.items() if key in ('ready', 'blockers', 'destinations', 'version', 'scan_date', 'variant', 'review_notes', 'distribution')} | {
        'service_id': service.id, 'can_select_additional_destination': can_select,
        'additional_destinations': additional.options(db, service.id) if can_select else [],
        'source_execution_id': execution.id if execution else None,
        'executions': [{'id': execution.id, 'scanned_at': execution.scanned_at.isoformat()}] if execution else [],
        'remediations': [{'id': row.id, 'label': row.job_key} for row in db.scalars(select(RemediationExecution).where(
            RemediationExecution.service_id == service.id,
            RemediationExecution.source_execution_id == execution.id if execution else False,
            RemediationExecution.source_version_id == service.current_version_id).order_by(RemediationExecution.id.desc()))],
        'can_request': (_runtime_manager(auth, service.id) if runtime else
                        auth.has('approval.request', service.id) and auth.has('service.export', service.id)), **runtime}


def _public(value):
    # Files remain private implementation details. All downloads recheck scope.
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key not in ('path', 'bundle_path', 'artifact_path', 'archive_path', 'candidate_path', 'directory', 'root', 'password', 'username', 'ca_pem', 'private_key')}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def dto(db, row, auth, detail=False):
    service = db.get(Service, row.service_id)
    runtime = row.snapshot.get('runtime_evidence')
    reviewer = can_review_release(auth, row)
    requested_by = db.get(User, row.requested_by_id) if row.requested_by_id else None
    approved_by_id = row.decided_by_id if row.status == 'approved' else None
    approved_by = db.get(User, approved_by_id) if approved_by_id else None
    approved_by_name = ((approved_by.display_name or '').strip() or approved_by.username
                        if approved_by else 'Retained account' if approved_by_id else None)
    result = {key: getattr(row, key) for key in ('id', 'release_key', 'variant', 'status', 'publish_status', 'rationale', 'decision_rationale', 'snapshot_digest', 'revocation_reason')}
    result.update(service_id=row.service_id, service_key=service.service_key, service_name=service.name, version=row.snapshot.get('version'),
        distribution_name=(row.snapshot.get('distribution') or {}).get('name'),
        scan_date=row.snapshot.get('scan_date'), label='CATS Remediated' if row.variant == 'cats_remediated' else 'Current Service',
        requested_at=row.requested_at.isoformat(), decided_at=row.decided_at.isoformat() if row.decided_at else None,
        approved_by=approved_by_name, approved_by_id=approved_by_id,
        requested_by=requested_by.display_name if requested_by else 'Retained account', destination=row.destination,
        publication=_public(row.publication), can_decide=row.status == 'pending' and reviewer,
        can_retry=row.status == 'approved' and row.publish_status == 'failed' and not row.revoked_at and reviewer,
        can_revoke=row.status == 'approved' and not row.revoked_at
            and row.publish_status not in ('queued', 'publishing') and reviewer,
        revoked=bool(row.revoked_at), revoked_at=row.revoked_at.isoformat() if row.revoked_at else None, release_id=row.id)
    result.update(release_validity.summary(row))
    if runtime:
        result.update(label='Runtime candidate', runtime_candidate_id=runtime['candidate_id'])
    result['can_retry'] = ((result['can_retry'] and result['validity_status'] in ('valid', 'expiring_soon'))
        or bool(row.revoked_at and row.publish_status == 'failed'
                and (row.publication or {}).get('revocation', {}).get('portable')
                and reviewer))
    if detail:
        result['snapshot'] = _public(row.snapshot)
        if runtime and row.status == 'returned':
            candidate = _runtime_candidate(db, service, runtime['candidate_id'])
            result['can_resubmit'] = (candidate.current and candidate.status == 'returned'
                and candidate.approval_id == row.id and _runtime_manager(auth, row.service_id))
        result['additional_destination'] = row.snapshot.get('additional_destination')
        result['additional_deliveries'] = additional.details(db, auth, row)
        if row.status == 'pending' and not row.destination_id:
            eligible = _eligible_destinations(db, service)
            choices = eligible[:1] if eligible and eligible[0].is_default else eligible
            result['destinations'] = [public_destination(item) for item in choices]
        if auth.has('service.export', row.service_id):
            result['evidence_url'] = f'/api/cyber-approvals/{row.id}/download/evidence'
            if runtime:
                result['submission_url'] = f'/api/cyber-approvals/{row.id}/download/submission'
            if row.publish_status == 'published':
                result['offline_bundle_url'] = f'/api/cyber-approvals/{row.id}/download/offline'
    return result


@router.post('/api/cyber-approvals', openapi_extra=SUBMISSION_BODY)
async def request_approval(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    data = await request.json()
    service = _service(db, auth, str(data.get('service_key', '')))
    _permission(auth, 'approval.request', service.id)
    _permission(auth, 'service.export', service.id)
    if service.lifecycle_status != 'active':
        raise HTTPException(409, 'Only active services can request approval')
    runtime_candidate = None
    if data.get('runtime_candidate_id') is not None:
        _permission(auth, 'service.edit', service.id)
        _permission(auth, 'runtime.prepare_release', service.id)
        if auth.user.id is None:
            raise HTTPException(403, 'A service manager account is required to submit a runtime candidate')
        if data.get('variant', 'current_service') != 'current_service' or any(
                data.get(key) is not None for key in ('amendment_proposal_id', 'distribution_id', 'release_revision',
                                                     'renews_approval_id', 'reassessment_event_id', 'remediation_id')):
            raise HTTPException(422, 'Runtime review uses the selected candidate inventory')
        runtime_candidate = _runtime_candidate(db, service, data['runtime_candidate_id'])
    if data.get('amendment_proposal_id') is not None:
        if data.get('renews_approval_id') is not None:
            raise HTTPException(422, 'An amendment is a separate approval, not an unchanged-inventory renewal')
        from .release_revisions import amendment_specification
        try:
            specification = amendment_specification(db, auth, data['amendment_proposal_id'], service.id)
        except (ValueError, PermissionError) as exc:
            raise HTTPException(409, str(exc)) from None
        if 'release_revision' in data and data['release_revision'] != specification:
            raise HTTPException(422, 'Revision inventory differs from amendment proposal')
        data['release_revision'] = specification
    variant = data.get('variant', 'current_service')
    distribution_id = data.get('distribution_id')
    if distribution_id is not None and (not isinstance(distribution_id, str) or not distribution_id or len(distribution_id) > 32):
        raise HTTPException(422, 'Select a saved distribution')
    if variant not in ('current_service', 'cats_remediated'):
        raise HTTPException(422, 'Select Current Service or CATS Remediated')
    if runtime_candidate is not None:
        result = _runtime_assessment(db, service, runtime_candidate)
        if runtime_candidate.status not in ('draft', 'returned'):
            raise HTTPException(409, 'This candidate already has a Cyber review')
        if data.get('review_digest') != _runtime_token(result, runtime_candidate):
            raise HTTPException(409, 'The candidate or its evidence changed. Review it again before submitting.')
    elif data.get('amendment_proposal_id') is not None:
        if variant != 'current_service' or data.get('remediation_id') is not None or distribution_id is not None:
            raise HTTPException(422, 'Amendment review uses its retained proposed assessment')
        from .proposal_assessments import assess
        try:
            result = assess(db, service, data['amendment_proposal_id'])
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
    else:
        result = _readiness(db, service, variant, data.get('remediation_id'), distribution_id)
    if not result['ready']:
        raise HTTPException(409, {'message': 'Resolve all missing evidence before requesting approval', 'blockers': result['blockers']})
    if distribution_id is not None and result['execution'].id != data.get('expected_source_execution_id'):
        raise HTTPException(409, 'Distribution scan changed. Review its current evidence before submitting.')
    eligible = _eligible_destinations(db, service)
    destination = eligible[0] if eligible else None
    if data.get('destination_id') is not None:
        destination = next((row for row in eligible if str(row.id) == str(data['destination_id'])), None)
        if destination is None:
            raise HTTPException(422, 'Select an available approved-release destination')
        _require_cyber_default(eligible, destination)
    extra = additional.freeze_target(db, auth, service.id, data.get('additional_destination_id'),
                                     public_destination(destination) if destination else None)
    renewal = None
    event = None
    if data.get('renews_approval_id') is not None:
        renewal = db.scalar(select(CyberApproval).where(CyberApproval.id == data['renews_approval_id']).with_for_update())
        if not renewal or renewal.service_id != service.id or renewal.status != 'approved' or renewal.revoked_at:
            raise HTTPException(409, 'Renewal requires a non-revoked approval for this service')
        if (renewal.snapshot.get('distribution') or {}).get('id') != distribution_id:
            raise HTTPException(409, 'A different distribution needs a separate Cyber approval.')
        if data.get('reassessment_event_id'):
            from .oci_lifecycle import OCIReassessmentEvent
            event = db.get(OCIReassessmentEvent, str(data['reassessment_event_id']))
            if not event or event.approval_id != renewal.id:
                raise HTTPException(409, 'Reassessment event does not match renewal')
            existing = db.scalar(select(CyberApproval).where(CyberApproval.service_id == service.id,
                CyberApproval.snapshot['reassessment_event_id'].as_string() == event.id))
            if existing:
                return dto(db, existing, auth, True)
        if data.get('expected_source_execution_id') is not None and result['execution'].id != data['expected_source_execution_id']:
            raise HTTPException(409, 'Reassessment source changed; review the current assessment')
        if (not result['execution'].complete or result['execution'].id == renewal.source_execution_id
                or release_validity.utc(result['execution'].scanned_at) <= release_validity.utc(renewal.requested_at)):
            raise HTTPException(409, 'Renewal requires a fresh complete assessment')
        def identities(items):
            return sorted((item.get('kind', ''), item.get('reference', ''), item.get('digest', '')) for item in items)
        if identities(result['artifacts']) != identities(renewal.snapshot.get('artifacts', [])):
            raise HTTPException(409, 'Renewal artifact identities changed; request a separate approval')
    from .cyber_approval_evidence import freeze
    release_key = uuid.uuid4().hex
    folder = root() / release_key
    folder.mkdir(parents=True, exist_ok=False)
    try:
        snapshot = freeze(db, service, auth, result, folder)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    frozen_destination = public_destination(destination) if destination else {}
    # Credentials may rotate, but endpoint, namespace, trust and signing identity are bound to review.
    if destination:
        frozen_destination['ca_digest'] = hashlib.sha256(destination.ca_pem.encode()).hexdigest()
    try:
        fingerprint = signing.configuration(_settings(db)).get('fingerprint')
    except ValueError:
        fingerprint = None
    snapshot.update(variant=variant, destination=frozen_destination, signing_fingerprint=fingerprint)
    if extra:
        snapshot['additional_destination'] = extra
    if runtime_candidate is not None:
        try:
            data['release_revision'] = _runtime_revision(db, service, snapshot)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
    if 'release_revision' in data:
        from . import release_revisions
        snapshot['release_revision'] = data['release_revision']
        candidate = CyberApproval(id=0, release_key=release_key, service_id=service.id,
            snapshot=snapshot, snapshot_digest=digest(snapshot))
        try:
            release_revisions._manifest(db, candidate)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(422, 'Invalid revision inventory: ' + str(exc)) from None
    if data.get('amendment_proposal_id') is not None:
        snapshot['amendment_proposal_id'] = data['amendment_proposal_id']
    if renewal:
        snapshot['renews_approval_id'] = renewal.id
        snapshot['reassessment_event_id'] = event.id if event else None
    from .oci_lifecycle import retain_public_key
    retain_public_key(db, signing.configuration(_settings(db)))
    snapshot['review_notes'] = list(dict.fromkeys(snapshot.get('review_notes', []) + result.get('review_notes', [])))
    requested_at = utcnow()
    if runtime_candidate is not None:
        from .release_revisions import canonical
        snapshot['previous_review_id'] = runtime_candidate.approval_id
        snapshot['submission'] = {'requested_by_id': auth.user.id, 'requested_at': requested_at.isoformat()}
        submission = canonical(_public(snapshot))
        with (folder / 'submitted-snapshot.json').open('xb') as output:
            output.write(submission)
        snapshot['submission_digest'] = 'sha256:' + hashlib.sha256(submission).hexdigest()
    row = CyberApproval(release_key=release_key, service_id=service.id, source_execution_id=result['execution'].id,
        remediation_id=result['remediation'].id if result.get('remediation') else None, requested_by_id=auth.user.id,
        requested_at=requested_at,
        destination_id=destination.id if destination else None, variant=variant, snapshot=snapshot, snapshot_digest=digest(snapshot),
        destination=frozen_destination, rationale=str(data.get('rationale') or '')[:10000])
    db.add(row)
    db.flush()
    if runtime_candidate is not None:
        _candidate_transition(db, runtime_candidate, 'submitted', row.id)
    record_audit(db, auth, 'cyber_approval.request', 'cyber_approval', row.id, snapshot_digest=row.snapshot_digest)
    db.commit()
    return dto(db, row, auth, True)


def runtime_review_notifications(db, auth, limit=10):
    from .runtime_candidates import RuntimeReleaseCandidate as Candidate
    roles = ('runtime.review_release', 'runtime.prepare_release')
    allowed = auth.accessible_service_ids('service.view')
    query = select(Candidate.id, Candidate.status, Candidate.current, Service.id, Service.service_key, Service.name,
        CyberApproval.id, CyberApproval.requested_by_id).select_from(Candidate).join(Service, Service.id == Candidate.service_id).join(
        CyberApproval, CyberApproval.id == Candidate.approval_id).where(
        or_(Candidate.current.is_(True), Candidate.status == 'submitted',
            CyberApproval.decided_at >= utcnow() - timedelta(days=7)),
        Candidate.status.in_(('submitted', 'returned', 'denied', 'approved'))
    ).order_by((Candidate.status == 'submitted').desc(), CyberApproval.id.desc())
    if allowed is not None:
        query = query.where(Service.id.in_(allowed))
    scoped = [auth.accessible_service_ids(permission) for permission in roles]
    if all(ids is not None for ids in scoped):
        query = query.where(Service.id.in_(set().union(*scoped)))
    items = []
    for candidate_id, status, current, service_id, service_key, service_name, approval_id, submitter_id in db.execute(query):
        pending = status == 'submitted'
        if pending:
            if not _runtime_reviewer(auth, service_id) or auth.user.id is None or auth.user.id == submitter_id:
                continue
        elif not _runtime_manager(auth, service_id):
            continue
        href = f'/cyber-approvals?id={approval_id}'
        if status == 'returned' and current:
            href = '/cyber-approvals?' + urlencode({'service': service_key, 'runtime_candidate_id': candidate_id})
        label = {'submitted': 'Runtime release awaiting Cyber review', 'returned': 'Runtime release returned for changes',
                 'denied': 'Runtime release rejected', 'approved': 'Runtime release approved'}[status]
        items.append({'label': label, 'service': service_name, 'href': href})
        if len(items) >= limit:
            break
    return items


def _list(db, auth, service=None, status=None, approved=False):
    query = select(CyberApproval)
    allowed = auth.accessible_service_ids('service.view')
    if allowed is not None:
        query = query.where(CyberApproval.service_id.in_(allowed))
    if service:
        query = query.where(CyberApproval.service_id == _service(db, auth, service).id)
    if approved:
        query = query.where(CyberApproval.status == 'approved')
    elif status:
        query = query.where(CyberApproval.status == status)
    rows = db.scalars(query.order_by(CyberApproval.id.desc())).all()
    items = [dto(db, row, auth) for row in rows if _visible_review(auth, row)]
    return {'items': items, 'total': len(items)}


@router.get('/api/cyber-approvals')
def approvals(service: str | None = None, status: str | None = None, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    return _list(db, auth, service, status)


@router.get('/api/cyber-approvals/{identity}')
def approval(identity: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    return dto(db, _record(db, auth, identity), auth, True)


def _enqueue(db, row, actor, revocation=None):
    job = submit(db, kind='cyber_release_publish', payload={'approval_id': row.id,
        **({'revocation': revocation} if revocation else {})}, service_id=row.service_id,
        requested_by_id=actor, source_execution_id=row.source_execution_id, version=str(row.snapshot.get('version', '')),
        dedupe_key=f'cyber:{row.id}:{uuid.uuid4().hex}', max_attempts=1, commit=False)
    row.job_id, row.publish_status = job.id, 'queued'


@router.post('/api/cyber-approvals/{identity}/decision', openapi_extra=DECISION_BODY)
async def decide(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    row = _record(db, auth, identity)
    _require_reviewer(auth, row)
    data = await request.json()
    decision = data.get('decision')
    rationale = data['rationale'].strip() if isinstance(data.get('rationale'), str) else ''
    runtime = row.snapshot.get('runtime_evidence')
    outcomes = ('approved', 'denied', 'returned') if runtime else ('approved', 'denied')
    if decision not in outcomes or not 3 <= len(rationale) <= 10000:
        raise HTTPException(422, 'Choose a Cyber decision and provide a rationale (3–10000 characters)')
    if not hmac.compare_digest(row.snapshot_digest, digest(row.snapshot)):
        raise HTTPException(409, 'Snapshot integrity check failed')
    if runtime:
        service = db.get(Service, row.service_id)
        candidate = _runtime_candidate(db, service, runtime['candidate_id'])
        if row.status != 'pending' or candidate.status != 'submitted' or candidate.approval_id != row.id:
            raise HTTPException(409, 'This candidate review already has a decision')
        submitted = _public(row.snapshot)
        expected = submitted.pop('submission_digest', '')
        path = root() / row.release_key / 'submitted-snapshot.json'
        if (not path.is_file() or path.is_symlink() or digest(submitted) != expected
                or 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise HTTPException(409, 'Submitted runtime snapshot integrity check failed')
    bound = {}
    decided_at = utcnow()
    if decision == 'approved' and row.status == 'pending':
        from .release_key_rotation import lock_configuration
        lock_configuration(db)
        snapshot = dict(row.snapshot)
        try:
            snapshot['approval_validity'] = release_validity.for_service(db, db.get(Service, row.service_id), decided_at)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        if not row.destination_id:
            destination = db.get(ApprovedReleaseDestination, data.get('destination_id')) if data.get('destination_id') else None
            if not destination or not _eligible(destination, db.get(Service, row.service_id)):
                raise HTTPException(409, 'Configure and select an approved-release OCI destination before approving publication')
            _require_cyber_default(_eligible_destinations(db, db.get(Service, row.service_id)), destination)
            frozen = public_destination(destination)
            additional.reject_duplicate(frozen, snapshot.get('additional_destination'))
            frozen['ca_digest'] = hashlib.sha256(destination.ca_pem.encode()).hexdigest()
            snapshot['destination'] = frozen
            bound.update(destination_id=destination.id, destination=frozen)
        if not snapshot.get('signing_fingerprint'):
            if not _signing_ready(db):
                raise HTTPException(409, 'An administrator must enable signing before approving publication')
            snapshot['signing_fingerprint'] = signing.configuration(_settings(db))['fingerprint']
        elif snapshot['signing_fingerprint'] != signing.configuration(_settings(db)).get('fingerprint'):
            raise HTTPException(409, 'Signing key changed after this request. Request approval again with the current signing key.')
        from .replica_models import reserve_publication
        snapshot['portable_release'] = {**reserve_publication(db, db.get(Service, row.service_id), row.id),
            **snapshot['approval_validity'], 'service_version': snapshot.get('version'), 'revoked_at': None}
        bound.update(snapshot=snapshot, snapshot_digest=digest(snapshot))
    changed = db.execute(update(CyberApproval).where(CyberApproval.id == row.id, CyberApproval.status == 'pending').values(
        status=decision, decision_rationale=rationale, decided_by_id=auth.user.id, decided_at=decided_at, **bound)).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, 'This request already has a decision')
    db.refresh(row)
    if runtime:
        _candidate_transition(db, candidate, decision, row.id)
    if decision != 'returned' and row.snapshot.get('release_revision') is not None:
        from . import release_revisions
        try:
            revision = release_revisions.propose(db, auth, row.id, decision_context=True)
            release_revisions.decide(db, auth, revision.id, 0)
        except (ValueError, PermissionError) as exc:
            db.rollback()
            raise HTTPException(409, str(exc)) from None
    if decision == 'approved':
        _enqueue(db, row, auth.user.id)
    record_audit(db, auth, 'cyber_approval.' + decision, 'cyber_approval', row.id, snapshot_digest=row.snapshot_digest)
    db.commit()
    return dto(db, row, auth, True)


@router.get('/api/approved-releases')
def releases(service: str | None = None, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    return _list(db, auth, service, approved=True)


@router.get('/api/approved-releases/{identity}')
def release(identity: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    row = _record(db, auth, identity)
    if row.status != 'approved':
        raise HTTPException(404, 'Approved release not found')
    return dto(db, row, auth, True)


@router.post('/api/approved-releases/{identity}/retry')
def retry(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    row = _record(db, auth, identity)
    _require_reviewer(auth, row)
    if row.revoked_at:
        metadata = (row.publication or {}).get('revocation', {}).get('portable')
        changed = db.execute(update(CyberApproval).where(CyberApproval.id == row.id,
            CyberApproval.status == 'approved', CyberApproval.publish_status == 'failed',
            CyberApproval.revoked_at.is_not(None)).values(publish_status='queued')).rowcount if metadata else 0
        if changed != 1:
            db.rollback()
            raise HTTPException(409, 'Only failed signed revocation publications can be retried')
        db.refresh(row)
        _enqueue(db, row, auth.user.id, metadata)
        record_audit(db, auth, 'cyber_release.revocation.retry', 'cyber_approval', row.id)
        db.commit()
        return dto(db, row, auth, True)
    try:
        release_validity.require_current(row)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    changed = db.execute(update(CyberApproval).where(CyberApproval.id == row.id, CyberApproval.status == 'approved',
        CyberApproval.publish_status == 'failed', CyberApproval.revoked_at.is_(None)).values(publish_status='queued')).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, 'Only failed, non-revoked publications can be retried')
    db.refresh(row)
    _enqueue(db, row, auth.user.id)
    record_audit(db, auth, 'cyber_release.retry', 'cyber_approval', row.id)
    db.commit()
    return dto(db, row, auth, True)


@router.post('/api/approved-releases/{identity}/additional-deliveries/{kind}/retry')
def retry_additional(identity: int, kind: str, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    row = _record(db, auth, identity)
    if row.snapshot.get('runtime_evidence'):
        _require_reviewer(auth, row)
    if not (auth.has('approval.decide', row.service_id) or additional.selectable(auth, row.service_id)):
        raise HTTPException(403, 'Permission denied')
    model = additional.AdditionalReleaseDelivery
    if kind not in ('release', 'revocation') or not additional.can_retry(auth, row, kind):
        raise HTTPException(409, 'Only failed, authorized additional deliveries can be retried')
    changed = db.execute(update(model).where(model.approval_id == row.id, model.kind == kind,
                                              model.status == 'failed').values(status='queued')).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, 'Only failed, authorized additional deliveries can be retried')
    delivery = db.get(model, (row.id, kind))
    additional.enqueue(db, row, delivery, auth.user.id)
    record_audit(db, auth, 'cyber_release.additional.retry', 'cyber_approval', row.id, delivery_kind=kind)
    db.commit()
    return dto(db, row, auth, True)


@router.post('/api/approved-releases/{identity}/revoke')
async def revoke(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    row = _record(db, auth, identity)
    _require_reviewer(auth, row)
    rationale = str((await request.json()).get('rationale') or '').strip()
    if len(rationale) < 3:
        raise HTTPException(409, 'Provide a rationale after publication has completed or failed')
    changed = db.execute(update(CyberApproval).where(CyberApproval.id == row.id,
        CyberApproval.status == 'approved', CyberApproval.publish_status.not_in(('queued', 'publishing')),
        CyberApproval.revoked_at.is_(None)).values(revoked_at=utcnow(), revocation_reason=rationale[:10000])).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, 'Only non-revoked releases without active publication can be revoked')
    db.refresh(row)
    if row.snapshot.get('portable_release') and row.destination_id:
        from .replica_models import reserve_publication
        metadata = {**reserve_publication(db, db.get(Service, row.service_id), row.id,
                    kind='revocation', target_release_id=str(row.id)),
                    **row.snapshot['approval_validity'],
                    'revoked_at': release_validity.utc(row.revoked_at).isoformat(),
                    'revoked_by_id': auth.user.id, 'reason': row.revocation_reason}
        row.publication = {**(row.publication or {}), 'revocation': {'status': 'queued', 'portable': metadata}}
        _enqueue(db, row, auth.user.id, metadata)
    record_audit(db, auth, 'cyber_release.revoke', 'cyber_approval', row.id)
    db.commit()
    return dto(db, row, auth, True)


@router.get('/api/cyber-approvals/{identity}/download/{kind}')
def download(identity: int, kind: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    row = _record(db, auth, identity)
    _permission(auth, 'service.export', row.service_id)
    entry = row.snapshot.get('evidence', {}) if kind == 'evidence' else {}
    if kind == 'submission' and row.snapshot.get('submission_digest'):
        entry = {'path': root() / row.release_key / 'submitted-snapshot.json', 'digest': row.snapshot['submission_digest']}
    if kind == 'offline' and row.publish_status == 'published':
        entry = {'path': row.publication.get('bundle_path'), 'digest': row.publication.get('bundle_digest')}
    if not entry.get('path'):
        raise HTTPException(404, 'Download unavailable')
    path = Path(entry['path']).resolve()
    if not path.is_relative_to((root() / row.release_key).resolve()) or not path.is_file():
        raise HTTPException(409, 'Retained download unavailable')
    with path.open('rb') as stream:
        checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
    if entry.get('digest', '').removeprefix('sha256:') != checksum:
        raise HTTPException(409, 'Retained download integrity check failed')
    if kind == 'submission':
        return FileResponse(path, filename='submitted-snapshot.json', media_type='application/json')
    return FileResponse(path, filename='all.zip' if kind == 'evidence' else 'offline-bundle.zip', media_type='application/zip')


@router.get('/api/approved-release-destinations')
def destinations(db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _permission(auth, 'release.destination.manage')
    return {'items': [public_destination(row) for row in db.scalars(select(ApprovedReleaseDestination))],
            'groups': [{'id': row.id, 'name': row.name} for row in db.scalars(select(Group))]}


@router.post('/api/approved-release-destinations')
async def save_destination(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    _permission(auth, 'release.destination.manage')
    data = await request.json()
    row = db.get(ApprovedReleaseDestination, data['id']) if data.get('id') else ApprovedReleaseDestination()
    if not row:
        raise HTTPException(404, 'Destination not found')
    prior = {key: getattr(row, key) or '' for key in ('name', 'endpoint', 'namespace', 'ca_pem')}
    values = validate_destination({**prior, **data})
    groups = data.get('group_ids', row.group_ids or [])
    if not isinstance(groups, list) or any(not isinstance(item, int) or not db.get(Group, item) for item in groups):
        raise HTTPException(422, 'Choose valid service groups')
    for key, value in values.items():
        setattr(row, key, value)
    row.group_ids = groups
    row.pull_instructions = str(data.get('pull_instructions', row.pull_instructions or ''))[:10000]
    row.is_default = bool(data.get('is_default', row.is_default or False))
    row.enabled = bool(data.get('enabled', row.enabled if row.id else True))
    for key in ('username', 'password'):
        if data.get(key):
            setattr(row, key, encrypt_secret(str(data[key])))
    if row.is_default:
        db.execute(update(ApprovedReleaseDestination).values(is_default=False))
    db.add(row)
    db.flush()
    record_audit(db, auth, 'cyber_release.destination.save', 'approved_release_destination', row.id)
    db.commit()
    return public_destination(row)


def publish_job(ctx, payload):
    from .cyber_release_publication import publish, PublicationError, failure_diagnostic
    from .delivery_execution import delivery_lock
    if payload.get('additional_delivery'):
        return additional.run(ctx, payload)
    with delivery_lock(root() / '.locks', int(payload['approval_id'])) as owned:
        if not owned:
            raise JobError('Another publisher still owns this release. Retry after it finishes.')
        if payload.get('revocation'):
            return _publish_revocation_job(ctx, payload)
        with ctx.session_factory() as db:
            row = db.get(CyberApproval, payload['approval_id'])
            if not row or row.status != 'approved' or row.revoked_at or row.job_id != ctx.job.id:
                raise JobError('Approved request is unavailable or has been revoked')
            if is_imported_service(db, row.service_id):
                raise JobError('Imported service evidence is managed by its OCI publisher')
            try:
                ctx.check()
                if row.snapshot_digest != digest(row.snapshot):
                    raise JobError('Approved snapshot integrity check failed')
                try:
                    release_validity.require_current(row)
                except ValueError as exc:
                    raise JobError(str(exc)) from None
                destination = db.get(ApprovedReleaseDestination, row.destination_id)
                service = db.get(Service, row.service_id)
                if not destination or not _eligible(destination, service):
                    raise JobError('Approved destination is disabled or outside service scope')
                if any(getattr(destination, key) != row.destination[key] for key in ('endpoint', 'namespace')) or hashlib.sha256(destination.ca_pem.encode()).hexdigest() != row.destination['ca_digest']:
                    raise JobError('Approved destination changed. Submit a new review for the new destination.')
                if signing.configuration(_settings(db)).get('fingerprint') != row.snapshot.get('signing_fingerprint'):
                    raise JobError('Signing identity changed. Submit a new review for the new signing key.')
                row.publish_status = 'publishing'
                db.commit()
                ctx.stage('Publishing and verifying approved release', 10)
                def check_owner():
                    ctx.check()
                    db.refresh(row)
                    if row.job_id != ctx.job.id or row.status != 'approved' or row.revoked_at:
                        raise JobError('Publication authorization changed')
                    try:
                        release_validity.require_current(row)
                    except ValueError as exc:
                        raise JobError(str(exc)) from None
                def checkpoint(receipt):
                    check_owner()
                    row.publication = dict(receipt)
                    db.commit()
                private_destination = {**public_destination(destination), 'username': decrypt_secret(destination.username),
                                       'password': destination.password, 'ca_pem': destination.ca_pem}
                receipt = publish(db, row, private_destination, checkpoint)
                check_owner()
                if (receipt.get('status') != 'published' or receipt.get('verification_status') != 'verified'
                        or receipt.get('signature_status') != 'verified'):
                    raise JobError('Publication did not return a verified complete release')
                bundle = Path(receipt.get('bundle_path') or '').resolve()
                if not bundle.is_relative_to((root() / row.release_key).resolve()) or not bundle.is_file():
                    raise JobError('Verified offline bundle is unavailable')
                with bundle.open('rb') as stream:
                    checksum = 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()
                if not hmac.compare_digest(checksum, str(receipt.get('bundle_digest') or '')):
                    raise JobError('Offline bundle integrity check failed')
                check_owner()
                row.publication, row.publish_status = receipt, 'published'
                additional.schedule(db, row, 'release')
                record_audit(db, None, 'cyber_release.published', 'cyber_approval', row.id, snapshot_digest=row.snapshot_digest)
                db.commit()
                return {'result_url': f'/approved-releases?id={row.id}', 'approval_id': row.id}
            except Exception as exc:
                db.rollback()
                row = db.get(CyberApproval, payload['approval_id'])
                diagnostic = exc.receipt.get('diagnostic') if isinstance(exc, PublicationError) else failure_diagnostic(exc, 'Publication worker checks')
                error = str(exc) if isinstance(exc, (JobError, PublicationError)) else diagnostic['cause']
                if row and row.job_id == ctx.job.id:
                    row.publish_status = 'failed'
                    row.publication = {**(row.publication or {}), 'status': 'failed', 'error': error,
                                       'diagnostic': diagnostic, 'correlation_id': ctx.job.id}
                    db.commit()
                raise JobError(error) from None


def _publish_revocation_job(ctx, payload):
    from .cyber_release_publication import publish_revocation, PublicationError, failure_diagnostic
    with ctx.session_factory() as db:
        row = db.get(CyberApproval, payload['approval_id'])
        if (not row or row.status != 'approved' or not row.revoked_at or row.job_id != ctx.job.id
                or (row.publication or {}).get('revocation', {}).get('portable') != payload['revocation']):
            raise JobError('Recorded revocation publication is unavailable')
        if is_imported_service(db, row.service_id):
            raise JobError('Imported service evidence is managed by its OCI publisher')
        try:
            ctx.check()
            destination = db.get(ApprovedReleaseDestination, row.destination_id)
            if not destination or not destination.enabled:
                raise JobError('Approved destination is disabled or unavailable')
            if (any(getattr(destination, key) != row.destination[key] for key in ('endpoint', 'namespace'))
                    or hashlib.sha256(destination.ca_pem.encode()).hexdigest() != row.destination['ca_digest']):
                raise JobError('Restore the approved destination to publish its revocation')
            def checkpoint(receipt):
                ctx.check()
                db.refresh(row)
                if row.job_id != ctx.job.id or not row.revoked_at:
                    raise JobError('Revocation publication authorization changed')
                row.publication = {**(row.publication or {}), 'revocation': dict(receipt)}
                row.publish_status = 'publishing' if receipt['status'] == 'publishing' else receipt['status']
                if receipt['status'] == 'published' and receipt.get('verification_status') == 'verified' and receipt.get('signature_status') == 'verified':
                    additional.schedule(db, row, 'revocation')
                db.commit()
            ctx.stage('Publishing signed Cyber revocation', 10)
            private_destination = {**public_destination(destination), 'username': decrypt_secret(destination.username),
                                   'password': destination.password, 'ca_pem': destination.ca_pem}
            receipt = publish_revocation(db, row, private_destination, payload['revocation'], checkpoint)
            if receipt.get('verification_status') != 'verified' or receipt.get('signature_status') != 'verified':
                raise JobError('Revocation publication did not return a verified event')
            record_audit(db, None, 'cyber_release.revocation.published', 'cyber_approval', row.id,
                         release_sequence=payload['revocation']['release_sequence'])
            db.commit()
            return {'result_url': f'/approved-releases?id={row.id}', 'approval_id': row.id}
        except Exception as exc:
            db.rollback()
            row = db.get(CyberApproval, payload['approval_id'])
            diagnostic = exc.receipt.get('diagnostic') if isinstance(exc, PublicationError) else failure_diagnostic(exc, 'Revocation worker checks')
            error = str(exc) if isinstance(exc, (JobError, PublicationError)) else diagnostic['cause']
            if row and row.job_id == ctx.job.id:
                row.publish_status = 'failed'
                row.publication = {**(row.publication or {}), 'revocation': {
                    **(row.publication or {}).get('revocation', {}), 'status': 'failed',
                    'error': error, 'diagnostic': diagnostic, 'correlation_id': ctx.job.id}}
                db.commit()
            raise JobError(error) from None


def reconcile_jobs(db):
    additional.reconcile(db)
    for row in db.scalars(select(CyberApproval).where(CyberApproval.publish_status.in_(('queued', 'publishing')),
            ~imported_service_predicate(CyberApproval.service_id))):
        job = db.get(DurableJob, row.job_id) if row.job_id else None
        if not job or job.status in ('failed', 'cancelled', 'completed'):
            row.publish_status = 'failed'
            receipt = dict(row.publication or {})
            failure = {'status': 'failed', 'error': 'Publication worker stopped. Review the retained receipts and retry this exact release.'}
            if row.revoked_at and receipt.get('revocation'):
                receipt['revocation'] = {**receipt['revocation'], **failure}
            else:
                receipt.update(failure)
            row.publication = receipt
    db.commit()


@router.get('/api/approved-releases/{identity}/revision')
def release_revision(identity: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    from .release_revisions import ReleaseRevision, ReleaseRevisionState, ServiceActiveRelease
    approval = _record(db, auth, identity)
    revision = db.scalar(select(ReleaseRevision).where(ReleaseRevision.approval_id == approval.id))
    if revision is None:
        raise HTTPException(404, 'Release revision not found')
    state = db.get(ReleaseRevisionState, revision.id)
    pointer = db.get(ServiceActiveRelease, revision.service_id)
    return dict(id=revision.id, approval_id=approval.id, manifest=revision.manifest,
        manifest_digest=revision.manifest_digest, decision=state.decision, can_manage=can_review_release(auth, approval),
        suspended=state.suspended, revoked=state.revoked, version=state.version,
        active_revision_id=pointer.revision_id if pointer else None,
        pointer_version=pointer.version if pointer else None,
        validity=release_validity.summary(approval))


@router.post('/api/approved-releases/{identity}/revision/{action}')
async def release_revision_action(identity: int, action: str, request: Request,
        db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    from . import release_revisions
    _csrf(request, auth)
    approval = _record(db, auth, identity)
    _require_reviewer(auth, approval)
    data = await request.json()
    version = data.get('expected_version')
    if type(version) is not int or version < 0:
        raise HTTPException(422, 'An expected version is required')
    revision = db.scalar(select(release_revisions.ReleaseRevision).where(
        release_revisions.ReleaseRevision.approval_id == approval.id))
    if revision is None:
        raise HTTPException(404, 'Release revision not found')
    try:
        if action == 'activate':
            release_revisions.activate(db, auth, revision.id, version)
        elif action in {'suspend', 'revoke'}:
            release_revisions.restrict(db, auth, revision.id, version, action, data.get('reason', ''))
        else:
            raise HTTPException(422, 'Unknown revision action')
    except (ValueError, PermissionError) as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from None
    record_audit(db, auth, 'release_revision.' + action, 'release_revision', revision.id)
    db.commit()
    return release_revision(identity, db, auth)
