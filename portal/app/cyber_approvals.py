"""Cyber decisions on immutable service evidence and durable approved releases."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column
from .database import Base, get_db
from .models import Service, Group, User, PortalSetting, RemediationExecution, utcnow
from .auth import AuthContext, require_user, record_audit
from .durable_jobs import DurableJob, submit, JobError
from .service_oci import validate_destination, _csrf
from .secrets import encrypt_secret, decrypt_secret
from . import signing, release_validity

router = APIRouter()


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
    if not row or not auth.has('service.view', row.service_id):
        raise HTTPException(404, 'Approval not found')
    return row


def public_destination(row):
    return {key: getattr(row, key) for key in ('id', 'name', 'endpoint', 'namespace', 'group_ids', 'is_default', 'enabled', 'pull_instructions')} | {
        'credentials_configured': bool(row.password), 'ca_configured': bool(row.ca_pem)}


def _eligible(destination, service):
    return destination.enabled and (not destination.group_ids or bool(set(destination.group_ids) & {group.id for group in service.groups}))


def _settings(db):
    return {row.key: row.value for row in db.scalars(select(PortalSetting))}


def _signing_ready(db):
    try:
        config = signing.configuration(_settings(db))
        return bool(config.get('enabled') and config.get('private_key') and config.get('public_key') and config.get('fingerprint'))
    except ValueError:
        return False


def _readiness(db, service, variant, remediation_id):
    from .cyber_approval_evidence import readiness
    result = readiness(db, service, variant, remediation_id)
    destinations = [public_destination(row) for row in db.scalars(select(ApprovedReleaseDestination)) if _eligible(row, service)]
    notes = list(result.get('review_notes', []))
    if not destinations:
        notes.append('An administrator must configure an approved-release OCI destination before Cyber approves publication.')
    if not _signing_ready(db):
        notes.append('An administrator must enable the CATS signing key before Cyber approves publication.')
    return {**result, 'review_notes': notes, 'destinations': destinations}



@router.get('/api/services/{key}/cyber-approval-readiness')
def readiness_api(key: str, variant: str = 'current_service', remediation_id: int | None = None,
                  db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    service = _service(db, auth, key)
    result = _readiness(db, service, variant, remediation_id)
    execution = result.get('execution')
    return {key: value for key, value in result.items() if key in ('ready', 'blockers', 'destinations', 'version', 'scan_date', 'variant', 'review_notes')} | {
        'executions': [{'id': execution.id, 'scanned_at': execution.scanned_at.isoformat()}] if execution else [],
        'remediations': [{'id': row.id, 'label': row.job_key} for row in db.scalars(select(RemediationExecution).where(
            RemediationExecution.service_id == service.id,
            RemediationExecution.source_execution_id == execution.id if execution else False,
            RemediationExecution.source_version_id == service.current_version_id).order_by(RemediationExecution.id.desc()))],
        'can_request': auth.has('approval.request', service.id) and auth.has('service.export', service.id)}


def _public(value):
    # Files remain private implementation details. All downloads recheck scope.
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key not in ('path', 'bundle_path', 'artifact_path', 'archive_path', 'candidate_path', 'directory', 'root', 'password', 'username', 'ca_pem', 'private_key')}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def dto(db, row, auth, detail=False):
    service = db.get(Service, row.service_id)
    requested_by = db.get(User, row.requested_by_id) if row.requested_by_id else None
    result = {key: getattr(row, key) for key in ('id', 'release_key', 'variant', 'status', 'publish_status', 'rationale', 'decision_rationale', 'snapshot_digest', 'revocation_reason')}
    result.update(service_key=service.service_key, service_name=service.name, version=row.snapshot.get('version'),
        scan_date=row.snapshot.get('scan_date'), label='CATS Remediated' if row.variant == 'cats_remediated' else 'Current Service',
        requested_at=row.requested_at.isoformat(), decided_at=row.decided_at.isoformat() if row.decided_at else None,
        requested_by=requested_by.display_name if requested_by else 'Retained account', destination=row.destination,
        publication=_public(row.publication), can_decide=row.status == 'pending' and auth.has('approval.decide', row.service_id),
        can_retry=row.status == 'approved' and row.publish_status == 'failed' and not row.revoked_at and auth.has('approval.decide', row.service_id),
        revoked=bool(row.revoked_at), release_id=row.id)
    result.update(release_validity.summary(row))
    result['can_retry'] = result['can_retry'] and result['validity_status'] in ('valid', 'expiring_soon')
    if detail:
        result['snapshot'] = _public(row.snapshot)
        if row.status == 'pending' and not row.destination_id:
            result['destinations'] = [public_destination(item) for item in db.scalars(select(ApprovedReleaseDestination).order_by(
                ApprovedReleaseDestination.is_default.desc(), ApprovedReleaseDestination.id)) if _eligible(item, service)]
        if auth.has('service.export', row.service_id):
            result['evidence_url'] = f'/api/cyber-approvals/{row.id}/download/evidence'
            if row.publish_status == 'published':
                result['offline_bundle_url'] = f'/api/cyber-approvals/{row.id}/download/offline'
    return result


@router.post('/api/cyber-approvals')
async def request_approval(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    data = await request.json()
    service = _service(db, auth, str(data.get('service_key', '')))
    _permission(auth, 'approval.request', service.id)
    _permission(auth, 'service.export', service.id)
    if service.lifecycle_status != 'active':
        raise HTTPException(409, 'Only active services can request approval')
    variant = data.get('variant', 'current_service')
    if variant not in ('current_service', 'cats_remediated'):
        raise HTTPException(422, 'Select Current Service or CATS Remediated')
    result = _readiness(db, service, variant, data.get('remediation_id'))
    if not result['ready']:
        raise HTTPException(409, {'message': 'Resolve all missing evidence before requesting approval', 'blockers': result['blockers']})
    eligible = [row for row in db.scalars(select(ApprovedReleaseDestination).order_by(
        ApprovedReleaseDestination.is_default.desc(), ApprovedReleaseDestination.id)) if _eligible(row, service)]
    destination = eligible[0] if eligible else None
    if data.get('destination_id') is not None:
        destination = next((row for row in eligible if str(row.id) == str(data['destination_id'])), None)
        if destination is None:
            raise HTTPException(422, 'Select an available approved-release destination')
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
    snapshot['review_notes'] = list(dict.fromkeys(snapshot.get('review_notes', []) + result.get('review_notes', [])))
    row = CyberApproval(release_key=release_key, service_id=service.id, source_execution_id=result['execution'].id,
        remediation_id=result['remediation'].id if result.get('remediation') else None, requested_by_id=auth.user.id,
        destination_id=destination.id if destination else None, variant=variant, snapshot=snapshot, snapshot_digest=digest(snapshot),
        destination=frozen_destination, rationale=str(data.get('rationale') or '')[:10000])
    db.add(row)
    db.flush()
    record_audit(db, auth, 'cyber_approval.request', 'cyber_approval', row.id, snapshot_digest=row.snapshot_digest)
    db.commit()
    return dto(db, row, auth, True)


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
    return {'items': [dto(db, row, auth) for row in rows], 'total': len(rows)}


@router.get('/api/cyber-approvals')
def approvals(service: str | None = None, status: str | None = None, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    return _list(db, auth, service, status)


@router.get('/api/cyber-approvals/{identity}')
def approval(identity: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    return dto(db, _record(db, auth, identity), auth, True)


def _enqueue(db, row, actor):
    job = submit(db, kind='cyber_release_publish', payload={'approval_id': row.id}, service_id=row.service_id,
        requested_by_id=actor, source_execution_id=row.source_execution_id, version=str(row.snapshot.get('version', '')),
        dedupe_key=f'cyber:{row.id}:{uuid.uuid4().hex}', max_attempts=1, commit=False)
    row.job_id, row.publish_status = job.id, 'queued'


@router.post('/api/cyber-approvals/{identity}/decision')
async def decide(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    row = _record(db, auth, identity)
    _permission(auth, 'approval.decide', row.service_id)
    data = await request.json()
    decision, rationale = data.get('decision'), str(data.get('rationale') or '').strip()
    if decision not in ('approved', 'denied') or not 3 <= len(rationale) <= 10000:
        raise HTTPException(422, 'Choose approve or deny and provide a rationale (3–10000 characters)')
    if not hmac.compare_digest(row.snapshot_digest, digest(row.snapshot)):
        raise HTTPException(409, 'Snapshot integrity check failed')
    bound = {}
    decided_at = utcnow()
    if decision == 'approved' and row.status == 'pending':
        snapshot = dict(row.snapshot)
        try:
            snapshot['approval_validity'] = release_validity.for_service(db, db.get(Service, row.service_id), decided_at)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        if not row.destination_id:
            destination = db.get(ApprovedReleaseDestination, data.get('destination_id')) if data.get('destination_id') else None
            if not destination or not _eligible(destination, db.get(Service, row.service_id)):
                raise HTTPException(409, 'Configure and select an approved-release OCI destination before approving publication')
            frozen = public_destination(destination)
            frozen['ca_digest'] = hashlib.sha256(destination.ca_pem.encode()).hexdigest()
            snapshot['destination'] = frozen
            bound.update(destination_id=destination.id, destination=frozen)
        if not snapshot.get('signing_fingerprint'):
            if not _signing_ready(db):
                raise HTTPException(409, 'An administrator must enable signing before approving publication')
            snapshot['signing_fingerprint'] = signing.configuration(_settings(db))['fingerprint']
        bound.update(snapshot=snapshot, snapshot_digest=digest(snapshot))
    changed = db.execute(update(CyberApproval).where(CyberApproval.id == row.id, CyberApproval.status == 'pending').values(
        status=decision, decision_rationale=rationale, decided_by_id=auth.user.id, decided_at=decided_at, **bound)).rowcount
    if changed != 1:
        db.rollback()
        raise HTTPException(409, 'This request already has a decision')
    db.refresh(row)
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
    _permission(auth, 'approval.decide', row.service_id)
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


@router.post('/api/approved-releases/{identity}/revoke')
async def revoke(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    row = _record(db, auth, identity)
    _permission(auth, 'approval.decide', row.service_id)
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
    record_audit(db, auth, 'cyber_release.revoke', 'cyber_approval', row.id)
    db.commit()
    return dto(db, row, auth, True)


@router.get('/api/cyber-approvals/{identity}/download/{kind}')
def download(identity: int, kind: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    row = _record(db, auth, identity)
    _permission(auth, 'service.export', row.service_id)
    entry = row.snapshot.get('evidence', {}) if kind == 'evidence' else {}
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
    with delivery_lock(root() / '.locks', int(payload['approval_id'])) as owned:
        if not owned:
            raise JobError('Another publisher still owns this release. Retry after it finishes.')
        with ctx.session_factory() as db:
            row = db.get(CyberApproval, payload['approval_id'])
            if not row or row.status != 'approved' or row.revoked_at or row.job_id != ctx.job.id:
                raise JobError('Approved request is unavailable or has been revoked')
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


def reconcile_jobs(db):
    for row in db.scalars(select(CyberApproval).where(CyberApproval.publish_status.in_(('queued', 'publishing')))):
        job = db.get(DurableJob, row.job_id) if row.job_id else None
        if not job or job.status in ('failed', 'cancelled', 'completed'):
            row.publish_status = 'failed'
            row.publication = {**(row.publication or {}), 'status': 'failed', 'error': 'Publication worker stopped. Review the retained receipts and retry this exact release.'}
    db.commit()
