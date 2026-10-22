"""Durable digest-pinned reassessment; only Cyber can grant renewal."""
import asyncio
import json
import re
import secrets
from types import SimpleNamespace
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column, Session
from .database import Base, get_db
from .models import User, Service
from .auth import AuthContext, require_user
from .durable_jobs import DurableJob, JobError, aware, now, submit
from . import cyber_approvals as approvals, signing
from .service_oci import _csrf
router = APIRouter()
KIND = 'oci_reassessment'

class OCIReassessmentSchedule(Base):
    __tablename__ = 'oci_reassessment_schedules'
    approval_id: Mapped[int] = mapped_column(ForeignKey('cyber_approvals.id'), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    interval_days: Mapped[int] = mapped_column(Integer)
    next_run: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

class OCIReassessmentEvent(Base):
    __tablename__ = 'oci_reassessment_events'
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    approval_id: Mapped[int] = mapped_column(ForeignKey('cyber_approvals.id'), index=True)
    scan_id: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default='queued')
    renewal_id: Mapped[int | None] = mapped_column(ForeignKey('cyber_approvals.id'))
    detail: Mapped[str] = mapped_column(Text, default='')

class ApprovalPublicKey(Base):
    __tablename__ = 'approval_public_keys'
    fingerprint: Mapped[str] = mapped_column(String(80), primary_key=True)
    public_key: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[object] = mapped_column(DateTime(timezone=True), default=now)

def retain_public_key(db, config):
    if not config.get('public_key'):
        return
    pem, fingerprint = signing.public_key(config['public_key'].encode())
    if fingerprint != config.get('fingerprint'):
        raise ValueError('Signing key fingerprint mismatch')
    if not db.get(ApprovalPublicKey, fingerprint):
        db.add(ApprovalPublicKey(fingerprint=fingerprint, public_key=pem))
        db.flush()

def public_keys(db):
    config = signing.configuration(approvals._settings(db))
    items = {r.fingerprint: {'fingerprint': r.fingerprint, 'public_key': r.public_key}
             for r in db.scalars(select(ApprovalPublicKey))}
    if config.get('public_key'):
        pem, fp = signing.public_key(config['public_key'].encode())
        if fp == config.get('fingerprint'):
            items[fp] = {'fingerprint': fp, 'public_key': pem}
    return {'keys': [{**item, 'current': key == config.get('fingerprint')} for key, item in sorted(items.items())]}

@router.get('/api/oci/approval-keys')
def key_discovery(db: Session = Depends(get_db)):
    return public_keys(db)

def scan_references(row):
    if hasattr(row, 'snapshot_digest') and row.snapshot_digest != approvals.digest(row.snapshot):
        raise HTTPException(409, 'Approval evidence integrity check failed')
    items = row.snapshot.get('artifacts') or []
    if not items or any(i.get('kind') != 'image' or i.get('archive_path') or i.get('format') == 'docker-archive' for i in items):
        raise HTTPException(409, 'Scheduled reassessment requires registry-backed images only; charts and archives need a full assessment')
    refs = sorted({str(i.get('reference', '')) for i in items})
    if any(not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', ref) for ref in refs):
        raise HTTPException(409, 'Scheduled reassessment requires immutable image digests')
    return refs

@router.put('/api/cyber-approvals/{identity}/reassessment')
async def schedule(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    row = approvals._record(db, auth, identity)
    for permission in ('approval.request', 'service.export', 'scan.ingest', 'service.edit'):
        approvals._permission(auth, permission, row.service_id)
    data = await request.json()
    days = data.get('interval_days', 7)
    if type(days) is not int or not 1 <= days <= 365:
        raise HTTPException(422, 'Interval must be 1 to 365 days')
    if row.status != 'approved' or row.revoked_at:
        raise HTTPException(409, 'Only non-revoked approved releases can be reassessed')
    scan_references(row)
    item = db.get(OCIReassessmentSchedule, row.id)
    if item is None:
        item = OCIReassessmentSchedule(approval_id=row.id, next_run=now())
        db.add(item)
    item.actor_id, item.interval_days = auth.user.id, days
    item.enabled = data.get('enabled', True) is True
    approvals.record_audit(db, auth, 'cyber_approval.reassessment_schedule', 'cyber_approval', row.id, interval_days=days, enabled=item.enabled)
    db.commit()
    return {'approval_id': row.id, 'next_run': item.next_run.isoformat(), 'enabled': item.enabled}

@router.get('/api/cyber-approvals/{identity}/reassessment')
def events(identity: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    approvals._record(db, auth, identity)
    item = db.get(OCIReassessmentSchedule, identity)
    return {'schedule': {'interval_days': item.interval_days, 'enabled': item.enabled, 'next_run': item.next_run.isoformat()} if item else None,
            'events': [{'id': r.id, 'state': r.state, 'scan_id': r.scan_id, 'renewal_id': r.renewal_id, 'detail': r.detail}
            for r in db.scalars(select(OCIReassessmentEvent).where(OCIReassessmentEvent.approval_id == identity).limit(100))]}

def enqueue_due(db, clock=None):
    clock = clock or now()
    schedules = db.scalars(select(OCIReassessmentSchedule).where(OCIReassessmentSchedule.enabled.is_(True),
        OCIReassessmentSchedule.next_run <= clock).with_for_update(skip_locked=True).limit(100)).all()
    for item in schedules:
        row = db.get(approvals.CyberApproval, item.approval_id)
        if not row or row.revoked_at or row.status != 'approved':
            item.enabled = False
            continue
        job = submit(db, kind=KIND, payload={'approval_id': row.id}, service_id=row.service_id,
            requested_by_id=item.actor_id, source_execution_id=row.source_execution_id,
            dedupe_key=f'oci-reassess:{row.id}:{aware(item.next_run).isoformat()}', max_attempts=1, commit=False)
        if not db.get(OCIReassessmentEvent, job.id):
            db.add(OCIReassessmentEvent(id=job.id, approval_id=row.id))
        item.next_run = clock + timedelta(days=item.interval_days)
    db.commit()

def _actor(db, job):
    user = db.get(User, job.requested_by_id)
    auth = AuthContext(user=user, session=SimpleNamespace(csrf_token=secrets.token_urlsafe(32))) if user and user.enabled else None
    service = db.get(Service, job.service_id)
    if not auth or not service or service.lifecycle_status != 'active' or any(not auth.has(p, service.id)
        for p in ('service.view', 'service.edit', 'scan.ingest', 'approval.request', 'service.export')):
        raise JobError('Reassessment owner no longer has access; configure an authorized schedule')
    return auth, service

def handle(ctx, payload):
    from . import main
    ctx.check()
    with main.SessionLocal() as db:
        event = db.get(OCIReassessmentEvent, ctx.job.id)
        row = db.get(approvals.CyberApproval, payload['approval_id'])
        if not event or not row or row.revoked_at or row.status != 'approved':
            raise JobError('Release is no longer eligible for reassessment')
        auth, service = _actor(db, ctx.job)
        if event.scan_id:
            return {'scan_id': event.scan_id}
        refs = scan_references(row)
        # One attempt: never blindly duplicate a submission interrupted by a crash.
        ctx.check()
        event.scan_id = main._start_public_scan('\n'.join(refs), ingest_service_id=service.service_key,
            owner_user_id=auth.user.id, ingest_scope='service', ingest_service_version=str(row.snapshot.get('version') or ''))
        event.state = 'scanning'
        db.commit()
        return {'scan_id': event.scan_id}

def _request(data, auth):
    async def receive():
        return {'type': 'http.request', 'body': json.dumps(data).encode()}
    return Request({'type': 'http', 'method': 'POST', 'headers': [(b'x-csrf-token', auth.csrf_token.encode())]}, receive)

def reconcile(db):
    from . import main
    for event in db.scalars(select(OCIReassessmentEvent).where(OCIReassessmentEvent.state.in_(('queued', 'scanning')))
                           .with_for_update(skip_locked=True).limit(100)):
        job = db.get(DurableJob, event.id)
        if not job:
            event.state, event.detail = 'failed', 'Dispatcher missing'
            continue
        if not event.scan_id:
            if job.status in ('failed', 'cancelled'):
                event.state, event.detail = 'failed', 'Scan submission interrupted; approval unchanged'
            continue
        scan = main.PUBLIC_JOBS.get(event.scan_id, {})
        if scan.get('status') in ('failed', 'error', 'incomplete', 'cancelled'):
            event.state, event.detail = 'failed', 'Reassessment failed; approval unchanged'
        elif scan.get('status') == 'complete':
            try:
                auth, service = _actor(db, job)
                original = db.get(approvals.CyberApproval, event.approval_id)
                if original.revoked_at or original.status != 'approved':
                    raise JobError('Release is no longer eligible for renewal')
                ingested = main.ingest_public_scan(event.scan_id, service.service_key, _request({}, auth), scan_scope='service', db=db, auth=auth)
                result = asyncio.run(approvals.request_approval(_request({'service_key': service.service_key,
                    'variant': 'current_service', 'renews_approval_id': original.id, 'reassessment_event_id': event.id,
                    'expected_source_execution_id': ingested['execution_id'],
                    'rationale': 'Scheduled digest-pinned reassessment; requires a fresh Cyber decision'}, auth), db, auth))
                event.renewal_id, event.state = result['id'], 'pending_review'
            except (HTTPException, JobError, ValueError):
                event.state, event.detail = 'review_required', 'Renewal readiness requires review; approval unchanged'
    db.commit()

def maintenance(db):
    retain_public_key(db, signing.configuration(approvals._settings(db)))
    enqueue_due(db)
    reconcile(db)
