"""Local, append-only mission-continuity authority, separate from imported evidence.

Grants are authenticated using the existing encrypted-configuration key. A grant
never broadens the immutable release inventory. No authorization result is cached.
"""
from datetime import datetime, timezone
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, event, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .auth import AuthContext, record_audit, require_user
from .database import Base, get_db
from .models import AuditEvent, Service
from .replica_models import ReplicaRelease, ReplicaServiceState
from .release_validity import utc
from .secrets import decrypt_secret, encrypt_secret
from .service_oci import _csrf


def now():
    return datetime.now(timezone.utc)


class LocalCyberOverride(Base):
    __tablename__ = 'local_cyber_overrides'
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    release_id: Mapped[int] = mapped_column(ForeignKey('replica_releases.id'), index=True)
    manifest_digest: Mapped[str] = mapped_column(String(80))
    digests: Mapped[list] = mapped_column(JSON)
    denial_condition: Mapped[str] = mapped_column(String(40))
    mission_impact: Mapped[str] = mapped_column(Text)
    justification: Mapped[str] = mapped_column(Text)
    risk_acceptance: Mapped[str] = mapped_column(Text)
    elevated_risk_acknowledged: Mapped[bool] = mapped_column(default=False)
    created_by_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    created_by_username: Mapped[str] = mapped_column(String(200))
    created_by_display_name: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authenticated_record: Mapped[str] = mapped_column(Text)


class LocalCyberOverrideRevocation(Base):
    __tablename__ = 'local_cyber_override_revocations'
    override_id: Mapped[int] = mapped_column(ForeignKey('local_cyber_overrides.id'), primary_key=True)
    revoked_by_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    reason: Mapped[str] = mapped_column(Text)


def _immutable(*args):
    raise ValueError('Local Cyber authorization history is immutable; revoke the grant instead')


for _model in (LocalCyberOverride, LocalCyberOverrideRevocation):
    event.listen(_model, 'before_update', _immutable)
    event.listen(_model, 'before_delete', _immutable)


GRANT_FIELDS = ('id', 'service_id', 'release_id', 'manifest_digest', 'digests', 'denial_condition',
    'mission_impact', 'justification', 'risk_acceptance', 'elevated_risk_acknowledged',
    'created_by_id', 'created_by_username', 'created_by_display_name', 'created_at', 'expires_at', 'review_at')
DENIAL_CONDITIONS = frozenset({'expired', 'superseded', 'revoked'})


def _payload(row):
    values = {key: getattr(row, key) for key in GRANT_FIELDS}
    for key in ('created_at', 'expires_at', 'review_at'):
        values[key] = utc(values[key]).isoformat() if values[key] else None
    return json.dumps(values, sort_keys=True, separators=(',', ':'), allow_nan=False)


def authentic(row):
    try:
        return decrypt_secret(row.authenticated_record) == _payload(row)
    except (ValueError, TypeError):
        return False


def _permission(auth, service_id, action):
    if not auth.has('service.view', service_id) or not auth.has(action, service_id):
        raise PermissionError('Local Cyber permission denied')


def _imported_only(db, service_id):
    from .imported_services import uses_imported_evidence
    if not uses_imported_evidence(db, service_id):
        raise ValueError('Local Cyber overrides are available only for imported services')


def _text(data, key):
    value = data.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > 20000:
        raise ValueError(f'{key} is required and must be at most 20000 characters')
    return value.strip()


def _date(value, name, timestamp):
    if value is None:
        return None
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None or utc(result) <= timestamp:
            raise ValueError()
        return utc(result)
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f'{name} must be a future timestamp including timezone') from None


def create_override(db, auth, service_id, data, timestamp=None):
    _imported_only(db, service_id)
    _permission(auth, service_id, 'local_override.create')
    from .replica_authorization import trusted_release, override_release_denial
    timestamp = utc(timestamp or now())
    if not isinstance(data, dict) or type(data.get('release_id')) is not int:
        raise ValueError('A specific release_id is required')
    release = db.get(ReplicaRelease, data['release_id'], populate_existing=True)
    state = db.get(ReplicaServiceState, service_id, populate_existing=True)
    if release is None or release.service_id != service_id or not trusted_release(db, release, state, timestamp):
        raise ValueError('Override requires a locally verified, complete release from a trusted publisher')
    inventory = {item['digest'] for item in release.artifacts}
    selected = data.get('digest')
    if selected is not None and (not isinstance(selected, str) or selected not in inventory):
        raise ValueError('digest must identify an exact artifact in the selected release')
    selected_digests = sorted(inventory if selected is None else {selected})
    denial = override_release_denial(db, release, state, selected_digests, timestamp)
    if denial not in DENIAL_CONDITIONS or data.get('denial_condition') != denial:
        raise ValueError('denial_condition must match the current release denial')
    elevated = data.get('elevated_risk_acknowledged', False)
    if type(elevated) is not bool or (denial == 'revoked' and not elevated):
        raise ValueError('Revoked releases require explicit elevated-risk acknowledgement')
    row = LocalCyberOverride(service_id=service_id, release_id=release.id,
        manifest_digest=release.manifest_digest, digests=selected_digests,
        denial_condition=denial, mission_impact=_text(data, 'mission_impact'),
        justification=_text(data, 'justification'), risk_acceptance=_text(data, 'risk_acceptance'),
        elevated_risk_acknowledged=elevated, created_by_id=auth.user.id,
        created_by_username=auth.user.username, created_by_display_name=auth.user.display_name or '',
        created_at=timestamp, expires_at=_date(data.get('expires_at'), 'expires_at', timestamp),
        review_at=_date(data.get('review_at'), 'review_at', timestamp), authenticated_record='pending')
    # Allocate identity before sealing, without issuing an ORM UPDATE on the
    # append-only grant. The nested transaction ensures failed sealing is atomic.
    with db.begin_nested():
        db.add(row)
        db.flush()
        from sqlalchemy import update
        sealed = encrypt_secret(_payload(row))
        db.execute(update(LocalCyberOverride).where(LocalCyberOverride.id == row.id)
            .values(authenticated_record=sealed).execution_options(synchronize_session=False))
        db.expire(row)
        record_audit(db, auth, 'local_override.created', 'local_cyber_override', row.id,
            service_id=service_id, release_id=release.id, manifest_digest=release.manifest_digest,
            digests=row.digests, denial_condition=denial, indefinite=row.expires_at is None)
    return row


def revoke_override(db, auth, service_id, identity, reason, timestamp=None):
    _imported_only(db, service_id)
    _permission(auth, service_id, 'local_override.revoke')
    # Serialize revocation with final pull auditing. Once this commits, every
    # subsequent authorization reads the revocation; no decision cache exists.
    row = db.scalar(select(LocalCyberOverride).where(LocalCyberOverride.id == identity,
        LocalCyberOverride.service_id == service_id).with_for_update().execution_options(populate_existing=True))
    if row is None:
        raise ValueError('Local Cyber override not found')
    if db.get(LocalCyberOverrideRevocation, row.id, populate_existing=True) is not None:
        raise ValueError('Local Cyber override is already revoked')
    revocation = LocalCyberOverrideRevocation(override_id=row.id, revoked_by_id=auth.user.id,
        revoked_at=utc(timestamp or now()), reason=_text({'reason': reason}, 'reason'))
    db.add(revocation)
    record_audit(db, auth, 'local_override.revoked', 'local_cyber_override', row.id,
        service_id=service_id, release_id=row.release_id, reason=revocation.reason)
    return row


def applicable_override(db, release, digest, denial, timestamp):
    """Trust and artifact membership must be checked by the caller first."""
    if denial not in DENIAL_CONDITIONS:
        return None
    query = select(LocalCyberOverride).where(LocalCyberOverride.service_id == release.service_id,
        LocalCyberOverride.release_id == release.id, LocalCyberOverride.manifest_digest == release.manifest_digest,
        ~select(LocalCyberOverrideRevocation.override_id).where(
            LocalCyberOverrideRevocation.override_id == LocalCyberOverride.id).exists())
    for row in db.scalars(query.order_by(LocalCyberOverride.id).execution_options(populate_existing=True)):
        if (authentic(row) and utc(row.created_at) <= timestamp
                and (row.expires_at is None or timestamp < utc(row.expires_at))
                and digest in row.digests
                and (denial != 'revoked' or row.elevated_risk_acknowledged)):
            return row
    return None


def lock_for_use(db, identity, timestamp=None):
    row = db.scalar(select(LocalCyberOverride).where(LocalCyberOverride.id == identity)
        .with_for_update().execution_options(populate_existing=True))
    timestamp = utc(timestamp or now())
    if (row is None or not authentic(row) or utc(row.created_at) > timestamp
            or (row.expires_at is not None and utc(row.expires_at) <= timestamp)
            or db.get(LocalCyberOverrideRevocation, identity, populate_existing=True) is not None):
        raise ValueError('Local Cyber override expired, revoked, or failed integrity verification')
    return row


def public(db, row):
    result = json.loads(_payload(row))
    revocation = db.get(LocalCyberOverrideRevocation, row.id, populate_existing=True)
    result['status'] = ('revoked' if revocation else 'invalid' if not authentic(row)
        else 'expired' if row.expires_at and utc(row.expires_at) <= now() else 'active')
    result['revocation'] = ({'reason': revocation.reason, 'revoked_at': utc(revocation.revoked_at).isoformat(),
        'revoked_by_id': revocation.revoked_by_id} if revocation else None)
    last = db.scalar(select(AuditEvent.created_at).where(AuditEvent.action == 'local_override.used',
        AuditEvent.target_type == 'local_cyber_override', AuditEvent.target_id == str(row.id))
        .order_by(AuditEvent.created_at.desc()).limit(1))
    result['last_usage_at'] = utc(last).isoformat() if last else None
    return result


router = APIRouter(prefix='/api/services/{service_key}/local-overrides', tags=['Local Cyber overrides'])


def _service(db, auth, service_key, permission='service.view'):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404, 'Service not found')
    try:
        _permission(auth, service.id, permission)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from None
    return service


@router.get('')
def list_overrides(service_key: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    service = _service(db, auth, service_key)
    rows = db.scalars(select(LocalCyberOverride).where(LocalCyberOverride.service_id == service.id)
        .order_by(LocalCyberOverride.id.desc())).all()
    return {'overrides': [public(db, row) for row in rows]}


@router.post('')
async def create(service_key: str, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    service = _service(db, auth, service_key, 'local_override.create')
    try:
        row = create_override(db, auth, service.id, await request.json())
        db.commit()
        return public(db, row)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from None


@router.post('/{override_id}/revoke')
async def revoke(service_key: str, override_id: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    service = _service(db, auth, service_key, 'local_override.revoke')
    try:
        data = await request.json()
        if not isinstance(data, dict):
            raise ValueError('A revocation reason is required')
        row = revoke_override(db, auth, service.id, override_id, data.get('reason'))
        db.commit()
        return public(db, row)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from None


@router.get('/{override_id}/uses')
def uses(service_key: str, override_id: int, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    service = _service(db, auth, service_key, 'local_override.view_audit')
    row = db.get(LocalCyberOverride, override_id)
    if row is None or row.service_id != service.id:
        raise HTTPException(404, 'Local Cyber override not found')
    events = db.scalars(select(AuditEvent).where(AuditEvent.action == 'local_override.used',
        AuditEvent.target_type == 'local_cyber_override', AuditEvent.target_id == str(row.id))
        .order_by(AuditEvent.id.desc())).all()
    return {'uses': [dict(id=item.id, created_at=utc(item.created_at).isoformat(), **item.detail) for item in events]}
