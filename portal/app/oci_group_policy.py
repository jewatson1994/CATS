"""Local owning-group rules for OCI pulls, separate from publisher evidence."""
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import AuthContext, record_audit, require_user
from .database import get_db
from .models import Group, PortalSetting, Service, ServiceGroup, utcnow
from .service_oci import _csrf

SETTING = 'oci_pull_policy'
DEFAULT_POLICY = {
    'mode': 'approved_release',
    'blocked_severity': 'Critical',
    'require_service_compliant': False,
    'max_scan_age_days': None,
}
MODES = frozenset({'approved_release', 'compliance', 'both'})
SEVERITIES = frozenset({'Critical', 'High', 'Medium', 'Low', 'None'})
router = APIRouter(tags=['OCI group policy'])


def validate_policy(value):
    """Require a complete, typed policy; malformed stored rules never default open."""
    if not isinstance(value, dict) or set(value) != set(DEFAULT_POLICY):
        raise ValueError('Provide exactly mode, blocked_severity, require_service_compliant and max_scan_age_days')
    if not isinstance(value['mode'], str) or value['mode'] not in MODES:
        raise ValueError('Choose approved_release, compliance or both')
    if not isinstance(value['blocked_severity'], str) or value['blocked_severity'] not in SEVERITIES:
        raise ValueError('Choose Critical, High, Medium, Low or None for blocked severity')
    if type(value['require_service_compliant']) is not bool:
        raise ValueError('require_service_compliant must be a boolean')
    age = value['max_scan_age_days']
    if age is not None and (type(age) is not int or not 1 <= age <= 3650):
        raise ValueError('Maximum scan age must be null or a whole number from 1 to 3650 days')
    if (value['mode'] != 'approved_release' and value['blocked_severity'] == 'None'
            and not value['require_service_compliant']):
        raise ValueError('Compliance modes require a blocked severity or service compliance')
    return {key: value[key] for key in DEFAULT_POLICY}


def _key(group_id):
    return f'group:{group_id}:{SETTING}'


def _setting(db, group_id):
    row = db.scalar(select(PortalSetting).where(PortalSetting.key == _key(group_id))
        .execution_options(populate_existing=True))
    if row is not None and row.group_id != group_id:
        raise ValueError('OCI pull policy has an invalid owning group')
    return row


def _read(row):
    if row is None:
        return dict(DEFAULT_POLICY)
    try:
        return validate_policy(json.loads(row.value))
    except (ValueError, TypeError) as exc:
        raise ValueError('The group OCI pull policy is invalid; an administrator must repair it') from exc


def policy_for_service(db, service_id):
    """Resolve current local ownership and rules on every request, including imports.

    Group hierarchy and publisher-frozen configuration do not grant authority
    over this local setting. Services without an owner retain approval-only
    behavior; conflicting legacy ownership fails closed.
    """
    if type(service_id) is not int or db.get(Service, service_id, populate_existing=True) is None:
        raise ValueError('Service is unavailable for OCI pull policy')
    groups = list(db.scalars(select(ServiceGroup.group_id).where(ServiceGroup.service_id == service_id)))
    if len(groups) > 1:
        raise ValueError('Service has conflicting owning groups for OCI pull policy')
    group_id = groups[0] if groups else None
    if group_id is not None and db.get(Group, group_id, populate_existing=True) is None:
        raise ValueError('Service owning group is unavailable for OCI pull policy')
    policy = _read(_setting(db, group_id)) if group_id is not None else dict(DEFAULT_POLICY)
    return {**policy, 'group_id': group_id}


def _authorized_group(db, auth, group_id):
    if not auth.can_manage_group(group_id):
        raise HTTPException(403, 'You cannot administer this group scope')
    if db.get(Group, group_id, populate_existing=True) is None:
        raise HTTPException(404, 'Group not found')


@router.get('/pull-policy')
def get_policy(response: Response, group_id: int = Query(gt=0), db: Session = Depends(get_db),
               auth: AuthContext = Depends(require_user)):
    _authorized_group(db, auth, group_id)
    response.headers['Cache-Control'] = 'private, no-store'
    try:
        row = _setting(db, group_id)
        policy = _read(row)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    return {'group_id': group_id, 'policy': policy, 'is_default': row is None}


@router.put('/pull-policy')
async def save_policy(request: Request, response: Response, group_id: int = Query(gt=0),
                      db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _authorized_group(db, auth, group_id)
    _csrf(request, auth)
    try:
        policy = validate_policy(await request.json())
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from None
    try:
        row = _setting(db, group_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    try:
        previous = _read(row)
    except ValueError:
        previous = None  # A scoped administrator may repair malformed settings.
    if row is None:
        row = PortalSetting(key=_key(group_id), group_id=group_id)
        db.add(row)
    row.value = json.dumps(policy, separators=(',', ':'))
    row.updated_by_id, row.updated_at = auth.user.id, utcnow()
    record_audit(db, auth, 'oci.group_pull_policy.updated', 'group', group_id,
                 previous_policy=previous, policy=policy)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Group policy changed; reload before saving again') from None
    response.headers['Cache-Control'] = 'private, no-store'
    return {'group_id': group_id, 'policy': policy, 'is_default': False}
