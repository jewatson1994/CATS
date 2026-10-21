"""Durable access requests and strictly group-scoped Cybersecurity claims."""
import hmac

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .account_models import AccountAccessRequest, AccountRetirement
from .auth import APPLICATION_PERMISSIONS, PERMISSIONS, SYSTEM_ROLES, AuthContext, record_audit, require_user
from .database import get_db
from .models import Group, Role, User, UserRoleAssignment, utcnow

router = APIRouter()


def has_effective_access(auth: AuthContext) -> bool:
    for assignment in auth.effective_assignments:
        permissions = set(assignment.role.permissions or []) & PERMISSIONS.keys()
        if assignment.service_id is not None or assignment.group_id is not None:
            permissions -= APPLICATION_PERMISSIONS
        if permissions:
            return True
    return False


def cyber_assignments(auth: AuthContext):
    return [a for a in auth.effective_assignments
            if a.role.system and a.role.name == "Cybersecurity"]


def is_cybersecurity(auth: AuthContext) -> bool:
    return bool(cyber_assignments(auth))


def authorized_claim_groups(db: Session, auth: AuthContext) -> list[Group]:
    assignments = cyber_assignments(auth)
    if not assignments:
        return []
    query = select(Group).order_by(Group.name, Group.id)
    if not any(a.service_id is None and a.group_id is None for a in assignments):
        query = query.where(Group.id.in_({a.group_id for a in assignments
                                        if a.service_id is None and a.group_id is not None}))
    # Existing authorization uses exact groups; hierarchy is organizational only.
    return list(db.scalars(query))


def cyber_group_ids(db: Session, auth: AuthContext) -> set[int]:
    return {group.id for group in authorized_claim_groups(db, auth)}


def can_manage_accounts(auth: AuthContext) -> bool:
    return auth.has("user.manage") or is_cybersecurity(auth)


def register_pending_request(db: Session, auth: AuthContext):
    """Caller commits together with session/login changes; duplicate calls are safe."""
    if not auth.user.enabled or db.get(AccountRetirement, auth.user.id) or has_effective_access(auth):
        return None
    current = db.get(AccountAccessRequest, auth.user.id)
    if current:
        if current.status != "pending":
            current.status = "pending"
            current.created_at = utcnow()
            current.claimed_at = current.claimed_by_id = current.group_id = None
        return current
    try:
        with db.begin_nested():
            current = AccountAccessRequest(user_id=auth.user.id)
            db.add(current)
            db.flush()
    except IntegrityError:
        current = db.get(AccountAccessRequest, auth.user.id)
    return current


def list_pending_requests(db: Session, auth: AuthContext) -> list[dict]:
    if not is_cybersecurity(auth):
        return []
    rows = db.execute(select(AccountAccessRequest, User).join(User, User.id == AccountAccessRequest.user_id)
                      .where(AccountAccessRequest.status == "pending", User.enabled.is_(True))
                      .order_by(AccountAccessRequest.created_at, User.id)).all()
    return [{"user_id": user.id, "username": user.username, "display_name": user.display_name,
             "created_at": request.created_at.isoformat()}
            for request, user in rows
            if not db.get(AccountRetirement, user.id)
            and not has_effective_access(AuthContext(user, auth.session))]


def claim_access_request(db: Session, auth: AuthContext, user_id: int, group_id: int | None = None):
    # Discard cached roles/eligibility so a revoked operator cannot use an old page.
    db.expire_all()
    actor = db.get(User, auth.user.id)
    if not actor or not actor.enabled or db.get(AccountRetirement, actor.id):
        raise HTTPException(403, "Access denied")
    fresh = AuthContext(actor, auth.session)
    if not is_cybersecurity(fresh):
        raise HTTPException(403, "Cybersecurity role required")
    groups = authorized_claim_groups(db, fresh)
    if group_id is None and len(groups) == 1:
        group_id = groups[0].id
    if group_id is None:
        raise HTTPException(422, "Select an authorized group")
    if group_id not in {group.id for group in groups}:
        raise HTTPException(403, "Group outside your Cybersecurity scope")
    target = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if not target or not target.enabled or db.get(AccountRetirement, user_id):
        raise HTTPException(409, "Account is unavailable")
    if has_effective_access(AuthContext(target, auth.session)):
        raise HTTPException(409, "Account already has access")
    role = db.scalar(select(Role).where(Role.name == "Assessor", Role.system.is_(True)))
    if not role or set(role.permissions or []) != set(SYSTEM_ROLES["Assessor"]):
        raise HTTPException(409, "Default access role is unavailable or has been modified")
    changed = db.execute(update(AccountAccessRequest).where(
        AccountAccessRequest.user_id == user_id, AccountAccessRequest.status == "pending")
        .values(status="claimed", claimed_by_id=actor.id, group_id=group_id, claimed_at=utcnow()))
    if changed.rowcount != 1:
        raise HTTPException(409, "Access request has already been claimed or is no longer pending")
    db.add(UserRoleAssignment(user_id=user_id, role_id=role.id, group_id=group_id, source="local"))
    record_audit(db, fresh, "account.access_claimed", "user", user_id, group_id=group_id, role_id=role.id)
    db.flush()
    return {"user_id": user_id, "group_id": group_id, "role": role.name, "status": "claimed"}


class ClaimInput(BaseModel):
    csrf_token: str
    group_id: int | None = None


@router.get("/api/accounts/access-requests")
def pending_route(db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    if not is_cybersecurity(auth):
        raise HTTPException(403, "Cybersecurity role required")
    return {"requests": list_pending_requests(db, auth),
            "groups": [{"id": group.id, "name": group.name} for group in authorized_claim_groups(db, auth)]}


@router.post("/api/accounts/access-requests/{user_id}/claim")
def claim_route(user_id: int, payload: ClaimInput, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    if not hmac.compare_digest(payload.csrf_token, auth.csrf_token):
        raise HTTPException(403, "Invalid CSRF token")
    try:
        result = claim_access_request(db, auth, user_id, payload.group_id)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
