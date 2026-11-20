"""Durable access requests and strictly group-scoped Cybersecurity claims."""
import hmac

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .account_models import AccountAccessRequest, AccountRetirement, ServiceAccessRequest
from .auth import APPLICATION_PERMISSIONS, PERMISSIONS, SYSTEM_ROLES, AuthContext, record_audit, require_csrf, require_user
from .database import get_db
from .models import Group, Role, Service, ServiceGroup, User, UserRoleAssignment, utcnow
from .service_ownership import active_service_predicate

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


def uses_service_directory(user: User) -> bool:
    # A local account explicitly linked to a validated OIDC identity also qualifies.
    return user.auth_source == "oidc" or bool(user.external_subject)


def service_directory(db: Session, user_id: int):
    pending = select(ServiceAccessRequest.user_id).where(
        ServiceAccessRequest.service_id == Service.id, ServiceAccessRequest.user_id == user_id).exists()
    return db.execute(select(Service.id, Service.name, pending.label("pending")).where(active_service_predicate())
                      .order_by(Service.name, Service.id)).all()


@router.post("/account/access/service", response_class=RedirectResponse, status_code=303)
def request_service(service_id: int = Form(gt=0), db: Session = Depends(get_db), auth: AuthContext = Depends(require_csrf)):
    # Serialize submission and claim in account-then-service order. Re-read
    # grants after the lock in case an approval just unblocked this user.
    db.scalar(select(User.id).where(User.id == auth.user.id).with_for_update())
    db.expire(auth.user)
    if (not auth.user.enabled or db.get(AccountRetirement, auth.user.id)
            or not uses_service_directory(auth.user) or has_effective_access(auth)):
        raise HTTPException(403, "Service requests are available during organizational sign-in onboarding")
    if db.scalar(select(Service.id).where(Service.id == service_id, active_service_predicate()).with_for_update()) is None:
        raise HTTPException(404, "Service is unavailable")
    key = (auth.user.id, service_id)
    if not db.get(ServiceAccessRequest, key):
        try:
            with db.begin_nested():
                db.add(ServiceAccessRequest(user_id=auth.user.id, service_id=service_id))
                db.flush()
        except IntegrityError:
            if not db.get(ServiceAccessRequest, key):
                raise
        else:
            record_audit(db, auth, "account.service_access_requested", "service", service_id, service_id=service_id)
    db.commit()
    return RedirectResponse("/account/access", status_code=303, headers={"Cache-Control": "no-store"})


def register_pending_request(db: Session, auth: AuthContext):
    """Caller commits together with session/login changes; duplicate calls are safe."""
    if (uses_service_directory(auth.user) or not auth.user.enabled or db.get(AccountRetirement, auth.user.id)
            or has_effective_access(auth)):
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


def _service_claim_scope(auth: AuthContext):
    assignments = cyber_assignments(auth)
    if any(a.group_id is None and a.service_id is None for a in assignments):
        return True
    group_ids = {a.group_id for a in assignments if a.group_id is not None and a.service_id is None}
    # A scoped reviewer must cover every owner, including legacy memberships.
    owned = select(ServiceGroup.group_id).where(ServiceGroup.service_id == Service.id)
    return owned.where(ServiceGroup.group_id.in_(group_ids)).exists() & ~owned.where(ServiceGroup.group_id.not_in(group_ids)).exists()


def list_pending_requests(db: Session, auth: AuthContext) -> list[dict]:
    if not is_cybersecurity(auth):
        return []
    rows = db.execute(select(AccountAccessRequest, User).join(User, User.id == AccountAccessRequest.user_id)
                      .where(AccountAccessRequest.status == "pending", User.enabled.is_(True),
                             User.auth_source != "oidc", User.external_subject.is_(None))
                      .order_by(AccountAccessRequest.created_at, User.id)).all()
    legacy = [{"user_id": user.id, "username": user.username, "display_name": user.display_name,
             "created_at": request.created_at.isoformat()}
            for request, user in rows
            if not db.get(AccountRetirement, user.id)
            and not has_effective_access(AuthContext(user, auth.session))]
    requests = db.execute(select(User.id, User.username, User.display_name, Service.id, Service.name, ServiceAccessRequest.created_at)
        .select_from(ServiceAccessRequest).join(Service, ServiceAccessRequest.service_id == Service.id)
        .join(User, ServiceAccessRequest.user_id == User.id)
        .where(active_service_predicate(), _service_claim_scope(auth), User.enabled.is_(True), User.id != auth.user.id,
               ~select(AccountRetirement.user_id).where(AccountRetirement.user_id == User.id).exists())
        .order_by(ServiceAccessRequest.created_at, User.id, Service.id)).all()
    return legacy + [{"user_id": uid, "username": username, "display_name": display_name,
                      "service_id": sid, "service_name": name, "created_at": created.isoformat()}
                     for uid, username, display_name, sid, name, created in requests]


def _claim_service(db: Session, reviewer: AuthContext, target: User, service_id: int, role: Role):
    if target.id == reviewer.user.id:
        raise HTTPException(403, "Another Cybersecurity reviewer must approve this request")
    available = select(Service.id).where(Service.id == service_id, active_service_predicate(), _service_claim_scope(reviewer))
    if db.scalar(available.with_for_update()) is None:
        raise HTTPException(403, "Service unavailable or outside your Cybersecurity scope")
    consumed = db.execute(delete(ServiceAccessRequest).where(
        ServiceAccessRequest.user_id == target.id, ServiceAccessRequest.service_id == service_id))
    if consumed.rowcount != 1:
        raise HTTPException(409, "Service request is no longer pending")
    if AuthContext(target, reviewer.session).has("service.view", service_id):
        record_audit(db, reviewer, "account.service_access_already_granted", "user", target.id, service_id=service_id)
        return {"user_id": target.id, "service_id": service_id, "status": "already_granted"}
    db.add(UserRoleAssignment(user_id=target.id, role_id=role.id, service_id=service_id, source="local"))
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(409, "An existing grant conflicts with this service assignment") from exc
    record_audit(db, reviewer, "account.service_access_claimed", "user", target.id, service_id=service_id, role_id=role.id)
    return {"user_id": target.id, "service_id": service_id, "role": role.name, "status": "claimed"}


def claim_access_request(db: Session, auth: AuthContext, user_id: int, group_id: int | None = None, service_id: int | None = None):
    # Discard cached roles/eligibility so a revoked operator cannot use an old page.
    db.expire_all()
    actor = db.get(User, auth.user.id)
    if not actor or not actor.enabled or db.get(AccountRetirement, actor.id):
        raise HTTPException(403, "Access denied")
    fresh = AuthContext(actor, auth.session)
    if not is_cybersecurity(fresh):
        raise HTTPException(403, "Cybersecurity role required")
    target = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if not target or not target.enabled or db.get(AccountRetirement, user_id):
        raise HTTPException(409, "Account is unavailable")
    role = db.scalar(select(Role).where(Role.name == "Assessor", Role.system.is_(True)))
    if not role or set(role.permissions or []) != set(SYSTEM_ROLES["Assessor"]):
        raise HTTPException(409, "Default access role is unavailable or has been modified")
    if service_id is not None:
        if group_id is not None:
            raise HTTPException(422, "Choose only the requested service")
        return _claim_service(db, fresh, target, service_id, role)
    if uses_service_directory(target):
        raise HTTPException(409, "Select a pending service request for this account")
    if has_effective_access(AuthContext(target, auth.session)):
        raise HTTPException(409, "Account already has access")
    groups = authorized_claim_groups(db, fresh)
    if group_id is None and len(groups) == 1:
        group_id = groups[0].id
    if group_id is None:
        raise HTTPException(422, "Select an authorized group")
    if group_id not in {group.id for group in groups}:
        raise HTTPException(403, "Group outside your Cybersecurity scope")
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
    service_id: int | None = None


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
        result = claim_access_request(db, auth, user_id, payload.group_id, payload.service_id)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
