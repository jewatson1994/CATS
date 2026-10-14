"""Explicit, previewed account changes. History always keeps its original actor."""
import hashlib
import hmac
import json
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from .account_models import AccountChangePreview, AccountRetirement, OidcAccountIdentity
from .auth import AuthContext, aware, oidc_identity_key, record_audit, require_permission
from .database import Base, get_db
from .models import BundlePreview, ExchangePreview, OidcRoleEligibility, User, UserRoleAssignment, UserSession, utcnow
from .scan_coordination import ScanJob

router = APIRouter(prefix="/api/admin/accounts", tags=["accounts"])


class PreviewInput(BaseModel):
    csrf_token: str
    survivor_id: int
    source_id: int | None = None
    issuer: str = Field(min_length=1, max_length=2048)
    subject: str = Field(min_length=1, max_length=1024)
    identity_verified: bool = False


class ApplyInput(BaseModel):
    csrf_token: str
    preview_token: str
    selected_assignment_ids: list[int]
    confirmation: str


def administrator(auth):
    if not auth.has("user.manage") or not auth.has("role.manage"):
        raise HTTPException(403, "Global account and role management permissions are required")


def csrf(auth, token):
    administrator(auth)
    if not hmac.compare_digest(auth.csrf_token, token):
        raise HTTPException(403, "Invalid CSRF token")


def _account(db, user_id):
    user = db.get(User, user_id)
    if not user or db.get(AccountRetirement, user_id):
        raise HTTPException(409, "Account is unavailable or already retired")
    return user


def _roles(user):
    return [{"id": a.id, "user_id": user.id, "role_id": a.role_id, "role": a.role.name,
             "permissions": sorted(a.role.permissions), "service_id": a.service_id,
             "service": a.service.name if a.service else None,
             "group_id": a.group_id, "group": a.group.name if a.group else None,
             "scope": "service" if a.service_id else "group" if a.group_id else "global",
             "source": a.source, "selectable": a.source != "oidc"}
            for a in sorted(user.role_assignments, key=lambda a: a.id)]


def _snapshot(db, user):
    identities = [{"identity_key": row.identity_key, "issuer": row.issuer, "subject": row.subject}
                  for row in db.scalars(select(OidcAccountIdentity).where(
                      OidcAccountIdentity.user_id == user.id).order_by(OidcAccountIdentity.identity_key))]
    references = {}
    # All actor/requester/creator references stay attached to the historical
    # account; preview their counts without reading stored evidence or secrets.
    excluded = {"users", "user_sessions", "user_role_assignments", "oidc_account_identities",
                "account_retirements", "account_change_previews", "oidc_role_eligibilities"}
    for table in Base.metadata.sorted_tables:
        if table.name in excluded:
            continue
        for column in table.columns:
            if any(fk.target_fullname == "users.id" for fk in column.foreign_keys):
                count = db.scalar(select(func.count()).select_from(table).where(column == user.id))
                if count:
                    references[f"{table.name}.{column.name}"] = count
    jobs = db.scalars(select(ScanJob).where(ScanJob.payload["owner_user_id"].as_integer() == user.id)).all()
    return {"id": user.id, "username": user.username, "display_name": user.display_name,
            "enabled": user.enabled, "auth_source": user.auth_source,
            "locked_until": aware(user.locked_until).isoformat() if user.locked_until else None,
            "local_credentials": bool(user.password_hash), "external_subject": user.external_subject,
            "identities": identities, "roles": _roles(user), "historical_references": references,
            "scan_ownership": sorted(row.id for row in jobs),
            "active_scans": sum(row.status not in {"complete", "incomplete", "error", "cancelled"} for row in jobs)}


def _digest(snapshot):
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()


def make_preview(db, auth, data):
    csrf(auth, data.csrf_token)
    if not data.identity_verified:
        raise HTTPException(422, "Verify the issuer and subject in your identity provider before linking")
    issuer, subject = data.issuer.rstrip("/"), data.subject
    parsed = urlsplit(issuer)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or any(ord(c) < 32 for c in issuer + subject) or not subject.strip():
        raise HTTPException(422, "Enter the exact provider issuer URL and subject")
    survivor = _account(db, data.survivor_id)
    source = _account(db, data.source_id) if data.source_id else None
    if source and source.id == survivor.id:
        raise HTTPException(422, "Select two different accounts")
    if auth.user.id in {survivor.id, source.id if source else None}:
        raise HTTPException(409, "Another administrator must change your account to prevent self-lockout")
    if source and (source.auth_source == "local" or source.password_hash):
        raise HTTPException(409, "Select the local account as survivor to preserve its credentials")
    key = oidc_identity_key(issuer, subject)
    identity = db.get(OidcAccountIdentity, key)
    owner = identity.user_id if identity else db.scalar(select(User.id).where(User.external_subject == key))
    if owner and owner not in {survivor.id, source.id if source else None}:
        raise HTTPException(409, "Identity already belongs to a different account")
    if source and owner != source.id:
        raise HTTPException(409, "The supplied issuer and subject must identify the source account")
    # A disabled source cannot gain a working sign-in by being attached to an
    # enabled survivor. Administrators must resolve disabled status separately.
    if source and not source.enabled and survivor.enabled:
        raise HTTPException(409, "A disabled source cannot be merged into an enabled account")
    state = {"survivor": _snapshot(db, survivor), "source": _snapshot(db, source) if source else None}
    if source and state["source"]["active_scans"]:
        raise HTTPException(409, "Wait for source account scans to finish before merging")
    token = secrets.token_urlsafe(32)
    payload = {"survivor_id": survivor.id, "source_id": source.id if source else None,
               "issuer": issuer, "subject": subject, "identity_key": key, "digest": _digest(state)}
    db.add(AccountChangePreview(token=token, administrator_id=auth.user.id, payload=payload,
                               expires_at=utcnow() + timedelta(minutes=10)))
    db.flush()
    return {**state, "preview_token": token, "identity": {"issuer": issuer, "subject": subject},
            "confirmation": f"LINK {survivor.username}", "conflicts": [
                "Select every local or CATS-managed assignment to retain. Unselected assignments are removed.",
                "OIDC-derived access is cleared and synchronized from validated claims at the next login.",
                "All affected sessions and pending import previews are revoked.",
                "Historical actors remain unchanged; completed scan ownership moves to the survivor."]}


def _recovery_ids(db):
    return {u.id for u in db.scalars(select(User)).all() if u.enabled and u.auth_source == "local"
            and u.password_hash and not db.get(AccountRetirement, u.id)
            and (not u.locked_until or aware(u.locked_until) <= utcnow())
            and {"user.manage", "role.manage"}.issubset({permission
                for a in u.role_assignments
                if a.source == "local" and a.service_id is None and a.group_id is None
                for permission in a.role.permissions})}


def apply_preview(db, auth, data):
    csrf(auth, data.csrf_token)
    # Claiming the one-shot preview serializes SQLite writers as well as
    # PostgreSQL transactions; ordered row locks serialize overlapping merges.
    changed = db.execute(update(AccountChangePreview).where(
        AccountChangePreview.token == data.preview_token,
        AccountChangePreview.administrator_id == auth.user.id,
        AccountChangePreview.consumed.is_(False), AccountChangePreview.expires_at > utcnow()
    ).values(consumed=True)).rowcount
    if changed != 1:
        raise HTTPException(409, "Preview expired or was already applied; preview again")
    preview = db.get(AccountChangePreview, data.preview_token)
    payload = preview.payload
    # All account rows protect the last recovery account across disjoint merges.
    db.scalars(select(User).order_by(User.id).with_for_update()).all()
    survivor = _account(db, payload["survivor_id"])
    source = _account(db, payload["source_id"]) if payload["source_id"] else None
    state = {"survivor": _snapshot(db, survivor), "source": _snapshot(db, source) if source else None}
    if _digest(state) != payload["digest"]:
        raise HTTPException(409, "Accounts or access changed; preview again")
    if data.confirmation != f"LINK {survivor.username}":
        raise HTTPException(422, "Confirmation does not match the preview")
    before_recovery = _recovery_ids(db)
    user_ids = [survivor.id] + ([source.id] if source else [])
    assignments = db.scalars(select(UserRoleAssignment).where(UserRoleAssignment.user_id.in_(user_ids))).all()
    selectable = {a.id for a in assignments if a.source != "oidc"}
    selected = set(data.selected_assignment_ids)
    if not selected.issubset(selectable):
        raise HTTPException(422, "Only assignments shown as selectable in this preview can be retained")
    approved = [dict(role_id=a.role_id, service_id=a.service_id, group_id=a.group_id, source=a.source)
                for a in assignments if a.id in selected]
    permission_scopes = {}
    for grant in approved:
        signature = (grant["role_id"], grant["service_id"], grant["group_id"])
        if signature in permission_scopes and permission_scopes[signature] != grant["source"]:
            raise HTTPException(422, "Conflicting grant sources: retain only one source for each role and scope")
        permission_scopes[signature] = grant["source"]
    for assignment in assignments:
        db.delete(assignment)
    db.execute(delete(OidcRoleEligibility).where(OidcRoleEligibility.user_id.in_(user_ids)))
    db.flush()
    seen = set()
    for grant in approved:
        signature = tuple(grant.values())
        if signature not in seen:
            db.add(UserRoleAssignment(user_id=survivor.id, **grant))
            seen.add(signature)
    key = payload["identity_key"]
    identity = db.get(OidcAccountIdentity, key)
    if identity and identity.user_id not in user_ids:
        raise HTTPException(409, "Identity ownership changed; preview again")
    collision = db.scalar(select(User).where(User.external_subject == key, User.id.not_in(user_ids)))
    if collision:
        raise HTTPException(409, "Identity already belongs to another account")
    if not identity:
        db.add(OidcAccountIdentity(identity_key=key, issuer=payload["issuer"], subject=payload["subject"], user_id=survivor.id))
    if source:
        db.execute(update(OidcAccountIdentity).where(OidcAccountIdentity.user_id == source.id).values(user_id=survivor.id))
        source.enabled = False
        source.password_hash = None
        source.external_subject = None
        db.flush()
        db.add(AccountRetirement(user_id=source.id, survivor_id=survivor.id, administrator_id=auth.user.id))
        db.execute(update(AccountRetirement).where(AccountRetirement.survivor_id == source.id).values(survivor_id=survivor.id))
        for job in db.scalars(select(ScanJob).where(ScanJob.payload["owner_user_id"].as_integer() == source.id).with_for_update()):
            job.payload = {**job.payload, "owner_user_id": survivor.id,
                           "original_owner_user_id": job.payload.get("original_owner_user_id", source.id)}
    survivor.external_subject = survivor.external_subject or key
    for model in (UserSession, ExchangePreview, BundlePreview):
        db.execute(delete(model).where(model.user_id.in_(user_ids)))
    db.flush()
    db.expire_all()
    if before_recovery and not _recovery_ids(db):
        raise HTTPException(409, "The last usable local recovery administrator must be preserved")
    record_audit(db, auth, "account.merged" if source else "account.identity_linked", "user", survivor.id,
                 source_user_id=source.id if source else None, surviving_user_id=survivor.id,
                 identity_key=key, issuer=payload["issuer"], approved_assignments=approved,
                 previous_assignments=[a for snapshot in state.values() if snapshot for a in snapshot["roles"]])
    db.flush()
    return {"survivor_id": survivor.id, "retired_id": source.id if source else None, "sessions_revoked": True}


@router.post("/preview")
def preview_route(data: PreviewInput, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("user.manage"))):
    try:
        result = make_preview(db, auth, data)
        db.commit()
        return JSONResponse(result, headers={"Cache-Control": "no-store"})
    except Exception:
        db.rollback()
        raise


@router.post("/apply")
def apply_route(data: ApplyInput, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("user.manage"))):
    try:
        result = apply_preview(db, auth, data)
        db.commit()
        return JSONResponse(result, headers={"Cache-Control": "no-store"})
    except (IntegrityError, OperationalError) as exc:
        db.rollback()
        raise HTTPException(409, "Concurrent account change; preview again") from exc
    except Exception:
        db.rollback()
        raise
