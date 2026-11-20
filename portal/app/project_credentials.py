"""Service-bound machine credentials for CI projects on the authoritative portal."""
from datetime import datetime, timedelta
import re
import secrets
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import DateTime, ForeignKey, JSON, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from .account_models import AccountRetirement
from .auth import AuthContext, aware, record_audit, require_user, token_hash
from .database import Base, get_db
from .imported_services import is_imported_service
from .models import Service, ServiceGroup, User, utcnow
from .operating_mode import is_replica
from .service_ownership import active_service_predicate

TOKEN_PREFIX = "cats_project_"
Scope = Literal["artifacts.submit", "evidence.write"]
Status = Literal["active", "expired", "revoked", "inactive"]
router = APIRouter(prefix="/api/services/{service_key}/project-credentials", tags=["Project credentials"])


class ProjectCredential(Base):
    __tablename__ = "project_credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True)
    owning_group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    project_label: Mapped[str] = mapped_column(String(120))
    scopes: Mapped[list[str]] = mapped_column(JSON)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    service: Mapped[Service] = relationship()
    creator: Mapped[User | None] = relationship()


class CsrfInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csrf_token: str


class CreateCredential(CsrfInput):
    project_label: str = Field(min_length=1, max_length=120)
    scopes: list[Scope] = Field(min_length=1, max_length=2)
    expires_in_days: int = Field(default=30, ge=1, le=365, strict=True)

    @field_validator("project_label")
    @classmethod
    def validate_label(cls, value):
        label = value.strip()
        if not label or not label.isprintable():
            raise ValueError("Enter a printable project label")
        return label


class CredentialInfo(BaseModel):
    id: int
    service_key: str
    project_label: str
    scopes: list[Scope]
    status: Status
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


class CredentialList(BaseModel):
    credentials: list[CredentialInfo]


class CredentialResult(BaseModel):
    credential: CredentialInfo


class IssuedCredential(CredentialResult):
    token: str = Field(description="One-time project bearer secret")


def _full_only():
    if is_replica():
        raise HTTPException(403, "Project credentials require an authoritative portal")


def _check_csrf(auth, token):
    if not secrets.compare_digest(auth.csrf_token.encode(), token.encode()):
        raise HTTPException(403, "Invalid CSRF token")


def _managed_service(db, auth, service_key, *, write=False):
    _full_only()
    query = select(Service).where(Service.service_key == service_key)
    if write:
        query = query.with_for_update()
    service = db.scalar(query)
    if not service or not auth.has("service.edit", service.id):
        raise HTTPException(403, "Service management access required")
    return service


def _active_owner(db: Session, service_id: int) -> int | None:
    if is_imported_service(db, service_id):
        return None
    owners = db.scalars(select(ServiceGroup.group_id).join(Service, Service.id == ServiceGroup.service_id)
                        .where(Service.id == service_id, active_service_predicate())).all()
    return owners[0] if len(owners) == 1 else None


def _can_delegate(db: Session, issuer: User | None, service_id: int) -> bool:
    if not issuer or not issuer.enabled or db.get(AccountRetirement, issuer.id):
        return False
    auth = AuthContext(issuer, None)
    return auth.has("service.edit", service_id) and auth.has("scan.ingest", service_id)


def _status(db, row, owner_id) -> Status:
    if row.revoked_at is not None:
        return "revoked"
    if aware(row.expires_at) <= utcnow():
        return "expired"
    if owner_id is None or row.owning_group_id != owner_id or not _can_delegate(db, row.creator, row.service_id):
        return "inactive"
    return "active"


def _info(row, status):
    return CredentialInfo(id=row.id, project_label=row.project_label, scopes=row.scopes, service_key=row.service.service_key,
                          status=status, created_at=aware(row.created_at), expires_at=aware(row.expires_at),
                          revoked_at=aware(row.revoked_at))


def audit_project_use(db: Session, credential: ProjectCredential, operation: str, *, target_type: str, target_id):
    """Call inside the successful operation's transaction. Use only fixed event names and IDs."""
    record_audit(db, None, "project_credential.used", target_type, target_id,
                 credential_id=credential.id, project_label=credential.project_label, service_id=credential.service_id,
                 operation=operation)


def authenticate_project(db: Session, authorization: str | None, *, scope: Scope, service_key: str | None = None) -> ProjectCredential:
    """Authenticate a project bearer and hold its admission locks through the caller's transaction."""
    _full_only()
    invalid = HTTPException(401, "Invalid or inactive project credential", headers={"WWW-Authenticate": "Bearer"})
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not re.fullmatch(TOKEN_PREFIX + r"[A-Za-z0-9_-]{43}", token):
        raise invalid
    digest = token_hash(token)
    # Lock the service before the credential. Evidence writers also update the
    # service row, so serialize them without a shared-to-exclusive upgrade.
    service_id = db.scalar(select(ProjectCredential.service_id).where(ProjectCredential.token_hash == digest))
    if service_id is None:
        raise invalid
    service = db.scalar(select(Service).where(Service.id == service_id).with_for_update(read=scope != "evidence.write"))
    row = db.scalar(select(ProjectCredential).where(ProjectCredential.token_hash == digest)
                    .execution_options(populate_existing=True).with_for_update(read=True))
    if service is None or row is None or _status(db, row, _active_owner(db, service_id)) != "active":
        raise invalid
    if scope not in row.scopes or (service_key is not None and service_key != service.service_key):
        raise HTTPException(403, "Project credential does not permit this service or operation")
    return row


@router.get("", response_model=CredentialList)
def list_credentials(service_key: str, response: Response, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    response.headers["Cache-Control"] = "no-store"
    service = _managed_service(db, auth, service_key)
    owner_id = _active_owner(db, service.id)
    rows = db.scalars(select(ProjectCredential).where(ProjectCredential.service_id == service.id)
                      .order_by(ProjectCredential.id.desc()))
    return {"credentials": [_info(row, _status(db, row, owner_id)) for row in rows]}


@router.post("", response_model=IssuedCredential, status_code=201)
def create_credential(service_key: str, payload: CreateCredential, response: Response,
                      db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _check_csrf(auth, payload.csrf_token)
    response.headers["Cache-Control"] = "no-store"
    service = _managed_service(db, auth, service_key, write=True)
    owner_id = _active_owner(db, service.id)
    if owner_id is None:
        raise HTTPException(409, "Project credentials require an active local service with one owning group")
    if not _can_delegate(db, auth.user, service.id):
        raise HTTPException(403, "Service edit and scan ingest permissions are required")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ProjectCredential(service=service, owning_group_id=owner_id, creator=auth.user,
                            project_label=payload.project_label, scopes=sorted(set(payload.scopes)),
                            token_hash=token_hash(token), expires_at=utcnow() + timedelta(days=payload.expires_in_days))
    db.add(row)
    db.flush()
    record_audit(db, auth, "project_credential.created", "project_credential", row.id, service_id=service.id,
                 project_label=row.project_label, scopes=row.scopes, expires_at=row.expires_at.isoformat())
    info = _info(row, "active")
    db.commit()
    return {"credential": info, "token": token}


@router.post("/{credential_id}/revoke", response_model=CredentialResult)
def revoke_credential(service_key: str, credential_id: int, payload: CsrfInput, response: Response,
                      db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _check_csrf(auth, payload.csrf_token)
    response.headers["Cache-Control"] = "no-store"
    service = _managed_service(db, auth, service_key, write=True)
    row = db.scalar(select(ProjectCredential).where(ProjectCredential.id == credential_id,
                    ProjectCredential.service_id == service.id).with_for_update())
    if row is None:
        raise HTTPException(404, "Credential not found")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        record_audit(db, auth, "project_credential.revoked", "project_credential", row.id, service_id=service.id,
                     project_label=row.project_label)
    info = _info(row, "revoked")
    db.commit()
    return {"credential": info}
