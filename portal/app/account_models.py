"""Additive account identity/retirement records; imported before create_all."""
from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import utcnow


class OidcAccountIdentity(Base):
    __tablename__ = "oidc_account_identities"
    identity_key: Mapped[str] = mapped_column(String(72), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(2048))
    subject: Mapped[str] = mapped_column(String(1024))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccountRetirement(Base):
    __tablename__ = "account_retirements"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    survivor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    administrator_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccountChangePreview(Base):
    __tablename__ = "account_change_previews"
    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    administrator_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    payload: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class AccountAccessRequest(Base):
    """One durable request per account; compare-and-set protects competing claims."""
    __tablename__ = "account_access_requests"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"))
