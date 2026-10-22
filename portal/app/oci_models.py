"""Additive OCI metadata and small manifests; blob bytes remain on disk."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def now():
    return datetime.now(timezone.utc)


class OCIUpstream(Base):
    __tablename__ = 'oci_upstreams'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    endpoint: Mapped[str] = mapped_column(String(500))
    username: Mapped[str] = mapped_column(Text, default='')
    password: Mapped[str] = mapped_column(Text, default='')
    ca_pem: Mapped[str] = mapped_column(Text, default='')
    token_realms: Mapped[list] = mapped_column(JSON, default=list)
    redirect_origins: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class OCIRepository(Base):
    __tablename__ = 'oci_repositories'
    id: Mapped[int] = mapped_column(primary_key=True)
    public_repository: Mapped[str] = mapped_column(String(255), unique=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    upstream_id: Mapped[int] = mapped_column(ForeignKey('oci_upstreams.id'))
    upstream_repository: Mapped[str] = mapped_column(String(255))
    upstream: Mapped[OCIUpstream] = relationship()
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)


class OCIPrincipal(Base):
    __tablename__ = 'oci_principals'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    secret_hash: Mapped[str] = mapped_column(String(64))
    repository_ids: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class OCIManifest(Base):
    __tablename__ = 'oci_manifests'
    __table_args__ = (UniqueConstraint('repository_id', 'digest'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('oci_repositories.id'), index=True)
    digest: Mapped[str] = mapped_column(String(71), index=True)
    media_type: Mapped[str] = mapped_column(String(160))
    # Raw JSON text preserves the byte identity; all accepted OCI JSON is UTF-8.
    content: Mapped[str] = mapped_column(Text)


class OCIObjectLink(Base):
    __tablename__ = 'oci_object_links'
    __table_args__ = (UniqueConstraint('repository_id', 'root_digest', 'object_digest', 'kind'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('oci_repositories.id'), index=True)
    root_digest: Mapped[str] = mapped_column(String(71), index=True)
    object_digest: Mapped[str] = mapped_column(String(71), index=True)
    kind: Mapped[str] = mapped_column(String(16))


class OCITag(Base):
    __tablename__ = 'oci_tags'
    __table_args__ = (UniqueConstraint('repository_id', 'tag'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('oci_repositories.id'), index=True)
    tag: Mapped[str] = mapped_column(String(128))
    digest: Mapped[str] = mapped_column(String(71))
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
