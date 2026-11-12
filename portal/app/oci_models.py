"""Additive OCI metadata and small manifests; blob bytes remain on disk."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base
from .oci_transport import REPOSITORY


def is_project_pattern(value):
    return (isinstance(value, str) and value.endswith('/*') and value.count('/') == 1
            and len(value) <= 255 and bool(REPOSITORY.fullmatch(value[:-2])))


def parse_service_repository(repository):
    """Separate the authoritative local service ID from a consumer pull path."""
    if (not isinstance(repository, str) or len(repository) > 255
            or not REPOSITORY.fullmatch(repository)):
        raise ValueError('Invalid repository')
    parts = repository.split('/', 2)
    if (len(parts) != 3 or not parts[1].isascii() or not parts[1].isdigit()
            or parts[1].startswith('0')):
        raise ValueError('Repository must use project/service-id/image with a positive numeric service ID')
    identity = int(parts[1])
    if identity > 2147483647:
        raise ValueError('Invalid service ID')
    return identity, parts[0] + '/' + parts[2]


def service_repository(repository, service_id=None):
    """Expose scoped pull names without rewriting retained signed mapping names."""
    if is_project_pattern(repository):
        return repository[:-1] + '<service-id>/*'
    if (type(service_id) is not int or not 0 < service_id <= 2147483647
            or not isinstance(repository, str) or len(repository) > 255
            or not REPOSITORY.fullmatch(repository) or '/' not in repository):
        raise ValueError('A valid service and project repository are required')
    project, relative = repository.split('/', 1)
    first = relative.split('/', 1)[0]
    if '/' in relative and first.isascii() and first.isdigit():
        scoped_id, _ = parse_service_repository(repository)
        if scoped_id != service_id:
            raise ValueError('Repository service ID does not match its configured service')
        return repository
    result = f'{project}/{service_id}/{relative}'
    if len(result) > 255:
        raise ValueError('Service-scoped repository name is too long')
    return result


def project_repository(target_pattern, source_pattern, repository):
    """Translate only a concrete descendant of the configured Harbor project."""
    if (not is_project_pattern(target_pattern) or not is_project_pattern(source_pattern)
            or not isinstance(repository, str) or not REPOSITORY.fullmatch(repository)
            or not repository.startswith(source_pattern[:-1]) or len(repository) > 255):
        raise ValueError('Repository is outside the configured project')
    target_project = target_pattern.removesuffix('/*')
    _, _, relative_path = repository.partition('/')
    result = f'{target_project}/{relative_path}'
    if len(result) > 255:
        raise ValueError('Repository name is too long')
    return result


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
    service_id: Mapped[int | None] = mapped_column(ForeignKey('services.id'), index=True)
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


class OCIProjectObjectLink(Base):
    """A sibling repository's cached graph never conveys access to these objects."""
    __tablename__ = 'oci_project_object_links'
    __table_args__ = (Index('ix_oci_project_graph_root', 'repository_id', 'repository_path', 'root_digest', 'kind'),)
    repository_id: Mapped[int] = mapped_column(ForeignKey('oci_repositories.id'), primary_key=True)
    repository_path: Mapped[str] = mapped_column(String(255), primary_key=True)
    object_digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    root_digest: Mapped[str] = mapped_column(String(71), primary_key=True)


class OCITag(Base):
    __tablename__ = 'oci_tags'
    __table_args__ = (UniqueConstraint('repository_id', 'tag'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey('oci_repositories.id'), index=True)
    tag: Mapped[str] = mapped_column(String(128))
    digest: Mapped[str] = mapped_column(String(71))
    resolved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
