"""Local projections of existing approved releases, never a second approval system."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, select
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def now():
    return datetime.now(timezone.utc)


class ReleasePublicationSequence(Base):
    __tablename__ = 'release_publication_sequences'
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    previous_release_id: Mapped[str | None] = mapped_column(String(160))


def reserve_publication(db, service, approval_id, *, kind='release', target_release_id=None):
    """Allocate under the existing service row lock in the approval transaction."""
    from .models import Service
    from .release_key_rotation import lock_configuration
    lock_configuration(db)
    db.scalar(select(Service).where(Service.id == service.id).with_for_update())
    row = db.get(ReleasePublicationSequence, service.id)
    if row is None:
        row = ReleasePublicationSequence(service_id=service.id, sequence=0)
        db.add(row)
        db.flush()
    row.sequence += 1
    metadata = dict(format='cats-replica-release-v1', kind=kind,
                    service_uuid=service.service_key, release_uuid=str(approval_id),
                    release_sequence=row.sequence, supersedes_release_uuid=row.previous_release_id,
                    service_version=service.manual_version or '')
    if kind == 'release':
        row.previous_release_id = str(approval_id)
    elif kind == 'revocation':
        metadata['target_release_uuid'] = str(target_release_id or approval_id)
    else:
        raise ValueError('Unknown publication event kind')
    db.flush()
    return metadata


class ReplicaSource(Base):
    __tablename__ = 'replica_sources'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    upstream_id: Mapped[int] = mapped_column(ForeignKey('oci_upstreams.id'))
    repository: Mapped[str] = mapped_column(String(255))
    trusted_publishers: Mapped[list] = mapped_column(JSON, default=list)
    poll_seconds: Mapped[int] = mapped_column(Integer, default=300)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[int] = mapped_column(ForeignKey('users.id'))


class ReplicaServiceState(Base):
    __tablename__ = 'replica_service_states'
    __table_args__ = (UniqueConstraint('publisher', 'source_service_id'),)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), primary_key=True)
    publisher: Mapped[str] = mapped_column(String(128))
    source_service_id: Mapped[str] = mapped_column(String(160))
    upstream_id: Mapped[int] = mapped_column(ForeignKey('oci_upstreams.id'))
    source_id: Mapped[int] = mapped_column(ForeignKey('replica_sources.id'))
    active_release_id: Mapped[int | None] = mapped_column(ForeignKey('replica_releases.id', use_alter=True))
    active_execution_id: Mapped[int | None] = mapped_column(ForeignKey('executions.id'))
    high_sequence: Mapped[int] = mapped_column(Integer, default=0)
    last_sync_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ReplicaPublisherTrust(Base):
    """Authenticated high-water mark shared by every service from one publisher."""
    __tablename__ = 'replica_publisher_trust'
    source_id: Mapped[int] = mapped_column(ForeignKey('replica_sources.id'), primary_key=True)
    publisher_root: Mapped[str] = mapped_column(String(128), primary_key=True)
    current_fingerprint: Mapped[str] = mapped_column(String(128))
    generation: Mapped[int] = mapped_column(Integer, default=0)
    key_chain: Mapped[list] = mapped_column(JSON, default=list)
    integrity_seal: Mapped[str] = mapped_column(Text, default='')


class ReplicaRelease(Base):
    __tablename__ = 'replica_releases'
    __table_args__ = (UniqueConstraint('service_id', 'source_release_id'), UniqueConstraint('service_id', 'sequence'))
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    publisher: Mapped[str] = mapped_column(String(128))
    source_release_id: Mapped[str] = mapped_column(String(160))
    sequence: Mapped[int] = mapped_column(Integer)
    manifest: Mapped[dict] = mapped_column(JSON)
    manifest_digest: Mapped[str] = mapped_column(String(80))
    artifacts: Mapped[list] = mapped_column(JSON)
    evidence_state: Mapped[dict] = mapped_column(JSON)
    evidence_state_digest: Mapped[str] = mapped_column(String(80), default='')
    evidence_path: Mapped[str] = mapped_column(Text, default='')
    key_fingerprint: Mapped[str] = mapped_column(String(128))
    integrity_seal: Mapped[str] = mapped_column(Text, default='')
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    complete: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str] = mapped_column(Text, default='')
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    source_reference: Mapped[str] = mapped_column(Text)


class ReplicaEvent(Base):
    __tablename__ = 'replica_events'
    __table_args__ = (UniqueConstraint('publisher', 'source_service_id', 'sequence'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    publisher: Mapped[str] = mapped_column(String(128))
    source_service_id: Mapped[str] = mapped_column(String(160))
    sequence: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(24))
    manifest_digest: Mapped[str] = mapped_column(String(80))
    manifest: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ReplicaRecordMap(Base):
    __tablename__ = 'replica_record_maps'
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), primary_key=True)
    table_name: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    local_id: Mapped[int] = mapped_column(Integer)


class ReplicaEvidenceRecord(Base):
    """Stable local addresses for immutable captured risk detail drilldowns."""
    __tablename__ = 'replica_evidence_records'
    __table_args__ = (UniqueConstraint('release_id', 'kind', 'source_id'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    release_id: Mapped[int] = mapped_column(ForeignKey('replica_releases.id'))
    kind: Mapped[str] = mapped_column(String(80))
    source_id: Mapped[int] = mapped_column(Integer)
    record: Mapped[dict] = mapped_column(JSON)


class ReplicaFindingDecision(Base):
    """Indexed publisher decisions for the active release's read-only finding views."""
    __tablename__ = 'replica_finding_decisions'
    finding_id: Mapped[int] = mapped_column(ForeignKey('findings.id'), primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    release_id: Mapped[int] = mapped_column(ForeignKey('replica_releases.id'))
    eligible: Mapped[bool | None] = mapped_column(Boolean)
    noncompliant: Mapped[bool | None] = mapped_column(Boolean)
    excepted: Mapped[bool] = mapped_column(Boolean)
    vex_excluded: Mapped[bool] = mapped_column(Boolean)
    kev: Mapped[bool] = mapped_column(Boolean)
    epss: Mapped[float | None] = mapped_column(Float)


class ReplicaObservationDecision(Base):
    __tablename__ = 'replica_observation_decisions'
    observation_id: Mapped[int] = mapped_column(ForeignKey('finding_observations.id'), primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    release_id: Mapped[int] = mapped_column(ForeignKey('replica_releases.id'))
    excluded: Mapped[bool] = mapped_column(Boolean)


def upgrade_connection(connection):
    """Idempotent additive migration; no existing approval/evidence rows change."""
    tables = [ReleasePublicationSequence.__table__, ReplicaSource.__table__, ReplicaPublisherTrust.__table__,
              ReplicaServiceState.__table__, ReplicaRelease.__table__, ReplicaEvent.__table__,
              ReplicaRecordMap.__table__, ReplicaEvidenceRecord.__table__, ReplicaFindingDecision.__table__,
              ReplicaObservationDecision.__table__]
    Base.metadata.create_all(connection, tables=tables, checkfirst=True)
