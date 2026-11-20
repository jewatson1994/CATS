"""Local runtime observations, separate from authoritative release evidence."""
from datetime import datetime, timezone
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint, inspect, select, text, update
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def now():
    return datetime.now(timezone.utc)


class RuntimeEnvironment(Base):
    __tablename__ = 'runtime_environments'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    kind: Mapped[str] = mapped_column(String(24))
    service_scope: Mapped[str] = mapped_column(String(16), default='selected', server_default='selected')
    service_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class RuntimeLinkToken(Base):
    __tablename__ = 'runtime_link_tokens'
    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey('runtime_environments.id'), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class RuntimeAgent(Base):
    __tablename__ = 'runtime_agents'
    __table_args__ = (UniqueConstraint('environment_id', 'source_id'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    environment_id: Mapped[int] = mapped_column(ForeignKey('runtime_environments.id'), index=True)
    name: Mapped[str] = mapped_column(String(160))
    source_id: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    inventory_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sequence: Mapped[int] = mapped_column(Integer, default=0)
    report_hash: Mapped[str] = mapped_column(String(64), default='')
    complete: Mapped[bool] = mapped_column(Boolean, default=False)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    workloads: Mapped[list] = mapped_column(JSON, default=list)


class RuntimeEnrollmentReceipt(Base):
    """Recover a lost link acknowledgement only with the original agent secret."""
    __tablename__ = 'runtime_enrollment_receipts'
    link_id: Mapped[int] = mapped_column(ForeignKey('runtime_link_tokens.id'), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey('runtime_agents.id'))
    credential_hash: Mapped[str] = mapped_column(String(64), unique=True)


def upgrade_connection(connection):
    """Legacy scopes retain their explicit service selection, including empty lists."""
    table = RuntimeEnvironment.__tablename__
    if 'service_scope' not in {column['name'] for column in inspect(connection).get_columns(table)}:
        connection.execute(text("ALTER TABLE runtime_environments ADD COLUMN service_scope VARCHAR(16) NOT NULL DEFAULT 'selected'"))


def expire_link_keys(db, environment_id):
    timestamp = now()
    db.execute(update(RuntimeLinkToken).where(RuntimeLinkToken.environment_id == environment_id,
        RuntimeLinkToken.expires_at > timestamp).values(expires_at=timestamp).execution_options(synchronize_session=False))


def forget_service(db, service_id):
    """Called in the service deletion transaction, after locking the service."""
    candidates = [identity for identity, services in db.execute(select(RuntimeEnvironment.id, RuntimeEnvironment.service_ids)
                  .where(RuntimeEnvironment.service_scope == 'selected')) if service_id in services]
    for env in db.scalars(select(RuntimeEnvironment).where(RuntimeEnvironment.id.in_(candidates))
            .order_by(RuntimeEnvironment.id).with_for_update().execution_options(populate_existing=True)):
        if service_id in env.service_ids:
            env.service_ids = [item for item in env.service_ids if item != service_id]
            expire_link_keys(db, env.id)
