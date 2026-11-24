"""Transactional capture and durable, per-destination delivery of CATS events."""
from datetime import datetime, timezone
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy import UniqueConstraint, delete, func, select, text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .models import AuditEvent


def utcnow():
    return datetime.now(timezone.utc)


class ForwardDestination(Base):
    __tablename__ = "audit_forward_destinations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    secret_ciphertext: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    include_audit: Mapped[bool] = mapped_column(Boolean, default=True)
    include_diagnostics: Mapped[bool] = mapped_column(Boolean, default=False)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(300))
    retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    backfill_cursor: Mapped[int | None] = mapped_column(Integer)
    backfill_limit: Mapped[int | None] = mapped_column(Integer)


class ForwardDelivery(Base):
    __tablename__ = "audit_forward_deliveries"
    __table_args__ = (
        UniqueConstraint("destination_id", "event_id"),
        Index("ix_forward_pending", "destination_id", "delivered_at", "available_at", "id"),
        Index("ix_forward_receipt", "source_audit_id", "delivered_at"),
        Index("ix_forward_ready", "destination_id", "id",
              sqlite_where=text("delivered_at IS NULL"), postgresql_where=text("delivered_at IS NULL")),
        Index("ix_forward_category_ready", "category", "id",
              sqlite_where=text("delivered_at IS NULL"), postgresql_where=text("delivered_at IS NULL")),
        Index("ix_forward_active", "destination_id", "available_at",
              sqlite_where=text("lease_token IS NOT NULL"), postgresql_where=text("lease_token IS NOT NULL")),
        Index("ix_forward_receipt_cursor", "id", sqlite_where=text("delivered_at IS NOT NULL"),
              postgresql_where=text("delivered_at IS NOT NULL")),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    destination_id: Mapped[int] = mapped_column(ForeignKey("audit_forward_destinations.id"))
    event_id: Mapped[str] = mapped_column(String(200))
    source_audit_id: Mapped[int | None] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(16))
    timestamp: Mapped[str] = mapped_column(String(48))
    payload: Mapped[dict | None] = mapped_column(JSON(none_as_null=True))
    attempts: Mapped[int] = mapped_column(Integer, server_default="0")
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[str | None] = mapped_column(String(36))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ForwardIdentity(Base):
    """Identifies this audit trail across independent CATS installations."""
    __tablename__ = "audit_forward_identity"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(36))


def _capture_sql(dialect, category, row, recipients, extra_from="", where=""):
    """Shared projection keeps live and replay event IDs identical on each DB."""
    pg = dialect == "postgresql"
    audit = category == "audit"
    key = f"{row}.id" if audit else f"{row}.error_id"
    dt = f"{row}.created_at" if audit else f"{row}.timestamp"
    timestamp = (f"""to_char({dt} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')"""
                 if pg else f"replace({dt}, ' ', 'T')")
    # The timestamp distinguishes reused SQLite integer IDs after retention deletes.
    event_id = f"identity.source || ':{category}:' || {key} || ':' || {timestamp}"
    if audit:
        obj = "json_build_object" if pg else "json_object"
        detail = f"{row}.detail" if pg else f"json({row}.detail)"
        def actor(field):
            key = f"actor_{field}"
            recorded = f"{row}.detail ->> '{key}'" if pg else f"json_extract({row}.detail, '$.{key}')"
            return f"coalesce({recorded}, (SELECT {field} FROM users WHERE id = {row}.actor_user_id))"
        payload = (f"{obj}('id', {key}, 'actor_user_id', {row}.actor_user_id, "
                   f"'actor_username', {actor('username')}, 'actor_display_name', {actor('display_name')}, "
                   f"'action', {row}.action, 'target_type', {row}.target_type, "
                   f"'target_id', {row}.target_id, 'detail', {detail})")
    else:
        payload = f"{row}.diagnostic"
    return f"""
        INSERT INTO audit_forward_deliveries
          (destination_id, event_id, source_audit_id, category, timestamp, payload)
        SELECT dest.id, {event_id}, {key if audit else "NULL"}, '{category}', {timestamp}, {payload}
        FROM audit_forward_destinations dest CROSS JOIN audit_forward_identity identity {extra_from}
        WHERE {recipients} {where}
        ON CONFLICT (destination_id, event_id) DO NOTHING
    """


def upgrade_connection(connection):
    """Install capture on the database so all writers participate, including bulk SQL."""
    # Called from the portal's serialized startup migration, following diagnostics.
    for model in (ForwardIdentity, ForwardDestination, ForwardDelivery):
        model.__table__.create(connection, checkfirst=True)
    connection.execute(text("""
        INSERT INTO audit_forward_identity (id, source) VALUES (1, :source)
        ON CONFLICT (id) DO NOTHING
    """), {"source": str(uuid.uuid4())})
    dialect = connection.dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise ValueError("CATS audit forwarding requires SQLite or PostgreSQL")
    for category, table, preference in (("audit", "audit_events", "include_audit"),
                                        ("diagnostic", "diagnostic_events", "include_diagnostics")):
        sql = _capture_sql(dialect, category, "NEW", f"dest.enabled AND dest.{preference}")
        name = f"cats_forward_{category}"
        if dialect == "sqlite":
            connection.exec_driver_sql(f"""
                CREATE TRIGGER IF NOT EXISTS {name} AFTER INSERT ON {table}
                BEGIN {sql}; END
            """)
        else:
            installed = connection.scalar(text("""
                SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = to_regclass(:table)
                               AND tgname = :trigger AND NOT tgisinternal)
            """), {"table": table, "trigger": name})
            if installed:
                continue
            connection.exec_driver_sql(f"""
                CREATE OR REPLACE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $capture$
                BEGIN {sql}; RETURN NEW; END; $capture$
            """)
            connection.exec_driver_sql(f"""
                CREATE TRIGGER {name} AFTER INSERT ON {table}
                FOR EACH ROW EXECUTE FUNCTION {name}()
            """)


def pending_count(db, destination_id):
    return db.scalar(select(func.count()).select_from(ForwardDelivery).where(
        ForwardDelivery.destination_id == destination_id, ForwardDelivery.delivered_at.is_(None)))


def queue_test(db, destination):
    event_id = f"test:{uuid.uuid4()}"
    db.add(ForwardDelivery(destination_id=destination.id, event_id=event_id, category="test",
                           timestamp=utcnow().isoformat(), payload={"message": "CATS log forwarding test"}))
    return event_id


def request_backfill(db, destination):
    if not destination.enabled or not destination.include_audit:
        raise ValueError("Enable audit forwarding before replaying retained audit events")
    if destination.backfill_limit is None:
        destination.backfill_cursor = 0
        destination.backfill_limit = db.scalar(select(func.max(AuditEvent.id))) or 0


def backfill_page(db, batch_size=200):
    """Snapshot an indexed page locally; live capture and repeated replays deduplicate."""
    dest = db.scalar(select(ForwardDestination).where(
        ForwardDestination.enabled.is_(True), ForwardDestination.include_audit.is_(True),
        ForwardDestination.backfill_limit.is_not(None)
    ).order_by(ForwardDestination.id).limit(1).with_for_update(skip_locked=True, key_share=True))
    if dest is None:
        return False
    cursor = dest.backfill_cursor
    keys = db.scalars(select(AuditEvent.id).where(AuditEvent.id > cursor,
        AuditEvent.id <= dest.backfill_limit).order_by(AuditEvent.id).limit(batch_size)).all()
    if keys:
        db.execute(text(_capture_sql(db.get_bind().dialect.name, "audit", "a",
            "dest.id = :dest", "CROSS JOIN audit_events a", "AND a.id > :cursor AND a.id <= :end")),
            {"dest": dest.id, "cursor": cursor, "end": keys[-1]})
        dest.backfill_cursor = keys[-1]
    if len(keys) < batch_size or keys[-1] == dest.backfill_limit:
        dest.backfill_limit = dest.backfill_cursor = None
    return True


def delete_destination(db, destination, *, discard_count=None):
    """The caller commits this deletion and its management audit record together."""
    dest = db.scalar(select(ForwardDestination).where(
        ForwardDestination.id == destination.id).with_for_update().execution_options(populate_existing=True))
    if dest is None:
        raise ValueError("Destination no longer exists")
    if dest.enabled:
        raise ValueError("Disable this destination before deleting it")
    if db.scalar(select(ForwardDelivery.id).where(ForwardDelivery.destination_id == dest.id,
            ForwardDelivery.lease_token.is_not(None), ForwardDelivery.available_at > utcnow()).limit(1)):
        raise ValueError("Wait for active delivery to finish before deleting this destination")
    count = pending_count(db, dest.id)
    if (count or discard_count is not None) and discard_count != count:
        raise ValueError(f"Confirm the current count of {count} pending deliveries")
    db.execute(delete(ForwardDelivery).where(ForwardDelivery.destination_id == dest.id))
    db.delete(dest)
