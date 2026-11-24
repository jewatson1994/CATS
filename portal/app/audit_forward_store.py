"""Transactional capture and durable, per-destination delivery of CATS events."""
from datetime import datetime, timedelta, timezone
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy import UniqueConstraint, delete, func, inspect, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .diagnostic_store import bounded_setting
from .diagnostics import redact_audit_value
from .models import AuditEvent
from .operating_mode import is_replica


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
    include_operational: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("FALSE"))
    dropped_operational: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_operational_drop_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
        Index("ix_forward_ops_dest", "destination_id", "id", sqlite_where=text("category = 'operational'"),
              postgresql_where=text("category = 'operational'")),
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
    relay_fragment_next: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    relay_fragment_sha256: Mapped[str | None] = mapped_column(String(64))


class ForwardIdentity(Base):
    """Identifies this audit trail across independent CATS installations."""
    __tablename__ = "audit_forward_identity"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(36))


class ComponentOperationalEvent(Base):
    """Portal-owned copy of a component log, independent of diagnostics and audit retention."""
    __tablename__ = "component_operational_events"
    __table_args__ = (
        UniqueConstraint("source_id", "event_id"),
        Index("ix_component_log_source_time", "source_id", "timestamp"),
        Index("ix_component_log_source_receipt", "source_id", "received_at"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[str] = mapped_column(String(100))
    source_name: Mapped[str] = mapped_column(String(160))
    event_id: Mapped[str] = mapped_column(String(200))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    data: Mapped[dict] = mapped_column(JSON)


def record_operational_log(db, *, source_id, source_name, event):
    """Store an authenticated source's event and enqueue its copies in this transaction."""
    event_id = event.get("event_id")
    if (event.get("category") != "operational" or not isinstance(event_id, str)
            or not 0 < len(event_id) <= 200 or not isinstance(event.get("data"), dict)):
        raise ValueError("Invalid component operational event")
    timestamp = event.get("timestamp")
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if not isinstance(timestamp, datetime) or timestamp.tzinfo is None:
        raise ValueError("Component timestamp must include its timezone")
    if not source_id or len(source_id) > 100 or not source_name or len(source_name) > 160:
        raise ValueError("Invalid component identity")
    table = ComponentOperationalEvent.__table__
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    db.execute(insert(table).values(source_id=source_id, source_name=source_name, event_id=event_id,
        timestamp=timestamp.astimezone(timezone.utc), received_at=utcnow(), data=redact_audit_value(event["data"]))
        .on_conflict_do_nothing(index_elements=[table.c.source_id, table.c.event_id]))
    return event_id


def operational_limits():
    return {
        "history_days": bounded_setting("CATS_OPERATIONAL_LOG_RETENTION_DAYS", 7, 1, 365),
        "history_limit": bounded_setting("CATS_OPERATIONAL_LOG_MAX_ROWS", 50000, 100, 2000000),
        "pending_limit": bounded_setting("CATS_OPERATIONAL_QUEUE_MAX_ROWS", 50000, 100, 2000000),
    }


def maintain_operational_logs(db, now, *, history_days, history_limit, pending_limit):
    """Keep operational history/queues bounded without touching audit or diagnostic rows."""
    event = ComponentOperationalEvent
    delivery = ForwardDelivery
    batch = 2000
    cutoff = now - timedelta(days=history_days)
    floor = db.scalar(select(event.id).order_by(event.id.desc()).offset(history_limit - 1).limit(1))
    expired = event.received_at < cutoff
    if floor is not None:
        expired = or_(expired, event.id < floor)
    old = select(event.id).where(expired).order_by(event.id).limit(batch)
    more = db.execute(delete(event).where(event.id.in_(old))
                      .execution_options(synchronize_session=False)).rowcount == batch
    for dest_id in db.scalars(select(ForwardDestination.id)):
        pending = (delivery.destination_id == dest_id, delivery.category == "operational",
                   delivery.delivered_at.is_(None))
        floor = db.scalar(select(delivery.id).where(*pending).order_by(delivery.id.desc())
                          .offset(pending_limit).limit(1))
        if floor is None:
            continue
        # Lock in the same order as claim/delete. Skip busy recipients rather than
        # block an administrator or a concurrent delivery on maintenance.
        locked = db.scalar(select(ForwardDestination.id).where(ForwardDestination.id == dest_id)
                           .with_for_update(skip_locked=True, key_share=True))
        if locked is None:
            continue
        idle = or_(delivery.lease_token.is_(None), delivery.available_at <= now)
        excess = select(delivery.id).where(*pending, delivery.id <= floor, idle).order_by(delivery.id).limit(batch)
        removed = db.execute(delete(delivery).where(*pending, delivery.id.in_(excess), idle)
                             .execution_options(synchronize_session=False)).rowcount
        if removed:
            db.execute(update(ForwardDestination).where(ForwardDestination.id == dest_id)
                .values(dropped_operational=ForwardDestination.dropped_operational + removed,
                        last_operational_drop_at=now))
            more = more or removed == batch
    return more


def _capture_sql(dialect, category, row, recipients, extra_from="", where=""):
    """Shared projection keeps live and replay event IDs identical on each DB."""
    pg = dialect == "postgresql"
    audit = category == "audit"
    key = f"{row}.error_id" if category == "diagnostic" else f"{row}.id"
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
    elif category == "operational":
        obj = "json_build_object" if pg else "json_object"
        reported = f"{row}.data" if pg else f"json({row}.data)"
        received = (f"""to_char({row}.received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')"""
                    if pg else f"replace({row}.received_at, ' ', 'T') || 'Z'")
        payload = (f"{obj}('source_id', {row}.source_id, 'source_name', {row}.source_name, "
                   f"'event_id', {row}.event_id, 'received_at', {received}, 'reported', {reported})")
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
    for model in (ForwardIdentity, ForwardDestination, ForwardDelivery, ComponentOperationalEvent):
        model.__table__.create(connection, checkfirst=True)
    delivery_columns = {c["name"] for c in inspect(connection).get_columns(ForwardDelivery.__tablename__)}
    if "relay_fragment_next" not in delivery_columns:
        connection.exec_driver_sql("ALTER TABLE audit_forward_deliveries ADD COLUMN "
                                   "relay_fragment_next INTEGER NOT NULL DEFAULT 0")
    if "relay_fragment_sha256" not in delivery_columns:
        connection.exec_driver_sql("ALTER TABLE audit_forward_deliveries ADD COLUMN relay_fragment_sha256 VARCHAR(64)")
    for index in ForwardDelivery.__table__.indexes:
        if index.name == "ix_forward_ops_dest":
            index.create(connection, checkfirst=True)
    columns = {c["name"] for c in inspect(connection).get_columns(ForwardDestination.__tablename__)}
    if "include_operational" not in columns:
        connection.exec_driver_sql("ALTER TABLE audit_forward_destinations ADD COLUMN "
                                   "include_operational BOOLEAN NOT NULL DEFAULT FALSE")
    if "dropped_operational" not in columns:
        connection.exec_driver_sql("ALTER TABLE audit_forward_destinations ADD COLUMN "
                                   "dropped_operational INTEGER NOT NULL DEFAULT 0")
    if "last_operational_drop_at" not in columns:
        dt_type = "TIMESTAMP WITH TIME ZONE" if connection.dialect.name == "postgresql" else "DATETIME"
        connection.exec_driver_sql(f"ALTER TABLE audit_forward_destinations ADD COLUMN last_operational_drop_at {dt_type}")
    connection.execute(text("""
        INSERT INTO audit_forward_identity (id, source) VALUES (1, :source)
        ON CONFLICT (id) DO NOTHING
    """), {"source": str(uuid.uuid4())})
    dialect = connection.dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise ValueError("CATS audit forwarding requires SQLite or PostgreSQL")
    for category, table, preference in (("audit", "audit_events", "include_audit"),
                                        ("diagnostic", "diagnostic_events", "include_diagnostics"),
                                        ("operational", "component_operational_events", "include_operational")):
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
    if is_replica():
        from .replica_audit_reporter import install_portal_relay
        install_portal_relay(connection)


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


def backfill_page(db, batch_size=200, *, portal_only=False):
    """Snapshot an indexed page locally; live capture and repeated replays deduplicate."""
    dest = db.scalar(select(ForwardDestination).where(
        ForwardDestination.kind == "portal" if portal_only else ForwardDestination.kind != "portal",
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
