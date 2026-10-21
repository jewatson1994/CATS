"""Additive, immutable deployment evidence and explicit service confirmations."""
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, JSON, String, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import utcnow

class DiscoveryInventory(Base):
    __tablename__ = 'discovery_inventories'
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey('durable_jobs.id'), unique=True)
    group_id: Mapped[int] = mapped_column(ForeignKey('groups.id'), index=True)
    source_hash: Mapped[str] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(64))
    inventory: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class DiscoveryConfirmation(Base):
    __tablename__ = 'discovery_confirmations'
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    inventory_id: Mapped[str] = mapped_column(ForeignKey('discovery_inventories.id'), index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    confirmed_by: Mapped[int] = mapped_column(ForeignKey('users.id'))
    root_ids: Mapped[list] = mapped_column(JSON)
    acknowledge_partial: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class DiscoveryScan(Base):
    __tablename__ = 'discovery_scans'
    confirmation_id: Mapped[str] = mapped_column(ForeignKey('discovery_confirmations.id'), primary_key=True)
    scan_job_id: Mapped[str] = mapped_column(String(32), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# Immutable evidence is protected against ORM and direct SQL mutation.
from sqlalchemy import event, DDL

def _immutable_inventory(mapper, connection, target):
    raise ValueError('Discovery inventories are immutable; append a new inventory')

for _operation in ('before_update', 'before_delete'):
    event.listen(DiscoveryInventory, _operation, _immutable_inventory)
for _operation in ('UPDATE', 'DELETE'):
    event.listen(DiscoveryInventory.__table__, 'after_create', DDL(
        f"CREATE TRIGGER discovery_inventories_deny_{_operation.lower()} BEFORE {_operation} ON discovery_inventories BEGIN SELECT RAISE(ABORT, 'Discovery inventories are immutable'); END"
    ).execute_if(dialect='sqlite'))
event.listen(DiscoveryInventory.__table__, 'after_create', DDL(
    "CREATE OR REPLACE FUNCTION discovery_inventories_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'Discovery inventories are immutable'; END; $$ LANGUAGE plpgsql"
).execute_if(dialect='postgresql'))
event.listen(DiscoveryInventory.__table__, 'after_create', DDL(
    "CREATE TRIGGER discovery_inventories_immutable BEFORE UPDATE OR DELETE ON discovery_inventories FOR EACH ROW EXECUTE FUNCTION discovery_inventories_immutable()"
).execute_if(dialect='postgresql'))
