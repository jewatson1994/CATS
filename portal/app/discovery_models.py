"""Additive, immutable deployment evidence and explicit service confirmations."""
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, JSON, String, Boolean, select
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import ServiceGroup, utcnow

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


class DiscoveryDistribution(Base):
    __tablename__ = 'discovery_distributions'
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    confirmation_id: Mapped[str] = mapped_column(ForeignKey('discovery_confirmations.id'), index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id'), index=True)
    name: Mapped[str] = mapped_column(String(120))
    selection: Mapped[dict] = mapped_column(JSON)
    selection_digest: Mapped[str] = mapped_column(String(80), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def scan_context(self):
        selection = self.selection
        return dict(distribution_id=self.id, selection_digest=self.selection_digest,
                    discovery_inventory_id=selection['inventory_id'], discovery_confirmation_id=self.confirmation_id,
                    source_hash=selection['source_hash'], content_hash=selection['content_hash'],
                    root_ids=selection['root_ids'], discovery_completeness=selection['discovery_completeness'],
                    discovery_images=selection['image_occurrences'])


class DiscoveryDistributionScan(Base):
    __tablename__ = 'discovery_distribution_scans'
    scan_job_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    distribution_id: Mapped[str] = mapped_column(ForeignKey('discovery_distributions.id'), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def confirmed_inventories(service_id):
    return (select(DiscoveryConfirmation, DiscoveryInventory)
            .join(DiscoveryInventory, DiscoveryInventory.id == DiscoveryConfirmation.inventory_id)
            .join(ServiceGroup, (ServiceGroup.group_id == DiscoveryInventory.group_id)
                  & (ServiceGroup.service_id == DiscoveryConfirmation.service_id))
            .where(DiscoveryConfirmation.service_id == service_id))


def service_distributions(service_id):
    visible = confirmed_inventories(service_id).with_only_columns(DiscoveryConfirmation.id)
    return select(DiscoveryDistribution).where(DiscoveryDistribution.service_id == service_id,
                                              DiscoveryDistribution.confirmation_id.in_(visible))


# Immutable evidence is protected against ORM and direct SQL mutation.
from sqlalchemy import event, DDL

def _immutable(mapper, connection, target):
    raise ValueError('Discovery evidence is immutable')


for _model in (DiscoveryInventory, DiscoveryDistribution, DiscoveryDistributionScan):
    _table = _model.__tablename__
    for _operation in ('before_update', 'before_delete'):
        event.listen(_model, _operation, _immutable)
    for _operation in ('UPDATE', 'DELETE'):
        event.listen(_model.__table__, 'after_create', DDL(
            f"CREATE TRIGGER {_table}_deny_{_operation.lower()} BEFORE {_operation} ON {_table} BEGIN SELECT RAISE(ABORT, 'Discovery evidence is immutable'); END"
        ).execute_if(dialect='sqlite'))
    event.listen(_model.__table__, 'after_create', DDL(
        f"CREATE OR REPLACE FUNCTION {_table}_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'Discovery evidence is immutable'; END; $$ LANGUAGE plpgsql"
    ).execute_if(dialect='postgresql'))
    event.listen(_model.__table__, 'after_create', DDL(
        f"CREATE TRIGGER {_table}_immutable BEFORE UPDATE OR DELETE ON {_table} FOR EACH ROW EXECUTE FUNCTION {_table}_immutable()"
    ).execute_if(dialect='postgresql'))
