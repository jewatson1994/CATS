"""Append-only supplemental intelligence and atomic package installation history."""
from sqlalchemy import Column, Integer, BigInteger, String, Text, DateTime, ForeignKey, JSON, UniqueConstraint, event, DDL
from .database import Base
from .vex_models import utcnow, _reject_revision_mutation

class IntelligenceRecord(Base):
    __tablename__ = 'intelligence_records'
    __table_args__ = (UniqueConstraint('source_id', 'sha256'),)
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey('vex_sources.id'), nullable=False, index=True)
    kind = Column(String(40), nullable=False, index=True)
    record_id = Column(Text, nullable=False)
    cve = Column(String(40), nullable=False, index=True)
    product = Column(Text)
    data = Column(JSON, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    acquired_at = Column(DateTime(timezone=True), nullable=False)
    source_url = Column(Text, nullable=False)
    package_version = Column(String(128), nullable=False, index=True)

class IntelligencePackageInstall(Base):
    __tablename__ = 'intelligence_package_installs'
    id = Column(Integer, primary_key=True)
    version = Column(String(128), nullable=False, index=True)
    sequence = Column(BigInteger, nullable=False, unique=True)
    manifest = Column(JSON, nullable=False)
    counts = Column(JSON, nullable=False)
    installed_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

class IntelligencePackageCatalog(Base):
    """Small authenticated enrichment metadata for one immutable package install."""
    __tablename__ = 'intelligence_package_catalogs'
    __table_args__ = (UniqueConstraint('install_id', 'source_key'),)
    id = Column(Integer, primary_key=True)
    install_id = Column(Integer, ForeignKey('intelligence_package_installs.id'), nullable=False)
    source_id = Column(Integer, ForeignKey('vex_sources.id'), nullable=False)
    source_key = Column(String(200), nullable=False)
    kind = Column(String(40), nullable=False)
    metadata_json = Column(JSON, nullable=False)
    record_count = Column(Integer, nullable=False)

class IntelligencePackageMember(Base):
    """Exact signed membership; historical record existence never implies currency."""
    __tablename__ = 'intelligence_package_members'
    catalog_id = Column(Integer, ForeignKey('intelligence_package_catalogs.id'), primary_key=True)
    record_id = Column(Integer, ForeignKey('intelligence_records.id'), primary_key=True)

class IntelligencePackageState(Base):
    __tablename__ = 'intelligence_package_state'
    id = Column(Integer, primary_key=True)
    status = Column(String(40), nullable=False)
    last_error = Column(Text)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

for model in (IntelligenceRecord, IntelligencePackageInstall, IntelligencePackageCatalog, IntelligencePackageMember):
    for operation in ('update', 'delete'):
        event.listen(model, 'before_' + operation, _reject_revision_mutation)
        table = model.__tablename__
        event.listen(model.__table__, 'after_create', DDL(
            f"CREATE TRIGGER {table}_deny_{operation} BEFORE {operation.upper()} ON {table} BEGIN SELECT RAISE(ABORT, 'Intelligence revisions are immutable'); END"
        ).execute_if(dialect='sqlite'))
    event.listen(model.__table__, 'after_create', DDL(
        f"CREATE OR REPLACE FUNCTION {table}_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'Intelligence revisions are immutable'; END; $$ LANGUAGE plpgsql"
    ).execute_if(dialect='postgresql'))
    event.listen(model.__table__, 'after_create', DDL(
        f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION {table}_immutable()"
    ).execute_if(dialect='postgresql'))
