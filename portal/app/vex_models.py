"""Additive VEX evidence storage; revisions are append-only via service API."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, UniqueConstraint, JSON
from .database import Base

def utcnow():
    return datetime.now(timezone.utc)

class VexSource(Base):
    __tablename__ = 'vex_sources'
    id = Column(Integer, primary_key=True)
    name = Column(String(200), unique=True, nullable=False)
    allowed_hosts = Column(JSON, nullable=False, default=list)
    trusted = Column(Boolean, nullable=False, default=False)
    public_key = Column(Text)
    trust_reason = Column(Text)
    authoritative_prefixes = Column(JSON, nullable=False, default=list)
    max_age_days = Column(Integer, nullable=False, default=30)
    enabled = Column(Boolean, nullable=False, default=True)
    last_success = Column(DateTime(timezone=True))
    last_error = Column(Text)
    etags = Column(JSON, nullable=False, default=dict)

class VexDocument(Base):
    __tablename__ = 'vex_documents'
    __table_args__ = (UniqueConstraint('source_id', 'sha256'),)
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey('vex_sources.id'), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False)
    raw_text = Column(Text, nullable=False)
    format = Column(String(30), nullable=False)
    document_key = Column(Text, nullable=False)
    version = Column(String(100), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    retrieved_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    source_url = Column(Text)
    verification = Column(String(30), nullable=False, default='unverified')
    verification_key = Column(String(64))
    withdrawn = Column(Boolean, nullable=False, default=False)

class VexStatement(Base):
    __tablename__ = 'vex_statements'
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey('vex_documents.id'), nullable=False, index=True)
    cve = Column(String(40), nullable=False, index=True)
    product_id = Column(Text, nullable=False, index=True)
    identity = Column(JSON, nullable=False)
    status = Column(String(40), nullable=False)
    justification = Column(Text)
    impact = Column(Text)
    action = Column(Text)

class VexIngestionAudit(Base):
    __tablename__ = 'vex_ingestion_audits'
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey('vex_sources.id'), nullable=False, index=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    outcome = Column(String(40), nullable=False)
    detail = Column(Text)



# Service revisions and statements are immutable even if accidentally assigned by ORM callers.
from sqlalchemy import event

def _reject_revision_mutation(mapper, connection, target):
    raise ValueError('VEX revisions are immutable; ingest a new revision')

for _model in (VexDocument, VexStatement):
    event.listen(_model, 'before_update', _reject_revision_mutation)
    event.listen(_model, 'before_delete', _reject_revision_mutation)


# Bulk SQL must not bypass revision immutability or invalidate content-token assumptions.
from sqlalchemy import DDL
for _model in (VexDocument, VexStatement):
    _table = _model.__tablename__
    for _operation in ('UPDATE', 'DELETE'):
        event.listen(_model.__table__, 'after_create', DDL(
            f"CREATE TRIGGER {_table}_deny_{_operation.lower()} BEFORE {_operation} ON {_table} BEGIN SELECT RAISE(ABORT, 'VEX revisions are immutable'); END"
        ).execute_if(dialect='sqlite'))
    event.listen(_model.__table__, 'after_create', DDL(
        f"CREATE OR REPLACE FUNCTION {_table}_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'VEX revisions are immutable'; END; $$ LANGUAGE plpgsql"
    ).execute_if(dialect='postgresql'))
    event.listen(_model.__table__, 'after_create', DDL(
        f"CREATE TRIGGER {_table}_immutable BEFORE UPDATE OR DELETE ON {_table} FOR EACH ROW EXECUTE FUNCTION {_table}_immutable()"
    ).execute_if(dialect='postgresql'))
