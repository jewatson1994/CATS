"""Visual risk projections and append-only Cyber governance records."""
from datetime import datetime
from sqlalchemy import DateTime, Integer, JSON, String, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import utcnow

class RiskPolicyVersion(Base):
    __tablename__ = 'risk_policy_versions'
    __table_args__ = (UniqueConstraint('name', 'version'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    version: Mapped[int] = mapped_column(Integer)
    configuration: Mapped[dict] = mapped_column(JSON)
    digest: Mapped[str] = mapped_column(String(64))
    parent_policy_id: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String(240))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class RiskPolicyGroup(Base):
    """Additive ownership for new profiles; unscoped historical versions stay intact."""
    __tablename__ = 'risk_policy_groups'
    display_name: Mapped[str] = mapped_column(String(120))
    policy_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(Integer, index=True)

class RiskPolicyAssignment(Base):
    __tablename__ = 'risk_policy_assignments'
    id: Mapped[int] = mapped_column(primary_key=True)
    scope: Mapped[str] = mapped_column(String(20), index=True)
    scope_id: Mapped[int] = mapped_column(Integer, default=0, index=True)
    policy_id: Mapped[int | None] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String(240))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class RiskAssessment(Base):
    __tablename__ = 'risk_assessments'
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(Integer, index=True)
    policy_id: Mapped[int | None] = mapped_column(Integer)
    source_execution_id: Mapped[int | None] = mapped_column(Integer)
    as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    provenance: Mapped[dict] = mapped_column(JSON)
    summary: Mapped[dict] = mapped_column(JSON)
    details: Mapped[list] = mapped_column(JSON)

class RiskDecision(Base):
    __tablename__ = 'risk_decisions'
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(Integer, index=True)
    assessment_id: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(32))
    decision: Mapped[str] = mapped_column(String(24))
    payload: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(240))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

def _immutable(mapper, connection, target):
    raise ValueError('Risk history is immutable; append a new record')

for _model in (RiskPolicyVersion, RiskPolicyGroup, RiskPolicyAssignment, RiskAssessment, RiskDecision):
    event.listen(_model, 'before_update', _immutable)
    event.listen(_model, 'before_delete', _immutable)

# Database guards also reject bulk SQL updates/deletes, not just ORM mutation.
from sqlalchemy import DDL
for _model in (RiskPolicyVersion, RiskPolicyGroup, RiskPolicyAssignment, RiskAssessment, RiskDecision):
    _table = _model.__tablename__
    for _operation in ('UPDATE', 'DELETE'):
        _name = _table + '_deny_' + _operation.lower()
        event.listen(_model.__table__, 'after_create', DDL(
            f"CREATE TRIGGER {_name} BEFORE {_operation} ON {_table} BEGIN SELECT RAISE(ABORT, 'Risk history is immutable'); END"
        ).execute_if(dialect='sqlite'))
    event.listen(_model.__table__, 'after_create', DDL(
        f"CREATE OR REPLACE FUNCTION {_table}_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'Risk history is immutable'; END; $$ LANGUAGE plpgsql"
    ).execute_if(dialect='postgresql'))
    event.listen(_model.__table__, 'after_create', DDL(
        f"CREATE TRIGGER {_table}_immutable BEFORE UPDATE OR DELETE ON {_table} FOR EACH ROW EXECUTE FUNCTION {_table}_immutable()"
    ).execute_if(dialect='postgresql'))
