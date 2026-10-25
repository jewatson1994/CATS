"""Materialized native VEX evidence. Scanner records are never mutated.

Generation triggers cover ORM and Core/bulk writes in the same transaction.
Readers must use the predicates in native_vex, never the stored verdict alone.
"""
from sqlalchemy import (Column, Integer, String, Boolean, DateTime, ForeignKey,
                        JSON, UniqueConstraint, event, text)
from .database import Base
from .vex_models import utcnow

class VexDispositionPolicy(Base):
    __tablename__ = 'vex_disposition_policy'
    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, nullable=False, default=False)
    generation = Column(Integer, nullable=False, default=1)
    policy_version = Column(Integer, nullable=False, default=1)

class VexDispositionService(Base):
    __tablename__ = 'vex_disposition_services'
    service_id = Column(Integer, ForeignKey('services.id', ondelete='CASCADE'), primary_key=True)
    generation = Column(Integer, nullable=False, default=1)
    evaluation_id = Column(Integer, nullable=True)

class VexDispositionEvaluation(Base):
    __tablename__ = 'vex_disposition_evaluations'
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey('services.id', ondelete='CASCADE'), nullable=False, index=True)
    execution_id = Column(Integer, nullable=False)
    service_generation = Column(Integer, nullable=False)
    intelligence_generation = Column(Integer, nullable=False)
    policy_version = Column(Integer, nullable=False)
    algorithm = Column(String(100), nullable=False)
    evaluated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    valid_until = Column(DateTime(timezone=True), nullable=False)
    summary = Column(JSON, nullable=False, default=dict)

class VexObservationDisposition(Base):
    __tablename__ = 'vex_observation_dispositions'
    __table_args__ = (UniqueConstraint('evaluation_id', 'observation_id'),)
    id = Column(Integer, primary_key=True)
    evaluation_id = Column(Integer, ForeignKey('vex_disposition_evaluations.id', ondelete='CASCADE'), nullable=False, index=True)
    observation_id = Column(Integer, nullable=False, index=True)
    finding_id = Column(Integer, nullable=False, index=True)
    excluded = Column(Boolean, nullable=False)
    evidence = Column(JSON, nullable=False)

class VexFindingDisposition(Base):
    __tablename__ = 'vex_finding_dispositions'
    __table_args__ = (UniqueConstraint('evaluation_id', 'finding_id'),)
    id = Column(Integer, primary_key=True)
    evaluation_id = Column(Integer, ForeignKey('vex_disposition_evaluations.id', ondelete='CASCADE'), nullable=False, index=True)
    finding_id = Column(Integer, nullable=False, index=True)
    observations = Column(Integer, nullable=False)
    excluded_observations = Column(Integer, nullable=False)


def install_generation_triggers(connection):
    """Idempotent additive migration; do not enumerate or reassess the corpus."""
    dialect = connection.dialect.name
    if dialect not in ('sqlite', 'postgresql'):
        raise RuntimeError('Native VEX requires PostgreSQL or SQLite')
    connection.execute(text('INSERT INTO vex_disposition_policy (id, enabled, generation, policy_version) '
                            'VALUES (1, false, 1, 1) ON CONFLICT (id) DO NOTHING'))
    # Insert-only evidence revisions are already immutable at the database layer.
    global_tables = ('vex_sources', 'vex_documents', 'intelligence_package_installs',
                     'intelligence_package_state', 'portal_settings')
    service_tables = ('findings', 'finding_observations', 'executions', 'sbom_components')
    from sqlalchemy import inspect
    existing = set(inspect(connection).get_table_names())
    if {'executions', 'sbom_components'} <= existing:
        # A payload replacement invalidates its old projection in the same
        # transaction, including direct SQL writes. Never re-use stale SBOM rows
        # after re-evaluation; an explicit reindex can reconstruct new rows.
        name = 'sbom_execution_payload_changed'
        body = 'DELETE FROM sbom_components WHERE execution_id = NEW.id;'
        if dialect == 'sqlite':
            connection.execute(text(f'DROP TRIGGER IF EXISTS {name}'))
            connection.execute(text(f'CREATE TRIGGER {name} AFTER UPDATE OF raw_payload ON executions '
                f'WHEN OLD.raw_payload IS NOT NEW.raw_payload BEGIN {body} END'))
        else:
            connection.execute(text(f'CREATE OR REPLACE FUNCTION {name}_fn() RETURNS trigger AS $$ '
                f'BEGIN IF OLD.raw_payload::text IS DISTINCT FROM NEW.raw_payload::text THEN {body} END IF; '
                'RETURN NULL; END; $$ LANGUAGE plpgsql'))
            connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '{name}' "
                f"AND tgrelid = 'executions'::regclass) THEN CREATE TRIGGER {name} AFTER UPDATE OF raw_payload ON executions "
                f"FOR EACH ROW EXECUTE FUNCTION {name}_fn(); END IF; END $$"))
    for table in (*global_tables, *service_tables):
        if table not in existing:
            continue
        for operation in ('INSERT', 'UPDATE', 'DELETE'):
            name = 'native_vex_' + table + '_' + operation.lower()
            refs = ['NEW'] if operation == 'INSERT' else ['OLD'] if operation == 'DELETE' else ['OLD', 'NEW']
            if table in global_tables:
                body = 'UPDATE vex_disposition_policy SET generation = generation + 1 WHERE id = 1;'
                if table == 'portal_settings':
                    checks = ' OR '.join(f"{ref}.key NOT IN ('authorization_revision', 'service_posture_epoch')" for ref in refs)
                    body = f'UPDATE vex_disposition_policy SET generation = generation + 1 WHERE id = 1 AND ({checks});'
            else:
                statements = []
                for ref in refs:
                    expr = (f'(SELECT service_id FROM findings WHERE id = {ref}.finding_id)'
                            if table == 'finding_observations' else
                            f'(SELECT service_id FROM executions WHERE id = {ref}.execution_id)'
                            if table == 'sbom_components' else f'{ref}.service_id')
                    statements.append('INSERT INTO vex_disposition_services (service_id, generation) '
                        f'SELECT {expr}, 1 WHERE {expr} IS NOT NULL AND EXISTS (SELECT 1 FROM services WHERE id = {expr}) '
                        'ON CONFLICT (service_id) DO UPDATE SET generation = vex_disposition_services.generation + 1;')
                body = '\n'.join(statements)
            if dialect == 'sqlite':
                connection.execute(text(f'DROP TRIGGER IF EXISTS {name}'))
                connection.execute(text(f'CREATE TRIGGER {name} AFTER {operation} ON {table} BEGIN {body} END'))
            else:
                connection.execute(text(f'CREATE OR REPLACE FUNCTION {name}_fn() RETURNS trigger AS $$ BEGIN {body} RETURN NULL; END; $$ LANGUAGE plpgsql'))
                connection.execute(text(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '{name}' AND tgrelid = '{table}'::regclass) THEN CREATE TRIGGER {name} AFTER {operation} ON {table} FOR EACH ROW EXECUTE FUNCTION {name}_fn(); END IF; END $$"))

@event.listens_for(Base.metadata, 'after_create')
def _install(metadata, connection, **kwargs):
    from sqlalchemy import inspect
    # Subset schema creation (offline intelligence tools) has no disposition tables.
    existing = set(inspect(connection).get_table_names())
    if {'vex_disposition_policy', 'vex_disposition_services'} <= existing:
        install_generation_triggers(connection)
