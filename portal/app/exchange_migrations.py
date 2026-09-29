"""Additive exchange migration, safe for existing SQLite/PostgreSQL installs."""
from contextlib import contextmanager
import logging
from sqlalchemy import inspect, text


@contextmanager
def migration_transaction(engine):
    """Serialize all schema inspection and DDL across starting portal workers."""
    with engine.connect() as connection:
        try:
            if connection.dialect.name == "sqlite":
                # Explicit BEGIN also makes SQLite DDL transactional.
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                connection.begin()
                if connection.dialect.name == "postgresql":
                    connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 485018035649})
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise


def upgrade(engine):
    with migration_transaction(engine) as connection:
        upgrade_connection(connection)


def upgrade_connection(connection):
    tables = set(inspect(connection).get_table_names())
    if "services" in tables and "assessment_status" not in {c["name"] for c in inspect(connection).get_columns("services")}:
        connection.execute(text("ALTER TABLE services ADD COLUMN assessment_status VARCHAR(32) DEFAULT 'assessment_pending'"))
        if "executions" in tables:
            connection.execute(text("UPDATE services SET assessment_status = 'assessed' WHERE EXISTS (SELECT 1 FROM executions WHERE executions.service_id = services.id)"))
    columns = {c["name"] for c in inspect(connection).get_columns("poam_entries")}
    for name, kind in [("service_version", "VARCHAR(120)"), ("exchange_key", "VARCHAR(64)"), ("supplemental_fields", "JSON")]:
        if name not in columns:
            connection.execute(text(f"ALTER TABLE poam_entries ADD COLUMN {name} {kind}"))
    tables = set(inspect(connection).get_table_names())
    for table in ("bundle_previews", "exchange_previews"):
        if table in tables:
            connection.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_expiry_token ON {table} (expires_at, token)"))
    if "service_id" not in columns:
        return
    duplicates = connection.execute(text(
        "SELECT 1 FROM poam_entries WHERE exchange_key IS NOT NULL "
        "GROUP BY service_id, COALESCE(service_version, ''), exchange_key HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    if duplicates:
        # Historical evidence is never deleted or merged by a startup migration.
        logging.getLogger(__name__).warning("Duplicate POAM exchange identities exist; unique index deferred until administrator reconciliation")
    else:
        connection.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_poam_exchange_identity "
            "ON poam_entries (service_id, COALESCE(service_version, ''), exchange_key) "
            "WHERE exchange_key IS NOT NULL"
        ))
