"""Helpers for startup DDL that avoids locking already-current tables."""
from sqlalchemy import text


def create_index_if_missing(connection, table, name, statement):
    # PostgreSQL takes a table lock even for CREATE INDEX IF NOT EXISTS when
    # the index already exists. Inspect its catalog before issuing that DDL.
    # Resolve the target table through the same search_path as the DDL; it can
    # live in a later schema than current_schema().
    # Startup callers hold the shared migration advisory lock around this check.
    if connection.dialect.name == "postgresql":
        exists = connection.execute(text(
            "SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
            "WHERE i.indrelid = to_regclass(:table) AND c.relname = :name"
        ), {"table": table, "name": name}).first()
        if exists:
            return
    connection.execute(text(statement))
