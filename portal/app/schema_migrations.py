"""Helpers for startup DDL that avoids locking already-current tables."""
from sqlalchemy import inspect, text


def upgrade_topic_scopes(connection):
    """Extend existing group sources and bindings without rewriting scan history."""
    additions = {
        "gitlab_topic_sources": {"latest_preview_job_id": "VARCHAR(32) REFERENCES durable_jobs(id)"},
        "topic_projects": {"claim_group_id": "INTEGER REFERENCES groups(id)", "observed_topics": "JSON"},
    }
    for table, columns in additions.items():
        existing = {column["name"] for column in inspect(connection).get_columns(table)}
        for name, sql_type in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))


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
