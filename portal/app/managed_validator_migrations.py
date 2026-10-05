"""Preserve legacy validator records while upgrading the Docker-host schema."""
from sqlalchemy import inspect, text, MetaData, Table
from sqlalchemy.schema import CreateTable


def upgrade_connection(connection):
    if "managed_validators" not in inspect(connection).get_table_names():
        return
    columns = {c["name"] for c in inspect(connection).get_columns("managed_validators")}
    additions = {
        "ssh_username": "VARCHAR(64) DEFAULT 'ubuntu' NOT NULL",
        "fingerprint": "VARCHAR(120)",
        "fingerprint_confirmed": "BOOLEAN DEFAULT FALSE NOT NULL",
        "identity": "JSON DEFAULT '{}' NOT NULL",
        "last_health": "JSON DEFAULT '{}' NOT NULL",
        "image": "JSON DEFAULT '{}' NOT NULL",
        "active_operation_id": "VARCHAR(64)",
        "active_validation_id": "VARCHAR(64)",
        "last_contact_at": "TIMESTAMP",
        "updated_at": "TIMESTAMP",
    }
    for name, definition in additions.items():
        if name not in columns:
            connection.execute(text(f"ALTER TABLE managed_validators ADD COLUMN {name} {definition}"))
    # Only backfill newly introduced fields; never overwrite later administrator edits.
    for target, source in (("ssh_username", "username"), ("fingerprint", "ssh_fingerprint"),
                           ("last_health", "health"), ("last_contact_at", "last_seen"),
                           ("updated_at", "created_at")):
        if target not in columns and source in columns:
            connection.execute(text(f"UPDATE managed_validators SET {target} = {source} WHERE {source} IS NOT NULL"))
    connection.execute(text("UPDATE managed_validators SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"))
    # Retain obsolete columns and their data, but allow the new writer to omit them.
    legacy = {"username": "'ubuntu'", "labels": "'{}'", "enabled": "TRUE", "health": "'{}'"}
    legacy = {name: default for name, default in legacy.items() if name in columns}
    if connection.dialect.name == "postgresql":
        for name, default in legacy.items():
            connection.execute(text(f"ALTER TABLE managed_validators ALTER COLUMN {name} SET DEFAULT {default}"))
    elif connection.dialect.name == "sqlite" and legacy:
        existing = {c["name"]: c for c in inspect(connection).get_columns("managed_validators")}
        if all(existing[name].get("default") is not None for name in legacy):
            return
        # SQLite cannot alter column defaults. Preserve all columns, rows and indexes.
        if connection.exec_driver_sql("PRAGMA foreign_keys").scalar():
            raise RuntimeError("Legacy SQLite validator upgrade requires foreign_keys disabled before the migration transaction")
        metadata = MetaData()
        table = Table("managed_validators", metadata, autoload_with=connection)
        indexes = [str(__import__("sqlalchemy").schema.CreateIndex(index).compile(dialect=connection.dialect)) for index in table.indexes]
        from sqlalchemy import DefaultClause
        for name, default in legacy.items():
            table.c[name].server_default = DefaultClause(text(default))
        table.name = "managed_validators_upgrade"
        connection.execute(CreateTable(table))
        names = ", ".join(connection.dialect.identifier_preparer.quote(c.name) for c in table.columns)
        connection.exec_driver_sql(f"INSERT INTO managed_validators_upgrade ({names}) SELECT {names} FROM managed_validators")
        connection.exec_driver_sql("DROP TABLE managed_validators")
        connection.exec_driver_sql("ALTER TABLE managed_validators_upgrade RENAME TO managed_validators")
        for statement in indexes:
            connection.exec_driver_sql(statement)
