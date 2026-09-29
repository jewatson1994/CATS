import asyncio
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import BundlePreview, ExchangePreview, utcnow
from app.exchange_migrations import migration_transaction, upgrade_connection
from app.preview_cleanup import cleanup_expired_previews, expired_delete_statement, preview_cleanup_lifespan


def test_migration_is_repeatable_and_creates_provenance_and_expiry_indexes():
    engine = create_engine("sqlite://")
    for _ in range(2):
        with migration_transaction(engine) as connection:
            Base.metadata.create_all(connection)
            upgrade_connection(connection)
    assert "service_transfer_provenance" in inspect(engine).get_table_names()
    assert "ix_bundle_previews_expiry_token" in {item["name"] for item in inspect(engine).get_indexes("bundle_previews")}


def test_sqlite_migration_ddl_rolls_back_on_failure():
    engine = create_engine("sqlite://")
    with pytest.raises(RuntimeError):
        with migration_transaction(engine) as connection:
            connection.execute(text("CREATE TABLE rollback_probe (id INTEGER)"))
            raise RuntimeError("failed")
    assert "rollback_probe" not in inspect(engine).get_table_names()


def test_duplicate_exchange_identity_preserves_evidence_and_defers_index(caplog):
    engine = create_engine("sqlite://")
    with migration_transaction(engine) as connection:
        connection.execute(text("CREATE TABLE poam_entries (id INTEGER PRIMARY KEY, service_id INTEGER, service_version VARCHAR(120), exchange_key VARCHAR(64))"))
        connection.execute(text("INSERT INTO poam_entries VALUES (1, 1, NULL, 'key'), (2, 1, '', 'key')"))
        upgrade_connection(connection)
        assert connection.execute(text("SELECT COUNT(*) FROM poam_entries")).scalar_one() == 2
        assert not connection.execute(text("SELECT name FROM sqlite_master WHERE name = 'ux_poam_exchange_identity'")).first()
    assert "unique index deferred" in caplog.text


def test_postgres_schema_compiles_including_provenance():
    from sqlalchemy.schema import CreateTable
    for table in Base.metadata.sorted_tables:
        sql = str(CreateTable(table).compile(dialect=postgresql.dialect()))
        assert "CREATE TABLE" in sql


def test_postgres_lock_is_transaction_scoped_and_precedes_schema_work():
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.dialect.name = "postgresql"
    with migration_transaction(engine) as acquired:
        assert acquired is connection
        connection.begin.assert_called_once()
        statement, parameters = connection.execute.call_args.args
        assert str(statement) == "SELECT pg_advisory_xact_lock(:key)"
        assert isinstance(parameters["key"], int)
        connection.commit.assert_not_called()
    connection.commit.assert_called_once()


def test_postgres_cleanup_compiles_bounded_subquery():
    sql = str(expired_delete_statement(BundlePreview, utcnow(), 7).compile(dialect=postgresql.dialect()))
    assert "DELETE FROM bundle_previews" in sql
    assert "ORDER BY" in sql and "LIMIT" in sql
    assert sql.count("expires_at <=") == 2


def test_cleanup_bounds_each_table_and_preserves_live_previews():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine)
    now = utcnow()
    with sessions.begin() as session:
        for model in (BundlePreview, ExchangePreview):
            for index in range(5):
                fields = {"token": f"token-{index}", "user_id": 1, "payload": {},
                          "expires_at": now + timedelta(days=1 if index == 4 else -1)}
                fields.update({"target_key": "target"} if model is BundlePreview else
                              {"service_id": 1, "version": "1", "dataset": "poam"})
                session.add(model(**fields))
    assert cleanup_expired_previews(sessions, 2) == 4
    assert cleanup_expired_previews(sessions, 2) == 4
    assert cleanup_expired_previews(sessions, 2) == 0
    with sessions() as session:
        assert session.scalars(select(BundlePreview.token)).all() == ["token-4"]
        assert session.scalars(select(ExchangePreview.token)).all() == ["token-4"]


def test_lifespan_stops_sleeping_worker_without_waiting_interval(monkeypatch):
    import threading
    monkeypatch.setenv("CATS_PREVIEW_CLEANUP_INTERVAL_SECONDS", "300")
    async def exercise():
        async with preview_cleanup_lifespan(MagicMock()):
            assert any(t.name == "cats-preview-cleanup" for t in threading.enumerate())
        assert not any(t.name == "cats-preview-cleanup" for t in threading.enumerate())
    asyncio.run(exercise())
