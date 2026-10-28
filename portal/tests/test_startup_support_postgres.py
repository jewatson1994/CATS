"""Opt-in startup checks against an independently owned PostgreSQL schema."""
import os
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text

from app.intelligence_generation import install_generation_triggers
from app.managed_validator_migrations import upgrade_connection
from app.schema_migrations import create_index_if_missing


@pytest.fixture
def postgres_engine():
    url = os.environ.get("CATS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("Set CATS_TEST_POSTGRES_URL for isolated PostgreSQL startup checks")
    admin = create_engine(url)
    assert admin.dialect.name == "postgresql"
    schema = "startup_support_" + uuid.uuid4().hex
    isolated = None
    created = False
    try:
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        created = True
        isolated = create_engine(url, connect_args={"options": f"-c search_path={schema}"})
        yield isolated
    finally:
        if isolated is not None:
            isolated.dispose()
        if created:
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def test_validator_restart_preserves_legacy_data_and_defaults_with_live_reader(postgres_engine):
    with postgres_engine.begin() as connection:
        connection.execute(text("""CREATE TABLE managed_validators (
            id VARCHAR(32) PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            labels JSON NOT NULL,
            enabled BOOLEAN NOT NULL,
            health JSON NOT NULL,
            ssh_fingerprint VARCHAR(100),
            last_seen TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""))
        connection.execute(text("""INSERT INTO managed_validators
            (id, username, labels, enabled, health, ssh_fingerprint, last_seen)
            VALUES ('legacy', 'legacy-user', :labels, false, :health,
                    'SHA256:legacy', '2026-01-02 03:04:05')"""),
            {"labels": '{"team": "security"}', "health": '{"status": "healthy"}'})
        upgrade_connection(connection)
        old = connection.execute(text("SELECT * FROM managed_validators WHERE id = 'legacy'")).mappings().one()
        assert old["username"] == old["ssh_username"] == "legacy-user"
        assert old["fingerprint"] == "SHA256:legacy"
        assert old["labels"] == {"team": "security"}
        assert old["last_health"] == old["health"] == {"status": "healthy"}
        assert old["last_contact_at"] == old["last_seen"]
        assert old["updated_at"] == old["created_at"]
        assert old["enabled"] is False
        defaults = {column["name"]: column["default"]
                    for column in inspect(connection).get_columns("managed_validators")}
        assert all(defaults[name] is not None for name in ("username", "labels", "enabled", "health"))
        connection.execute(text("ALTER TABLE managed_validators ALTER COLUMN username SET DEFAULT 'operator'"))
        connection.execute(text("UPDATE managed_validators SET ssh_username = 'administrator-edit' WHERE id = 'legacy'"))
        preserved = dict(connection.execute(text("SELECT * FROM managed_validators WHERE id = 'legacy'")).mappings().one())

    with postgres_engine.connect() as reader:
        reader.execute(text("SELECT id FROM managed_validators")).all()
        for _ in range(2):
            with postgres_engine.begin() as connection:
                connection.execute(text("SET LOCAL lock_timeout = '250ms'"))
                upgrade_connection(connection)
                assert dict(connection.execute(text("SELECT * FROM managed_validators WHERE id = 'legacy'")).mappings().one()) == preserved
        reader.rollback()

    with postgres_engine.begin() as connection:
        connection.execute(text("INSERT INTO managed_validators (id) VALUES ('new')"))
        new = connection.execute(text("SELECT * FROM managed_validators WHERE id = 'new'")).mappings().one()
        assert new["username"] == "operator"
        assert new["labels"] == new["health"] == {}
        assert new["enabled"] is True


def test_intelligence_restart_keeps_trigger_with_live_reader_and_fences_mutations(postgres_engine):
    trigger = text("""SELECT oid FROM pg_trigger
        WHERE tgname = 'cats_generation_touch' AND tgrelid = 'vex_sources'::regclass""")
    token = text("SELECT token FROM intelligence_generation WHERE id = 1")
    with postgres_engine.begin() as connection:
        connection.execute(text("CREATE TABLE intelligence_generation (id INTEGER PRIMARY KEY, token VARCHAR(36) NOT NULL)"))
        connection.execute(text("CREATE TABLE vex_sources (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"))
        install_generation_triggers(connection)
        original_oid = connection.execute(trigger).scalar_one()
        original_token = connection.execute(token).scalar_one()

    with postgres_engine.connect() as reader:
        reader.execute(text("SELECT id FROM vex_sources")).all()
        for _ in range(2):
            with postgres_engine.begin() as connection:
                connection.execute(text("SET LOCAL lock_timeout = '250ms'"))
                install_generation_triggers(connection)
                assert connection.execute(trigger).scalar_one() == original_oid
                assert connection.execute(token).scalar_one() == original_token
        reader.rollback()

    previous = original_token
    for statement in (
        "INSERT INTO vex_sources VALUES (1, 'original')",
        "UPDATE vex_sources SET name = 'changed' WHERE id = 1",
        "DELETE FROM vex_sources WHERE id = 1",
        "TRUNCATE vex_sources",
    ):
        with postgres_engine.begin() as connection:
            connection.execute(text(statement))
            current = connection.execute(token).scalar_one()
            assert current != previous, statement
            previous = current


def test_index_guard_follows_target_table_search_path_with_live_writer(postgres_engine):
    shadow = "startup_shadow_" + uuid.uuid4().hex
    created = False
    try:
        with postgres_engine.begin() as connection:
            target_schema = connection.execute(text("SELECT current_schema()")).scalar_one()
            connection.execute(text(f'CREATE SCHEMA "{shadow}"'))
            created = True
            connection.execute(text("CREATE TABLE startup_target (id INTEGER PRIMARY KEY)"))
            connection.execute(text(f'CREATE TABLE "{shadow}".other_target (id INTEGER PRIMARY KEY)'))
            connection.execute(text(f'CREATE INDEX startup_target_index ON "{shadow}".other_target (id)'))
            search_path = text(f'SET LOCAL search_path = "{shadow}", "{target_schema}"')
            connection.execute(search_path)
            assert connection.execute(text("SELECT current_schema()")).scalar_one() == shadow
            # An unrelated index in the first schema must not hide a missing
            # index on the table resolved from the later application schema.
            statement = "CREATE INDEX IF NOT EXISTS startup_target_index ON startup_target (id)"
            create_index_if_missing(connection, "startup_target", "startup_target_index", statement)
            assert "startup_target_index" in {
                item["name"] for item in inspect(connection).get_indexes("startup_target", schema=target_schema)}
            connection.execute(text(f'DROP INDEX "{shadow}".startup_target_index'))

        with postgres_engine.connect() as writer:
            writer.execute(search_path)
            writer.execute(text("LOCK TABLE startup_target IN ROW EXCLUSIVE MODE"))
            with postgres_engine.begin() as connection:
                connection.execute(search_path)
                connection.execute(text("SET LOCAL lock_timeout = '250ms'"))
                # No index remains in the first schema: finding the existing
                # target index must still avoid CREATE INDEX's table lock.
                create_index_if_missing(connection, "startup_target", "startup_target_index", statement)
            writer.rollback()
    finally:
        if created:
            with postgres_engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{shadow}" CASCADE'))
