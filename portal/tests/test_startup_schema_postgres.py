"""Repeat the real startup migrations while PostgreSQL has active readers/writers."""
import ast
import os
from pathlib import Path
import time
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError

from app.exchange_migrations import migration_transaction
from app.service_ownership_migrations import upgrade_connection as upgrade_ownership


@pytest.fixture
def pg_engine():
    url = os.environ.get("CATS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("Set CATS_TEST_POSTGRES_URL for isolated PostgreSQL integration checks")
    admin = create_engine(url)
    assert admin.dialect.name == "postgresql"
    schema = "startup_test_" + uuid.uuid4().hex
    scoped = create_engine(url, connect_args={"options": f"-c search_path={schema}"})
    try:
        with admin.begin() as connection:
            connection.execute(text(f"CREATE SCHEMA {schema}"))
        yield scoped
    finally:
        scoped.dispose()
        with admin.begin() as connection:
            connection.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
        admin.dispose()


def test_full_startup_repeats_without_blocking_active_table_users(pg_engine):
    from app import main

    # Execute the actual migration body, including metadata hooks and every
    # additive migration. Importing main uses conftest's disposable SQLite DB.
    tree = ast.parse(Path(main.__file__).read_text(encoding="utf-8-sig"))
    migration = next(node for node in tree.body if isinstance(node, ast.With)
        and isinstance(node.items[0].context_expr, ast.Call)
        and getattr(node.items[0].context_expr.func, "id", None) == "migration_transaction")
    code = compile(ast.fix_missing_locations(ast.Module(body=migration.body, type_ignores=[])),
                   "startup_migrations", "exec")

    def run_startup(connection):
        namespace = dict(vars(main), connection=connection)
        exec(code, namespace)

    with migration_transaction(pg_engine) as connection:
        run_startup(connection)
        trigger_oid = connection.execute(text("SELECT oid FROM pg_trigger WHERE "
            "tgrelid = 'service_groups'::regclass AND tgname = 'cats_service_owner'")).scalar_one()
        tables = inspect(connection).get_table_names()
    with pg_engine.connect() as active_user:
        # ROW EXCLUSIVE is the lock an open INSERT/UPDATE/DELETE holds; it also
        # catches redundant CREATE INDEX, which a read-only transaction won't.
        active_user.execute(text("LOCK TABLE " + ", ".join(f'"{name}"' for name in tables)
                                 + " IN ROW EXCLUSIVE MODE"))
        try:
            with migration_transaction(pg_engine) as connection:
                connection.execute(text("SET LOCAL lock_timeout = '250ms'"))
                run_startup(connection)
                assert connection.execute(text("SELECT oid FROM pg_trigger WHERE "
                    "tgrelid = 'service_groups'::regclass AND tgname = 'cats_service_owner'")).scalar_one() == trigger_oid
        finally:
            active_user.rollback()


def test_ownership_preserves_conflicts_and_enforces_repairs(pg_engine):
    with pg_engine.begin() as connection:
        connection.execute(text("CREATE TABLE services (id INTEGER PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE service_groups (service_id INTEGER, group_id INTEGER, "
                                "PRIMARY KEY (service_id, group_id))"))
        connection.execute(text("INSERT INTO services VALUES (1), (2)"))
        connection.execute(text("INSERT INTO service_groups VALUES (1, 10), (1, 20), (2, 10)"))
        upgrade_ownership(connection)
        upgrade_ownership(connection)
        assert connection.execute(text("SELECT COUNT(*) FROM service_groups")).scalar_one() == 3
        assert "uq_service_owning_group_index" not in {
            index["name"] for index in inspect(connection).get_indexes("service_groups")}
    with pytest.raises(DBAPIError, match="already has an owning group"):
        with pg_engine.begin() as connection:
            connection.execute(text("INSERT INTO service_groups VALUES (2, 30)"))
    with pg_engine.begin() as connection:
        connection.execute(text("DELETE FROM service_groups WHERE service_id = 1 AND group_id = 20"))
        connection.execute(text("UPDATE service_groups SET group_id = 30 WHERE service_id = 2"))
        upgrade_ownership(connection)
        assert "uq_service_owning_group_index" in {
            index["name"] for index in inspect(connection).get_indexes("service_groups")}
    with pytest.raises(DBAPIError):
        with pg_engine.begin() as connection:
            connection.execute(text("INSERT INTO service_groups VALUES (2, 40)"))


def test_blocked_real_upgrade_times_out_and_rolls_back(pg_engine):
    with pg_engine.begin() as connection:
        connection.execute(text("CREATE TABLE upgrade_target (id INTEGER PRIMARY KEY)"))
    with pg_engine.connect() as reader:
        reader.execute(text("SELECT * FROM upgrade_target"))
        started = time.monotonic()
        try:
            with pytest.raises(DBAPIError) as failure:
                with migration_transaction(pg_engine) as connection:
                    assert connection.execute(text("SHOW lock_timeout")).scalar_one() == "5s"
                    connection.execute(text("CREATE TABLE rollback_probe (id INTEGER)"))
                    connection.execute(text("ALTER TABLE upgrade_target ADD COLUMN value TEXT"))
            assert failure.value.orig.sqlstate == "55P03"  # lock_not_available
            assert time.monotonic() - started < 12
        finally:
            reader.rollback()
    with pg_engine.connect() as connection:
        assert "rollback_probe" not in inspect(connection).get_table_names()
        assert {column["name"] for column in inspect(connection).get_columns("upgrade_target")} == {"id"}
        assert connection.execute(text("SHOW lock_timeout")).scalar_one() == "0"
