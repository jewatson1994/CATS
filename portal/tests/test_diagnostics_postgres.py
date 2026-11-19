"""Opt-in PostgreSQL acceptance; each test owns a disposable schema."""
from datetime import datetime, timedelta, timezone
import json
import os
import uuid

import pytest
from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.orm import sessionmaker

from app.diagnostic_migrations import upgrade_connection
from app.diagnostic_store import DiagnosticEvent, cleanup, record_diagnostic
from app.diagnostics import build_diagnostic


@pytest.fixture
def postgres():
    url = os.getenv("CATS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("Requires disposable CATS_TEST_POSTGRES_URL")
    assert url.startswith("postgresql")
    admin = create_engine(url)
    schema = "diagnostics_test_" + uuid.uuid4().hex
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield engine, sessionmaker(bind=engine, expire_on_commit=False)
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def test_postgres_migration_repairs_indexes_without_changing_existing_evidence(postgres):
    engine, sessions = postgres
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE existing_evidence (id INTEGER PRIMARY KEY, body JSON NOT NULL)"))
        connection.execute(text("INSERT INTO existing_evidence VALUES (1, CAST(:body AS JSON))"),
                           {"body": json.dumps({"retained": True})})
        upgrade_connection(connection)
    item = build_diagnostic(RuntimeError("vendor E567 token=hidden-value"), component="PostgreSQL acceptance", operation="migration")
    assert record_diagnostic(item, sessions)
    index = next(index for index in DiagnosticEvent.__table__.indexes if index.name == "ix_diagnostic_component_time")
    with engine.begin() as connection:
        index.drop(connection)
        upgrade_connection(connection)
        upgrade_connection(connection)
    actual = {index["name"]: index["column_names"] for index in inspect(engine).get_indexes("diagnostic_events")}
    for expected in DiagnosticEvent.__table__.indexes:
        assert actual[expected.name] == [column.name for column in expected.columns]
    with sessions() as db:
        assert db.execute(text("SELECT body FROM existing_evidence WHERE id=1")).scalar_one() == {"retained": True}
        stored = db.get(DiagnosticEvent, item["error_id"])
        assert stored.timestamp.tzinfo is not None
        assert stored.diagnostic["error_id"] == item["error_id"]
        assert "E567" in json.dumps(stored.diagnostic)
        assert "hidden-value" not in json.dumps(stored.diagnostic)


def test_postgres_retention_and_persistence_survive_request_rollback(postgres, monkeypatch):
    engine, sessions = postgres
    with engine.begin() as connection:
        upgrade_connection(connection)
        connection.execute(text("CREATE TABLE request_work (id INTEGER PRIMARY KEY)"))
    item = build_diagnostic(TimeoutError("scan timed out"), component="PostgreSQL acceptance", operation="rollback", resource={"job_id": "failed-job"})
    with sessions() as request_db:
        request_db.execute(text("INSERT INTO request_work VALUES (1)"))
        assert record_diagnostic(item, sessions)
        request_db.rollback()
    assert record_diagnostic(item, sessions)
    with sessions() as db:
        assert db.execute(text("SELECT count(*) FROM request_work")).scalar_one() == 0
        assert db.scalar(select(func.count()).select_from(DiagnosticEvent)) == 1
        db.get(DiagnosticEvent, item["error_id"]).timestamp = datetime.now(timezone.utc) - timedelta(days=40)
        db.commit()
        cleanup(db)
        db.commit()
        assert db.get(DiagnosticEvent, item["error_id"]) is None
    monkeypatch.setenv("CATS_DIAGNOSTIC_MAX_EVENTS", "100")
    for number in range(104):
        assert record_diagnostic(build_diagnostic("failure", component="PostgreSQL acceptance", operation=str(number)), sessions)
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(DiagnosticEvent)) == 100
