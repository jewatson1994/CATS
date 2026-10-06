from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Execution, Service, DependencyProjection, DependencyProjectionRow
from app import dependency_queries as queries


def fixture(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "lifecycle.sqlite"))
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Service(id=1, service_key="test", name="Test"))
        db.add(Execution(id=1, execution_key="scan", service_id=1, complete=True,
            scanned_at=datetime.now(timezone.utc), payload_digest="a" * 64,
            raw_payload={"sbom_components": [{"name": "package", "version": "1"}]}))
        db.commit()
    risk = lambda cve: (False, None)
    risk.cache_token = lambda: "catalog"
    return engine, risk


def request(engine, risk, **kwargs):
    with Session(engine) as db:
        execution = SimpleNamespace(id=1, payload_digest=db.scalar(select(Execution.payload_digest).where(Execution.id == 1)))
        return queries.request_current_projection(db, execution, risk, **kwargs)


def test_cold_get_is_scalar_and_worker_activates_ready(tmp_path):
    engine, risk = fixture(tmp_path)
    sql = []
    def capture(conn, cursor, statement, params, context, many):
        sql.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    state = request(engine, risk)
    event.remove(engine, "before_cursor_execute", capture)
    assert state["status"] == "pending"
    assert not any("raw_payload" in statement or "finding_observations" in statement for statement in sql)
    assert queries.pending_dependency_page(state)["dependency_total"] is None
    assert request(engine, risk)["build_token"] == state["build_token"]
    assert queries.build_projection(engine, 1, state["build_token"], risk)
    assert request(engine, risk)["status"] == "ready"
    with Session(engine) as db:
        assert len(queries.dependency_page(db, 1)["dependency_rows"]) == 1
    assert not queries.build_projection(engine, 1, state["build_token"], risk)
    engine.dispose()


def test_failure_is_visible_and_retry_is_explicit(tmp_path, monkeypatch):
    engine, risk = fixture(tmp_path)
    state = request(engine, risk)
    original = queries.persist_current_projection
    monkeypatch.setattr(queries, "persist_current_projection", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("secret detail")))
    assert not queries.build_projection(engine, 1, state["build_token"], risk)
    failed = request(engine, risk)
    assert failed["status"] == "failed" and "secret detail" not in failed["error"]
    monkeypatch.setattr(queries, "persist_current_projection", original)
    retry = request(engine, risk, retry=True)
    assert retry["status"] == "pending" and retry["build_token"] != state["build_token"]
    assert queries.build_projection(engine, 1, retry["build_token"], risk)
    assert request(engine, risk)["status"] == "ready"
    engine.dispose()


def test_deleted_or_superseded_claim_cannot_activate(tmp_path):
    engine, risk = fixture(tmp_path)
    state = request(engine, risk)
    with Session(engine) as db:
        db.delete(db.get(DependencyProjection, 1)); db.commit()
    newer = request(engine, risk)
    assert newer["build_token"] != state["build_token"]
    assert not queries.build_projection(engine, 1, state["build_token"], risk)
    with Session(engine) as db:
        assert db.scalar(select(DependencyProjectionRow)) is None
    assert queries.build_projection(engine, 1, newer["build_token"], risk)
    engine.dispose()


def test_abandoned_build_and_catalog_refresh_are_requeued(tmp_path):
    engine, risk = fixture(tmp_path)
    state = request(engine, risk)
    with Session(engine) as db:
        header = db.get(DependencyProjection, 1)
        header.status = "building"; header.updated_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.commit()
    recovered = request(engine, risk)
    assert recovered["status"] == "pending" and recovered["build_token"] != state["build_token"]
    assert queries.build_projection(engine, 1, recovered["build_token"], risk)
    risk.cache_token = lambda: "new-catalog"
    assert request(engine, risk)["status"] == "pending"
    engine.dispose()


def test_legacy_projection_schema_upgrade_is_idempotent():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE dependency_projections (execution_id INTEGER PRIMARY KEY, fingerprint VARCHAR(64) NOT NULL)"))
        connection.execute(text("INSERT INTO dependency_projections VALUES (7, 'retained')"))
        queries.upgrade_dependency_schema(connection)
        queries.upgrade_dependency_schema(connection)
        row = connection.execute(text("SELECT fingerprint, status, build_token FROM dependency_projections")).one()
        assert tuple(row) == ("retained", "ready", None)
    engine.dispose()
