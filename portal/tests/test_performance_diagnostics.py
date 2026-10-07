import asyncio
from types import SimpleNamespace

import anyio
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from app.performance import (
    PerformanceMiddleware, capture_performance, diagnostics_enabled,
    install_sqlalchemy_diagnostics, performance_scope,
)


def test_disabled_default_and_explicit_capture(monkeypatch):
    monkeypatch.delenv("CATS_PERFORMANCE_DIAGNOSTICS", raising=False)
    assert not diagnostics_enabled()
    engine = create_engine("sqlite://")
    sessions = sessionmaker(engine)
    install_sqlalchemy_diagnostics(engine, sessions.class_)
    install_sqlalchemy_diagnostics(engine, sessions.class_)
    with capture_performance() as measurement, engine.connect() as connection:
        connection.execute(text("SELECT :secret"), {"secret": "private-value"}).all()
    result = measurement.snapshot()
    assert result["query_count"] == 1
    assert result["cursor_reported_rows"] == 0
    assert result["cursor_unknown_rowcount_queries"] == 1
    assert "private-value" not in str(result)
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    assert measurement.query_count == 1


def test_orm_loads_and_stage_timing():
    class Base(DeclarativeBase):
        pass

    class Item(Base):
        __tablename__ = "diagnostic_items"
        id: Mapped[int] = mapped_column(primary_key=True)

    engine = create_engine("sqlite://")
    sessions = sessionmaker(engine)
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(Item.__table__.insert(), [{"id": 1}, {"id": 2}])
    install_sqlalchemy_diagnostics(engine, sessions.class_)
    with capture_performance() as measurement, sessions() as session:
        with performance_scope("transformation"):
            assert len(session.query(Item).all()) == 2
    assert measurement.orm_instances_loaded == 2
    assert measurement.snapshot()["stage_ms"]["transformation"] >= 0
    with pytest.raises(ValueError):
        with performance_scope("secret-user-id"):
            pass


def test_concurrent_requests_threadpool_privacy_and_disabled():
    async def run():
        records = []
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        sessions = sessionmaker(engine)
        install_sqlalchemy_diagnostics(engine, sessions.class_)

        async def app(scope, receive, send):
            scope["route"] = SimpleNamespace(path="/services/{service_id}")
            def worker():
                with performance_scope("policy"):
                    with engine.connect() as connection:
                        for _ in scope["body"]:
                            connection.execute(text("SELECT 1")).all()
            await anyio.to_thread.run_sync(worker)
            await asyncio.sleep(0)
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": scope["body"], "more_body": True})
            await send({"type": "http.response.body", "body": b"end"})

        async def receive():
            return {"type": "http.request"}

        async def send(message):
            pass

        middleware = PerformanceMiddleware(app, enabled=True, sink=records.append)
        await asyncio.gather(*(middleware({"type": "http", "path": "/services/secret",
            "query_string": b"token=private-token", "headers": [(b"authorization", b"secret")],
            "body": b"x" * n}, receive, send) for n in (1, 7)))
        assert sorted(record["response_bytes"] for record in records) == [4, 10]
        assert sorted(record["query_count"] for record in records) == [1, 7]
        assert all(record["route"] == "/services/{service_id}" for record in records)
        assert all("policy" in record["stage_ms"] for record in records)
        assert all(record["response_completed"] for record in records)
        assert "secret" not in str(records) and "private-token" not in str(records)
        records.clear()
        await PerformanceMiddleware(app, enabled=False, sink=records.append)(
            {"type": "http", "body": b""}, receive, send)
        assert not records
    asyncio.run(run())


def test_failure_restores_context_and_sink_cannot_break_response():
    async def run():
        async def failing_app(scope, receive, send):
            raise RuntimeError("private-error")
        async def noop(message=None):
            pass
        records = []
        with pytest.raises(RuntimeError):
            await PerformanceMiddleware(failing_app, enabled=True, sink=records.append)(
                {"type": "http", "path": "/secret"}, noop, noop)
        assert records[0]["route"] == "<unmatched>"
        assert records[0]["response_completed"] is False
        with performance_scope("policy"):
            pass
        assert records[0]["stage_ms"] == {}
        assert "private-error" not in str(records)
        async def app(scope, receive, send):
            await send({"type": "http.response.body", "body": b"ok"})
        def broken_sink(record):
            raise ValueError("private-sink-error")
        await PerformanceMiddleware(app, enabled=True, sink=broken_sink)({"type": "http"}, noop, noop)
    asyncio.run(run())


def test_application_registers_one_measuring_middleware():
    from app.main import app
    from starlette.middleware.gzip import GZipMiddleware
    classes = [entry.cls for entry in app.user_middleware]
    assert classes.count(PerformanceMiddleware) == 1
    # Inside GZip, so recorded bytes are the uncompressed payload budget.
    assert classes.index(GZipMiddleware) < classes.index(PerformanceMiddleware)
