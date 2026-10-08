"""Interactive requests and background work use separate connection pools."""
import threading

from sqlalchemy import create_engine

from app import database


def test_sessions_route_by_thread_and_explicit_binds_win(monkeypatch):
    interactive, background = create_engine("sqlite://"), create_engine("sqlite://")
    monkeypatch.setattr(database, "engine", interactive)
    monkeypatch.setattr(database, "background_engine", background)
    assert database.SessionLocal().get_bind() is interactive  # main thread
    seen = {}

    def work(name):
        seen[name] = database.SessionLocal().get_bind()

    for name in ("AnyIO worker thread", "cats-posture_0", "ThreadPoolExecutor-3_0", "cats-read-model-maintenance"):
        thread = threading.Thread(target=work, args=(name,), name=name)
        thread.start(); thread.join()
    assert seen["AnyIO worker thread"] is interactive
    assert all(seen[name] is background for name in ("cats-posture_0", "ThreadPoolExecutor-3_0", "cats-read-model-maintenance"))
    explicit = create_engine("sqlite://")
    assert database.SessionLocal(bind=explicit).get_bind() is explicit
    assert database.background_bind(interactive) is background
    assert database.background_bind(explicit) is explicit


def test_pool_sizes_are_configurable_and_bounded(monkeypatch):
    monkeypatch.setattr(database, "engine_options", {"pool_pre_ping": True, "connect_args": {}})
    monkeypatch.setenv("CATS_DB_POOL_SIZE", "7")
    monkeypatch.setenv("CATS_DB_BACKGROUND_MAX_OVERFLOW", "not-a-number")
    assert database._pool("CATS_DB", 10, 10, 15) == {"pool_size": 7, "max_overflow": 10, "pool_timeout": 15}
    assert database._pool("CATS_DB_BACKGROUND", 4, 4, 60)["max_overflow"] == 4
    assert "pool_recycle" not in database._pool("CATS_DB", 10, 10, 15)
    monkeypatch.setenv("CATS_DB_POOL_RECYCLE", "1800")
    assert database._pool("CATS_DB", 10, 10, 15)["pool_recycle"] == 1800


def test_postgresql_connections_disable_jit_unless_configured(monkeypatch):
    monkeypatch.delenv("CATS_DB_JIT", raising=False)
    assert database._postgresql_options("postgresql+psycopg://cats@db/cats") == {"options": "-c jit=off"}
    assert database._postgresql_options("postgresql+psycopg://cats@db/cats?options=-c%20work_mem%3D8MB") == {}
    assert database._postgresql_options("sqlite:///./cats.db") == {}
    monkeypatch.setenv("CATS_DB_JIT", "server")
    assert database._postgresql_options("postgresql+psycopg://cats@db/cats") == {}
