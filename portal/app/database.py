import os
import threading

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyber_hygiene.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}


def _postgresql_options(url: str) -> dict:
    """Session settings for PostgreSQL connections.

    JIT compilation is disabled by default: CATS issues short interactive
    queries whose planner costs cross ``jit_above_cost`` and spend ~20 ms
    compiling (measured at 10,000 findings per service: Overview 93 -> 61 ms,
    Simplified Findings 229 -> 147 ms). ``CATS_DB_JIT=server`` keeps the
    server's setting. Options already given in DATABASE_URL take precedence.
    """
    from sqlalchemy.engine import make_url
    try:
        parsed = make_url(url)
    except Exception:
        return {}
    if parsed.get_backend_name() != "postgresql" or "options" in parsed.query:
        return {}
    if os.getenv("CATS_DB_JIT", "off").strip().lower() in {"server", "on", "default"}:
        return {}
    return {"options": "-c jit=off"}


connect_args.update(_postgresql_options(DATABASE_URL))
engine_options = {"pool_pre_ping": True, "connect_args": connect_args}
if DATABASE_URL == "sqlite://":
    engine_options["poolclass"] = StaticPool


def _int(name, default, minimum=0):
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _pool(prefix, size, overflow, timeout):
    if "poolclass" in engine_options:
        return {}
    return {"pool_size": _int(f"{prefix}_POOL_SIZE", size, 1), "max_overflow": _int(f"{prefix}_MAX_OVERFLOW", overflow),
            "pool_timeout": _int(f"{prefix}_POOL_TIMEOUT", timeout, 1)}


# Interactive requests and background work (scans, remediation, validation
# orchestration, projections, maintenance) use separate connection pools, so
# long-running background sessions can never exhaust the connections that
# page and API requests need. Per process: 10+10 interactive, 4+4 background
# by default (CATS_DB_*, CATS_DB_BACKGROUND_*). In-memory SQLite (tests) has
# one shared connection, so both names refer to the same engine there.
engine = create_engine(DATABASE_URL, **engine_options, **_pool("CATS_DB", 10, 10, 15))
background_engine = (engine if DATABASE_URL == "sqlite://"
                     else create_engine(DATABASE_URL, **engine_options, **_pool("CATS_DB_BACKGROUND", 4, 4, 60)))
_INTERACTIVE_PREFIXES = ("AnyIO worker thread",)


def interactive_thread() -> bool:
    """Request handlers run on the event loop thread or AnyIO's worker pool."""
    thread = threading.current_thread()
    return thread is threading.main_thread() or thread.name.startswith(_INTERACTIVE_PREFIXES)


def background_bind(bind):
    """The background pool for work handed off from a request."""
    return background_engine if bind is engine else bind


class RoutingSession(Session):
    """Default sessions bind to the pool matching the thread doing the work."""

    def get_bind(self, mapper=None, **kwargs):
        if self.bind is not None or kwargs.get("bind") is not None:
            return super().get_bind(mapper, **kwargs)
        return engine if interactive_thread() else background_engine


SessionLocal = sessionmaker(class_=RoutingSession, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
