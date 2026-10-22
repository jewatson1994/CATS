import os
import threading

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql import visitors
from sqlalchemy.sql.schema import Table


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


def _pool(prefix, size, overflow, timeout, options=None):
    if "poolclass" in (engine_options if options is None else options):
        return {}
    options = {"pool_size": _int(f"{prefix}_POOL_SIZE", size, 1), "max_overflow": _int(f"{prefix}_MAX_OVERFLOW", overflow),
               "pool_timeout": _int(f"{prefix}_POOL_TIMEOUT", timeout, 1)}
    # Optional age limit for pooled connections (firewalls/proxies that drop
    # idle connections); pool_pre_ping already replaces dead ones on checkout.
    recycle = _int(f"{prefix}_POOL_RECYCLE", 0)
    if recycle:
        options["pool_recycle"] = recycle
    return options


# Interactive requests and background work (scans, remediation, validation
# orchestration, projections, maintenance) use separate connection pools, so
# long-running background sessions can never exhaust the connections that
# page and API requests need. Per process: 10+10 interactive, 4+4 background
# by default (CATS_DB_*, CATS_DB_BACKGROUND_*). In-memory SQLite (tests) has
# one shared connection, so both names refer to the same engine there.
engine = create_engine(DATABASE_URL, **engine_options, **_pool("CATS_DB", 10, 10, 15))
background_engine = (engine if DATABASE_URL == "sqlite://"
                     else create_engine(DATABASE_URL, **engine_options, **_pool("CATS_DB_BACKGROUND", 4, 4, 60)))
INTELLIGENCE_DATABASE_URL = os.getenv("INTELLIGENCE_DATABASE_URL") or DATABASE_URL
INTELLIGENCE_SEPARATE = INTELLIGENCE_DATABASE_URL != DATABASE_URL
intelligence_connect_args = ({"check_same_thread": False}
                             if INTELLIGENCE_DATABASE_URL.startswith("sqlite") else {})
intelligence_connect_args.update(_postgresql_options(INTELLIGENCE_DATABASE_URL))
if INTELLIGENCE_DATABASE_URL.startswith("postgresql"):
    intelligence_connect_args.setdefault("connect_timeout", 5)
if INTELLIGENCE_DATABASE_URL.startswith("postgresql") and os.getenv("INTELLIGENCE_DB_PASSWORD"):
    intelligence_connect_args["password"] = os.environ["INTELLIGENCE_DB_PASSWORD"]
intelligence_engine_options = {"pool_pre_ping": True, "connect_args": intelligence_connect_args}
if INTELLIGENCE_DATABASE_URL in {"sqlite://", "sqlite:///:memory:"}:
    intelligence_engine_options["poolclass"] = StaticPool
intelligence_engine = (create_engine(
    INTELLIGENCE_DATABASE_URL, **intelligence_engine_options,
    **_pool("INTELLIGENCE_DB", 10, 10, 15, intelligence_engine_options))
    if INTELLIGENCE_SEPARATE else engine)
intelligence_background_engine = (
    create_engine(INTELLIGENCE_DATABASE_URL, **intelligence_engine_options,
                  **_pool("INTELLIGENCE_DB_BACKGROUND", 4, 4, 60, intelligence_engine_options))
    if INTELLIGENCE_SEPARATE and "poolclass" not in intelligence_engine_options
    else intelligence_engine if INTELLIGENCE_SEPARATE else background_engine)

# Explicit ownership: native_vex_* are operational records, not feed data.
INTELLIGENCE_TABLE_NAMES = frozenset({
    "intelligence_generation", "vex_sources", "vex_documents", "vex_statements", "vex_ingestion_audits",
    "intelligence_records", "intelligence_package_installs", "intelligence_package_catalogs",
    "intelligence_package_members", "intelligence_package_state",
})
_INTERACTIVE_PREFIXES = ("AnyIO worker thread",)


def interactive_thread() -> bool:
    """Request handlers run on the event loop thread or AnyIO's worker pool."""
    thread = threading.current_thread()
    return thread is threading.main_thread() or thread.name.startswith(_INTERACTIVE_PREFIXES)


def background_bind(bind):
    """The background pool for work handed off from a request."""
    if bind is engine:
        return background_engine
    return intelligence_background_engine if bind is intelligence_engine else bind


class RoutingSession(Session):
    """Default sessions bind to the pool matching the thread doing the work."""

    def get_bind(self, mapper=None, *, clause=None, **kwargs):
        if self.bind is not None or kwargs.get("bind") is not None:
            return super().get_bind(mapper, clause=clause, **kwargs)
        names = set()
        if mapper is not None:
            names.update(table.name for table in mapper.tables)
        if clause is not None:
            names.update(node.name for node in visitors.iterate(clause) if isinstance(node, Table))
        intelligence = names & INTELLIGENCE_TABLE_NAMES
        if INTELLIGENCE_SEPARATE and intelligence:
            if names - INTELLIGENCE_TABLE_NAMES:
                raise ValueError("SQL spanning portal and intelligence databases is unsupported; query each database separately")
            return intelligence_engine if interactive_thread() else intelligence_background_engine
        return engine if interactive_thread() else background_engine


SessionLocal = sessionmaker(class_=RoutingSession, autoflush=False, expire_on_commit=False)


class IntelligenceSession(Session):
    """Explicit intelligence sessions also support text SQL and importer work."""

    def get_bind(self, mapper=None, **kwargs):
        if self.bind is not None or kwargs.get("bind") is not None:
            return super().get_bind(mapper, **kwargs)
        return intelligence_engine if interactive_thread() else intelligence_background_engine


IntelligenceSessionLocal = sessionmaker(class_=IntelligenceSession, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def intelligence_tables():
    """Registered feed tables, in foreign-key dependency order."""
    from . import intelligence_models, vex_models, intelligence_generation  # noqa: F401
    return [table for table in Base.metadata.sorted_tables if table.name in INTELLIGENCE_TABLE_NAMES]


def portal_tables():
    """Startup schema: all tables in legacy mode, operational tables when split.

    Callers must import their operational model modules first.
    """
    intelligence_tables()
    return [table for table in Base.metadata.sorted_tables
            if not INTELLIGENCE_SEPARATE or table.name not in INTELLIGENCE_TABLE_NAMES]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
