"""Constant-cost intelligence fence; not a distributed atomic commit protocol.

PostgreSQL statement triggers lock the singleton BEFORE mutating evidence. A
consumer holds its shared lock through its operational transaction. A failed
connection fails closed; restart/restore changes the incarnation fingerprint.
"""
import uuid

from sqlalchemy import CheckConstraint, Column, Integer, String, event, inspect, text
from sqlalchemy.orm import Session
from . import database


class IntelligenceGeneration(database.Base):
    __tablename__ = "intelligence_generation"
    __table_args__ = (CheckConstraint("id = 1"),)
    id = Column(Integer, primary_key=True)
    token = Column(String(36), nullable=False)


class GenerationUnavailable(RuntimeError):
    pass


class GenerationChanged(GenerationUnavailable):
    pass


def install_generation_triggers(connection):
    names = set(inspect(connection).get_table_names())
    if "intelligence_generation" not in names:
        return
    dialect = connection.dialect.name
    connection.execute(text("INSERT INTO intelligence_generation (id, token) VALUES (1, :token) ON CONFLICT (id) DO NOTHING"), {"token": str(uuid.uuid4())})
    if dialect == "postgresql":
        connection.execute(text("""CREATE OR REPLACE FUNCTION cats_intelligence_generation_touch()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
          UPDATE intelligence_generation SET token = gen_random_uuid()::text WHERE id = 1;
          IF NOT FOUND THEN RAISE EXCEPTION 'intelligence generation missing'; END IF;
          RETURN NULL;
        END $$"""))
    for name in sorted((database.INTELLIGENCE_TABLE_NAMES - {"intelligence_generation"}) & names):
        if dialect == "postgresql":
            connection.execute(text(f'DROP TRIGGER IF EXISTS cats_generation_touch ON "{name}"'))
            connection.execute(text(f'CREATE TRIGGER cats_generation_touch BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON "{name}" FOR EACH STATEMENT EXECUTE FUNCTION cats_intelligence_generation_touch()'))
        elif dialect == "sqlite":
            for operation in ("INSERT", "UPDATE", "DELETE"):
                connection.execute(text(f'CREATE TRIGGER IF NOT EXISTS cats_generation_{name}_{operation.lower()} BEFORE {operation} ON "{name}" BEGIN UPDATE intelligence_generation SET token = lower(hex(randomblob(16))) WHERE id = 1; END'))


@event.listens_for(database.Base.metadata, "after_create")
def _created(metadata, connection, **kwargs):
    install_generation_triggers(connection)


def _engine(db):
    if db is not None and db.bind is not None:
        return db.bind
    return database.intelligence_engine if database.interactive_thread() else database.intelligence_background_engine


def _read(connection, lock=False):
    if connection.dialect.name == "postgresql":
        row = connection.execute(text("""SELECT token,
          (SELECT oid::text FROM pg_database WHERE datname=current_database()),
          pg_relation_filenode('intelligence_generation'::regclass)::text,
          pg_postmaster_start_time()::text
          FROM intelligence_generation WHERE id=1""" + (" FOR SHARE" if lock else ""))).one()
        return "|".join(str(value) for value in row)
    return connection.execute(text("SELECT token FROM intelligence_generation WHERE id=1")).scalar_one()


def _configure(connection):
    if connection.dialect.name == "postgresql":
        connection.execute(text("SET LOCAL lock_timeout = '5s'"))
        connection.execute(text("SET LOCAL statement_timeout = '5s'"))


def current_generation(db=None):
    try:
        if db is not None and _engine(db).dialect.name == "sqlite":
            return _read(db.connection(bind_arguments={"bind": _engine(db)}))
        with _engine(db).connect() as connection:
            _configure(connection)
            return _read(connection)
    except Exception as exc:
        raise GenerationUnavailable("Intelligence generation is unavailable") from exc


def guard_generation(db, expected):
    """Hold a live fence until the outer operational transaction finishes.

    Acquire before reading evidence or modifying operational authorization.
    SQLite is a development fallback and does not provide the cross-DB fence.
    """
    existing = db.info.get("intelligence_generation_guard")
    if existing:
        if existing[1] != expected:
            raise GenerationChanged("Intelligence generation changed")
        return expected
    connection = None
    try:
        if not db.in_transaction():
            db.begin()
        owned = _engine(db).dialect.name != "sqlite"
        connection = (_engine(db).connect() if owned else
                      db.connection(bind_arguments={"bind": _engine(db)}))
        _configure(connection)
        actual = _read(connection, lock=True)
        if actual != expected:
            raise GenerationChanged("Intelligence generation changed")
        db.info["intelligence_generation_guard"] = (connection, actual, owned)
        return actual
    except Exception as exc:
        if connection is not None and owned:
            connection.close()
        if isinstance(exc, GenerationChanged):
            raise
        raise GenerationUnavailable("Intelligence generation fence is unavailable") from exc


@event.listens_for(Session, "before_commit")
def _check_guard(db):
    guard = db.info.get("intelligence_generation_guard")
    if guard:
        try:
            if _read(guard[0], lock=True) != guard[1]:
                raise GenerationChanged("Intelligence generation changed")
        except GenerationChanged:
            raise
        except Exception as exc:
            raise GenerationUnavailable("Intelligence generation fence was lost") from exc


@event.listens_for(Session, "after_transaction_end")
def _release_guard(db, transaction):
    if transaction.parent is None:
        guard = db.info.pop("intelligence_generation_guard", None)
        if guard and guard[2]:
            guard[0].close()
