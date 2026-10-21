"""Feed storage routing leaves operational and explicitly bound sessions intact."""
import pytest
from sqlalchemy import create_engine, select, text, inspect, insert
from app import database
from app.models import Service
from app.vex_models import VexSource
from app.native_vex_models import VexDispositionPolicy


@pytest.fixture
def split(monkeypatch):
    portal, intelligence, background = [create_engine("sqlite://") for _ in range(3)]
    monkeypatch.setattr(database, "INTELLIGENCE_SEPARATE", True)
    monkeypatch.setattr(database, "engine", portal)
    monkeypatch.setattr(database, "intelligence_engine", intelligence)
    monkeypatch.setattr(database, "intelligence_background_engine", background)
    yield portal, intelligence, background
    for engine in (portal, intelligence, background):
        engine.dispose()


def test_orm_core_alias_and_nested_queries(split, monkeypatch):
    portal, intelligence, background = split
    with database.SessionLocal() as session:
        for clause in (select(VexSource), select(VexSource.__table__.alias()),
                       select(select(VexSource.id).scalar_subquery()),
                       insert(VexSource).values(name="source")):
            assert session.get_bind(clause=clause) is intelligence
        assert session.get_bind(mapper=inspect(VexSource)) is intelligence
        assert session.get_bind(clause=select(Service)) is portal
        assert session.get_bind(clause=select(VexDispositionPolicy)) is portal
        assert session.get_bind(clause=text("SELECT 1")) is portal
        assert session.get_bind(clause=select(1)) is portal
        monkeypatch.setattr(database, "interactive_thread", lambda: False)
        assert session.get_bind(clause=select(VexSource)) is background


def test_cross_database_query_and_explicit_override(split):
    portal, intelligence, _ = split
    mixed = select(Service.id, VexSource.id)
    with database.SessionLocal() as session:
        with pytest.raises(ValueError, match="query each database separately"):
            session.get_bind(clause=mixed)
    with database.SessionLocal(bind=portal) as session:
        assert session.get_bind(clause=mixed) is portal
    with database.IntelligenceSessionLocal() as session:
        assert session.get_bind(clause=text("SELECT 1")) is intelligence
    assert database.background_bind(intelligence) is split[2]


def test_unconfigured_deployment_retains_one_database(split, monkeypatch):
    monkeypatch.setattr(database, "INTELLIGENCE_SEPARATE", False)
    assert set(database.portal_tables()) == set(database.Base.metadata.tables.values())
    with database.SessionLocal() as session:
        assert session.get_bind(clause=select(VexSource)) is split[0]
        assert session.get_bind(clause=select(Service.id, VexSource.id)) is split[0]


def test_schema_partition_and_actual_core_and_orm_writes(split):
    portal, intelligence, _ = split
    feed = database.intelligence_tables()
    operational = database.portal_tables()
    assert {t.name for t in feed} == database.INTELLIGENCE_TABLE_NAMES
    assert VexDispositionPolicy.__table__ in operational
    assert not set(feed) & set(operational)
    assert set(feed) | set(operational) == set(database.Base.metadata.tables.values())
    database.Base.metadata.create_all(intelligence, tables=feed)
    VexDispositionPolicy.__table__.create(portal)
    with database.SessionLocal() as session:
        session.add(VexSource(name="ORM"))
        session.add(VexDispositionPolicy())
        session.commit()
        session.execute(insert(VexSource).values(name="Core"))
        session.commit()
        assert len(session.scalars(select(VexSource)).all()) == 2
        assert len(session.scalars(select(VexDispositionPolicy)).all()) == 1
        assert session.scalar(text('SELECT count(*) FROM vex_sources'),
                              bind_arguments={'mapper': inspect(VexSource)}) == 2
        assert session.scalar(text('SELECT count(*) FROM vex_disposition_policy')) == 1
        from app.risk_routes import _source_statement_count
        assert _source_statement_count(session, 1)['statements'] == 0
    assert "vex_sources" not in inspect(portal).get_table_names()
    assert "vex_disposition_policy" not in inspect(intelligence).get_table_names()
