from sqlalchemy import create_engine, inspect, text
from app import intelligence_importer as worker
from app.database import INTELLIGENCE_TABLE_NAMES
from app.vex_models import VexSource


def test_schema_initialization_only_creates_intelligence_tables(monkeypatch):
    engine = create_engine('sqlite://')
    monkeypatch.setattr(worker, 'intelligence_engine', engine)
    worker.initialize_schema()
    worker.initialize_schema()
    assert set(inspect(engine).get_table_names()) == INTELLIGENCE_TABLE_NAMES


def test_repeat_init_skips_existing_seed_and_repairs_missing_trigger_and_seed(monkeypatch):
    engine = create_engine('sqlite://')
    monkeypatch.setattr(worker, 'intelligence_engine', engine)
    token = text('SELECT token FROM intelligence_generation WHERE id = 1')
    worker.initialize_schema()
    with engine.begin() as connection:
        original = connection.scalar(token)
        assert original
        # Even an INSERT that resolves to DO NOTHING enters the unique-index
        # write path on PostgreSQL. Assert that repeat init never attempts it.
        connection.exec_driver_sql("""CREATE TRIGGER reject_repeat_seed BEFORE INSERT ON intelligence_generation
            WHEN EXISTS (SELECT 1 FROM intelligence_generation WHERE id = NEW.id)
            BEGIN SELECT RAISE(ABORT, 'attempted duplicate seed insert'); END""")
        connection.exec_driver_sql('DROP TRIGGER cats_generation_vex_sources_insert')

    worker.initialize_schema()
    with engine.begin() as connection:
        assert connection.scalar(token) == original
        connection.execute(VexSource.__table__.insert().values(name='after-repair'))
        assert connection.scalar(token) != original
        connection.exec_driver_sql('DELETE FROM intelligence_generation WHERE id = 1')

    worker.initialize_schema()
    with engine.connect() as connection:
        restored = connection.scalar(token)
        assert restored and restored != original


def test_worker_reports_import_failure_and_schema_only_skips_import(monkeypatch):
    from app import embedded_intelligence
    calls = []
    monkeypatch.setattr(worker, 'initialize_schema', lambda: calls.append('schema'))
    monkeypatch.setattr(embedded_intelligence, 'install_package', lambda factory: calls.append(factory) or 'failed')
    assert worker.main(['--schema-only']) == 0
    assert calls == ['schema']
    assert worker.main([]) == 1
    assert calls[-1] is worker.IntelligenceSessionLocal
