from sqlalchemy import create_engine, inspect
from app import intelligence_importer as worker
from app.database import INTELLIGENCE_TABLE_NAMES


def test_schema_initialization_only_creates_intelligence_tables(monkeypatch):
    engine = create_engine('sqlite://')
    monkeypatch.setattr(worker, 'intelligence_engine', engine)
    worker.initialize_schema()
    worker.initialize_schema()
    assert set(inspect(engine).get_table_names()) == INTELLIGENCE_TABLE_NAMES


def test_worker_reports_import_failure_and_schema_only_skips_import(monkeypatch):
    from app import embedded_intelligence
    calls = []
    monkeypatch.setattr(worker, 'initialize_schema', lambda: calls.append('schema'))
    monkeypatch.setattr(embedded_intelligence, 'install_package', lambda factory: calls.append(factory) or 'failed')
    assert worker.main(['--schema-only']) == 0
    assert calls == ['schema']
    assert worker.main([]) == 1
    assert calls[-1] is worker.IntelligenceSessionLocal
