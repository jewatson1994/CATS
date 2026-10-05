"""Real route regression budgets include DTO serialization and DBAPI fetches."""
import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('finding_page_benchmark', ROOT / 'scripts/benchmark-backend.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


@pytest.mark.parametrize('size', [1000, 10000])
def test_route_pages_keep_query_transfer_and_response_budgets(size, monkeypatch, tmp_path):
    import sqlite3
    from app import main
    from app.models import FindingObservation

    database = tmp_path / 'page-budget.sqlite'
    engine = create_engine('sqlite://', creator=lambda: sqlite3.connect(database, factory=bench.Connection))
    bench.fixture(engine, size, all_target=True, group_count=100, include_states=True)
    monkeypatch.setattr(main, 'SessionLocal', sessionmaker(engine))
    monkeypatch.setattr(main, 'utcnow', lambda: bench.NOW)
    with Session(engine) as db:
        group_id = db.scalar(select(FindingObservation.simplified_key)
            .where(FindingObservation.package == 'package-00002').limit(1))

    def checked(endpoint, **kwargs):
        metrics = bench.measure(engine, main, endpoint, size, route_kwargs=kwargs)
        assert metrics['status_code'] == 200, metrics.get('error')
        assert metrics['dbapi_rows_fetched'] <= 350, metrics
        assert metrics['response_bytes'] <= 100_000, metrics
        assert metrics['orm_by_class'].get('FindingObservation', 0) == 0, metrics
        assert metrics['query_count'] <= (40 if 'view=raw' in endpoint else 25), metrics
        if 'view=raw' not in endpoint:
            assert metrics['orm_by_class'].get('Finding', 0) == 0, metrics
        else:
            assert metrics['orm_by_class'].get('Finding', 0) <= 50, metrics
        return metrics

    try:
        simplified = '/services/bench-1?findings_view=simplified'
        first = checked(simplified)
        assert first['page_metadata']['total_pages'] >= 2
        checked(simplified, page=first['page_metadata']['total_pages'])
        checked(simplified, q='package-00002', severity=['Medium'])
        raw = '/services/bench-1?findings_view=raw'
        first = checked(raw)
        checked(raw, page=first['page_metadata']['total_pages'])
        checked(raw, severity=['High'], resource='images/bench-11')
        endpoint = f'/api/v1/services/bench-1/findings/simplified/{group_id}/members'
        first = checked(endpoint, group_id=group_id)
        assert 0 < first['page_metadata']['total_items'] <= size // 100
        if size == 10000:
            assert first['page_metadata']['total_pages'] >= 2
        checked(endpoint, group_id=group_id, page=first['page_metadata']['total_pages'])
    finally:
        engine.dispose()
