"""Disposable SQLite page/filter benchmark; does not access production data."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('backend_benchmark', ROOT / 'scripts/benchmark-backend.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='docs/backend-performance-pages.json')
    args = parser.parse_args()
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session, sessionmaker
    results = []
    with tempfile.TemporaryDirectory(prefix='cats-page-bench-') as directory:
        os.environ['DATABASE_URL'] = 'sqlite:///' + str(Path(directory) / 'unused.sqlite')
        from app import main as routes
        from app.database import engine as default_engine
        from app.models import FindingObservation
        routes.utcnow = lambda: bench.NOW
        def run_fixture(size, label, *, groups=30, all_target=False, states=False):
            path = Path(directory) / f'{label}-{size}.sqlite'
            engine = create_engine('sqlite://', creator=lambda: sqlite3.connect(path, factory=bench.Connection))
            bench.fixture(engine, size, all_target=all_target, group_count=groups, include_states=states)
            routes.SessionLocal = sessionmaker(engine)
            return engine
        def measure(engine, size, label, *, view='simplified', kwargs=None, members=False, plan=False):
            endpoint = f"/api/v1/services/bench-1/findings/simplified/{kwargs['group_id']}/members" if members else f'/services/bench-1?findings_view={view}'
            row = bench.measure(engine, routes, endpoint, size, route_kwargs=kwargs, capture_plan=plan)
            row['scenario'] = label
            row['route_parameters'] = kwargs or {}
            assert row['status_code'] == 200, row.get('error')
            assert row['dbapi_rows_fetched'] <= 350, row
            assert row['orm_by_class'].get('FindingObservation', 0) == 0, row
            if members or view == 'simplified':
                assert row['query_count'] <= 25, row
                assert row['response_bytes'] <= 100_000, row
            results.append(row)
            print(json.dumps({key: row.get(key) for key in ('scenario', 'duration_ms', 'query_count', 'dbapi_rows_fetched', 'status_code', 'error')}), flush=True)
            return row
        for size in (1000, 10000, 100000):
            engine = run_fixture(size, 'default')
            measure(engine, size, 'simplified_default', plan=size == 100000)
            engine.dispose()
        engine = run_fixture(100000, 'all-target-many-groups', groups=5000, all_target=True, states=True)
        first = measure(engine, 100000, 'simplified_all_target_first', plan=True)
        assert first.get('page_metadata', {}).get('total_items', 0) >= 3000, 'Many-group fixture must expose at least 3000 visible groups'
        last = max(1, first.get('page_metadata', {}).get('total_pages', 1))
        for page, label in ((max(1, last//2), 'middle'), (last, 'late')):
            measure(engine, 100000, f'simplified_all_target_{label}', kwargs={'page': page})
        for label, kwargs in [('search', {'q': 'package-00012'}), ('resource', {'resource': 'images/bench-12'}),
                              ('severity', {'severity': ['High']}), ('active', {'finding_state': 'active'}),
                              ('resolved', {'finding_state': 'resolved'}), ('exceptions', {'finding_state': 'exceptions'}),
                              ('noncompliant', {'finding_state': 'noncompliant'})]:
            measure(engine, 100000, f'simplified_filter_{label}', kwargs=kwargs)
        raw = measure(engine, 100000, 'raw_all_target_first', view='raw')
        raw_last = max(1, raw.get('page_metadata', {}).get('total_pages', 1))
        for page, label in ((max(1, raw_last//2), 'middle'), (raw_last, 'late')):
            measure(engine, 100000, f'raw_all_target_{label}', view='raw', kwargs={'page': page})
        measure(engine, 100000, 'raw_all_target_filter', view='raw', kwargs={'severity': ['High'], 'resource': 'images/bench-11'})
        engine.dispose()
        engine = run_fixture(100000, 'all-target-large-members', all_target=True)
        with Session(engine) as db:
            group_id = db.scalar(select(FindingObservation.simplified_key).where(FindingObservation.package == 'package-00002').limit(1))
        member = measure(engine, 100000, 'members_first', members=True, kwargs={'group_id': group_id}, plan=True)
        member_last = max(1, member.get('page_metadata', {}).get('total_pages', 1))
        for page, label in ((max(1, member_last//2), 'middle'), (member_last, 'late')):
            measure(engine, 100000, f'members_{label}', members=True, kwargs={'group_id': group_id, 'page': page})
        engine.dispose()
        default_engine.dispose()
    files = ('portal/app/main.py', 'portal/app/simplified_queries.py', 'portal/app/findings_sql.py',
             'scripts/benchmark-backend.py', 'scripts/benchmark-simplified-pages.py')
    report = {'method': 'Actual route bodies plus DTO/JSON serialization in fresh ORM sessions. Disposable SQLite fixtures, cProfile and tracemalloc enabled. No HTTP middleware/authentication/network. DBAPI rows fetched measured; internal database rows examined and Python rows considered not measured. Each fixture has three scans per service and one observation per finding. Default splits half findings into target service; all-target scenarios put all 100000 there. Many-group fixture has 5000 package/remediation groups before risk/state filters. Exceptions and overdue/resolved findings are present in state-filter fixture. Member fixture has 30 groups, including one with thousands of findings. SQLite query plans captured for representative CTE statements. Not PostgreSQL or production latency.',
              'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in files}, 'results': results}
    (ROOT/args.output).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
