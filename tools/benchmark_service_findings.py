"""Measure findings HTTP pages using an isolated, disposable SQLite database.

Run: .venv/Scripts/python.exe tools/benchmark_service_findings.py
Output is JSON; use --count and --repeats to narrow a repeatable run.
DATABASE_URL is deliberately ignored to protect existing databases.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--count', type=int, action='append')
    parser.add_argument('--history', type=int, default=6)
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    if args.history < 1 or args.repeats < 1 or any(n < 1 for n in args.count or []):
        parser.error('counts, history and repeats must be positive')
    with tempfile.TemporaryDirectory(prefix='cats-findings-benchmark-') as directory:
        os.environ.update(DATABASE_URL=f"sqlite:///{Path(directory) / 'benchmark.db'}",
                          CATS_BOOTSTRAP_USERNAME='admin',
                          CATS_BOOTSTRAP_PASSWORD='benchmark-password-long',
                          SESSION_COOKIE_SECURE='false', PIPELINE_API_TOKEN='benchmark-token',
                          CATS_DEPLOYMENT_VALIDATION_ENABLED='false')
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
        from fastapi.testclient import TestClient
        from sqlalchemy import event, insert
        from sqlalchemy.orm import Session
        from app.auth import seed_auth
        from app.database import Base, engine
        from app.main import app
        import app.main as main_module
        import app.findings_query as findings_query
        import app.findings_sql as findings_sql
        import app.frontend as frontend
        from app.models import Execution, Finding, FindingObservation, Service

        def populate(count):
            Base.metadata.drop_all(engine)
            Base.metadata.create_all(engine)
            seed_auth()
            now = datetime(2026, 10, 2, tzinfo=timezone.utc)
            with engine.begin() as connection:
                connection.execute(insert(Service), [{'id': 1, 'service_key': 'benchmark',
                    'name': 'Benchmark Service', 'owner': 'benchmark', 'poc': 'benchmark@example.invalid'}])
                connection.execute(insert(Execution), [{'id': h + 1, 'execution_key': f'benchmark-{h}',
                    'service_id': 1, 'scanned_at': now - timedelta(days=(args.history-h-1)*14),
                    'complete': True, 'scan_scope': 'service', 'raw_payload': {'service': {'version': '1'}}}
                    for h in range(args.history)])
                connection.execute(insert(Finding), [{'id': i+1, 'service_id': 1,
                    'cve': f'CVE-2026-{i:06d}', 'severity': ('Critical','High','Medium','Low')[i%4],
                    'first_seen': now-timedelta(days=90), 'episode_started': now-timedelta(days=90),
                    'last_seen': now, 'active': i%5 != 0,
                    'resolved_at': None if i%5 else now-timedelta(days=1), 'recurrence_count': i%3}
                    for i in range(count)])
                for h in range(args.history):
                    connection.execute(insert(FindingObservation), [{'id': h*count+i+1,
                        'finding_id': i+1, 'execution_id': h+1,
                        'image': f'registry.example.invalid/app-{i%12}:1', 'image_digest': None,
                        'package': f'package-{i%150}', 'installed_version': '1.0', 'fixed_version': '1.1',
                        'evidence': {'description': 'Synthetic vulnerability evidence', 'epss': (i%100)/100,
                                     'kev': i%19 == 0}} for i in range(count)])

        def measure(client, view):
            durations = []
            loaded = Counter()
            statements = Counter()
            stages = Counter()
            patched = []
            def instrument(owner, name):
                original = getattr(owner, name)
                def timed(*args, **kwargs):
                    started = time.perf_counter()
                    try:
                        return original(*args, **kwargs)
                    finally:
                        stages[name] += (time.perf_counter()-started)*1000
                setattr(owner, name, timed)
                patched.append((owner, name, original))
            for owner, names in (
                (main_module, ('service_view', 'configuration_for_service', 'page_context')),
                (findings_query, ('load_page_support', 'load_simplified_support')),
                (findings_sql, ('get_raw_finding_page',)),
                (frontend, ('page_data',)),
                (main_module.templates, ('TemplateResponse',)),
            ):
                for name in names:
                    instrument(owner, name)
            def before(conn, cursor, statement, parameters, context, many):
                context._benchmark_started = time.perf_counter()
                statements[re.sub(r'\s+', ' ', statement).strip()] += 1
            def after(conn, cursor, statement, parameters, context, many):
                durations.append((time.perf_counter()-context._benchmark_started)*1000)
            def hydrate(session, instance):
                if isinstance(instance, (Finding, FindingObservation)):
                    loaded[type(instance).__name__] += 1
            event.listen(engine, 'before_cursor_execute', before)
            event.listen(engine, 'after_cursor_execute', after)
            event.listen(Session, 'loaded_as_persistent', hydrate)
            try:
                started = time.perf_counter()
                response = client.get(f'/services/benchmark?findings_view={view}&page_size=50')
                elapsed = (time.perf_counter()-started)*1000
                response.raise_for_status()
                return {'sql_count': len(durations), 'sql_ms': round(sum(durations), 2),
                        'finding_hydrated': loaded['Finding'],
                        'observation_hydrated': loaded['FindingObservation'],
                        'stages_ms': {key: round(value, 2) for key, value in stages.items()},
                        'repeated_sql': [{'count': count, 'sql': sql} for sql, count in statements.most_common()
                                         if count > 1],
                        'response_bytes': len(response.content), 'total_ms': round(elapsed, 2)}
            finally:
                for owner, name, original in reversed(patched):
                    setattr(owner, name, original)
                event.remove(engine, 'before_cursor_execute', before)
                event.remove(engine, 'after_cursor_execute', after)
                event.remove(Session, 'loaded_as_persistent', hydrate)

        try:
            for count in args.count or [1000, 5000, 10000]:
                populate(count)
                with TestClient(app) as client:
                    login = client.post('/login', data={'username':'admin', 'password':'benchmark-password-long'},
                                        follow_redirects=False)
                    if login.status_code != 303:
                        raise RuntimeError(f'Login failed: {login.status_code}')
                    for view in ('raw', 'simplified'):
                        first = measure(client, view)
                        samples = [measure(client, view) for _ in range(args.repeats)]
                        print(json.dumps({'python': platform.python_version(), 'database': 'disposable SQLite',
                            'findings': count, 'observations': count*args.history, 'history':args.history,
                            'view': view, 'page_size':50, 'first': first, 'repeated':samples}), flush=True)
        finally:
            engine.dispose()


if __name__ == '__main__':
    main()
