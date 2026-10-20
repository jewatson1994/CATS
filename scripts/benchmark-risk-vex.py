#!/usr/bin/env python3
"""Reproducible SQLite DB/VEX batch benchmark; no network or timing assertions."""
import base64
import hashlib
import json
import platform
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from time import perf_counter
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'portal'))
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from app.database import Base
from app.models import Service, Execution, Finding, FindingObservation
from app.risk_models import RiskAssessment
from app.risk_profiles import validate_policy, score_observation
from app.vex_intelligence import configure_source, evaluate_batch
from app.vex_snapshot import import_snapshot, _canonical


def main():
    now = datetime(2026, 10, 19, tzinfo=timezone.utc)
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    docs = []
    for revision in range(10):
        statements = [{'vulnerability': {'name': f'CVE-2026-{10000+i}'},
                       'products': [{'@id': f'pkg:generic/bench/package{i}@{revision+1}'}],
                       'status': 'not_affected', 'justification': 'vulnerable_code_not_present'} for i in range(1000)]
        raw = _canonical({'@context': 'https://openvex.dev/ns/v0.2.0', '@id': f'benchmark-document-{revision}',
                          'author': 'Synthetic benchmark', 'version': 1, 'timestamp': now.isoformat(), 'statements': statements})
        docs.append({'sha256': hashlib.sha256(raw).hexdigest(), 'raw': base64.b64encode(raw).decode()})
    manifest = {'schema': 'cats-vex-snapshot/v1', 'source': 'benchmark', 'allowed_hosts': [],
                'authoritative_prefixes': ['pkg:generic/bench/'], 'documents': docs}
    envelope = _canonical({'manifest': manifest, 'signature': base64.b64encode(key.sign(_canonical(manifest))).decode()})
    with Session(engine) as db:
        source = configure_source(db, 'benchmark', trusted=True, public_key=public,
                   trust_reason='Synthetic benchmark only', authoritative_prefixes=['pkg:generic/bench/'])
        started = perf_counter()
        import_snapshot(db, source.id, envelope)
        db.commit()
        ingestion_seconds = perf_counter() - started
        service = Service(name='benchmark', service_key='benchmark')
        db.add(service); db.flush()
        execution = Execution(service_id=service.id, execution_key='benchmark', scanned_at=now, complete=True, raw_payload={})
        db.add(execution); db.flush()
        service_id, execution_id = service.id, execution.id
        for i in range(1000):
            finding = Finding(service_id=service_id, cve=f'CVE-2026-{10000+i}', severity='high',
                              first_seen=now, last_seen=now, episode_started=now, active=True)
            db.add(finding); db.flush()
            db.add(FindingObservation(finding_id=finding.id, execution_id=execution_id, image='synthetic',
                   package=f'package{i}', installed_version='1', evidence={'purl': f'pkg:generic/bench/package{i}@1'}))
        db.commit()
    runs = []
    for run in range(3):
        counts = Counter()
        def count_sql(connection, cursor, statement, parameters, context, executemany):
            counts[statement.split(None, 1)[0].upper()] += 1
        event.listen(engine, 'before_cursor_execute', count_sql)
        started = perf_counter()
        details, cursor_id, batches = [], 0, 0
        with Session(engine) as db:
            while True:
                rows = db.execute(select(FindingObservation, Finding).join(Finding, Finding.id == FindingObservation.finding_id)
                    .where(Finding.service_id == service_id, FindingObservation.execution_id == execution_id,
                           FindingObservation.id > cursor_id).order_by(FindingObservation.id).limit(250)).all()
                if not rows:
                    break
                batches += 1
                items = [{'cve': f.cve, 'context': {'purl': o.evidence['purl'], 'version': o.installed_version}} for o, f in rows]
                evaluations = evaluate_batch(db, items, as_of=now)
                for (observation, finding), vex in zip(rows, evaluations):
                    assert vex['status'] == 'not_affected' and len(vex['statements']) == 1
                    assessed = score_observation(validate_policy({}), severity=finding.severity, epss=.1, kev=False, vex=vex)
                    details.append({'finding_id': finding.id, 'observation_id': observation.id, **assessed})
                cursor_id = rows[-1][0].id
                for observation, finding in rows:
                    db.expunge(observation)
            db.add(RiskAssessment(service_id=service_id, source_execution_id=execution_id, as_of=now,
                   valid_until=now+timedelta(days=1), provenance={'benchmark': True},
                   summary={'findings': len(details)}, details=details))
            db.commit()
        seconds = perf_counter() - started
        event.remove(engine, 'before_cursor_execute', count_sql)
        assert len(details) == 1000 and batches == 4
        runs.append({'seconds': round(seconds, 4), 'sql_statements': dict(counts), 'batches': batches,
                     'serialized_details_bytes': len(json.dumps(details).encode())})
    print(json.dumps({'python': platform.python_version(), 'platform': platform.platform(), 'sqlite': sqlite3.sqlite_version,
          'database': 'SQLite in-memory', 'documents': 10, 'vex_statements': 10000, 'findings': 1000,
          'observations': 1000, 'statements_per_cve': 10, 'exact_matches_per_observation': 1,
          'batch_size': 250, 'signed_snapshot_bytes': len(envelope), 'signed_ingestion_seconds': round(ingestion_seconds, 4),
          'runs': runs, 'excluded': ['classification refresh', 'catalog loading', 'durable queue/lease', 'network', 'HTTP rendering', 'disk database I/O', 'concurrent writers']}, indent=2))
    engine.dispose()

if __name__ == '__main__':
    main()
