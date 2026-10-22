"""Real signed-package restore drill, driven in two disposable runtime processes.

Run `seed EVIDENCE_DIRECTORY`, pg_dump intelligence and pg_restore into a fresh
database, then run `verify EVIDENCE_DIRECTORY` with INTELLIGENCE_DATABASE_URL
pointing to the restored DB. DATABASE_URL must retain the independent portal DB.
No production database is suitable: seed creates schemas and fixture data.
"""
import base64
import gzip
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import inspect, select, text
from app import database, durable_jobs, service_posture
from app import embedded_intelligence as loader
from app.intelligence_generation import current_generation
from app.intelligence_models import IntelligencePackageInstall
from app.packaged_risk_intelligence import overlay_packaged_epss

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
DATE = '2026-10-18T00:00:00+00:00'


def package(root, sequence, values, key):
    directory = root / str(sequence)
    directory.mkdir()
    entries = [{'source': 'first-epss', 'kind': 'risk_enrichment', 'record_id': cve,
                'cve': cve, 'url': 'https://example.org/data', 'data': {
                    'epss': score, 'percentile': .9, 'score_date': DATE,
                    'model_version': 'vtest'}} for cve, score in values]
    raw = b''.join(loader.canonical(entry) + b'\n' for entry in entries)
    payload = gzip.compress(raw, mtime=0)
    (directory / 'intelligence.jsonl.gz').write_bytes(payload)
    manifest = {'schema': 'cats-embedded-intelligence/v1', 'version': f'package-{sequence}',
                'sequence': sequence, 'built_at': DATE,
                'payload_sha256': hashlib.sha256(payload).hexdigest(),
                'payload_bytes': len(payload), 'uncompressed_bytes': len(raw),
                'sources': [{'id': 'first-epss', 'name': 'first-epss',
                             'category': 'risk_enrichment', 'allowed_hosts': ['example.org'],
                             'authoritative_prefixes': [], 'trusted': True,
                             'max_age_days': 7, 'acquired_at': DATE, 'score_date': DATE,
                             'model_version': 'vtest', 'url': 'https://example.org/data',
                             'license': 'fixture'}]}
    encoded = loader.canonical(manifest)
    (directory / 'manifest.json').write_bytes(encoded)
    (directory / 'manifest.sig').write_bytes(base64.b64encode(key.sign(encoded)))
    return directory


def snapshot(engine):
    with engine.connect() as connection:
        return {name: connection.execute(text(
            f'SELECT row_to_json(t)::text FROM "{name}" t ORDER BY row_to_json(t)::text'
        )).scalars().all() for name in sorted(database.INTELLIGENCE_TABLE_NAMES)}


def check_reads():
    assert database.INTELLIGENCE_SEPARATE
    assert not set(inspect(database.engine).get_table_names()) & database.INTELLIGENCE_TABLE_NAMES
    assert set(inspect(database.intelligence_engine).get_table_names()) == database.INTELLIGENCE_TABLE_NAMES
    initial = {'epss': {'state': 'MISSING'}, 'findings': {
        'CVE-2026-1001': {'epss': None}, 'CVE-2026-1002': {'epss': None}}}
    with database.SessionLocal() as db:
        assert db.bind is None  # Exercise production split RoutingSession.
        assert db.scalar(select(IntelligencePackageInstall.sequence).order_by(
            IntelligencePackageInstall.sequence.desc()).limit(1)) == 2
        fresh = overlay_packaged_epss(db, initial, NOW)
        assert fresh['findings']['CVE-2026-1001']['epss'] == .9
        assert fresh['findings']['CVE-2026-1002']['epss'] is None
        assert overlay_packaged_epss(db, initial, NOW + timedelta(days=8)) == initial
    with database.engine.connect() as connection:
        assert connection.execute(text('SELECT value FROM restore_portal_sentinel')).scalar_one() == 'independent'


def main(mode, root):
    root.mkdir(exist_ok=True)
    pin = root / 'pin.pem'
    if mode == 'seed':
        database.Base.metadata.create_all(database.engine, tables=database.portal_tables())
        database.Base.metadata.create_all(database.intelligence_engine, tables=database.intelligence_tables())
        with database.engine.begin() as connection:
            connection.execute(text('CREATE TABLE restore_portal_sentinel(value text)'))
            connection.execute(text("INSERT INTO restore_portal_sentinel VALUES ('independent')"))
        key = Ed25519PrivateKey.generate()
        pin.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        for sequence, values in [(1, [('CVE-2026-1001', .1), ('CVE-2026-1002', .2)]),
                                 (2, [('CVE-2026-1001', .9)])]:
            assert loader.install_package(database.SessionLocal, package(root, sequence, values, key), key_path=pin) == 'installed'
        check_reads()
        (root / 'before.json').write_text(json.dumps({'rows': snapshot(database.intelligence_engine),
                                                     'generation': current_generation()}))
    elif mode == 'verify':
        before = json.loads((root / 'before.json').read_text())
        assert snapshot(database.intelligence_engine) == before['rows']
        assert current_generation().split('|')[0] == before['generation'].split('|')[0]
        assert current_generation() != before['generation']  # Actual restored DB identity.
        check_reads()
        assert loader.install_package(database.SessionLocal, root / '2', key_path=pin) == 'unchanged'
        assert loader.install_package(database.SessionLocal, root / '1', key_path=pin) == 'older_skipped'
        prior = current_generation()
        with database.intelligence_engine.begin() as connection:
            connection.execute(text('UPDATE vex_sources SET trusted=false'))
        assert current_generation() != prior  # Dump restored working generation triggers.
        initial = {'epss': {'state': 'MISSING'}, 'findings': {'CVE-2026-1001': {'epss': None}}}
        with database.SessionLocal() as db:
            assert overlay_packaged_epss(db, initial, NOW) == initial
    else:
        raise ValueError(mode)
    print(f'{mode}: signed package restore checks passed', flush=True)


if __name__ == '__main__':
    main(sys.argv[1], Path(sys.argv[2]))
