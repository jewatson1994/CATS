import base64
import gzip
import hashlib
from pathlib import Path
import pytest
from sqlalchemy import create_engine, select, func, update
from sqlalchemy.orm import sessionmaker
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from app.database import Base
from app.embedded_intelligence import canonical, install_package, package_status
from app.intelligence_models import IntelligenceRecord, IntelligencePackageInstall
from app.vex_models import VexSource, VexDocument, VexStatement

DATE = '2026-10-18T00:00:00+00:00'

@pytest.fixture
def env(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'db.sqlite'))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    key = Ed25519PrivateKey.generate()
    pin = tmp_path / 'pinned.pem'
    pin.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    yield tmp_path, factory, key, pin
    engine.dispose()

def record(n=1):
    return {'source':'vendor', 'kind':'risk_enrichment', 'record_id':str(n), 'cve':'CVE-2026-12345', 'data':{'epss':n/100}, 'url':'https://example.org/feed'}

def vex():
    return {'source':'vendor', 'kind':'vex', 'url':'https://example.org/vex', 'acquired_at':DATE, 'raw':{'@context':'https://openvex.dev/ns/v0.2.0', '@id':'https://example.org/vex', 'version':1, 'timestamp':DATE, 'statements':[{'vulnerability':{'name':'CVE-2026-12345'}, 'products':[{'@id':'pkg:apk/wolfi/test@1'}], 'status':'not_affected', 'justification':'vulnerable_code_not_present'}]}}

def package(env, seq=1, entries=None):
    path, _, key, _ = env
    directory = path / ('package-' + str(seq))
    directory.mkdir(exist_ok=True)
    raw = b''.join(canonical(e)+b'\n' for e in (entries if entries is not None else [record(), vex()]))
    payload = gzip.compress(raw, mtime=0)
    (directory/'intelligence.jsonl.gz').write_bytes(payload)
    manifest = {'schema':'cats-embedded-intelligence/v1', 'version':hashlib.sha256(payload).hexdigest(), 'sequence':seq, 'built_at':DATE, 'payload_sha256':hashlib.sha256(payload).hexdigest(), 'payload_bytes':len(payload), 'uncompressed_bytes':len(raw), 'sources':[{'id':'vendor', 'name':'Vendor', 'category':'mixed', 'allowed_hosts':['example.org'], 'authoritative_prefixes':['pkg:apk/wolfi/'], 'trusted':True, 'max_age_days':30, 'acquired_at':DATE, 'license':'test', 'url':'https://example.org/feed'}]}
    (directory/'manifest.json').write_bytes(canonical(manifest))
    (directory/'manifest.sig').write_bytes(base64.b64encode(key.sign(canonical(manifest))))
    return directory

def install(env, directory):
    return install_package(env[1], directory, key_path=env[3])

def test_install_skip_upgrade_and_history(env):
    directory = package(env)
    assert install(env, directory) == 'installed'
    assert install(env, directory) == 'unchanged'
    with env[1]() as db:
        source = db.scalar(select(VexSource))
        source.trusted = False
        source.enabled = False
        db.commit()
    assert install(env, package(env, 2, [record(2), vex()])) == 'installed'
    assert install(env, directory) == 'older_skipped'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 2
        assert db.scalar(select(func.count(VexDocument.id))) == 1
        assert db.scalar(select(func.count(VexStatement.id))) == 1
        assert db.scalar(select(VexSource)).trusted is False
        assert db.scalar(select(VexSource)).enabled is False
        assert db.scalar(select(VexDocument)).retrieved_at.isoformat().startswith('2026-10-18')
        status = package_status(db)
        assert len(status['history']) == 2
        assert status['sources'][0]['health'] == 'disabled'
        assert status['counts']['vex_statements'] == 1

def test_signature_and_payload_tamper(env):
    directory = package(env)
    (directory/'manifest.sig').write_bytes(base64.b64encode(b'x'*64))
    assert install(env, directory) == 'failed'
    directory = package(env)
    with (directory/'intelligence.jsonl.gz').open('ab') as f:
        f.write(b'tamper')
    assert install(env, directory) == 'failed'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 0
        assert package_status(db)['status'] == 'failed'


def test_supplemental_duplicates_across_batches_and_upgrades_without_hash_scan(env):
    from sqlalchemy import event

    engine = env[1].kw['bind']
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(engine, 'before_cursor_execute', capture)
    try:
        assert install(env, package(env, entries=[record()] * 501)) == 'installed'
        assert install(env, package(env, 2, [record(), record(2), record(2)])) == 'installed'
        with env[1]() as db:
            rows = db.scalars(select(IntelligenceRecord).order_by(IntelligenceRecord.record_id)).all()
            assert len(rows) == 2
            assert rows[0].package_version != rows[1].package_version
        assert not any('select intelligence_records.source_id, intelligence_records.sha256' in sql
                       for sql in statements)
        assert any('on conflict (source_id, sha256) do nothing' in sql for sql in statements)
    finally:
        event.remove(engine, 'before_cursor_execute', capture)

def test_atomic_rollback_and_last_good_status(env):
    assert install(env, package(env)) == 'installed'
    bad = record(99)
    bad['url'] = 'https://attacker.example/feed'
    assert install(env, package(env, 2, [record(n) for n in range(1000)] + [bad])) == 'failed'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 1
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 1
        status = package_status(db)
        assert status['sequence'] == 1
        assert status['status'] == 'failed'
        assert status['last_error']

def test_same_sequence_conflict(env):
    assert install(env, package(env)) == 'installed'
    assert install(env, package(env, 1, [record(2)])) == 'failed'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 1

def test_bulk_immutability(env):
    assert install(env, package(env)) == 'installed'
    with env[1]() as db:
        with pytest.raises(Exception, match='immutable'):
            db.execute(update(IntelligenceRecord).values(cve='CVE-2020-1234'))
        db.rollback()

def test_distribution_cannot_replace_pinned_key(env):
    directory = package(env)
    other = Ed25519PrivateKey.generate()
    (directory/'release-key.pem').write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    (directory/'manifest.sig').write_bytes(base64.b64encode(other.sign((directory/'manifest.json').read_bytes())))
    assert install(env, directory) == 'failed'

def test_current_exploitation_membership_after_upgrade(env):
    first, second = record(1), record(2)
    first['kind'] = second['kind'] = 'exploitation'
    assert install(env, package(env, 1, [first, second])) == 'installed'
    assert install(env, package(env, 2, [second])) == 'installed'
    with env[1]() as db:
        status = package_status(db)
        hashes = db.scalar(select(IntelligencePackageInstall).where(IntelligencePackageInstall.sequence == 2)).manifest['sources'][0]['exploitation_sha256s']
        assert len(hashes) == 1
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 2
        assert db.scalar(select(IntelligenceRecord).where(IntelligenceRecord.sha256.in_(hashes))).record_id == '2'

def test_concurrent_install_is_serialized(env):
    from concurrent.futures import ThreadPoolExecutor
    directory = package(env)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: install(env, directory), range(2)))
    assert sorted(results) == ['installed', 'unchanged']
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 1


def test_same_sequence_metadata_conflict(env):
    directory = package(env)
    assert install(env, directory) == 'installed'
    import json
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    manifest['sources'][0]['max_age_days'] = 3650
    raw = canonical(manifest)
    (directory / 'manifest.json').write_bytes(raw)
    (directory / 'manifest.sig').write_bytes(base64.b64encode(env[2].sign(raw)))
    assert install(env, directory) == 'failed'

def test_package_upgrade_preserves_risk_and_cyber_history(env):
    from datetime import datetime, timedelta, timezone
    from app.risk_models import RiskAssessment, RiskDecision
    # The fixture intentionally creates metadata before these optional models load.
    Base.metadata.create_all(env[1].kw['bind'])
    now = datetime.now(timezone.utc)
    with env[1]() as db:
        assessment = RiskAssessment(service_id=123, as_of=now, valid_until=now+timedelta(days=1), provenance={'original':'evidence'}, summary={'score':72}, details=[{'finding_id':123}])
        db.add(assessment)
        db.flush()
        decision = RiskDecision(service_id=123, assessment_id=assessment.id, kind='cyber', decision='accepted', payload={'reason':'original decision'}, created_by='analyst', expires_at=now+timedelta(days=1))
        db.add(decision)
        db.commit()
    assert install(env, package(env)) == 'installed'
    assert install(env, package(env, 2, [record(2)])) == 'installed'
    with env[1]() as db:
        assessment = db.scalar(select(RiskAssessment))
        decision = db.scalar(select(RiskDecision))
        assert assessment.summary == {'score':72}
        assert assessment.provenance == {'original':'evidence'}
        assert decision.payload == {'reason':'original decision'}
        assert decision.assessment_id == assessment.id

def test_verified_retry_clears_previous_failure(env):
    directory = package(env)
    assert install(env, directory) == 'installed'
    assert install(env, package(env, 2, [dict(record(), url='http://example.org/feed')])) == 'failed'
    assert install(env, directory) == 'unchanged'
    with env[1]() as db:
        assert package_status(db)['status'] == 'installed'
        assert package_status(db)['last_error'] is None


def test_main_lifespan_automatically_calls_installer(monkeypatch):
    monkeypatch.delenv('INTELLIGENCE_DATABASE_URL', raising=False)
    import asyncio
    from app import main, embedded_intelligence
    calls = []
    class StartupObserved(Exception):
        pass
    def installer(factory):
        calls.append(factory)
        raise StartupObserved()
    monkeypatch.setattr(embedded_intelligence, 'install_package', installer)
    async def enter():
        async with main.app_lifespan(main.app):
            raise AssertionError('Expected test startup boundary')
    with pytest.raises(StartupObserved):
        asyncio.run(enter())
    assert calls == [main.SessionLocal]


def test_split_database_startup_does_not_run_importer(monkeypatch):
    import asyncio
    from app import main, embedded_intelligence
    monkeypatch.setenv('INTELLIGENCE_DATABASE_URL', 'postgresql://separate/intelligence')
    def forbidden(*args):
        raise AssertionError('Portal startup must not import intelligence')
    class RecoveryReached(Exception):
        pass
    def recovery():
        raise RecoveryReached()
    monkeypatch.setattr(embedded_intelligence, 'install_package', forbidden)
    monkeypatch.setattr(main.validator_management, 'recover_operations', recovery)
    async def enter():
        async with main.app_lifespan(main.app):
            pass
    with pytest.raises(RecoveryReached):
        asyncio.run(enter())

def test_supplemental_trust_does_not_require_product_authority(env):
    directory = package(env, entries=[record()])
    import json
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    manifest['sources'][0]['category'] = 'enrichment'
    manifest['sources'][0]['authoritative_prefixes'] = []
    raw = canonical(manifest)
    (directory / 'manifest.json').write_bytes(raw)
    (directory / 'manifest.sig').write_bytes(base64.b64encode(env[2].sign(raw)))
    assert install(env, directory) == 'installed'
    with env[1]() as db:
        source = db.scalar(select(VexSource))
        assert source.trusted
        assert source.authoritative_prefixes == []

def test_newer_sequence_with_same_payload_preserves_revisions(env):
    assert install(env, package(env, 1)) == 'installed'
    assert install(env, package(env, 2)) == 'installed'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 1
        assert db.scalar(select(func.count(VexDocument.id))) == 1
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 2


def test_payload_replaced_after_preflight_rolls_back(env, monkeypatch):
    from app import embedded_intelligence as loader
    directory = package(env, entries=[record(1)])
    original = loader._manifest
    def replace_after_verification(*args):
        manifest = original(*args)
        replacement = gzip.compress(canonical(record(2)) + b'\n', mtime=0)
        (directory / 'intelligence.jsonl.gz').write_bytes(replacement)
        return manifest
    monkeypatch.setattr(loader, '_manifest', replace_after_verification)
    assert install(env, directory) == 'failed'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 0
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 0
        assert 'Payload changed' in package_status(db)['last_error']


def advisory(n=1):
    return dict(record(n), kind='advisory', data={'id': str(n), 'affected': [
        {'package': {'ecosystem': 'PyPI', 'name': 'example'}, 'versions': ['1.0']}]})


def advisory_members(db, sequence):
    from app.intelligence_models import IntelligencePackageCatalog, IntelligencePackageMember
    return db.execute(select(IntelligenceRecord.record_id, IntelligenceRecord.package_version)
        .join(IntelligencePackageMember, IntelligencePackageMember.record_id == IntelligenceRecord.id)
        .join(IntelligencePackageCatalog, IntelligencePackageCatalog.id == IntelligencePackageMember.catalog_id)
        .join(IntelligencePackageInstall, IntelligencePackageInstall.id == IntelligencePackageCatalog.install_id)
        .where(IntelligencePackageInstall.sequence == sequence, IntelligencePackageCatalog.kind == 'advisory')).all()


def test_advisory_membership_projects_exact_signed_entries_and_reuses_older_records(env):
    from app.intelligence_models import IntelligencePackageCatalog
    assert install(env, package(env, 1, [advisory(1), advisory(2), advisory(2)])) == 'installed'
    assert install(env, package(env, 2, [advisory(2)])) == 'installed'
    with env[1]() as db:
        first = db.scalar(select(IntelligencePackageInstall).where(IntelligencePackageInstall.sequence == 1))
        second = db.scalar(select(IntelligencePackageInstall).where(IntelligencePackageInstall.sequence == 2))
        assert {row.record_id for row in advisory_members(db, 1)} == {'1', '2'}
        assert advisory_members(db, 2) == [('2', first.version)]
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 2
        catalogs = db.scalars(select(IntelligencePackageCatalog).order_by(IntelligencePackageCatalog.install_id)).all()
        assert [row.record_count for row in catalogs] == [2, 1]
        assert all(not any(key.endswith('_sha256s') for key in row.metadata_json) for row in catalogs)
        assert 'advisory_sha256s' not in second.manifest['sources'][0]


def test_same_sequence_advisory_backfill_authenticates_membership_without_reimport(env, monkeypatch):
    from app import embedded_intelligence as loader
    project = loader._materialize_advisory_catalogs
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', lambda *args: None)
    assert install(env, package(env, 1, [advisory(1), advisory(2)])) == 'installed'
    directory = package(env, 2, [advisory(2)])
    assert install(env, directory) == 'installed'
    with env[1]() as db:
        installed = db.scalar(select(IntelligencePackageInstall).where(IntelligencePackageInstall.sequence == 2))
        before = (installed.id, installed.manifest, installed.counts, installed.installed_at)
        existing = db.scalar(select(IntelligenceRecord).where(IntelligenceRecord.record_id == '2'))
        # A matching package_version alone must never grant current membership.
        db.add(IntelligenceRecord(source_id=existing.source_id, kind='advisory', record_id='unsigned',
            cve=existing.cve, data={}, sha256='f' * 64, acquired_at=existing.acquired_at,
            source_url=existing.source_url, package_version=installed.version))
        db.commit()
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', project)
    monkeypatch.setattr(loader, '_import', lambda *args: pytest.fail('Existing evidence must not be reimported'))
    assert install(env, directory) == 'unchanged'
    monkeypatch.setattr(loader, '_authenticated_payload', lambda *args: pytest.fail('Complete catalogs must not be projected again'))
    assert install(env, directory) == 'unchanged'
    with env[1]() as db:
        installed = db.get(IntelligencePackageInstall, before[0])
        assert (installed.id, installed.manifest, installed.counts, installed.installed_at) == before
        assert [row.record_id for row in advisory_members(db, 2)] == ['2']
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 3
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 2


def test_advisory_backfill_rolls_back_if_authenticated_member_is_missing(env, monkeypatch):
    from app import embedded_intelligence as loader
    from app.intelligence_models import IntelligencePackageCatalog, IntelligencePackageMember
    project = loader._materialize_advisory_catalogs
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', lambda *args: None)
    directory = package(env, entries=[advisory(1)])
    assert install(env, directory) == 'installed'
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', project)
    # Simulate a missing record lookup without mutating immutable evidence.
    original = loader._decode
    monkeypatch.setattr(loader, '_decode', lambda raw: dict(advisory(2)) if b'"record_id"' in raw else original(raw))
    assert install(env, directory) == 'failed'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligencePackageCatalog.id))) == 0
        assert db.scalar(select(func.count()).select_from(IntelligencePackageMember)) == 0
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 1
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 1
        assert 'membership is incomplete' in package_status(db)['last_error']


def test_advisory_backfill_reauthenticates_payload_after_preflight(env, monkeypatch):
    from app import embedded_intelligence as loader
    from app.intelligence_models import IntelligencePackageCatalog
    project = loader._materialize_advisory_catalogs
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', lambda *args: None)
    directory = package(env, entries=[advisory(1)])
    assert install(env, directory) == 'installed'
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', project)
    original = loader._manifest
    def replace_after_verification(*args):
        manifest = original(*args)
        with (directory / 'intelligence.jsonl.gz').open('ab') as stream:
            stream.write(b'tamper')
        return manifest
    monkeypatch.setattr(loader, '_manifest', replace_after_verification)
    assert install(env, directory) == 'failed'
    with env[1]() as db:
        assert db.scalar(select(func.count(IntelligencePackageCatalog.id))) == 0
        assert 'Payload changed' in package_status(db)['last_error']


def test_advisory_projection_batches_and_deduplicates_across_batch_boundaries(env):
    entries = [advisory(n) for n in range(405)] + [advisory(1)]
    assert install(env, package(env, entries=entries)) == 'installed'
    with env[1]() as db:
        assert len(advisory_members(db, 1)) == 405
