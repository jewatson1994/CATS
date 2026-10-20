"""Signed catalog projections preserve history while bounding assessment reads."""
import base64
import gzip
import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, select, func, update, delete, text
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app import embedded_intelligence as loader
from app.embedded_intelligence import install_package as install_signed_package
from app.intelligence_models import (IntelligenceRecord, IntelligencePackageInstall,
    IntelligencePackageCatalog, IntelligencePackageMember)
from app.packaged_risk_intelligence import (overlay_packaged_epss, overlay_packaged_kev,
    _current_catalog, _current_records)

DATE = '2026-10-18T00:00:00+00:00'
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


@contextmanager
def isolated_engine(tmp_path, decode):
    """Use an owned schema on PostgreSQL; never reset the shared database."""
    url = os.environ.get('CATS_TEST_DATABASE_URL')
    if not url or not url.startswith('postgresql'):
        engine = create_engine('sqlite:///' + str(tmp_path / 'db.sqlite'), json_deserializer=decode)
        try:
            yield engine
        finally:
            engine.dispose()
        return
    admin = create_engine(url)
    schema = 'intelligence_membership_test_' + uuid.uuid4().hex
    try:
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA {schema}'))
        engine = create_engine(url, connect_args={'options': f'-c search_path={schema}'},
                               json_deserializer=decode)
        try:
            yield engine
        finally:
            engine.dispose()
    finally:
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS {schema} CASCADE'))
        admin.dispose()


@pytest.fixture
def signed_catalog(tmp_path):
    decoding = {'forbid_manifest': False}
    def decode(raw):
        if not isinstance(raw, str):
            raw = bytes(raw).decode('utf-8')
        if decoding['forbid_manifest']:
            assert 'must_not_decode_full_manifest' not in raw
        return json.loads(raw)
    with isolated_engine(tmp_path, decode) as engine:
        Base.metadata.create_all(engine)
        Base.metadata.create_all(engine)  # Additive schema creation remains restart-safe.
        factory = sessionmaker(engine)
        key = Ed25519PrivateKey.generate()
        pin = tmp_path / 'pin.pem'
        pin.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        def package(sequence, values, source_key='first-epss'):
            kind = 'advisory' if source_key == 'advisory-fixture' else 'risk_enrichment' if source_key == 'first-epss' else 'exploitation'
            entries = [{'source': source_key, 'kind': kind, 'record_id': cve, 'cve': cve,
                'url': 'https://example.org/data', 'data': {'epss': score, 'percentile': .9,
                    'score_date': DATE, 'model_version': 'vtest'}} for cve, score in values]
            raw = b''.join(loader.canonical(entry) + b'\n' for entry in entries)
            payload = gzip.compress(raw, mtime=0)
            path = tmp_path / str(sequence)
            path.mkdir()
            (path / 'intelligence.jsonl.gz').write_bytes(payload)
            manifest = {'schema': 'cats-embedded-intelligence/v1', 'version': 'package-' + str(sequence),
                'sequence': sequence, 'built_at': DATE, 'payload_sha256': hashlib.sha256(payload).hexdigest(),
                'payload_bytes': len(payload), 'uncompressed_bytes': len(raw),
                'must_not_decode_full_manifest': True, 'sources': [{'id': source_key, 'name': source_key,
                    'category': kind, 'allowed_hosts': ['example.org'], 'authoritative_prefixes': [],
                    'trusted': True, 'max_age_days': 7, 'acquired_at': DATE, 'score_date': DATE,
                    'model_version': 'vtest', 'url': 'https://example.org/data', 'license': 'fixture'}]}
            encoded = loader.canonical(manifest)
            (path / 'manifest.json').write_bytes(encoded)
            (path / 'manifest.sig').write_bytes(base64.b64encode(key.sign(encoded)))
            return path
        def install(path):
            return install_signed_package(factory, path, key_path=pin)
        yield factory, package, install, decoding


def observation():
    return {'epss': {'state': 'MISSING'}, 'kev': {'state': 'MISSING'}, 'findings': {
        'CVE-2026-1001': {'epss': None, 'kev': None},
        'CVE-2026-1002': {'epss': None, 'kev': None},
        'CVE-2026-1003': {'epss': None, 'kev': None}}}


@pytest.mark.parametrize('source_key', ['first-epss', 'cisa-kev'])
def test_signed_updates_reuse_evidence_and_select_only_current_members(signed_catalog, source_key):
    factory, package, install, decoding = signed_catalog
    first = package(1, [('CVE-2026-1001', .1), ('CVE-2026-1002', .2), ('CVE-2026-1003', .3)], source_key)
    second = package(2, [('CVE-2026-1001', .9), ('CVE-2026-1003', .3)], source_key)
    assert install(first) == install(second) == 'installed'
    decoding['forbid_manifest'] = True
    assert install(second) == 'unchanged'
    assert install(first) == 'older_skipped'
    with factory() as db:
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 4
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 2
        assert db.scalar(select(func.count(IntelligencePackageCatalog.id))) == 2
        assert db.scalar(select(func.count()).select_from(IntelligencePackageMember)) == 5
        kind = 'risk_enrichment' if source_key == 'first-epss' else 'exploitation'
        catalog = _current_catalog(db, source_key, kind)
        rows = list(_current_records(db, catalog.id, list(observation()['findings']), scores=True))
        assert {cve: data['epss'] for cve, data in rows} == {'CVE-2026-1001': .9, 'CVE-2026-1003': .3}
        assert not any(key.endswith('_sha256s') for key in catalog.metadata_json)
        overlay = overlay_packaged_epss if source_key == 'first-epss' else overlay_packaged_kev
        result = overlay(db, observation(), NOW)
        field = 'epss' if source_key == 'first-epss' else 'kev'
        assert result['findings']['CVE-2026-1001'][field] == (.9 if field == 'epss' else True)
        assert result['findings']['CVE-2026-1002'][field] is None
        assert result[field]['records'] == 2


def test_existing_signed_install_backfills_once_without_reimport(signed_catalog, monkeypatch):
    factory, package, install, decoding = signed_catalog
    path = package(1, [('CVE-2026-1001', .1)])
    materialize = loader._materialize_enrichment_catalogs
    monkeypatch.setattr(loader, '_materialize_enrichment_catalogs', lambda *args: None)
    assert install(path) == 'installed'  # Simulate a package installed before the additive tables existed.
    monkeypatch.setattr(loader, '_materialize_enrichment_catalogs', materialize)
    assert install(path) == 'unchanged'
    decoding['forbid_manifest'] = True
    assert install(path) == 'unchanged'
    with factory() as db:
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 1
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 1
        assert db.scalar(select(func.count()).select_from(IntelligencePackageMember)) == 1
        assert overlay_packaged_epss(db, observation(), NOW)['findings']['CVE-2026-1001']['epss'] == .1


@pytest.mark.parametrize('model', [IntelligencePackageCatalog, IntelligencePackageMember])
@pytest.mark.parametrize('operation', ['update', 'delete'])
def test_materialized_signed_membership_is_immutable(signed_catalog, model, operation):
    factory, package, install, _ = signed_catalog
    assert install(package(1, [('CVE-2026-1001', .1)])) == 'installed'
    with factory() as db:
        statement = delete(model) if operation == 'delete' else update(model).values(
            {('record_count' if model is IntelligencePackageCatalog else 'record_id'): 999})
        with pytest.raises(Exception, match='immutable'):
            db.execute(statement)
        db.rollback()


def test_membership_materialization_failure_rolls_back_whole_install(signed_catalog, monkeypatch):
    factory, package, install, _ = signed_catalog
    materialize = loader._materialize_enrichment_catalogs
    def fail_after_materializing(db, installed):
        materialize(db, installed)
        raise ValueError('simulated projection failure')
    monkeypatch.setattr(loader, '_materialize_enrichment_catalogs', fail_after_materializing)
    assert install(package(1, [('CVE-2026-1001', .1)])) == 'failed'
    with factory() as db:
        for model in (IntelligenceRecord, IntelligencePackageInstall, IntelligencePackageCatalog, IntelligencePackageMember):
            assert db.scalar(select(func.count()).select_from(model)) == 0


def test_advisory_backfill_projects_only_current_signed_members_on_each_dialect(signed_catalog, monkeypatch):
    factory, package, install, decoding = signed_catalog
    project = loader._materialize_advisory_catalogs
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', lambda *args: None)
    assert install(package(1, [('CVE-2026-1001', .1), ('CVE-2026-1002', .2)], 'advisory-fixture')) == 'installed'
    current = package(2, [('CVE-2026-1002', .2)], 'advisory-fixture')
    assert install(current) == 'installed'
    monkeypatch.setattr(loader, '_materialize_advisory_catalogs', project)
    decoding['forbid_manifest'] = True
    assert install(current) == 'unchanged'
    assert install(current) == 'unchanged'
    with factory() as db:
        catalog = db.scalar(select(IntelligencePackageCatalog).where(IntelligencePackageCatalog.kind == 'advisory'))
        assert catalog.record_count == 1
        rows = db.execute(select(IntelligenceRecord.cve, IntelligenceRecord.package_version)
            .join(IntelligencePackageMember, IntelligencePackageMember.record_id == IntelligenceRecord.id)
            .where(IntelligencePackageMember.catalog_id == catalog.id)).all()
        assert rows == [('CVE-2026-1002', 'package-1')]
        assert db.scalar(select(func.count(IntelligenceRecord.id))) == 2
        assert db.scalar(select(func.count(IntelligencePackageInstall.id))) == 2
        assert not any(key.endswith('_sha256s') for key in catalog.metadata_json)
