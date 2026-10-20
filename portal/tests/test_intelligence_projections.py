"""Small status/token responses must not decode retained membership manifests."""
import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.database import Base
from app.embedded_intelligence import package_status
from app.intelligence_models import IntelligencePackageInstall, IntelligencePackageState
from app.packaged_risk_intelligence import packaged_catalog_token
from app.risk_profiles import digest
from app.vex_models import VexSource


DATE = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture(params=['sqlite', 'postgresql'])
def projection_db(request):
    def decode_without_large_manifest(raw):
        # The database may inspect JSON internally, but must not return these
        # manifests to Python for a small history/token response.
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode('utf-8')
        assert 'must_not_decode_membership' not in raw
        return json.loads(raw)

    url = os.environ.get('CATS_TEST_POSTGRES_URL') if request.param == 'postgresql' else 'sqlite://'
    if not url:
        pytest.skip('Set CATS_TEST_POSTGRES_URL for isolated PostgreSQL projection checks')
    admin = create_engine(url)
    schema = 'status_projection_' + uuid.uuid4().hex
    options = {}
    if request.param == 'postgresql':
        with admin.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA {schema}'))
        options['connect_args'] = {'options': f'-c search_path={schema}'}
    engine = create_engine(url, json_deserializer=decode_without_large_manifest, **options)
    try:
        Base.metadata.create_all(engine, tables=[VexSource.__table__,
            IntelligencePackageInstall.__table__, IntelligencePackageState.__table__])
        with Session(engine) as db:
            yield db
    finally:
        engine.dispose()
        if request.param == 'postgresql':
            with admin.begin() as connection:
                connection.execute(text(f'DROP SCHEMA {schema} CASCADE'))
        admin.dispose()


def manifest(*, large=False, payload=None):
    result = {'built_at': DATE.isoformat(), 'sources': []}
    if payload is not None:
        result['payload_sha256'] = payload
    if large:
        result['must_not_decode_membership'] = [format(n, '064x') for n in range(128)]
    return result


def add_install(db, sequence, value):
    db.add(IntelligencePackageInstall(version=f'package-{sequence}', sequence=sequence,
        installed_at=DATE, manifest=value, counts={'records': sequence}))


def test_history_returns_twenty_summaries_without_decoding_older_manifests(projection_db):
    db = projection_db
    for sequence in range(1, 22):
        add_install(db, sequence, manifest(large=sequence < 21))
    db.add(IntelligencePackageState(id=1, status='installed'))
    db.commit()
    db.expunge_all()

    status = package_status(db)

    assert status['version'] == 'package-21'
    assert status['status'] == 'installed'
    assert [row['sequence'] for row in status['history']] == list(range(21, 1, -1))
    assert status['history'][0] == {'version': 'package-21', 'sequence': 21,
        'installed_at': DATE.isoformat(), 'counts': {'records': 21}}


@pytest.mark.parametrize('payload', [None, 'payload-sha256'])
def test_token_extracts_scalar_payload_without_decoding_manifest(projection_db, payload):
    db = projection_db
    add_install(db, 1, manifest(large=True, payload=payload))
    db.add(VexSource(name='FIRST EPSS', enabled=True, trusted=True, max_age_days=7))
    db.commit()
    db.expunge_all()

    assert packaged_catalog_token(db) == digest({'version': 'package-1', 'sequence': 1,
        'payload': payload, 'sources': [['FIRST EPSS', True, True, 7]]})


def test_token_tracks_latest_package_without_decoding_either_manifest(projection_db):
    db = projection_db
    add_install(db, 1, manifest(large=True, payload='first'))
    db.commit()
    before = packaged_catalog_token(db)
    add_install(db, 2, manifest(large=True, payload='second'))
    db.commit()

    after = packaged_catalog_token(db)
    assert after != before
    assert after == digest({'version': 'package-2', 'sequence': 2,
        'payload': 'second', 'sources': []})


def test_token_without_an_installed_package(projection_db):
    assert packaged_catalog_token(projection_db) is None


def test_latest_status_strips_membership_in_database_and_keeps_public_fields(projection_db):
    db = projection_db
    sources = [{'id': 'epss', 'name': 'FIRST EPSS', 'acquired_at': DATE.isoformat(),
        'max_age_days': 7, 'counts': {'risk_enrichment': 2}, 'coverage': 'Published score snapshot',
        'extensions': {'preserved': True},
        'risk_enrichment_sha256s': ['must_not_decode_membership']},
        {'id': 'kev', 'name': 'CISA KEV', 'acquired_at': DATE.isoformat(), 'max_age_days': 30,
        'counts': {'exploitation': 1}, 'exploitation_sha256s': ['must_not_decode_membership']}]
    add_install(db, 1, {'built_at': DATE.isoformat(), 'sources': sources,
        'exclusions': [{'reason': 'Unavailable terms'}],
        'must_not_decode_membership': 'Other large private manifest fields'})
    db.add(VexSource(name='FIRST EPSS', enabled=False, trusted=False, max_age_days=3))
    db.add(IntelligencePackageState(id=1, status='failed', last_error='Rejected newer package'))
    db.commit()
    db.expunge_all()

    status = package_status(db)

    assert status['status'] == 'failed'
    assert status['last_error'] == 'Rejected newer package'
    assert status['built_at'] == DATE.isoformat()
    assert status['exclusions'] == [{'reason': 'Unavailable terms'}]
    assert [item['id'] for item in status['sources']] == ['epss', 'kev']
    epss = status['sources'][0]
    assert epss['health'] == 'disabled'
    assert epss['max_age_days'] == 3
    assert epss['counts'] == {'risk_enrichment': 2}
    assert epss['extensions'] == {'preserved': True}
    assert not epss['enabled'] and not epss['trusted']
    assert all('risk_enrichment_sha256s' not in item and 'exploitation_sha256s' not in item
               for item in status['sources'])


def test_status_supports_legacy_sources_without_membership_arrays(projection_db):
    db = projection_db
    add_install(db, 1, {'built_at': DATE.isoformat(), 'sources': [
        {'id': 'vendor', 'name': 'Vendor', 'acquired_at': DATE.isoformat(),
         'max_age_days': 30, 'counts': {'vex_documents': 1, 'vex_statements': 2}}]})
    db.commit()
    status = package_status(db)
    assert status['exclusions'] == []
    assert status['sources'][0]['counts']['vex_statements'] == 2
    assert status['sources'][0]['health'] == 'unknown'
