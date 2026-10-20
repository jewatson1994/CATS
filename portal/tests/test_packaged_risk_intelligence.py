"""Signed package KEV overlays are bounded, explicit and informational."""
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.intelligence_models import IntelligencePackageInstall, IntelligenceRecord
from app.vex_models import VexSource
from app.packaged_risk_intelligence import overlay_packaged_kev, packaged_catalog_token
from app.risk_worker import _catalog_current
from app.embedded_intelligence import _materialize_enrichment_catalogs

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)

@pytest.fixture
def package():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        source = VexSource(name='CISA KEV', enabled=True, trusted=True, max_age_days=7)
        db.add(source); db.flush()
        for cve, sha in [('CVE-2026-1234', 'a'), ('CVE-2026-9999', 'b')]:
            db.add(IntelligenceRecord(source_id=source.id, kind='exploitation', record_id=cve, cve=cve, data={}, sha256=sha,
                acquired_at=NOW-timedelta(days=1), source_url='https://example.com/kev', package_version='previous'))
        meta = {'id': 'cisa-kev', 'name': source.name, 'url': 'https://example.com/kev', 'acquired_at': (NOW-timedelta(hours=1)).isoformat(), 'exploitation_sha256s': ['a']}
        install = IntelligencePackageInstall(version='new', sequence=2, manifest={'sources': [meta], 'payload_sha256': 'test'}, counts={})
        db.add(install); db.flush()
        _materialize_enrichment_catalogs(db, install)
        db.commit()
        yield db, source
    engine.dispose()

def snapshot():
    return {'kev': {'state': 'MISSING', 'metadata': {}}, 'epss': {'state': 'MISSING', 'metadata': {}},
            'findings': {'CVE-2026-1234': {'kev': None, 'epss': None}, 'CVE-2026-9999': {'kev': None, 'epss': None}}}

def test_exact_membership_supports_deduplicated_records_but_excludes_removed_entries(package):
    db, _ = package
    original = snapshot()
    merged = overlay_packaged_kev(db, original, NOW)
    assert merged['findings']['CVE-2026-1234']['kev'] is True
    assert merged['findings']['CVE-2026-9999']['kev'] is None
    assert original['findings']['CVE-2026-1234']['kev'] is None
    assert merged['kev']['metadata']['package_version'] == 'new'
    assert merged['kev']['metadata']['date_released'] == (NOW-timedelta(hours=1)).isoformat()
    assert not _catalog_current(merged, NOW, {'max_age_hours': 24})[0]  # KEV does not manufacture EPSS.

@pytest.mark.parametrize('field,value', [('enabled', False), ('trusted', False), ('max_age_days', 0)])
def test_source_administration_invalidates_token_and_prevents_overlay(package, field, value):
    db, source = package
    before = packaged_catalog_token(db)
    setattr(source, field, value); db.flush()
    assert packaged_catalog_token(db) != before
    original = snapshot()
    assert overlay_packaged_kev(db, original, NOW) is original

def test_newer_existing_catalog_is_preserved(package):
    db, _ = package
    original = snapshot()
    original['kev'] = {'state': 'LOADED', 'metadata': {'date_released': NOW.isoformat()}}
    assert overlay_packaged_kev(db, original, NOW) is original

def test_expired_or_future_package_does_not_overlay(package):
    db, _ = package
    for now in (NOW+timedelta(days=8), NOW-timedelta(days=1)):
        original = snapshot()
        assert overlay_packaged_kev(db, original, now) is original

def test_missing_new_membership_does_not_erase_previous_positive_exploitation(package):
    db, _ = package
    original = snapshot()
    original['kev'] = {'state': 'LOADED', 'metadata': {'date_released': (NOW-timedelta(days=1)).isoformat()}}
    original['findings']['CVE-2026-9999']['kev'] = True
    merged = overlay_packaged_kev(db, original, NOW)
    assert merged['findings']['CVE-2026-9999']['kev'] is True
    assert merged['kev']['metadata']['prior_catalog'] == original['kev']

@pytest.fixture
def epss_package():
    from contextlib import contextmanager
    @contextmanager
    def make(*, dated=None, value=0.25, percentile=0.9, signed=True, row_dated=None):
        dated = dated or NOW-timedelta(hours=2)
        engine = create_engine('sqlite://')
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            source = VexSource(name='FIRST EPSS', enabled=True, trusted=True, max_age_days=7)
            db.add(source); db.flush()
            data = dict(epss=value, percentile=percentile, score_date=(row_dated or dated).isoformat(), model_version='vtest')
            db.add(IntelligenceRecord(source_id=source.id, kind='risk_enrichment', record_id='CVE-2026-1234', cve='CVE-2026-1234',
                data=data, sha256='score-a', acquired_at=NOW-timedelta(hours=1), source_url='https://example.com/epss', package_version='previous'))
            # An old, removed score must never be revived by a later package.
            db.add(IntelligenceRecord(source_id=source.id, kind='risk_enrichment', record_id='CVE-2026-9999', cve='CVE-2026-9999',
                data=dict(data, epss=0.8), sha256='removed', acquired_at=NOW-timedelta(hours=1), source_url='https://example.com/epss', package_version='previous'))
            meta = dict(id='first-epss', name=source.name, url='https://example.com/epss', acquired_at=(NOW-timedelta(hours=1)).isoformat(),
                        score_date=dated.isoformat(), model_version='vtest', risk_enrichment_sha256s=['score-a'] if signed else ['other'])
            install = IntelligencePackageInstall(version='new', sequence=2, manifest={'sources': [meta]}, counts={})
            db.add(install); db.flush()
            if signed:
                _materialize_enrichment_catalogs(db, install)
            db.commit()
            yield db, source
        engine.dispose()
    return make


def test_epss_uses_exact_membership_and_keeps_missing_scores_unknown(epss_package):
    from app.packaged_risk_intelligence import overlay_packaged_epss
    with epss_package(value=0.0, percentile=0.0) as (db, _):
        original = snapshot()
        original['findings']['CVE-2026-9999']['epss'] = 0.8
        merged = overlay_packaged_epss(db, original, NOW)
        assert merged['findings']['CVE-2026-1234']['epss'] == 0.0
        assert merged['findings']['CVE-2026-1234']['epss_percentile'] == 0.0
        assert merged['findings']['CVE-2026-9999']['epss'] is None
        assert merged['findings']['CVE-2026-1234']['kev'] is None
        assert original['findings']['CVE-2026-1234']['epss'] is None
        assert merged['epss']['metadata']['package_version'] == 'new'
        assert merged['epss']['metadata']['score_date'] == (NOW-timedelta(hours=2)).isoformat()


@pytest.mark.parametrize('dated', [NOW-timedelta(days=8), NOW+timedelta(hours=1)])
def test_epss_publication_freshness_is_not_reset_by_acquisition(epss_package, dated):
    from app.packaged_risk_intelligence import overlay_packaged_epss
    with epss_package(dated=dated) as (db, _):
        original = snapshot()
        assert overlay_packaged_epss(db, original, NOW) is original


@pytest.mark.parametrize('field,value', [('enabled', False), ('trusted', False), ('max_age_days', 0)])
def test_epss_respects_source_administration(epss_package, field, value):
    from app.packaged_risk_intelligence import overlay_packaged_epss
    with epss_package() as (db, source):
        setattr(source, field, value); db.flush()
        original = snapshot()
        assert overlay_packaged_epss(db, original, NOW) is original


@pytest.mark.parametrize('value', [True, -0.01, 1.01, '0.5'])
def test_epss_rejects_invalid_signed_scores(epss_package, value):
    from app.packaged_risk_intelligence import overlay_packaged_epss
    with epss_package(value=value) as (db, _):
        original = snapshot()
        assert overlay_packaged_epss(db, original, NOW) is original


def test_epss_rejects_mismatched_publication_and_preserves_newer_catalog(epss_package):
    from app.packaged_risk_intelligence import overlay_packaged_epss
    with epss_package(row_dated=NOW-timedelta(days=2)) as (db, _):
        original = snapshot()
        assert overlay_packaged_epss(db, original, NOW) is original
    with epss_package() as (db, _):
        original = snapshot()
        original['epss'] = {'state': 'LOADED', 'metadata': {'score_date': NOW.isoformat()}}
        assert overlay_packaged_epss(db, original, NOW) is original
