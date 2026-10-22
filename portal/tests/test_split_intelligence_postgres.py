"""Opt-in real PostgreSQL tests with independently owned portal/intelligence DBs.

CATS_TEST_SPLIT_POSTGRES_URL must name a disposable server with CREATE DATABASE
privileges. Each case creates and drops only its own randomly named databases.
"""
import os
import uuid

import pytest
from sqlalchemy import create_engine, inspect, select, text

from app import database, service_posture
from app.database import Base
import test_native_vex as native_cases
import test_risk_profiles as risk_cases
import test_vex_repository as vex_cases


@pytest.fixture
def splitdb(monkeypatch):
    url = os.environ.get('CATS_TEST_SPLIT_POSTGRES_URL')
    if not url:
        pytest.skip('Set CATS_TEST_SPLIT_POSTGRES_URL for isolated split PostgreSQL checks')
    admin = create_engine(url, isolation_level='AUTOCOMMIT')
    assert admin.dialect.name == 'postgresql'
    names = ['split_portal_' + uuid.uuid4().hex, 'split_intel_' + uuid.uuid4().hex]
    engines = []
    created = []
    monkeypatch.setattr(service_posture, 'background_enabled', lambda bind: False)
    try:
        with admin.connect() as connection:
            for name in names:
                connection.execute(text(f'CREATE DATABASE {name}'))
                created.append(name)
                engines.append(create_engine(admin.url.set(database=name)))
        portal, intel = engines
        for name, value in [('engine', portal), ('background_engine', portal),
                            ('intelligence_engine', intel), ('intelligence_background_engine', intel),
                            ('INTELLIGENCE_SEPARATE', True)]:
            monkeypatch.setattr(database, name, value)
        Base.metadata.create_all(portal, tables=database.portal_tables())
        Base.metadata.create_all(intel, tables=database.intelligence_tables())
        assert not set(inspect(portal).get_table_names()) & database.INTELLIGENCE_TABLE_NAMES
        assert set(inspect(intel).get_table_names()) == database.INTELLIGENCE_TABLE_NAMES
        with database.SessionLocal() as db:
            assert db.bind is None
            yield db
    finally:
        for engine in engines:
            engine.dispose()
        with admin.connect() as connection:
            for name in created:
                connection.execute(text(f'DROP DATABASE {name} WITH (FORCE)'))
        admin.dispose()


@pytest.mark.parametrize('scenario', [
    native_cases.test_older_evaluation_cannot_publish_after_mutation,
    vex_cases.test_exact_matching_scopes_and_dedupe,
    vex_cases.test_stale_conflict_and_withdrawn,
])
def test_split_runtime_contracts(splitdb, scenario):
    scenario(splitdb)


@pytest.mark.parametrize('mutation', ['observation', 'execution', 'trust', 'revision'])
def test_split_native_invalidation(splitdb, mutation):
    from sqlalchemy import update
    from app import native_vex as nv
    from app.models import FindingObservation, Execution
    from app.vex_models import VexSource
    from datetime import timedelta
    service, finding, observations, source = native_cases.setup(splitdb)
    native_cases.enable(splitdb)
    evaluation = nv.evaluate_service(splitdb, service.id, now=vex_cases.NOW)
    splitdb.commit()
    assert evaluation.summary['excluded_observations'] == 1
    assert 'atomic intelligence invalidation' in evaluation.summary['exclusion_unavailable_reason']
    assert not native_cases.excluded(splitdb, finding)
    assert not splitdb.scalar(select(nv.finding_excluded(finding.id, vex_cases.NOW, preview=True)))
    assert not splitdb.scalar(select(nv.observation_excluded(observations[0].id, vex_cases.NOW)))
    if mutation == 'observation':
        splitdb.execute(update(FindingObservation).values(installed_version='2.0'))
    elif mutation == 'execution':
        splitdb.execute(update(Execution).values(complete=False))
    elif mutation == 'trust':
        splitdb.execute(update(VexSource).values(trusted=False))
    else:
        vex_cases.ingest(splitdb, source, vex_cases.raw('affected', issued=vex_cases.NOW + timedelta(seconds=1)))
    splitdb.flush()
    assert not native_cases.excluded(splitdb, finding)
    splitdb.commit()
    assert not native_cases.excluded(splitdb, finding)
    assert finding.active


@pytest.mark.parametrize('scan_age,complete', [(0, True), (48, True), (0, False)])
def test_split_risk_materialization(splitdb, monkeypatch, scan_age, complete):
    risk_cases.test_worker_scores_every_latest_observation_before_cve_reduction(
        splitdb, monkeypatch, scan_age, complete)

@pytest.mark.parametrize('mode,reason', [('disabled', 'untrusted_or_disabled'),
    ('untrusted', 'untrusted_or_disabled'), ('stale', 'stale'), ('withdrawn', 'withdrawn')])
def test_split_advisory_trust_and_freshness(splitdb, mode, reason):
    import test_container_intelligence as cases
    from app.vex_models import VexSource
    from app.intelligence_models import IntelligencePackageInstall, IntelligencePackageCatalog
    splitdb.add(VexSource(id=1, name='Signed advisory source', trusted=True, enabled=True, max_age_days=30))
    splitdb.add(IntelligencePackageInstall(id=1, sequence=1, version='one', manifest={}, counts={}))
    splitdb.flush()
    splitdb.add(IntelligencePackageCatalog(id=1, install_id=1, source_id=1, source_key='advisory',
        kind='advisory', metadata_json={'acquired_at': cases.NOW.isoformat()}, record_count=1))
    splitdb.flush()
    cases.test_advisory_trust_freshness_and_withdrawal(splitdb, mode, reason)


def test_split_transaction_rollback_and_sql_ownership(splitdb):
    from app.models import Service
    from app.vex_models import VexSource
    splitdb.add(Service(name='rollback', service_key='rollback'))
    splitdb.add(VexSource(name='rollback', trusted=False, enabled=False))
    splitdb.flush()
    assert splitdb.scalar(select(Service.id))
    assert splitdb.scalar(select(VexSource.id))
    splitdb.rollback()
    assert splitdb.scalar(select(Service.id)) is None
    assert splitdb.scalar(select(VexSource.id)) is None
    with pytest.raises(ValueError, match='spanning portal and intelligence'):
        splitdb.execute(select(Service, VexSource))


def test_split_risk_reads_live_intelligence_after_independent_trust_change(splitdb, monkeypatch):
    from app import finding_classification as fc, policy_data
    from app.risk_worker import refresh_assessment
    from app.models import FindingClassificationState
    from app.vex_models import VexSource
    from sqlalchemy import update
    service, finding, observations, source = native_cases.setup(splitdb)
    splitdb.add(FindingClassificationState(service_id=service.id, algorithm=2, config_digest='test', findings=1))
    splitdb.commit()
    monkeypatch.setattr(fc, '_service_configuration', lambda *a: {})
    monkeypatch.setattr(fc, 'status', lambda *a: ('current', 0))
    monkeypatch.setattr(policy_data, 'risk_catalog_token', lambda: 'stable')
    feed = {'state': 'LOADED', 'metadata': {'score_date': vex_cases.NOW.isoformat(), 'date_released': vex_cases.NOW.isoformat()}}
    monkeypatch.setattr(policy_data, 'review_intelligence_snapshot', lambda *a: {
        'kev': feed, 'epss': feed, 'findings': {finding.cve: {'epss': .1, 'kev': False}}})
    first = refresh_assessment(splitdb, service.id, vex_cases.NOW)
    splitdb.commit()
    assert first.details[0]['observations'][0]['vex']['status'] == 'not_affected'
    with database.IntelligenceSessionLocal() as importer:
        importer.execute(update(VexSource).where(VexSource.id == source.id).values(trusted=False))
        importer.commit()
    splitdb.expire_all()
    second = refresh_assessment(splitdb, service.id, vex_cases.NOW)
    assert second.details[0]['observations'][0]['vex']['status'] != 'not_affected'
    assert second.provenance['vex_token'] != first.provenance['vex_token']
    assert second.details[0]['score'] >= first.details[0]['score']



def test_split_native_policy_reports_configured_but_unavailable(splitdb):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app import risk_routes as routes
    from app.auth import require_user
    from test_risk_routes import auth
    native_cases.enable(splitdb)
    application = FastAPI()
    application.include_router(routes.router)
    application.dependency_overrides[require_user] = lambda: auth(('config.manage',), None)
    application.dependency_overrides[routes.get_db] = lambda: splitdb
    with TestClient(application) as client:
        response = client.get('/api/risk/native-vex/policy')
    assert response.status_code == 200
    assert response.json()['enabled'] is True
    assert response.json()['effective_available'] is False
    assert 'findings remain actionable' in response.json()['unavailable_reason']
