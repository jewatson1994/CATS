"""Opt-in PostgreSQL integration checks; set CATS_TEST_POSTGRES_URL to a test DB.

Each case owns a random schema and drops only that schema in teardown.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text, select, func
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Service
from app.risk_models import RiskPolicyVersion, RiskPolicyAssignment, RiskAssessment, RiskDecision
from app.risk_profiles import create_policy, assign_policy, record_decision, DEFAULT_POLICY
from app.vex_models import VexDocument, VexStatement
import test_risk_profiles as risk_cases
import test_vex_repository as vex_cases


@pytest.fixture
def pgdb(monkeypatch):
    # These cases seed classification state explicitly. A commit-triggered daemon
    # must not replace that fixture or outlive its disposable PostgreSQL schema.
    from app import service_posture
    monkeypatch.setattr(service_posture, "background_enabled", lambda bind: False)
    url = os.environ.get('CATS_TEST_POSTGRES_URL')
    if not url:
        pytest.skip('Set CATS_TEST_POSTGRES_URL for isolated PostgreSQL integration checks')
    engine = create_engine(url)
    assert engine.dialect.name == 'postgresql'
    schema = 'risk_vex_test_' + uuid.uuid4().hex
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA {schema}'))
        scoped = create_engine(url, connect_args={'options': f'-c search_path={schema}'})
        try:
            Base.metadata.create_all(scoped)
            Base.metadata.create_all(scoped)  # Existing tables/triggers must be safe on restart.
            with Session(scoped) as db:
                yield db
        finally:
            scoped.dispose()
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS {schema} CASCADE'))
        engine.dispose()


@pytest.mark.parametrize('scenario', [
    risk_cases.test_inheritance_and_append_only,
    risk_cases.test_decision_requires_evidence_and_is_separate_history,
    vex_cases.test_signed_snapshot_tamper_atomic_and_scope,
    vex_cases.test_exact_matching_scopes_and_dedupe,
    vex_cases.test_stale_conflict_and_withdrawn,
])
def test_postgres_contracts(pgdb, scenario):
    scenario(pgdb)


@pytest.mark.parametrize('scan_age,complete', [(0, True), (48, True), (0, False)])
def test_postgres_worker_materialization(pgdb, monkeypatch, scan_age, complete):
    risk_cases.test_worker_scores_every_latest_observation_before_cve_reduction(pgdb, monkeypatch, scan_age, complete)


def test_postgres_every_history_table_rejects_bulk_mutation(pgdb):
    now = datetime.now(timezone.utc)
    service = Service(name='guard test', service_key='guard-test')
    pgdb.add(service)
    pgdb.flush()
    from app.models import Group
    group = Group(name='Risk policy owner')
    pgdb.add(group); pgdb.flush()
    policy = create_policy(pgdb, 'Guard policy', {}, 'tester', group_id=group.id)
    assignment = assign_policy(pgdb, 'group', group.id, policy.id, 'tester')
    assessment = RiskAssessment(service_id=service.id, policy_id=policy.id, as_of=now,
        valid_until=now+timedelta(days=1), provenance={'configuration': DEFAULT_POLICY}, summary={}, details=[])
    pgdb.add(assessment)
    pgdb.flush()
    record_decision(pgdb, service.id, {'assessment_id': assessment.id, 'kind': 'recommendation',
        'decision': 'accept', 'mission_impact': 'test', 'controls': 'test', 'justification': 'test',
        'reviewer': 'test', 'evidence_refs': ['test:1'], 'expires_at': (now+timedelta(days=1)).isoformat()}, 'tester')
    source = vex_cases.source(pgdb)
    vex_cases.ingest(pgdb, source, vex_cases.raw())
    pgdb.commit()
    for model in (RiskPolicyVersion, RiskPolicyAssignment, RiskAssessment, RiskDecision, VexDocument, VexStatement):
        table = model.__tablename__
        for command in (f'UPDATE {table} SET id=id', f'DELETE FROM {table}'):
            with pytest.raises(DBAPIError, match='immutable'):
                pgdb.execute(text(command))
            pgdb.rollback()
            assert pgdb.scalar(select(func.count()).select_from(model)) == 1


def test_postgres_signed_snapshot_creates_verified_revision(pgdb):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from app.vex_snapshot import export_snapshot, import_snapshot
    from app.vex_intelligence import configure_source, evaluate
    signing = Ed25519PrivateKey.generate()
    public = signing.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    private = signing.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    original = configure_source(pgdb, 'snapshot-publisher', public_key=public, trusted=True,
        trust_reason='Integration test', authoritative_prefixes=['pkg:apk/wolfi/'])
    vex_cases.ingest(pgdb, original, vex_cases.raw())
    payload = export_snapshot(pgdb, original.id, private)
    original.name = 'exporter-retained-history'
    original.enabled = False
    pgdb.flush()
    destination = configure_source(pgdb, 'snapshot-publisher', public_key=public, trusted=True,
        trust_reason='Independent pin', authoritative_prefixes=['pkg:apk/wolfi/'])
    result = import_snapshot(pgdb, destination.id, payload)
    pgdb.commit()
    document = pgdb.get(VexDocument, result['document_ids'][0])
    assert document.source_id == destination.id
    assert document.verification == 'signature' and document.verification_key
    assert evaluate(pgdb, 'CVE-2026-12345', vex_cases.CTX, vex_cases.NOW)['status'] == 'not_affected'
    assert import_snapshot(pgdb, destination.id, payload)['document_ids'] == result['document_ids']


def test_postgres_applicability_query_bounds(pgdb, monkeypatch):
    vex_cases.test_assessment_history_bound_never_returns_partial_safe_conclusion(pgdb, monkeypatch)


def test_postgres_applicability_defers_raw_documents(pgdb):
    vex_cases.test_assessment_defers_raw_vendor_documents(pgdb)


def test_postgres_applicability_exact_pairs(pgdb, monkeypatch):
    vex_cases.test_assessment_pairs_do_not_load_unrequested_cross_products(pgdb, monkeypatch)
