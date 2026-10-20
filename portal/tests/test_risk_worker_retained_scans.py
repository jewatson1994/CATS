"""Actual retained scanner rows through classification + saved risk assessment.

Only these tests inject trusted synthetic VEX; no finding identity is invented.
The companion CLI uses the shipped populated corpus without fixture statements.
"""
from datetime import datetime, timedelta
import importlib.util
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Group, ServiceGroup, Service, Finding, ExceptionRecord
from app.risk_models import RiskAssessment
from app.vex_intelligence import _VERIFIED, configure_source, ingest_document

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('retained_worker_verifier', ROOT / 'scripts/verify-container-risk-worker.py')
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


@pytest.mark.parametrize('with_fixture_vex', [False, True])
def test_retained_real_scans_survive_worker_with_unchanged_classification(with_fixture_vex):
    captures = verifier.load_captures(ROOT / 'docs/evidence/container-vex-scans', ('alpine-3-20-0', 'ubuntu'))
    now = max(datetime.fromisoformat(c['capture']['completed_at']) for c, _ in captures) + timedelta(hours=1)
    engine = create_engine('sqlite://')
    # Import model metadata before constructing this disposable test schema.
    from app import main  # noqa: F401
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(bind=connection, join_transaction_mode='rollback_only') as db:
                service_id, execution_id, observed = verifier.stage_service(db, captures, 'retained-scan-unit')
                alpine = captures[0][0]
                row = alpine['findings'][0]
                mismatch = next(r for r in alpine['findings'] if r['cve'] != row['cve'] and r['package'] == row['package'])
                # Existing exception must survive even when display-only VEX changes.
                finding = db.scalar(select(Finding).where(Finding.service_id == service_id, Finding.cve == row['cve']))
                db.add(ExceptionRecord(finding_id=finding.id, justification='Fixture exception preservation',
                    approved_by='pytest fixture', starts_at=now - timedelta(hours=1), expires_at=now + timedelta(days=1)))
                if with_fixture_vex:
                    source = configure_source(db, 'Synthetic retained-scan test publisher', trusted=True,
                        allowed_hosts=['fixture.example'], authoritative_prefixes=['pkg:apk/alpine/'],
                        trust_reason='TEST ONLY: exact retained identity and deliberate mismatched version')
                    old_purl = mismatch['purl'].replace('@' + mismatch['installed_version'], '@0-fixture')
                    fixture = {'@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'synthetic-retained-scan-fixture',
                        'version': 1, 'timestamp': now.isoformat(), 'statements': [
                            {'vulnerability': {'name': row['cve']}, 'products': [{'@id': row['purl']}],
                             'status': 'not_affected', 'justification': 'vulnerable_code_not_present'},
                            {'vulnerability': {'name': mismatch['cve']}, 'products': [{'@id': old_purl}],
                             'status': 'not_affected', 'justification': 'vulnerable_code_not_present'}]}
                    ingest_document(db, source.id, json.dumps(fixture).encode(), verification='tls',
                        source_url='https://fixture.example/test-vex.json', _proof=_VERIFIED, retrieved_at=now)
                db.flush()
                report, details = verifier.assess_staged(db, service_id, execution_id, observed, now)
                assert report['observations'] == 140
                assert report['owning_groups'] == 1
                assert report['findings'] < report['observations']
                assert report['summary']['visual_only'] is True
                assert report['summary']['assessment_state'] == 'assessed'
                assert report['classification_and_scan_rows_unchanged']
                assert report['provenance']['source_execution_id'] == execution_id
                assert len(report['summary']['coverage']['images']) == 2
                assert any(o['classification']['excepted'] for item in details for o in item['observations'])
                target = next(o for item in details if item['cve'] == row['cve'] for o in item['observations']
                              if o['identity']['raw_purl'] == row['purl'])
                rejected = next(o for item in details if item['cve'] == mismatch['cve'] for o in item['observations']
                                if o['identity']['raw_purl'] == mismatch['purl'])
                if with_fixture_vex:
                    assert target['vex']['status'] == 'not_affected'
                    assert target['vex']['statements'][0]['accepted'] is True
                    assert target['vex']['statements'][0]['document_id']
                    assert target['identity']['image_digest'] == alpine['image_digest']
                    assert 'digest' not in target['identity']['context']
                    assert rejected['vex']['status'] == 'no_vex'
                    assert rejected['vex']['exact_candidate_count'] == 0
                    assert rejected['vex']['cve_present'] is True
                    assert any(r.get('sample_only') and 'identity' in r['reason'] for r in rejected['vex']['rejected_candidates'])
                    assert report['summary']['coverage']['counts']['applicable_vex'] >= 1
                    assert report['summary']['coverage']['counts']['identity_rejected'] >= 1
                else:
                    assert target['vex']['status'] == 'no_vex'
                    assert report['summary']['coverage']['counts']['applicable_vex'] == 0
                assert db.get(RiskAssessment, report['assessment_id_before_rollback']) is not None
                assert transaction.is_active
        finally:
            transaction.rollback()
    with Session(engine) as db:
        assert db.scalar(select(Service.id).where(Service.service_key == 'retained-scan-unit')) is None
        assert db.scalar(select(RiskAssessment.id)) is None
        assert db.scalar(select(Group.id)) is None
        assert db.scalar(select(ServiceGroup.service_id)) is None
    engine.dispose()
