"""Conservative advisory enrichment, unique-finding coverage and evidence access."""
from datetime import datetime, timedelta, timezone
import json
from test_intelligence_membership import isolated_engine
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from app.database import Base
from app import container_intelligence as ci
from app.intelligence_models import IntelligenceRecord, IntelligencePackageInstall, IntelligencePackageCatalog, IntelligencePackageMember
from app.vex_models import VexSource, VexDocument
from test_risk_routes import api, auth
from app.risk_models import RiskAssessment

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)
CVE = 'CVE-2026-12345'

@pytest.fixture
def db(tmp_path, request):
    with isolated_engine(tmp_path, json.loads) as engine:
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(VexSource(id=1, name='Signed advisory source', trusted=True, enabled=True, max_age_days=30))
            session.add(IntelligencePackageInstall(id=1, sequence=1, version='one', manifest={}, counts={}))
            session.flush()
            session.add(IntelligencePackageCatalog(id=1, install_id=1, source_id=1, source_key='advisory', kind='advisory', metadata_json={'acquired_at': getattr(request, 'param', NOW.isoformat())}, record_count=1))
            session.flush()
            yield session


def advisory(db, data, identity=1, member=True):
    db.add(IntelligenceRecord(id=identity, source_id=1, kind='advisory', record_id=str(identity), cve=CVE,
        data=data, sha256=f'{identity:064x}', acquired_at=NOW, source_url='https://publisher.example/advisory', package_version='one'))
    db.flush()  # Persist the record before its membership FK on PostgreSQL.
    if member:
        db.add(IntelligencePackageMember(catalog_id=1, record_id=identity))
    db.flush()

def item(purl='pkg:pypi/requests@1.2', cve=CVE, aliases=None):
    identity = ci.observation_identity(SimpleNamespace(evidence={'purl': purl, 'aliases': aliases or []}, image_digest=None, installed_version=purl.split('@')[-1]))
    return {'cve': cve, 'identity': identity, 'context': identity['context'], 'aliases': aliases or []}

def osv(ecosystem='PyPI', name='requests', **extra):
    return {'affected': [{'package': {'ecosystem': ecosystem, 'name': name}, 'versions': ['1.2'], **extra}]}

@pytest.mark.parametrize('purl,ecosystem,name', [
    ('pkg:pypi/Requests@1.2', 'PyPI', 'requests'), ('pkg:maven/org.test/example@1.2', 'Maven', 'org.test:example'),
    ('pkg:npm/%40test/example@1.2', 'npm', '@test/example'), ('pkg:golang/example.org/lib@1.2', 'Go', 'example.org/lib'),
    ('pkg:nuget/Example@1.2', 'NuGet', 'Example'), ('pkg:cargo/example@1.2', 'crates.io', 'example')])
def test_ecosystem_specific_references_never_establish_vex(db, purl, ecosystem, name):
    advisory(db, osv(ecosystem, name))
    result = ci.advisory_batch(db, [item(purl)], NOW)[0]
    assert result['has_current'] and result['records'][0]['match_reason'] == 'explicit_version_list'
    assert result['records'][0]['applicability'] == 'advisory_reference_only'
    assert 'status' not in result
    assert ci.evaluate_container_batch(db, [item(purl)], NOW)[0]['status'] == 'no_vex'

@pytest.mark.parametrize('data', [osv('npm', 'requests'), osv(name='request'), osv(versions=['1.3']),
    {'affected': ['bad', None, {'package': 'bad'}]}, osv(versions='1.2'), osv(versions=[], ranges='anything')])
def test_advisory_wrong_or_malformed_scope_has_no_link(db, data):
    advisory(db, data)
    assert ci.advisory_batch(db, [item()], NOW)[0]['records'] == []

def test_ranges_are_reference_only_and_scanner_aliases_work(db):
    advisory(db, osv(versions=[], ranges=[{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '9'}]}]))
    result = ci.advisory_batch(db, [item(cve='GHSA-example', aliases=[CVE])], NOW)[0]
    assert result['has_current'] and result['records'][0]['match_reason'] == 'package_reference_ranges_not_evaluated'
    assert result['records'][0]['version_ranges_evaluated'] is False

def test_retained_historical_records_are_not_current_membership(db):
    advisory(db, osv(), member=False)
    assert not ci.advisory_batch(db, [item()], NOW)[0]['has_current']
    db.add(IntelligencePackageMember(catalog_id=1, record_id=1)); db.flush()
    assert ci.advisory_batch(db, [item()], NOW)[0]['has_current']
    db.add(IntelligencePackageInstall(id=2, sequence=2, version='two', manifest={}, counts={})); db.flush()
    assert not ci.advisory_batch(db, [item()], NOW)[0]['has_current']

@pytest.mark.parametrize('mode,reason', [('disabled','untrusted_or_disabled'), ('untrusted','untrusted_or_disabled'), ('stale','stale'), ('withdrawn','withdrawn')])
def test_advisory_trust_freshness_and_withdrawal(db, mode, reason):
    advisory(db, osv() | ({'withdrawn': NOW.isoformat()} if mode == 'withdrawn' else {}))
    if mode == 'disabled': db.get(VexSource,1).enabled = False
    if mode == 'untrusted': db.get(VexSource,1).trusted = False
    db.flush()
    result = ci.advisory_batch(db, [item()], NOW + timedelta(days=31) if mode == 'stale' else NOW)[0]
    assert not result['has_current'] and result['records'][0]['reason'] == reason
    assert result['valid_until'] is None

def test_current_evidence_beyond_display_limit_is_counted(db):
    for index in range(1,23): advisory(db, osv() | ({'withdrawn': NOW.isoformat()} if index <=20 else {}), index)
    result = ci.advisory_batch(db,[item()],NOW)[0]
    assert result['truncated'] and len(result['records']) ==20 and result['has_current']
    assert result['valid_until'] == (NOW + timedelta(days=30)).isoformat()
    report = ci.coverage_report([{'finding_id':1,'observations':[{'observation_id':1,'advisory':result}]}],NOW)
    assert report['counts']['advisory_only'] ==1

def test_advisory_overflow_discards_partial_results(db,monkeypatch):
    advisory(db,osv(),1); advisory(db,osv(),2)
    monkeypatch.setattr(ci,'MAX_ADVISORY_CANDIDATES',1)
    result=ci.advisory_batch(db,[item()],NOW)[0]
    assert result['records']==[] and result['reasons']==['advisory_candidate_limit']
    assert result['valid_until'] is None

def test_batch_queries_are_bounded_and_do_not_load_raw_documents(db):
    advisory(db,osv())
    sql=[]
    def capture(conn,cursor,statement,params,context,many): sql.append(statement)
    event.listen(db.get_bind(),'before_cursor_execute',capture)
    try: ci.advisory_batch(db,[item() for _ in range(250)],NOW)
    finally: event.remove(db.get_bind(),'before_cursor_execute',capture)
    assert len(sql)==1 and 'raw_text' not in sql[0]

def test_coverage_unions_duplicates_sources_and_images():
    first={'observation_id':1,'image':'a','image_digest':'one','kev':True,'epss':.5,'vex':{'exact_candidate_count':2,'statements':[{'accepted':True}]}}
    second={'observation_id':2,'image':'b','image_digest':'two','advisory':{'has_current':True}}
    report=ci.coverage_report([{'finding_id':1,'observations':[first,first,second]}, {'finding_id':2,'observations':[{'vex':{'applicability_state':'missing_context'}}]}],NOW)
    assert report['total_findings']==2 and report['counts']['applicable_vex']==1
    assert report['counts']['advisory_only']==0 and report['counts']['kev']==1 and report['counts']['epss']==1
    assert report['counts']['no_intelligence']==1 and report['counts']['unresolved_identity']==1
    assert next(r for r in report['images'] if r['image']=='b')['counts']['advisory_only']==1

@pytest.mark.parametrize('epss',[True,False,float('nan'),float('inf'),-1,1.1,'0.1',None])
def test_invalid_epss_does_not_claim_coverage(epss):
    result=ci.coverage_report([{'finding_id':1,'observations':[{'observation_id':1,'epss':epss}]}],NOW)
    assert result['counts']['epss']==0 and result['counts']['no_intelligence']==1

def test_overflow_preserves_uncertainty_without_false_identity_claim(monkeypatch):
    monkeypatch.setattr(ci,'evaluate_batch',lambda *a,**k:[{'status':'under_investigation','reasons':['candidate_limit']}])
    monkeypatch.setattr(ci,'_presence_samples',lambda db,cves: {} if not cves else pytest.fail('overflow must not probe'))
    result=ci.evaluate_container_batch(None,[item()],NOW)[0]
    assert result['cve_present'] is None and 'candidate_limit' in result['reasons']
    assert 'cve_present_without_exact_product' not in result['reasons']
    assert 'cve_absent_from_vex' not in result['reasons']
    assert not result.get('rejected_candidates')

def test_revision_rejection_is_not_identity_rejection():
    report=ci.coverage_report([{'finding_id':1,'observations':[{'observation_id':1,'vex':{'rejected_candidates':[{'reason':'future_dated'}]}}]}],NOW)
    assert report['counts']['identity_rejected']==0

@pytest.mark.parametrize('candidate_key',['statements','rejected_candidates'])
def test_original_document_access_requires_service_scope_and_assessment_reference(api,candidate_key):
    client,db,current=api
    db.add(VexSource(id=1,name='Vendor'))
    db.add(VexDocument(id=1,source_id=1,sha256='a'*64,raw_text='{"original":true}',format='openvex',document_key='one',version='1',issued_at=NOW))
    db.commit()
    row=RiskAssessment(service_id=1,as_of=NOW,valid_until=NOW+timedelta(days=1),provenance={},summary={},
        details=[{'observations':[{'vex':{candidate_key:[{'document_id':1}]}}]}])
    db.add(row); db.commit()
    path=f'/api/risk/assessments/{row.id}/documents/1'
    assert client.get(path).json()['raw_text']=='{"original":true}'
    assert client.get(f'/api/risk/assessments/{row.id}/documents/2').status_code==404
    current['auth']=auth(service_id=2)
    assert client.get(path).status_code==404
    current['auth']=auth(())
    assert client.get(path).status_code==404


def test_oversized_advisory_scope_is_not_materialized_or_used(db,monkeypatch):
    advisory(db,osv(versions=['1.2']*100))
    monkeypatch.setattr(ci,'MAX_ADVISORY_SCOPE_BYTES',100)
    result=ci.advisory_batch(db,[item()],NOW)[0]
    assert result['records']==[] and 'advisory_scope_limit' in result['reasons']


@pytest.mark.parametrize('db', [None, 'invalid', '9999-12-31T00:00:00+00:00',
                               (NOW + timedelta(days=1)).isoformat()], indirect=True)
def test_unusable_advisory_acquisition_does_not_supply_expiry(db):
    advisory(db, osv())
    result = ci.advisory_batch(db, [item()], NOW)[0]
    assert not result['has_current'] and result['has_stale']
    assert result['valid_until'] is None


def test_earliest_current_advisory_expiry_is_retained(db):
    advisory(db, osv())
    db.add(VexSource(id=2, name='Short lived advisory', trusted=True, enabled=True, max_age_days=1))
    db.flush()
    db.add(IntelligencePackageCatalog(id=2, install_id=1, source_id=2, source_key='short-lived',
        kind='advisory', metadata_json={'acquired_at': NOW.isoformat()}, record_count=1))
    db.add(IntelligenceRecord(id=2, source_id=2, kind='advisory', record_id='2', cve=CVE,
        data=osv(), sha256='2'*64, acquired_at=NOW, source_url='https://publisher.example/short',
        package_version='one'))
    db.flush()
    db.add(IntelligencePackageMember(catalog_id=2, record_id=2))
    db.flush()
    result = ci.advisory_batch(db, [item()], NOW)[0]
    assert result['candidate_count'] == 2
    assert result['valid_until'] == (NOW + timedelta(days=1)).isoformat()


@pytest.mark.parametrize('db', [(NOW + timedelta(minutes=1) - timedelta(days=30)).isoformat()], indirect=True)
def test_assessment_expires_when_current_advisory_expires(db, monkeypatch):
    from app import finding_classification as fc, policy_data
    from app.models import Execution, Finding, FindingClassificationState, FindingObservation, Service
    from app.risk_profiles import aware, latest_assessment
    from app.risk_worker import refresh_assessment

    # This test controls classification freshness; do not race its fixture with a background rebuild.
    monkeypatch.setattr(fc, 'schedule', lambda *args: None)
    expiry = NOW + timedelta(minutes=1)
    advisory(db, osv())
    service = Service(name='advisory expiry', service_key='advisory-expiry')
    db.add(service)
    db.flush()
    execution = Execution(service_id=service.id, execution_key='scan', scanned_at=NOW,
                          complete=True, raw_payload={})
    finding = Finding(service_id=service.id, cve=CVE, severity='high', first_seen=NOW,
                      episode_started=NOW, last_seen=NOW, active=True)
    db.add_all([execution, finding])
    db.flush()
    db.add(FindingClassificationState(service_id=service.id, algorithm=2, config_digest='test',
        latest_execution_id=execution.id, findings=1, valid_until=NOW + timedelta(hours=1)))
    db.add(FindingObservation(finding_id=finding.id, execution_id=execution.id,
        image='registry.example/app:1', package='requests', installed_version='1.2',
        evidence={'purl': 'pkg:pypi/requests@1.2'}))
    db.commit()
    monkeypatch.setattr(fc, '_service_configuration', lambda *args: {})
    monkeypatch.setattr(fc, 'status', lambda *args: ('current', 0))
    monkeypatch.setattr(policy_data, 'risk_catalog_token', lambda: 'stable')
    feeds = {
        'kev': {'state': 'LOADED', 'metadata': {'date_released': NOW.isoformat()}},
        'epss': {'state': 'LOADED', 'metadata': {'score_date': NOW.isoformat()}},
    }
    monkeypatch.setattr(policy_data, 'review_intelligence_snapshot', lambda *args: {
        **feeds, 'findings': {CVE: {'epss': .1, 'kev': False}}})
    monkeypatch.setattr(policy_data, 'intelligence_status', lambda: feeds)

    assessment = refresh_assessment(db, service.id, NOW)
    db.commit()
    assert aware(assessment.valid_until) == expiry
    assert assessment.details[0]['observations'][0]['advisory']['valid_until'] == expiry.isoformat()
    assert assessment.summary['coverage']['counts']['advisory_only'] == 1
    current = latest_assessment(db, service.id, NOW)
    assert not current['stale'], current['stale_reasons']
    expired = latest_assessment(db, service.id, NOW + timedelta(minutes=2))
    assert expired['stale'] and expired['stale_reasons'] == ['assessment_expired']
