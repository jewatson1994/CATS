from datetime import datetime, timedelta, timezone
from copy import deepcopy
from time import perf_counter
import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, Group, ServiceGroup
from app.risk_models import RiskPolicyVersion, RiskAssessment
from app.risk_profiles import DEFAULT_POLICY, validate_policy, score_observation, create_policy, assign_policy, resolve_policy, record_decision

@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()

@pytest.mark.parametrize('config', [{'unknown': 1}, {'max_age_hours': 0}, {'epss_weight': float('nan')}, {'thresholds': {'low': 0, 'medium': 50, 'high': 40, 'critical': 90}}, {'exception_multiplier': 2}])
def test_invalid_policy(config):
    with pytest.raises(ValueError):
        validate_policy(config)

def test_kev_overrides_vex_and_uncertainty_cannot_reduce():
    p = validate_policy({})
    result = score_observation(p, severity='critical', epss=0.2, kev=True, vex={'status': 'not_affected'})
    assert result['score'] >= p['kev_override']
    affected = score_observation(p, severity='high', epss=.1, kev=False, vex={'status': 'affected'})
    for status in ('conflicting', 'stale', 'under_investigation', 'unverified', 'no_vex'):
        uncertain = score_observation(p, severity='high', epss=.1, kev=False, vex={'status': status})
        assert uncertain['uncertain'] and uncertain['score'] >= affected['score']
    stale = score_observation(p, severity='critical', epss=.2, kev=False, vex={'status': 'not_affected'}, intelligence_current=False)
    assert stale['score'] >= 85
    missing = score_observation(p, severity='high', epss=None, kev=False, vex={'status': 'not_affected'})
    assert missing['score'] >= 65

def test_inheritance_and_append_only(db):
    parent = Group(name='parent'); child = Group(name='child')
    db.add(parent); db.flush(); child.parent_id = parent.id; db.add(child)
    service = Service(name='svc', service_key='svc'); db.add(service); db.flush()
    db.add(ServiceGroup(service_id=service.id, group_id=child.id)); db.flush()
    p1 = create_policy(db, 'Default', {}, 'admin', group_id=parent.id)
    p2 = create_policy(db, 'Default', {'epss_weight': 20}, 'admin', group_id=parent.id)
    assert p2.version == 2 and p1.digest != p2.digest
    with pytest.raises(ValueError, match='group scope'):
        assign_policy(db, 'default', 0, p1.id, 'admin')
    assign_policy(db, 'group', parent.id, p2.id, 'admin')
    assert resolve_policy(db, service.id)[0].id == p2.id
    with pytest.raises(ValueError, match='group scope'):
        assign_policy(db, 'service', service.id, p1.id, 'admin')
    with pytest.raises(ValueError, match='belong'):
        assign_policy(db, 'group', child.id, p1.id, 'admin')
    from app.risk_models import RiskPolicyAssignment
    db.add(RiskPolicyAssignment(scope='service', scope_id=service.id, policy_id=p1.id, created_by='legacy'))
    db.flush()
    assert resolve_policy(db, service.id)[0].id == p2.id
    assign_policy(db, 'group', parent.id, None, 'admin')
    assert resolve_policy(db, service.id)[0] is None
    db.commit()
    with pytest.raises(Exception, match='immutable'):
        db.execute(update(RiskPolicyVersion).where(RiskPolicyVersion.id == p1.id).values(name='tampered'))
    db.rollback()
    from app.risk_models import RiskPolicyGroup
    assert db.get(RiskPolicyGroup, p1.id).display_name == 'Default'

def test_decision_requires_evidence_and_is_separate_history(db):
    now = datetime.now(timezone.utc)
    assessment = RiskAssessment(service_id=1, as_of=now, valid_until=now+timedelta(days=1), provenance={'configuration': DEFAULT_POLICY}, summary={}, details=[])
    db.add(assessment); db.flush()
    payload = {'assessment_id': assessment.id, 'kind': 'recommendation', 'decision': 'accept', 'mission_impact': 'Limited', 'controls': 'Isolation', 'justification': 'Review complete', 'reviewer': 'Cyber', 'evidence_refs': ['ticket:123'], 'expires_at': (now+timedelta(days=1)).isoformat()}
    first = record_decision(db, 1, payload, 'cyber')
    second = record_decision(db, 1, {**payload, 'kind': 'ao_decision', 'decision': 'reject'}, 'AO')
    assert first.id != second.id and first.kind == 'recommendation'
    with pytest.raises(ValueError):
        record_decision(db, 2, payload, 'cyber')
    with pytest.raises(ValueError):
        record_decision(db, 1, {**payload, 'evidence_refs': []}, 'cyber')

def test_scoring_microbenchmark():
    policy = validate_policy({})
    started = perf_counter()
    for _ in range(10000):
        result = score_observation(policy, severity='high', epss=.3, kev=False, age_days=40, vex={'status': 'affected'})
    elapsed = perf_counter() - started
    assert result['score'] == 73.94
    print(f'Pure scoring benchmark: 10000 observations in {elapsed:.3f}s; excludes SQL, VEX lookup and rendering')

@pytest.mark.parametrize('scan_age, complete', [(0, True), (48, True), (0, False)])
def test_worker_scores_every_latest_observation_before_cve_reduction(db, monkeypatch, scan_age, complete):
    from app import finding_classification as fc, policy_data, vex_intelligence, container_intelligence
    from app.models import Execution, Finding, FindingObservation, FindingClassificationState
    from app.risk_worker import refresh_assessment
    now = datetime.now(timezone.utc)
    service = Service(name='mixed', service_key='mixed'); db.add(service); db.flush()
    execution = Execution(service_id=service.id, execution_key='one', scanned_at=now-timedelta(hours=scan_age), complete=complete, raw_payload={}); db.add(execution); db.flush()
    finding = Finding(service_id=service.id, cve='CVE-2026-1234', severity='high', first_seen=now, episode_started=now, last_seen=now, active=True)
    db.add(finding); db.flush()
    missing = Finding(service_id=service.id, cve='CVE-2026-9999', severity='high', first_seen=now, episode_started=now, last_seen=now, active=True)
    db.add(missing); db.flush()
    for package in ('proven', 'unknown'):
        db.add(FindingObservation(finding_id=finding.id, execution_id=execution.id, image='image', package=package, installed_version='1', evidence={'purl': 'pkg:generic/'+package+'@1'}))
    db.add(FindingClassificationState(service_id=service.id, algorithm=2, config_digest='test', findings=1))
    db.commit()
    monkeypatch.setattr(fc, '_service_configuration', lambda *a: {})
    monkeypatch.setattr(fc, 'status', lambda *a: ('current', 0))
    monkeypatch.setattr(policy_data, 'risk_catalog_token', lambda: 'stable')
    feed = {'state': 'LOADED', 'metadata': {'score_date': now.isoformat(), 'date_released': now.isoformat()}}
    monkeypatch.setattr(policy_data, 'review_intelligence_snapshot', lambda *a: {'kev': feed, 'epss': feed, 'findings': {finding.cve: {'epss': .1, 'kev': False}, missing.cve: {'epss': .1, 'kev': True}}})
    monkeypatch.setattr(vex_intelligence, 'intelligence_token', lambda db: 'vex')
    seen = []
    def evaluate(db, items, as_of=None):
        seen.extend(items)
        return [{'status': 'not_affected'}, {'status': 'no_vex'}]
    monkeypatch.setattr(container_intelligence, 'evaluate_container_batch', evaluate)
    assessment = refresh_assessment(db, service.id, now)
    assert len(seen) == 2
    detail = assessment.details[0]
    assert len(detail['observations']) == 2
    assert detail['score'] == max(x['score'] for x in detail['observations'])
    if scan_age == 0 and complete:
        assert detail['score'] > detail['observations'][0]['score']
        assert assessment.provenance['scan_current']
    else:
        assert detail['observations'][0]['uncertain']
        assert detail['observations'][0]['score'] >= 65
        assert not assessment.provenance['scan_current']
    assert detail['uncertain']
    assert finding.active and finding.severity == 'high'
    missing_detail = next(item for item in assessment.details if item['finding_id'] == missing.id)
    assert missing_detail['uncertain'] and missing_detail['score'] >= DEFAULT_POLICY['kev_override']
    assert 'No observation in latest execution' in missing_detail['observations'][0]['reasons']


@pytest.mark.parametrize('overrides', [
    {'severity': None}, {'severity': 'unknown'}, {'severity': 'unrecognized'},
    {'epss': float('nan')}, {'epss': float('inf')}, {'epss': -1}, {'epss': '0.1'},
    {'kev': 'false'}, {'vex': {'status': 'not_affected', 'stale': True}},
    {'vex': {'status': 'not_affected', 'conflict': True}}, {'vex': {'status': 'unexpected'}},
])
def test_invalid_or_unknown_evidence_never_reduces(overrides):
    policy = validate_policy({'exception_multiplier': 0.01})
    args = {'severity': 'high', 'epss': .1, 'kev': False, 'excepted': True, 'vex': {'status': 'not_affected'}}
    result = score_observation(policy, **{**args, **overrides})
    assert result['uncertain']
    assert result['score'] >= policy['missing_floor']
    assert 'Applicable trusted VEX not affected' not in result['reasons']
    assert 'Configured exception weighting; no enforcement change' not in result['reasons']


def test_worker_rechecks_cancellation_under_publication_lock(monkeypatch):
    from types import SimpleNamespace
    from app import risk_worker, database
    from app.durable_jobs import JobCancelled
    class SessionStub:
        committed = False
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def commit(self):
            self.committed = True
    session = SessionStub()
    monkeypatch.setattr(database, 'SessionLocal', lambda: session)
    monkeypatch.setattr(risk_worker, 'refresh_assessment', lambda *a, **k: SimpleNamespace(id=1))
    context = SimpleNamespace(check=lambda: None, _owned=lambda db: SimpleNamespace(cancel_requested=True))
    with pytest.raises(JobCancelled):
        risk_worker.handler(context, {'service_id': 1})
    assert not session.committed
