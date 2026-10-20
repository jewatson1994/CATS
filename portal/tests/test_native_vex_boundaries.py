"""Native policy HTTP boundary, durable admission, and database invalidation contracts."""
from datetime import timedelta
import pytest
from sqlalchemy import select, func, text
from sqlalchemy.orm import sessionmaker
from app import native_vex as nv, native_vex_worker as worker
from app.models import AuditEvent, ExceptionRecord
from app.native_vex_models import VexDispositionPolicy, VexDispositionEvaluation, install_generation_triggers
from app.durable_jobs import DurableJob, JobCancelled
from test_native_vex import db, setup, enable, excluded
from test_risk_routes import api, auth, post
from test_vex_repository import NOW
from test_risk_vex_postgres import pgdb


def test_native_policy_permissions_csrf_version_and_audit(api):
    client, db, current = api
    assert client.get('/api/risk/native-vex/policy').status_code == 403
    assert client.get('/api/risk/native-vex/preview').status_code == 403
    assert post(client, '/native-vex/policy', {'enabled':True,'version':1}).status_code == 403
    current['auth'] = auth(('config.manage',), None)
    assert client.get('/api/risk/native-vex/policy').json()['enabled'] is False
    assert client.post('/api/risk/native-vex/policy',json={'enabled':True,'version':1}).status_code == 403
    assert post(client,'/native-vex/policy',{'enabled':1,'version':1}).status_code == 422
    assert post(client,'/native-vex/policy',{'enabled':True,'version':True}).status_code == 422
    assert post(client,'/native-vex/policy',{'enabled':True,'version':1}).json() == {'enabled':True,'version':2}
    assert post(client,'/native-vex/policy',{'enabled':False,'version':1}).status_code == 409
    assert db.scalar(select(func.count()).select_from(AuditEvent)) == 1
    assert post(client,'/native-vex/policy',{'enabled':False,'version':2}).status_code == 200
    assert db.scalar(select(func.count()).select_from(AuditEvent)) == 2


def test_native_evidence_scoping_and_precedence(api, monkeypatch):
    client, db, current = api
    service, finding, observations, src = setup(db)
    enable(db)
    nv.evaluate_service(db, service.id, now=NOW); db.commit()
    import app.risk_routes as routes
    class Clock:
        @staticmethod
        def now(tz): return NOW
    monkeypatch.setattr(routes, 'datetime', Clock)
    path='/api/risk/services/native/native-vex'
    assert client.get(path).status_code == 404
    current['auth'] = auth(('service.view',),service.id)
    assert client.get(path).json()['items'][0]['effective_disposition'] == 'vex_not_affected'
    assert client.get(path+'?finding_id=99999').json()['items'] == []
    assert client.get(path+f'?finding_id={finding.id}').json()['finding_disposition'] == 'vex_not_affected'
    current['auth'] = auth(('service.view','config.manage'),None)
    preview=client.get('/api/risk/native-vex/preview')
    assert preview.status_code == 200, preview.text
    impact=next(item for item in preview.json()['items'] if item['service_id']==service.id)
    assert impact['eligible_before'] == 1 and impact['eligible_after'] == 0
    assert isinstance(impact['compliance_before'], bool)
    assert isinstance(impact['compliance_after'], bool)
    # Non-vulnerability blockers must survive the vulnerability exclusion preview.
    import app.main as main
    monkeypatch.setattr(main, 'service_overview_rows_aggregated', lambda *args: ([{
        'service': service, 'policy_noncompliant': ['required policy evidence'],
        'evidence_noncompliant': False}], {}))
    blocked = client.get('/api/risk/native-vex/preview').json()['items'][0]
    assert blocked['eligible_after'] == 0
    assert blocked['compliance_after'] is False
    db.add(ExceptionRecord(finding_id=finding.id,justification='test',approved_by='reviewer',starts_at=NOW-timedelta(days=1),expires_at=NOW+timedelta(days=1)))
    db.commit()
    assert client.get(path).json()['items'][0]['effective_disposition'] == 'exception'
    finding.active=False; finding.resolved_at=NOW; db.commit()
    assert client.get(path).json()['items'][0]['effective_disposition'] == 'resolved'


def test_worker_admission_deduplicates_and_retries_after_failure(db, monkeypatch):
    service, finding, observations, src = setup(db)
    factory=sessionmaker(bind=db.get_bind())
    monkeypatch.setattr(worker,'utcnow',lambda:NOW)
    assert worker.maintenance(factory) == 1
    assert worker.maintenance(factory) == 0
    job=db.scalar(select(DurableJob)); job.status='failed';job.completed_at=NOW;db.commit()
    assert worker.maintenance(factory) == 0
    job.completed_at=NOW-timedelta(hours=2);db.commit()
    assert worker.maintenance(factory) == 1


def test_worker_cancel_rolls_back_evidence(db, monkeypatch):
    service, finding, observations, src=setup(db)
    monkeypatch.setattr(worker,'SessionLocal',sessionmaker(bind=db.get_bind()))
    class Cancelled:
        def check(self): raise JobCancelled()
    with pytest.raises(JobCancelled):worker.handler(Cancelled(),{'service_id':service.id})
    assert db.scalar(select(func.count()).select_from(VexDispositionEvaluation)) == 0


def test_sqlite_trigger_upgrade_replaces_obsolete_definition(db):
    db.execute(text('DROP TRIGGER native_vex_findings_update'))
    db.execute(text('CREATE TRIGGER native_vex_findings_update AFTER UPDATE ON findings BEGIN SELECT 1; END'))
    install_generation_triggers(db.connection());db.commit()
    service,finding,observations,src=setup(db);enable(db)
    nv.evaluate_service(db,service.id,now=NOW);db.commit()
    assert excluded(db,finding)
    finding.severity='high';db.commit()
    assert not excluded(db,finding)


@pytest.mark.parametrize('mutation',['observation','execution','trust','revision'])
def test_native_postgres_invalidation(pgdb,mutation):
    from test_native_vex import test_bulk_mutations_invalidate_immediately_without_worker
    test_bulk_mutations_invalidate_immediately_without_worker(pgdb,mutation)


def test_native_postgres_mixed(pgdb):
    from test_native_vex import test_mixed_never_excludes_whole_finding
    test_mixed_never_excludes_whole_finding(pgdb)

@pytest.mark.parametrize('mutation', ['product','version','architecture','distribution','trust','authority','conflict','withdrawn','stale'])
def test_native_strict_applicability_end_to_end(db, mutation):
    from test_vex_repository import source, ingest, raw, PID
    service,finding,observations,src=setup(db);enable(db)
    observation=observations[0]
    now=NOW
    if mutation in ('product','architecture','distribution'):
        replacement={'product':PID.replace('libtest','other'), 'architecture':PID.replace('x86_64','aarch64'), 'distribution':PID.replace('wolfi','alpine')}[mutation]
        observation.evidence={**observation.evidence,'purl':replacement}
    elif mutation=='version': observation.installed_version='2.0'
    elif mutation=='trust':src.trusted=False
    elif mutation=='authority':src.authoritative_prefixes=['pkg:apk/other/']
    elif mutation=='conflict':ingest(db,source(db,'other-publisher'),raw('affected'))
    elif mutation=='withdrawn':
        ingest(db,src,raw(issued=NOW+timedelta(seconds=1),withdrawn=True));now+=timedelta(seconds=2)
    elif mutation=='stale':now+=timedelta(days=31)
    db.commit()
    nv.evaluate_service(db,service.id,now=now);db.commit()
    assert not excluded(db,finding,now)
    assert observation.evidence and finding.active

@pytest.mark.parametrize('target',['scan','intelligence','policy'])
def test_postgres_concurrent_change_fences_publication(pgdb,target):
    from sqlalchemy import update
    from sqlalchemy.orm import Session
    from app.models import FindingObservation
    from app.vex_models import VexSource
    service,finding,observations,src=setup(pgdb);enable(pgdb)
    observation_id,source_id=observations[0].id,src.id
    changed=False
    def concurrent_change():
        nonlocal changed
        if changed:return
        changed=True
        with Session(pgdb.get_bind()) as other:
            if target=='scan':other.execute(update(FindingObservation).where(FindingObservation.id==observation_id).values(installed_version='2.0'))
            elif target=='intelligence':other.execute(update(VexSource).where(VexSource.id==source_id).values(trusted=False))
            else:other.execute(update(VexDispositionPolicy).where(VexDispositionPolicy.id==1).values(policy_version=2))
            other.commit()
    with pytest.raises(ValueError,match='changed'):
        nv.evaluate_service(pgdb,service.id,now=NOW,check=concurrent_change)
    pgdb.rollback()
    assert not excluded(pgdb,finding)
    assert pgdb.scalar(select(func.count()).select_from(VexDispositionEvaluation)) == 0


def test_postgres_mixed_consumer_groups_and_members(pgdb):
    from test_native_vex_consumers import test_mixed_groups_only_include_retained_packages_and_unique_members
    test_mixed_groups_only_include_retained_packages_and_unique_members(pgdb)
