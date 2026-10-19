"""Lifecycle persistence, digest boundaries, and failure non-renewal."""
from datetime import timedelta
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from app.database import Base
from app import oci_lifecycle as lifecycle
from app.cyber_approvals import CyberApproval, digest
from app.models import Service, Execution
from app.durable_jobs import DurableJob, now

@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key='one', name='One')
        db.add(service); db.flush()
        execution = Execution(service_id=service.id, execution_key='one', scanned_at=now(), complete=True, raw_payload={})
        db.add(execution); db.flush()
        snapshot = {'artifacts': [{'kind': 'image', 'reference': 'registry.example/image@sha256:' + 'a'*64, 'digest': 'sha256:'+'a'*64}]}
        row = CyberApproval(service_id=service.id, source_execution_id=execution.id, variant='current_service',
            status='approved', snapshot=snapshot, snapshot_digest=digest(snapshot))
        db.add(row); db.flush()
        db.add(lifecycle.OCIReassessmentSchedule(approval_id=row.id, actor_id=1, interval_days=7, next_run=now()-timedelta(days=1)))
        db.commit()
        yield db
    engine.dispose()

def test_due_submission_is_durable_and_idempotent(db):
    clock = now()
    lifecycle.enqueue_due(db, clock)
    # A new database session models worker restart; no in-memory scheduler state is reused.
    with Session(db.get_bind()) as restarted:
        lifecycle.enqueue_due(restarted, clock)
    db.expire_all()
    assert db.scalar(select(func.count()).select_from(DurableJob)) == 1
    assert db.scalar(select(func.count()).select_from(lifecycle.OCIReassessmentEvent)) == 1
    job = db.scalar(select(DurableJob))
    assert job.kind == lifecycle.KIND and job.max_attempts == 1
    lifecycle.enqueue_due(db, clock + timedelta(days=8))
    assert db.scalar(select(func.count()).select_from(DurableJob)) == 2

def test_revocation_disables_schedule_without_job(db):
    row = db.scalar(select(CyberApproval)); row.revoked_at = now(); db.commit()
    lifecycle.enqueue_due(db)
    assert not db.get(lifecycle.OCIReassessmentSchedule, row.id).enabled
    assert db.scalar(select(func.count()).select_from(DurableJob)) == 0

@pytest.mark.parametrize('reference', ['registry/image:latest', 'registry/image@sha256:abc', 'registry/image@sha256:'+'A'*64])
def test_mutable_or_invalid_identity_rejected(reference):
    with pytest.raises(HTTPException):
        lifecycle.scan_references(SimpleNamespace(snapshot={'artifacts':[{'kind':'image','reference':reference}]}))

def test_chart_requires_complete_assessment():
    with pytest.raises(HTTPException):
        lifecycle.scan_references(SimpleNamespace(snapshot={'artifacts':[{'kind':'chart'}]}))

@pytest.mark.parametrize('status', ['failed','error','incomplete','cancelled'])
def test_scan_failure_never_creates_or_extends_approval(db, monkeypatch, status):
    import sys
    from app import main
    lifecycle.enqueue_due(db)
    event = db.scalar(select(lifecycle.OCIReassessmentEvent)); event.scan_id='scan'; event.state='scanning'; db.commit()
    original = db.scalar(select(CyberApproval)); original_snapshot = dict(original.snapshot)
    monkeypatch.setattr(main, 'PUBLIC_JOBS', {'scan': {'status': status}})
    lifecycle.reconcile(db)
    assert event.state == 'failed'
    assert original.snapshot == original_snapshot
    assert db.scalar(select(func.count()).select_from(CyberApproval)) == 1

def test_interrupted_dispatch_requires_review_without_duplicate(db, monkeypatch):
    from app import main
    lifecycle.enqueue_due(db)
    job = db.scalar(select(DurableJob)); job.status = 'failed'; db.commit()
    lifecycle.reconcile(db)
    assert db.get(lifecycle.OCIReassessmentEvent, job.id).state == 'failed'
    lifecycle.enqueue_due(db)
    assert db.scalar(select(func.count()).select_from(DurableJob)) == 1

def test_public_key_history_does_not_expose_secrets(db, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    configs=[]
    for _ in range(2):
        pem=ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        normalized, fp=lifecycle.signing.public_key(pem)
        config={'public_key':normalized,'fingerprint':fp,'private_key':'secret','password':'secret'}
        lifecycle.retain_public_key(db,config); configs.append(config)
    db.commit()
    monkeypatch.setattr(lifecycle.signing,'configuration',lambda _:configs[1])
    keys=lifecycle.public_keys(db)['keys']
    assert len(keys)==2 and sum(k['current'] for k in keys)==1
    assert all(set(k)=={'fingerprint','public_key','current'} for k in keys)
from test_cyber_approvals import db as approval_db, auth, request
import asyncio
from app import cyber_approvals as approvals

def test_renewal_creates_pending_record_and_preserves_old_decision(approval_db, monkeypatch):
    db = approval_db
    original_result = asyncio.run(approvals.request_approval(request({'service_key':'one'}), db, auth()))
    original = db.get(CyberApproval, original_result['id'])
    original.status = 'approved'
    original.requested_at = now()-timedelta(days=2)
    previous_snapshot = dict(original.snapshot)
    fresh = Execution(service_id=original.service_id, execution_key='fresh', complete=True, scanned_at=now(), raw_payload={'version':'1.0','findings':[]})
    db.add(fresh); db.commit()
    monkeypatch.setattr(approvals, '_readiness', lambda *args: {'ready':True,'blockers':[],'execution':fresh,'remediation':None,'artifacts':[]})
    result=asyncio.run(approvals.request_approval(request({'service_key':'one','renews_approval_id':original.id}),db,auth()))
    renewal=db.get(CyberApproval,result['id'])
    assert renewal.id != original.id and renewal.status=='pending'
    assert renewal.snapshot['renews_approval_id']==original.id
    assert 'approval_validity' not in renewal.snapshot
    assert original.snapshot==previous_snapshot and original.status=='approved'
    assert db.scalar(select(func.count()).select_from(DurableJob))==0

def test_failed_or_same_scan_cannot_renew(approval_db, monkeypatch):
    db=approval_db
    result=asyncio.run(approvals.request_approval(request({'service_key':'one'}),db,auth()))
    original=db.get(CyberApproval,result['id']); original.status='approved'; db.commit()
    with pytest.raises(HTTPException,match='fresh complete'):
        asyncio.run(approvals.request_approval(request({'service_key':'one','renews_approval_id':original.id}),db,auth()))
    assert db.scalar(select(func.count()).select_from(CyberApproval))==1

def test_successful_scan_reconciles_to_new_review_once(db, monkeypatch):
    from app import main
    lifecycle.enqueue_due(db)
    event=db.scalar(select(lifecycle.OCIReassessmentEvent)); event.scan_id='scan'; event.state='scanning'; db.commit()
    actor=SimpleNamespace(csrf_token='internal')
    service=db.get(Service,1)
    monkeypatch.setattr(lifecycle,'_actor',lambda *args:(actor,service))
    monkeypatch.setattr(main,'PUBLIC_JOBS',{'scan':{'status':'complete'}})
    calls=[]
    monkeypatch.setattr(main,'ingest_public_scan',lambda *args,**kwargs:(calls.append('ingest') or {'execution_id': 2}))
    async def renew(req,db,auth):
        data=await req.json()
        assert data['renews_approval_id']==event.approval_id
        calls.append('renew'); return {'id':12}
    monkeypatch.setattr(approvals,'request_approval',renew)
    lifecycle.reconcile(db); db.expire_all(); lifecycle.reconcile(db)
    assert calls==['ingest','renew']
    assert event.state=='pending_review' and event.renewal_id==12
def test_handler_submits_existing_scanner_once_and_resumes_receipt(db, monkeypatch):
    from contextlib import nullcontext
    from app import main
    lifecycle.enqueue_due(db)
    job=db.scalar(select(DurableJob))
    monkeypatch.setattr(main,'SessionLocal',lambda:nullcontext(db))
    monkeypatch.setattr(lifecycle,'_actor',lambda *args:(SimpleNamespace(user=SimpleNamespace(id=1)),db.get(Service,1)))
    calls=[]
    def start(refs,**options):
        calls.append((refs,options)); return 'persisted-scan'
    monkeypatch.setattr(main,'_start_public_scan',start)
    ctx=SimpleNamespace(job=job,check=lambda:None)
    assert lifecycle.handle(ctx,job.payload)=={'scan_id':'persisted-scan'}
    db.expire_all()
    assert lifecycle.handle(ctx,job.payload)=={'scan_id':'persisted-scan'}
    assert len(calls)==1
    assert '@sha256:' in calls[0][0]
    assert calls[0][1]['ingest_scope']=='service'


def test_renewal_event_replay_returns_same_pending_request(approval_db, monkeypatch):
    db=approval_db
    first=asyncio.run(approvals.request_approval(request({'service_key':'one'}),db,auth()))
    original=db.get(CyberApproval,first['id']); original.status='approved'; original.requested_at=now()-timedelta(days=1)
    event=lifecycle.OCIReassessmentEvent(id='event',approval_id=original.id,state='scanning')
    fresh=Execution(service_id=original.service_id,execution_key='fresh-event',complete=True,scanned_at=now(),raw_payload={'version':'1','findings':[]})
    db.add_all([event,fresh]);db.commit()
    monkeypatch.setattr(approvals,'_readiness',lambda *args:{'ready':True,'blockers':[],'execution':fresh,'remediation':None,'artifacts':[]})
    payload={'service_key':'one','renews_approval_id':original.id,'reassessment_event_id':event.id}
    first=asyncio.run(approvals.request_approval(request(payload),db,auth()))
    second=asyncio.run(approvals.request_approval(request(payload),db,auth()))
    assert first['id']==second['id']
    assert db.scalar(select(func.count()).select_from(CyberApproval))==2


def test_complete_scan_imports_real_evidence_and_requests_cyber_review(db, monkeypatch, tmp_path):
    import json
    from zipfile import ZipFile
    from app import main, service_exports
    original = db.scalar(select(CyberApproval))
    original.requested_at = now() - timedelta(days=2)
    db.commit()
    lifecycle.enqueue_due(db)
    event = db.scalar(select(lifecycle.OCIReassessmentEvent))
    event.scan_id, event.state = 'complete-real', 'scanning'
    db.commit()
    actor = auth(permissions=('service.view','service.edit','service.export','approval.request','scan.ingest'))
    actor.user.id = 1
    service = db.get(Service, original.service_id)
    monkeypatch.setattr(lifecycle, '_actor', lambda *args: (actor, service))
    monkeypatch.setattr(main, 'PUBLIC_JOB_ROOT', tmp_path)
    monkeypatch.setattr(main, 'PUBLIC_JOBS', {'complete-real': {'status':'complete', 'owner_user_id':1,
        'ingest_service_id':'one', 'ingest_service_version':'1.0', 'ingest_scope':'service'}})
    monkeypatch.setattr(approvals, 'root', lambda: tmp_path / 'approvals')
    monkeypatch.setattr(approvals, 'record_audit', lambda *args, **kwargs: None)
    def export(output, *args):
        with ZipFile(output, 'w') as archive:
            archive.writestr('findings.xlsx', b'export fixture')
        return {'entries':[{'name':'findings.xlsx','status':'included'}]}
    monkeypatch.setattr(service_exports, 'write_all', export)
    result = {'schema_version':'1.0','execution_id':'reassessment-real', 'scanned_at':now().isoformat(),
        'complete':True,'fixable_only':True,'scan_scope':'service', 'service':{'id':'one','name':'One','version':'1.0'},
        'findings':[], 'sbom_components':[{'name':'package','version':'1','image':'registry.example/image'}],
        'service_overview':{'images':[{'image':'registry.example/image','digest':'sha256:'+'a'*64}]}}
    output = tmp_path / 'complete-real' / 'output'
    output.mkdir(parents=True)
    (output / 'portal-result.json').write_text(json.dumps(result))
    lifecycle.reconcile(db)
    assert event.state == 'pending_review', event.detail
    renewal = db.get(CyberApproval, event.renewal_id)
    assert renewal.status == 'pending' and renewal.source_execution_id != original.source_execution_id
    execution = db.get(Execution, renewal.source_execution_id)
    assert execution.execution_key == 'public:complete-real' and execution.service_id == original.service_id
    assert renewal.snapshot['renews_approval_id'] == original.id
    assert [{k:item[k] for k in ('kind','reference','digest')} for item in renewal.snapshot['artifacts']] == original.snapshot['artifacts']
    assert original.status == 'approved' and 'approval_validity' not in renewal.snapshot
    db.expire_all()
    lifecycle.reconcile(db)
    assert db.scalar(select(func.count()).select_from(CyberApproval)) == 2


def test_renewal_rejects_concurrently_selected_different_execution(approval_db, monkeypatch):
    db = approval_db
    first = asyncio.run(approvals.request_approval(request({'service_key':'one'}), db, auth()))
    original = db.get(CyberApproval, first['id'])
    original.status = 'approved'
    original.requested_at = now() - timedelta(days=2)
    fresh = Execution(service_id=original.service_id, execution_key='competing', complete=True,
        scanned_at=now(), raw_payload={'version':'1.0','findings':[]})
    db.add(fresh); db.commit()
    monkeypatch.setattr(approvals, '_readiness', lambda *args: {'ready':True,'blockers':[],
        'execution':fresh,'remediation':None,'artifacts':[]})
    with pytest.raises(HTTPException, match='source changed'):
        asyncio.run(approvals.request_approval(request({'service_key':'one','renews_approval_id':original.id,
            'expected_source_execution_id':fresh.id + 100}), db, auth()))
    assert db.scalar(select(func.count()).select_from(CyberApproval)) == 1
