"""Controlled native VEX benchmark; no vendor/real-world success is asserted.

Run from repository root with CATS_TEST_POSTGRES_URL pointing to a disposable
PostgreSQL database. Each scenario creates and drops only its random schema.
Without that environment variable it uses an in-memory SQLite database.
"""
import json, os, sys, time, uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'portal'),str(ROOT/'portal/tests')]
from sqlalchemy import create_engine, select, insert, update, func, text, event
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, Execution, Finding, FindingObservation
from app import native_vex as nv
from app.native_vex_models import VexDispositionPolicy
from test_vex_repository import source, ingest, raw, PID
from unittest.mock import patch


def scenario(count, images, url):
    schema='native_vex_bench_'+uuid.uuid4().hex
    admin=create_engine(url)
    pg=admin.dialect.name=='postgresql'
    if pg:
        with admin.begin() as c:c.execute(text('CREATE SCHEMA '+schema))
        engine=create_engine(url,connect_args={'options':'-c search_path='+schema})
    else:engine=admin
    try:
        Base.metadata.create_all(engine)
        now=datetime.now(timezone.utc)
        started=time.perf_counter()
        with Session(engine) as db:
            src=source(db)
            for start in range(0,count,250):
                doc=json.loads(raw(key='controlled-'+str(start),issued=now))
                template=doc['statements'][0]
                doc['statements']=[dict(template,vulnerability={'name':f'CVE-2026-{10000+i}'}) for i in range(start,min(start+250,count))]
                ingest(db,src,json.dumps(doc).encode())
            service=Service(name='Controlled native benchmark',service_key='controlled');db.add(service);db.flush()
            execution=Execution(service_id=service.id,execution_key='controlled',scanned_at=now,complete=True,raw_payload={});db.add(execution);db.flush()
            db.execute(insert(Finding),[dict(service_id=service.id,cve=f'CVE-2026-{10000+i}',severity='critical',first_seen=now,episode_started=now,last_seen=now,active=True) for i in range(count)])
            ids=list(db.scalars(select(Finding.id).order_by(Finding.id)))
            db.execute(insert(FindingObservation),[dict(finding_id=fid,execution_id=execution.id,image=f'image-{image}',package='libtest',installed_version='1.0' if image%2==0 else '2.0',evidence={'purl':PID if image%2==0 else PID.replace('@1.0','@2.0'),'distro':'wolfi'}) for fid in ids for image in range(images)])
            db.get(VexDispositionPolicy,1).enabled=True;db.commit()
            seed=time.perf_counter()-started
            calls=[0]
            def query(*args):calls[0]+=1
            event.listen(engine,'before_cursor_execute',query)
            start=time.perf_counter();evaluation=nv.evaluate_service(db,service.id,now=now);db.commit();elapsed=time.perf_counter()-start
            evaluation_queries=calls[0]
            start=time.perf_counter();excluded=db.scalar(select(func.count()).select_from(Finding).where(nv.finding_excluded(Finding.id,now)));read=time.perf_counter()-start
            expected=count if images==1 else 0
            assert excluded==expected,(excluded,expected)
            transitions={}
            for enabled in (False,True):
                start=time.perf_counter()
                db.execute(update(VexDispositionPolicy).values(enabled=enabled,policy_version=VexDispositionPolicy.policy_version+1));db.commit()
                assert db.scalar(select(func.count()).select_from(Finding).where(nv.finding_excluded(Finding.id,now)))==0
                transitions['enable' if enabled else 'disable']=time.perf_counter()-start
            start=time.perf_counter();nv.evaluate_service(db,service.id,now=now);db.commit()
            reclassification=time.perf_counter()-start
            start=time.perf_counter();db.execute(update(FindingObservation).where(FindingObservation.finding_id==ids[0]).values(installed_version='3.0'));db.commit()
            invalidated=db.scalar(select(func.count()).select_from(Finding).where(nv.finding_excluded(Finding.id,now)));invalidation=time.perf_counter()-start
            assert invalidated==0
            result={'dialect':engine.dialect.name,'findings':count,'observations':count*images,'images':images,'controlled_statements':count,'seed_seconds':seed,'evaluation_seconds':elapsed,'evaluation_queries':evaluation_queries,'classification_read_seconds':read,'excluded_findings':excluded,'summary':evaluation.summary,'scan_mutation_and_conservative_read_seconds':invalidation,'excluded_immediately_after_mutation':invalidated,'policy_transition_seconds':transitions,'reevaluation_after_policy_change_seconds':reclassification}
            event.remove(engine,'before_cursor_execute',query)
            print(json.dumps(result),flush=True)
            return result
    finally:
        if pg:
            engine.dispose()
            with admin.begin() as c:c.execute(text('DROP SCHEMA '+schema+' CASCADE'))
        admin.dispose()

if __name__=='__main__':
    url=os.environ.get('CATS_TEST_POSTGRES_URL','sqlite://')
    # Isolate evaluator cost and prevent background tasks outliving temporary schemas.
    with patch('app.service_posture.background_enabled',return_value=False):
        results=[scenario(n,images,url) for n,images in ((1000,1),(10000,1),(1000,10))]
    output=ROOT/'docs/evidence/native-vex/controlled-benchmark.json'
    output.write_text(json.dumps({'run_at':datetime.now(timezone.utc).isoformat(),'scope':'Controlled test fixtures only; not genuine vendor applicability or full 29.2-million-statement corpus performance. Asynchronous posture refresh disabled to isolate evaluator cost. Single run, no statistical confidence interval.','results':results},indent=2))
