"""Reproduce bounded activity route/DTO measurements on 100k synthetic events.

Run: .venv/Scripts/python.exe scripts/benchmark-activity.py
No production DB, network, authentication middleware or browser is used.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import tracemalloc
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('activity_benchmark_base', ROOT/'scripts/benchmark-backend.py')
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def run():
    from sqlalchemy import create_engine, insert, event
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import QueuePool
    from starlette.requests import Request
    with tempfile.TemporaryDirectory(prefix='cats-activity-bench-') as directory:
        os.environ['DATABASE_URL'] = 'sqlite:///' + str(Path(directory)/'unused.sqlite')
        from app import main
        from app.database import Base, engine as default_engine
        from app.models import Service, User, AuditEvent
        main.utcnow = lambda: benchmark.NOW
        database = Path(directory)/'fixture.sqlite'
        engine = create_engine('sqlite://', creator=lambda: sqlite3.connect(database, factory=benchmark.Connection), poolclass=QueuePool)
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(insert(Service), [dict(id=i,service_key=f'activity-{i}',name=f'Activity {i}',owner='Owner',poc='Contact') for i in (1,2)])
            connection.execute(insert(User), [dict(id=i,username=f'actor-{i}',display_name=f'Actor {i}',enabled=True) for i in range(1,21)])
            for start in range(0,100000,1000):
                connection.execute(insert(AuditEvent), [dict(id=i+1, actor_user_id=1+i%20,
                    action='service.filtered' if i%4==0 else 'service.updated',target_type='service',
                    target_id=str(1 if i<50000 else 2), created_at=benchmark.NOW,
                    detail={'service_id':1 if i<50000 else 2,'service_key':f'activity-{1 if i<50000 else 2}', 'reason':'Synthetic retained event'})
                    for i in range(start,start+1000)])
        auth = SimpleNamespace(user=SimpleNamespace(id=1,username='benchmark',display_name='Benchmark',role_assignments=[]),
            csrf_token='benchmark',has=lambda permission,*args,**kwargs: permission!='config.manage',
            accessible_service_ids=lambda permission: None)
        results=[]
        cases=[('service-first','service',1,1,''),('service-middle','service',1,500,''),
            ('service-late','service',1,1000,''),('service-filter-other','service',2,500,''),
            ('global-first','global',None,1,''),('global-middle','global',None,1000,''),
            ('global-late','global',None,2000,''),('global-action-filter','global',None,250,'service.filtered')]
        for label,kind,service_id,page,action in cases:
            metrics=dict(case=label,page_requested=page,page_size=50,query_count=0,dbapi_rows_fetched=0,
                orm_objects_loaded=0,evidence_queries=0)
            def before(conn,cursor,statement,parameters,context,many):
                metrics['query_count']+=1
                if 'raw_payload' in statement or 'finding_observations.evidence' in statement:
                    metrics['evidence_queries']+=1
            def loaded(item,context):
                metrics['orm_objects_loaded']+=1
            event.listen(engine,'before_cursor_execute',before)
            event.listen(Base,'load',loaded,propagate=True)
            benchmark.ACTIVE=metrics
            query=f'page={page}&page_size=50' + (f'&action={action}' if action else '')
            path=f'/services/activity-{service_id}' if kind=='service' else '/admin/audit'
            if kind=='service':query+='&activity=true'
            request=Request(dict(type='http',method='GET',path=path,query_string=query.encode(),
                headers=[(b'accept',b'application/vnd.cats.page+json')],scheme='http',server=('benchmark',80)))
            tracemalloc.start(); started=time.perf_counter()
            with Session(engine) as db:
                if kind=='service':
                    response=main.service_detail(f'activity-{service_id}',request,activity=True,severity=[],page=page,page_size=50,db=db,auth=auth)
                else:
                    response=main.audit_page(request,page=page,page_size=50,action=action,db=db,auth=auth)
                metrics['duration_ms']=(time.perf_counter()-started)*1000
                metrics['response_bytes']=len(response.body)
                metrics['status_code']=response.status_code
                data=json.loads(response.body)['data']
                metrics['page_rows']=len(data['events'])
                metrics['total_items']=data.get('total_items',data.get('retained_count'))
                metrics['page_returned']=data['page']
                metrics['page_count']=data['page_count']
                metrics['event_ids']=[row['id'] for row in data['events']]
                metrics['orm_identity_map_size']=len(db.identity_map)
            _,metrics['python_peak_traced_bytes']=tracemalloc.get_traced_memory();tracemalloc.stop()
            benchmark.ACTIVE=None
            event.remove(engine,'before_cursor_execute',before)
            event.remove(Base,'load',loaded)
            assert metrics['page_rows']==50
            assert metrics['evidence_queries']==0
            assert metrics['query_count'] <= 13
            assert metrics['dbapi_rows_fetched'] <= 73
            assert metrics['orm_objects_loaded'] <= 71
            assert metrics['total_items']==(25000 if action else (50000 if kind=='service' else 100000))
            assert metrics['event_ids']==sorted(metrics['event_ids'],reverse=True)
            results.append(metrics)
            print(json.dumps({key:value for key,value in metrics.items() if key != 'event_ids'}),flush=True)
        source_paths=['scripts/benchmark-activity.py','scripts/benchmark-backend.py','portal/app/main.py',
            'portal/app/activity_queries.py','portal/app/service_tab_queries.py','portal/app/frontend_admin.py',
            'portal/app/frontend_service_secondary.py']
        report=dict(method='Actual service Activity and global Audit route bodies including explicit DTO/JSON serialization; fresh sessions, SQLite, tracemalloc enabled. Excludes middleware/authentication/network. DBAPI counters measure returned rows, not rows scanned internally by SQLite. Offset late-page cost may grow with retained event count.',
            fixture=dict(events=100000,services=2,events_per_service=50000,actors=20,
                timestamp='2026-10-04T00:00:00+00:00',same_timestamp_stable_id_tiebreak=True,filtered_action_events=25000),
            command='.venv/Scripts/python.exe scripts/benchmark-activity.py',
            source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source_paths},results=results)
        (ROOT/'docs/backend-activity-second-pass.json').write_text(json.dumps(report,indent=2)+'\n')
        engine.dispose();default_engine.dispose()


if __name__=='__main__':run()