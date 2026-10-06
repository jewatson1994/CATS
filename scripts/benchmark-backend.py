"""Reproducible SQLite route benchmark. Runs no server, network, or production DB.

Use .venv/Scripts/python.exe scripts/benchmark-backend.py --output docs/backend-performance-baseline.json
The measured route body includes DTO generation and JSON serialization; HTTP
middleware/authentication/network transport are deliberately excluded.
"""
import argparse
from collections import Counter
import cProfile
from datetime import datetime, timedelta, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import tracemalloc
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'portal'))
NOW=datetime(2026,10,4,tzinfo=timezone.utc)
ACTIVE=None


class Cursor(sqlite3.Cursor):
    def fetchone(self):
        result=super().fetchone()
        if ACTIVE is not None and result is not None:ACTIVE['dbapi_rows_fetched']+=1
        return result
    def fetchmany(self,size=None):
        result=super().fetchmany() if size is None else super().fetchmany(size)
        if ACTIVE is not None:ACTIVE['dbapi_rows_fetched']+=len(result)
        return result
    def fetchall(self):
        result=super().fetchall()
        if ACTIVE is not None:ACTIVE['dbapi_rows_fetched']+=len(result)
        return result


class Connection(sqlite3.Connection):
    def cursor(self,*args,**kwargs):return super().cursor(factory=Cursor)


def fixture(engine,size, *, all_target=False, group_count=30, include_states=False):
    from sqlalchemy import insert
    from app.database import Base
    from app.models import Service,Execution,Finding,FindingObservation,PolicyFinding,ExceptionRecord
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(Service),[dict(id=i,service_key=f'bench-{i}',name=f'Benchmark {i}',lifecycle_status='active') for i in range(1,11)])
        scans=[dict(id=(service-1)*3+scan,execution_key=f'bench-{service}-{scan}',service_id=service,scanned_at=NOW-timedelta(days=4-scan),complete=True,scan_scope='service',raw_payload={'service':{'version':f'1.{scan}'},'sbom_images':[f'image-{service}'],'findings':[]}) for service in range(1,11) for scan in range(1,4)]
        connection.execute(insert(Execution),scans)
        for start in range(0,size,5000):
            findings=[];observations=[]
            for number in range(start,min(size,start+5000)):
                service=1 if all_target or number<size//2 else 2+number%9
                identifier=number+1
                findings.append(dict(id=identifier,service_id=service,cve=f'CVE-2026-{identifier:07}',severity=['Critical','High','Medium','Low','Unknown'][number%5],first_seen=NOW-timedelta(days=40),last_seen=NOW,episode_started=NOW-timedelta(days=100 if include_states and number%11==0 else 40),active=number%10!=9,resolved_at=None))
                observations.append(dict(id=identifier,finding_id=identifier,execution_id=(service-1)*3+3,image=f'images/bench-{number%20}:1.0',image_digest='sha256:'+hashlib.sha256(str(number%20).encode()).hexdigest(),package=f'package-{number%group_count:05}',installed_version='1.0',fixed_version='1.1' if number%3 else '',evidence={'kev':number%17==0,'epss':(number%100)/100,'scanners':['trivy','grype'],'cvss':float(number%10)}))
            from app.simplified_queries import observation_metadata, finding_metadata
            for finding in findings:
                finding.update(finding_metadata(finding))
            for observation in observations:
                observation.update(observation_metadata(observation))
            connection.execute(insert(Finding),findings);connection.execute(insert(FindingObservation),observations)
            if include_states:
                exceptions=[dict(finding_id=finding['id'],justification='benchmark accepted exception',approved_by='benchmark',starts_at=NOW-timedelta(days=1),expires_at=NOW+timedelta(days=30)) for finding in findings if finding['active'] and finding['id']%37==0]
                if exceptions:connection.execute(insert(ExceptionRecord),exceptions)
        from app.simplified_queries import policy_metadata
        policies=[dict(service_id=1,identity_key=f'policy-{i}',finding=f'POLICY-{i}',severity='High',scanner='dockle',first_seen=NOW,last_seen=NOW,episode_started=NOW,active=True) for i in range(25)]
        for policy in policies:
            policy.update(policy_metadata(policy))
        connection.execute(insert(PolicyFinding),policies)


def measure(engine,main,name,size, *, route_kwargs=None, capture_plan=False):
    global ACTIVE
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    from app.database import Base
    from starlette.requests import Request
    metrics={'endpoint':name,'fixture_findings':size,'query_count':0,'database_execute_ms':0.,'dbapi_rows_fetched':0,'orm_objects_loaded':0}
    orm=Counter();stack=[];captured=[]
    route_kwargs=route_kwargs or {}
    def before(*args):
        metrics['query_count']+=1;stack.append(time.perf_counter())
        if capture_plan and 'WITH' in args[2].upper() and not args[5]:captured.append((args[2],args[3]))
    def after(*args):metrics['database_execute_ms']+=(time.perf_counter()-stack.pop())*1000
    def loaded(item,context):metrics['orm_objects_loaded']+=1;orm[type(item).__name__]+=1
    event.listen(engine,'before_cursor_execute',before);event.listen(engine,'after_cursor_execute',after);event.listen(Base,'load',loaded,propagate=True)
    auth=SimpleNamespace(user=SimpleNamespace(id=1,username='benchmark',display_name='Benchmark',role_assignments=[]),csrf_token='benchmark',has=lambda *a,**k:True,accessible_service_ids=lambda permission:None)
    request=Request({'type':'http','method':'GET','path':name,'query_string':b'','headers':[(b'accept',b'application/vnd.cats.page+json')],'scheme':'http','server':('benchmark',80)})
    gc.collect();tracemalloc.start();profile=cProfile.Profile();ACTIVE=metrics;started=time.perf_counter()
    try:
        with Session(engine) as db:
            profile.enable()
            if name.startswith('/api/v1/services/'):
                from starlette.responses import JSONResponse
                response=JSONResponse(main.simplified_members('bench-1',**(dict(severity=[],page=1,page_size=50) | route_kwargs),db=db,auth=auth))
            elif name.endswith('/history'):
                from app.exchange_routes import history_page
                response=history_page('bench-1', request, page=1, imported_page=1, page_size=10, db=db, auth=auth)
            elif name.endswith('/exports/findings.xlsx'):
                response=main.export_service_findings('bench-1', db=db, auth=auth)
            elif name.startswith('/services/'):
                kwargs=dict(findings=True,findings_view='raw' if 'raw' in name else 'simplified',severity=[],page=1,page_size=50)
                kwargs.update(route_kwargs)
                response=main.service_detail('bench-1',request,**kwargs,db=db,auth=auth)
            elif name=='/api/dashboard/services':response=main.dashboard_services_data(request,page=1,page_size=50,db=db,auth=auth)
            else:response=main.cybersecurity_portfolio_data(request,page=1,page_size=50,db=db,auth=auth)
            profile.disable()
            metrics['duration_ms']=(time.perf_counter()-started)*1000
            metrics['response_bytes']=len(response.body);metrics['status_code']=response.status_code
            payload=json.loads(response.body)
            data=payload.get('data',payload)
            metrics['returned_collection_counts']={key:len(value) for key,value in data.items() if isinstance(value,list)}
            metrics['pagination']=data.get('pagination')
            metrics['page_metadata']={key:data[key] for key in ('page','page_size','total_items','total_pages') if key in data}
            metrics['route_timings']=getattr(request.state,'snapshot_timings',None)
    except Exception as exc:
        metrics['duration_ms']=(time.perf_counter()-started)*1000
        metrics['status_code']=None
        metrics['response_bytes']=0
        metrics['error']={'type':type(exc).__name__,'message':str(getattr(exc,'orig',exc))[:500]}
    finally:
        profile.disable();ACTIVE=None
        _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        event.remove(engine,'before_cursor_execute',before);event.remove(engine,'after_cursor_execute',after);event.remove(Base,'load',loaded)
    if capture_plan:
        with engine.connect() as connection:
            metrics['sqlite_query_plans']=[{'sql':sql,'plan':[list(row) for row in connection.exec_driver_sql('EXPLAIN QUERY PLAN '+sql,parameters)]} for sql,parameters in captured[:2]]
    metrics['python_peak_traced_bytes']=peak;metrics['orm_by_class']=dict(orm)
    stats=profile.getstats()
    metrics['profile_selected_functions']=[{'function':f'{item.code.co_filename}:{item.code.co_name}','calls':item.callcount,'self_ms':item.inlinetime*1000,'inclusive_ms':item.totaltime*1000} for item in stats if hasattr(item.code,'co_name') and item.code.co_name in {'service_view','prepare_findings_view','project_service','page_data','render','TemplateResponse','evaluate_policy'}]
    return metrics


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True);parser.add_argument('--sizes',nargs='+',type=int,default=[1000,10000,100000]);args=parser.parse_args()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    source_sha256={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in [ROOT/'portal/app/main.py',ROOT/'portal/app/findings_query.py',ROOT/'portal/app/findings_sql.py',ROOT/'portal/app/dashboard_portfolio.py']}
    with tempfile.TemporaryDirectory(prefix='cats-backend-bench-') as directory:
        os.environ['DATABASE_URL']='sqlite:///'+str(Path(directory)/'unused.db')
        from app import main as app_main
        from app.database import engine as default_engine
        app_main.utcnow=lambda:NOW
        results=[]
        for size in args.sizes:
            database=Path(directory)/f'fixture-{size}.sqlite'
            engine=create_engine('sqlite://',creator=lambda path=database:sqlite3.connect(path,factory=Connection))
            fixture(engine,size);app_main.SessionLocal=sessionmaker(engine)
            for endpoint in ['/services/bench-1?findings_view=raw','/services/bench-1?findings_view=simplified','/api/dashboard/services','/api/dashboard/cybersecurity']:
                row=measure(engine,app_main,endpoint,size);results.append(row);print(json.dumps(row),flush=True)
            engine.dispose()
        default_engine.dispose()
    report={'method':'Direct actual route invocation including DTO/JSON response. SQL execution excludes cursor fetch; DBAPI fetched row counts include scalar/aggregate rows. Database rows examined internally and Python rows considered are not measured. cProfile and tracemalloc enabled: instrumentation overhead included. No HTTP middleware/authentication/transport. Fresh ORM Session per request; SQLite OS page cache may be warm. Fixed ten-service dataset, half findings in target service, three scans each, one observation per finding. Not PostgreSQL/production latency.','source_sha256':source_sha256,'results':results}
    Path(args.output).write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
