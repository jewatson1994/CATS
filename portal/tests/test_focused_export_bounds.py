"""Focused export SQL residency; use CATS_EXPORT_BENCHMARK_ROWS for a large run."""
import ast
import os
import time
import tracemalloc
from pathlib import Path
from sqlalchemy import create_engine, insert, select, event
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, Execution, Finding, FindingObservation, PolicyFinding, utcnow


def test_projected_export_database_residency():
    size = int(os.environ.get('CATS_EXPORT_BENCHMARK_ROWS', '1000'))
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    stamp = utcnow()
    with Session(engine) as db:
        db.add(Service(id=1, service_key='large', name='Large', owner='Owner', poc='Contact'))
        db.add(Execution(id=1, service_id=1, execution_key='latest', scanned_at=stamp,
                         complete=True, raw_payload={'large': 'x'*1000000}))
        db.commit()
        for start in range(0, size, 500):
            end = min(start+500, size)
            db.execute(insert(Finding), [dict(id=i+1, service_id=1, cve=f'CVE-{i}', severity='High',
                active=True, first_seen=stamp, episode_started=stamp, last_seen=stamp) for i in range(start,end)])
            db.execute(insert(FindingObservation), [dict(finding_id=i+1, execution_id=1, image='image',
                package='package', evidence={'retained': 'x'*100}) for i in range(start,end)])
        db.commit(); db.expunge_all()
        tree = ast.parse((Path(__file__).parents[1]/'app/main.py').read_text(encoding='utf-8-sig'))
        function = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='export_service_findings')
        function.decorator_list=[]
        function.args.defaults=[ast.Constant(None) for _ in function.args.defaults]
        peak_models = 0
        def consume(headers, rows):
            nonlocal peak_models
            count=0
            for row in rows:
                count+=1
                peak_models=max(peak_models,len(db.identity_map))
                assert len(row)==10
            return count
        namespace=dict(Service=Service,Execution=Execution,Finding=Finding,FindingObservation=FindingObservation,
            PolicyFinding=PolicyFinding,select=select,Session=Session,AuthContext=object,
            _focused_export_book=consume,workbook_response=lambda value,name:value)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),'export','exec'),namespace)
        statements=[]
        event.listen(engine,'before_cursor_execute',lambda c,r,s,p,x,m:statements.append(s))
        tracemalloc.start(); start=time.perf_counter()
        assert namespace['export_service_findings']('large',db,None)==size
        elapsed=time.perf_counter()-start
        _,peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
        assert peak_models <= 1
        assert len(statements)==4
        assert not any('raw_payload' in sql or 'finding_observations.evidence' in sql for sql in statements)
        print(f'export rows={size} SQL={len(statements)} ORM_peak={peak_models} seconds={elapsed:.3f} Python_peak_MiB={peak/1024/1024:.2f}; workbook cells excluded')