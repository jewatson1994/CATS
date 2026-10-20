#!/usr/bin/env python3
"""Read-only, CVE-indexed root-cause audit of immutable retained container scans.

This diagnostic compares vendor statements without treating a shared CVE, source
name, versionless product, or near match as applicability. Corpus access is read-only.
The optional controlled benchmark creates a private schema and rolls it back.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
from urllib.parse import unquote

PRIMARY = ['ubuntu', 'debian-12-9', 'alpine-3-20-0', 'redhat-ubi', 'suse', 'python', 'node-image-catalogers']
SOURCE_BY_DISTRO = {'ubuntu': 1, 'rhel': 5, 'redhat': 5, 'sles': 6, 'suse': 6}
CATEGORY_ORDER = ['cve_absent_from_corpus', 'vendor_or_ecosystem_not_covered',
                  'cve_absent_from_vendor_statements', 'no_verified_named_vendor_product',
                  'vendor_product_context_unverified', 'package_version_mismatch',
                  'distribution_or_release_mismatch', 'architecture_mismatch',
                  'purl_qualifier_mismatch', 'source_binary_identity_mismatch',
                  'other_verified_identity_difference']

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, indent=2, default=str) + '\n', encoding='utf-8')

def parse(purl):
    base, _, qs = purl.partition('?')
    path, sep, version = base.partition('@')
    parts = path[4:].split('/') if path.startswith('pkg:') else []
    return {'type': parts[0] if parts else '', 'namespace': '/'.join(parts[1:-1]),
            'name': unquote(parts[-1]) if len(parts)>1 else '',
            'version': unquote(version) if sep else None,
            'qualifiers': dict(unquote(x).split('=',1) for x in qs.split('&') if '=' in x)}

def source_metadata(row):
    evidence = row.get('evidence', {})
    artifact = evidence.get('sbom_artifact', {})
    metadata = {**artifact.get('metadata', {}), **evidence.get('artifact_metadata', {})}
    name = metadata.get('source') or metadata.get('originPackage')
    version = metadata.get('sourceVersion')
    rpm = metadata.get('sourceRpm')
    if rpm:
        match = re.fullmatch(r'(.+)-([^-]+)-([^-]+)\.(?:src|nosrc)\.rpm', rpm)
        if match:
            name, ver, release = match.groups()
            version = ver + '-' + release
    return {'name':name, 'version':version, 'source_rpm':rpm,
            'metadata':metadata, 'provenance': evidence.get('artifact_metadata_source'),
            'joined_artifact_id': artifact.get('id')}

def evaluate_retained(options, engine, captures, provenance):
    """Run production evaluation with exact joins into hash-verified raw captures."""
    from copy import deepcopy
    from types import SimpleNamespace
    import resource
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
    from app.container_intelligence import (observation_identity, evaluate_container_batch,
                                            advisory_batch, coverage_report)
    from app.packaged_risk_intelligence import overlay_packaged_kev, overlay_packaged_epss
    from app.vex_intelligence import _item_cves
    metadata_fields = {'package','name','version','architecture','source','sourceVersion','sourceRpm',
                       'originPackage','vendor','modularityLabel','epoch','release'}
    def bounded(value, kind, limit):
        return value if isinstance(value, kind) and len(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()) <= limit else None
    def project_artifact(value):
        if not isinstance(value,dict): return None
        result={k:value.get(k) for k in ('id','name','version','purl','type','language','metadataType','foundBy')}
        metadata=value.get('metadata')
        result['metadata']=bounded({k:v for k,v in metadata.items() if k in metadata_fields},dict,8192) if isinstance(metadata,dict) else None
        locations=value.get('locations')
        result['locations']=bounded([{k:v for k,v in loc.items() if k in ('path','accessPath','layerID','annotations')} for loc in locations if isinstance(loc,dict)],list,8192) if isinstance(locations,list) else None
        for key in ('upstreams','cpes'): result[key]=bounded(value.get(key),list,8192)
        return bounded(result,dict,32768)
    def project_source(value):
        if not isinstance(value,dict): return None
        fields=('userInput','imageID','manifestDigest','repoDigests','architecture','os','labels','annotations')
        def selected(part): return {k:part.get(k) for k in fields} if isinstance(part,dict) else part
        return bounded({'type':value.get('type'),'name':value.get('name'),'target':selected(value.get('target')),
                        'metadata':selected(value.get('metadata')) if isinstance(value.get('metadata'),dict) else None},dict,32768)
    def descriptor(value):
        return bounded({k:v for k,v in value.items() if k in ('name','version','timestamp')},dict,1024) if isinstance(value,dict) else None
    def artifact_tuple(value):
        return tuple(value.get(k) for k in ('id','name','version','type','purl'))
    workload=[]
    raw_join_counts=Counter()
    for image_key in PRIMARY:
        capture=captures[image_key]
        syft=json.loads((options.raw_evidence/(image_key+'.syft.json')).read_text())
        grype=json.loads((options.raw_evidence/(image_key+'.grype.json')).read_text())
        artifacts=defaultdict(list)
        for art in syft['artifacts']: artifacts[art.get('id')].append(art)
        matches=defaultdict(list)
        for match in grype.get('matches',[]):
            matches[(match['vulnerability']['id'],artifact_tuple(match['artifact']))].append(match)
        for index,row in enumerate(capture['findings']):
            expected=(row['artifact_id'],row['package'],row['installed_version'],row['ecosystem'],row['purl'])
            raw_matches=matches[(row['cve'],expected)]
            if len(raw_matches)!=1: raise AssertionError('Expected exactly one raw Grype match: '+repr((image_key,index,expected)))
            raw_match=raw_matches[0]
            raw_artifacts=artifacts[row['artifact_id']]
            joined=(raw_artifacts[0] if len(raw_artifacts)==1 and artifact_tuple(raw_artifacts[0])==expected else None)
            raw_join_counts['verified_exact_artifact_join' if joined is not None else 'no_unique_exact_artifact_join']+=1
            if row['ecosystem'] in ('deb','rpm'):
                old=row.get('evidence',{}).get('sbom_artifact',{})
                raw_join_counts['installed_package_observations']+=1
                if not all(old.get(key) for key in ('metadataType','foundBy','locations')):
                    raw_join_counts['old_projection_missing_installed_database_provenance']+=1
                if joined is not None and all(joined.get(key) for key in ('metadataType','foundBy','locations')):
                    raw_join_counts['raw_installed_database_provenance_present']+=1
                if row['ecosystem']=='deb' and joined is not None:
                    meta=joined.get('metadata',{})
                    if meta.get('source')=='': raw_join_counts['debian_empty_source_name_policy_defaults_to_binary']+=1
                    if meta.get('sourceVersion')=='': raw_join_counts['debian_empty_source_version_policy_defaults_to_binary']+=1
            # A fresh projection of original bytes, never a promotion of old display fields.
            evidence=deepcopy(row.get('evidence',{}))
            evidence.update(purl=row['purl'],aliases=row.get('aliases',[]),
                scanner_distro=bounded(grype.get('distro'),dict,4096),scanner_source=project_source(grype.get('source')),
                scanner_descriptor=descriptor(grype.get('descriptor')),scanner_artifact=project_artifact(raw_match['artifact']),
                sbom_artifact=project_artifact(joined),sbom_distro=bounded(syft.get('distro'),dict,4096),
                sbom_source=project_source(syft.get('source')),sbom_descriptor=descriptor(syft.get('descriptor')),
                sbom_schema=bounded({k:v for k,v in syft.get('schema',{}).items() if k in ('version','url')},dict,2048))
            identity=observation_identity(SimpleNamespace(evidence=evidence,installed_version=row['installed_version'],image_digest=capture['image_digest']))
            workload.append({'image_key':image_key,'observation_index':index,'finding_id':row['cve'],
                'image':capture['image'],'image_digest':capture['image_digest'],'row':row,
                'reconstruction':{'method':'unique raw Syft ID plus exact name/version/type/PURL; exact raw Grype finding/artifact tuple',
                    'raw_syft_file':image_key+'.syft.json','raw_grype_file':image_key+'.grype.json',
                    'exact_tuple':expected,'joined':joined is not None},
                'item':{'cve':row['cve'],'aliases':row.get('aliases',[]),'context':identity['context'],'identity':identity}})
    now=datetime.fromisoformat(options.as_of.replace('Z','+00:00')) if options.as_of else datetime.now(timezone.utc)
    if now.tzinfo is None: raise ValueError('--as-of must include timezone')
    query_shapes=Counter()
    query_examples={}
    def observe(connection,cursor,statement,parameters,context,executemany):
        if 'vex_documents.raw_text' in statement: raise AssertionError('Evaluation retrieved raw VEX documents')
        query_shapes[' '.join(statement.split())]+=1
        if 'wanted_cves' in statement: query_examples.setdefault('vex_cve_presence',(statement,parameters))
        elif 'vex_statements' in statement and 'product_id' in statement: query_examples.setdefault('vex_observed_and_resolved_pairs',(statement,parameters))
    event.listen(engine,'before_cursor_execute',observe)
    started,cpu=time.perf_counter(),time.process_time()
    details=[]
    factory=sessionmaker(bind=engine)
    try:
        with factory() as db:
            for start in range(0,len(workload),250):
                batch=workload[start:start+250]
                items=[record['item'] for record in batch]
                vex=evaluate_container_batch(db,items,now)
                advisory=advisory_batch(db,items,now)
                cves=sorted({cve for item in items for cve in _item_cves(item)})
                snapshot={'kev':{'state':'MISSING'},'epss':{'state':'MISSING'},'findings':{cve:{'kev':None,'epss':None} for cve in cves}}
                snapshot=overlay_packaged_epss(db,overlay_packaged_kev(db,snapshot,now),now)
                for record,result,enrichment in zip(batch,vex,advisory):
                    signals=[snapshot['findings'].get(cve,{}) for cve in _item_cves(record['item'])]
                    scores=[s['epss'] for s in signals if s.get('epss') is not None]
                    details.append({k:record[k] for k in ('image_key','observation_index','finding_id','image','image_digest','reconstruction')} |
                        {'cve':record['row']['cve'],'package':record['row']['package'],'installed_version':record['row']['installed_version'],
                         'purl':record['row']['purl'],'identity':record['item']['identity'],'vex':result,'advisory':enrichment,
                         'kev':True if any(s.get('kev') is True for s in signals) else None,'epss':max(scores) if scores else None})
    finally: event.remove(engine,'before_cursor_execute',observe)
    measurement={'seconds':round(time.perf_counter()-started,6),'process_cpu_seconds':round(time.process_time()-cpu,6),
        'queries':sum(query_shapes.values()),'query_shapes':len(query_shapes),'batch_size':250,'batches':(len(workload)+249)//250,
        'process_lifetime_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        'note':'Single bounded real-corpus coverage run, warm/unknown database cache; not an independent cold benchmark. RSS includes earlier diagnostic audit.'}
    plans={}
    with engine.connect() as db:
        installed=dict(db.execute(__import__('sqlalchemy').text('SELECT version,sequence,counts FROM intelligence_package_installs ORDER BY sequence DESC LIMIT 1')).mappings().one())
        for label,(statement,parameters) in query_examples.items():
            plans[label]={'sql':statement,'plan':db.exec_driver_sql('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+statement,parameters).scalar()}
    def coverage(rows):
        grouped={}
        for index,row in enumerate(rows):
            grouped.setdefault(row['finding_id'],{'finding_id':row['finding_id'],'observations':[]})['observations'].append(
                {k:row[k] for k in ('image','image_digest','vex','advisory','kev','epss')} | {'observation_id':index+1})
        return coverage_report(list(grouped.values()),now)
    overall=coverage(details)
    overall['percentages']={k:round(v*100/overall['total_findings'],4) for k,v in overall['counts'].items()}
    metric_names=('exact_candidate_count','direct_candidate_count','resolved_candidate_count','resolved_identity_count','direct_applicable_count','resolved_applicable_count')
    def metrics(rows):
        return {'observations':len(rows),'resolution_outcomes':dict(Counter(r['vex'].get('resolution_outcome','not_available') for r in rows)),
            'resolution_reasons':dict(Counter(reason for r in rows for reason in r['identity'].get('resolution',{}).get('reasons',[]))),
            'status_counts':dict(Counter(r['vex'].get('applicability_state',r['vex']['status']) for r in rows)),
            'metric_sums':{key:sum(r['vex'].get(key,0) for r in rows) for key in metric_names},
            'metric_observation_counts':{key:sum(bool(r['vex'].get(key,0)) for r in rows) for key in metric_names}}
    output=options.output/(options.stage+'-evaluation-details.json.gz')
    with gzip.open(output,'wt',encoding='utf-8') as f:json.dump(details,f,default=str)
    report={'schema_version':1,'stage':options.stage,'as_of':now.isoformat(),'coverage':overall,
        'occurrence_metrics':metrics(details),'per_image':{key:metrics([r for r in details if r['image_key']==key])|{'coverage':coverage([r for r in details if r['image_key']==key])} for key in PRIMARY},
        'measurement':measurement,'raw_join_counts':dict(raw_join_counts),'input_provenance':provenance,'query_plans':plans,'installed_package':installed,
        'projection':'Equivalent bounded field selection to scanning-main/scripts/report-to-portal.sh; source and distro copies retained; no inferred timestamps or containing-product context.',
        'script_sha256':sha(Path(__file__)),'details_sha256':sha(output),
        'code_sha256':{name:sha(options.app_path/'app'/name) for name in ('container_intelligence.py','package_identity_resolution.py','vex_intelligence.py','packaged_risk_intelligence.py')},
        'scanner_projection_sha256':sha(options.app_path.parent/'scanning-main/scripts/report-to-portal.sh')}
    baseline_path=options.evidence/'coverage-and-benchmark.json'
    if baseline_path.exists():
        baseline=json.loads(baseline_path.read_text())
        baseline_counts=baseline['primary_service']['counts']
        report['baseline_comparison']={'path':str(baseline_path),'sha256':sha(baseline_path),'as_of':baseline['as_of'],
            'same_evaluation_time':baseline['as_of']==now.isoformat(),
            'common_root_coverage':{key:{'before':baseline_counts[key],'after':overall['counts'][key]} for key in baseline_counts}}
        report['baseline_comparison']['note']='Before values are the immutable prior audit, with original projections and original evaluator; new identity metrics did not exist then.'
    write(options.output/(options.stage+'-evaluation.json'),report)
    print(json.dumps({'evaluation':report['occurrence_metrics'],'coverage':overall['counts'],'measurement':measurement,'raw_join_counts':dict(raw_join_counts)},indent=2))
    if options.benchmark:benchmark_retained(options,engine,workload,now)

def plan_summary(value):
    plan=value[0]
    nodes=[]
    def visit(node):
        nodes.append(node)
        for child in node.get('Plans',[]):visit(child)
    visit(plan['Plan'])
    return {'planning_ms':plan.get('Planning Time'),'execution_ms':plan.get('Execution Time'),
        'output_rows':plan['Plan'].get('Actual Rows'),'nodes':len(nodes),
        'indexes':sorted({node['Index Name'] for node in nodes if node.get('Index Name')}),
        'vex_sequential_scans':sum(node.get('Node Type')=='Seq Scan' and node.get('Relation Name')=='vex_statements' for node in nodes),
        'limit_nodes':[{'actual_rows':node.get('Actual Rows'),'loops':node.get('Actual Loops'),'planned_rows':node.get('Plan Rows')}
            for node in nodes if node.get('Node Type')=='Limit']}


def benchmark_retained(options, engine, workload, now):
    """Scaling measurements use reconstructed real identities, never new findings."""
    from concurrent.futures import ThreadPoolExecutor
    from copy import deepcopy
    import importlib.util
    import resource
    import threading
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
    from app.container_intelligence import evaluate_container_batch, advisory_batch
    from app.packaged_risk_intelligence import overlay_packaged_kev, overlay_packaged_epss
    from app.vex_intelligence import _item_cves
    helper_spec=importlib.util.spec_from_file_location('retained_benchmark_helpers',Path(__file__).with_name('verify-container-intelligence.py'))
    helper=importlib.util.module_from_spec(helper_spec)
    helper_spec.loader.exec_module(helper)
    local=threading.local()
    code_files=('container_intelligence.py','package_identity_resolution.py','vex_intelligence.py','packaged_risk_intelligence.py')
    code_hashes={name:sha(options.app_path/'app'/name) for name in code_files}
    def observe(connection,cursor,statement,parameters,context,executemany):
        if 'vex_documents.raw_text' in statement:raise AssertionError('Runtime materialized raw VEX')
        if hasattr(local,'queries'):local.queries+=1
    event.listen(engine,'before_cursor_execute',observe)
    factory=sessionmaker(bind=engine)
    # Strip the output cache once; each measured batch owns its own identity objects.
    inputs=[{k:v for k,v in record.items() if k in ('finding_id','image_key','image_digest')}|
        {'item':{k:v for k,v in record['item'].items() if k!='identity'}|
         {'identity':{k:v for k,v in record['item']['identity'].items() if k!='resolution'}}} for record in workload]
    def evaluate(records):
        local.queries=0
        started,cpu=time.perf_counter(),time.process_time()
        stop,samples=threading.Event(),[helper.rss_bytes()]
        sampler=threading.Thread(target=helper.memory_sample,args=(stop,samples),daemon=True)
        sampler.start()
        statuses,metrics=Counter(),Counter()
        try:
            with factory() as db:
                for start in range(0,len(records),250):
                    items=[deepcopy(record['item']) for record in records[start:start+250]]
                    results=evaluate_container_batch(db,items,now)
                    advisory_batch(db,items,now)
                    cves=sorted({cve for item in items for cve in _item_cves(item)})
                    snapshot={'kev':{'state':'MISSING'},'epss':{'state':'MISSING'},'findings':{cve:{'kev':None,'epss':None} for cve in cves}}
                    overlay_packaged_epss(db,overlay_packaged_kev(db,snapshot,now),now)
                    for result in results:
                        statuses[result['status']]+=1
                        for key in ('direct_candidate_count','resolved_candidate_count','resolved_identity_count','direct_applicable_count','resolved_applicable_count'):
                            metrics[key]+=result.get(key,0)
        finally:
            stop.set();sampler.join();samples.append(helper.rss_bytes())
        return {'observations':len(records),'distinct_findings':len({r['finding_id'] for r in records}),
            'images':len({r['image_digest'] for r in records}),'batches':(len(records)+249)//250,
            'queries':local.queries,'seconds':round(time.perf_counter()-started,6),'process_cpu_seconds':round(time.process_time()-cpu,6),
            'sampled_process_peak_rss_bytes':max(samples),'process_lifetime_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            'status_counts':dict(statuses),'metric_sums':dict(metrics)}
    report={'schema_version':1,'as_of':now.isoformat(),'kind':'real retained observations, repeated only for scaling',
        'script_sha256':sha(Path(__file__)),'helper_sha256':sha(Path(__file__).with_name('verify-container-intelligence.py')),
        'code_sha256':code_hashes,'batch_size':250,'benchmarks':[],
        'notes':['Warm/unknown OS and database cache; no cold-cache claim.',
                 'Real corpus remains PostgreSQL-enforced read-only; all workloads include VEX, advisory, KEV and EPSS.',
                 'Repeated observations are load tests, not additional unique scanned findings.',
                 'Per-job CPU and process RSS overlap during concurrency and must not be summed; database CPU/RSS are not measured.',
                 'RSS includes Python and prior root-cause/evaluation input materialization; lifetime peak is cumulative.',
                 'Real inputs have zero applicable statements; controlled positive evidence is explicitly separate.']}
    path=options.output/(options.stage+'-benchmarks.json')
    try:
        scenarios=[('single_finding',inputs[:1]),('1000_observations',(inputs*2)[:1000]),
            ('10000_observations',(inputs*10)[:10000]),('multiple_images_one_service',inputs)]
        for name,records in scenarios:
            print('Benchmark '+name,flush=True)
            report['benchmarks'].append({'name':name,**evaluate(records)})
            write(path,report)
        started=time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as executor:
            jobs=list(executor.map(lambda _:evaluate((inputs*2)[:1000]),range(4)))
        report['concurrent']={'jobs':4,'observations_per_job':1000,'seconds_wall':round(time.perf_counter()-started,6),
            'queries':sum(job['queries'] for job in jobs),'job_metrics':jobs}
    finally:event.remove(engine,'before_cursor_execute',observe)
    report['code_unchanged_during_run']=all(sha(options.app_path/'app'/name)==value for name,value in code_hashes.items())
    if not report['code_unchanged_during_run']:raise AssertionError('Production code changed during benchmark')
    write(path,report)
    print(json.dumps({'benchmarks':report['benchmarks'],'concurrent':report['concurrent']},indent=2),flush=True)
    if options.controlled_positive:controlled_positive(options,engine.url,inputs,now,helper)


def controlled_positive(options, url, inputs, now, helper):
    """Synthetic VEX statements in a new transaction-local schema; rollback removes it.

    The public 29M-statement corpus is never inserted into, updated or deleted.
    This opt-in case proves materialization limits and positive-path work, not
    additional real matches. Schema and all rows are rolled back, even on errors.
    """
    from copy import deepcopy
    from datetime import timedelta
    import resource
    import threading
    import uuid
    from sqlalchemy import MetaData, create_engine, event, insert, text
    from sqlalchemy.schema import CreateSchema
    from sqlalchemy.orm import Session
    from app.vex_models import VexSource,VexDocument,VexStatement
    from app.container_intelligence import evaluate_container_batch
    from app.package_identity_resolution import resolve_package_identity
    from app.vex_intelligence import MAX_EVALUATION_CANDIDATES
    schema='identity_audit_'+uuid.uuid4().hex
    # This engine is used exclusively for an uncommitted private schema.
    controlled=create_engine(url,connect_args={'options':'-c statement_timeout=120000'})
    metadata=MetaData()
    for model in (VexSource,VexDocument,VexStatement):model.__table__.to_metadata(metadata,schema=schema)
    base=deepcopy(next(record['item'] for record in inputs if record['image_key']=='ubuntu' and
        record['item']['identity'].get('sbom_artifact',{}).get('metadata',{}).get('source') not in (None,'')))
    base['aliases']=[]
    derived=[c for c in resolve_package_identity(base['identity'],now=now)['candidates'] if c['kind']=='authoritative_resolved']
    candidate=next((c for c in derived if c.get('relationship')=='installed_binary_to_source_package'),derived[-1])
    cases=[('resolved_positive','CVE-2099-90001',1),('resolved_high_fanout_at_cap','CVE-2099-90002',MAX_EVALUATION_CANDIDATES),
           ('resolved_high_fanout_overflow','CVE-2099-90003',MAX_EVALUATION_CANDIDATES+1),('direct_derived_conflict','CVE-2099-90004',2)]
    report={'schema_version':1,'kind':'controlled synthetic positive VEX statements, not discovered real matches',
        'schema':schema,'as_of':now.isoformat(),'candidate_cap':MAX_EVALUATION_CANDIDATES,
        'code_sha256':{name:sha(options.app_path/'app'/name) for name in ('container_intelligence.py','package_identity_resolution.py','vex_intelligence.py')},
        'script_sha256':sha(Path(__file__)),'identity_origin':'Exact reconstructed Ubuntu artifact; synthetic CVEs and VEX rows only.',
        'base_identity':base['identity'],'selected_resolved_candidate':candidate,'cases':[],
        'isolation':'New random schema in one transaction; production corpus untouched; entire transaction rolled back.',
        'notes':['VEX evaluator only; excludes advisory/KEV/EPSS because this measures positive materialization and limits.',
                 'Single warm/unknown-cache run per controlled case; small private schema planner choices are separate from real-corpus plans.',
                 'Trust is fixture setup within an isolated transaction, not a newly accepted vendor document.']}
    plans={}
    with controlled.connect() as initial:
        transaction=initial.begin()
        connection=initial.execution_options(schema_translate_map={None:schema})
        try:
            connection.execute(CreateSchema(schema))
            metadata.create_all(connection)
            connection.execute(insert(VexSource),[{'id':1,'name':'CONTROLLED Canonical-shaped benchmark fixture',
                'allowed_hosts':['security-metadata.canonical.com'],'trusted':True,'enabled':True,
                'max_age_days':30,'authoritative_prefixes':['pkg:deb/ubuntu/']}])
            statement_id=1
            for document_id,(name,cve,count) in enumerate(cases,1):
                connection.execute(insert(VexDocument),[{'id':document_id,'source_id':1,'sha256':hashlib.sha256(name.encode()).hexdigest(),
                    'raw_text':'CONTROLLED BENCHMARK ONLY','format':'openvex','document_key':'controlled:'+name,'version':'1',
                    'issued_at':now-timedelta(days=1),'retrieved_at':now,'source_url':'https://security-metadata.canonical.com/controlled-benchmark/'+cve+'.json',
                    'verification':'tls','withdrawn':False}])
                rows=[]
                for i in range(count):
                    context=base['context'] if name=='direct_derived_conflict' and i==0 else candidate['context']
                    rows.append({'id':statement_id,'document_id':document_id,'cve':cve,'product_id':context['product_id'],
                        'identity':context,'status':'affected' if name=='direct_derived_conflict' and i==0 else 'not_affected'})
                    statement_id+=1
                connection.execute(insert(VexStatement),rows)
            for table in ('vex_sources','vex_documents','vex_statements'):
                connection.exec_driver_sql('ANALYZE "'+schema+'"."'+table+'"')
            for name,cve,count in cases:
                query_data=[]
                def record_query(conn,cursor,statement,parameters,context,executemany):
                    if 'vex_documents.raw_text' in statement:raise AssertionError('Controlled runtime retrieved raw VEX')
                    query_data.append((statement,parameters))
                event.listen(controlled,'before_cursor_execute',record_query)
                item=deepcopy(base);item['cve']=cve
                started,cpu=time.perf_counter(),time.process_time()
                stop,samples=threading.Event(),[helper.rss_bytes()]
                sampler=threading.Thread(target=helper.memory_sample,args=(stop,samples),daemon=True);sampler.start()
                try:
                    with Session(bind=connection,join_transaction_mode='create_savepoint') as db:
                        result=evaluate_container_batch(db,[item],now)[0]
                finally:
                    event.remove(controlled,'before_cursor_execute',record_query)
                    stop.set();sampler.join();samples.append(helper.rss_bytes())
                metric={'name':name,'synthetic_statements':count,'queries':sum(not sql.startswith(('SAVEPOINT','ROLLBACK TO SAVEPOINT')) for sql,_ in query_data),
                    'seconds':round(time.perf_counter()-started,6),'process_cpu_seconds':round(time.process_time()-cpu,6),
                    'sampled_process_peak_rss_bytes':max(samples),'process_lifetime_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                    'status':result['status'],'reasons':result['reasons'],'returned_statements':len(result.get('statements',[])),
                    'direct_candidates':result.get('direct_candidate_count',0),'resolved_candidates':result.get('resolved_candidate_count',0),
                    'direct_applicable':result.get('direct_applicable_count',0),'resolved_applicable':result.get('resolved_applicable_count',0),
                    'cve_present':result.get('cve_present'),'resolution_outcome':result.get('resolution_outcome')}
                sql,params=next((sql,params) for sql,params in query_data if 'vex_statements' in sql and 'product_id' in sql)
                plan=connection.exec_driver_sql('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+sql,params).scalar()
                plans[name]={'sql':sql,'parameters':params,'plan':plan}
                metric['query_plan']=plan_summary(plan)
                expected='conflicting' if name=='direct_derived_conflict' else 'under_investigation' if name.endswith('overflow') else 'not_affected'
                assert result['status']==expected,(name,result['status'],result['reasons'])
                if name.endswith('overflow'):assert result['reasons']==['candidate_limit'] and not result['statements'] and result['cve_present'] is None
                report['cases'].append(metric)
            identity_limit=resolve_package_identity(base['identity'],now=now,max_candidates=1)
            report['identity_candidate_limit']={'configured_limit':1,'outcome':identity_limit['outcome'],
                'reasons':identity_limit['reasons'],'retained_candidate_kinds':[c['kind'] for c in identity_limit['candidates']]}
        finally:transaction.rollback()
    with controlled.connect() as connection:
        report['schema_removed']=not connection.execute(text('SELECT 1 FROM pg_namespace WHERE nspname=:schema'),{'schema':schema}).first()
    controlled.dispose()
    assert report['schema_removed'],'Controlled schema persisted unexpectedly'
    planpath=options.output/'controlled-positive-query-plans.json.gz'
    with gzip.open(planpath,'wt',encoding='utf-8') as f:json.dump(plans,f,default=str)
    report['query_plans_sha256']=sha(planpath)
    write(options.output/'controlled-positive-benchmark.json',report)
    print(json.dumps({'controlled_positive':report['cases'],'schema_removed':report['schema_removed']},indent=2),flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--raw-evidence',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--app-path',type=Path,default=Path('/workspace/portal'))
    p.add_argument('--stage',default='before')
    p.add_argument('--evaluate',action='store_true',help='Evaluate production resolver after verified reconstruction of retained raw Syft/Grype artifacts')
    p.add_argument('--as-of',default=None)
    p.add_argument('--benchmark',action='store_true',help='Run real scaling and concurrency measurements after evaluation')
    p.add_argument('--controlled-positive',action='store_true',help='Also benchmark synthetic positive statements in a rollback-only private schema')
    a=p.parse_args()
    if (a.benchmark or a.controlled_positive) and not a.evaluate:p.error('--benchmark and --controlled-positive require --evaluate')
    if a.controlled_positive and not a.benchmark:p.error('--controlled-positive requires --benchmark')
    a.output.mkdir(parents=True,exist_ok=True)
    sys.path.insert(0,str(a.app_path))
    from sqlalchemy import create_engine,text
    from sqlalchemy.engine import make_url
    url=make_url(os.environ['DATABASE_URL'])
    if url.get_backend_name()!='postgresql' or url.host not in ('127.0.0.1','localhost','::1'):
        p.error('The audit requires isolated loopback PostgreSQL')
    original_connect=socket.socket.connect
    def guarded(sock,address):
        if isinstance(address,tuple) and address[0] in ('127.0.0.1','localhost','::1') and address[1]==(url.port or 5432):
            return original_connect(sock,address)
        raise RuntimeError('External network access prohibited')
    socket.socket.connect=guarded
    engine=create_engine(url,connect_args={'options':'-c default_transaction_read_only=on -c statement_timeout=120000'})
    manifest=json.loads((a.evidence/'manifest.json').read_text())
    captures={}
    provenance={}
    records=[]
    names=set()
    cves=set()
    for key in PRIMARY:
        capture=json.loads((a.evidence/(key+'.json')).read_text())
        captures[key]=capture
        provenance[key]={'capture_sha256':sha(a.evidence/(key+'.json')),'image_digest':capture['image_digest'],'raw_files':[]}
        entry=next(x for x in manifest['images'] if x['image_key']==key)
        for raw in entry['raw_evidence']:
            path=a.raw_evidence/raw['name']
            actual=sha(path)
            if actual!=raw['sha256']: raise AssertionError('Raw evidence hash mismatch: '+raw['name'])
            provenance[key]['raw_files'].append({'name':raw['name'],'sha256':actual,'bytes':path.stat().st_size})
        for n,row in enumerate(capture['findings']):
            parsed=parse(row['purl'])
            source=source_metadata(row)
            aliases=sorted({v for v in [row['cve'],*row.get('aliases',[])] if re.fullmatch(r'CVE-\d{4}-\d{4,}',v)})
            observed={'image_key':key,'observation_index':n,'finding':row['cve'],
                      'cves':aliases,'package':row['package'],'installed_version':row['installed_version'],
                      'purl':row['purl'],'parsed':parsed,'source':source,'distro':capture['distro']}
            records.append(observed)
            names.add(parsed['name'])
            if source['name']:names.add(source['name'])
            cves.update(aliases)
    started=time.perf_counter()
    stats=defaultdict(Counter)
    products=[]
    sql_counts=0
    queries={}
    with engine.connect() as db:
        sources=[dict(x) for x in db.execute(text('SELECT id,name,allowed_hosts,authoritative_prefixes,trusted,enabled,max_age_days FROM vex_sources ORDER BY id')).mappings()]
        sql_counts+=1
        # CVE constraints preserve the existing ix_vex_statements_cve index.
        sql='''SELECT s.cve,d.source_id,count(*) AS statements
               FROM vex_statements s JOIN vex_documents d ON d.id=s.document_id
               WHERE s.cve=ANY(:cves) GROUP BY s.cve,d.source_id'''
        product_sql='''SELECT s.id AS statement_id,s.cve,s.product_id,s.identity,s.status,d.id AS document_id,
                    d.source_id,d.source_url,d.document_key,d.sha256,d.issued_at,d.retrieved_at,d.withdrawn
                 FROM vex_statements s JOIN vex_documents d ON d.id=s.document_id
                 WHERE s.cve=ANY(:cves)
                 AND split_part(split_part(s.product_id,'?',1),'@',1)=ANY(:names)
                 ORDER BY s.cve,s.product_id,d.id,s.id LIMIT 50001'''
        prefixes=['pkg:deb/ubuntu/','pkg:rpm/redhat/','pkg:rpm/suse/']
        wanted_names=[prefix+name for prefix in prefixes for name in sorted(names)]
        wanted=sorted(cves)
        for start in range(0,len(wanted),40):
            batch=wanted[start:start+40]
            for row in db.execute(text(sql),{'cves':batch}).mappings():
                stats[row['cve']][row['source_id']]=row['statements']
            part=[dict(x) for x in db.execute(text(product_sql),{'cves':batch,'names':wanted_names}).mappings()]
            if len(part)>50000:raise AssertionError('Diagnostic named-product cap exceeded; refusing incomplete classification')
            products.extend(part)
            sql_counts+=2
            if start==0:
                for label,query,params in [('cve_vendor_membership',sql,{'cves':batch}),('named_vendor_products',product_sql,{'cves':batch,'names':wanted_names})]:
                    queries[label]={'sql':query,'plan':db.execute(text('EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) '+query),params).scalar()}
                    sql_counts+=1
    by_cve=defaultdict(list)
    for item in products:
        item['parsed']=parse(item['product_id'])
        by_cve[item['cve']].append(item)
    results=[]
    for record in records:
        obs=record['parsed']
        source=record['source']
        vendor=SOURCE_BY_DISTRO.get(record['distro'].get('id')) if obs['type'] in ('deb','rpm') else None
        represented=any(stats[cve] for cve in record['cves'])
        vendor_present=vendor is not None and any(stats[cve].get(vendor,0) for cve in record['cves'])
        relevant=[x for cve in record['cves'] for x in by_cve[cve] if x['source_id']==vendor
                  and x['parsed']['name'] in {obs['name'],source['name']}]
        direct=[x for x in relevant if x['product_id']==record['purl']]
        binary=[x for x in relevant if x['parsed']['name']==obs['name']]
        src=[x for x in relevant if source['name'] and x['parsed']['name']==source['name']
             and (x['parsed']['qualifiers'].get('arch') in ('source','src') or source['name']!=obs['name'])]
        # Diagnostic equivalence is only explicit Debian omitted-source-version semantics,
        # RPM source filenames, and observed codename; it cannot grant VEX applicability.
        srcversion=source['version'] or (record['installed_version'] if obs['type']=='deb' else None)
        def expected_version(x):
            if x['parsed']['qualifiers'].get('arch') in ('src','source'):return srcversion
            return obs['version']
        versions=[x for x in relevant if x['parsed']['version']==expected_version(x)]
        versionless=[x for x in relevant if not x['parsed']['version']]
        code=record['distro'].get('versionCodename')
        dq=obs['qualifiers'].get('distro')
        def release_ok(x):
            value=x['parsed']['qualifiers'].get('distro')
            return value is None or value in {dq,code}
        releases=[x for x in relevant if release_ok(x)]
        architectures=[x for x in relevant if x['parsed']['qualifiers'].get('arch') in
                       (None,obs['qualifiers'].get('arch'),'source','src')]
        contexts=[x for x in relevant if x['identity'].get('csaf_product_context')]
        flags=[]
        if not represented:flags.append('cve_absent_from_corpus')
        elif vendor is None:flags.append('vendor_or_ecosystem_not_covered')
        elif not vendor_present:flags.append('cve_absent_from_vendor_statements')
        elif not relevant:flags.append('no_verified_named_vendor_product')
        else:
            if contexts:flags.append('vendor_product_context_unverified')
            if not versions and not versionless:flags.append('package_version_mismatch')
            if not releases:flags.append('distribution_or_release_mismatch')
            if not architectures:flags.append('architecture_mismatch')
            if not direct and versions:flags.append('purl_qualifier_mismatch')
            if src and not binary:flags.append('source_binary_identity_mismatch')
            if not flags:flags.append('other_verified_identity_difference')
        # Independent observed blockers are multi-cause flags and not exclusive buckets.
        if source['name'] and source['name']!=obs['name'] and src:
            flags.append('source_binary_identity_mismatch')
        if relevant and any(x['parsed']['qualifiers'].get('distro') not in (None,dq) for x in relevant):
            flags.append('purl_distribution_qualifier_difference')
        if relevant and obs['qualifiers'].get('upstream') and any(not x['parsed']['qualifiers'].get('upstream') for x in relevant):
            flags.append('purl_upstream_qualifier_difference')
        if relevant and versionless:flags.append('vendor_versionless_product_requires_scoped_relationship')
        if obs['type'] in ('deb','rpm') and not source['name']:
            flags.append('missing_explicit_source_package_relationship')
        exclusive=next(x for x in CATEGORY_ORDER if x in flags)
        selected=sorted(relevant,key=lambda x:(x not in versions,x not in src,x['product_id']))[:5]
        results.append({k:v for k,v in record.items() if k!='parsed'}|{
            'cve_present':represented,'vendor_source_id':vendor,'vendor_cve_present':vendor_present,
            'exclusive_category':exclusive,'verified_flags':sorted(set(flags)),
            'exact_candidate_count':len(direct),'named_vendor_statements':len(relevant),
            'binary_name_statements':len(binary),'source_name_statements':len(src),
            'same_version_statements':len(versions),'versionless_statements':len(versionless),
            'containing_product_context_statements':len(contexts),
            'candidate_examples':selected})
    def counts(rows,root=False):
        denominator=len({x['finding'] for x in rows}) if root else len(rows)
        categories={}
        for flag in sorted(set(CATEGORY_ORDER) | {f for x in rows for f in x['verified_flags']}):
            matching=[x for x in rows if flag in x['verified_flags']]
            count=len({x['finding'] for x in matching}) if root else len(matching)
            categories[flag]={'count':count,'percent':round(100*count/denominator,4) if denominator else 0}
        return {'denominator':denominator,'multi_cause_union_counts':categories}
    rootgroups=defaultdict(list)
    for row in results:rootgroups[row['finding']].append(row)
    # A root may have multiple observations. Its exclusive bucket is the most-specific
    # represented observation's barrier, with unsupported observations not hiding it.
    priority={key:i for i,key in enumerate(CATEGORY_ORDER)}
    rootexclusive=Counter(max((r['exclusive_category'] for r in group),key=priority.get) for group in rootgroups.values())
    obsexclusive=Counter(x['exclusive_category'] for x in results)
    def percentages(counter,denominator):return {k:{'count':counter[k],'percent':round(100*counter[k]/denominator,4)} for k in CATEGORY_ORDER}
    catalog=a.output/(a.stage+'-named-vendor-statements.json.gz')
    with gzip.open(catalog,'wt',encoding='utf-8') as f:json.dump(products,f,default=str)
    detailpath=a.output/(a.stage+'-observations.json')
    write(detailpath,results)
    report={'schema_version':1,'stage':a.stage,'recorded_at':datetime.now(timezone.utc).isoformat(),
            'script_sha256':sha(Path(__file__)),'manifest_sha256':sha(a.evidence/'manifest.json'),
            'input_provenance':provenance,'sources':sources,'observations':counts(results),
            'findings':counts(results,True),'exclusive_observation_categories':percentages(obsexclusive,len(results)),
            'exclusive_finding_categories':percentages(rootexclusive,len(rootgroups)),
            'exclusive_finding_rule':'Use most-specific verified barrier among a finding root\'s observations; multi-cause counts separately union every observation flag.',
            'root_classifications':[{'finding':finding,'exclusive_category':max((r['exclusive_category'] for r in group),key=priority.get),
                'verified_flags':sorted({flag for r in group for flag in r['verified_flags']}),'observations':len(group),'images':sorted({r['image_key'] for r in group})}
                for finding,group in sorted(rootgroups.items())],
            'cve_present_findings':sum(any(r['cve_present'] for r in group) for group in rootgroups.values()),
            'exact_candidates':sum(x['exact_candidate_count'] for x in results),
            'per_image':{key:counts([x for x in results if x['image_key']==key])|{'findings':counts([x for x in results if x['image_key']==key],True)} for key in PRIMARY},
            'diagnostic_sql_statements':sql_counts,'diagnostic_seconds':round(time.perf_counter()-started,6),
            'named_vendor_statement_rows':len(products),'query_plans':queries,
            'detail_sha256':sha(detailpath),'catalog_sha256':sha(catalog),
            'limitations':['Diagnostic near identities never establish applicability.',
                'Source names are taken only from retained joined scanner metadata; no fuzzy name matching.',
                'Absent explicit source fields are distinguished from Debian policy implicit same-source defaults.',
                'Shared CVEs and versionless products do not establish installed-version or containing-product applicability.',
                'No corpus rebuild, source refresh, database mutation, or external runtime network access.']}
    write(a.output/(a.stage+'-root-cause.json'),report)
    print(json.dumps({k:report[k] for k in ('stage','cve_present_findings','exact_candidates','named_vendor_statement_rows','exclusive_observation_categories','exclusive_finding_categories','diagnostic_seconds')},indent=2))
    if a.evaluate: evaluate_retained(a,engine,captures,provenance)
if __name__=='__main__':main()
