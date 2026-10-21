"""Authenticated informational risk APIs; no enforcement or publication mutations."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Query, Path as PathParameter
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from sqlalchemy import select, func, or_, cast, Text, LargeBinary, text, inspect
from sqlalchemy.orm import load_only
from .auth import AuthContext, require_user, record_audit
from .database import get_db
from .models import Service, Group, ServiceGroup, ServicePosture
from .service_oci import _csrf
from .durable_jobs import DurableJob
from . import risk_profiles as risk, vex_intelligence as vex
from .risk_models import RiskPolicyVersion, RiskPolicyGroup, RiskPolicyAssignment, RiskAssessment, RiskDecision
from .vex_models import VexSource, VexDocument, VexStatement, VexIngestionAudit
from .vex_snapshot import import_snapshot
from .embedded_intelligence import package_status
from .intelligence_models import IntelligenceRecord

router = APIRouter(prefix='/api/risk', tags=['Risk Intelligence'])

def row(item, fields):
    return {key: getattr(item, key) for key in fields}

POLICY_FIELDS = ('id','name','version','configuration','digest','parent_policy_id','created_by','created_at')
DECISION_FIELDS = ('id','assessment_id','kind','decision','payload','created_by','created_at','expires_at')
SOURCE_FIELDS = ('id','name','allowed_hosts','trusted','max_age_days','enabled','last_success','last_error')

def allowed(auth, permission, service_id=None):
    if not auth.has(permission, service_id):
        raise HTTPException(403, 'Permission required for this scope')

def viewer(auth):
    if not auth.has('config.manage') and auth.accessible_service_ids('service.view') == set():
        raise HTTPException(403, 'Service access is required')

def service(db, auth, key, permission='service.view'):
    item = db.scalar(select(Service).where(Service.service_key == key))
    can_read_as_owner = item is not None and permission == 'service.view' and any(
        auth.can_manage_group(group_id) for group_id in db.scalars(
            select(ServiceGroup.group_id).where(ServiceGroup.service_id == item.id)))
    if item is None or not (auth.has(permission, item.id) or can_read_as_owner):
        raise HTTPException(404, 'Service not found')
    return item

async def body(request, auth, limit=65536):
    _csrf(request, auth)
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > limit:
            raise HTTPException(413, 'Request exceeds the size limit')
    return bytes(raw)

async def data(request, auth):
    try:
        value = json.loads(await body(request, auth))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise HTTPException(422, 'Expected a JSON object') from None

def checked(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, str(exc)[:400]) from None

def managed_groups(db, auth):
    return [g for g in db.scalars(select(Group).order_by(Group.name)) if auth.can_manage_group(g.id)]

def policy_row(db, item):
    result = row(item, POLICY_FIELDS)
    owner = db.get(RiskPolicyGroup, item.id)
    result['group_id'] = owner.group_id if owner else None
    if owner: result['name'] = owner.display_name
    return result

@router.get('/capabilities')
def capabilities(auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    groups = managed_groups(db, auth)
    if not groups: viewer(auth)
    return {'manage': bool(groups), 'default_policy': risk.DEFAULT_POLICY,
            'groups': [row(g, ('id','name')) for g in groups], 'informational_only': True}

@router.get('/profiles')
def profiles(auth: AuthContext = Depends(require_user), db=Depends(get_db), before: int | None = None, group_id: int | None = None):
    ids = [g.id for g in managed_groups(db, auth)]
    if group_id is not None and group_id not in ids:
        raise HTTPException(403, 'Group configuration permission required')
    query = select(RiskPolicyVersion).join(RiskPolicyGroup, RiskPolicyGroup.policy_id == RiskPolicyVersion.id).where(RiskPolicyGroup.group_id.in_([group_id] if group_id is not None else ids)).order_by(RiskPolicyVersion.id.desc()).limit(100)
    if before is not None: query = query.where(RiskPolicyVersion.id < before)
    items = db.scalars(query).all()
    return {'items': [policy_row(db, p) for p in items], 'next_before': items[-1].id if len(items)==100 else None}

@router.post('/profiles')
async def create_profile(request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    payload = await data(request, auth)
    group_id = payload.get('group_id')
    if not isinstance(group_id, int) or isinstance(group_id, bool):
        raise HTTPException(422, 'An owning group is required')
    if not auth.can_manage_group(group_id):
        raise HTTPException(403, 'Group configuration permission required')
    item = checked(risk.create_policy, db, payload.get('name'), payload.get('configuration'), auth.user.username,
                   parent_policy_id=payload.get('parent_policy_id'), group_id=group_id)
    record_audit(db, auth, 'risk.policy.created', 'risk_policy', item.id, name=item.name, version=item.version)
    db.commit()
    return policy_row(db, item)

@router.post('/assignments')
async def assign_profile(request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    payload = await data(request, auth)
    scope, identity = payload.get('scope'), payload.get('scope_id')
    if scope != 'group': raise HTTPException(422, 'Risk policy assignments require a group scope')
    if not isinstance(identity, int) or isinstance(identity, bool): raise HTTPException(422, 'Invalid scope identifier')
    if not auth.can_manage_group(identity): raise HTTPException(403, 'Group configuration permission required')
    if not db.get(Group, identity): raise HTTPException(404, 'Group not found')
    item = checked(risk.assign_policy, db, scope, identity, payload.get('policy_id'), auth.user.username)
    record_audit(db, auth, 'risk.policy.assigned', 'risk_assignment', item.id, scope=scope, scope_id=identity)
    db.commit()
    return {'id': item.id}

@router.get('/services')
def services(q: str = Query('', max_length=120), after: int = 0, group_id: int | None = None, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    if group_id is not None:
        if not auth.can_manage_group(group_id): raise HTTPException(403, 'Group configuration permission required')
    else: viewer(auth)
    query = select(Service).where(Service.id > after).order_by(Service.id).limit(50)
    if group_id is not None:
        query = query.where(Service.id.in_(select(ServiceGroup.service_id).where(ServiceGroup.group_id == group_id)))
    ids = auth.accessible_service_ids('service.view')
    if group_id is None and ids is not None: query = query.where(Service.id.in_(ids))
    if q: query = query.where(or_(Service.name.ilike('%'+q+'%'), Service.service_key.ilike('%'+q+'%')))
    items = db.scalars(query).all()
    return {'items': [row(s, ('id','service_key','name')) for s in items], 'next_after': items[-1].id if len(items)==50 else None}

@router.get('/services/{key}')
def service_risk(key: str, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    item = service(db, auth, key)
    latest = checked(risk.latest_assessment, db, item.id)
    policy, provenance = checked(risk.resolve_policy, db, item.id)
    history = db.scalars(select(RiskAssessment).options(load_only(RiskAssessment.id,RiskAssessment.policy_id,RiskAssessment.as_of,RiskAssessment.valid_until,RiskAssessment.summary)).where(RiskAssessment.service_id == item.id).order_by(RiskAssessment.id.desc()).limit(20)).all()
    decisions = db.scalars(select(RiskDecision).where(RiskDecision.service_id == item.id).order_by(RiskDecision.id.desc()).limit(50)).all()
    now = datetime.now(timezone.utc)
    def decision(d):
        result = row(d, DECISION_FIELDS)
        result.update(risk.decision_status(d, latest, now))
        return result
    posture = db.get(ServicePosture, item.id)
    return {'service': row(item, ('id','service_key','name')), 'assessment': latest,
            'policy': policy_row(db, policy) if policy else None, 'assignment': provenance,
            'compliance': (posture.cyber_row or {}).get('status') if posture else None,
            'compliance_cached_at': posture.cyber_calculated_at if posture else None,
            'history': [row(a, ('id','policy_id','as_of','valid_until','summary')) for a in history],
            'decisions': [decision(d) for d in decisions],
            'can_assess': auth.has('config.manage', item.id),
            'decision_kinds': [k for k,p in [('recommendation','risk.recommend'),('delegated_approval','risk.decide'),('ao_decision','risk.authorize')] if auth.has(p,item.id)]}

@router.post('/services/{key}/assess')
async def assess(key: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    item = service(db, auth, key, 'config.manage')
    payload = await data(request, auth)
    job = checked(risk.enqueue_assessment, db, item.id, actor_id=auth.user.id, configuration=payload.get('configuration'))
    db.commit()
    return {'job_id': job.id, 'status': job.status}

@router.get('/jobs/{identity}')
def risk_job(identity: str, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    job = db.get(DurableJob, identity)
    owning_manager = job is not None and any(auth.can_manage_group(group_id) for group_id in db.scalars(
        select(ServiceGroup.group_id).where(ServiceGroup.service_id == job.service_id)))
    if job is None or not job.kind.startswith('risk_') or not (auth.has('service.view',job.service_id) or owning_manager):
        raise HTTPException(404, 'Job not found')
    return row(job, ('id','status','stage','progress','result','error'))

@router.post('/services/{key}/decisions')
async def decision(key: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    item = service(db, auth, key)
    payload = await data(request, auth)
    permission = {'recommendation':'risk.recommend','delegated_approval':'risk.decide','ao_decision':'risk.authorize'}.get(payload.get('kind'))
    if permission is None: raise HTTPException(422, 'Choose an authority role')
    allowed(auth, permission, item.id)
    payload['reviewer'] = auth.user.username
    result = checked(risk.record_decision, db, item.id, payload, auth.user.username)
    record_audit(db, auth, 'risk.decision.recorded', 'service', item.id, status=result.decision)
    db.commit()
    return row(result, DECISION_FIELDS)

# Repository counts include retained revisions and manual uploads. Stop before a
# source's full history can turn this administrative page into a corpus scan.
SOURCE_STATEMENT_COUNT_LIMIT = 10_000


def _source_statement_count(db, source_id):
    # Preserve document-first indexed access. A flat join with LIMIT can still
    # scan millions of another source's rows before finding this source.
    if db.get_bind(mapper=inspect(VexStatement)).dialect.name == 'postgresql':
        probe = """SELECT statement.id FROM vex_documents AS document
            CROSS JOIN LATERAL (SELECT id FROM vex_statements
                WHERE document_id = document.id LIMIT :bound) AS statement
            WHERE document.source_id = :source_id LIMIT :bound"""
    else:  # SQLite's CROSS JOIN fixes the document/source index as the outer loop.
        probe = """SELECT statement.id FROM vex_documents AS document
            CROSS JOIN vex_statements AS statement
            WHERE document.source_id = :source_id AND statement.document_id = document.id
            LIMIT :bound"""
    count = db.scalar(text('SELECT count(*) FROM (' + probe + ') AS bounded_statements'),
        {'source_id': source_id, 'bound': SOURCE_STATEMENT_COUNT_LIMIT + 1},
        bind_arguments={'mapper': inspect(VexStatement)})
    exact = count <= SOURCE_STATEMENT_COUNT_LIMIT
    return {'statements': count if exact else None,
            'statement_count_state': 'exact' if exact else 'lower_bound',
            'statement_count_lower_bound': count,
            'statement_count_scope': 'retained_history'}


@router.get('/sources')
def sources(auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    allowed(auth, 'config.manage')
    documents = dict(db.execute(select(VexDocument.source_id, func.count()).group_by(VexDocument.source_id)).all())
    catalog_file = Path(__file__).with_name('intelligence_sources.json')
    catalog = json.loads(catalog_file.read_text()) if catalog_file.exists() else []
    items = [s | {'documents': documents.get(s['id'], 0), 'key_configured': s['has_pinned_key']}
             | _source_statement_count(db, s['id'])
             for s in sorted(vex.list_sources(db), key=lambda s: s['name'])]
    return {'items': items, 'catalog': catalog, 'embedded_package': package_status(db)}

@router.post('/sources')
async def configure_source(request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    allowed(auth, 'config.manage')
    payload = await data(request, auth)
    item = checked(vex.configure_source, db, payload.get('name'), allowed_hosts=payload.get('allowed_hosts',[]), trusted=payload.get('trusted',False), max_age_days=payload.get('max_age_days',30), public_key=payload.get('public_key'), trust_reason=payload.get('trust_reason'), authoritative_prefixes=payload.get('authoritative_prefixes',[]), enabled=payload.get('enabled',True))
    record_audit(db, auth, 'risk.source.configured', 'vex_source', item.id, name=item.name)
    db.commit()
    return row(item, SOURCE_FIELDS)

@router.post('/sources/{identity}/documents')
async def upload_document(identity: int, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    allowed(auth,'config.manage')
    raw = await body(request,auth,4*1024*1024)
    item = checked(vex.ingest_document,db,identity,raw)
    record_audit(db,auth,'risk.document.imported','vex_document',item.id)
    db.commit()
    return {'id':item.id, 'verification':item.verification, 'sha256':item.sha256}

@router.post('/sources/{identity}/snapshot')
async def upload_snapshot(identity: int, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    allowed(auth,'config.manage')
    raw = await body(request,auth,4*1024*1024)
    result = checked(import_snapshot,db,identity,raw)
    record_audit(db,auth,'risk.snapshot.imported','vex_source',identity)
    db.commit()
    return result


# Lists intentionally never select the potentially large publisher data object.
_RECORD_TEXT_LIMITS = {'record_id': 512, 'product': 2048, 'source_url': 4096}
MAX_RECORD_DETAIL_BYTES = 8 * 1024 * 1024


def _record_query():
    return select(IntelligenceRecord.id, IntelligenceRecord.source_id, IntelligenceRecord.kind,
        IntelligenceRecord.cve, IntelligenceRecord.sha256, IntelligenceRecord.acquired_at,
        IntelligenceRecord.package_version, VexSource.name.label('source_name'),
        VexSource.enabled.label('source_enabled'),
        *[func.substr(getattr(IntelligenceRecord, field), 1, limit + 1).label(field)
          for field, limit in _RECORD_TEXT_LIMITS.items()]
    ).join(VexSource, VexSource.id == IntelligenceRecord.source_id)


def _record_summary(item):
    truncated = [field for field, limit in _RECORD_TEXT_LIMITS.items()
                 if item[field] is not None and len(item[field]) > limit]
    return {'id': item['id'], 'cve': item['cve'], 'kind': item['kind'],
            'category': 'supplemental', 'record_id': item['record_id'][:_RECORD_TEXT_LIMITS['record_id']],
            'product': item['product'][:_RECORD_TEXT_LIMITS['product']] if item['product'] else None,
            'source': {'id': item['source_id'], 'name': item['source_name'], 'enabled': item['source_enabled']},
            'provenance': {'sha256': item['sha256'], 'acquired_at': item['acquired_at'],
                           'source_url': item['source_url'][:_RECORD_TEXT_LIMITS['source_url']],
                           'first_import_package_version': item['package_version']},
            'retained_history': True, 'current_package_membership': 'not_evaluated',
            'applicability': 'not_evaluated', 'informational_only': True,
            'truncated_summary_fields': truncated}


@router.get('/records')
def records(cve: str = Query(..., pattern=r'^CVE-\d{4}-\d{4,}$', max_length=40),
            kind: Literal['advisory', 'vulnerability', 'exploitation', 'risk_enrichment'] | None = None,
            source_id: int | None = Query(None, ge=1, le=9223372036854775807), cursor: int = Query(0, ge=0, le=9223372036854775807),
            limit: int = Query(50, ge=1, le=100), auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    viewer(auth)
    query = _record_query().where(IntelligenceRecord.cve == cve, IntelligenceRecord.id > cursor)
    if kind is not None:
        query = query.where(IntelligenceRecord.kind == kind)
    if source_id is not None:
        query = query.where(IntelligenceRecord.source_id == source_id)
    found = db.execute(query.order_by(IntelligenceRecord.id).limit(limit + 1)).mappings().all()
    items = found[:limit]
    return {'items': [_record_summary(item) for item in items],
            'next_cursor': items[-1]['id'] if len(found) > limit else None,
            'scope': 'retained_history', 'informational_only': True,
            'note': 'Stored records include earlier imports. First import does not establish current package membership. '
                    'Supplemental records alone do not establish product applicability or VEX status.'}


@router.get('/records/{identity}')
def record(identity: int = PathParameter(..., ge=1, le=9223372036854775807), auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    viewer(auth)
    item = db.execute(_record_query().where(IntelligenceRecord.id == identity)).mappings().one_or_none()
    if item is None:
        raise HTTPException(404, 'Record not found')
    stored_json = cast(IntelligenceRecord.data, Text)
    # Check storage bytes in the database before materializing publisher JSON.
    if db.get_bind(mapper=inspect(IntelligenceRecord)).dialect.name == 'postgresql':
        size = func.octet_length(stored_json)
    else:
        size = func.length(cast(stored_json, LargeBinary))
    data_query = select(IntelligenceRecord.data).where(IntelligenceRecord.id == identity,
                                                        size <= MAX_RECORD_DETAIL_BYTES)
    payload = db.execute(data_query).first()
    if payload is None:
        raise HTTPException(413, 'Record detail exceeds the 8 MiB response limit')
    result = _record_summary(item) | {'data': payload[0]}
    encoded = json.dumps(jsonable_encoder(result), separators=(',', ':'), ensure_ascii=False,
                         allow_nan=False).encode('utf-8')
    if len(encoded) > MAX_RECORD_DETAIL_BYTES:
        raise HTTPException(413, 'Record detail exceeds the 8 MiB response limit')
    return Response(encoded, media_type='application/json')

@router.get('/statements')
def statements(q: str = Query('',max_length=200), status: str = '', source_id: int | None = None, after: int = 0, auth: AuthContext = Depends(require_user),db=Depends(get_db)):
    allowed(auth,'config.manage')
    query = select(VexStatement,VexDocument,VexSource).join(VexDocument,VexStatement.document_id==VexDocument.id).join(VexSource,VexSource.id==VexDocument.source_id).where(VexStatement.id>after).order_by(VexStatement.id).limit(100)
    if q: query=query.where(or_(VexStatement.cve.ilike('%'+q+'%'),VexStatement.product_id.ilike('%'+q+'%'),VexSource.name.ilike('%'+q+'%')))
    if status: query=query.where(VexStatement.status==status)
    if source_id is not None: query=query.where(VexSource.id==source_id)
    found=db.execute(query).all()
    return {'items':[row(s,('id','cve','product_id','identity','status','justification','impact','action')) | {'document_id':d.id,'source':source.name,'verification':d.verification,'issued_at':d.issued_at,'withdrawn':d.withdrawn} for s,d,source in found], 'next_after':found[-1][0].id if len(found)==100 else None}

@router.get('/documents/{identity}')
def document(identity:int,auth:AuthContext=Depends(require_user),db=Depends(get_db)):
    allowed(auth,'config.manage')
    item=db.get(VexDocument,identity)
    if item is None: raise HTTPException(404,'Document not found')
    return row(item,('id','source_id','sha256','format','document_key','version','issued_at','retrieved_at','source_url','verification','withdrawn','raw_text'))

@router.get('/assessments/{identity}')
def assessment(identity:int,auth:AuthContext=Depends(require_user),db=Depends(get_db)):
    item=db.get(RiskAssessment,identity)
    if item is None or not auth.has('service.view',item.service_id): raise HTTPException(404,'Assessment not found')
    return risk.serialize(item)

@router.get('/assessments/{identity}/documents/{document_id}')
def assessment_document(identity: int, document_id: int, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    assessment = db.get(RiskAssessment, identity)
    if assessment is None or not auth.has('service.view', assessment.service_id):
        raise HTTPException(404, 'Assessment not found')
    referenced = any(candidate.get('document_id') == document_id
        for finding in assessment.details for observation in finding.get('observations', [])
        for key in ('statements', 'rejected_candidates') for candidate in observation.get('vex', {}).get(key, []))
    if not referenced:
        raise HTTPException(404, 'Document not referenced by assessment')
    # Original documents are loaded only on explicit drilldown, with a storage-byte cap.
    size = func.octet_length(VexDocument.raw_text) if db.get_bind(mapper=inspect(VexDocument)).dialect.name == 'postgresql' else func.length(cast(VexDocument.raw_text, LargeBinary))
    item = db.scalar(select(VexDocument).where(VexDocument.id == document_id, size <= vex.MAX_BYTES))
    if item is None:
        raise HTTPException(404, 'Document unavailable or exceeds evidence limit')
    return row(item, ('id','source_id','sha256','format','document_key','version','issued_at','retrieved_at','source_url','verification','withdrawn','raw_text'))


@router.post('/sources/{identity}/state')
async def source_state(identity:int,request:Request,auth:AuthContext=Depends(require_user),db=Depends(get_db)):
    allowed(auth,'config.manage')
    payload=await data(request,auth)
    if not isinstance(payload.get('enabled'),bool): raise HTTPException(422,'enabled must be boolean')
    item=db.get(VexSource,identity)
    if item is None: raise HTTPException(404,'Source not found')
    item.enabled=payload['enabled']
    record_audit(db,auth,'risk.source.state','vex_source',identity,enabled=item.enabled)
    db.commit()
    return {'id':item.id,'enabled':item.enabled}


@router.get('/native-vex/policy')
def native_vex_policy(auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    allowed(auth, 'config.manage')
    from .native_vex_models import VexDispositionPolicy
    policy = db.get(VexDispositionPolicy, 1)
    return {'enabled': policy.enabled, 'version': policy.policy_version,
            'name': 'Automatic VEX Not Affected Exclusion'}


@router.post('/native-vex/policy')
async def update_native_vex_policy(request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    allowed(auth, 'config.manage')
    payload = await data(request, auth)
    if type(payload.get('enabled')) is not bool or type(payload.get('version')) is not int:
        raise HTTPException(422, 'Provide enabled and the current policy version')
    from .native_vex_models import VexDispositionPolicy
    policy = db.scalar(select(VexDispositionPolicy).where(VexDispositionPolicy.id == 1).with_for_update())
    if policy.policy_version != payload['version']:
        raise HTTPException(409, 'Policy changed; refresh the preview before saving')
    old = policy.enabled
    if old != payload['enabled']:
        policy.enabled = payload['enabled']
        policy.policy_version += 1
        record_audit(db, auth, 'vex.exclusion.policy.changed', 'vex_disposition_policy', 1,
                     old_enabled=old, new_enabled=policy.enabled, policy_version=policy.policy_version)
    db.commit()
    return {'enabled': policy.enabled, 'version': policy.policy_version}


@router.get('/native-vex/preview')
def native_vex_preview(after: int = 0, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    """Bounded, current evidence only; never join the intelligence corpus."""
    allowed(auth, 'config.manage')
    from .models import Finding
    from .native_vex import finding_excluded, observation_excluded
    from .native_vex_models import VexDispositionPolicy
    from .main import (_risk_finding_expressions, configuration_for_service,
        service_overview_rows_aggregated, get_configuration)
    from .models import ExceptionRecord, FindingObservation
    now = datetime.now(timezone.utc)
    items = db.scalars(select(Service).where(Service.id > after).order_by(Service.id).limit(50)).all()
    configurations = {item.id: configuration_for_service(db, item) for item in items}
    overview, _ = service_overview_rows_aggregated(db, auth, now, get_configuration(db), items, configurations)
    blockers = {row['service'].id: bool(len(row['policy_noncompliant']) or row['evidence_noncompliant'])
                for row in overview}
    results = []
    for item in items:
        configuration = configurations[item.id]
        exception = select(ExceptionRecord.id).where(ExceptionRecord.finding_id == Finding.id,
            ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).exists()
        eligible, noncompliant, needs_observations = _risk_finding_expressions({item.id: configuration}, now, exception, native_disposition=False)
        excluded = finding_excluded(Finding.id, now, preview=True) & ~exception
        # Existing exception/resolution semantics remain in the canonical expressions.
        base = select(func.count()).select_from(Finding).where(Finding.service_id == item.id, Finding.active.is_(True))
        if needs_observations:
            latest = select(func.max(FindingObservation.id)).where(FindingObservation.finding_id == Finding.id).correlate(Finding).scalar_subquery()
            base = base.outerjoin(FindingObservation, FindingObservation.id == latest)
        noncompliant = noncompliant & ~exception
        before = db.scalar(base.where(noncompliant))
        after_count = db.scalar(base.where(noncompliant, ~excluded))
        results.append({'service_id': item.id, 'service_key': item.service_key, 'name': item.name,
            'eligible_before': db.scalar(base.where(eligible)),
            'eligible_after': db.scalar(base.where(eligible, ~excluded)),
            'noncompliant_before': before, 'noncompliant_after': after_count,
            'compliance_before': not before and not blockers.get(item.id, True),
            'compliance_after': not after_count and not blockers.get(item.id, True)})
    policy = db.get(VexDispositionPolicy, 1)
    return {'items': results, 'version': policy.policy_version,
            'next_after': items[-1].id if len(items) == 50 else None,
            'note': 'Only current completed evaluations are included. Other compliance rules still apply.'}


@router.get('/services/{key}/native-vex')
def native_vex_evidence(key: str, after: int = 0, finding_id: int | None = None, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    item = service(db, auth, key)
    from .native_vex_models import VexDispositionService, VexDispositionEvaluation, VexDispositionPolicy, VexObservationDisposition
    from .native_vex import current_evaluation
    state = db.get(VexDispositionService, item.id)
    evaluation = db.get(VexDispositionEvaluation, state.evaluation_id) if state and state.evaluation_id else None
    now = datetime.now(timezone.utc)
    current = bool(db.scalar(select(VexDispositionEvaluation.id).join(VexDispositionService,
        VexDispositionService.service_id == VexDispositionEvaluation.service_id).join(VexDispositionPolicy, VexDispositionPolicy.id == 1)
        .where(VexDispositionEvaluation.service_id == item.id, *current_evaluation(now, enabled=False)).limit(1)))
    policy = db.get(VexDispositionPolicy, 1)
    observations = db.scalars(select(VexObservationDisposition).where(
        VexObservationDisposition.evaluation_id == evaluation.id, VexObservationDisposition.id > after,
        *([VexObservationDisposition.finding_id == finding_id] if finding_id is not None else []))
        .order_by(VexObservationDisposition.id).limit(100)).all() if evaluation else []
    # Technical evidence does not override resolution or a current human exception.
    from .models import Finding, ExceptionRecord
    finding_ids = {o.finding_id for o in observations}
    findings = {f.id: f for f in db.scalars(select(Finding).where(Finding.id.in_(finding_ids)))} if finding_ids else {}
    exceptions = set(db.scalars(select(ExceptionRecord.finding_id).where(
        ExceptionRecord.finding_id.in_(finding_ids), ExceptionRecord.revoked_at.is_(None),
        ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now))) if finding_ids else set()
    def disposition(observation):
        finding = findings.get(observation.finding_id)
        if finding is None or not finding.active or finding.resolved_at is not None:
            return 'resolved'
        if finding.id in exceptions:
            return 'exception'
        return 'vex_not_affected' if current and policy.enabled and observation.excluded else 'actionable'
    finding_disposition = None
    if finding_id is not None:
        from .native_vex import finding_excluded, observation_excluded
        target = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.service_id == item.id))
        if target is not None:
            if not target.active or target.resolved_at is not None:
                finding_disposition = 'resolved'
            elif db.scalar(select(ExceptionRecord.id).where(ExceptionRecord.finding_id == finding_id,
                    ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now,
                    ExceptionRecord.expires_at > now).limit(1)):
                finding_disposition = 'exception'
            elif db.scalar(select(finding_excluded(finding_id, now))):
                finding_disposition = 'vex_not_affected'
            else:
                from .models import FindingObservation
                mixed = db.scalar(select(FindingObservation.id).where(FindingObservation.finding_id == finding_id,
                    observation_excluded(FindingObservation.id, now)).limit(1))
                finding_disposition = 'mixed_vex' if mixed else 'active'
    return {'current': current, 'enabled': policy.enabled, 'pending': not current,
            'finding_disposition': finding_disposition,
            'evaluation': row(evaluation, ('id','evaluated_at','valid_until','policy_version','summary')) if evaluation else None,
            'items': [{'id': o.id, 'finding_id': o.finding_id, 'observation_id': o.observation_id,
                       'effective_disposition': disposition(o),
                       'verified_not_affected': bool(current and o.excluded),
                       'evidence': o.evidence} for o in observations],
            'next_after': observations[-1].id if len(observations) == 100 else None}
