"""Named environments, one-use enrollment and bounded monitoring-only reports."""
import hashlib
import json
import os
import re
import secrets
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy import and_, inspect, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer

from .auth import AuthContext, record_audit, require_permission
from .database import get_db
from .models import Group, Service
from .oci_transport import valid_image_reference
from . import runtime_applications as applications
from .release_validity import utc
from .runtime_models import RuntimeAgent, RuntimeEnvironment, RuntimeEnrollmentReceipt, RuntimeLinkToken, expire_link_keys, now
from .service_oci import _csrf

router = APIRouter(prefix='/api/runtime', tags=['Runtime'])
view = require_permission('runtime.view')
manage = require_permission('runtime.manage')
MAX_BODY = 2 * 1024 * 1024
MAX_WORKLOADS = 2000
DISPLAY_LIMIT = 5000
STALE_SECONDS = 300
CLUSTER_ROLES = ('unspecified', 'development', 'validation', 'production')
ENVIRONMENT_FIELDS = {
    'name': {'type': 'string', 'maxLength': 160},
    'kind': {'type': 'string', 'enum': ['kubernetes', 'docker']},
    'cluster_role': {'type': 'string', 'enum': list(CLUSTER_ROLES), 'default': 'unspecified'},
    'discovery_group_id': {'type': ['integer', 'null']},
    'service_scope': {'type': 'string', 'enum': ['all', 'selected']},
    'service_ids': {'type': 'array', 'items': {'type': 'integer', 'minimum': 1}, 'maxItems': 256},
}
OPTIONAL_FIELDS = {'pod', 'workload_kind', 'container_kind', 'namespace_uid', 'pod_uid', 'workload_uid',
                   'controller_uid', 'controller_kind', 'controller_name', 'helm_namespace', 'app_name',
                   'app_instance', 'app_part_of', 'app_version', 'service_hint', 'chart_digest', 'desired_image'}
OBSERVATION_LIMITS = dict.fromkeys(OPTIONAL_FIELDS | {'namespace', 'workload', 'container', 'node', 'state',
                                                      'chart_name', 'chart_version', 'helm_release'}, 255)
OBSERVATION_LIMITS.update(uid=512, image_ref=1024, image_id=1024, desired_image=1024)


def json_body(properties, required):
    schema = {'type': 'object', 'properties': properties, 'additionalProperties': False, 'required': list(required)}
    return {'requestBody': {'required': True, 'content': {'application/json': {'schema': schema}}}}


def report_body_schema(max_rows, max_pages=None):
    fields = {k: {'type': 'string', 'maxLength': size} for k, size in sorted(OBSERVATION_LIMITS.items())}
    fields['container_kind']['enum'] = ['', 'regular', 'init', 'ephemeral']
    fields['chart_digest']['pattern'] = '^sha256:[0-9a-f]{64}$'
    fields['service_hint']['description'] = 'Untrusted suggestion for human assignment.'
    observation = {'type': 'object', 'additionalProperties': False, 'required': ['uid', 'container', 'state'], 'properties': fields}
    report = {'sequence': {'type': 'integer', 'minimum': 1, 'maximum': 2147483647},
              'observed_at': {'type': 'string', 'format': 'date-time'}, 'complete': {'type': 'boolean'},
              'discovery_version': {'type': 'integer', 'enum': [1]},
              'errors': {'type': 'array', 'maxItems': 32, 'items': {'type': 'string', 'pattern': '^[a-z0-9_.:-]{1,100}$'}},
              'workloads': {'type': 'array', 'maxItems': max_rows, 'items': observation}}
    required = ['sequence', 'observed_at', 'complete', 'workloads']
    if max_pages:
        report.update(page={'type': 'integer', 'minimum': 0, 'maximum': max_pages-1},
                      pages={'type': 'integer', 'minimum': 1, 'maximum': max_pages},
                      snapshot_sha256={'type': 'string', 'pattern': '^[0-9a-f]{64}$'})
        required.extend(('page', 'pages', 'snapshot_sha256'))
    return json_body(report, required)


def hashed(value):
    return hashlib.sha256(value.encode()).hexdigest()


def reply(value):
    # Linking credentials and runtime inventory must not enter browser/proxy caches.
    return JSONResponse(value, headers={'Cache-Control': 'no-store'})


def iso(value):
    return utc(value).isoformat() if value else None


def text(value, field, limit, required=True):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise HTTPException(422, f'Invalid {field}')
    value = value.strip()
    if required and not value:
        raise HTTPException(422, f'{field} is required')
    return value


async def body(request, allowed, limit=16384):
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > limit:
            raise HTTPException(413, 'Runtime request is too large')
        raw.extend(chunk)
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(422, 'A JSON object is required') from None
    if not isinstance(data, dict) or set(data) - set(allowed):
        raise HTTPException(422, 'Unknown runtime request fields')
    return data


def commit(db):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'The environment name or linked source already exists') from None


def environment(db, identity, *, lock=False):
    query = select(RuntimeEnvironment).where(RuntimeEnvironment.id == identity).execution_options(populate_existing=True)
    row = db.scalar(query.with_for_update() if lock else query)
    if row is None:
        raise HTTPException(404, 'Environment not found')
    return row


def environment_public(row):
    return {'id': row.id, 'name': row.name, 'kind': row.kind,
            'cluster_role': row.cluster_role, 'discovery_group_id': row.discovery_group_id,
            'service_scope': row.service_scope, 'service_ids': row.service_ids, 'created_at': iso(row.created_at)}


def discovery_settings(db, row, data):
    if 'cluster_role' in data:
        role = data['cluster_role']
        if role not in CLUSTER_ROLES:
            raise HTTPException(422, 'Select a supported cluster role')
        if role != 'unspecified' and row.kind != 'kubernetes':
            raise HTTPException(422, 'Application discovery roles require a Kubernetes environment')
        row.cluster_role = role
    if 'discovery_group_id' in data:
        identity = data['discovery_group_id']
        if identity is not None and (type(identity) is not int or not db.get(Group, identity)):
            raise HTTPException(422, 'Select an existing discovery group')
        row.discovery_group_id = identity


def scope(db, value, mode, *, lock=False):
    if mode not in ('all', 'selected'):
        raise HTTPException(422, 'Choose all or selected services')
    if (not isinstance(value, list) or len(value) > 256
            or any(type(item) is not int or item < 1 for item in value)):
        raise HTTPException(422, 'Select valid CATS services')
    ids = sorted(set(value))
    if ids and mode == 'all':
        raise HTTPException(422, 'Choose selected scope to supply service IDs')
    query = select(Service.id).where(Service.id.in_(ids)).order_by(Service.id)
    if ids and set(db.scalars(query.with_for_update(read=True) if lock else query)) != set(ids):
        raise HTTPException(422, 'A selected service no longer exists')
    return ids


def coverage(agent, timestamp):
    if not agent.enabled:
        return 'revoked'
    if agent.last_seen_at is None:
        return 'never_reported'
    if (timestamp - utc(agent.last_seen_at)).total_seconds() > STALE_SECONDS:
        return 'stale'
    if not agent.complete:
        return 'incomplete'
    if agent.observed_at is None or (timestamp - utc(agent.observed_at)).total_seconds() > STALE_SECONDS:
        return 'stale'
    return 'fresh'


def workload_issue_reasons(decision):
    """Keep every applicable category on one issue, most severe first."""
    reasons = {}
    if decision['status'] == 'noncompliant':
        reasons['noncompliant'] = decision['reason']
    scan = decision.get('scan_assessment')
    if scan and scan['status'] == 'noncompliant':
        reasons['scan_noncompliant'] = scan['reason']
    if decision['status'] == 'unverified':
        reasons['unverified'] = decision['reason']
    return reasons


@router.get('')
def overview(environment_id: int | None = Query(default=None, ge=1),
             offset: int = Query(default=0, ge=0), limit: int = Query(default=DISPLAY_LIMIT, ge=1, le=DISPLAY_LIMIT),
             issue_offset: int = Query(default=0, ge=0), issue_limit: int = Query(default=DISPLAY_LIMIT, ge=1, le=DISPLAY_LIMIT),
             issue_namespace: str | None = Query(default=None, min_length=1, max_length=255),
             issue_code: Literal['coverage', 'noncompliant', 'scan_noncompliant', 'unverified'] | None = None,
             db: Session = Depends(get_db), auth: AuthContext = Depends(view)):
    from .runtime_policy import RuntimePolicyCache, evaluate_observation
    timestamp = now()
    policy_cache = RuntimePolicyCache()
    query = select(RuntimeEnvironment).order_by(RuntimeEnvironment.name)
    cutoff = timestamp - timedelta(seconds=STALE_SECONDS)
    fresh = and_(RuntimeAgent.complete.is_(True), RuntimeAgent.last_seen_at >= cutoff,
                 RuntimeAgent.observed_at >= cutoff).is_(True)
    # Read the preferred source first so only container UIDs, not prior inventories,
    # need to be retained to reconcile overlapping Kubernetes collectors.
    agents_query = select(RuntimeAgent).order_by(RuntimeAgent.environment_id, fresh.desc(),
                    RuntimeAgent.inventory_observed_at.desc().nulls_last(), RuntimeAgent.id.desc()).execution_options(yield_per=1)
    if environment_id is not None:
        query = query.where(RuntimeEnvironment.id == environment_id)
        agents_query = agents_query.where(RuntimeAgent.environment_id == environment_id)
    environments = list(db.scalars(query))
    if environment_id is not None and not environments:
        raise HTTPException(404, 'Environment not found')
    by_id = {row.id: row for row in environments}
    mappings = applications.mapping_index(db, [row.id for row in environments if row.cluster_role != 'unspecified'])
    clusters = {row.id: {**environment_public(row), 'agent_count': 0, 'workload_count': 0, 'namespace_count': 0,
                         'issue_count': 0, 'inventory_truncated': False, 'coverage': 'unlinked',
                         'can_manage': auth.has('runtime.manage')} for row in environments}
    namespaces, issues, total_issues = {}, [], 0
    decision_cache = {row.id: {} for row in environments}
    coverage_rank = {'fresh': 0, 'never_reported': 1, 'incomplete': 2, 'stale': 3}

    def add_issue(cluster, agent_id, reasons, observation=None, decision=None):
        nonlocal total_issues
        cluster['issue_count'] += 1
        namespace = observation.get('namespace') if observation else None
        if namespace:
            key = cluster['id'], namespace
            if key not in namespaces:
                namespaces[key] = dict(environment_id=cluster['id'], name=namespace, workload_count=0, issue_count=0)
                cluster['namespace_count'] += 1
            namespaces[key]['issue_count'] += 1
        if issue_namespace is not None and issue_namespace != namespace:
            return
        if issue_code is not None and issue_code not in reasons:
            return
        total_issues += 1
        if not issue_offset < total_issues <= issue_offset + issue_limit:
            return
        code, reason = next(iter(reasons.items()))
        severity = 'error' if code in ('noncompliant', 'scan_noncompliant') else 'warning'
        issue = dict(environment_id=cluster['id'], agent_id=agent_id, severity=severity,
                     code=code, reason=reason, codes=list(reasons))
        if observation:
            issue['compliance'] = decision
            issue.update({field: observation.get(field, '') for field in
                          ('uid', 'namespace', 'pod', 'workload', 'container', 'image_ref', 'image_id', 'observed_at')})
            issue.update({field: decision[field] for field in ('service_id', 'approval_id', 'release_id', 'override_id')
                          if field in decision})
        issues.append(issue)

    agents, workloads, total = [], [], 0
    previous_environment, seen_uids = None, set()
    complete_production = {}
    for row in db.scalars(agents_query):
        status = coverage(row, timestamp)
        cluster = clusters[row.environment_id]
        agents.append({'id': row.id, 'environment_id': row.environment_id, 'name': row.name,
                       'source_id': row.source_id, 'version': row.version, 'enabled': row.enabled,
                       'last_seen_at': iso(row.last_seen_at), 'observed_at': iso(row.observed_at),
                       'inventory_observed_at': iso(row.inventory_observed_at),
                       'complete': row.complete, 'errors': row.errors, 'coverage': status,
                       'workload_count': len(row.workloads)})
        if not row.enabled:
            if cluster['coverage'] == 'unlinked':
                cluster['coverage'] = 'revoked'
            continue
        cluster['agent_count'] += 1
        env = by_id[row.environment_id]
        if (env.cluster_role == 'production' and status == 'fresh' and env.discovery_observed_at and
                row.inventory_observed_at and utc(env.discovery_observed_at) == utc(row.inventory_observed_at)):
            complete_production.setdefault(env.id, row.id)
        if coverage_rank[status] > coverage_rank.get(cluster['coverage'], -1):
            cluster['coverage'] = status
        if status != 'fresh':
            add_issue(cluster, row.id, {'coverage': 'coverage_' + status})
        if row.environment_id != previous_environment:
            seen_uids.clear()
            previous_environment = row.environment_id
        decisions = decision_cache[row.environment_id]
        for observation in row.workloads:
            if observation['state'] == 'desired':
                continue
            if cluster['kind'] == 'kubernetes':
                if observation['uid'] in seen_uids:
                    continue
                seen_uids.add(observation['uid'])
            position, total = total, total + 1
            cluster['workload_count'] += 1
            namespace = observation.get('namespace')
            if namespace:
                key = (row.environment_id, namespace)
                if key not in namespaces:
                    namespaces[key] = dict(environment_id=row.environment_id, name=namespace, workload_count=0, issue_count=0)
                    cluster['namespace_count'] += 1
                namespaces[key]['workload_count'] += 1
            app = mappings.get((row.environment_id, applications.workload_key(observation)))
            service_id = app.service_id if app and applications.in_scope(by_id[row.environment_id], app.service_id) else None
            key = (observation['state'], observation['image_ref'], observation['image_id'], service_id,
                   observation.get('workload_kind'), observation.get('workload'), observation.get('container_kind'), observation.get('container'))
            if status != 'fresh':
                decision = {'status': 'unverified', 'reason': 'coverage_' + status}
            elif key in decisions:
                decision = decisions[key]
            else:
                env = by_id[row.environment_id]
                scope = dict(kind=env.kind, service_scope='selected', service_ids=[service_id]) if service_id else env
                decision = evaluate_observation(db, scope, observation, now=timestamp, cache=policy_cache)
                if env.cluster_role in ('development', 'validation'):
                    decision = {**decision, 'status': 'observed', 'reason': env.cluster_role + '_inventory'}
                elif env.cluster_role == 'production' and observation['state'] == 'running':
                    decision = applications.production_decision(db, decision, observation, service_id, timestamp, policy_cache)
                decisions[key] = decision
            if status == 'fresh' and observation['state'] == 'running':
                reasons = workload_issue_reasons(decision)
                if reasons:
                    add_issue(cluster, row.id, reasons, {**observation, 'observed_at': iso(row.inventory_observed_at)}, decision)
            if not offset <= position < offset + limit:
                cluster['inventory_truncated'] = True
                continue
            workloads.append({**observation, 'agent_id': row.id, 'environment_id': row.environment_id,
                              'observed_at': iso(row.inventory_observed_at), 'compliance': decision})
    for identity, agent_id in complete_production.items():
        for missing, decision in applications.missing_components(db, by_id[identity], timestamp, policy_cache):
            add_issue(clusters[identity], agent_id, workload_issue_reasons(decision), missing, decision)
    for cluster in clusters.values():
        if cluster['coverage'] in ('unlinked', 'revoked'):
            add_issue(cluster, None, {'coverage': 'coverage_' + cluster['coverage']})
    return reply({'environments': [environment_public(row) for row in environments], 'agents': agents,
                  'clusters': list(clusters.values()), 'namespaces': list(namespaces.values()), 'issues': issues,
                  'total_issues': total_issues, 'issue_offset': issue_offset,
                  'unfiltered_total_issues': sum(cluster['issue_count'] for cluster in clusters.values()),
                  'next_issue_offset': issue_offset + issue_limit if issue_offset + issue_limit < total_issues else None,
                  'workloads': workloads, 'total_workloads': total, 'inventory_truncated': len(workloads) < total,
                  'next_offset': offset + limit if offset + limit < total else None, 'offset': offset,
                  'services': [{'id': row.id, 'name': row.name} for row in db.scalars(select(Service).order_by(Service.name))],
                  'groups': [{'id': group.id, 'name': group.name} for group in db.scalars(select(Group).order_by(Group.name))] if auth.has('runtime.manage') else [],
                  'permissions': {'manage': auth.has('runtime.manage')}})


@router.post('/environments', openapi_extra=json_body(ENVIRONMENT_FIELDS, ('name', 'kind')))
async def create_environment(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(manage)):
    _csrf(request, auth)
    data = await body(request, {'name', 'kind', 'service_ids', 'service_scope', 'cluster_role', 'discovery_group_id'})
    if data.get('kind') not in ('kubernetes', 'docker'):
        raise HTTPException(422, 'Choose Kubernetes or Docker')
    mode = data.get('service_scope', 'selected')
    row = RuntimeEnvironment(name=text(data.get('name'), 'name', 160), kind=data['kind'], service_scope=mode,
                             service_ids=scope(db, data.get('service_ids', []), mode, lock=True))
    db.add(row)
    discovery_settings(db, row, data)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Environment name already exists') from None
    record_audit(db, auth, 'runtime.environment.created', 'runtime_environment', row.id, name=row.name,
                 cluster_role=row.cluster_role, discovery_group_id=row.discovery_group_id)
    commit(db)
    return reply(environment_public(row))


@router.put('/environments/{identity}', openapi_extra=json_body({k: v for k, v in ENVIRONMENT_FIELDS.items() if k != 'kind'}, ()))
async def edit_environment(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(manage)):
    _csrf(request, auth)
    data = await body(request, {'name', 'service_scope', 'service_ids', 'cluster_role', 'discovery_group_id'})
    if 'service_ids' in data:
        # Match service deletion's service -> environment lock order.
        scope(db, data['service_ids'], data.get('service_scope', 'selected'), lock=True)
    row = environment(db, identity, lock=True)
    discovery_settings(db, row, data)
    if 'name' in data:
        row.name = text(data['name'], 'name', 160)
    if 'service_ids' in data or 'service_scope' in data:
        mode = data.get('service_scope', row.service_scope)
        updated = scope(db, data.get('service_ids', [] if mode == 'all' else row.service_ids), mode)
        if mode != row.service_scope or sorted(row.service_ids) != updated:
            row.service_scope, row.service_ids = mode, updated
            expire_link_keys(db, identity)
    if {'cluster_role', 'service_ids', 'service_scope'} & data.keys():
        scopes = set(db.execute(select(applications.RuntimeApplication.service_id, applications.RuntimeApplication.namespace)
            .where(applications.RuntimeApplication.environment_id == identity, applications.RuntimeApplication.service_id.is_not(None))))
        applications.prepare(db, row, scopes)
    record_audit(db, auth, 'runtime.environment.updated', 'runtime_environment', row.id,
                 name=row.name, service_ids=row.service_ids, service_scope=row.service_scope,
                 cluster_role=row.cluster_role, discovery_group_id=row.discovery_group_id)
    commit(db)
    return reply(environment_public(row))


@router.post('/environments/{identity}/link-tokens')
async def create_link_token(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(manage)):
    _csrf(request, auth)
    await body(request, set())
    env = environment(db, identity, lock=True)
    scope(db, env.service_ids, env.service_scope)
    timestamp = now()
    # A replacement key supersedes earlier keys and their retry windows.
    expire_link_keys(db, identity)
    secret = 'cats-link-' + secrets.token_urlsafe(32)
    expiry = timestamp + timedelta(hours=1)
    db.add(RuntimeLinkToken(environment_id=identity, token_hash=hashed(secret), expires_at=expiry))
    record_audit(db, auth, 'runtime.link_key.created', 'runtime_environment', identity, expires_at=iso(expiry))
    commit(db)
    result = {'linking_key': secret, 'expires_at': iso(expiry), 'environment_id': identity,
              'environment_name': env.name, 'kind': env.kind, 'service_ids': env.service_ids, 'service_scope': env.service_scope}
    image = os.getenv('CATS_IMAGE')
    if valid_image_reference(image):
        # Compose implicitly selects latest for an untagged repository. Helm requires an explicit selector.
        result['image_reference'] = image if ':' in image.rsplit('/', 1)[-1] else image + ':latest'
    return reply(result)


@router.post('/link')
async def link(request: Request, db: Session = Depends(get_db)):
    data = await body(request, {'linking_key', 'name', 'source_id', 'version', 'kind', 'agent_token'})
    key = text(data.get('linking_key'), 'linking_key', 256)
    name = text(data.get('name'), 'name', 160)
    source_id = text(data.get('source_id'), 'source_id', 255)
    version = text(data.get('version'), 'version', 80)
    proposed = data.get('agent_token')
    if 'agent_token' in data and (not isinstance(proposed, str)
            or not re.fullmatch(r'cats-agent-[A-Za-z0-9_-]{43}', proposed)):
        raise HTTPException(422, 'Invalid agent enrollment credential')
    if ('kind' in data or proposed) and data.get('kind') not in ('kubernetes', 'docker'):
        raise HTTPException(422, 'Choose Kubernetes or Docker')
    invalid = HTTPException(401, 'Linking key is invalid, expired or already used')
    digest = hashed(key)
    env_id = db.scalar(select(RuntimeLinkToken.environment_id).where(RuntimeLinkToken.token_hash == digest))
    if env_id is None:
        raise invalid
    # Serialize issuance, scope edits and consumption in the same lock order.
    env = environment(db, env_id, lock=True)
    token = db.scalar(select(RuntimeLinkToken).where(RuntimeLinkToken.token_hash == digest)
                      .with_for_update().execution_options(populate_existing=True))
    timestamp = now()
    if token is None or utc(token.expires_at) <= timestamp:
        raise invalid
    if 'kind' in data and env.kind != data['kind']:
        raise HTTPException(409, 'Collector kind does not match the selected environment')
    if token.consumed_at is not None:
        receipt = db.get(RuntimeEnrollmentReceipt, token.id)
        if proposed and receipt and secrets.compare_digest(hashed(proposed), receipt.credential_hash):
            row = db.scalar(select(RuntimeAgent).where(RuntimeAgent.id == receipt.agent_id,
                RuntimeAgent.environment_id == env.id, RuntimeAgent.source_id == source_id,
                RuntimeAgent.token_hash == receipt.credential_hash, RuntimeAgent.enabled.is_(True)).with_for_update())
            if row is not None:
                return linked(row, env, proposed)
        raise invalid
    claimed = db.execute(update(RuntimeLinkToken).where(RuntimeLinkToken.id == token.id,
        RuntimeLinkToken.consumed_at.is_(None), RuntimeLinkToken.expires_at > timestamp)
        .values(consumed_at=timestamp).execution_options(synchronize_session=False))
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(401, 'Linking key is invalid, expired or already used')
    row = db.scalar(select(RuntimeAgent).where(RuntimeAgent.environment_id == env.id,
                                               RuntimeAgent.source_id == source_id).with_for_update())
    if row is not None and row.enabled:
        db.rollback()
        raise HTTPException(409, 'This source is already linked; revoke its previous agent before relinking')
    secret = proposed or 'cats-agent-' + secrets.token_urlsafe(32)
    credential_hash = hashed(secret)
    if proposed and ((row is not None and row.token_hash == credential_hash) or db.scalar(
            select(RuntimeEnrollmentReceipt.link_id).where(RuntimeEnrollmentReceipt.credential_hash == credential_hash)) is not None):
        db.rollback()
        raise HTTPException(409, 'Relinking requires a fresh agent credential')
    if row is None:
        row = RuntimeAgent(environment_id=env.id, source_id=source_id)
        db.add(row)
    else:
        from .runtime_report_pages import clear_pages
        clear_pages(db, row.id)
    row.name, row.version, row.token_hash, row.enabled = name, version, credential_hash, True
    row.last_sequence, row.report_hash, row.complete, row.errors = 0, '', False, []
    row.last_seen_at, row.observed_at = None, None
    # Old inventory remains visible as unverified until a complete new report arrives.
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'This source is already linked') from None
    db.add(RuntimeEnrollmentReceipt(link_id=token.id, agent_id=row.id, credential_hash=row.token_hash))
    record_audit(db, None, 'runtime.agent.linked', 'runtime_agent', row.id, environment_id=env.id)
    commit(db)
    return linked(row, env, secret)


def linked(row, env, secret):
    return reply({'agent_id': row.id, 'agent_token': secret, 'environment_id': env.id,
                  'environment_name': env.name, 'kind': env.kind, 'report_interval_seconds': 60})


@router.post('/agents/{identity}/revoke')
async def revoke(identity: str, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(manage)):
    _csrf(request, auth)
    await body(request, set())
    row = db.get(RuntimeAgent, identity)
    if row is None:
        raise HTTPException(404, 'Agent not found')
    db.execute(update(RuntimeAgent).where(RuntimeAgent.id == identity).values(enabled=False))
    from .runtime_report_pages import clear_pages
    clear_pages(db, identity)
    record_audit(db, auth, 'runtime.agent.revoked', 'runtime_agent', identity)
    commit(db)
    return reply({'id': identity, 'enabled': False})


def authenticate(request, db):
    authorization = request.headers.get('Authorization', '')
    if not authorization.startswith('Bearer cats-agent-') or len(authorization) > 300:
        raise HTTPException(401, 'A linked agent credential is required')
    token_hash = hashed(authorization[7:])
    row = db.scalar(select(RuntimeAgent).options(defer(RuntimeAgent.workloads)).where(
                    RuntimeAgent.token_hash == token_hash, RuntimeAgent.enabled.is_(True))
                    .execution_options(populate_existing=True))
    if row is None:
        raise HTTPException(401, 'Agent credential is invalid or revoked')
    return row, token_hash


def validate_report(data, timestamp, *, max_workloads=MAX_WORKLOADS):
    if 'discovery_version' in data and (type(data['discovery_version']) is not int or data['discovery_version'] != 1):
        raise HTTPException(422, 'Unsupported runtime discovery protocol version')
    sequence = data.get('sequence')
    if type(sequence) is not int or not 1 <= sequence <= 2147483647 or type(data.get('complete')) is not bool:
        raise HTTPException(422, 'A positive sequence and complete boolean are required')
    try:
        from datetime import datetime
        observed = datetime.fromisoformat(data['observed_at'])
        if observed.utcoffset() is None or observed > timestamp + timedelta(minutes=5):
            raise ValueError()
        observed = utc(observed)
    except (KeyError, ValueError, TypeError, AttributeError):
        raise HTTPException(422, 'observed_at must be a timezone-aware date, no more than five minutes in the future') from None
    errors = data.get('errors', [])
    if (not isinstance(errors, list) or len(errors) > 32
            or any(not isinstance(error, str) or not re.fullmatch(r'[a-z0-9_.:-]{1,100}', error) for error in errors)
            or (data['complete'] and errors)):
        raise HTTPException(422, 'Use short error codes; complete reports cannot include errors')
    workloads = data.get('workloads')
    if not isinstance(workloads, list) or len(workloads) > max_workloads:
        raise HTTPException(422, f'Report at most {max_workloads} container observations')
    cleaned, seen = [], set()
    for item in workloads:
        if not isinstance(item, dict) or set(item) - OBSERVATION_LIMITS.keys():
            raise HTTPException(422, 'Unknown observation fields; report only container metadata')
        observation = {key: text(item.get(key, ''), key, limit, required=key in {'uid', 'container', 'state'})
                       for key, limit in OBSERVATION_LIMITS.items()
                       if key in item or key not in OPTIONAL_FIELDS}
        if observation.get('container_kind', '') not in ('', 'regular', 'init', 'ephemeral'):
            raise HTTPException(422, 'Invalid container kind')
        if 'chart_digest' in item and not re.fullmatch(r'sha256:[a-f0-9]{64}', item['chart_digest']):
            raise HTTPException(422, 'Chart digest must be a lowercase SHA-256 digest')
        if observation['uid'] in seen:
            raise HTTPException(422, 'Container observation identities must be unique')
        if observation['state'] not in {'running', 'waiting', 'terminated', 'unknown', 'paused', 'restarting', 'exited', 'created', 'dead', 'removing', 'desired'}:
            raise HTTPException(422, 'Invalid container state')
        if observation['state'] == 'desired' and (data.get('discovery_version') != 1 or observation['image_id']
                or observation.get('pod') or observation.get('pod_uid') or not observation.get('workload_uid')
                or observation.get('container_kind') not in ('regular', 'init')):
            raise HTTPException(422, 'Desired template components require a controller and cannot claim a running image')
        seen.add(observation['uid'])
        cleaned.append(observation)
    return observed, errors, cleaned


@router.post('/reports', openapi_extra=report_body_schema(MAX_WORKLOADS))
async def report(request: Request, db: Session = Depends(get_db)):
    row, token_hash = authenticate(request, db)
    db.rollback()  # Release the admission connection while reading the network body.
    data = await body(request, {'sequence', 'observed_at', 'complete', 'errors', 'workloads', 'discovery_version'}, limit=MAX_BODY)
    try:
        return await run_in_threadpool(accept_report, db, row, token_hash, data, now())
    finally:
        db.rollback()  # Release the agent write lock on a rejected or replayed report.


def lock_reporting_agent(db, identity, token_hash):
    # SQLite ignores SELECT FOR UPDATE. A guarded no-op write serializes both transports
    # with each other and revocation before examining accepted sequences or pending pages.
    locked = db.execute(update(RuntimeAgent).where(RuntimeAgent.id == identity, RuntimeAgent.enabled.is_(True),
                        RuntimeAgent.token_hash == token_hash).values(last_sequence=RuntimeAgent.last_sequence)
                        .execution_options(synchronize_session=False))
    if locked.rowcount != 1:
        raise HTTPException(401, 'Agent credential is invalid or revoked')
    return db.get(RuntimeAgent, identity, populate_existing=True, options=[defer(RuntimeAgent.workloads)])


def accept_report(db, row, token_hash, data, timestamp, *, max_workloads=MAX_WORKLOADS):
    from .runtime_report_pages import clear_pages, ensure_pending_matches
    observed, errors, workloads = validate_report(data, timestamp, max_workloads=max_workloads)
    row = lock_reporting_agent(db, inspect(row).identity[0], token_hash)
    checksum = hashed(json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
    if data['sequence'] == row.last_sequence and checksum == row.report_hash:
        # Retry acknowledgements never refresh freshness or resurrect revoked credentials.
        return reply({'accepted': True, 'duplicate': True, 'sequence': row.last_sequence})
    if data['sequence'] <= row.last_sequence or (row.observed_at and observed < utc(row.observed_at)):
        raise HTTPException(409, 'Report is older than the accepted inventory or conflicts with an accepted sequence')
    ensure_pending_matches(db, row.id, data['sequence'], checksum, observed)
    values = dict(last_sequence=data['sequence'], report_hash=checksum, last_seen_at=timestamp,
                  observed_at=observed, complete=data['complete'], errors=errors)
    if data['complete']:
        values.update(workloads=workloads, inventory_observed_at=observed)
    changed = db.execute(update(RuntimeAgent).where(RuntimeAgent.id == row.id, RuntimeAgent.enabled.is_(True),
        RuntimeAgent.token_hash == token_hash, RuntimeAgent.last_sequence == row.last_sequence)
        .values(**values).execution_options(synchronize_session=False))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, 'Agent state changed; retry the report')
    if data['complete'] and data.get('discovery_version') == 1:
        env = environment(db, row.environment_id, lock=True)
        applications.reconcile_inventory(db, env, observed, workloads)
    clear_pages(db, row.id, through_sequence=data['sequence'])
    commit(db)
    return reply({'accepted': True, 'duplicate': False, 'sequence': data['sequence']})


from .runtime_application_routes import router as application_router
router.include_router(application_router)
