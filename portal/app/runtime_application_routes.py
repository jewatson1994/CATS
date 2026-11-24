"""Manager review of cluster observations and their server-authorized service mappings."""
from collections import defaultdict
from datetime import timedelta
import re
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, load_only

from .artifact_catalog import GlobalArtifact, ServiceArtifactAssignment
from .auth import AuthContext, record_audit, require_user
from .database import get_db
from .imported_services import imported_service_ids
from .models import Group, Service
from .operating_mode import is_replica, permission_available
from .runtime_applications import RuntimeApplication as Application, in_scope, prepare
from .runtime_models import RuntimeEnvironment as Environment, now
from .release_validity import utc
from .service_oci import _csrf
from .service_ownership import active_service_predicate, create_owned_service

router = APIRouter(prefix='/applications')
workspace_url = '/?runtime_applications=1#runtime-applications'
manager_permissions = ('runtime.prepare_release', 'service.edit', 'scan.ingest', 'approval.request')


def manages(auth, service_id):
    return all(auth.has(permission, service_id) for permission in manager_permissions)


def manages_group(auth, group_id, permissions=manager_permissions):
    if not all(permission_available(permission) for permission in permissions):
        return False
    assignments = [a for a in auth.effective_assignments
                   if a.service_id is None and a.group_id in (None, group_id)]
    return all(any(permission in (a.role.permissions or []) and
                   (permission != 'scan.ingest' or a.role.name != 'Administrator')
                   for a in assignments) for permission in permissions)


def reporting_targets(db, auth):
    ids = auth.accessible_service_ids('runtime.map_import')
    if ids == set():
        return set()
    return {sid for sid in imported_service_ids(db, ids) if auth.has('service.view', sid)}


def reviews_environment(auth, env, reporting_ids=()):
    if env.cluster_role == 'production' and any(in_scope(env, sid) for sid in reporting_ids):
        if manages_group(auth, env.discovery_group_id, ('runtime.map_import', 'service.view')):
            return True
        if not env.discovery_group_id and env.service_scope == 'selected' and set(env.service_ids) <= reporting_ids:
            return True
    if env.discovery_group_id or manages_group(auth, None):
        return manages_group(auth, env.discovery_group_id)
    return env.service_scope == 'selected' and bool(env.service_ids) and all(manages(auth, sid) for sid in env.service_ids)


def eligible(auth, env, service, reporting_ids):
    return (in_scope(env, service.id) and
            ((env.cluster_role == 'production' and service.id in reporting_ids)
             or (len(service.groups) == 1 and manages(auth, service.id))))


def can_assign_mapping(auth, env, app, reporting_ids):
    if not app.service_id:
        return reviews_environment(auth, env, reporting_ids)
    return manages(auth, app.service_id) or (env.cluster_role == 'production' and app.service_id in reporting_ids)


def suggestions(db, app, services, associations):
    evidence = defaultdict(list)
    def match(service, priority, reason):
        if (priority, reason) not in evidence[service.id]:
            evidence[service.id].append((priority, reason))

    def values(field):
        return {str(c[field]).casefold() for c in app.components if c.get(field)}

    hints, parts, labels, workloads = (values(field) for field in ('service_hint', 'app_part_of', 'app_name', 'workload'))
    releases = {(c.get('helm_namespace') or app.namespace, c['helm_release']) for c in app.components if c.get('helm_release')}
    digests = {c.get('image_id', '').split('@')[-1] for c in app.components}
    catalog = set(db.scalars(select(ServiceArtifactAssignment.service_id).join(GlobalArtifact)
                             .where(GlobalArtifact.digest.in_(digests), ServiceArtifactAssignment.service_id.in_([s.id for s in services]))))
    for service in services:
        names = {service.service_key.casefold(), service.name.casefold()}
        if (names | {str(service.id)}) & hints:
            match(service, 1, 'CATS service annotation')
        if service.id == app.service_id:
            match(service, 2, 'Manager-authorized workload mapping')
        if releases & associations.get(service.id, set()):
            match(service, 3, 'Previously assigned Helm release in this cluster and namespace')
        if service.service_key.casefold() in {release.casefold() for _, release in releases}:
            match(service, 3, 'Helm release name matches service key')
        if names & (parts | labels):
            match(service, 4, 'Kubernetes application label')
        if names & workloads:
            match(service, 5, 'Owning workload name')
        if service.id in catalog:
            match(service, 6, 'Existing artifact digest assignment')
    ordered = sorted(evidence, key=lambda sid: (min(evidence[sid])[0], sid))
    return [dict(service_id=sid, confidence='high' if min(evidence[sid])[0] <= 2 else
                 'medium' if min(evidence[sid])[0] <= 4 else 'low',
                 evidence=[reason for _, reason in sorted(evidence[sid])]) for sid in ordered]


def candidate_link(candidate, service, manager, reviewer):
    if manager and (not candidate['approval_id'] or (candidate['status'] == 'returned' and candidate['current'])):
        query = {'service': service.service_key, 'runtime_candidate_id': candidate['id']}
    elif candidate['approval_id'] and (manager or reviewer or candidate['status'] == 'approved'):
        query = {'id': candidate['approval_id']}
    else:
        return None
    return '/cyber-approvals?' + urlencode(query)


@router.get('')
def list_applications(offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                      db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    from .cyber_approvals import _runtime_manager, _runtime_reviewer
    from .runtime_candidates import list_candidates
    environments = {env.id: env for env in db.scalars(select(Environment).where(Environment.kind == 'kubernetes'))}
    reporting_ids = reporting_targets(db, auth)
    reviewed = {env.id for env in environments.values() if reviews_environment(auth, env, reporting_ids)}
    query = select(Application).order_by(Application.present.desc(), Application.id.desc())
    visible = auth.accessible_service_ids('service.view')
    assigned = Application.service_id.is_not(None) if visible is None else Application.service_id.in_(visible)
    query = query.where(assigned | (Application.service_id.is_(None) & Application.environment_id.in_(reviewed)))
    apps = list(db.scalars(query.offset(offset).limit(limit + 1)))
    choices = select(Service).order_by(Service.name, Service.id)
    if visible is not None:
        choices = choices.where(Service.id.in_(visible))
    services = {s.id: s for s in db.scalars(choices)}
    active = set(db.scalars(select(Service.id).where(Service.id.in_(services), active_service_predicate())))
    rows, candidates, associations = [], {}, defaultdict(lambda: defaultdict(set))
    histories = select(Application).where(Application.service_id.in_(list(services)), Application.environment_id.in_({app.environment_id for app in apps}))
    for prior in db.scalars(histories):
        associations[prior.environment_id][prior.service_id].update(
            (c.get('helm_namespace') or prior.namespace, c['helm_release']) for c in prior.components if c.get('helm_release'))
    for app in apps[:limit]:
        env = environments[app.environment_id]
        authority = can_assign_mapping(auth, env, app, reporting_ids) if app.service_id else env.id in reviewed
        stable = all(c.get('workload_uid') and c.get('namespace_uid') for c in app.components)
        can_assign = app.present and stable and authority
        service_choices = [s for s in services.values() if s.id in active and eligible(auth, env, s, reporting_ids)] if can_assign else []
        service = services.get(app.service_id)
        if service and service.id not in candidates:
            manager, reviewer = _runtime_manager(auth, service.id), _runtime_reviewer(auth, service.id)
            candidates[service.id] = [dict(c, service=service.name, environment=environments[c['environment_id']].name,
                href=candidate_link(c, service, manager, reviewer))
                for c in list_candidates(db, service_id=service.id)]
        rows.append(dict(id=app.id, name=app.name, environment_id=env.id, environment=env.name,
            namespace=app.namespace, cluster_role=env.cluster_role, present=app.present, fingerprint=app.fingerprint,
            service_id=app.service_id, service=service.name if service else None, assignment_status='assigned' if service else 'unassigned',
            discovered_at=utc(app.discovered_at).isoformat(), last_observed_at=utc(app.last_observed_at).isoformat(),
            components=app.components, can_assign=can_assign,
            assignment_blocker='The collector must report namespace and workload UIDs before assignment.' if not stable else None,
            can_create=can_assign and env.service_scope == 'all' and
            bool(env.discovery_group_id) and manages_group(auth, env.discovery_group_id),
            services=[{'id': s.id, 'name': s.name} for s in service_choices],
            suggestions=suggestions(db, app, service_choices, associations[env.id]) if service_choices else []))
    return {'applications': rows, 'candidates': [c for batch in candidates.values() for c in batch],
            'next_offset': offset + limit if len(apps) > limit else None}


class Assignment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_fingerprint: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
    expected_service_id: int | None
    service_id: Annotated[int, Field(gt=0)] | None = None
    new_service_key: Annotated[str, Field(max_length=120)] | None = None


@router.post('/{identity}/assignment')
def assign(identity: int, data: Assignment, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    _csrf(request, auth)
    if (data.service_id is None) == (data.new_service_key is None):
        raise HTTPException(422, 'Choose an existing service or provide a new service key')
    env_id = db.scalar(select(Application.environment_id).where(Application.id == identity))
    if env_id is None:
        raise HTTPException(404, 'Application not found')
    services = {s.id: s for s in db.scalars(select(Service).where(
        Service.id.in_([i for i in (data.service_id, data.expected_service_id) if i])).order_by(Service.id).with_for_update())}
    # Serializes assignment with full-report reconciliation on SQLite and PostgreSQL.
    db.execute(update(Environment).where(Environment.id == env_id).values(name=Environment.name))
    env, app = db.get(Environment, env_id), db.get(Application, identity, populate_existing=True)
    reporting_ids = reporting_targets(db, auth)
    if is_replica() and (data.service_id not in reporting_ids or env.cluster_role != 'production'):
        raise HTTPException(403, 'A replica may only map production observations to an existing publisher-managed service')
    if not can_assign_mapping(auth, env, app, reporting_ids):
        raise HTTPException(403, 'Application assignment requires manager access to this discovery scope')
    if not app.present or app.fingerprint != data.expected_fingerprint or app.service_id != data.expected_service_id:
        raise HTTPException(409, 'Inventory or assignment changed. Refresh and review the current components.')
    if not all(c.get('workload_uid') and c.get('namespace_uid') for c in app.components):
        raise HTTPException(409, 'The collector must report namespace and workload UIDs before assignment.')
    if data.new_service_key is not None:
        if env.service_scope != 'all' or not env.discovery_group_id or not manages_group(auth, env.discovery_group_id):
            raise HTTPException(403, 'Creating a service requires an all-services environment and authority in its discovery group')
        key = data.new_service_key.strip().lower()
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,119}', key):
            raise HTTPException(422, 'Use letters, numbers, dots, underscores or hyphens for the service key')
        if db.scalar(select(Service.id).where(func.lower(Service.service_key) == key)):
            raise HTTPException(409, 'This service key already exists. Select its service to assign it.')
        try:
            service = create_owned_service(db, key, app.name, db.get(Group, env.discovery_group_id))
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'Service creation conflicted with another catalog change. Refresh the service list.') from None
        record_audit(db, auth, 'service.created', 'service', service.id, runtime_application_id=app.id, group_id=env.discovery_group_id)
    else:
        service = services.get(data.service_id)
        if (not service or not eligible(auth, env, service, reporting_ids) or
                not db.scalar(select(Service.id).where(Service.id == service.id, active_service_predicate()))):
            raise HTTPException(403, 'Select an active, in-scope service with an owning group and manager access')
    old = app.service_id
    if old != service.id:
        app.service_id, app.assigned_at = service.id, now()
        # Bind exactly the controllers currently displayed, including their immutable UIDs.
        app.members = sorted({c['member'] for c in app.components})
        record_audit(db, auth, 'runtime.application.assigned', 'runtime_application', app.id,
                     service_id=service.id, previous_service_id=old, fingerprint=app.fingerprint)
        prepare(db, env, {(sid, app.namespace) for sid in (old, service.id) if sid})
    db.commit()
    return {'id': app.id, 'service_id': service.id, 'service_key': service.service_key}


def discovery_notifications(db, auth, limit=8):
    from .runtime_candidates import RuntimeReleaseCandidate as Candidate
    result = []
    reporting_ids = reporting_targets(db, auth)
    for env, count in db.execute(select(Environment, func.count(Application.id)).join(Application)
            .where(Application.present.is_(True), Application.service_id.is_(None)).group_by(Environment.id).order_by(Environment.name)):
        if reviews_environment(auth, env, reporting_ids):
            result.append(dict(label='Unassigned applications', service=env.name, count=count, href=workspace_url))
    visible = auth.accessible_service_ids('runtime.prepare_release')
    query = select(Candidate, Service).join(Service, Candidate.service_id == Service.id).where(
        Candidate.current.is_(True), Candidate.status == 'draft').options(
        load_only(Candidate.id, Candidate.assessment_status), load_only(Service.id, Service.name, Service.service_key)
    ).order_by(Candidate.id.desc())
    if visible is not None:
        query = query.where(Service.id.in_(visible))
    for candidate, service in db.execute(query):
        if not manages(auth, service.id):
            continue
        label = {'ready': 'Assessment complete · release ready for review', 'blocked': 'Release assessment needs attention'}.get(
            candidate.assessment_status, 'Application assigned · assessment pending')
        result.append(dict(label=label, service=service.name, href='/cyber-approvals?' + urlencode(
            {'service': service.service_key, 'runtime_candidate_id': candidate.id})))
        if len(result) >= limit:
            break
    if len(result) < limit:
        recent = select(Application, Service).join(Service, Application.service_id == Service.id).join(
            Environment, Application.environment_id == Environment.id).where(Application.present.is_(True),
            Application.assigned_at >= now() - timedelta(days=7), Environment.cluster_role.in_(['production', 'unspecified'])
        ).options(load_only(Application.id), load_only(Service.id, Service.name)).order_by(Application.assigned_at.desc())
        if visible is not None:
            recent = recent.where(Service.id.in_(visible | reporting_ids))
        for app, service in db.execute(recent):
            if manages(auth, service.id) or service.id in reporting_ids:
                result.append(dict(label='Application assigned', service=service.name, href=workspace_url))
                if len(result) >= limit:
                    break
    return result[:limit]
