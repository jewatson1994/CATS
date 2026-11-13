"""Signed OCI source administration and immutable imported evidence browsing."""
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select

from .auth import AuthContext, require_user, record_audit
from .database import get_db
from .models import Service
from .oci_models import OCIUpstream, OCIRepository, is_project_pattern
from .oci_transport import REPOSITORY
from .operating_mode import mode
from .replica_models import ReplicaSource, ReplicaRelease, ReplicaServiceState
from .replica_integrity import verify_record, digest
from .replica_sync import enqueue, KIND, FAILURE_MESSAGES
from .durable_jobs import DurableJob
from .release_validity import utc
from .service_oci import _csrf

router = APIRouter(prefix='/api/replica', tags=['Replica'])
SOURCE_FIELDS = ('id','name','upstream_id','repository','trusted_publishers','poll_seconds','enabled',
                 'last_attempt_at','last_success_at','last_error')


def require(auth, permission, service_id=None):
    if not auth.has(permission, service_id):
        raise HTTPException(403, 'Permission required for this scope')


def fields(row, names):
    return {name: getattr(row, name) for name in names}


async def data(request, auth):
    _csrf(request, auth)
    content = bytearray()
    async for part in request.stream():
        content.extend(part)
        if len(content) > 65536:
            raise HTTPException(413, 'Configuration is too large')
    try:
        import json
        result = json.loads(content)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, UnicodeError):
        raise HTTPException(422, 'Expected a JSON object') from None


def configure(db, auth, payload, source=None):
    if source is not None:
        # Serialize configuration against a first import binding this source.
        # Refresh an already-loaded row after waiting for the import to commit.
        source = db.scalar(select(ReplicaSource).where(ReplicaSource.id == source.id)
                           .with_for_update().execution_options(populate_existing=True))
        if source is None:
            raise HTTPException(404, 'Source not found')
    allowed = {'name','upstream_id','repository','trusted_publishers','poll_seconds','enabled'}
    if set(payload) - allowed:
        raise HTTPException(422, 'Unknown replica source field')
    value = {**(fields(source, allowed) if source else {'poll_seconds': 300, 'enabled': True}), **payload}
    if (not isinstance(value.get('name'), str) or not 1 <= len(value['name'].strip()) <= 160
            or type(value.get('upstream_id')) is not int
            or type(value.get('enabled')) is not bool
            or type(value.get('poll_seconds')) is not int or not 10 <= value['poll_seconds'] <= 86400):
        raise HTTPException(422, 'Provide a name, local registry and polling interval from 10 to 86400 seconds')
    repository = value.get('repository')
    if (not isinstance(repository, str) or len(repository) > 255 or
            not (is_project_pattern(repository) or (REPOSITORY.fullmatch(repository) and repository.endswith('/releases')))):
        raise HTTPException(422, 'Use an exact releases repository or a project/* discovery scope')
    pins = value.get('trusted_publishers')
    if not isinstance(pins, list) or not pins or any(not isinstance(pin, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', pin) for pin in pins):
        raise HTTPException(422, 'Independently trusted publisher SHA-256 public-key fingerprints are required')
    if db.get(OCIUpstream, value['upstream_id']) is None:
        raise HTTPException(422, 'Configure the local registry connection first')
    if source and (value['upstream_id'], repository) != (source.upstream_id, source.repository) and db.scalar(
            select(ReplicaServiceState.service_id).where(ReplicaServiceState.source_id == source.id).limit(1)) is not None:
        raise HTTPException(409, 'An imported source cannot be rebound to a different registry or repository')
    collision = db.scalar(select(ReplicaSource.id).where(ReplicaSource.name == value['name'].strip()))
    if collision and (source is None or collision != source.id):
        raise HTTPException(409, 'Replica source name is already in use')
    if source is None:
        source = ReplicaSource(created_by_id=auth.user.id)
        db.add(source)
    for key, item in value.items():
        setattr(source, key, item.strip() if key == 'name' else sorted(set(item)) if key == 'trusted_publishers' else item)
    db.flush()
    record_audit(db, auth, 'replica.source.configured', 'replica_source', source.id,
                 configuration=fields(source, allowed))
    db.commit()
    return fields(source, SOURCE_FIELDS)


@router.get('/sources')
def sources(auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    require(auth, 'replica.admin')
    return {'sources': [fields(row, SOURCE_FIELDS) for row in db.scalars(select(ReplicaSource).order_by(ReplicaSource.id))]}


@router.get('/registries')
def registries(auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    """Source administrators can select a registry without credential authority."""
    require(auth, 'replica.admin')
    return [fields(row, ('id', 'name', 'endpoint', 'enabled'))
        for row in db.scalars(select(OCIUpstream).order_by(OCIUpstream.id))]


@router.post('/sources')
async def create_source(request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    require(auth, 'replica.admin')
    return configure(db, auth, await data(request, auth))


@router.put('/sources/{identity}')
async def update_source(identity: int, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    require(auth, 'replica.admin')
    source = db.get(ReplicaSource, identity)
    if source is None:
        raise HTTPException(404, 'Source not found')
    return configure(db, auth, await data(request, auth), source)


@router.post('/sync')
async def synchronize(request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    require(auth, 'replica.sync')
    payload = await data(request, auth)
    if set(payload) - {'source_id'} or (payload.get('source_id') is not None and type(payload['source_id']) is not int):
        raise HTTPException(422, 'Choose a replica source')
    query = select(ReplicaSource).where(ReplicaSource.enabled.is_(True))
    if payload.get('source_id') is not None:
        query = query.where(ReplicaSource.id == payload['source_id'])
    selected = list(db.scalars(query))
    if not selected:
        raise HTTPException(404, 'Enabled source not found')
    jobs = [enqueue(db, source, auth.user.id) for source in selected]
    record_audit(db, auth, 'replica.sync.requested', 'replica_source', payload.get('source_id'), jobs=[job.id for job in jobs])
    db.commit()
    return {'jobs': [fields(job, ('id','status','stage','progress')) for job in jobs]}


def release_row(db, release):
    from .replica_authorization import trusted_release
    from .oci_models import service_repository
    service = db.get(Service, release.service_id)
    state = db.get(ReplicaServiceState, release.service_id, populate_existing=True)
    timestamp = datetime.now(timezone.utc)
    trusted = trusted_release(db, release, state, timestamp)
    status = ('untrusted' if not trusted else 'revoked' if release.revoked_at else
              'expired' if release.expires_at and utc(release.expires_at) <= timestamp else
              'active' if state and state.active_release_id == release.id else 'superseded')
    routes = list(db.scalars(select(OCIRepository).where(OCIRepository.service_id == release.service_id)))
    pull_routes = []
    for route in routes:
        try:
            pull_routes.append((route, service_repository(route.public_repository, route.service_id)))
        except ValueError:
            # Invalid legacy configuration must not advertise a usable pull path.
            continue
    result = fields(release, ('id','service_id','source_release_id','sequence','manifest_digest','approved_at',
        'expires_at','revoked_at','revocation_reason','imported_at','publisher','key_fingerprint','source_reference'))
    result.update(service_key=service.service_key, service_name=service.name, status=status,
        key_generation=len(release.manifest.get('signing_key_chain', [])),
        artifacts=[{**artifact, 'proxy_repositories': [repository for route, repository in pull_routes
            if route.upstream_repository == artifact.get('repository')]} for artifact in release.artifacts],
        evidence_url=f'/api/replica/releases/{release.id}/evidence',
        context_url=f'/api/replica/releases/{release.id}/context')
    return result


@router.get('/releases')
def releases(service_id: int | None = None, service_key: str | None = None,
             auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    query = select(ReplicaRelease).join(Service, Service.id == ReplicaRelease.service_id)
    if service_id is not None:
        query = query.where(ReplicaRelease.service_id == service_id)
    if service_key is not None:
        query = query.where(Service.service_key == service_key)
    accessible = auth.accessible_service_ids('service.view')
    if accessible is not None:
        query = query.where(ReplicaRelease.service_id.in_(accessible))
    return {'releases': [release_row(db, release) for release in db.scalars(query.order_by(ReplicaRelease.id.desc()))]}


def evidence_release(db, auth, identity):
    release = db.get(ReplicaRelease, identity)
    if release is None or not auth.has('service.view', release.service_id):
        raise HTTPException(404, 'Release not found')
    require(auth, 'evidence.view', release.service_id)
    if not verify_record(release) or digest(release.evidence_state) != release.evidence_state_digest:
        raise HTTPException(409, 'Retained release integrity check failed')
    return release


@router.get('/releases/{identity}/context')
def context(identity: int, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    release = evidence_release(db, auth, identity)
    return {'release': release_row(db, release), 'original_evidence': release.evidence_state,
            'manifest': release.manifest, 'read_only': True}


@router.get('/releases/{identity}/evidence')
def evidence(identity: int, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    release = evidence_release(db, auth, identity)
    path = Path(release.evidence_path)
    expected = release.manifest.get('evidence', {}).get('digest')
    if not path.is_file() or path.is_symlink() or 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise HTTPException(409, 'Retained evidence archive is unavailable or corrupt')
    record_audit(db, auth, 'replica.evidence.downloaded', 'replica_release', release.id)
    db.commit()
    return FileResponse(path, media_type='application/zip', filename=f'{release.source_release_id}-approved-evidence.zip',
                        headers={'Cache-Control': 'private, no-store'})


def sync_job_view(job):
    result = fields(job, ('id','status','stage','progress','result','error','created_at','completed_at'))
    # Never display external exception text. Handler-authored classifications
    # make replica failures actionable without changing shared retry behavior.
    code = (job.result or {}).get('failure_code')
    message = FAILURE_MESSAGES.get(code) if isinstance(code, str) else None
    if message and job.error and job.status in {'queued', 'failed'}:
        result['error'] = f'{message} Reference: {job.correlation_id}'
    return result


@router.get('/status')
def status(auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    if not (auth.has('replica.admin') or auth.has('replica.sync')):
        raise HTTPException(403, 'Replica administration permission required')
    return {'mode': mode(), 'sources': [fields(row, SOURCE_FIELDS) for row in db.scalars(select(ReplicaSource))],
        'services': [dict(service_id=state.service_id, service_key=service.service_key, service_name=service.name,
            active_release_id=state.active_release_id, high_sequence=state.high_sequence, last_sync_at=state.last_sync_at)
            for state, service in db.execute(select(ReplicaServiceState, Service).join(Service, ReplicaServiceState.service_id == Service.id))],
        'jobs': [sync_job_view(job)
            for job in db.scalars(select(DurableJob).where(DurableJob.kind == KIND).order_by(DurableJob.created_at.desc()).limit(50))]}
