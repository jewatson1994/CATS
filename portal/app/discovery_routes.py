"""Group-scoped Discovery: source review and confirmation precede scan admission."""
import hashlib
import errno
from functools import wraps
import hmac
import json
import os
from pathlib import Path
import re
import uuid
from starlette.datastructures import UploadFile
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from .auth import AuthContext, require_user, record_audit
from .database import get_db
from .models import Service, Group, ServiceGroup
from .durable_jobs import DurableJob, submit
from .discovery_models import DiscoveryInventory, DiscoveryConfirmation, DiscoveryScan
from .discovery_worker import upload_root
from .discovery_sources import encrypted_writer, storage_key, SourceStorageError

router = APIRouter(prefix='/api/discovery', tags=['Discovery'])


def upload_resource_diagnostics(endpoint):
    """Report exhausted upload storage/memory without exposing local paths."""
    @wraps(endpoint)
    async def wrapped(*args, **kwargs):
        try:
            return await endpoint(*args, **kwargs)
        except MemoryError:
            raise HTTPException(503, 'Discovery upload exhausted available memory; increase upload service memory and retry.') from None
        except OSError as exc:
            if exc.errno in (errno.ENOSPC, getattr(errno, 'EDQUOT', -1)):
                raise HTTPException(507, 'Discovery upload storage is full or its quota is exhausted; free storage and retry.') from None
            if exc.errno == errno.ENOMEM:
                raise HTTPException(503, 'Discovery upload exhausted available memory; increase upload service memory and retry.') from None
            raise
    return wrapped

def permitted_group(auth, group_id):
    return any(a.service_id is None and a.group_id in (None, group_id) and
        ('service.edit' in (a.role.permissions or []) or 'config.manage' in (a.role.permissions or []))
        for a in auth.effective_assignments)

def group_scope(db, auth, group_id):
    if not isinstance(group_id, int) or not permitted_group(auth, group_id) or not db.get(Group, group_id):
        raise HTTPException(403, 'Deployment management permission required for this owning group')

def get_job(db, auth, job_id, lock=False):
    query = select(DurableJob).where(DurableJob.id == job_id, DurableJob.kind == 'discovery')
    if lock: query = query.with_for_update()
    job = db.scalar(query)
    if not job or not permitted_group(auth, job.payload.get('group_id')):
        raise HTTPException(404, 'Discovery not found')
    return job

def job_view(job):
    return {key: getattr(job, key) for key in ('id', 'status', 'stage', 'progress', 'result', 'error', 'created_at', 'completed_at') } | {'group_id': job.payload['group_id']}

def csrf(auth, supplied):
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, auth.csrf_token):
        raise HTTPException(403, 'Invalid CSRF token')

async def body(request, auth):
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > 65536: raise HTTPException(413, 'Request too large')
    try:
        data = json.loads(raw)
        if not isinstance(data, dict): raise ValueError()
    except (ValueError, UnicodeError): raise HTTPException(422, 'Expected JSON object') from None
    csrf(auth, data.get('csrf_token', request.headers.get('X-CSRF-Token', '')))
    return data

def options(value):
    if not isinstance(value, dict) or len(json.dumps(value)) > 32768:
        raise HTTPException(422, 'Invalid discovery configuration')
    allowed = {'environment', 'values_files', 'profiles', 'compose_files', 'chart_map', 'source_map', 'reference_kind', 'reference_version', 'component_values'}
    if set(value) - allowed: raise HTTPException(422, 'Unsupported discovery option')
    for key in ('values_files', 'profiles', 'compose_files'):
        if key in value and (not isinstance(value[key], list) or len(value[key]) > 100 or any(not isinstance(v, str) or len(v)>512 for v in value[key])):
            raise HTTPException(422, 'Invalid configuration selection')
    if 'component_values' in value and (not isinstance(value['component_values'], dict) or any(not isinstance(k, str) or len(k) > 128 or not isinstance(v, list) or any(not isinstance(item, str) or len(item) > 512 for item in v) for k, v in value['component_values'].items())):
        raise HTTPException(422, 'Invalid component values selection')
    if 'environment' in value and (not isinstance(value['environment'], str) or len(value['environment']) > 128):
        raise HTTPException(422, 'Invalid environment selection')
    if 'source_map' in value and (not isinstance(value['source_map'], dict) or len(value['source_map']) > 100 or any(not isinstance(k, str) or not isinstance(v, str) or len(k) > 512 or len(v) > 512 for k,v in value['source_map'].items())):
        raise HTTPException(422, 'Invalid local source mapping')
    if 'chart_map' in value and (not isinstance(value['chart_map'], dict) or len(value['chart_map']) > 100 or any(not isinstance(k, str) or not isinstance(v, str) or len(k) > 512 or len(v) > 512 for k,v in value['chart_map'].items())):
        raise HTTPException(422, 'Invalid local chart mapping')
    if 'reference_version' in value and (not isinstance(value['reference_version'], str) or not value['reference_version'] or len(value['reference_version']) > 512):
        raise HTTPException(422, 'Provide an exact artifact version')
    if 'reference_kind' in value and value['reference_kind'] not in ('image', 'chart', 'helm'):
        raise HTTPException(422, 'Invalid artifact kind')
    # Only local non-secret files can be selected; credentials are never accepted here.
    return value

def can_stage(db, auth, group_id):
    # Match Accounts' existing staging authority; discovery permission alone is insufficient.
    from .access_requests import can_manage_accounts, authorized_claim_groups
    if not can_manage_accounts(auth) and not auth.has('role.manage'):
        return False
    allowed = auth.has('user.manage') or group_id in {g.id for g in authorized_claim_groups(db, auth)}
    scan = any(a.service_id is None and a.group_id in (None, group_id)
        and a.role.name != 'Administrator' and 'scan.ingest' in (a.role.permissions or [])
        for a in auth.effective_assignments)
    return allowed and scan

@router.get('')
def listing(auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    groups = [g for g in db.scalars(select(Group).order_by(Group.name)) if permitted_group(auth, g.id)]
    ids = {g.id for g in groups}
    jobs = db.scalars(select(DurableJob).where(DurableJob.kind == 'discovery', DurableJob.payload['group_id'].as_integer().in_(ids)).order_by(DurableJob.created_at.desc()).limit(100))
    services = [{'id': s.id, 'service_key': s.service_key, 'name': s.name, 'group_id': g} for s,g in db.execute(select(Service, ServiceGroup.group_id).join(ServiceGroup)) if g in ids and auth.has('scan.ingest', s.id)]
    return {'jobs': [job_view(j) for j in jobs if j.payload.get('group_id') in ids][:100], 'groups': [{'id':g.id,'name':g.name,'can_stage':can_stage(db,auth,g.id)} for g in groups], 'services': services}

@router.post('')
@upload_resource_diagnostics
async def create(request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    # Enforce an optional operator budget while multipart files spool to disk.
    from .discovery_limits import limit as discovery_limit
    maximum = discovery_limit('UPLOAD_BYTES')
    limit = maximum + 131072
    receive, received = request._receive, 0
    async def bounded_receive():
        nonlocal received
        message = await receive()
        received += len(message.get('body', b''))
        if maximum and received > limit: raise HTTPException(413, 'Discovery upload exceeds size limit')
        return message
    request._receive = bounded_receive
    form = await request.form(max_files=1, max_fields=8, max_part_size=65536)
    try:
        csrf(auth, form.get('csrf_token', request.headers.get('X-CSRF-Token', '')))
        try: group_id = int(form.get('group_id', ''))
        except (ValueError, TypeError): raise HTTPException(422, 'Choose an owning group') from None
        group_scope(db, auth, group_id)
        try: selected = options(json.loads(str(form.get('options', '{}'))))
        except (ValueError, TypeError): raise HTTPException(422, 'Invalid discovery options') from None
        upload, reference = form.get('upload'), str(form.get('reference', '')).strip()
        if bool(upload) == bool(reference): raise HTTPException(422, 'Provide one upload or one artifact reference')
        if upload and not isinstance(upload, UploadFile):
            raise HTTPException(422, 'Upload must be a file')
        try:
            storage_key()
        except SourceStorageError:
            raise HTTPException(503, 'Discovery source encryption is not configured') from None
        source_id = uuid.uuid4().hex
        folder = upload_root() / source_id
        folder.mkdir(parents=True, mode=0o750)
        if os.name == 'posix':
            os.chown(folder, -1, int(os.getenv('CATS_DISCOVERY_GID', '10003')))
        filename = 'images.txt'
        if upload:
            filename = Path(str(upload.filename or 'source.zip').replace('\\','/')).name
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,180}', filename): filename = 'source.zip'
        target = folder / filename
        digest, size = hashlib.sha256(), 0
        try:
            with encrypted_writer(target, source_id) as stream:
                if reference:
                    if len(reference)>1024 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]*', reference) or '@' in reference.split('/')[0]:
                        raise HTTPException(422, 'Provide an image reference without credentials')
                    data = (reference+'\n').encode()
                    if reference.startswith('oci://'):
                        filename = 'chart-reference.txt'
                        selected = {**selected, 'reference_kind': 'helm'}
                    stream.write(data); digest.update(data)
                else:
                    while chunk := await upload.read(1024*1024):
                        size += len(chunk)
                        if maximum and size > maximum:
                            raise HTTPException(413, 'Discovery upload exceeds size limit')
                        stream.write(chunk); digest.update(chunk)
            if os.name == 'posix':
                os.chown(target, -1, int(os.getenv('CATS_DISCOVERY_GID', '10003')))
                target.chmod(0o640)
            if target.name != filename:
                target.rename(folder / filename)
                target = folder / filename
            job = submit(db, kind='discovery', payload={'source_id': source_id, 'filename': filename, 'source_hash': digest.hexdigest(), 'group_id': group_id, 'options': selected}, requested_by_id=auth.user.id, commit=False)
            record_audit(db, auth, 'discovery.submitted', 'discovery', job.id, group_id=group_id)
            db.commit()
            return {'job_id': job.id}
        except BaseException:
            target.unlink(missing_ok=True)
            folder.rmdir()
            raise
        finally:
            if upload: await upload.close()
    finally:
        await form.close()

@router.get('/{job_id}')
def detail(job_id: str, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    job = get_job(db, auth, job_id)
    item = db.scalar(select(DiscoveryInventory).where(DiscoveryInventory.job_id == job.id))
    return {'job':job_view(job), 'inventory':item.inventory if item else None}

@router.post('/{job_id}/cancel')
async def cancel(job_id: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    await body(request, auth)
    job = get_job(db, auth, job_id, True)
    if job.status in ('queued', 'running'):
        job.cancel_requested = True
        if job.status == 'queued': job.status, job.stage = 'cancelled', 'Cancelled'
    db.commit()
    return {'job_id': job.id}

@router.post('/{job_id}/retry')
async def retry(job_id: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    data = await body(request, auth)
    old = get_job(db, auth, job_id, True)
    if old.result.get('source_expired') or not (upload_root() / old.payload['source_id'] / old.payload['filename']).is_file():
        raise HTTPException(410, 'Discovery source expired; upload it again')
    if old.status in ('queued','running'): raise HTTPException(409, 'Discovery is still running')
    payload = {**old.payload, 'previous_job_id': old.id}
    if 'options' in data: payload['options'] = options(data['options'])
    job = submit(db, kind='discovery', payload=payload, requested_by_id=auth.user.id)
    return {'job_id':job.id}

@router.post('/{job_id}/supplements')
@upload_resource_diagnostics
async def supplement(job_id: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    from .discovery_limits import limit as discovery_limit
    from .compose_ingestion import _relative, ComposeInputError
    old = get_job(db, auth, job_id, True)
    parent = db.scalar(select(DiscoveryInventory).where(DiscoveryInventory.job_id == old.id))
    if old.status != 'completed' or parent is None:
        raise HTTPException(409, 'Discovery must finish before supplying dependencies')
    chain = old.payload.get('supplements', [])
    if not (upload_root() / old.payload['source_id'] / old.payload['filename']).is_file():
        raise HTTPException(410, 'Discovery source expired; upload it again')
    maximum = discovery_limit('UPLOAD_BYTES')
    receive, received = request._receive, 0
    async def bounded_receive():
        nonlocal received
        message = await receive()
        received += len(message.get('body', b''))
        if maximum and received > maximum + 131072:
            raise HTTPException(413, 'Discovery upload exceeds size limit')
        return message
    request._receive = bounded_receive
    form = await request.form(max_files=1, max_fields=5, max_part_size=65536)
    try:
        csrf(auth, form.get('csrf_token', request.headers.get('X-CSRF-Token', '')))
        if form.get('acknowledge_non_secret') != 'true':
            raise HTTPException(422, 'Confirm that supplemental files contain no secrets or credentials')
        try:
            target_path = _relative(str(form.get('target_path', '.')))
            selected = options(json.loads(str(form.get('options', json.dumps(old.payload.get('options', {}))))))
        except (ValueError, TypeError, ComposeInputError):
            raise HTTPException(422, 'Invalid supplemental path or options') from None
        upload = form.get('upload')
        if not isinstance(upload, UploadFile):
            raise HTTPException(422, 'Supply one dependency file or archive')
        filename = str(upload.filename or '')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,180}', filename) or filename in ('.', '..'):
            raise HTTPException(422, 'Supply a simple filename without directories')
        try:
            storage_key()
        except SourceStorageError:
            raise HTTPException(503, 'Discovery source encryption is not configured') from None
        identity = uuid.uuid4().hex
        folder = upload_root() / identity
        folder.mkdir(parents=True, mode=0o750)
        target = folder / filename
        try:
            digest, size = hashlib.sha256(), 0
            with encrypted_writer(target, identity) as stream:
                while chunk := await upload.read(1024*1024):
                    size += len(chunk)
                    if maximum and size > maximum:
                        raise HTTPException(413, 'Discovery upload exceeds size limit')
                    stream.write(chunk)
                    digest.update(chunk)
            if not size:
                raise HTTPException(422, 'Supplemental upload is empty')
            if os.name == 'posix':
                gid = int(os.getenv('CATS_DISCOVERY_GID', '10003'))
                os.chown(folder, -1, gid)
                os.chown(target, -1, gid)
                target.chmod(0o640)
            record = dict(source_id=identity, filename=filename, source_hash=digest.hexdigest(), target_path=target_path,
                          parent_job_id=old.id, parent_inventory_id=parent.id, parent_content_hash=parent.content_hash)
            payload = {**old.payload, 'options': selected, 'previous_job_id': old.id, 'supplements': [*chain, record]}
            job = submit(db, kind='discovery', payload=payload, requested_by_id=auth.user.id, commit=False)
            record_audit(db, auth, 'discovery.supplement.submitted', 'discovery', job.id, parent_job_id=old.id, parent_inventory_id=parent.id, source_hash=digest.hexdigest())
            db.commit()
            return {'job_id': job.id}
        except BaseException:
            target.unlink(missing_ok=True)
            folder.rmdir()
            raise
    finally:
        await form.close()

@router.post('/{job_id}/confirm')
async def confirm(job_id: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    data = await body(request, auth)
    job = get_job(db, auth, job_id, True)
    item = db.scalar(select(DiscoveryInventory).where(DiscoveryInventory.job_id == job.id))
    if not item or job.status != 'completed': raise HTTPException(409, 'Discovery must finish before confirmation')
    service = db.get(Service, data.get('service_id')) if isinstance(data.get('service_id'), int) else None
    owner = db.scalar(select(ServiceGroup.group_id).where(ServiceGroup.service_id == service.id)) if service else None
    new_key = data.get('new_service_key')
    if new_key is not None:
        if data.get('service_id') is not None or not isinstance(new_key, str) or not new_key.strip() or len(new_key.strip()) > 120:
            raise HTTPException(422, 'Provide one new service key or select an existing service')
        new_key = new_key.strip()
        if not can_stage(db, auth, item.group_id):
            raise HTTPException(403, 'Service staging and scan permission required in this owning group')
        if db.scalar(select(Service.id).where(Service.service_key == new_key)):
            raise HTTPException(409, 'Service key already exists')
    elif not service or owner != item.group_id or not auth.has('scan.ingest', service.id):
        raise HTTPException(403, 'Choose a service in this owning group with scan permission')
    roots = data.get('root_ids')
    known = {r['id'] for r in item.inventory.get('roots', [])}
    if not isinstance(roots,list) or not roots or any(not isinstance(r,str) for r in roots) or not set(roots)<=known:
        raise HTTPException(422, 'Select the deployment roots that belong to this service')
    completeness = str(item.inventory.get('completeness', 'blocked')).lower()
    if completeness in ('blocked','invalid'): raise HTTPException(409, 'Blocked or invalid inventories cannot be confirmed')
    partial = completeness != 'complete'
    if partial and data.get('acknowledge_partial') is not True: raise HTTPException(422, 'Explicitly acknowledge the incomplete inventory')
    if new_key is not None:
        service = Service(service_key=new_key, name=f'Staged — {new_key}', lifecycle_status='staged',
            staging_original_name=new_key, staging_name_generated=True)
        service.groups.append(db.get(Group, item.group_id))
        db.add(service)
        db.flush()
        record_audit(db, auth, 'service.staged', 'service', service.id, discovery_inventory_id=item.id)
    confirmation = DiscoveryConfirmation(id=uuid.uuid4().hex, inventory_id=item.id, service_id=service.id,
        confirmed_by=auth.user.id, root_ids=sorted(set(roots)), acknowledge_partial=partial)
    db.add(confirmation)
    job.result = {**job.result, 'confirmed_inventory_id': confirmation.id}
    record_audit(db, auth, 'discovery.confirmed', 'service', service.id, inventory_id=item.id, confirmation_id=confirmation.id, partial=partial)
    db.commit()
    return {'inventory_id': confirmation.id, 'confirmed_inventory_id': confirmation.id}

@router.post('/{job_id}/scan')
async def scan(job_id: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    from . import main
    data = await body(request, auth)
    job = get_job(db, auth, job_id, True)
    confirmation_id = data.get('confirmation_id') or job.result.get('confirmed_inventory_id')
    confirmation = db.get(DiscoveryConfirmation, confirmation_id) if confirmation_id else None
    item = db.get(DiscoveryInventory, confirmation.inventory_id) if confirmation else None
    if not item or item.job_id != job.id: raise HTTPException(409, 'Confirm the inventory before scanning')
    service = db.get(Service, confirmation.service_id)
    owner = db.scalar(select(ServiceGroup.group_id).where(ServiceGroup.service_id == service.id)) if service else None
    if not service or owner != item.group_id or not auth.has('scan.ingest', service.id): raise HTTPException(403, 'Scan permission required in the owning group')
    existing = db.get(DiscoveryScan, confirmation.id)
    if existing: return {'job_id':existing.scan_job_id, 'url':'/scan?job_id='+existing.scan_job_id}
    # Admission persists in its own transaction. Recover the association if the
    # portal stopped after admission but before this transaction committed.
    from .scan_coordination import ScanJob
    admitted = db.scalar(select(ScanJob).where(
        ScanJob.payload['definition_context']['discovery_confirmation_id'].as_string() == confirmation.id,
        ScanJob.service_key == service.service_key).order_by(ScanJob.created_at).limit(1))
    if admitted:
        db.add(DiscoveryScan(confirmation_id=confirmation.id, scan_job_id=admitted.id))
        db.commit()
        return {'job_id': admitted.id, 'url': '/scan?job_id=' + admitted.id}
    images = sorted({i['reference'] for i in item.inventory.get('images',[]) if i.get('root_id') in confirmation.root_ids})
    if not images: raise HTTPException(422, 'Selected roots have no resolved images to scan')
    configuration = main.get_global_configuration(db)
    scan_id = await main._prepare_public_scan('\n'.join(images), ingest_service_id=service.service_key,
        ingest_service_version='discovery-'+item.id, ingest_scope='service', owner_user_id=auth.user.id,
        trusted_ca_certificates=main.parse_json(configuration.get('trusted_ca_certificates'), []),
        definition_context={'discovery_inventory_id':item.id, 'discovery_confirmation_id':confirmation.id,
            'source_hash':item.source_hash,'content_hash':item.content_hash,'root_ids':confirmation.root_ids,
            'discovery_completeness':item.inventory.get('completeness'),
            'discovery_images':[image for image in item.inventory.get('images', []) if image.get('root_id') in confirmation.root_ids]})
    db.add(DiscoveryScan(confirmation_id=confirmation.id, scan_job_id=scan_id))
    record_audit(db, auth, 'discovery.scan.queued', 'service', service.id, inventory_id=item.id, scan_job_id=scan_id)
    db.commit()
    return {'job_id':scan_id, 'url':'/scan?job_id='+scan_id}

@router.get('/{job_id}/compare/{previous_job_id}')
def compare(job_id: str, previous_job_id: str, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    inventories = []
    for identity in (previous_job_id, job_id):
        job = get_job(db, auth, identity)
        item = db.scalar(select(DiscoveryInventory).where(DiscoveryInventory.job_id==job.id))
        if not item: raise HTTPException(409, 'Both inventories must exist')
        inventories.append({n['id']:n for n in item.inventory.get('nodes',[])})
    old,new = inventories
    return {'added': sorted(new.keys()-old.keys()), 'removed': sorted(old.keys()-new.keys()),
        'changed': sorted(k for k in new.keys() & old.keys() if new[k] != old[k])}


@router.post('/{job_id}/forget-source')
async def forget_source(job_id: str, request: Request, auth: AuthContext = Depends(require_user), db=Depends(get_db)):
    await body(request, auth)
    job = get_job(db, auth, job_id, True)
    source_id = job.payload['source_id']
    siblings = db.scalars(select(DurableJob).where(DurableJob.kind == 'discovery', DurableJob.payload['source_id'].as_string() == source_id)).all()
    if any(j.payload.get('source_id') == source_id and j.status in ('queued','running') for j in siblings):
        raise HTTPException(409, 'Source is still in use')
    path = upload_root() / source_id / job.payload['filename']
    if not path.is_symlink() and path.resolve().is_relative_to(upload_root().resolve()):
        path.unlink(missing_ok=True)
    from .discovery_supplements import remove_supplement_sources
    remove_supplement_sources(upload_root(), siblings)
    record_audit(db, auth, 'discovery.source.removed', 'discovery', job.id)
    db.commit()
    return {'job_id': job.id, 'source_removed': True}
