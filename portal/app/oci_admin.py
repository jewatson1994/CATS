"""Application-admin configuration for the OCI distribution boundary."""
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import AuthContext, record_audit, require_permission
from .database import get_db
from .models import Service
from .oci_models import OCIPrincipal, OCIRepository, OCIUpstream
from .release_validity import utc
from .secrets import encrypt_secret
from .service_oci import _csrf, validate_destination

router = APIRouter(prefix='/api/oci', tags=['OCI administration'])
admin = require_permission('release.destination.manage')
MODELS = {'upstreams': OCIUpstream, 'repositories': OCIRepository, 'principals': OCIPrincipal}
REPOSITORY = re.compile(r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*\Z')


def public(row):
    if isinstance(row, OCIUpstream):
        return {key: getattr(row, key) for key in ('id', 'name', 'endpoint', 'enabled', 'token_realms', 'redirect_origins')} | {
            'credentials_configured': bool(row.password), 'ca_configured': bool(row.ca_pem)}
    if isinstance(row, OCIRepository):
        return {key: getattr(row, key) for key in ('id', 'public_repository', 'service_id', 'upstream_id',
            'upstream_repository', 'policy', 'enabled', 'suspended')}
    return {key: getattr(row, key) for key in ('id', 'name', 'repository_ids', 'enabled', 'expires_at', 'created_at')}


def _model(kind):
    if kind not in MODELS:
        raise HTTPException(404, 'Configuration type not found')
    return MODELS[kind]


def _row(db, kind, identity):
    row = db.get(_model(kind), identity)
    if row is None:
        raise HTTPException(404, 'Configuration not found')
    return row


def _boolean(data, key, default):
    value = data.get(key, default)
    if type(value) is not bool:
        raise HTTPException(422, f'{key} must be a boolean')
    return value


def _name(value, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise HTTPException(422, 'A valid name is required')
    return value.strip()


def _origins(data, key, previous):
    values = data.get(key, previous)
    if not isinstance(values, list) or len(values) > 32:
        raise HTTPException(422, f'{key} must be a list of HTTPS origins')
    result = []
    for value in values:
        if not isinstance(value, str):
            raise HTTPException(422, f'Invalid {key}')
        # Token realms may include a path; redirects are origin-only.
        parsed = urlsplit(value)
        origin = f'{parsed.scheme}://{parsed.netloc}'
        validate_destination({'name': 'Origin', 'endpoint': origin})
        if parsed.query or parsed.fragment or (key == 'redirect_origins' and parsed.path not in ('', '/')):
            raise HTTPException(422, f'Invalid {key}')
        result.append(value.rstrip('/'))
    return sorted(set(result))


def _save_upstream(row, data):
    values = validate_destination({**{key: getattr(row, key, '') or '' for key in ('name', 'endpoint', 'ca_pem')}, **data})
    for key in ('name', 'endpoint', 'ca_pem'):
        setattr(row, key, values[key])
    for key in ('username', 'password'):
        if key in data:
            if not isinstance(data[key], str) or len(data[key]) > 16384:
                raise HTTPException(422, 'Invalid upstream credentials')
            setattr(row, key, encrypt_secret(data[key]) if data[key] else '')
    for key in ('token_realms', 'redirect_origins'):
        setattr(row, key, _origins(data, key, getattr(row, key, None) or []))


def _save_repository(db, row, data):
    for key in ('public_repository', 'upstream_repository'):
        value = data.get(key, getattr(row, key, None))
        if not isinstance(value, str) or len(value) > 255 or not REPOSITORY.fullmatch(value):
            raise HTTPException(422, f'Invalid {key}')
        if key == 'public_repository' and '/' not in value:
            raise HTTPException(422, 'Public repository must include a project namespace')
        setattr(row, key, value)
    for key, model in (('service_id', Service), ('upstream_id', OCIUpstream)):
        identity = data.get(key, getattr(row, key, None))
        if type(identity) is not int or db.get(model, identity) is None:
            raise HTTPException(422, f'Invalid {key}')
        setattr(row, key, identity)
    policy = data.get('policy', row.policy or {})
    if not isinstance(policy, dict) or set(policy) - {'max_scan_age_days', 'max_approval_age_days'}:
        raise HTTPException(422, 'Unsupported distribution policy')
    for key, value in policy.items():
        if type(value) is not int or not 1 <= value <= 3650:
            raise HTTPException(422, f'{key} must be from 1 to 3650')
    row.policy = policy
    row.suspended = _boolean(data, 'suspended', row.suspended if row.suspended is not None else False)


def _save_principal(db, row, data):
    row.name = _name(data.get('name', row.name), 100)
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', row.name):
        raise HTTPException(422, 'Machine name must use letters, numbers, dots, underscores or hyphens')
    identities = data.get('repository_ids', row.repository_ids or [])
    if not isinstance(identities, list) or not identities or len(identities) > 256:
        raise HTTPException(422, 'Select at least one repository')
    if any(type(identity) is not int or db.get(OCIRepository, identity) is None for identity in identities):
        raise HTTPException(422, 'Invalid repository grants')
    row.repository_ids = sorted(set(identities))
    value = data.get('expires_at', utc(row.expires_at) if row.expires_at else (datetime.now(timezone.utc) + timedelta(days=90)))
    try:
        expiry = datetime.fromisoformat(value) if isinstance(value, str) else value
        if expiry.utcoffset() is None or not datetime.now(timezone.utc) < expiry <= datetime.now(timezone.utc) + timedelta(days=365):
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise HTTPException(422, 'Expiry must be a timezone-aware future date within 365 days') from None
    row.expires_at = utc(expiry)


def _commit(db):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Configuration name or repository already exists or is in use') from None


@router.get('/status/overview')
def overview(db: Session = Depends(get_db), auth: AuthContext = Depends(admin)):
    now = datetime.now(timezone.utc)
    repositories = list(db.scalars(select(OCIRepository)))
    principals = list(db.scalars(select(OCIPrincipal)))
    return {'repositories': len(repositories),
            'available_repositories': sum(row.enabled and not row.suspended and row.upstream.enabled for row in repositories),
            'active_principals': sum(row.enabled and utc(row.expires_at) > now for row in principals),
            'services': [{'id': row.id, 'name': row.name} for row in db.scalars(select(Service).order_by(Service.name))],
            'authorization': 'Live Cyber approval and current service compliance checked on every pull',
            'proxy_health': 'Use the separately deployed distribution endpoint to verify runtime availability'}


@router.post('/repositories/{identity}/test')
async def test_repository(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(admin)):
    _csrf(request, auth)
    row = _row(db, 'repositories', identity)
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError()
    except ValueError:
        raise HTTPException(422, 'JSON object required') from None
    from .oci_transport import RegistryClient, RegistryError
    from .secrets import decrypt_secret
    from starlette.concurrency import run_in_threadpool
    upstream = row.upstream
    try:
        client = RegistryClient(dict(endpoint=upstream.endpoint, username=decrypt_secret(upstream.username),
            password=decrypt_secret(upstream.password), ca_pem=upstream.ca_pem,
            token_realms=upstream.token_realms, redirect_origins=upstream.redirect_origins))
        _, _, digest = await run_in_threadpool(client.fetch_manifest, row.upstream_repository, body.get('reference', 'latest'))
    except (RegistryError, ValueError, OSError):
        return {'ok': False, 'message': 'Connection check failed. Check registry access, reference, credentials, TLS and allowed token realms.'}
    record_audit(db, auth, 'oci.connection.test', 'repositories', row.id)
    _commit(db)
    return {'ok': True, 'digest': digest, 'message': 'Registry authentication, TLS and manifest integrity verified. Distribution still requires current Cyber approval.'}


@router.get('/{kind}')
def listing(kind: str, db: Session = Depends(get_db), auth: AuthContext = Depends(admin)):
    return [public(row) for row in db.scalars(select(_model(kind)).order_by(_model(kind).id))]


async def save(kind, identity, request, db, auth):
    _csrf(request, auth)
    try:
        data = await request.json()
    except ValueError:
        raise HTTPException(422, 'JSON object required') from None
    if not isinstance(data, dict):
        raise HTTPException(422, 'JSON object required')
    row = _row(db, kind, identity) if identity is not None else _model(kind)()
    if kind == 'upstreams': _save_upstream(row, data)
    elif kind == 'repositories': _save_repository(db, row, data)
    else: _save_principal(db, row, data)
    row.enabled = _boolean(data, 'enabled', row.enabled if row.enabled is not None else True)
    secret = None
    if kind == 'principals' and identity is None:
        secret = secrets.token_urlsafe(32)
        row.secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    db.add(row)
    try:
        db.flush()
        record_audit(db, auth, 'oci.configuration.save', kind, row.id)
        _commit(db)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Configuration already exists') from None
    result = public(row)
    if secret:
        result['secret'] = secret
    return result


@router.post('/{kind}')
async def create(kind: str, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(admin)):
    return await save(kind, None, request, db, auth)


@router.put('/{kind}/{identity}')
async def update(kind: str, identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(admin)):
    return await save(kind, identity, request, db, auth)


@router.delete('/{kind}/{identity}')
def delete(kind: str, identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(admin)):
    _csrf(request, auth)
    row = _row(db, kind, identity)
    if kind == 'upstreams' and db.scalar(select(OCIRepository.id).where(OCIRepository.upstream_id == identity).limit(1)):
        raise HTTPException(409, 'Remove dependent repository mappings first')
    if kind == 'repositories':
        # Keep referential cache metadata and audit continuity; disabling removes access.
        row.enabled = False
        for principal in db.scalars(select(OCIPrincipal)):
            principal.repository_ids = [value for value in principal.repository_ids if value != identity]
    else:
        db.delete(row)
    record_audit(db, auth, 'oci.configuration.delete', kind, identity)
    _commit(db)
    return {'disabled': True} if kind == 'repositories' else {'deleted': True}


@router.post('/principals/{identity}/rotate')
def rotate(identity: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(admin)):
    _csrf(request, auth)
    row = _row(db, 'principals', identity)
    secret = secrets.token_urlsafe(32)
    row.secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    record_audit(db, auth, 'oci.principal.rotate', 'oci_principal', identity)
    _commit(db)
    return {**public(row), 'secret': secret}
