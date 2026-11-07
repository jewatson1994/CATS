"""CATS read-only distribution endpoint. Every object requires live authorization."""
import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.background import BackgroundTask

from . import main as _portal  # Existing additive schema/bootstrap and policy engine.
from .auth import record_audit
from .database import SessionLocal
from .oci_models import (OCIManifest, OCIObjectLink, OCIPrincipal, OCIProjectObjectLink,
                         OCIRepository, project_repository)
from .oci_authorization import authorize, candidate_service_ids, project_tag_allowed
from .oci_transport import ContentCache, DIGEST, REPOSITORY, RegistryClient, RegistryError
from .release_validity import utc
from .release_revisions import (resolve_distribution_tag as _full_distribution_tag,
                                resolve_distribution_location as _full_distribution_location)
from .secrets import decrypt_secret
from .oci_signatures import legacy_subject, discover_legacy_signature, verify_legacy_signature
from .oci_signatures import verify_legacy_attestation
from .oci_attestations import ATTESTATION_TYPE, legacy_attestation_subject
from . import oci_attestation_inventory

app = FastAPI(title='CATS OCI distribution', docs_url=None, redoc_url=None, openapi_url=None)
from .oci_evidence import router as evidence_router
app.include_router(evidence_router)
V2 = {'Docker-Distribution-Api-Version': 'registry/2.0', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, no-store'}
MANIFEST_TYPES = {'application/vnd.oci.image.manifest.v1+json', 'application/vnd.oci.image.index.v1+json',
                  'application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.docker.distribution.manifest.list.v2+json'}


class Denied(Exception):
    def __init__(self, reason, status=403, code='DENIED', decision=None):
        self.reason, self.status, self.code = reason, status, code
        self.decision = asdict(decision) if is_dataclass(decision) else None


@app.exception_handler(Denied)
async def denied(request, exc):
    try:
        with SessionLocal() as db:
            record_audit(db, None, 'oci.denied', 'oci_repository', getattr(request.state, 'repository_id', None),
                         principal_id=getattr(request.state, 'principal_id', None), reason=exc.reason,
                         decision=exc.decision)
            db.commit()
    except SQLAlchemyError:
        pass  # Unavailable audit storage never converts a denial to permission.
    headers = dict(V2)
    if exc.status == 401:
        headers['WWW-Authenticate'] = 'Basic realm="CATS OCI"'
    error = {'code': exc.code, 'message': exc.reason}
    if exc.decision:
        error['detail'] = exc.decision
    return JSONResponse({'errors': [error]}, status_code=exc.status, headers=headers)


@app.exception_handler(RegistryError)
async def upstream_error(request, exc):
    status = exc.status if exc.status in (400, 404, 413, 429) else 502
    return JSONResponse({'errors': [{'code': 'MANIFEST_UNKNOWN' if status == 404 else 'UNKNOWN', 'message': str(exc)}]}, status_code=status, headers=V2)


@app.exception_handler(SQLAlchemyError)
async def unavailable(request, exc):
    return JSONResponse({'errors': [{'code': 'UNAVAILABLE', 'message': 'Authorization storage unavailable'}]}, status_code=503, headers=V2)


def principal(db, request, repository_id=None):
    try:
        scheme, value = request.headers.get('authorization', '').split(' ', 1)
        if scheme.lower() != 'basic' or len(value) > 2048:
            raise ValueError()
        username, secret = base64.b64decode(value, validate=True).decode().split(':', 1)
    except (ValueError, UnicodeError):
        raise Denied('Machine authentication required', 401, 'UNAUTHORIZED') from None
    row = db.scalar(select(OCIPrincipal).where(OCIPrincipal.name == username).execution_options(populate_existing=True))
    expected = row.secret_hash if row else '0' * 64
    valid = hmac.compare_digest(expected, hashlib.sha256(secret.encode()).hexdigest())
    if not valid or not row or not row.enabled or utc(row.expires_at) <= datetime.now(timezone.utc):
        raise Denied('Machine authentication required', 401, 'UNAUTHORIZED')
    if repository_id is not None and repository_id not in row.repository_ids:
        raise Denied('Repository access denied')
    request.state.principal_id, request.state.repository_id = row.id, repository_id
    return row


def mapping_for(db, repository):
    if len(repository) > 255 or not REPOSITORY.fullmatch(repository):
        raise Denied('Invalid repository', 400, 'NAME_INVALID')
    names = [repository]
    if '/' in repository:
        names.append(repository.partition('/')[0] + '/*')
    name = OCIRepository.public_repository
    mapping = db.scalar(select(OCIRepository).where(name.in_(names))
                        .order_by((name == repository).desc()).limit(1).execution_options(populate_existing=True))
    if mapping is None:
        raise Denied('Unknown repository', 404, 'NAME_UNKNOWN')
    db.refresh(mapping.upstream)
    if mapping.public_repository == repository:
        return mapping
    if mapping.service_id is not None or not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
        raise Denied('Project mapping unavailable')
    try:
        upstream_repository = project_repository(mapping.upstream_repository, mapping.public_repository, repository)
    except ValueError as exc:
        raise Denied(str(exc)) from None
    return ProjectMapping(mapping, repository, upstream_repository)


class ProjectMapping:
    def __init__(self, project, public_repository, upstream_repository, service_id=None):
        self.project = project
        self.public_repository = public_repository
        self.upstream_repository = upstream_repository
        self.service_id = service_id

    def __getattr__(self, name):
        return getattr(self.project, name)


def service_mapping(db, mapping, digest):
    """Bind a project pull to unambiguous evidence before checking live policy."""
    if not isinstance(mapping, ProjectMapping) or mapping.service_id is not None:
        return mapping
    candidates = candidate_service_ids(db, mapping, digest)
    if len(candidates) != 1:
        raise Denied('No unique service approval for this repository and digest')
    return ProjectMapping(mapping.project, mapping.public_repository, mapping.upstream_repository,
                          next(iter(candidates)))


class EffectiveMapping:
    """Request-local view; never mutate the configured or signed mapping."""
    def __init__(self, mapping, repository):
        self._mapping = mapping
        self.upstream_repository = repository
    def __getattr__(self, name):
        return getattr(self._mapping, name)


def resolve_distribution_tag(db, mapping, tag):
    from .operating_mode import is_replica
    return None if is_replica() else _full_distribution_tag(db, mapping, tag)


def resolve_distribution_location(db, mapping, digest):
    from .operating_mode import is_replica
    if is_replica():
        from .replica_authorization import distribution_location
        return distribution_location(db, mapping, digest)
    return _full_distribution_location(db, mapping, digest)


def effective_mapping(db, mapping, digest, binding=None):
    if isinstance(mapping, ProjectMapping):
        return mapping
    try:
        repository = binding['upstream_repository'] if binding else resolve_distribution_location(db, mapping, digest)
    except ValueError as exc:
        raise Denied(str(exc)) from None
    return EffectiveMapping(mapping, repository)


def client(mapping):
    upstream = mapping.upstream
    return RegistryClient(dict(endpoint=upstream.endpoint, username=decrypt_secret(upstream.username),
        password=decrypt_secret(upstream.password), ca_pem=upstream.ca_pem,
        token_realms=upstream.token_realms, redirect_origins=upstream.redirect_origins))


def content_cache():
    return ContentCache(os.getenv('CATS_OCI_CACHE_DIR', '/var/cache/cats-oci'),
        int(os.getenv('CATS_OCI_CACHE_MAX_BYTES', str(10 * 1024**3))),
        int(os.getenv('CATS_OCI_MAX_BLOB_BYTES', str(4 * 1024**3))))


def save_signature(db, mapping, subject, signature):
    save_unique(db, OCIManifest, dict(repository_id=mapping.id, digest=signature.digest),
                media_type=signature.media_type, content=signature.raw.decode('utf-8'))
    link_object(db, mapping, subject, signature.digest, 'signature')
    for blob in signature.blob_digests:
        link_object(db, mapping, subject, blob, 'blob')


def attestation_inventory(db, mapping, subject):
    owner = service_mapping(db, getattr(mapping, '_mapping', mapping), subject)
    decision = authorize(db, owner, subject)
    if not decision.allowed:
        raise Denied(decision.reason, decision=decision)
    return oci_attestation_inventory.inventory(db, mapping, subject, decision)


def save_attestation(db, mapping, subject, attestation):
    save_unique(db, OCIManifest, dict(repository_id=mapping.id, digest=attestation.digest),
                media_type=attestation.media_type, content=attestation.raw.decode('utf-8'))
    link_object(db, mapping, subject, attestation.digest, 'attestation')
    for blob in attestation.blob_digests:
        link_object(db, mapping, subject, blob, 'attestation_blob')


def retained_attestation(db, mapping, transport, subject, inventory):
    if inventory is None:
        raise Denied('No attestation belongs to the currently authorized release')
    raw, media, digest, _ = manifest(db, mapping, transport, inventory['digest'])
    if (digest != inventory['digest'] or len(raw) != inventory.get('size')
            or media != inventory.get('mediaType')):
        raise RegistryError('Attestation descriptor differs from signed inventory')
    verified = verify_legacy_attestation(raw, media, digest, transport,
        mapping.upstream_repository, subject, content_cache(), inventory.get('receipts'))
    if sorted(set(verified.blob_digests)) != inventory.get('blobs'):
        raise RegistryError('Attestation blobs differ from signed inventory')
    save_attestation(db, mapping, subject, verified)
    return verified


def require(db, mapping, digest):
    owner = service_mapping(db, getattr(mapping, '_mapping', mapping), digest)
    decision = authorize(db, owner, digest)
    if not decision.allowed:
        raise Denied(decision.reason, decision=decision)
    remember_decision(db, owner, digest, decision)
    return decision


def remember_decision(db, mapping, digest, decision):
    if getattr(decision, 'authorization_source', None):
        db.info.setdefault('oci_pull_decisions', {})[(mapping.service_id, digest)] = (mapping, decision)


def save_unique(db, model, where, **values):
    row = db.scalar(select(model).filter_by(**where))
    if row is None:
        try:
            with db.begin_nested():
                row = model(**where, **values)
                db.add(row)
                db.flush()
        except IntegrityError:
            row = db.scalar(select(model).filter_by(**where))
    return row


def manifest(db, mapping, transport, reference):
    row = None
    if DIGEST.fullmatch(reference):
        query = select(OCIManifest).filter_by(repository_id=mapping.id, digest=reference)
        if isinstance(mapping, ProjectMapping):
            # Reuse immutable bytes only after observing them in this concrete repo.
            link, scope = link_scope(mapping)
            query = query.where(select(link.root_digest).filter_by(**scope, object_digest=reference)
                                .where(link.kind.in_(('manifest', 'signature', 'attestation'))).exists())
        row = db.scalar(query)
    if row:
        raw, media, digest = row.content.encode('utf-8'), row.media_type, row.digest
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
            raise RegistryError('Retained manifest integrity failure')
    else:
        raw, media, digest = transport.fetch_manifest(mapping.upstream_repository, reference)
    try:
        doc = json.loads(raw)
        if not isinstance(doc, dict) or doc.get('schemaVersion') != 2 or media not in MANIFEST_TYPES:
            raise ValueError()
        content = raw.decode('utf-8')
    except (ValueError, UnicodeError):
        raise RegistryError('Invalid OCI manifest') from None
    if not row:
        save_unique(db, OCIManifest, dict(repository_id=mapping.id, digest=digest), media_type=media, content=content)
    return raw, media, digest, doc


def descriptor(value):
    if not isinstance(value, dict) or not DIGEST.fullmatch(str(value.get('digest', ''))) or type(value.get('size')) is not int or value['size'] < 0:
        raise RegistryError('Invalid OCI descriptor')
    if value.get('urls'):
        raise RegistryError('Externally fetched layers are not distributable through CATS')
    return value['digest']


def link_scope(mapping):
    if isinstance(mapping, ProjectMapping):
        return OCIProjectObjectLink, dict(repository_id=mapping.id, repository_path=mapping.public_repository)
    return OCIObjectLink, dict(repository_id=mapping.id)


def link_object(db, mapping, root, digest, kind):
    model, scope = link_scope(mapping)
    save_unique(db, model, dict(**scope, root_digest=root, object_digest=digest, kind=kind))


def check_project_tag(db, mapping, reference, digest):
    if isinstance(mapping, ProjectMapping) and not DIGEST.fullmatch(reference):
        if not project_tag_allowed(db, mapping, reference, digest):
            raise Denied('Tag is not bound to this digest in the active release')


def graph(db, mapping, transport, reference, root=None, seen=None, depth=0):
    seen = set() if seen is None else seen
    if depth > 8 or len(seen) >= 256:
        raise RegistryError('Manifest graph limit exceeded', 413)
    raw, media, digest, doc = manifest(db, mapping, transport, reference)
    root = root or digest
    if digest in seen:
        return raw, media, digest
    seen.add(digest)
    mapping = service_mapping(db, mapping, digest)
    require(db, mapping, digest)
    check_project_tag(db, mapping, reference, digest)
    link_object(db, mapping, root, digest, 'manifest')
    if 'manifests' in doc:
        if not isinstance(doc['manifests'], list) or len(doc['manifests']) > 256:
            raise RegistryError('Invalid artifact index')
        for item in doc['manifests']:
            child = descriptor(item)
            child_raw, _, _ = graph(db, mapping, transport, child, root, seen, depth + 1)
            if len(child_raw) != item['size']:
                raise RegistryError('Manifest descriptor size mismatch')
    else:
        if not isinstance(doc.get('layers'), list) or len(doc['layers']) > 512:
            raise RegistryError('Invalid or oversized layer list')
        blobs = [doc.get('config'), *doc['layers']]
        for item in blobs:
            blob = descriptor(item)
            link_object(db, mapping, root, blob, 'blob')
    return raw, media, digest


def authorize_object(db, mapping, digest, kind):
    mapping = getattr(mapping, '_mapping', mapping)
    model, scope = link_scope(mapping)
    kinds = (kind, 'attestation_blob') if kind == 'blob' else (kind,)
    roots = db.execute(select(model.root_digest, model.kind).filter_by(**scope, object_digest=digest)
                       .where(model.kind.in_(kinds))).all()
    last_denial = None
    for root, association_kind in roots:
        try:
            owner = service_mapping(db, mapping, root)
        except Denied:
            continue
        decision = authorize(db, owner, root)
        if not decision.allowed:
            last_denial = decision
            continue
        if association_kind in ('attestation', 'attestation_blob'):
            routed = effective_mapping(db, owner, root)
            inventory = oci_attestation_inventory.inventory(db, routed, root, decision)
            if inventory is None or (digest != inventory.get('digest') if association_kind == 'attestation'
                                     else digest not in inventory.get('blobs', [])):
                continue
        # Index children must remain authorized after graph construction too.
        members = db.scalars(select(model.object_digest).filter_by(**scope, root_digest=root, kind='manifest')).all()
        decisions = [(member, authorize(db, owner, member)) for member in members]
        if all(item.allowed for _, item in decisions):
            remember_decision(db, owner, root, decision)
            for member, member_decision in decisions:
                remember_decision(db, owner, member, member_decision)
            return root
    raise Denied('Object has no currently authorized image association', decision=last_denial)


def audit(db, machine, mapping, digest, outcome):
    effective = []
    remembered = db.info.pop('oci_pull_decisions', {})
    if outcome in {'allowed', 'referrers'}:
        from .local_cyber_overrides import lock_for_use
        for owner, previous in remembered.values():
            override_id = getattr(previous, 'override_id', None)
            if override_id is not None:
                try:
                    lock_for_use(db, override_id)
                except ValueError as exc:
                    raise Denied(str(exc)) from None
            current = authorize(db, owner, previous.artifact_digest)
            if not current.allowed:
                raise Denied(current.reason, decision=current)
            detail = dict(service_id=current.service_id, digest=current.artifact_digest,
                release_id=current.release_id, override_id=current.override_id,
                authorization_source=current.authorization_source, approval_status=current.approval_status,
                override_status=current.override_status, effective_policy=current.effective_policy,
                reason=current.reason, decision_at=current.decision_at)
            effective.append(detail)
            if current.override_id is not None:
                # A new override discovered during reauthorization also gets the
                # final row lock before its use and the response are committed.
                try:
                    lock_for_use(db, current.override_id)
                except ValueError as exc:
                    raise Denied(str(exc)) from None
                record_audit(db, None, 'local_override.used', 'local_cyber_override', current.override_id,
                    principal_id=machine.id, repository=mapping.public_repository, **detail)
    record_audit(db, None, 'oci.pull', 'oci_repository', mapping.id,
                 principal_id=machine.id, repository=mapping.public_repository, digest=digest,
                 outcome=outcome, decisions=effective)
    db.commit()


@app.api_route('/v2/', methods=['GET', 'HEAD'])
def ping(request: Request):
    with SessionLocal() as db:
        principal(db, request)
    return Response(headers=V2)


@app.get('/healthz')
def health():
    with SessionLocal() as db:
        db.execute(text('SELECT 1'))
    return {'status': 'ready'}


@app.api_route('/v2/{repository:path}/manifests/{reference}', methods=['GET', 'HEAD'])
def get_manifest(repository: str, reference: str, request: Request):
    with SessionLocal() as db:
        mapping = mapping_for(db, repository)
        machine = principal(db, request, mapping.id)
        try:
            signature_root = legacy_subject(reference)
            attestation_root = legacy_attestation_subject(reference)
            binding = None
            if not isinstance(mapping, ProjectMapping) and not signature_root and not attestation_root and not DIGEST.fullmatch(reference):
                try:
                    binding = resolve_distribution_tag(db, mapping, reference)
                except ValueError as exc:
                    raise Denied(str(exc)) from None
                if binding:
                    require(db, mapping, binding['digest'])
            transport = client(mapping)
            if DIGEST.fullmatch(reference):
                for root in oci_attestation_inventory.candidate_subjects(db, mapping, reference):
                    try:
                        owner = service_mapping(db, mapping, root)
                        routed = effective_mapping(db, owner, root)
                        inventory = attestation_inventory(db, routed, root)
                        if inventory and inventory.get('digest') == reference:
                            attestation_root = root
                            break
                    except Denied:
                        continue
                try:
                    if not attestation_root:
                        signature_root = authorize_object(db, mapping, reference, 'signature')
                except Denied:
                    pass
                if not signature_root and not attestation_root:
                    mapping = service_mapping(db, mapping, reference)
            mapping = effective_mapping(db, mapping, attestation_root or signature_root or (binding['digest'] if binding else reference), binding)
            if attestation_root:
                require(db, mapping, attestation_root)
                attestation = retained_attestation(db, mapping, transport, attestation_root,
                    attestation_inventory(db, mapping, attestation_root))
                raw, media, digest = attestation.raw, attestation.media_type, attestation.digest
            elif signature_root:
                require(db, mapping, signature_root)
                raw, media, digest, _ = manifest(db, mapping, transport, reference)
                signature = verify_legacy_signature(raw, media, digest, transport, mapping.upstream_repository, signature_root, content_cache())
                save_signature(db, mapping, signature_root, signature)
            else:
                raw, media, digest = graph(db, mapping, transport, binding['digest'] if binding else reference)
                if binding and digest != binding['digest']:
                    raise Denied('Resolved artifact differs from signed tag binding')
            db.commit()
            db.expire_all()
            mapping = mapping_for(db, repository)
            principal(db, request, mapping.id)
            if not signature_root and not attestation_root and not DIGEST.fullmatch(reference):
                if isinstance(mapping, ProjectMapping):
                    check_project_tag(db, service_mapping(db, mapping, digest), reference, digest)
                else:
                    try:
                        current_binding = resolve_distribution_tag(db, mapping, reference)
                    except ValueError as exc:
                        raise Denied(str(exc)) from None
                    if current_binding != binding:
                        raise Denied('Active release changed during retrieval; retry')
            authorize_object(db, mapping, digest, 'attestation' if attestation_root else 'signature' if signature_root else 'manifest')
            audit(db, machine, mapping, digest, 'allowed')
        except Denied as exc:
            db.rollback()
            audit(db, machine, mapping, reference, exc.reason)
            raise
    return Response(raw if request.method == 'GET' else b'', media_type=media,
        headers={**V2, 'Docker-Content-Digest': digest, 'ETag': '"' + digest + '"', 'Content-Length': str(len(raw))})


@app.get('/v2/{repository:path}/referrers/{digest}')
def referrers(repository: str, digest: str, request: Request):
    with SessionLocal() as db:
        mapping = mapping_for(db, repository)
        machine = principal(db, request, mapping.id)
        require(db, mapping, digest)
        mapping = effective_mapping(db, mapping, digest)
        transport = client(mapping)
        try:
            document = transport.referrers(mapping.upstream_repository, digest)
        except RegistryError as exc:
            if exc.status not in (404, 405):
                raise
            document = {'manifests': []}
        if not isinstance(document.get('manifests'), list) or len(document['manifests']) > 256:
            raise RegistryError('Referrer count exceeds limit', 413)
        retained = []
        for item in document.get('manifests', []):
            reference = descriptor(item)
            # A registry subject pointer alone cannot authorize arbitrary blobs.
            # Only supported, payload-bound signatures are exposed as referrers.
            from .oci_signatures import SIGNATURE_TYPE
            if item.get('artifactType') != SIGNATURE_TYPE:
                continue
            raw, media, actual, doc = manifest(db, mapping, transport, reference)
            if descriptor(doc.get('subject')) != digest:
                raise RegistryError('Signature subject mismatch')
            verified = verify_legacy_signature(raw, media, actual, transport,
                mapping.upstream_repository, digest, content_cache())
            if len(raw) != item['size']:
                raise RegistryError('Referrer descriptor size mismatch')
            save_signature(db, mapping, digest, verified)
            if not request.query_params.get('artifactType') or item.get('artifactType') == request.query_params['artifactType']:
                retained.append(item)
        signature = discover_legacy_signature(transport, mapping.upstream_repository, digest, content_cache())
        if signature:
            save_signature(db, mapping, digest, signature)
            if (not request.query_params.get('artifactType') or signature.descriptor.get('artifactType') == request.query_params['artifactType']) and not any(item['digest'] == signature.digest for item in retained):
                retained.append(signature.descriptor)
        inventory = attestation_inventory(db, mapping, digest)
        if inventory:
            attestation = retained_attestation(db, mapping, transport, digest, inventory)
            if not request.query_params.get('artifactType') or request.query_params['artifactType'] == ATTESTATION_TYPE:
                retained.append(attestation.descriptor)
        db.commit()
        db.expire_all()
        mapping = mapping_for(db, repository)
        principal(db, request, mapping.id)
        require(db, mapping, digest)
        for item in retained:
            if item.get('artifactType') == ATTESTATION_TYPE:
                authorize_object(db, mapping, item['digest'], 'attestation')
        audit(db, machine, mapping, digest, 'referrers')
    return JSONResponse({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': retained},
                        media_type='application/vnd.oci.image.index.v1+json', headers=V2)


@app.get('/.well-known/cats/signing-keys')
def signing_keys():
    from .oci_lifecycle import public_keys
    with SessionLocal() as db:
        result = public_keys(db)
        db.commit()
        return result


def byte_range(header, size):
    if not header:
        return 0, size - 1, False
    match = re.fullmatch(r'bytes=(\d*)-(\d*)', header)
    if not match or not any(match.groups()) or size == 0:
        raise Denied('Requested range is not satisfiable', 416, 'RANGE_INVALID')
    left, right = match.groups()
    if left:
        start, end = int(left), min(int(right), size - 1) if right else size - 1
    else:
        start, end = max(0, size - int(right)), size - 1
    if start > end or start >= size:
        raise Denied('Requested range is not satisfiable', 416, 'RANGE_INVALID')
    return start, end, True


@app.api_route('/v2/{repository:path}/blobs/{digest}', methods=['GET', 'HEAD'])
def get_blob(repository: str, digest: str, request: Request):
    if not DIGEST.fullmatch(digest):
        raise Denied('Invalid digest', 400, 'DIGEST_INVALID')
    stream = None
    try:
        with SessionLocal() as db:
            mapping = mapping_for(db, repository)
            machine = principal(db, request, mapping.id)
            root = authorize_object(db, mapping, digest, 'blob')
            mapping = effective_mapping(db, mapping, root)
            cache = content_cache()
            path = client(mapping).fetch_blob(mapping.upstream_repository, digest, cache)
            try:
                stream = path.open('rb')
            except FileNotFoundError:
                raise RegistryError('Cached object was evicted; retry request', 429) from None
            size = os.fstat(stream.fileno()).st_size
            db.commit()
            db.expire_all()
            mapping = mapping_for(db, repository)
            principal(db, request, mapping.id)
            authorize_object(db, mapping, digest, 'blob')
            audit(db, machine, mapping, digest, 'allowed')
        header = request.headers.get('range') if request.method == 'GET' else None
        if request.headers.get('if-range') not in (None, '"' + digest + '"'):
            header = None
        try:
            start, end, partial = byte_range(header, size)
        except Denied:
            stream.close()
            return JSONResponse({'errors': [{'code': 'RANGE_INVALID', 'message': 'Unsatisfiable range'}]}, status_code=416, headers={**V2, 'Content-Range': f'bytes */{size}'})
        headers = {**V2, 'Docker-Content-Digest': digest, 'ETag': '"' + digest + '"',
                   'Accept-Ranges': 'bytes', 'Content-Length': str(end - start + 1)}
        if partial:
            headers['Content-Range'] = f'bytes {start}-{end}/{size}'
        if request.method == 'HEAD':
            stream.close()
            return Response(headers=headers, media_type='application/octet-stream')
        def chunks():
            try:
                stream.seek(start)
                remaining = end - start + 1
                while remaining:
                    part = stream.read(min(1024 * 1024, remaining))
                    if not part:
                        break
                    remaining -= len(part)
                    yield part
            finally:
                stream.close()
        return StreamingResponse(chunks(), status_code=206 if partial else 200, headers=headers,
                                 media_type='application/octet-stream', background=BackgroundTask(stream.close))
    except BaseException:
        if stream:
            stream.close()
        raise
