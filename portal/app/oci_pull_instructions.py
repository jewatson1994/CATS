"""Read-only, digest-pinned pull instructions from the live OCI authorization path."""
import ipaddress
import os
import re
import shlex
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import or_, select

from .auth import AuthContext, require_permission, require_user
from .cyber_approval_evidence import _identity, _registry_path, _repository_identity
from .database import get_db
from .models import Service, ServiceImage
from .oci_models import OCIRepository, is_project_pattern, project_repository, service_repository
from .oci_service_access import service_pull_is_public
from .oci_transport import DIGEST, REPOSITORY

router = APIRouter(tags=['OCI pull instructions'])


class PullRoute(BaseModel):
    repository: str
    digest: str
    reference: str
    command: str
    login_command: str | None
    login_required: bool
    anonymous_pull: bool


class PullInstructions(BaseModel):
    service_id: int
    image_reference: str | None
    registry: str | None
    status: Literal['available', 'unavailable']
    reason: str | None
    routes: list[PullRoute]


class InventoryImagePull(PullInstructions):
    image_id: int


class ReleaseImagePull(PullInstructions):
    release_id: int
    artifact_index: int


def registry_authority():
    """Never turn an HTTP Host header or shell syntax into a copyable command."""
    value = os.getenv('CATS_OCI_HOSTNAME', '')
    if not value:
        return None
    if len(value) > 300 or not re.fullmatch(r'[A-Za-z0-9.\-:\[\]]+', value):
        raise ValueError('Invalid CATS OCI hostname')
    try:
        parsed = urlsplit('https://' + value)
        hostname, port = parsed.hostname, parsed.port
        if not hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError()
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
        if ':' in hostname:
            ipaddress.IPv6Address(hostname)
            if not re.fullmatch(r'\[[0-9A-Fa-f:]+\](?::[0-9]+)?', value):
                raise ValueError()
        else:
            if len(hostname) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                                       for part in hostname.rstrip('.').split('.')):
                raise ValueError()
            if not re.fullmatch(r'[A-Za-z0-9.\-]+(?::[0-9]+)?', value):
                raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Invalid CATS OCI hostname') from None
    return value.lower()


def same_image(reference, digest, image_identity):
    """Both repository and immutable bytes must identify the selected image."""
    try:
        pinned, retained = _identity(reference, digest)
        return retained == image_identity[1] and _repository_identity(pinned) == _repository_identity(image_identity[0])
    except (ValueError, TypeError, AttributeError):
        return False


def _location(reference, digest, *, published=False):
    try:
        reference, digest = _identity(reference, digest)
        if not DIGEST.fullmatch(digest):
            return None
        return reference, digest, published
    except (ValueError, TypeError, AttributeError):
        return None


def image_locations(db, image, image_identity):
    """Discover candidates only; the proxy's current authorization decides each."""
    from .imported_services import uses_imported_evidence
    locations = set()
    if uses_imported_evidence(db, image.service_id):
        from .replica_models import ReplicaRelease, ReplicaServiceState
        from .replica_authorization import trusted_release
        state = db.get(ReplicaServiceState, image.service_id, populate_existing=True)
        if state is None:
            return locations
        for release in db.scalars(select(ReplicaRelease).where(ReplicaRelease.service_id == image.service_id)
                                  .execution_options(populate_existing=True)):
            if not trusted_release(db, release, state):
                continue
            for artifact in release.artifacts:
                if not isinstance(artifact, dict) or artifact.get('kind') != 'image':
                    continue
                target = _location(artifact.get('reference'), artifact.get('digest'), published=True)
                if target is None:
                    continue
                sources = artifact.get('source_references') or []
                if not isinstance(sources, list):
                    sources = []
                sources = [artifact.get('source_reference'), *sources]
                retained_source = (artifact.get('scan_identity_retained') is True
                    and artifact.get('identity_resolution') == 'retained-evidence'
                    and artifact.get('verification_status') == 'verified'
                    and any(same_image(source, artifact.get('source_digest'), image_identity) for source in sources))
                if same_image(target[0], target[1], image_identity) or retained_source:
                    locations.add(target)
        return locations

    from .cyber_approvals import CyberApproval, digest as snapshot_digest
    # Retained scan identity is also a candidate for a direct upstream mapping.
    locations.add((*image_identity, False))
    for approval in db.scalars(select(CyberApproval).where(CyberApproval.service_id == image.service_id)
                               .execution_options(populate_existing=True)):
        snapshot, receipt = approval.snapshot, approval.publication
        if not isinstance(snapshot, dict) or not isinstance(receipt, dict):
            continue
        try:
            if snapshot.get('service_id') != image.service_id or snapshot_digest(snapshot) != approval.snapshot_digest:
                continue
        except (TypeError, ValueError):
            continue
        for source, target in _published_locations(approval):
            if same_image(source.get('reference'), source.get('digest'), image_identity):
                locations.add(target)
    return locations


def _published_locations(approval, artifact_index=None):
    """A verified receipt binds each published manifest to its exact snapshot slot."""
    receipt = approval.publication
    if not isinstance(receipt, dict):
        return
    manifest = receipt.get('manifest')
    if (not isinstance(manifest, dict) or receipt.get('verification_status') != 'verified'
            or receipt.get('signature_status') != 'verified' or manifest.get('approval_id') != approval.id
            or manifest.get('snapshot_digest') != approval.snapshot_digest
            or manifest.get('artifacts') != receipt.get('artifacts')):
        return
    originals, published = approval.snapshot.get('artifacts'), receipt.get('artifacts')
    if not isinstance(originals, list) or not isinstance(published, list):
        return
    for index, (source, artifact) in enumerate(zip(originals, published)):
        if artifact_index is not None and index != artifact_index:
            continue
        if (not isinstance(source, dict) or source.get('kind') != 'image'
                or not DIGEST.fullmatch(str(source.get('digest')))
                or not isinstance(artifact, dict) or artifact.get('kind') != 'image'
                or artifact.get('source_digest') != source.get('digest')
                or artifact.get('scan_identity_retained') is not True
                or artifact.get('identity_resolution') != 'retained-evidence'
                or artifact.get('verification_status') != 'verified'):
            continue
        target = _location(artifact.get('reference'), artifact.get('digest'), published=True)
        if target:
            yield source, target


def _base_result(service_id, image_reference, **identity):
    return dict(service_id=service_id, image_reference=image_reference, registry=None,
                status='unavailable', reason=None, routes=[], **identity)


def _image_slot(artifacts, index):
    if not isinstance(artifacts, list) or not 0 <= index < len(artifacts):
        raise HTTPException(404, 'Container image not found in this release')
    artifact = artifacts[index]
    if not isinstance(artifact, dict) or artifact.get('kind') != 'image':
        raise HTTPException(404, 'Container image not found in this release')
    return artifact


@router.get('/api/services/{service_key}/artifacts/images/{image_id}/pull', response_model=InventoryImagePull)
def pull_instructions(service_key: str, image_id: int, db=Depends(get_db),
                      auth: AuthContext = Depends(require_permission('service.view', scoped=True)),
                      response: Response = None):
    if response is not None:
        response.headers['Cache-Control'] = 'private, no-store'
    service = db.scalar(select(Service).where(Service.service_key == service_key).execution_options(populate_existing=True))
    if service is None or not auth.has('service.view', service.id):
        raise HTTPException(404, 'Service not found')
    image = db.scalar(select(ServiceImage).where(ServiceImage.id == image_id, ServiceImage.service_id == service.id)
                      .execution_options(populate_existing=True))
    if image is None:
        raise HTTPException(404, 'Container image not found in this service')
    result = _base_result(service.id, image.image_reference, image_id=image.id)
    if image.lifecycle_status != 'active':
        return dict(result, reason='This container image is not active in the service inventory.')
    try:
        identity = _identity(image.image_reference, image.image_digest)
    except ValueError:
        return dict(result, reason='This image has no verified immutable digest. Complete its scan first.')
    return _pull_routes(db, service, result, image_locations(db, image, identity))


@router.get('/api/approved-releases/{identity}/artifacts/{artifact_index}/pull', response_model=ReleaseImagePull)
def release_pull_instructions(identity: int, artifact_index: int, response: Response, db=Depends(get_db),
                              auth: AuthContext = Depends(require_user)):
    """Resolve a zero-based snapshot artifact without consulting mutable service inventory."""
    from .cyber_approvals import _record, digest as snapshot_digest
    from .release_validity import summary
    from .release_revisions import ReleaseRevision, ServiceActiveRelease, active_revision
    response.headers['Cache-Control'] = 'private, no-store'
    approval = _record(db, auth, identity)
    if approval.status != 'approved':
        raise HTTPException(404, 'Approved release not found')
    snapshot = approval.snapshot
    if (not isinstance(snapshot, dict) or snapshot.get('service_id') != approval.service_id
            or snapshot_digest(snapshot) != approval.snapshot_digest):
        raise HTTPException(409, 'Retained approval snapshot integrity check failed')
    artifact = _image_slot(snapshot.get('artifacts'), artifact_index)
    result = _base_result(approval.service_id, artifact.get('reference'), release_id=identity, artifact_index=artifact_index)
    validity = summary(approval)['validity_status']
    if validity not in {'valid', 'expiring_soon'}:
        return dict(result, reason=f'This release cannot supply pull instructions. Approval status: {validity}.')
    managed = ('release_revision' in snapshot or db.get(ServiceActiveRelease, approval.service_id) is not None
               or db.scalar(select(ReleaseRevision.id).where(ReleaseRevision.service_id == approval.service_id).limit(1)) is not None)
    if managed:
        active = active_revision(db, approval.service_id)
        if active is None or active.approval_id != identity:
            return dict(result, reason='This release is not the active, verified release revision.')
    candidates = {target for _, target in _published_locations(approval, artifact_index)}
    if not artifact.get('resolve_at_publication') and not artifact.get('path') and artifact.get('format') != 'docker-archive':
        scanned = _location(artifact.get('reference'), artifact.get('digest'))
        if scanned:
            candidates.add(scanned)
    return _pull_routes(db, db.get(Service, approval.service_id), result, candidates)


@router.get('/api/replica/releases/{identity}/artifacts/{artifact_index}/pull', response_model=ReleaseImagePull)
def replica_pull_instructions(identity: int, artifact_index: int, response: Response, db=Depends(get_db),
                             auth: AuthContext = Depends(require_user)):
    """Use the signed imported inventory and its local registry repository."""
    from datetime import datetime, timezone
    from .oci_models import OCIUpstream
    from .replica_authorization import trusted_release, release_denial
    from .replica_models import ReplicaRelease, ReplicaServiceState
    response.headers['Cache-Control'] = 'private, no-store'
    release = db.get(ReplicaRelease, identity, populate_existing=True)
    if release is None or not auth.has('service.view', release.service_id):
        raise HTTPException(404, 'Release not found')
    state = db.get(ReplicaServiceState, release.service_id, populate_existing=True)
    now = datetime.now(timezone.utc)
    if not trusted_release(db, release, state, now):
        raise HTTPException(409, 'Imported release trust check failed')
    artifact = _image_slot(release.artifacts, artifact_index)
    repository = artifact.get('repository')
    result = _base_result(release.service_id, artifact.get('reference') or repository,
                          release_id=identity, artifact_index=artifact_index)
    denial = release_denial(release, state, now)
    if denial:
        return dict(result, reason=f'This imported release is {denial}.')
    upstream = db.get(OCIUpstream, state.upstream_id)
    if upstream is None or not REPOSITORY.fullmatch(str(repository or '')):
        return dict(result, reason='No verified registry repository is available for this release image.')
    reference = urlsplit(upstream.endpoint).netloc + '/' + repository
    target = _location(reference, artifact.get('digest'), published=True)
    return _pull_routes(db, db.get(Service, release.service_id), result, {target} if target else set())


def _pull_routes(db, service, result, candidates):
    from . import oci_proxy as proxy
    from .oci_authorization import authorize
    from .main import service_lifecycle
    try:
        result['registry'] = registry_authority()
    except ValueError:
        return dict(result, reason='The configured CATS OCI hostname is invalid. Ask an administrator to correct it.')
    if result['registry'] is None:
        return dict(result, reason='The CATS OCI hostname is not configured. Ask an administrator to set CATS_OCI_HOSTNAME.')
    db.expire(service, ['archive_events'])
    if service_lifecycle(service) != 'active':
        return dict(result, reason='This service is not active and cannot distribute images.')
    if not candidates:
        return dict(result, reason='No verified image identity binds this container to a distribution repository.')
    mappings = list(db.scalars(select(OCIRepository).where(or_(OCIRepository.service_id == service.id,
                                                               OCIRepository.service_id.is_(None)))
                              .execution_options(populate_existing=True)))
    public_pull = service_pull_is_public(db, service.id)
    routes, matched = {}, False
    for mapping in mappings:
        if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
            continue
        for source, digest, published in sorted(candidates):
            try:
                location = _registry_path(source, urlsplit(mapping.upstream.endpoint).netloc, explicit_host=published)
                if not location or not REPOSITORY.fullmatch(location):
                    continue
                if is_project_pattern(mapping.public_repository):
                    logical = project_repository(mapping.public_repository, mapping.upstream_repository, location)
                    route = service_repository(logical, service.id)
                else:
                    route = service_repository(mapping.public_repository, service.id)
                # Respect exact-map precedence and the same service/active-route
                # checks as an actual pull; do not advertise a shadowed wildcard.
                actual = proxy.mapping_for(db, route)
                routed = proxy.effective_mapping(db, actual, digest)
                if (actual.service_id != service.id or actual.upstream_id != mapping.upstream_id
                        or routed.upstream_repository != location):
                    continue
                matched = True
                if not authorize(db, actual, digest).allowed:
                    continue
            except (ValueError, proxy.Denied):
                continue
            reference = f"{result['registry']}/{route}@{digest}"
            routes[reference] = dict(repository=route, digest=digest, reference=reference,
                command='docker pull ' + shlex.quote(reference),
                anonymous_pull=public_pull, login_required=not public_pull,
                login_command=None if public_pull else 'docker login ' + shlex.quote(result['registry']))
    if not routes:
        return dict(result, reason="This image does not meet the service's current OCI pull policy." if matched
                    else 'No enabled CATS repository mapping serves this image for this service.')
    result.update(status='available', routes=[routes[key] for key in sorted(routes)])
    return result
