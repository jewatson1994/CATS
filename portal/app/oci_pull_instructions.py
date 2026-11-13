"""Read-only, digest-pinned pull instructions from the live OCI approval path."""
import ipaddress
import os
import re
import shlex
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import or_, select

from .auth import AuthContext, require_permission
from .cyber_approval_evidence import _identity, _registry_path, _repository_identity
from .database import get_db
from .models import Service, ServiceImage
from .oci_models import OCIRepository, is_project_pattern, project_repository, service_repository
from .oci_transport import DIGEST, REPOSITORY

router = APIRouter(tags=['OCI pull instructions'])


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

    from .cyber_approvals import CyberApproval
    # Retained scan identity is also a candidate for a direct upstream mapping.
    locations.add((*image_identity, False))
    for approval in db.scalars(select(CyberApproval).where(CyberApproval.service_id == image.service_id)
                               .execution_options(populate_existing=True)):
        snapshot, receipt = approval.snapshot or {}, approval.publication or {}
        manifest = receipt.get('manifest') or {}
        if (approval.publish_status != 'published' or receipt.get('status') != 'published'
                or receipt.get('verification_status') != 'verified' or receipt.get('signature_status') != 'verified'
                or manifest.get('approval_id') != approval.id
                or manifest.get('snapshot_digest') != approval.snapshot_digest
                or manifest.get('artifacts') != receipt.get('artifacts')):
            continue
        originals = snapshot.get('artifacts', [])
        for index, artifact in enumerate(receipt.get('artifacts', [])):
            if not isinstance(artifact, dict) or artifact.get('kind') != 'image' or index >= len(originals):
                continue
            source = originals[index]
            if (not isinstance(source, dict) or source.get('kind') != 'image'
                    or not same_image(source.get('reference'), source.get('digest'), image_identity)
                    or artifact.get('source_digest') != source.get('digest')
                    or artifact.get('scan_identity_retained') is not True
                    or artifact.get('identity_resolution') != 'retained-evidence'
                    or artifact.get('verification_status') != 'verified'):
                continue
            target = _location(artifact.get('reference'), artifact.get('digest'), published=True)
            if target:
                locations.add(target)
    return locations


@router.get('/api/services/{service_key}/artifacts/images/{image_id}/pull')
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
    result = dict(service_id=service.id, image_id=image.id, image_reference=image.image_reference,
                  registry=None, status='unavailable', reason=None, routes=[])

    def unavailable(reason):
        result['reason'] = reason
        return result

    try:
        result['registry'] = registry_authority()
    except ValueError:
        return unavailable('The configured CATS OCI hostname is invalid. Ask an administrator to correct it.')
    if result['registry'] is None:
        return unavailable('The CATS OCI hostname is not configured. Ask an administrator to set CATS_OCI_HOSTNAME.')
    from .main import service_lifecycle
    db.expire(service, ['archive_events'])
    if service_lifecycle(service) != 'active':
        return unavailable('This service is not active and cannot distribute images.')
    if image.lifecycle_status != 'active':
        return unavailable('This container image is not active in the service inventory.')
    try:
        identity = _identity(image.image_reference, image.image_digest)
    except ValueError:
        return unavailable('This image has no verified immutable digest. Complete its scan and release approval first.')

    from . import oci_proxy as proxy
    from .oci_authorization import authorize
    candidates = image_locations(db, image, identity)
    if not candidates:
        return unavailable('No verified approved release binds this image to a distribution repository.')
    mappings = list(db.scalars(select(OCIRepository).where(or_(OCIRepository.service_id == service.id,
                                                               OCIRepository.service_id.is_(None)))
                              .execution_options(populate_existing=True)))
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
                login_command='docker login ' + shlex.quote(result['registry']))
    if not routes:
        return unavailable('The approved release for this service does not currently authorize this image.' if matched
                           else 'No enabled CATS repository mapping serves this image for this service.')
    result.update(status='available', routes=[routes[key] for key in sorted(routes)])
    return result
