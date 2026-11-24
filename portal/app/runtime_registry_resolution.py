"""Resolve missing candidate inventory through the service's configured OCI origin."""
import hashlib
import json
import ssl
from dataclasses import dataclass
from types import SimpleNamespace

from sqlalchemy import select, update

from . import oci_proxy
from .models import PortalSetting, Service
from .oci_models import OCIManifest
from .oci_transport import RegistryError
from .runtime_candidates import RuntimeReleaseCandidate, _registry_request, checksum, reconcile, registry_mapping, require_current
from .runtime_models import RuntimeEnvironment, now
from .runtime_image_manifests import INDEX_TYPES


DIAGNOSTIC_LIMIT = 64
FAILURES = {
    'unmapped': 'Configure an enabled service-owned OCI mapping for this repository.',
    'authentication': 'Registry access was denied. Check the mapped credentials, token realm and repository pull permissions.',
    'not_found': 'The registry could not find this reference. Check the mapped repository and tag or digest.',
    'tls': 'Registry TLS verification or negotiation failed. Check the upstream hostname, certificate and trusted CA.',
    'transport': 'The registry lookup failed. Check upstream availability, DNS and connectivity.',
    'configuration': 'Check the mapped upstream credentials, trusted CA and approved registry origins.',
    'integrity': 'The registry manifest failed content validation. Verify its digest, media type, size and mirrored bytes.',
}


def resolution_blockers(candidate):
    unresolved = set(candidate.inventory.get('unresolved_image_requests', []))
    diagnostics = candidate.resolution_diagnostics or {}
    return [f'{request}: {FAILURES[diagnostics[request]["reason"]]}'
            for request in sorted(unresolved.intersection(diagnostics))
            if diagnostics[request].get('reason') in FAILURES]


@dataclass
class Attempt:
    config: tuple | None
    started_at: str
    reason: str | None = None
    resolution: dict | None = None


def _verified_manifest(raw, media, claimed, requested):
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if (digest != claimed or (requested.startswith('sha256:') and digest != requested)
            or media not in oci_proxy.MANIFEST_TYPES):
        raise ValueError('Registry image identity mismatch')
    doc = json.loads(raw)
    if (not isinstance(doc, dict) or doc.get('schemaVersion') != 2 or doc.get('artifactType')
            or doc.get('mediaType', media) != media):
        raise ValueError('Invalid image manifest')
    if media in INDEX_TYPES:
        entries = doc.get('manifests')
        if not isinstance(entries, list) or not 0 < len(entries) <= 256:
            raise ValueError('Invalid image index')
    else:
        config, layers = doc.get('config'), doc.get('layers')
        if ('manifests' in doc or not isinstance(config, dict) or config.get('mediaType') not in {
                'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}
                or not isinstance(layers, list) or len(layers) > 512):
            raise ValueError('Invalid image configuration')
        entries = [config, *layers]
    for entry in entries:
        oci_proxy.descriptor(entry)
    return digest


def _current(db, row, service):
    try:
        eligible = require_current(db, row, service)
    except ValueError:
        return None
    return eligible if eligible.status in ('draft', 'returned') else None


def _binding(db, service, identity):
    matched = registry_mapping(db, service.id, *identity[:2])
    if not matched:
        return None, None
    mapping, _ = matched
    origin = mapping.upstream
    trust = db.scalar(select(PortalSetting.value).where(PortalSetting.group_id.is_(None),
                                                        PortalSetting.key == 'trusted_ca_certificates'))
    # Used only in memory to reject answers from a mapping or trust configuration edited in flight.
    settings = checksum([origin.endpoint, origin.username, origin.password, origin.ca_pem, trust,
                         origin.token_realms, origin.redirect_origins])
    return mapping, (mapping.id, mapping.upstream_id, mapping.upstream_repository, settings)


def _failure(exc, default='transport'):
    if isinstance(exc, ssl.SSLError):
        return 'tls'
    if isinstance(exc, RegistryError):
        if exc.category in FAILURES:
            return exc.category
        if exc.status in (401, 403):
            return 'authentication'
        if exc.status == 404:
            return 'not_found'
    return default


def _resolve_one(session_factory, candidate_id, requested, budget):
    identity = _registry_request(requested)
    if not identity:
        return None
    cached = None
    with session_factory() as db:
        row = db.get(RuntimeReleaseCandidate, candidate_id)
        service = db.get(Service, row.service_id) if row else None
        row = _current(db, row, service)
        if not row or requested not in row.inventory.get('unresolved_image_requests', []):
            return None
        mapping, config = _binding(db, service, identity)
        attempt = Attempt(config, now().isoformat(timespec='microseconds'))
        if not mapping:
            attempt.reason = 'unmapped'
            return attempt
        if identity[2].startswith('sha256:'):
            manifest = db.scalar(select(OCIManifest).filter_by(repository_id=mapping.id, digest=identity[2]))
            if manifest:
                cached = (manifest.content.encode('utf-8'), manifest.media_type, manifest.digest)
        if not cached:
            if budget[0] <= 0:
                return None
            budget[0] -= 1
            try:
                transport = oci_proxy.client(mapping)
                transport.timeout = min(transport.timeout, 4)
            except (ValueError, OSError) as exc:
                attempt.reason = _failure(exc, 'configuration')
                return attempt
    try:
        raw, media, claimed = cached or transport.fetch_manifest(config[2], identity[2])
    except (ValueError, OSError) as exc:
        attempt.reason = _failure(exc)
        return attempt
    try:
        digest = _verified_manifest(raw, media, claimed, identity[2])
    except (TypeError, ValueError, RecursionError):
        attempt.reason = 'integrity'
        return attempt
    attempt.resolution = {
        'reference': f'{identity[0]}/{identity[1]}@{digest}', 'digest': digest, 'media_type': media,
        'repository_id': config[0], 'source': 'configured_oci_manifest', 'resolved_at': attempt.started_at}
    return attempt


def _persist(db, candidate_id, attempts):
    # SQLite ignores SELECT FOR UPDATE. Serialize only the short result transaction, after all I/O.
    if db.get_bind().dialect.name == 'sqlite':
        locked = db.execute(update(RuntimeReleaseCandidate).where(
            RuntimeReleaseCandidate.id == candidate_id, RuntimeReleaseCandidate.current.is_(True),
            RuntimeReleaseCandidate.status.in_(('draft', 'returned'))).values(current=RuntimeReleaseCandidate.current))
        if not locked.rowcount:
            return candidate_id
    row = db.get(RuntimeReleaseCandidate, candidate_id)
    if not row:
        return candidate_id
    service = db.get(Service, row.service_id, with_for_update=True)
    row = _current(db, row, service)
    if not row:
        return candidate_id
    diagnostics = dict(row.resolution_diagnostics or {})
    verified = dict(row.inventory.get('registry_resolutions', {}))
    for requested, attempt in attempts.items():
        if (requested not in row.inventory.get('unresolved_image_requests', [])
                or diagnostics.get(requested, {}).get('started_at', '') >= attempt.started_at):
            continue
        _, config = _binding(db, service, _registry_request(requested))
        if attempt.config != config:
            continue
        if attempt.reason:
            diagnostics[requested] = {'reason': attempt.reason, 'started_at': attempt.started_at}
        else:
            verified[requested] = attempt.resolution
    if verified != row.inventory.get('registry_resolutions', {}):
        env = db.get(RuntimeEnvironment, row.environment_id)
        apps = [SimpleNamespace(**app) for app in row.inventory['applications']]
        row = reconcile(db, env, service, apps, row.namespace, registry_resolutions=verified)
    unresolved = set(row.inventory.get('unresolved_image_requests', []))
    recent = sorted(unresolved.intersection(diagnostics), key=lambda ref: (diagnostics[ref]['started_at'], ref))
    row.resolution_diagnostics = {ref: diagnostics[ref] for ref in recent[-DIAGNOSTIC_LIMIT:]}
    db.commit()
    return row.id


def resolve_requests(session_factory, candidate_id, budget):
    """Fetch bounded metadata outside database locks. Changed resolutions create a new auditable revision."""
    with session_factory() as db:
        row = db.get(RuntimeReleaseCandidate, candidate_id)
        requests = row.inventory.get('unresolved_image_requests', []) if row and row.current else []
    if not requests:
        return candidate_id
    # Rotate the starting item so an unreachable origin cannot starve sibling requests.
    start = int(now().timestamp() // 60) % len(requests)
    attempts = {}
    for requested in (requests[start:] + requests[:start])[:8]:
        attempt = _resolve_one(session_factory, candidate_id, requested, budget)
        if attempt:
            attempts[requested] = attempt
    if attempts:
        with session_factory() as db:
            return _persist(db, candidate_id, attempts)
    return candidate_id
