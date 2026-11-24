"""Versioned service release drafts prepared from explicitly assigned runtime applications."""
from datetime import datetime
import hashlib
import json
import re
from urllib.parse import urlsplit
import os

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint, event, inspect, select
from sqlalchemy.orm import Mapped, load_only, mapped_column

from .auth import record_audit
from .database import Base
from .models import Service
from .oci_models import OCIRepository, service_repository
from .runtime_models import RuntimeEnvironment, now
from .runtime_image_manifests import IMAGE_TYPES, INDEX_BLOCKER, INDEX_TYPES
from .runtime_policy import _actual_identity, _fully_qualified


class RuntimeReleaseCandidate(Base):
    __tablename__ = 'runtime_release_candidates'
    __table_args__ = (UniqueConstraint('environment_id', 'service_id', 'namespace', 'version'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey('runtime_environments.id', ondelete='CASCADE'), index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey('services.id', ondelete='CASCADE'), index=True)
    namespace: Mapped[str] = mapped_column(String(255))
    version: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str] = mapped_column(String(64))
    inventory: Mapped[dict] = mapped_column(JSON)
    proposed_version: Mapped[str] = mapped_column(String(120))
    current: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    status: Mapped[str] = mapped_column(String(24), default='draft')
    approval_id: Mapped[int | None] = mapped_column(Integer)
    # Links point to locally bound scanner receipts. They are distinct from immutable observed inventory.
    jobs: Mapped[dict] = mapped_column(JSON, default=dict)
    resolution_diagnostics: Mapped[dict | None] = mapped_column(JSON, default=dict)
    execution_id: Mapped[int | None] = mapped_column(Integer)
    assessment_status: Mapped[str] = mapped_column(String(24), default='pending')
    assessment_error: Mapped[str | None] = mapped_column(String(500))
    assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


@event.listens_for(RuntimeReleaseCandidate, 'before_update')
def _preserve_inventory(mapper, connection, row):
    fields = ('environment_id', 'service_id', 'namespace', 'version', 'fingerprint', 'inventory', 'proposed_version')
    if any(inspect(row).attrs[field].history.has_changes() for field in fields):
        raise ValueError('Observed candidate inventory is immutable. Create a revision for changed inventory.')


def checksum(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _applications(applications):
    from .runtime_applications import release_components
    return [{'id': app.id, 'identity': app.identity, 'name': app.name, 'components': release_components(app.components)}
            for app in sorted(applications, key=lambda a: a.identity)]


def _registry_request(value):
    """Parse a fully qualified tag or digest without Docker's default registry or repository rewrites."""
    if not isinstance(value, str) or '://' in value:
        return None
    if '@' in value:
        ident = _actual_identity({'image_id': value})
        return ident if ident and _fully_qualified(ident[0]) else None
    last = value.rsplit('/', 1)[-1]
    tag = last.rsplit(':', 1)[1] if ':' in last else 'latest'
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag):
        return None
    ident = _actual_identity({'image_id': value + '@sha256:' + '0' * 64})
    return (ident[0], ident[1], tag) if ident and _fully_qualified(ident[0]) else None


def conflicting_tag_repository(item):
    actual = _actual_identity(item)
    for ref in (item.get('image_ref'), item.get('desired_image')):
        if actual and ref and '@' not in ref:
            wanted = _registry_request(ref)
            if wanted and wanted[:2] != actual[:2]:
                return f'{ref}: the requested image repository differs from the running image.'
    return None


def _inventory(environment, apps, namespace, resolutions):
    images, charts, blockers, slots = {}, {}, set(), {}
    unresolved = set()
    def image(identity, provenance):
        host, path, digest = identity
        ref = f'{host}/{path}@{digest}'
        asset = images.setdefault(ref, {'kind': 'image', 'reference': ref, 'digest': digest, 'observed': False, 'desired': False})
        asset[provenance] = True
        return ref
    for app in apps:
        for item in app['components']:
            slot = tuple(item.get(k, '') for k in ('workload_kind', 'workload', 'workload_uid', 'container_kind', 'container'))
            label = '/'.join(str(x) for x in (slot[0], slot[1], slot[-1]) if x)
            running_ref = item.get('image_ref') or ''
            desired = item.get('desired_image') or running_ref
            actual = _actual_identity(item)
            # A CRI bare value may be a config ID. A repository manifest whose *bytes*
            # hash to that ID independently proves identity for the coincident Pod spec pin.
            pod_pin = _actual_identity({'image_id': running_ref})
            if (not actual and environment.kind == 'kubernetes' and pod_pin and _fully_qualified(pod_pin[0])
                    and item.get('image_id') == pod_pin[2]):
                proof = resolutions.get(running_ref)
                if proof and proof['digest'] == pod_pin[2] and proof.get('media_type') in IMAGE_TYPES:
                    actual = pod_pin
                elif proof and proof.get('media_type') in INDEX_TYPES:
                    blockers.add(f'{label}: {INDEX_BLOCKER}')
                else:
                    unresolved.add(running_ref)
            desired_pin = _actual_identity({'image_id': desired})
            mutable_desired = not desired_pin
            conflict = conflicting_tag_repository(item)
            if conflict:
                blockers.add(conflict)
            if not desired_pin and (not actual or desired != running_ref or conflict):
                if desired in resolutions:
                    desired_pin = _actual_identity({'image_id': resolutions[desired]['reference']})
                elif _registry_request(desired):
                    unresolved.add(desired)
            if desired_pin:
                image(desired_pin, 'desired')
            if pod_pin and pod_pin != desired_pin and pod_pin != actual:
                image(pod_pin, 'desired')
                blockers.add(f'{label}: the Pod image pin differs from the running identity or workload template.')
            if not actual:
                blockers.add(f'{label}: no immutable repository digest observed for {desired or "this container"}.')
            else:
                ref = image(actual, 'observed')
                slots.setdefault((app['identity'], slot), set()).add(ref)
                if desired_pin and desired_pin != actual:
                    blockers.add(f'{label}: the desired image pin differs from the running image.')
                elif running_ref and desired != running_ref and mutable_desired:
                    blockers.add(f'{label}: the running container spec differs from its workload template. Await rollout convergence.')
            if item.get('helm_release') or item.get('chart_name') or item.get('chart_version'):
                key = tuple(item.get(k, '') for k in ('helm_namespace', 'helm_release', 'chart_name', 'chart_version', 'chart_digest'))
                charts[key] = dict(zip(('namespace', 'release', 'name', 'version', 'digest'), key), kind='chart')
                charts[key]['digest'] = key[-1] or None
    if any(len(refs) > 1 for refs in slots.values()):
        blockers.add('Multiple image digests are running in the same workload container. Await rollout convergence.')
    releases = {}
    for namespace_name, release, name, version, digest in charts:
        if release:
            releases.setdefault((namespace_name, release), set()).add((name, version, digest))
    if any(len(identities) > 1 for identities in releases.values()):
        blockers.add('Multiple chart identities are reported for the same Helm release. Await rollout convergence.')
    if not any(asset['observed'] for asset in images.values()):
        blockers.add('No running immutable image identities were observed.')
    return {'source': {'environment_id': environment.id, 'cluster': environment.name,
                       'role': environment.cluster_role, 'namespace': namespace},
            'applications': apps, 'images': [images[key] for key in sorted(images)],
            'charts': [charts[key] for key in sorted(charts)], 'blockers': sorted(blockers),
            'registry_resolutions': resolutions, 'unresolved_image_requests': sorted(unresolved)}


def reconcile(db, environment, service, applications, namespace, *, registry_resolutions=None):
    """Caller holds the environment write lock; serialize candidate and assessment changes too."""
    if service is None:
        return None
    previous = db.scalar(select(RuntimeReleaseCandidate).where(
        RuntimeReleaseCandidate.environment_id == environment.id, RuntimeReleaseCandidate.service_id == service.id,
        RuntimeReleaseCandidate.namespace == namespace).order_by(RuntimeReleaseCandidate.version.desc())
        .limit(1).with_for_update())
    if environment.cluster_role not in ('development', 'validation'):
        applications = []
    apps = _applications(applications)
    retained = (previous.inventory.get('registry_resolutions', {}) if previous and previous.current
                and previous.inventory['applications'] == apps else {})
    inventory = _inventory(environment, apps, namespace, registry_resolutions if registry_resolutions is not None else retained) if apps else None
    fingerprint = checksum(inventory) if inventory else None
    if previous and previous.current and previous.fingerprint == fingerprint:
        return previous
    if previous and previous.current:
        previous.current = False
        record_audit(db, None, 'runtime.candidate.superseded', 'runtime_candidate', previous.id,
                     service_id=service.id, fingerprint=previous.fingerprint)
    if not inventory:
        return None
    version = previous.version + 1 if previous else 1
    labels = {c['app_version'] for app in inventory['applications'] for c in app['components'] if c.get('app_version')}
    fallback = (service.current_version.version if service.current_version else service.manual_version) or 'release'
    suffix = f'-runtime.{version}'
    label = next(iter(labels)) if len(labels) == 1 else ''
    proposed = label if 0 < len(label) <= 120 and all(ch.isprintable() for ch in label) else fallback[:120-len(suffix)] + suffix
    row = RuntimeReleaseCandidate(environment_id=environment.id, service_id=service.id, namespace=namespace,
        version=version, fingerprint=fingerprint, inventory=inventory, proposed_version=proposed, current=True,
        jobs={}, status='draft', assessment_status='pending')
    db.add(row)
    db.flush()
    record_audit(db, None, 'runtime.candidate.created', 'runtime_candidate', row.id,
                 service_id=service.id, environment_id=environment.id, namespace=namespace,
                 fingerprint=fingerprint, revision=version)
    return row


def require_current(db, candidate, service):
    from .runtime_applications import in_scope
    from .service_ownership import active_service_predicate
    if not candidate or not service or candidate.service_id != service.id:
        raise ValueError('Runtime candidate does not belong to this service.')
    env = db.scalar(select(RuntimeEnvironment).where(RuntimeEnvironment.id == candidate.environment_id)
                    .with_for_update().execution_options(populate_existing=True))
    row = db.scalar(select(RuntimeReleaseCandidate).where(RuntimeReleaseCandidate.id == candidate.id)
                    .with_for_update().execution_options(populate_existing=True))
    from .imported_services import is_imported_service
    if (not env or not row or not row.current or env.kind != 'kubernetes'
            or env.cluster_role not in ('development', 'validation')
            or env.cluster_role != row.inventory['source']['role']
            or not db.scalar(select(Service.id).where(Service.id == service.id, active_service_predicate()))
            or is_imported_service(db, service.id)
            or not in_scope(env, service.id) or checksum(row.inventory) != row.fingerprint):
        raise ValueError('Runtime inventory changed or this candidate is no longer eligible. Open the current draft.')
    return row


def registry_mapping(db, service_id, host, path):
    """Only a concrete enabled mapping may select the remote host, repository and credentials."""
    from .cyber_approval_evidence import _registry_name
    gateway = _registry_name(os.environ.get('CATS_OCI_HOSTNAME', '').lower())
    query = select(OCIRepository).where(OCIRepository.service_id == service_id, OCIRepository.enabled.is_(True),
                                        OCIRepository.suspended.is_(False))
    for mapping in db.scalars(query):
        if not mapping.upstream.enabled:
            continue
        upstream = _registry_name(urlsplit(mapping.upstream.endpoint).netloc)
        try:
            public = service_repository(mapping.public_repository, service_id)
        except ValueError:
            continue
        if '.' not in upstream and ':' not in upstream and upstream != 'localhost':
            continue  # Container pull clients interpret this segment as a Docker Hub namespace.
        if (host, path) == (upstream, mapping.upstream_repository) or (host, path) == (gateway, public):
            return mapping, upstream
    return None


def trusted_scan_reference(db, service_id, observed):
    identity = _actual_identity({'image_id': observed})
    if identity:
        matched = registry_mapping(db, service_id, *identity[:2])
        if matched:
            mapping, upstream = matched
            return f'{upstream}/{mapping.upstream_repository}@{identity[2]}'
    return None


def summary(row):
    return dict(id=row.id, environment_id=row.environment_id, service_id=row.service_id, namespace=row.namespace,
                version=row.version, proposed_version=row.proposed_version, fingerprint=row.fingerprint,
                status=row.status, current=row.current, approval_id=row.approval_id, assessment_status=row.assessment_status,
                created_at=row.created_at.isoformat())


def list_candidates(db, environment_id=None, service_id=None):
    row = RuntimeReleaseCandidate
    query = select(row).options(load_only(row.id, row.environment_id, row.service_id, row.namespace,
        row.version, row.proposed_version, row.fingerprint, row.status, row.current, row.approval_id,
        row.assessment_status, row.created_at))
    if environment_id is not None:
        query = query.where(RuntimeReleaseCandidate.environment_id == environment_id)
    if service_id is not None:
        query = query.where(RuntimeReleaseCandidate.service_id == service_id)
    return [summary(row) for row in db.scalars(query.order_by(RuntimeReleaseCandidate.id.desc()))]


def assessment_for_review(db, candidate, service):
    from .runtime_candidate_assessment import assess
    row = require_current(db, candidate, service)
    return assess(db, row, service)
