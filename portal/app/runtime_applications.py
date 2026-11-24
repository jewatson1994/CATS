"""Reconcile complete cluster inventories under the environment write lock."""
from collections import defaultdict
from datetime import datetime
import hashlib
import json

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, mapped_column

from .auth import record_audit
from .database import Base
from .models import Service
from .operating_mode import is_replica
from .release_validity import utc
from .runtime_models import RuntimeEnvironment, now
from .service_ownership import active_service_predicate


class RuntimeApplication(Base):
    __tablename__ = 'runtime_applications'
    __table_args__ = (UniqueConstraint('environment_id', 'identity'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    environment_id: Mapped[int] = mapped_column(ForeignKey('runtime_environments.id'), index=True)
    identity: Mapped[str] = mapped_column(String(64))
    namespace: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    service_id: Mapped[int | None] = mapped_column(ForeignKey('services.id', ondelete='SET NULL'), index=True)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    # Only a human assignment binds these workload identities to a service.
    members: Mapped[list] = mapped_column(JSON, default=list)
    components: Mapped[list] = mapped_column(JSON, default=list)
    fingerprint: Mapped[str] = mapped_column(String(64))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


def checksum(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def workload_key(row):
    # A newly created controller cannot inherit a mapping by copying its labels.
    return checksum([row.get(key, '') for key in (
        'namespace', 'namespace_uid', 'workload_kind', 'workload', 'workload_uid')])


def inferred(row):
    for field in ('helm_release', 'app_part_of', 'app_instance', 'app_name'):
        if row.get(field):
            return field, row[field]
    return 'workload', row['workload']


def components(rows):
    """Collapse replicas while retaining every distinct desired and observed image."""
    fields = ('namespace', 'namespace_uid', 'workload_uid', 'workload', 'workload_kind', 'container', 'container_kind',
              'chart_name', 'chart_version', 'chart_digest', 'helm_release', 'helm_namespace', 'app_name', 'app_part_of',
              'app_instance', 'app_version', 'service_hint', 'image_ref', 'image_id', 'desired_image')
    by_slot = defaultdict(dict)
    for row in rows:
        component = {key: row.get(key, '') for key in fields}
        component['member'] = workload_key(row)
        slot = (workload_key(row), component['container_kind'], component['container'],
                component['desired_image'] or component['image_ref'])
        by_slot[slot][checksum(component)] = component
    result = {}
    for variants in by_slot.values():
        # A template without a runtime digest describes the same slot as its pods.
        observed = [item for item in variants.values() if item['image_id']]
        for item in observed or variants.values():
            result[checksum(item)] = item
    return [result[key] for key in sorted(result)]


def release_components(rows):
    """A service assignment fixes ownership. Correlation hints do not change its artifacts."""
    unique = {}
    for row in rows:
        component = {key: value for key, value in row.items()
                     if key not in ('service_hint', 'app_name', 'app_instance', 'app_part_of')}
        unique[checksum(component)] = component
    return [unique[key] for key in sorted(unique)]


def in_scope(env, service_id):
    return env.service_scope == 'all' or service_id in (env.service_ids or [])


def prepare(db, env, scopes):
    if not scopes or is_replica():
        return
    from .imported_services import is_imported_service
    from .runtime_candidates import reconcile
    db.flush()
    for service_id, namespace in sorted(scopes):
        service = db.get(Service, service_id)
        if not service or is_imported_service(db, service_id):
            continue
        eligible = (env.cluster_role in ('development', 'validation') and in_scope(env, service_id)
                    and db.scalar(select(Service.id).where(Service.id == service_id, active_service_predicate())))
        apps = list(db.scalars(select(RuntimeApplication).where(
            RuntimeApplication.environment_id == env.id, RuntimeApplication.namespace == namespace,
            RuntimeApplication.present.is_(True), RuntimeApplication.service_id == service_id)
            .order_by(RuntimeApplication.id))) if eligible else []
        reconcile(db, env, service, apps, namespace)


def reconcile_inventory(db, env, observed, workloads):
    if env.kind != 'kubernetes' or (env.discovery_observed_at and observed <= utc(env.discovery_observed_at)):
        return
    env.discovery_observed_at = observed
    apps = list(db.scalars(select(RuntimeApplication).where(RuntimeApplication.environment_id == env.id)))
    known = {key: app for app in apps for key in app.members}
    existing_identities = {app.identity for app in apps}
    grouped = defaultdict(list)
    new = defaultdict(list)
    by_workload = defaultdict(list)
    for row in workloads:
        if row.get('namespace') and row.get('workload'):
            by_workload[workload_key(row)].append(row)
    for key, batch in by_workload.items():
        batch.sort(key=lambda row: (row.get('state') != 'desired', row['uid']))
        row = batch[0]
        app = known.get(key)
        if app:
            grouped[app].extend(batch)
        else:
            group = (row['namespace'], row.get('namespace_uid', ''), *inferred(row))
            new[group].extend(batch)
    unassigned = defaultdict(list)
    for app, batch in grouped.items():
        if app.service_id is None:
            first = batch[0]
            unassigned[(first['namespace'], first.get('namespace_uid', ''), *inferred(first))].append(app)
    for group, rows in new.items():
        namespace, _, _, name = group
        # Group previously unseen components for review. Only an unassigned record
        # can gain new members based on untrusted Helm metadata or application labels.
        matches = unassigned[group]
        if len(matches) == 1:
            grouped[matches[0]].extend(rows)
            continue
        identity = checksum(sorted({workload_key(row) for row in rows}))
        # A manager may have bound the original record to only its other controllers.
        if identity in existing_identities:
            identity = checksum([identity, observed.isoformat()])
        app = RuntimeApplication(environment_id=env.id, identity=identity, namespace=namespace, name=name,
                                 discovered_at=observed, last_observed_at=observed, members=[], components=[],
                                 present=True, fingerprint='')
        db.add(app)
        grouped[app] = rows
    scopes = set()
    for app, rows in grouped.items():
        inventory = components(rows)
        fingerprint = checksum(inventory)
        changed = fingerprint != app.fingerprint or not app.present
        first = not app.fingerprint
        app.last_observed_at = observed
        if changed:
            changed_inventory = not app.present or release_components(app.components) != release_components(inventory)
            app.present, app.components, app.fingerprint = True, inventory, fingerprint
            if app.service_id is None:
                app.members = sorted(set(app.members) | {workload_key(row) for row in rows})
            db.flush()
            if first or changed_inventory:
                record_audit(db, None, 'runtime.application.discovered' if first else 'runtime.application.changed',
                             'runtime_application', app.id, fingerprint=fingerprint, environment_id=env.id)
        if app.service_id:
            scopes.add((app.service_id, app.namespace))
    for app in apps:
        if app.present and app not in grouped:
            app.present = False
            record_audit(db, None, 'runtime.application.absent', 'runtime_application', app.id,
                         fingerprint=app.fingerprint, environment_id=env.id)
            if app.service_id:
                scopes.add((app.service_id, app.namespace))
    prepare(db, env, scopes)


def mapping_index(db, environment_ids):
    return {(app.environment_id, member): app for app in db.scalars(select(RuntimeApplication)
            .where(RuntimeApplication.environment_id.in_(environment_ids), RuntimeApplication.present.is_(True)))
            for member in app.members}


def _approved_components(db, service_id, timestamp, cache, approval_id=None):
    """Return current authority and its slot pins. Empty pins denote a legacy image-only release."""
    from . import release_revisions, replica_authorization
    from .cyber_approvals import CyberApproval
    from .imported_services import uses_imported_evidence
    from .oci_compliance_imported import _captured_execution
    from .replica_models import ReplicaRelease
    from .runtime_policy import _actual_identity, _bound_snapshot

    authority = {}
    try:
        children = {}
        if cache.get(uses_imported_evidence, db, service_id):
            state = cache.get(replica_authorization._state, db, service_id)
            if state is None or not state.active_release_id:
                return authority, None
            authority = {'release_id': state.active_release_id}
            release = db.get(ReplicaRelease, state.active_release_id, populate_existing=True)
            if (not replica_authorization.trusted_release(db, release, state, timestamp)
                    or replica_authorization.release_denial(release, state, timestamp)):
                return authority, None
            # The importer seals the capture digest. Verify the stored bytes and original service binding.
            _captured_execution(release, state)
            snapshot = release.evidence_state['extension']['approval_context']
            for artifact in release.artifacts:
                if artifact.get('kind') == 'image':
                    children.setdefault(artifact['digest'], set()).update(artifact.get('manifests', []))
        else:
            revision = cache.get(release_revisions.active_revision, db, service_id, timestamp)
            if revision is None:
                pointer = db.get(release_revisions.ServiceActiveRelease, service_id)
                if pointer and pointer.revision_id:
                    return {'revision_id': pointer.revision_id}, None
                if not approval_id:
                    return authority, None
            authority = {'approval_id': revision.approval_id if revision else approval_id}
            approval = db.get(CyberApproval, authority['approval_id'], populate_existing=True)
            if (not approval or approval.service_id != service_id or approval.status != 'approved'
                    or not _bound_snapshot(approval)):
                return authority, None
            snapshot = approval.snapshot
            if revision is None and ('release_revision' in snapshot or 'runtime_evidence' in snapshot):
                return authority, None

        if 'runtime_evidence' not in snapshot:
            return authority, None if snapshot.get('evidence_scope') == 'runtime-release-candidate' else {}
        applications = snapshot['runtime_evidence']['applications']
        if not isinstance(applications, list) or not applications:
            return authority, None
        slots = {}
        for app in applications:
            if not isinstance(app['components'], list) or not app['components']:
                return authority, None
            for component in app['components']:
                key = tuple(component[k] for k in ('workload_kind', 'workload', 'container_kind', 'container'))
                identity = _actual_identity(component)
                if identity is None:
                    # The candidate assessment independently verifies bare CRI IDs against pinned Pod specs.
                    identity = _actual_identity({'image_id': component.get('image_ref')})
                    if not identity or identity[2] != component.get('image_id'):
                        return authority, None
                if not all(isinstance(k, str) and k for k in key):
                    return authority, None
                accepted = {identity[2], *children.get(identity[2], ())}
                if key in slots and slots[key] != accepted:
                    return authority, None
                slots[key] = accepted
        return authority, slots
    except (KeyError, AttributeError, TypeError, ValueError):
        return authority, None


def production_decision(db, decision, observation, service_id, timestamp, cache):
    from .runtime_policy import _actual_identity
    if not service_id:
        return {'status': 'noncompliant', 'reason': 'unassigned_application'}
    result = {**decision, 'service_id': service_id}
    identity = _actual_identity(observation)
    if identity and result['reason'] in ('no_approved_release_match', 'requested_digest_mismatch',
                                         'service_outside_environment_scope', 'requested_service_repository_mismatch'):
        result['status'] = 'noncompliant'
    if result['status'] != 'approved':
        return result
    authority, slots = cache.get(_approved_components, db, service_id, timestamp, cache, result.get('approval_id'))
    if (slots is None or decision.get('service_id') != service_id
            or not all(result.get(k) == v for k, v in authority.items())):
        return {**result, 'status': 'unverified', 'reason': 'current_release_evidence_unavailable'}
    if not slots:
        return result
    key = tuple(observation.get(k, '') for k in ('workload_kind', 'workload', 'container_kind', 'container'))
    if key not in slots:
        return {**result, 'status': 'noncompliant', 'reason': 'unexpected_component'}
    if identity is None:
        identity = _actual_identity({'image_id': observation.get('image_ref')})
        if not identity or identity[2] != observation.get('image_id'):
            return {**result, 'status': 'unverified', 'reason': 'immutable_runtime_identity_unavailable'}
    if identity[2] not in slots[key]:
        roots = (cache.get(_service_manifest_roots, cache, db, service_id, identity[2])
                 if 'approval_id' in authority else ())
        if slots[key].isdisjoint(roots):
            result.update(status='noncompliant', reason='component_digest_mismatch')
    return result


def _service_manifest_roots(cache, db, service_id, digest):
    from .oci_models import OCIRepository
    from .runtime_policy import _full_roots
    roots = {digest}
    for mapping in db.scalars(select(OCIRepository).where(OCIRepository.service_id == service_id)):
        roots.update(_full_roots(cache, db, mapping, digest))
    return roots


def missing_components(db, env, timestamp, cache):
    observed = defaultdict(set)
    for app in db.scalars(select(RuntimeApplication).where(RuntimeApplication.environment_id == env.id,
                          RuntimeApplication.service_id.is_not(None))):
        if in_scope(env, app.service_id):
            slots = observed[app.service_id, app.namespace]
            if app.present:
                slots.update(tuple(c.get(k, '') for k in ('workload_kind', 'workload', 'container_kind', 'container'))
                             for c in app.components)
    for (service_id, namespace), slots in observed.items():
        authority, expected = cache.get(_approved_components, db, service_id, timestamp, cache, None)
        location = {'namespace': namespace, 'observed_at': utc(env.discovery_observed_at).isoformat()}
        if expected is None and authority:
            yield location, {'status': 'unverified', 'reason': 'current_release_evidence_unavailable',
                             'service_id': service_id, **authority}
        for kind, workload, container_kind, container in sorted(set(expected or ()) - slots):
            yield {**location, 'workload_kind': kind, 'workload': workload, 'container_kind': container_kind,
                   'container': container}, {'status': 'noncompliant', 'reason': 'missing_approved_component',
                                             'service_id': service_id, **authority}
