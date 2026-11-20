"""Evaluate observed container bytes against current, service-scoped releases.

This is an observation policy, not registry authentication. Agents neither gain
pull grants nor supply service scope. Mutable tags and runtime configuration IDs
cannot establish which approved manifest is actually running.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
from types import SimpleNamespace
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.orm import joinedload

from . import oci_authorization, release_revisions, release_validity, replica_authorization
from .cyber_approval_evidence import DIGEST, _identity, _registry_name
from .cyber_approvals import CyberApproval, digest as snapshot_digest
from .imported_services import imported_service_ids, uses_imported_evidence
from .models import Service
from .oci_models import (OCIManifest, OCIObjectLink, OCIProjectObjectLink, OCIRepository,
                         OCIUpstream, is_project_pattern, parse_service_repository, project_repository)
from .oci_transport import REPOSITORY
from .oci_pull_instructions import registry_authority
from .replica_models import ReplicaRelease, ReplicaServiceState
from .service_ownership import active_service_predicate


class RuntimePolicyCache:
    """Share evidence lookups only within one overview request and decision timestamp."""
    def __init__(self):
        self._values = {}

    def get(self, function, *args):
        key = (function, args)
        if key not in self._values:
            self._values[key] = function(*args)
        return self._values[key]


def _active_service_ids(db):
    return frozenset(db.scalars(select(Service.id).where(active_service_predicate())))


def _service_status(db, identity):
    if db.get(Service, identity, populate_existing=True) is None:
        return 'service_unavailable'
    if not db.scalar(select(Service.id).where(Service.id == identity, active_service_predicate())):
        return 'service_inactive'
    return 'active'


def _value(environment, key, default=None):
    return environment.get(key, default) if isinstance(environment, dict) else getattr(environment, key, default)


def _actual_identity(observation):
    value = observation.get('image_id') if isinstance(observation, dict) else None
    if not isinstance(value, str) or len(value) > 2048:
        return None
    value = value.removeprefix('docker-pullable://')
    if '://' in value or value.count('@') != 1 or any(c.isspace() for c in value):
        return None
    repository, digest = value.split('@')
    host, separator, path = repository.partition('/')
    if ':' in path.rsplit('/', 1)[-1]:
        path, tag = path.rsplit(':', 1)
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag):
            return None
    # Requiring a qualified repository deliberately excludes docker://sha256,
    # bare CRI image IDs, and a later resolution of the requested mutable tag.
    if (not separator or not host or not DIGEST.fullmatch(digest)
            or not REPOSITORY.fullmatch(path) or len(path) > 255
            or not re.fullmatch(r'[A-Za-z0-9.\-:\[\]]+', host)):
        return None
    try:
        authority = urlsplit('https://' + host)
        if not authority.hostname or authority.port == 0:
            return None
    except ValueError:
        return None
    host = _registry_name(host)
    if host == 'docker.io' and '/' not in path:
        path = 'library/' + path
    return host, path, digest


def _configured_repositories(db, scope):
    by_host = {}
    rows = db.scalars(select(OCIRepository).options(joinedload(OCIRepository.upstream)).where(
        or_(OCIRepository.service_id.in_(scope), OCIRepository.service_id.is_(None)))
        .execution_options(populate_existing=True))
    for row in rows:
        if row.enabled and not row.suspended and row.upstream.enabled:
            host = _registry_name(urlsplit(row.upstream.endpoint).netloc)
            by_host.setdefault(host, []).append(row)
    return by_host


def _upstream_routes(cache, db, host, repository, scope, timestamp):
    from .oci_proxy import ProjectMapping
    for row in cache.get(_configured_repositories, db, scope).get(host, []):
        if is_project_pattern(row.public_repository):
            if row.service_id is not None:
                continue
            try:
                logical = project_repository(row.public_repository, row.upstream_repository, repository)
                project, _, relative = logical.partition('/')
                for service_id in scope:
                    public = f'{project}/{service_id}/{relative}'
                    if len(public) <= 255:
                        yield ProjectMapping(row, logical, repository, service_id, public)
            except ValueError:
                continue
        elif row.service_id in scope:
            if row.upstream_repository == repository:
                yield row
            elif not cache.get(uses_imported_evidence, db, row.service_id):
                revision = cache.get(release_revisions.active_revision, db, row.service_id, timestamp)
                if revision and any(item.get('repository_id') == row.id
                        and item.get('upstream_repository') == repository
                        for item in revision.manifest.get('distribution_bindings', [])):
                    yield row


def _fully_qualified(host):
    return host == 'localhost' or '.' in host or ':' in host


def _explicit_location(reference, location):
    host, _, path = location.partition('/')
    registry, separator, retained_path = reference.split('@')[0].partition('/')
    return (separator and _registry_name(registry) == _registry_name(host)
            and (retained_path == path or (host == 'docker.io' and 'library/' + retained_path == path)))


def _bound_snapshot(approval):
    retained = approval.snapshot
    return (isinstance(retained, dict) and retained.get('service_id') == approval.service_id
            and snapshot_digest(retained) == approval.snapshot_digest)


def _local_repository_index(db, scope, imported):
    """Locate potentially matching approvals without loading their assessment bodies."""
    index = {}
    query = select(CyberApproval.id, CyberApproval.service_id, CyberApproval.snapshot['artifacts'],
                   CyberApproval.publication['artifacts']).where(
        CyberApproval.status == 'approved', CyberApproval.service_id.in_(scope))
    for identity, service_id, source, published in db.execute(query.execution_options(yield_per=128)):
        if service_id in imported:
            continue
        for artifacts in (source, published):
            if not isinstance(artifacts, list):
                continue
            for item in artifacts:
                if not isinstance(item, dict) or item.get('kind') != 'image':
                    continue
                try:
                    reference, _ = _identity(item.get('reference'), item.get('digest'))
                except ValueError:
                    continue
                host, separator, repository = reference.split('@')[0].partition('/')
                host = _registry_name(host)
                if not separator or not _fully_qualified(host):
                    continue
                if host == 'docker.io' and '/' not in repository:
                    repository = 'library/' + repository
                index.setdefault((host, repository), set()).add(identity)
    return index


def _approval(db, identity):
    return db.get(CyberApproval, identity, populate_existing=True)


def _direct_candidates(cache, db, host, repository, scope, timestamp):
    """Discover scope from fully qualified retained evidence without inventing a gateway route."""
    if not _fully_qualified(host):
        return {}
    location = host + '/' + repository
    imported = frozenset(cache.get(imported_service_ids, db, scope))
    from .operating_mode import is_replica
    routes = {}
    if not is_replica():
        ids = cache.get(_local_repository_index, db, scope, imported).get((host, repository), ())
        for identity in ids:
            approval = cache.get(_approval, db, identity)
            if approval is None:
                continue
            if not cache.get(_bound_snapshot, approval):
                continue
            digests = cache.get(_image_digests, approval, location, True)
            if digests:
                if approval.service_id not in routes:
                    source = SimpleNamespace(endpoint='https://' + host, enabled=True)
                    route = SimpleNamespace(id=None, service_id=approval.service_id, upstream=source,
                        upstream_repository=repository, enabled=True, suspended=False, policy={})
                    routes[approval.service_id] = route, set()
                routes[approval.service_id][1].update(digests)
    if imported:
        routes.update(cache.get(_imported_repository_inventory, cache, db, scope, host, timestamp).get(repository, {}))
    return routes


def _imported_upstreams(db, scope):
    by_host = {}
    rows = db.execute(select(ReplicaServiceState, OCIUpstream)
            .join(OCIUpstream, OCIUpstream.id == ReplicaServiceState.upstream_id)
            .where(ReplicaServiceState.service_id.in_(scope), OCIUpstream.enabled.is_(True)))
    for state, upstream in rows:
        host = _registry_name(urlsplit(upstream.endpoint).netloc)
        by_host.setdefault(host, []).append((state, upstream))
    return by_host


def _imported_repository_inventory(cache, db, scope, host, timestamp):
    """Index sealed entries for this upstream once across all repositories on the page."""
    repositories = {}
    for state, upstream in cache.get(_imported_upstreams, db, scope).get(host, []):
        for release in replica_authorization._releases(db, state.service_id):
            if not replica_authorization.trusted_release(db, release, state, timestamp):
                continue
            for image in release.artifacts:
                if not isinstance(image, dict) or image.get('kind') != 'image':
                    continue
                repository = image['repository']
                routes = repositories.setdefault(repository, {})
                if state.service_id not in routes:
                    route = SimpleNamespace(id=None, service_id=state.service_id, upstream=upstream,
                        upstream_repository=repository, upstream_id=upstream.id, enabled=True, suspended=False, policy={})
                    routes[state.service_id] = route, set()
                routes[state.service_id][1].update([image['digest'], *image.get('manifests', [])])
    return repositories


def _image_digests(approval, location, strict):
    """Index image identities per approval and repository, independently of other artifact kinds."""
    result = set()
    snapshot = approval.snapshot if isinstance(approval.snapshot, dict) else {}
    receipt = approval.publication if isinstance(approval.publication, dict) else {}
    for published, source in ((False, snapshot), (True, receipt)):
        artifacts = source.get('artifacts')
        if not isinstance(artifacts, list):
            continue
        # A validated chart receipt for identical bytes cannot bless an
        # unverified image publication. Refuse mixed-kind published identities.
        matching_kinds = {}
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            try:
                reference, pin = _identity(item.get('reference'), item.get('digest'))
            except ValueError:
                continue
            if strict and item.get('kind') == 'image' and not _explicit_location(reference, location):
                continue
            if oci_authorization._artifact_matches({'artifacts': [item]}, location, pin, published=published):
                matching_kinds.setdefault(pin, set()).add(item['kind'])
        for pin, kinds in matching_kinds.items():
            if 'image' not in kinds:
                continue
            if not published or (kinds == {'image'} and oci_authorization._published_artifact_matches(approval, location, pin)):
                result.add(pin)
    return result


def _local_approvals(db, service_id):
    return list(db.scalars(select(CyberApproval).where(
        CyberApproval.service_id == service_id, CyberApproval.status == 'approved')
        .order_by(CyberApproval.id.desc()).execution_options(populate_existing=True)))


def _verified_child(db, mapping_id, root, target):
    """Verify cached index bytes and descriptors; links alone are not evidence."""
    visited = set()

    def visit(digest, depth=0, expected_size=None):
        if depth > 8 or len(visited) >= 256 or digest in visited:
            return False
        visited.add(digest)
        row = db.scalar(select(OCIManifest).where(
            OCIManifest.repository_id == mapping_id, OCIManifest.digest == digest))
        if row is None:
            return False
        raw = row.content.encode('utf-8')
        if ('sha256:' + hashlib.sha256(raw).hexdigest() != digest
                or (expected_size is not None and len(raw) != expected_size)):
            return False
        try:
            document = json.loads(raw)
        except (TypeError, ValueError):
            return False
        if not isinstance(document, dict) or document.get('schemaVersion') != 2:
            return False
        if document.get('artifactType') or document.get('mediaType', row.media_type) != row.media_type:
            return False
        if digest == target:
            config = document.get('config')
            return (row.media_type in {'application/vnd.oci.image.manifest.v1+json',
                                       'application/vnd.docker.distribution.manifest.v2+json'}
                    and isinstance(config, dict) and DIGEST.fullmatch(str(config.get('digest', ''))) is not None
                    and config.get('mediaType') in {'application/vnd.oci.image.config.v1+json',
                                                   'application/vnd.docker.container.image.v1+json'}
                    and isinstance(document.get('layers'), list))
        if row.media_type not in {'application/vnd.oci.image.index.v1+json',
                                  'application/vnd.docker.distribution.manifest.list.v2+json'}:
            return False
        children = document.get('manifests')
        if not isinstance(children, list) or len(children) > 256:
            return False
        for child in children:
            if (isinstance(child, dict) and DIGEST.fullmatch(str(child.get('digest', '')))
                    and type(child.get('size')) is int and child['size'] >= 0
                    and not child.get('urls')
                    and (child.get('annotations') or {}).get('vnd.docker.reference.type') != 'attestation-manifest'
                    and visit(child['digest'], depth + 1, child['size'])):
                return True
        return False

    return visit(root)


def _manifest_links(db, repository_id, request_repository):
    if request_repository is not None:
        model = OCIProjectObjectLink
        query = select(model.object_digest, model.root_digest).filter_by(
            repository_id=repository_id, repository_path=request_repository, kind='manifest')
    else:
        model = OCIObjectLink
        query = select(model.object_digest, model.root_digest).filter_by(repository_id=repository_id, kind='manifest')
    roots = {}
    for child, root in db.execute(query):
        if child != root:
            roots.setdefault(child, set()).add(root)
    return roots


def _full_roots(cache, db, mapping, digest):
    yield digest
    if mapping.id is None:
        return
    graph = cache.get(_manifest_links, db, mapping.id, getattr(mapping, 'request_repository', None))
    for root in graph.get(digest, ()):
        if cache.get(_verified_child, db, mapping.id, root, digest):
            yield root


def _result(status, reason, service_id=None, *, approval_id=None, release_id=None, override_id=None):
    result = dict(status=status, reason=reason)
    values = dict(service_id=service_id, approval_id=approval_id, release_id=release_id, override_id=override_id)
    result.update((key, value) for key, value in values.items() if value is not None)
    return result


def _imported_result(db, mapping, digest, timestamp):
    service_id = mapping.service_id
    decision = replica_authorization.authorize(db, mapping, digest, timestamp)
    state = replica_authorization._state(db, service_id)
    if state is None or state.upstream_id != mapping.upstream_id:
        return _result('unverified', 'current_release_evidence_unavailable', service_id)
    if decision.release_id is not None:
        release = db.get(ReplicaRelease, decision.release_id, populate_existing=True)
        if replica_authorization.trusted_release(db, release, state, timestamp):
            images = [item for item in replica_authorization._matches(release, mapping.upstream_repository, digest)
                      if item.get('kind') == 'image']
            if images and decision.override_id:
                from .local_cyber_overrides import applicable_override
                for image in images:
                    grant = applicable_override(db, release, image['digest'], decision.approval_status, timestamp)
                    if grant and grant.id == decision.override_id:
                        return _result('excepted', 'local_cyber_override', service_id,
                                       release_id=release.id, override_id=grant.id)
            elif images:
                return _result('approved' if decision.allowed else 'noncompliant', decision.reason,
                               service_id, release_id=release.id)
        return _result('unverified', 'image_not_in_retained_release_evidence', service_id)
    if decision.reason == 'artifact_not_in_verified_release' and state.active_release_id:
        active = db.get(ReplicaRelease, state.active_release_id, populate_existing=True)
        if (replica_authorization.trusted_release(db, active, state, timestamp)
                and replica_authorization.release_denial(active, state, timestamp) is None):
            return _result('noncompliant', 'image_outside_current_approved_release', service_id,
                           release_id=active.id)
        return _result('unverified', 'current_release_evidence_unavailable', service_id)
    return _result('unverified', decision.reason, service_id)


def _approval_denial(db, service_id, approval, timestamp):
    """Explain a denial only from intact, service-bound, approved evidence."""
    if (approval.status != 'approved' or not isinstance(approval.snapshot, dict)
            or approval.snapshot.get('service_id') != service_id
            or snapshot_digest(approval.snapshot) != approval.snapshot_digest):
        return None
    if approval.revoked_at:
        return 'release_revoked'
    start, end = release_validity.dates(approval.snapshot.get('approval_validity'))
    if not approval.decided_at or release_validity.utc(approval.decided_at) != start:
        return None
    if timestamp >= end:
        return 'release_expired'
    if timestamp < start:
        return None
    revision = db.scalar(select(release_revisions.ReleaseRevision).filter_by(
        service_id=service_id, approval_id=approval.id).execution_options(populate_existing=True))
    if revision:
        state = db.get(release_revisions.ReleaseRevisionState, revision.id, populate_existing=True)
        if state and state.revoked:
            return 'release_revoked'
        if state and state.suspended:
            return 'release_suspended'
        active = release_revisions.active_revision(db, service_id, timestamp)
        if active and active.id != revision.id and state and state.decision == 'approved':
            return 'release_superseded'
    return None


def _local_result(cache, db, mapping, digest, observed_repository, timestamp):
    service_id = mapping.service_id
    active = cache.get(release_revisions.active_revision, db, service_id, timestamp)
    approvals = cache.get(_local_approvals, db, service_id)
    outcomes = []
    for root in _full_roots(cache, db, mapping, digest):
        path = release_revisions.distribution_location(mapping, active, root) if active else mapping.upstream_repository
        if observed_repository is not None and observed_repository != path:
            continue
        location = urlsplit(mapping.upstream.endpoint).netloc + '/' + path
        members = {a.id: a for a in approvals if root in cache.get(_image_digests, a, location, mapping.id is None)}
        if not members:
            continue
        # Group policy can authorize an OCI read on scan compliance alone.
        # Only the release-specific authorizer may certify running release bytes.
        decision = oci_authorization._authorize_approved_release(db, mapping, root, timestamp)
        approval = members.get(decision.approval_id)
        if decision.allowed and approval:
            return _result('approved', 'approved', service_id, approval_id=approval.id)
        if decision.reason in ('approval_not_current', 'active_revision_unavailable', 'digest_not_approved'):
            for candidate in ([approval] if approval else members.values()):
                reason = _approval_denial(db, service_id, candidate, timestamp)
                if reason:
                    outcomes.append(_result('noncompliant', reason, service_id, approval_id=candidate.id))
                    break
        if not any(outcome['status'] == 'noncompliant' for outcome in outcomes):
            outcomes.append(_result('unverified', decision.reason if not decision.allowed else
                                    'image_not_in_retained_release_evidence', service_id))
    if outcomes:
        return next((item for item in outcomes if item['status'] == 'noncompliant'), outcomes[0])
    if active:
        # An unknown digest can still be a platform child when the signed
        # inventory contains an index and the local manifest graph is incomplete.
        if not all(a.get('media_type') in {'application/vnd.oci.image.manifest.v1+json',
                        'application/vnd.docker.distribution.manifest.v2+json'} for a in active.manifest['artifacts']):
            return _result('unverified', 'platform_manifest_membership_unavailable', service_id)
        return _result('noncompliant', 'image_outside_current_approved_release', service_id,
                       approval_id=active.approval_id)
    reason = 'no_approved_release_match' if mapping.id is None else 'image_not_in_retained_release_evidence'
    return _result('unverified', reason, service_id)


def evaluate_observation(db, environment, observation, now=None, *, cache=None):
    """Evaluate the observed repository digest; never resolve a tag or change workloads."""
    timestamp = release_validity.utc(now or datetime.now(timezone.utc))
    if isinstance(observation, dict) and observation.get('state') != 'running':
        return _result('unverified', 'container_not_running')
    identity = _actual_identity(observation)
    raw = observation.get('image_id') if isinstance(observation, dict) else None
    bare = isinstance(raw, str) and DIGEST.fullmatch(raw) is not None
    if bare and _value(environment, 'kind') == 'kubernetes' and observation.get('state') == 'running':
        request = observation.get('image_ref')
        if isinstance(request, str) and request.endswith('@' + raw) and '://' not in request:
            pinned = _actual_identity({'image_id': request})
            if pinned and _fully_qualified(pinned[0]):
                identity = pinned
    if identity is None:
        return _result('unverified', 'immutable_runtime_identity_unavailable')
    cache = cache or RuntimePolicyCache()
    try:
        result = _evaluate_identity(cache, db, environment, observation, identity, timestamp)
    except (ValueError, KeyError, TypeError, AttributeError):
        return _result('unverified', 'current_release_evidence_unavailable')
    # CRI bare IDs can denote image configurations. A coincident spec pin
    # becomes manifest identity only through independent retained membership.
    if bare and result['status'] == 'noncompliant' and result['reason'] not in {
            'release_expired', 'release_revoked', 'release_suspended', 'release_superseded'}:
        return _result('unverified', 'immutable_runtime_identity_unavailable')
    return result


def _requested_gateway(observation, public_host):
    ref = observation.get('image_ref')
    if not isinstance(ref, str) or not public_host:
        return None
    authority, separator, _ = ref.partition('/')
    if not separator or _registry_name(authority) != _registry_name(public_host):
        return None
    repo, pinned, pin = ref.partition('@')
    # A tag may supply service routing context. It never supplies manifest bytes.
    identity = _actual_identity({'image_id': repo + '@' + (pin if pinned else 'sha256:' + '0' * 64)})
    if identity is None:
        raise ValueError('Invalid requested gateway repository')
    return identity[1], pin if pinned else None


def _matches_requested_pin(cache, db, mapping, requested, actual, timestamp, imported):
    if requested == actual:
        return True
    if not imported:
        return requested in _full_roots(cache, db, mapping, actual)
    state = replica_authorization._state(db, mapping.service_id)
    if state is None or state.upstream_id != mapping.upstream_id:
        return False
    return any(replica_authorization.trusted_release(db, release, state, timestamp) and
               any(item.get('kind') == 'image' and item.get('repository') == mapping.upstream_repository
                   and item.get('digest') == requested and actual in item.get('manifests', [])
                   for item in release.artifacts)
               for release in replica_authorization._releases(db, mapping.service_id))


def _evaluate_identity(cache, db, environment, observation, identity, timestamp):
    host, repository, digest = identity
    scope_mode = _value(environment, 'service_scope', 'selected')
    if scope_mode == 'all':
        scope = cache.get(_active_service_ids, db)
    else:
        ids = _value(environment, 'service_ids', [])
        scope = frozenset(v for v in ids if type(v) is int and v > 0) if scope_mode == 'selected' and isinstance(ids, list) else frozenset()
    if not scope:
        return _result('unverified', 'environment_service_scope_unavailable')
    try:
        public_host = registry_authority()
    except ValueError:
        public_host = None
    observed_repository = repository
    on_gateway = public_host and host == _registry_name(public_host)
    requested = _requested_gateway(observation, public_host)
    if on_gateway or requested:
        from .oci_proxy import Denied, mapping_for
        gateway_repository = requested[0] if requested else repository
        if on_gateway and gateway_repository != repository:
            return _result('unverified', 'requested_service_repository_mismatch')
        try:
            service_id, _ = parse_service_repository(gateway_repository)
        except ValueError:
            return _result('unverified', 'repository_mapping_unavailable')
        if service_id not in scope:
            return _result('unverified', 'service_outside_environment_scope')
        status = cache.get(_service_status, db, service_id)
        if status != 'active':
            return _result('noncompliant' if on_gateway and status == 'service_inactive' else 'unverified', status, service_id)
        try:
            mapping = cache.get(mapping_for, db, gateway_repository)
        except Denied:
            return _result('unverified', 'repository_mapping_unavailable', service_id)
        if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
            return _result('unverified', 'repository_mapping_unavailable', service_id)
        imported = cache.get(uses_imported_evidence, db, service_id)
        if on_gateway:
            observed_repository = None
        else:
            upstream = _registry_name(urlsplit(mapping.upstream.endpoint).netloc)
            if upstream != host:
                return _result('unverified', 'requested_service_repository_mismatch', service_id)
            if repository != mapping.upstream_repository:
                active = None if imported else cache.get(release_revisions.active_revision, db, service_id, timestamp)
                if active is None or not any(release_revisions.distribution_location(mapping, active, root) == repository
                                              for root in _full_roots(cache, db, mapping, digest)):
                    return _result('unverified', 'requested_service_repository_mismatch', service_id)
        if requested and requested[1] and not _matches_requested_pin(cache, db, mapping, requested[1], digest, timestamp, imported):
            return _result('unverified', 'requested_digest_mismatch', service_id)
        routes = [mapping]
    else:
        routes = list(_upstream_routes(cache, db, host, repository, scope, timestamp))
        candidates = cache.get(_direct_candidates, cache, db, host, repository, scope, timestamp)
        direct = [row for row, digests in candidates.values() if digest in digests]
        if not direct:
            direct = [row for row, _ in candidates.values()]
        if direct:
            # A project-wide wildcard does not independently assign a workload
            # to every service. Retained qualified evidence can narrow it.
            verified_services = {row.service_id for row in direct}
            routes = [row for row in routes if not getattr(row, 'project', None)
                      or row.service_id in verified_services]
            mapped = {row.service_id for row in routes}
            routes.extend(row for row in direct if row.service_id not in mapped)
        if not routes:
            reason = 'no_approved_release_match' if _fully_qualified(host) else 'immutable_runtime_identity_unavailable'
            return _result('unverified', reason)
    service_ids = {mapping.service_id for mapping in routes}
    if len(service_ids) > 1:
        return _result('unverified', 'ambiguous_service_membership')
    service_id = service_ids.pop()
    status = cache.get(_service_status, db, service_id)
    if status != 'active':
        return _result('noncompliant' if status == 'service_inactive' else 'unverified', status, service_id)
    imported = cache.get(uses_imported_evidence, db, service_id)
    results = []
    for mapping in routes:
        try:
            result = (_imported_result(db, mapping, digest, timestamp) if imported else
                      _local_result(cache, db, mapping, digest, observed_repository, timestamp))
        except (ValueError, KeyError, TypeError, AttributeError):
            result = _result('unverified', 'current_release_evidence_unavailable', service_id)
        results.append(result)
    rank = {'approved': 0, 'excepted': 1, 'noncompliant': 2, 'unverified': 3}
    return min(results, key=lambda item: rank[item['status']])
