"""Digest-bound OCI authorization from local verified imported release state.

This module deliberately does not evaluate vulnerability policy or require an
assessment worker or connection to the originating CATS installation.
"""
from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import defer

from .cyber_approval_evidence import DIGEST
from .release_validity import utc


def trusted_release(db, release, state, timestamp=None):
    from .replica_integrity import verify_record
    from .replica_models import ReplicaSource, ReplicaPublisherTrust
    timestamp = utc(timestamp or datetime.now(timezone.utc))
    if (release is None or state is None or release.service_id != state.service_id
            or release.publisher != state.publisher or not release.verified or not release.complete
            or release.approved_at is None or utc(release.approved_at) > timestamp):
        return False
    source = db.get(ReplicaSource, state.source_id, populate_existing=True)
    if (source is None or not source.enabled or source.upstream_id != state.upstream_id
            or release.publisher not in (source.trusted_publishers or [])):
        return False
    try:
        if not verify_record(release):
            return False
        from .release_key_rotation import verify_trust, _sequence_allowed
        trust = db.get(ReplicaPublisherTrust, (source.id, release.publisher), populate_existing=True)
        if trust is None:
            # Existing unrotated installations need no destructive backfill.
            return release.key_fingerprint == release.publisher and not release.manifest.get('signing_key_chain')
        if not verify_trust(trust):
            return False
        chain = release.manifest.get('signing_key_chain', [])
        if chain != trust.key_chain[:len(chain)]:
            return False
        return (_sequence_allowed(trust.key_chain, release.key_fingerprint, state.source_service_id, release.sequence)
                if trust.key_chain else release.key_fingerprint == release.publisher)
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def release_denial(release, state, timestamp):
    if release.revoked_at is not None:
        return 'revoked'
    if release.expires_at is not None and timestamp >= utc(release.expires_at):
        return 'expired'
    if state.active_release_id != release.id:
        return 'superseded'
    return None


def repository_policy_error(policy):
    if (not isinstance(policy, dict) or set(policy) - {'max_scan_age_days', 'max_approval_age_days'}
            or any(type(value) is not int or not 1 <= value <= 3650 for value in policy.values())):
        return 'invalid_policy'
    if policy.get('max_scan_age_days') is not None:
        return 'replica_scan_policy_unsupported'
    return None


def effective_release_denial(release, state, timestamp, policy):
    """The same expiry condition applies to enforcement and local risk acceptance."""
    denial = release_denial(release, state, timestamp)
    if (denial is None and policy.get('max_approval_age_days') is not None
            and timestamp >= utc(release.approved_at) + timedelta(days=policy['max_approval_age_days'])):
        return 'expired'
    return denial


def override_release_denial(db, release, state, digests, timestamp):
    """Validate every selected root against its service's actual repository policy.

    Publisher expiry/revocation/supersession is release-wide. Local freshness
    expiry must exist on an enabled matching route for every selected artifact;
    a claim of expiry alone cannot authorize a normal approved artifact.
    """
    from .oci_models import OCIRepository
    denial = release_denial(release, state, timestamp)
    if denial is not None:
        return denial
    mappings = list(db.scalars(select(OCIRepository).where(
        OCIRepository.service_id == release.service_id,
        OCIRepository.upstream_id == state.upstream_id,
        OCIRepository.enabled.is_(True), OCIRepository.suspended.is_(False))
        .execution_options(populate_existing=True)))
    for digest in digests:
        repositories = {item['repository'] for item in release.artifacts if item['digest'] == digest}
        if not any(mapping.upstream.enabled and mapping.upstream_repository in repositories
                and repository_policy_error(mapping.policy or {}) is None
                and effective_release_denial(release, state, timestamp, mapping.policy or {}) == 'expired'
                for mapping in mappings):
            return None
    return 'expired' if digests else None


def _matches(release, repository, digest):
    """Return approved roots; child membership is explicitly sealed by importer."""
    return [item for item in release.artifacts if item.get('repository') == repository
        and (item.get('digest') == digest or digest in item.get('manifests', []))]


def _state(db, service_id):
    from .replica_models import ReplicaServiceState
    return db.get(ReplicaServiceState, service_id, populate_existing=True)


def _releases(db, service_id):
    from .replica_models import ReplicaRelease
    return db.scalars(select(ReplicaRelease).where(ReplicaRelease.service_id == service_id)
        .options(defer(ReplicaRelease.evidence_state))
        .order_by(ReplicaRelease.sequence.desc(), ReplicaRelease.id.desc())
        .execution_options(populate_existing=True))


def authorize(db, mapping, digest, now=None):
    from .oci_authorization import AuthorizationDecision
    from .local_cyber_overrides import applicable_override
    from .models import Service
    from urllib.parse import urlencode, quote
    timestamp = utc(now or datetime.now(timezone.utc))
    base = dict(service_id=mapping.service_id, artifact_digest=digest,
        decision_at=timestamp.isoformat(), authorization_source='denied', override_status='not_evaluated',
        effective_policy={'mode': 'replica', 'exact_digest': True, 'trusted_publisher_required': True,
            'repository_policy': mapping.policy or {}})
    def decision(allowed, reason, **extra):
        return AuthorizationDecision(allowed, reason, **{**base, **extra})
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return decision(False, 'invalid_digest')
    if not mapping.enabled or mapping.suspended or not mapping.upstream.enabled:
        return decision(False, 'mapping_disabled')
    state = _state(db, mapping.service_id)
    service = db.get(Service, mapping.service_id, populate_existing=True)
    if state is None or state.upstream_id != mapping.upstream_id or service is None:
        return decision(False, 'replica_service_unavailable')
    from .main import service_lifecycle
    db.expire(service, ['archive_events'])
    if service_lifecycle(service) != 'active':
        return decision(False, 'service_inactive')
    policy = mapping.policy or {}
    policy_error = repository_policy_error(policy)
    if policy_error:
        return decision(False, policy_error)
    denied = 'artifact_not_in_verified_release'
    candidates = []
    for release in _releases(db, state.service_id):
        if not trusted_release(db, release, state, timestamp):
            continue
        artifacts = _matches(release, mapping.upstream_repository, digest)
        if not artifacts:
            continue
        denial = effective_release_denial(release, state, timestamp, policy)
        if denial is None:
            return decision(True, 'active_approved_release', release_id=release.id,
                authorization_source='approved_release', approval_status='approved', override_status='not_needed')
        denied = 'release_' + denial
        candidates.append((release, artifacts, denial))
    # Every currently active membership is considered before any exception.
    for release, artifacts, denial in candidates:
        for artifact in artifacts:
            grant = applicable_override(db, release, artifact['digest'], denial, timestamp)
            if grant is not None:
                return decision(True, 'local_cyber_override', release_id=release.id,
                    override_id=grant.id, authorization_source='local_override', approval_status=denial,
                    override_status='active')
    extra = {}
    if candidates:
        release, artifacts, denial = candidates[0]
        denied = 'release_' + denial
        extra = dict(release_id=release.id, override_url=f'/services/{quote(service.service_key, safe="")}/cyber-overrides?'
            + urlencode(dict(release_id=release.id, digest=artifacts[0]['digest'], denial_condition=denial)))
    return decision(False, denied, approval_status=denied.removeprefix('release_'),
        override_status='no_applicable_override', **extra)


def candidate_service_ids(db, mapping, digest):
    from .replica_models import ReplicaServiceState
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        return set()
    result = set()
    for state in db.scalars(select(ReplicaServiceState).where(
            ReplicaServiceState.upstream_id == mapping.upstream_id).execution_options(populate_existing=True)):
        for release in _releases(db, state.service_id):
            if trusted_release(db, release, state) and _matches(release, mapping.upstream_repository, digest):
                result.add(state.service_id)
                break
    return result


def distribution_location(db, mapping, digest):
    """Local routing configuration cannot change signed component membership."""
    if not DIGEST.fullmatch(str(digest)):
        # Tags remain hints: upstream returns bytes whose exact digest is checked
        # by authorize(). A tag never grants authority to a different digest.
        return mapping.upstream_repository
    state = _state(db, mapping.service_id)
    if state is None or state.upstream_id != mapping.upstream_id:
        raise ValueError('Replica service distribution unavailable')
    if not any(trusted_release(db, row, state) and _matches(row, mapping.upstream_repository, digest)
            for row in _releases(db, state.service_id)):
        raise ValueError('Artifact does not belong to this verified replica repository')
    return mapping.upstream_repository


def ensure_repository_mappings(db, state, artifacts):
    """Create deterministic service-specific routes atomically with activation.

    A shared project route cannot unambiguously identify a service when two
    services approve the same image. Automatic routes always name the local
    service explicitly, and never overwrite an administrator's configuration.
    """
    from .oci_models import OCIRepository
    from .oci_transport import REPOSITORY
    routes = []
    for repository in sorted({item['repository'] for item in artifacts}):
        if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository) or len(repository) > 255:
            raise ValueError('Verified artifact repository is invalid')
        public = f'services/{state.service_id}/{repository}'
        if len(public) > 255:
            public = f'services/{state.service_id}/artifact-' + hashlib.sha256(repository.encode()).hexdigest()
        existing = db.scalar(select(OCIRepository).where(OCIRepository.public_repository == public)
            .execution_options(populate_existing=True))
        if existing is not None:
            if (existing.service_id != state.service_id or existing.upstream_id != state.upstream_id
                    or existing.upstream_repository != repository):
                raise ValueError('Replica distribution route conflicts with existing local configuration')
        else:
            existing = OCIRepository(public_repository=public, service_id=state.service_id,
                upstream_id=state.upstream_id, upstream_repository=repository, policy={})
            db.add(existing)
        routes.append(existing)
    db.flush()
    return routes
