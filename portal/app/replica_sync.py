"""Restart-safe signed OCI consumer, available alongside full CATS or on a replica."""
from datetime import datetime, timezone
import logging
import hashlib
from pathlib import Path

from sqlalchemy import extract, or_, select

from .database import SessionLocal
from .auth import record_audit
from . import durable_jobs as jobs, portable_release
from .oci_models import OCIUpstream
from .replica_models import ReplicaSource, ReplicaRelease, ReplicaServiceState, reserve_sqlite_writer
from .replica_integrity import verify_record, digest
from .replica_import import reconcile
from .release_documentation import registry_environment
from .secrets import decrypt_secret
from .trusted_ca import configured_certificates
from .diagnostics import build_diagnostic, record_diagnostic, public_diagnostic

KIND = 'replica_sync'
FAILURE_MESSAGES = {
    'release_verification_failed': (
        'Release verification failed. Complete registry replication, verify publisher trust '
        'and signed sequence, then retry.'),
}


def retained_complete(release):
    """Skip registry work only while the retained, verified evidence is intact."""
    try:
        archive = Path(release.evidence_path)
        expected = release.manifest.get('evidence', {}).get('digest')
        if (not verify_record(release) or digest(release.evidence_state) != release.evidence_state_digest
                or not archive.is_file() or archive.is_symlink()):
            return False
        with archive.open('rb') as stream:
            return 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() == expected
    except (OSError, TypeError, ValueError, AttributeError):
        return False


def _active_job(source_id):
    return select(jobs.DurableJob).where(
        jobs.DurableJob.kind == KIND,
        jobs.DurableJob.status.in_(('queued', 'running')),
        jobs.DurableJob.payload['source_id'].as_integer() == source_id)


def _retained_reference(session_factory, source_id, upstream_id, trusted, reference):
    # Read one discovered digest. Hash the retained projection and archive only
    # after returning the connection, and never touch unrelated release files.
    with session_factory() as db:
        release = db.scalar(select(ReplicaRelease)
            .join(ReplicaServiceState, ReplicaServiceState.service_id == ReplicaRelease.service_id)
            .where(ReplicaRelease.source_reference == reference,
                   ReplicaServiceState.source_id == source_id,
                   ReplicaServiceState.upstream_id == upstream_id,
                   ReplicaRelease.publisher.in_(trusted))
            .order_by(ReplicaRelease.id.desc()).limit(1))
    return release is not None and retained_complete(release)


def enqueue(db, source, actor_id=None):
    # Source row locking serializes manual and scheduled admission.
    reserve_sqlite_writer(db)
    db.scalar(select(ReplicaSource).where(ReplicaSource.id == source.id).with_for_update())
    existing = db.scalar(_active_job(source.id).limit(1))
    if existing:
        return existing
    return jobs.submit(db, kind=KIND, payload={'source_id': source.id},
                       requested_by_id=actor_id, commit=False)


def sync(ctx, payload):
    # Clear an earlier attempt's diagnostic before any validation can fail.
    # DurableJobs keeps retry/backoff semantics; only this handler authors codes.
    ctx.checkpoint({'failure_code': None, 'diagnostics': [], 'diagnostics_truncated': 0})
    source_id = payload['source_id']
    with ctx.session_factory() as db:
        if ctx._owned(db).cancel_requested:
            raise jobs.JobCancelled()
        source = db.get(ReplicaSource, source_id)
        upstream = db.get(OCIUpstream, source.upstream_id) if source else None
        if not source or not source.enabled or not upstream or not upstream.enabled:
            raise jobs.JobError('Replica source or local registry is disabled.')
        source.last_attempt_at = datetime.now(timezone.utc)
        source.last_error = None
        db.commit()
        configuration = (source.upstream_id, source.repository, tuple(source.trusted_publishers))
        destination = dict(name=upstream.name, endpoint=upstream.endpoint,
            namespace=source.repository.removesuffix('/*'), ca_pem=upstream.ca_pem,
            username=decrypt_secret(upstream.username), password=upstream.password)
        realms, origins = upstream.token_realms, upstream.redirect_origins
        certificates = configured_certificates(db)
        repository, trusted = source.repository, list(source.trusted_publishers)
        host = upstream.endpoint.removeprefix('https://').rstrip('/')
    result = {'discovered': 0, 'activated': 0, 'revoked': 0, 'unchanged': 0, 'failed': 0,
              'diagnostics': [], 'diagnostics_truncated': 0}
    try:
        ctx.stage('Discovering signed releases in the local registry', 5)
        with registry_environment(destination, certificates) as env:
            env.update(CATS_OCI_TOKEN_REALMS=','.join(realms), CATS_OCI_BLOB_REDIRECT_ORIGINS=','.join(origins))
            for reference in portable_release.discover_release_references(host, repository, env):
                ctx.check()
                result['discovered'] += 1
                if _retained_reference(ctx.session_factory, source_id, configuration[0], trusted, reference):
                    result['unchanged'] += 1
                    continue
                with ctx.session_factory() as db:
                    ctx._owned(db)
                    record_audit(db, None, 'replica.discovered', 'replica_source', source_id,
                                 reference=reference, correlation_id=ctx.job.correlation_id)
                    db.commit()
                ctx.stage('Verifying release signatures, evidence and all artifact bytes', 20)
                try:
                    verified = portable_release.fetch_release(reference, env, trusted)
                    ctx.check()
                    with ctx.session_factory() as db:
                        current = db.scalar(select(ReplicaSource).where(ReplicaSource.id == source_id).with_for_update())
                        local_registry = db.get(OCIUpstream, current.upstream_id) if current else None
                        if (not current or not current.enabled or not local_registry or not local_registry.enabled
                                or configuration != (current.upstream_id, current.repository, tuple(current.trusted_publishers))):
                            raise jobs.JobError('Replica source changed during verification. Sync again.')
                        record_audit(db, None, 'replica.verified', 'replica_source', source_id,
                                     reference=reference, publisher=verified.get('publisher_root', verified['key_fingerprint']),
                                     key_fingerprint=verified['key_fingerprint'],
                                     complete=True, correlation_id=ctx.job.correlation_id)
                        outcome = reconcile(db, current, verified)
                        # Heartbeats must be able to renew during a long import.
                        # Fence the projection immediately before publishing it.
                        if ctx._owned(db).cancel_requested:
                            raise jobs.JobCancelled()
                        db.commit()
                    result[outcome['status']] += 1
                except (jobs.JobCancelled, jobs.LeaseLost, jobs.JobError):
                    raise
                except Exception as exc:
                    result['failed'] += 1
                    event = build_diagnostic(exc, component='replica', operation='verify_release',
                        correlation_id=ctx.job.correlation_id,
                        resource={'source_id': source_id, 'reference': reference},
                        context={'job_id': ctx.job.id, 'source_id': source_id, 'reference': reference},
                        summary='A replicated release could not be verified or activated.')
                    record_diagnostic(event, session_factory=ctx.session_factory)
                    if len(result['diagnostics']) < 20:
                        result['diagnostics'].append(public_diagnostic(event))
                    else:
                        result['diagnostics_truncated'] += 1
                    logging.getLogger(__name__).warning('replica_release_rejected source=%s correlation=%s type=%s',
                        source_id, ctx.job.correlation_id, type(exc).__name__)
                    with ctx.session_factory() as db:
                        ctx._owned(db)
                        record_audit(db, None, 'replica.rejected', 'replica_source', source_id,
                                     reference=reference, failure_type=type(exc).__name__,
                                     correlation_id=ctx.job.correlation_id)
                        db.commit()
                ctx.checkpoint(result)
        with ctx.session_factory() as db:
            ctx._owned(db)
            source = db.get(ReplicaSource, source_id)
            if result['failed']:
                source.last_error = f"{result['failed']} release(s) rejected or incomplete. Check registry replication, publisher trust and signed sequence; retry. Reference: {ctx.job.correlation_id}"
            else:
                source.last_success_at, source.last_error = datetime.now(timezone.utc), None
            db.commit()
        if result['failed']:
            # Retrying is safe: committed events are idempotent, incomplete
            # releases remain inactive. DurableJobs supplies bounded backoff.
            ctx.checkpoint({'failure_code': 'release_verification_failed'})
            raise RuntimeError('Incomplete release replication')
        return result
    except (jobs.LeaseLost, jobs.JobCancelled):
        raise
    except Exception:
        with ctx.session_factory() as db:
            ctx._owned(db)
            source = db.get(ReplicaSource, source_id)
            if source and not source.last_error:
                source.last_error = f'Local registry sync failed. Check connectivity, CA trust, pull credentials and repository scope. Reference: {ctx.job.correlation_id}'
                db.commit()
        raise


def schedule_due(session_factory=SessionLocal):
    """Admit a bounded batch. Release queue and source locks after each admission."""
    now = datetime.now(timezone.utc).timestamp()
    for _ in range(16):
        with session_factory() as db:
            reserve_sqlite_writer(db)
            source = db.scalar(select(ReplicaSource)
                .join(OCIUpstream, OCIUpstream.id == ReplicaSource.upstream_id)
                .where(ReplicaSource.enabled.is_(True), OCIUpstream.enabled.is_(True),
                       or_(ReplicaSource.last_attempt_at.is_(None),
                           extract('epoch', ReplicaSource.last_attempt_at) + ReplicaSource.poll_seconds <= now),
                       ~_active_job(ReplicaSource.id).exists())
                .order_by(ReplicaSource.last_attempt_at.asc().nulls_first(), ReplicaSource.id)
                .limit(1).with_for_update(of=ReplicaSource, skip_locked=True))
            if source is None:
                return
            enqueue(db, source)
            db.commit()
