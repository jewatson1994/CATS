"""Small restart-safe OCI consumer; no scanner, intelligence feed or source CATS."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
import asyncio
import logging
import hashlib
from pathlib import Path
import os
import threading
import uuid

from sqlalchemy import select

from .database import SessionLocal
from .auth import record_audit
from . import durable_jobs as jobs, portable_release
from .oci_models import OCIUpstream
from .replica_models import ReplicaSource, ReplicaRelease, ReplicaServiceState
from .replica_integrity import verify_record, digest
from .replica_import import reconcile
from .release_documentation import registry_environment
from .release_validity import utc
from .secrets import decrypt_secret
from .trusted_ca import configured_certificates

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


def enqueue(db, source, actor_id=None):
    # Source row locking serializes manual and scheduled admission.
    db.scalar(select(ReplicaSource).where(ReplicaSource.id == source.id).with_for_update())
    pending = db.scalars(select(jobs.DurableJob).where(jobs.DurableJob.kind == KIND,
        jobs.DurableJob.status.in_(['queued', 'running']))).all()
    existing = next((job for job in pending if job.payload.get('source_id') == source.id), None)
    if existing:
        return existing
    return jobs.submit(db, kind=KIND, payload={'source_id': source.id},
                       requested_by_id=actor_id, commit=False)


def sync(ctx, payload):
    # Clear an earlier attempt's diagnostic before any validation can fail.
    # DurableJobs keeps retry/backoff semantics; only this handler authors codes.
    ctx.checkpoint({'failure_code': None})
    source_id = payload['source_id']
    with ctx.session_factory() as db:
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
        # A known registry digest does not prove our retained local evidence is
        # still present or intact. Re-fetch damaged/missing content for recovery
        # or a fail-closed import error, and never borrow another source's state.
        known = {release.source_reference for release in db.scalars(select(ReplicaRelease)
            .join(ReplicaServiceState, ReplicaServiceState.service_id == ReplicaRelease.service_id)
            .where(ReplicaServiceState.source_id == source.id,
                   ReplicaServiceState.upstream_id == source.upstream_id,
                   ReplicaRelease.publisher.in_(trusted))) if retained_complete(release)}
    result = {'discovered': 0, 'activated': 0, 'revoked': 0, 'unchanged': 0, 'failed': 0}
    try:
        ctx.stage('Discovering signed releases in the local registry', 5)
        with registry_environment(destination, certificates) as env:
            env.update(CATS_OCI_TOKEN_REALMS=','.join(realms), CATS_OCI_BLOB_REDIRECT_ORIGINS=','.join(origins))
            for reference in portable_release.discover_release_references(host, repository, env):
                ctx.check()
                result['discovered'] += 1
                if reference in known:
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
                        owned = ctx._owned(db)
                        if owned.cancel_requested:
                            raise jobs.JobCancelled()
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
                        db.commit()
                    result[outcome['status']] += 1
                except (jobs.JobCancelled, jobs.LeaseLost, jobs.JobError):
                    raise
                except Exception as exc:
                    # Registry responses can contain credentials/hostile text.
                    # Keep public diagnostics fixed and correlation-addressable.
                    result['failed'] += 1
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
    except Exception:
        with ctx.session_factory() as db:
            source = db.get(ReplicaSource, source_id)
            if source and not source.last_error:
                source.last_error = f'Local registry sync failed. Check connectivity, CA trust, pull credentials and repository scope. Reference: {ctx.job.correlation_id}'
                db.commit()
        raise


def schedule_due(session_factory=SessionLocal):
    now = datetime.now(timezone.utc)
    with session_factory() as db:
        for source in db.scalars(select(ReplicaSource).where(ReplicaSource.enabled.is_(True))):
            if source.last_attempt_at is None or utc(source.last_attempt_at) + timedelta(seconds=source.poll_seconds) <= now:
                enqueue(db, source)
        db.commit()


@asynccontextmanager
async def replica_lifespan():
    if os.getenv('CATS_REPLICA_SYNC_ENABLED', 'true').lower() not in {'1', 'true', 'yes'}:
        yield
        return
    stop = threading.Event()
    worker_id = 'replica-' + uuid.uuid4().hex[:16]
    def worker():
        while not stop.is_set():
            try:
                schedule_due()
                job = jobs.claim([KIND], worker_id)
                if job:
                    jobs.execute(job, sync)
                    continue
            except Exception as exc:
                logging.getLogger(__name__).error('replica_worker_failure type=%s', type(exc).__name__)
            stop.wait(5)
    thread = threading.Thread(target=worker, name='replica-sync', daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        await asyncio.to_thread(thread.join, 5)
