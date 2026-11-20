"""Portal-owned raw source expiry; immutable inventories are retained."""
from datetime import timedelta
import os
import re
from sqlalchemy import select, or_
from .models import utcnow
from .durable_jobs import DurableJob
from .discovery_worker import upload_root


def cleanup_sources(session_factory, batch_size=100):
    # Raw archives can contain sensitive source material. No unlimited setting.
    hours = max(1, min(168, int(os.getenv('CATS_DISCOVERY_SOURCE_RETENTION_HOURS', '24'))))
    cutoff = utcnow() - timedelta(hours=hours)
    with session_factory() as db:
        candidates = db.scalars(select(DurableJob).where(
            DurableJob.kind == 'discovery', DurableJob.created_at < cutoff,
            DurableJob.status.in_(['completed', 'failed', 'cancelled']),
            or_(DurableJob.result['source_expired'].as_boolean().is_(None), DurableJob.result['source_expired'].as_boolean() == False))
            .order_by(DurableJob.created_at).limit(batch_size)).all()
        removed = 0
        for candidate in candidates:
            source_id = candidate.payload.get('source_id', '')
            if not re.fullmatch(r'[a-f0-9]{32}', source_id):
                continue
            siblings = db.scalars(select(DurableJob).where(DurableJob.kind == 'discovery',
                DurableJob.payload['source_id'].as_string() == source_id).with_for_update()).all()
            if any(j.status in ('queued', 'running') for j in siblings):
                continue
            folder = upload_root() / source_id
            filename = candidate.payload.get('filename', '')
            path = folder / filename
            if folder.is_symlink() or path.is_symlink() or path.parent != folder or not path.resolve().is_relative_to(upload_root().resolve()):
                continue
            from .discovery_render_cache import remove_source_cache
            remove_source_cache(source_id)
            if path.is_file():
                path.unlink()
                removed += 1
            from .discovery_supplements import remove_supplement_sources
            remove_supplement_sources(upload_root(), siblings)
            for job in siblings:
                job.result = {**job.result, 'source_expired': True}
            db.commit()
    return removed + _cleanup_topic_staging(session_factory, cutoff, batch_size)


def _cleanup_topic_staging(session_factory, cutoff, batch_size):
    """Clean files from expired/terminated retrievals that never reached Discovery."""
    from .topic_intake_models import TopicRevision
    still_waiting = select(TopicRevision.id).where(TopicRevision.processing_job_id == DurableJob.id,
        TopicRevision.status == "pending").exists()
    removed = 0
    with session_factory() as db:
        jobs = db.scalars(select(DurableJob).where(DurableJob.kind == "topic_intake_process",
            DurableJob.created_at < cutoff, DurableJob.status.in_(("completed", "failed", "cancelled")),
            DurableJob.result["topic_staging_checked"].as_boolean().is_(None), ~still_waiting)
            .order_by(DurableJob.created_at).limit(batch_size).with_for_update(skip_locked=True)).all()
        for job in jobs:
            if not re.fullmatch(r"[a-f0-9]{32}", job.id):
                continue
            folder = upload_root() / job.id
            if folder.is_symlink() or folder.resolve().parent != upload_root().resolve():
                continue
            # Published sources use the existing Discovery sibling-aware retention path.
            if folder.is_dir():
                for path in folder.iterdir():
                    abandoned = re.fullmatch(r"[a-f0-9]{32}\.part", path.name)
                    unpublished = path.name == "repository.zip" and not (job.result or {}).get("discovery_job_id")
                    if (abandoned or unpublished) and not path.is_symlink() and path.is_file():
                        path.unlink()
                        removed += 1
            job.result = {**(job.result or {}), "topic_staging_checked": True}
        db.commit()
    return removed
