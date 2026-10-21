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
            if path.is_file():
                path.unlink()
                removed += 1
            for job in siblings:
                job.result = {**job.result, 'source_expired': True}
            db.commit()
        return removed
