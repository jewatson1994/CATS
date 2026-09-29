"""Bounded expired-preview deletion with an explicitly joined lifespan worker."""
import asyncio
from contextlib import asynccontextmanager
import logging
import math
import os
import threading

from sqlalchemy import delete, select
from .models import BundlePreview, ExchangePreview, utcnow


def expired_delete_statement(model, cutoff, batch_size):
    expired = (select(model.token).where(model.expires_at <= cutoff)
               .order_by(model.expires_at, model.token).limit(batch_size))
    return delete(model).where(model.token.in_(expired), model.expires_at <= cutoff)


def cleanup_expired_previews(session_factory, batch_size=100):
    if batch_size < 1:
        raise ValueError("Preview cleanup batch must be positive")
    cutoff = utcnow()
    total = 0
    # Separate transactions bound each table's deletion and lock duration.
    for model in (BundlePreview, ExchangePreview):
        with session_factory() as session:
            result = session.execute(expired_delete_statement(model, cutoff, batch_size),
                                     execution_options={"synchronize_session": False})
            session.commit()
            total += result.rowcount
    return total


@asynccontextmanager
async def preview_cleanup_lifespan(session_factory):
    interval = float(os.getenv("CATS_PREVIEW_CLEANUP_INTERVAL_SECONDS", "300"))
    batch = int(os.getenv("CATS_PREVIEW_CLEANUP_BATCH_SIZE", "100"))
    if not math.isfinite(interval) or interval <= 0 or batch < 1:
        raise ValueError("Preview cleanup interval and batch must be positive")
    stopped = threading.Event()

    def worker():
        while not stopped.wait(interval):
            try:
                cleanup_expired_previews(session_factory, batch)
            except Exception:
                logging.getLogger(__name__).exception("Expired preview cleanup failed")

    thread = threading.Thread(target=worker, name="cats-preview-cleanup", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        # Finish an in-flight bounded transaction before disposing application resources.
        await asyncio.to_thread(thread.join)
