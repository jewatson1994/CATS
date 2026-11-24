"""Consume OCI synchronization and full-portal GitLab topic intake on independent slots."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import logging
import os
from pathlib import Path
import shutil
import signal
import threading

from . import dependency_queries, durable_jobs, replica_sync  # dependency queries registers write invalidations
from .database import SessionLocal
from .execution_summaries import install_execution_summary_hooks
from .operating_mode import is_replica
from .patch_ownership import execution_lock


@contextmanager
def verification_workspace():
    location = os.getenv('CATS_POLLING_VERIFY_DIR')
    if not location:
        yield
        return
    root = Path(location)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The kernel releases this lock on process death. A mistakenly shared
    # scratch volume cannot clean files that another worker is still using.
    with execution_lock(root / '.worker.lock'):
        for abandoned in root.glob('cats-release-verify-*'):
            if abandoned.is_dir() and not abandoned.is_symlink():
                shutil.rmtree(abandoned)
        yield


def main():
    with verification_workspace():
        _run()


def _run():
    oci = os.getenv('CATS_REPLICA_SYNC_ENABLED', 'true').strip().lower() in {'1', 'true', 'yes'}
    install_execution_summary_hooks(SessionLocal.class_)
    if is_replica() and oci:
        _oci_worker()
        return
    if not is_replica() and not oci:
        _topic_worker()
        return
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    if is_replica():
        logging.getLogger(__name__).info('OCI polling is disabled')
        stop.wait()
        return
    # A large OCI download and a busy GitLab namespace each retain a slot.
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='gitlab-poll') as pool:
        topic = pool.submit(_topic_worker, stop)
        topic.add_done_callback(lambda _: stop.set())
        try:
            _oci_worker(stop)
        finally:
            stop.set()
        topic.result()


def _oci_worker(stop=None):
    durable_jobs.run_worker((replica_sync.KIND,), replica_sync.sync,
                            maintenance=replica_sync.schedule_due, maintenance_interval=5, stop_event=stop)


def _topic_worker(stop=None):
    from . import gitlab_topic_poll, topic_intake_processing

    def maintenance():
        try:
            gitlab_topic_poll.schedule_due()
        finally:
            topic_intake_processing.advance_ready()

    def handle(ctx, payload):
        if ctx.job.kind in (gitlab_topic_poll.KIND, gitlab_topic_poll.PREVIEW_KIND):
            return gitlab_topic_poll.poll(ctx, payload)
        return topic_intake_processing.handler(ctx, payload)

    durable_jobs.run_worker((gitlab_topic_poll.KIND, gitlab_topic_poll.PREVIEW_KIND, topic_intake_processing.KIND), handle,
                            maintenance=maintenance, maintenance_interval=5, stop_event=stop)


if __name__ == '__main__':
    main()
