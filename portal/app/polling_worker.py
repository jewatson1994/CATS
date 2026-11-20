"""Poll configured OCI sources and consume manual or scheduled synchronization jobs."""
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
    if os.getenv('CATS_REPLICA_SYNC_ENABLED', 'true').strip().lower() in {'1', 'true', 'yes'}:
        install_execution_summary_hooks(SessionLocal.class_)
        durable_jobs.run_worker((replica_sync.KIND,), replica_sync.sync,
                                maintenance=replica_sync.schedule_due, maintenance_interval=5)
        return
    # A disabled service stays idle under Compose's restart policy.
    logging.getLogger(__name__).info('OCI polling is disabled')
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()


if __name__ == '__main__':
    main()
