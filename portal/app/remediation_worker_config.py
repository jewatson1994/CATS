"""Validate remediation capacity before importing modules that create DB pools."""
import os


def _integer(name, value, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}") from None
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return parsed


def configure(environ=None):
    """Return concurrency and reserve bounded connections for jobs and leases.

    Handlers can retain a session while opening another for a lease check. Two
    connections per concurrent handler plus two spare connections leave room
    for heartbeat renewal. Serial workers retain their original routing/pools.
    """
    environ = os.environ if environ is None else environ
    workers = _integer("CATS_REMEDIATION_WORKERS", environ.get("CATS_REMEDIATION_WORKERS") or "1", 1, 32)
    minimum = 2 if workers == 1 else 2 * workers + 2
    configured = environ.get("CATS_REMEDIATION_DB_POOL_SIZE") or environ.get("CATS_DB_BACKGROUND_POOL_SIZE")
    pool_size = _integer("CATS_REMEDIATION_DB_POOL_SIZE / CATS_DB_BACKGROUND_POOL_SIZE",
                         configured or str(minimum), minimum, 512)
    environ["CATS_DB_BACKGROUND_POOL_SIZE"] = str(pool_size)
    environ["CATS_DB_BACKGROUND_MAX_OVERFLOW"] = "0"
    return workers
