"""Cross-process delivery ownership released automatically on process exit."""
from contextlib import contextmanager
import os
from pathlib import Path


@contextmanager
def delivery_lock(root, attempt_id):
    if not isinstance(attempt_id, int) or attempt_id < 1:
        raise ValueError("Invalid delivery identity")
    directory = Path(root) / ".delivery-locks"
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise ValueError("Unsafe delivery lock path")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / str(attempt_id)
    if path.is_symlink():
        raise ValueError("Unsafe delivery lock file")
    with path.open("a+b") as stream:
        if path.stat().st_size == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
