"""Process-lifetime ownership for patch execution on a shared job volume.

This lock fences local duplicate workers, not remote BuildKit operations.
A crashed worker is not automatically safe to retry or publish over.
"""
from contextlib import contextmanager
import os
from pathlib import Path


class ExecutionAlreadyOwned(RuntimeError):
    pass


@contextmanager
def execution_lock(path: Path):
    # Retain the inode: unlinking a lock file permits independent owners.
    with path.open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise ExecutionAlreadyOwned(str(path)) from exc
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ExecutionAlreadyOwned(str(path)) from exc
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
