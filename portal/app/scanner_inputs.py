"""Worker-local binding of a trusted Grype database snapshot to scan execution.

This is evidence groundwork, not a complete patch recipe identity. Configuration
comes only from the worker environment; request JSON cannot select trusted inputs.
The digest is derived from snapshot bytes and checked after copying. The optional
CATS_PATCH_GRYPE_DB_DIGEST is a consistency check, never an identity assertion.
"""
import hashlib
import json
import shutil
import stat
from pathlib import Path


def snapshot_digest(root):
    root = Path(root)
    if root.is_symlink() or getattr(root, "is_junction", lambda: False)() or not root.is_dir():
        raise ValueError("Scanner snapshot must be a real directory")
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("Scanner snapshot cannot contain links")
        mode = path.stat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError("Scanner snapshot cannot contain special files")
        if stat.S_ISREG(mode):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            entries.append([path.relative_to(root).as_posix(), digest.hexdigest()])
    if not entries:
        raise ValueError("Scanner snapshot is empty")
    encoded = json.dumps(entries, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ScannerSnapshot:
    def __init__(self, root, digest):
        self.root, self.digest = root, digest

    def verify(self):
        if snapshot_digest(self.root) != self.digest:
            raise RuntimeError("Bound scanner database changed during patch execution")


def bind_scanner_snapshot(environment, workspace):
    source = environment.pop("CATS_PATCH_GRYPE_DB_SNAPSHOT", "")
    expected = environment.pop("CATS_PATCH_GRYPE_DB_DIGEST", "")
    if not source and not expected:
        return None
    if not source:
        raise ValueError("Trusted scanner snapshot directory is required")
    actual = snapshot_digest(source)
    if expected and actual != expected:
        raise ValueError("Trusted scanner snapshot digest does not match")
    destination = Path(workspace) / "grype-db-snapshot"
    shutil.copytree(source, destination)
    # Derive identity from actual bytes, never from the optional operator check.
    binding = ScannerSnapshot(destination, actual)
    binding.verify()
    environment.update(GRYPE_DB_CACHE_DIR=str(destination), GRYPE_DB_AUTO_UPDATE="false",
                       GRYPE_DB_VALIDATE_BY_HASH_ON_START="true")
    return binding
