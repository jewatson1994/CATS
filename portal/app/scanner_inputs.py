"""Worker-local binding of a trusted Grype database snapshot to scan execution.

This is evidence groundwork, not a complete patch recipe identity. Configuration
comes only from the worker environment; request JSON cannot select trusted inputs.
"""
import hashlib
import json
import shutil
from pathlib import Path


def snapshot_digest(root):
    root = Path(root)
    if root.is_symlink() or getattr(root, "is_junction", lambda: False)() or not root.is_dir():
        raise ValueError("Scanner snapshot must be a real directory")
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("Scanner snapshot cannot contain links")
        if path.is_file():
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
    if not source or not expected or snapshot_digest(source) != expected:
        raise ValueError("Trusted scanner snapshot digest does not match")
    destination = Path(workspace) / "grype-db-snapshot"
    shutil.copytree(source, destination)
    binding = ScannerSnapshot(destination, expected)
    binding.verify()
    environment.update(GRYPE_DB_CACHE_DIR=str(destination), GRYPE_DB_AUTO_UPDATE="false",
                       GRYPE_DB_VALIDATE_BY_HASH_ON_START="true")
    return binding
