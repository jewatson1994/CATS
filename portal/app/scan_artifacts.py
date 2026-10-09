"""Bounded, checksummed artifact envelopes shared by Portal and scan workers."""
import hashlib
import json
import os
import tarfile
from pathlib import Path, PurePosixPath


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if not name or "\\" in name or ":" in name or path.is_absolute() or any(p in {"..", ".", ""} for p in name.split("/")):
        raise ValueError("Unsafe artifact path")
    return path


def pack(root, destination, identity):
    root = Path(root)
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Artifact links are forbidden")
        if path.is_file():
            name = path.relative_to(root).as_posix()
            safe_name(name)
            files[name] = {"size": path.stat().st_size, "sha256": digest(path)}
    manifest = {"schema": 1, **identity, "files": files}
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    import io
    with tarfile.open(destination, "w") as archive:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(encoded)
        archive.addfile(info, io.BytesIO(encoded))
        for name in files:
            archive.add(root / name, arcname=name, recursive=False)
    return manifest


def unpack(source, destination, identity):
    """Never use extractall: reject duplicates, links, devices and undeclared files."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    maximum = int(os.getenv("CATS_SCAN_DISK_BYTES", str(8 * 1024**3)))
    total, seen = 0, set()
    with tarfile.open(source, "r:*") as archive:
        first = archive.next()
        if not first or first.name != "manifest.json" or not first.isfile() or first.size > 4 * 1024**2:
            raise ValueError("Missing or oversized artifact manifest")
        manifest = json.load(archive.extractfile(first))
        if not isinstance(manifest, dict) or manifest.get("schema") != 1 or any(manifest.get(key) != value for key, value in identity.items()):
            raise ValueError("Artifact identity does not match the authorized attempt")
        declared = manifest.get("files")
        if not isinstance(declared, dict) or len(declared) > 20000:
            raise ValueError("Invalid artifact manifest")
        for name, entry in declared.items():
            safe_name(name)
            if not isinstance(entry, dict) or not isinstance(entry.get("size"), int) or entry["size"] < 0:
                raise ValueError("Invalid artifact length")
            total += entry["size"]
            if total > maximum:
                raise ValueError("Artifact disk budget exceeded")
        for member in iter(archive.next, None):
            safe_name(member.name)
            entry = declared.get(member.name)
            if not member.isfile() or member.name in seen or not entry or member.size != entry["size"]:
                raise ValueError("Unexpected artifact member")
            seen.add(member.name)
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            checksum = hashlib.sha256()
            with archive.extractfile(member) as incoming, target.open("xb") as output:
                for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
                    checksum.update(chunk)
                    output.write(chunk)
            if checksum.hexdigest() != entry.get("sha256"):
                raise ValueError("Artifact checksum mismatch")
        if seen != set(declared):
            raise ValueError("Artifact manifest is incomplete")
    return manifest
