"""Atomic offline database publication and attempt-scoped scanner snapshots.

The pointer is replaced only after a complete, hashed generation exists. Published
generations are never modified or removed by an import; active scans can therefore
continue reading their pinned generation while later attempts see a new pointer.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
import uuid

POINTER = ".cats-current.json"
GENERATIONS = ".cats-generations"
DEFAULT_SOURCES = {"grype": "/opt/catscan/grype-db", "trivy": "/opt/catscan/trivy-cache"}


def _hash(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _files(root: Path) -> dict:
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Scanner database contains a symbolic link")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = {"size": path.stat().st_size, "sha256": _hash(path)}
        elif not path.is_dir():
            raise ValueError("Scanner database contains a special file")
    if not files:
        raise ValueError("Scanner database is empty")
    return files


def _identity(files: dict) -> str:
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _atomic_json(path: Path, value: dict) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".cats-pointer-", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(json.dumps(value, sort_keys=True).encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    try:
        # Concurrent publishers or antivirus can retain a Windows file handle.
        # Retry only that sharing condition; never remove the active pointer or
        # fall back to a non-atomic write.
        for attempt in range(5):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 4:
                    raise
                time.sleep(0.025 * (attempt + 1))
    finally:
        temporary.unlink(missing_ok=True)


def publish_generation(staged: Path, destination: Path, scanner: str, metadata: dict) -> dict:
    """Publish a validated database without replacing the mounted volume root."""
    if scanner not in DEFAULT_SOURCES:
        raise ValueError("Unknown scanner database")
    destination.mkdir(parents=True, exist_ok=True)
    generations = destination / GENERATIONS
    generations.mkdir(exist_ok=True)
    generation = uuid.uuid4().hex
    candidate = generations / (".staging-" + generation)
    final = generations / generation
    try:
        candidate.mkdir()
        shutil.copytree(staged, candidate / "data", symlinks=True)
        files = _files(candidate / "data")
        manifest = {"schema_version": 1, "scanner": scanner, "generation": generation,
                    "identity": _identity(files), "published_at": datetime.now(timezone.utc).isoformat(),
                    "version": metadata.get("schemaVersion", metadata.get("Version", metadata.get("version"))),
                    "built_at": metadata.get("built", metadata.get("Built", metadata.get("UpdatedAt"))),
                    "metadata": metadata, "files": files}
        _atomic_json(candidate / "manifest.json", manifest)
        # Antivirus/indexing on Windows can briefly retain a handle after the
        # manifest closes. Retry that transient sharing failure only; publication
        # still requires a successful same-directory atomic rename.
        for attempt in range(5):
            try:
                candidate.rename(final)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 4:
                    raise
                time.sleep(0.025 * (attempt + 1))
        # Concurrent imports have separate generation directories and separate
        # temporary pointer files. Readers observe one complete pointer atomically.
        _atomic_json(destination / POINTER, {"generation": generation, "identity": manifest["identity"]})
        return manifest
    finally:
        shutil.rmtree(candidate, ignore_errors=True)


def _read_json(path: Path) -> dict:
    if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Invalid scanner database manifest")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Invalid scanner database manifest")
    return value


def _select(source: Path, scanner: str) -> tuple[Path, dict]:
    pointer = _read_json(source / POINTER)
    generation = str(pointer.get("generation", ""))
    if not re.fullmatch(r"[0-9a-f]{32}", generation):
        raise ValueError("Invalid scanner database generation")
    directory = source / GENERATIONS / generation
    if directory.is_symlink() or (directory / "data").is_symlink():
        raise ValueError("Invalid scanner database generation path")
    manifest = _read_json(directory / "manifest.json")
    if (manifest.get("scanner") != scanner or manifest.get("generation") != generation
            or manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), dict)
            or _identity(manifest["files"]) != manifest.get("identity")
            or pointer.get("identity") != manifest.get("identity")):
        raise ValueError("Scanner database generation identity mismatch")
    return directory / "data", manifest


def pin_databases(environment: dict, workspace: Path) -> dict:
    """Copy the current generations into a private attempt workspace and fence hashes.

    Source paths are separate from writable worker caches. Scanner subprocesses
    receive only private cache paths and cannot mutate another attempt's snapshot.
    A legacy image database is also hashed, and is reported as unversioned.
    """
    provenance = {}
    environment.update(GRYPE_DB_AUTO_UPDATE="false", GRYPE_DB_REQUIRE_UPDATE_CHECK="false",
                       TRIVY_SKIP_DB_UPDATE="true", TRIVY_SKIP_JAVA_DB_UPDATE="true",
                       TRIVY_SKIP_CHECK_UPDATE="true")
    for scanner in DEFAULT_SOURCES:
        source = Path(environment.get("CATS_SCAN_" + scanner.upper() + "_SOURCE", DEFAULT_SOURCES[scanner]))
        cache = workspace / "intelligence" / scanner
        cache.parent.mkdir(parents=True, exist_ok=True)
        manifest = None
        if (source / POINTER).exists():
            selected, manifest = _select(source, scanner)
            shutil.copytree(selected, cache, symlinks=True)
            if _files(cache) != manifest["files"]:
                raise ValueError(f"{scanner} database generation integrity mismatch")
        else:
            cache.mkdir()
            if source.exists():
                # Hidden generation staging directories must never become legacy data.
                for child in source.iterdir():
                    if child.name.startswith(".cats-"):
                        continue
                    if child.is_symlink():
                        raise ValueError("Scanner database contains a symbolic link")
                    if child.is_dir():
                        shutil.copytree(child, cache / child.name, symlinks=True)
                    else:
                        shutil.copy2(child, cache / child.name)
            if any(cache.iterdir()):
                files = _files(cache)
                metadata = {}
                locations = list(cache.rglob("metadata.json")) + list(cache.rglob("latest.json"))
                if locations:
                    metadata = _read_json(locations[0])
                manifest = {"generation": "legacy", "identity": _identity(files), "metadata": metadata,
                            "version": metadata.get("schemaVersion", metadata.get("Version")),
                            "built_at": metadata.get("built", metadata.get("UpdatedAt"))}
        provenance[scanner] = ({key: value for key, value in manifest.items() if key != "files"}
                               if manifest else {"status": "unavailable"})
        if manifest:
            provenance[scanner]["status"] = "pinned" if manifest["generation"] != "legacy" else "legacy"
        if scanner == "grype":
            environment["GRYPE_DB_CACHE_DIR"] = str(cache)
            environment["GRYPE_DB_METADATA"] = str(cache / "latest.json")
        else:
            environment["TRIVY_CACHE_DIR"] = str(cache)
    return provenance


def intelligence_status(provenance: dict, environment: dict | None = None) -> dict:
    """Mark pinned identities superseded during execution, without changing scans."""
    environment = environment or os.environ
    result = {}
    for scanner, pinned in provenance.items():
        source = Path(environment.get("CATS_SCAN_" + scanner.upper() + "_SOURCE", DEFAULT_SOURCES[scanner]))
        try:
            _, current = _select(source, scanner)
            status = "current" if current["identity"] == pinned.get("identity") else "superseded"
            result[scanner] = {"status": status, "current_generation": current["generation"]}
        except FileNotFoundError:
            result[scanner] = {"status": "unversioned" if pinned.get("status") == "legacy" else "unavailable"}
        except (OSError, ValueError):
            result[scanner] = {"status": "invalid"}
    return result
