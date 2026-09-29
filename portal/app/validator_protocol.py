"""Versioned, bounded CATS deployment validation wire contract."""

from __future__ import annotations

from pathlib import PurePosixPath
import re


SCHEMA_VERSION = "cats.validation/v1"


def validate_package(package: dict, *, max_bytes: int = 100 * 1024 * 1024) -> dict:
    if not isinstance(package, dict) or package.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported validation package schema version")
    manifest = package.get("manifest")
    artifact = package.get("artifact")
    if not isinstance(manifest, dict) or not isinstance(artifact, dict):
        raise ValueError("Validation package requires manifest and artifact")
    service = str(manifest.get("service_key") or "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,119}", service):
        raise ValueError("Invalid service key")
    source_files = artifact.get("source_files")
    if not isinstance(source_files, dict) or not source_files or len(source_files) > 5000:
        raise ValueError("Validation package requires bounded source files")
    total = 0
    normalized = set()
    for name, content in source_files.items():
        if not isinstance(name, str) or not isinstance(content, str):
            raise ValueError("Source files must be UTF-8 text")
        path = PurePosixPath(name.replace("\\", "/"))
        if not name or len(name) > 500 or path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
            raise ValueError("Unsafe source path")
        if str(path) in normalized:
            raise ValueError("Duplicate source path")
        normalized.add(str(path))
        total += len(name.encode()) + len(content.encode())
        if total > max_bytes:
            raise ValueError("Validation package exceeds source size limit")
    values = artifact.get("values_files") or []
    if not isinstance(values, list) or len(values) > 50 or any(value not in normalized for value in values):
        raise ValueError("Values files must be retained in the package")
    declared = artifact.get("declared_resources") or []
    if not isinstance(declared, list) or len(declared) > 5000 or any(not isinstance(item, dict) for item in declared):
        raise ValueError("Declared resources are invalid or too large")
    timeout = manifest.get("timeout_seconds", 600)
    if not isinstance(timeout, int) or not 30 <= timeout <= 3600:
        raise ValueError("Validation timeout must be 30 to 3600 seconds")
    namespace = manifest.get("namespace")
    if namespace and (not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", namespace)):
        raise ValueError("Validation namespace is invalid")
    images = manifest.get("referenced_images") or []
    capabilities = manifest.get("required_capabilities") or []
    if not isinstance(images, list) or len(images) > 500 or any(not isinstance(image, str) or not image or len(image) > 1000 for image in images):
        raise ValueError("Referenced image list is invalid")
    if not isinstance(capabilities, list) or len(capabilities) > 50 or any(not isinstance(item, str) or len(item) > 80 for item in capabilities):
        raise ValueError("Required capabilities are invalid")
    return package
