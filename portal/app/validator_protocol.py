"""Versioned, bounded CATS deployment validation wire contract."""

from __future__ import annotations

from pathlib import PurePosixPath
import re
import json


SCHEMA_VERSION = "cats.validation/v1"


def _fields(value, allowed, label):
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError(f"Invalid {label} fields")


def _text(value, limit):
    return isinstance(value, str) and len(value) <= limit and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def strict_json_loads(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Invalid JSON number")))


def validate_package(package: dict, *, max_bytes: int = 100 * 1024 * 1024) -> dict:
    if not isinstance(package, dict) or package.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported validation package schema version")
    manifest = package.get("manifest")
    artifact = package.get("artifact")
    _fields(package, {"schema_version", "manifest", "artifact"}, "package")
    _fields(manifest, {"service_key", "timeout_seconds", "namespace", "referenced_images", "required_capabilities"}, "manifest")
    _fields(artifact, {"source_files", "values_files", "declared_resources", "artifact_type", "reference"}, "artifact")
    try:
        encoded = json.dumps(package, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError("Package must contain bounded JSON data") from exc
    if len(encoded) > max_bytes:
        raise ValueError("Validation package exceeds size limit")
    if not isinstance(manifest, dict) or not isinstance(artifact, dict):
        raise ValueError("Validation package requires manifest and artifact")
    service = manifest.get("service_key")
    if not isinstance(service, str):
        raise ValueError("Invalid service key")
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
        path = PurePosixPath(name)
        if not path.parts or not _text(name, 500) or "\\" in name or str(path) != name or path.is_absolute() or ".." in path.parts or ":" in name:
            raise ValueError("Unsafe source path")
        if str(path) in normalized:
            raise ValueError("Duplicate source path")
        normalized.add(str(path))
        total += len(name.encode()) + len(content.encode())
        if total > max_bytes:
            raise ValueError("Validation package exceeds source size limit")
    values = artifact.get("values_files", [])
    if not isinstance(values, list) or len(values) > 50 or any(not isinstance(value, str) or value not in normalized for value in values) or len(set(values)) != len(values):
        raise ValueError("Values files must be retained in the package")
    declared = artifact.get("declared_resources", [])
    if not isinstance(declared, list) or len(declared) > 5000 or any(not isinstance(item, dict) for item in declared):
        raise ValueError("Declared resources are invalid or too large")
    timeout = manifest.get("timeout_seconds", 600)
    if type(timeout) is not int or not 30 <= timeout <= 3600:
        raise ValueError("Validation timeout must be 30 to 3600 seconds")
    namespace = manifest.get("namespace")
    if "namespace" in manifest and (not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", namespace)):
        raise ValueError("Validation namespace is invalid")
    images = manifest.get("referenced_images", [])
    capabilities = manifest.get("required_capabilities", [])
    if not isinstance(images, list) or len(images) > 500 or any(not _text(image, 1000) or not image for image in images):
        raise ValueError("Referenced image list is invalid")
    if not isinstance(capabilities, list) or len(capabilities) > 50 or any(not _text(item, 80) or not item for item in capabilities):
        raise ValueError("Required capabilities are invalid")
    for field in ("artifact_type", "reference"):
        if field in artifact and not _text(artifact[field], 1000):
            raise ValueError(f"Invalid artifact {field}")
    return package
