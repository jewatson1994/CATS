"""Bounded scanner identity preservation; never infer applicability equivalence."""
import json
import re
from urllib.parse import parse_qs, urlsplit

IDENTITY_LIMITS = {
    "architecture": 120, "component_id": 1500, "distro_id": 120, "distro_version": 200,
    "distro_codename": 120, "distro_cpe": 700, "distro_variant": 200,
    "package_origin": 300, "source_package": 300, "source_version": 200,
    "source_rpm": 700, "package_vendor": 300, "package_epoch": 80,
    "package_release": 200, "package_modularity": 300,
    "package_metadata_type": 120, "package_found_by": 200,
    "package_db_path": 1000, "package_db_name": 300, "package_db_version": 200,
    "package_nevra": 1000, "package_metadata": 8192,
    "scanner_name": 80, "scanner_version": 120, "scanner_schema_version": 80,
    "scanner_timestamp": 120,
    "scanner_source_type": 80, "scanner_source_name": 1000,
    "image_id": 180, "image_manifest_digest": 180,
    "image_architecture": 120, "image_os": 120,
}
PROPERTY_PREFIX = "cats:identity:"
COMMENT_PREFIX = "CATS identity: "
# Keep actual field presence, empty strings and nulls in the original projection.
# Flat display fields alone cannot establish source-package equivalence.
PACKAGE_METADATA_FIELDS = frozenset((
    "package", "name", "version", "architecture", "source", "sourceVersion", "sourceRpm",
    "originPackage", "vendor", "modularityLabel", "epoch", "release",
))


def scalar(value):
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def bounded(fields):
    return {key: scalar(value) for key, value in fields.items()
            if key in IDENTITY_LIMITS and scalar(value)
            and len(scalar(value)) <= IDENTITY_LIMITS[key]}


def saved_identity(value):
    result = {}
    for item in value.get("properties") or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            if item["name"].startswith(PROPERTY_PREFIX):
                result[item["name"][len(PROPERTY_PREFIX):]] = item.get("value")
    for line in scalar(value.get("comment") or value.get("documentComment")).splitlines():
        if line.startswith(COMMENT_PREFIX):
            try:
                parsed = json.loads(line[len(COMMENT_PREFIX):])
                if isinstance(parsed, dict):
                    result.update(parsed)
            except (ValueError, TypeError):
                pass
    return bounded(result)


def package_purl(artifact):
    candidates = [artifact.get("purl")]
    for item in artifact.get("externalRefs") or []:
        if isinstance(item, dict) and item.get("referenceType") == "purl":
            candidates.append(item.get("referenceLocator"))
    values = set(value for value in candidates if isinstance(value, str) and value)
    # Ambiguous or oversized identifiers must not be truncated into another identity.
    return next(iter(values)) if len(values) == 1 and len(next(iter(values))) <= 1500 else ""


def primary_database_path(artifact):
    locations = artifact.get("locations")
    paths = set()
    for location in locations if isinstance(locations, list) else []:
        if not isinstance(location, dict):
            continue
        annotations = location.get("annotations")
        if isinstance(annotations, dict) and annotations.get("evidence") == "primary":
            value = location.get("path") or location.get("accessPath")
            if isinstance(value, str) and value:
                paths.add(value)
    return next(iter(paths)) if len(paths) == 1 else ""


def rpm_nevra(artifact, metadata):
    # Descriptive composition of the observed binary record, never a source identity.
    if artifact.get("metadataType") != "rpm-db-entry":
        return ""
    parts = [metadata.get(key) for key in ("name", "version", "release", "architecture")]
    if not all(isinstance(part, str) and part for part in parts):
        return ""
    epoch = metadata.get("epoch")
    if epoch is not None and (isinstance(epoch, bool) or not re.fullmatch(r"[0-9]+", str(epoch))):
        return ""
    name, version, release, architecture = parts
    prefix = str(epoch) + ":" if epoch is not None else ""
    return f"{name}-{prefix}{version}-{release}.{architecture}"


def package_identity(artifact):
    metadata = artifact.get("metadata") if isinstance(artifact.get("metadata"), dict) else {}
    result = saved_identity(artifact)
    original_metadata = {key: value for key, value in metadata.items() if key in PACKAGE_METADATA_FIELDS}
    result.update(bounded({
        "component_id": result.get("component_id") or artifact.get("id") or artifact.get("bom-ref") or artifact.get("SPDXID"),
        "architecture": metadata.get("architecture") or artifact.get("architecture"),
        "package_origin": metadata.get("originPackage"),
        "source_package": metadata.get("source"), "source_version": metadata.get("sourceVersion"),
        "source_rpm": metadata.get("sourceRpm"), "package_vendor": metadata.get("vendor"),
        "package_epoch": metadata.get("epoch"), "package_release": metadata.get("release"),
        "package_modularity": metadata.get("modularityLabel"),
        "package_metadata_type": artifact.get("metadataType"),
        "package_found_by": artifact.get("foundBy"),
        "package_db_path": primary_database_path(artifact),
        "package_db_name": metadata.get("package") or metadata.get("name"),
        "package_db_version": metadata.get("version"),
        "package_nevra": rpm_nevra(artifact, metadata),
        "package_metadata": json.dumps(original_metadata, sort_keys=True, separators=(",", ":")) if original_metadata else "",
    }))
    return result


def purl_fields(purl):
    # These are descriptive fields only. The evaluator validates the full PURL.
    if not isinstance(purl, str) or not re.match(r"^pkg:[a-z][a-z0-9.+-]*/", purl):
        return {}
    try:
        query = parse_qs(urlsplit(purl).query, keep_blank_values=True, max_num_fields=64)
    except ValueError:
        return {}
    fields = {"ecosystem": purl.split(":", 1)[1].split("/", 1)[0]}
    if len(query.get("arch", [])) == 1:
        fields["architecture"] = query["arch"][0]
    return fields


def document_identity(raw):
    result = saved_identity(raw)
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    result.update(saved_identity(metadata))
    distro = raw.get("distro") if isinstance(raw.get("distro"), dict) else {}
    source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    image = source.get("metadata") if isinstance(source.get("metadata"), dict) else {}
    descriptor = raw.get("descriptor") if isinstance(raw.get("descriptor"), dict) else {}
    schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else {}
    result.update(bounded({
        "distro_id": distro.get("id"), "distro_version": distro.get("versionID"),
        "distro_codename": distro.get("versionCodename"), "distro_cpe": distro.get("cpeName"),
        "distro_variant": distro.get("variantID") or distro.get("variant"),
        "scanner_source_type": source.get("type"), "scanner_source_name": source.get("name"),
        "image_id": image.get("imageID"), "image_manifest_digest": image.get("manifestDigest"),
        "image_architecture": image.get("architecture"), "image_os": image.get("os"),
        "scanner_name": descriptor.get("name"), "scanner_version": descriptor.get("version"),
        "scanner_schema_version": schema.get("version"), "scanner_timestamp": descriptor.get("timestamp"),
    }))
    return result


def identity_properties(fields):
    return [{"name": PROPERTY_PREFIX + key, "value": value} for key, value in bounded(fields).items()]


def identity_comment(fields):
    return COMMENT_PREFIX + json.dumps(bounded(fields), sort_keys=True, separators=(",", ":"))
