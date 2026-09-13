#!/usr/bin/env python3
"""Serialize one Syft inventory into additional offline SBOM formats."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid
import xml.etree.ElementTree as ET


FORMAT_ALIASES = {
    "syft": "syft-json",
    "syft-json": "syft-json",
    "cyclonedx": "cyclonedx-json",
    "cyclonedx-json": "cyclonedx-json",
    "cdx-json": "cyclonedx-json",
    "cyclonedx-xml": "cyclonedx-xml",
    "cdx-xml": "cyclonedx-xml",
    "spdx": "spdx-json",
    "spdx-json": "spdx-json",
}
SUPPORTED = {"syft-json", "cyclonedx-json", "cyclonedx-xml", "spdx-json"}


def requested_formats(value: str) -> list[str]:
    values = [part.strip().lower() for part in value.replace(";", ",").split(",") if part.strip()]
    result = []
    for value in values or ["syft-json"]:
        normalized = FORMAT_ALIASES.get(value)
        if normalized not in SUPPORTED:
            raise ValueError(f"Unsupported SBOM format: {value}")
        if normalized not in result:
            result.append(normalized)
    return result


def text(value: object, fallback: str = "") -> str:
    return str(value).strip() if value is not None and str(value).strip() else fallback


def component_type(artifact: dict) -> str:
    kind = text(artifact.get("type"), "library").lower()
    return "application" if kind in {"application", "binary", "file"} else "library"


def component_ref(artifact: dict, index: int) -> str:
    purl = text(artifact.get("purl"))
    if purl:
        return purl
    return f"pkg:generic/{text(artifact.get('name'), 'unknown').replace(' ', '%20')}@{text(artifact.get('version'), 'unknown')}?cats-index={index}"


def artifact_license(artifact: dict) -> str:
    licenses = artifact.get("licenses") or []
    names = []
    for item in licenses:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            names.append(text(item.get("spdxExpression") or item.get("value") or item.get("name")))
    return " AND ".join(dict.fromkeys(value for value in names if value)) or "NOASSERTION"


def source_metadata(raw: dict, image: str, digest: str, timestamp: str) -> dict:
    descriptor = raw.get("descriptor") if isinstance(raw.get("descriptor"), dict) else {}
    generator = text(descriptor.get("name"), "Syft")
    generator_version = text(descriptor.get("version"), "unknown")
    return {
        "format": "syft-json",
        "spec_version": text(raw.get("schema", {}).get("version") if isinstance(raw.get("schema"), dict) else "", "unknown"),
        "version": "1",
        "generator": generator,
        "generator_version": generator_version,
        "timestamp": timestamp,
        "source": image or text((raw.get("source") or {}).get("name") if isinstance(raw.get("source"), dict) else "", "unknown"),
        "digest": digest or "",
    }


def cdx_document(raw: dict, image: str, digest: str, spec_version: str, timestamp: str) -> dict:
    descriptor = raw.get("descriptor") if isinstance(raw.get("descriptor"), dict) else {}
    generator_version = text(descriptor.get("version"), "unknown")
    source = image or text((raw.get("source") or {}).get("name") if isinstance(raw.get("source"), dict) else "", "unknown")
    components = []
    for index, artifact in enumerate(raw.get("artifacts") or [], 1):
        if not isinstance(artifact, dict):
            continue
        item = {
            "type": component_type(artifact),
            "bom-ref": component_ref(artifact, index),
            "name": text(artifact.get("name"), "unknown"),
            "version": text(artifact.get("version"), "unknown"),
            "licenses": [{"license": {"id": artifact_license(artifact)}}],
        }
        if artifact.get("purl"):
            item["purl"] = artifact["purl"]
        components.append(item)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, source + '|' + digest)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "Anchore", "name": text(descriptor.get("name"), "Syft"), "version": generator_version}],
            "properties": [{"name": "cats:source", "value": source}, {"name": "cats:digest", "value": digest or ""}],
        },
        "components": components,
    }


def cdx_xml(document: dict) -> bytes:
    namespace = f"http://cyclonedx.org/schema/bom/{document['specVersion']}"
    root = ET.Element("bom", {"xmlns": namespace, "version": str(document["version"]), "serialNumber": document["serialNumber"]})
    ET.SubElement(root, "metadata").append(ET.Element("timestamp"))
    metadata = root.find("metadata")
    metadata.find("timestamp").text = document["metadata"]["timestamp"]
    tools = ET.SubElement(metadata, "tools")
    for tool in document["metadata"]["tools"]:
        element = ET.SubElement(tools, "tool")
        ET.SubElement(element, "vendor").text = tool["vendor"]
        ET.SubElement(element, "name").text = tool["name"]
        ET.SubElement(element, "version").text = tool["version"]
    properties = ET.SubElement(metadata, "properties")
    for property_item in document["metadata"]["properties"]:
        prop = ET.SubElement(properties, "property", {"name": property_item["name"]})
        prop.text = property_item["value"]
    components = ET.SubElement(root, "components")
    for item in document["components"]:
        component = ET.SubElement(components, "component", {"type": item["type"], "bom-ref": item["bom-ref"]})
        ET.SubElement(component, "name").text = item["name"]
        ET.SubElement(component, "version").text = item["version"]
        if item.get("purl"):
            ET.SubElement(component, "purl").text = item["purl"]
        licenses = ET.SubElement(component, "licenses")
        license_item = item["licenses"][0]["license"]["id"]
        ET.SubElement(licenses, "license").append(ET.Element("id"))
        licenses.find("license/id").text = license_item
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def spdx_document(raw: dict, image: str, digest: str, timestamp: str) -> dict:
    descriptor = raw.get("descriptor") if isinstance(raw.get("descriptor"), dict) else {}
    source = image or text((raw.get("source") or {}).get("name") if isinstance(raw.get("source"), dict) else "", "unknown")
    namespace = f"https://cats.example.invalid/spdx/{hashlib.sha256((source + '|' + digest).encode()).hexdigest()}"
    packages = []
    for index, artifact in enumerate(raw.get("artifacts") or [], 1):
        if not isinstance(artifact, dict):
            continue
        packages.append({
            "SPDXID": f"SPDXRef-Package-{index}",
            "name": text(artifact.get("name"), "unknown"),
            "versionInfo": text(artifact.get("version"), "unknown"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": artifact_license(artifact),
            "externalRefs": ([{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": artifact["purl"]}] if artifact.get("purl") else []),
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": source,
        "documentNamespace": namespace,
        "creationInfo": {"created": timestamp, "creators": [f"Tool: {text(descriptor.get('name'), 'Syft')} {text(descriptor.get('version'), 'unknown')}"]},
        "documentComment": f"CATS source={source}; digest={digest or 'unknown'}",
        "packages": packages,
    }


def update_manifest(path: Path, entries: list[dict]) -> None:
    current = {item.get("path"): item for item in (json.loads(path.read_text(encoding="utf-8")).get("reports", []) if path.exists() else []) if isinstance(item, dict)}
    for entry in entries:
        current[entry["path"]] = entry
    path.write_text(json.dumps({"schema_version": "cats.sbom/v1", "reports": list(current.values())}, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--digest", default="")
    parser.add_argument("--formats", default="syft-json")
    parser.add_argument("--cyclonedx-spec-version", default="1.5")
    args = parser.parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    formats = requested_formats(args.formats)
    base = input_path.stem
    metadata = source_metadata(raw, args.image, args.digest, timestamp)
    entries = []
    for format_name in formats:
        if format_name == "syft-json":
            target = input_path
            spec_version = metadata["spec_version"]
        elif format_name == "cyclonedx-json":
            target = output_dir / f"{base}.cyclonedx.json"
            target.write_text(json.dumps(cdx_document(raw, args.image, args.digest, args.cyclonedx_spec_version, timestamp), indent=2) + "\n", encoding="utf-8")
            spec_version = args.cyclonedx_spec_version
        elif format_name == "cyclonedx-xml":
            target = output_dir / f"{base}.cyclonedx.xml"
            target.write_bytes(cdx_xml(cdx_document(raw, args.image, args.digest, args.cyclonedx_spec_version, timestamp)))
            spec_version = args.cyclonedx_spec_version
        else:
            target = output_dir / f"{base}.spdx.json"
            target.write_text(json.dumps(spdx_document(raw, args.image, args.digest, timestamp), indent=2) + "\n", encoding="utf-8")
            spec_version = "SPDX-2.3"
        entries.append({**metadata, "format": format_name, "spec_version": spec_version, "path": target.as_posix(), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    update_manifest(output_dir / "manifest.json", entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
