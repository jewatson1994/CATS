#!/usr/bin/env python3
"""Retain bounded, evidence-backed software identity from Syft/CDX/SPDX SBOMs."""

import json
from pathlib import Path
import sys


LIMITS = {"name": 300, "version": 200, "ecosystem": 80, "purl": 700,
          "image": 1000, "cpe": 700, "supplier": 300, "author": 300,
          "architecture": 120, "hashes": 1000, "copyright": 500,
          "license_declared": 500, "license_detected": 500,
          "license_expression": 500, "license_source": 120,
          "location": 1000, "sbom": 300, "image_digest": 180,
          "dependency_parents": 1000, "dependency_children": 1000}


def text(value):
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def license_text(items):
    if isinstance(items, str):
        return items
    values = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, dict):
            value = item.get("license") or item.get("spdxExpression") or item.get("expression") or item.get("value")
            if isinstance(value, dict):
                value = value.get("id") or value.get("name")
            if value:
                values.append(str(value))
    return "; ".join(dict.fromkeys(values))


def normalize(artifact, image, digest, sbom_name, source, graph=None):
    if not isinstance(artifact, dict):
        return None
    name = artifact.get("name") or artifact.get("PackageName")
    if not name:
        return None
    metadata = artifact.get("metadata") if isinstance(artifact.get("metadata"), dict) else {}
    supplier = artifact.get("supplier") or ""
    if isinstance(supplier, dict):
        supplier = supplier.get("name") or ""
    cpe = artifact.get("cpe") or ""
    for item in artifact.get("cpes") or artifact.get("externalRefs") or []:
        candidate = item if isinstance(item, str) else item.get("referenceLocator", "") if isinstance(item, dict) else ""
        if not cpe and str(candidate).startswith("cpe:"):
            cpe = candidate
    hashes = artifact.get("hashes") or artifact.get("checksums") or []
    hash_text = "; ".join(f"{item.get('alg') or item.get('algorithm')}:{item.get('content') or item.get('checksumValue')}"
                          for item in hashes[:8] if isinstance(item, dict)
                          and (item.get("alg") or item.get("algorithm")) and (item.get("content") or item.get("checksumValue")))
    licenses = artifact.get("licenses") or []
    declared = artifact.get("licenseDeclared") or license_text(licenses)
    detected = ""
    if source == "Syft" and isinstance(licenses, list):
        declared_items = [item.get("spdxExpression") or item.get("value") for item in licenses
                          if isinstance(item, dict) and item.get("type") == "declared"]
        detected_items = [item.get("spdxExpression") or item.get("value") for item in licenses
                          if isinstance(item, dict) and item.get("type") == "concluded"]
        declared = "; ".join(dict.fromkeys(filter(None, declared_items))) or declared
        detected = "; ".join(dict.fromkeys(filter(None, detected_items)))
    expression = artifact.get("licenseExpression") or artifact.get("licenseConcluded") or ""
    locations = artifact.get("locations") or []
    location = locations[0].get("path") if locations and isinstance(locations[0], dict) else ""
    reference = artifact.get("bom-ref") or artifact.get("SPDXID") or artifact.get("id")
    parents, children = (graph or {}).get(reference, ((), ()))
    fields = {"name": name, "version": artifact.get("version") or artifact.get("versionInfo"),
              "ecosystem": artifact.get("type") or artifact.get("primaryPackagePurpose"),
              "purl": artifact.get("purl"), "image": image, "image_digest": digest,
              "cpe": cpe, "supplier": supplier, "author": artifact.get("author") or artifact.get("originator"),
              "architecture": metadata.get("architecture") or artifact.get("architecture"),
              "hashes": hash_text, "copyright": artifact.get("copyright") or artifact.get("copyrightText"),
              "license_declared": declared, "license_detected": detected, "license_expression": expression,
              "license_source": source if declared or detected or expression else "",
              "location": location, "sbom": sbom_name,
              "dependency_parents": "; ".join(parents[:12]),
              "dependency_children": "; ".join(children[:12])}
    return {key: text(value)[:LIMITS[key]] for key, value in fields.items() if text(value)}


def main(root: Path, output: Path) -> None:
    components = []
    images = []
    for path in sorted(root.glob("*.json")):
        image_path = path.with_suffix(".image")
        if not image_path.is_file():
            continue
        image = image_path.read_text(encoding="utf-8").strip()[:1000]
        digest_path = path.with_suffix(".digest")
        digest = digest_path.read_text(encoding="utf-8").strip()[:180] if digest_path.is_file() else ""
        try:
            sbom = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(sbom, dict):
                continue
            if isinstance(sbom.get("artifacts"), list):
                artifacts, source = sbom["artifacts"], "Syft"
            elif isinstance(sbom.get("components"), list):
                artifacts, source = sbom["components"], "CycloneDX"
            elif isinstance(sbom.get("packages"), list):
                artifacts, source = sbom["packages"], "SPDX"
            else:
                continue
            edges = []
            if source == "CycloneDX":
                for relation in sbom.get("dependencies") or []:
                    if isinstance(relation, dict) and isinstance(relation.get("ref"), str):
                        edges.extend((relation["ref"], child) for child in relation.get("dependsOn") or []
                                     if isinstance(child, str))
            elif source == "SPDX":
                for relation in sbom.get("relationships") or []:
                    if not isinstance(relation, dict):
                        continue
                    kind = relation.get("relationshipType")
                    source_ref, target_ref = relation.get("spdxElementId"), relation.get("relatedSpdxElement")
                    if isinstance(source_ref, str) and isinstance(target_ref, str):
                        if kind == "DEPENDS_ON":
                            edges.append((source_ref, target_ref))
                        elif kind == "DEPENDENCY_OF":
                            edges.append((target_ref, source_ref))
            graph = {}
            for parent, child in edges[:100000]:
                graph.setdefault(parent, [[], []])[1].append(child)
                graph.setdefault(child, [[], []])[0].append(parent)
            images.append(image)
            for artifact in artifacts:
                if len(components) >= 50000:
                    break
                row = normalize(artifact, image, digest, path.name, source, graph)
                if row:
                    components.append(row)
        except (OSError, ValueError, UnicodeError):
            continue
    output.write_text(json.dumps({"components": components, "images": sorted(set(images))}), encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
