#!/usr/bin/env python3
"""Capture live, offline Syft/Grype evidence from locally available Docker images.

Pull images explicitly before running. This script never updates intelligence,
starts a target image, touches existing containers, or changes shared databases.
Raw evidence remains in --output; bounded identity projections go to --summary-dir.
The Grype --only-fixed filter is identical to scanning-main/scripts/scan-sboms.sh.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid


IMAGES = {
    "ubuntu": "ubuntu:jammy-20260731.1",
    "debian": "debian:bookworm-slim",
    "alpine": "httpd:2.4-alpine",
    "redhat-ubi": "registry.access.redhat.com/ubi9/ubi:9.6",
    "suse": "registry.suse.com/bci/bci-base:15.6",
    "python": "python:3.11.13-slim-bookworm",
    "node": "node:20-bookworm-slim",
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def run(args, *, check=True):
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", check=False)
    if check and result.returncode:
        raise RuntimeError(f"{args[:4]} failed ({result.returncode}): {result.stderr[-3000:]}")
    return result


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def file_provenance(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {"name": path.name, "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def valid_purl(value):
    """Conservative syntax checks; counts are not assertions of applicability."""
    if not isinstance(value, str) or not value.startswith("pkg:") or re.search(r"\s|%(?![0-9a-fA-F]{2})", value):
        return False
    main = value[4:].split("#", 1)[0].split("?", 1)[0]
    ecosystem, separator, path = main.partition("/")
    if not separator or not re.fullmatch(r"[a-z][a-z0-9.+-]*", ecosystem):
        return False
    name, sep, version = path.rpartition("@")
    if not sep:
        name = path
    if not name or (sep and not version) or any(not piece or unquote(piece) in {".", ".."} for piece in name.split("/")):
        return False
    pairs = parse_qsl(urlsplit(value).query, keep_blank_values=True)
    return len({key for key, _ in pairs}) == len(pairs) and all(key and val for key, val in pairs)


def project_metadata(metadata):
    # Identity evidence only; omit file inventories, descriptions, and licenses.
    if not isinstance(metadata, dict):
        return {}
    keys = ("name", "version", "epoch", "architecture", "arch", "source", "sourceRpm",
            "sourceRPM", "originPackage", "origin", "package", "packageName",
            "sourcePackage", "sourcePackageName", "sourceVersion", "vendor",
            "release", "modularityLabel")
    result = {key: metadata[key] for key in keys if metadata.get(key) is not None}
    return result


def summarize(image_key, image_ref, inspect, sbom, findings, capture):
    artifacts = sbom.get("artifacts", [])
    components = [{
        "id": artifact.get("id"), "name": artifact.get("name"),
        "version": artifact.get("version"), "type": artifact.get("type"),
        "purl": artifact.get("purl"), "metadata": project_metadata(artifact.get("metadata")),
    } for artifact in artifacts]
    component_id_counts = Counter(component["id"] for component in components)
    components_by_id = {
        component["id"]: component for component in components
        if component["id"] and component_id_counts[component["id"]] == 1
    }
    rows = []
    for match in findings.get("matches", []):
        artifact = match.get("artifact", {})
        vulnerability = match.get("vulnerability", {})
        related = match.get("relatedVulnerabilities", [])
        aliases = sorted({item["id"] for item in related if item.get("id")})
        component = components_by_id.get(artifact.get("id"))
        if component and any(component.get(field) != artifact.get(field)
                             for field in ("name", "version", "type")):
            component = None
        identity_metadata = project_metadata(artifact.get("metadata"))
        metadata_source = "grype_artifact"
        if not identity_metadata and component:
            identity_metadata = component["metadata"]
            metadata_source = "syft_component_joined_by_unique_id_name_version_type"
        rows.append({
            "cve": vulnerability.get("id"), "aliases": aliases,
            "package": artifact.get("name"), "installed_version": artifact.get("version"),
            "purl": artifact.get("purl"), "ecosystem": artifact.get("type"),
            "artifact_id": artifact.get("id"), "severity": vulnerability.get("severity"),
            "evidence": {
                "purl": artifact.get("purl"),
                "artifact_metadata": identity_metadata,
                "artifact_metadata_source": metadata_source,
                "sbom_component_id": component["id"] if component else None,
                "sbom_artifact": component,
                "namespace": vulnerability.get("namespace"),
                "data_source": vulnerability.get("dataSource"),
                "related_vulnerabilities": [
                    {k: item.get(k) for k in ("id", "namespace", "dataSource")}
                    for item in related],
                "fix": vulnerability.get("fix"),
                "match_details": match.get("matchDetails", []),
            },
        })
    return {
        "schema_version": 1, "capture_kind": "live_scan",
        "image_key": image_key, "image": image_ref,
        "image_digest": (inspect.get("RepoDigests") or [inspect["Id"]])[0],
        "image_id": inspect["Id"], "repo_digests": inspect.get("RepoDigests", []),
        "platform": {"os": inspect.get("Os"), "architecture": inspect.get("Architecture")},
        "oci_labels": inspect.get("Config", {}).get("Labels") or {},
        "distro": sbom.get("distro"), "sbom_source": sbom.get("source"),
        "scanner_descriptor": sbom.get("descriptor", {}).get("version"),
        "capture": capture,
        "counts": {
            "sbom_components": len(components),
            "components_with_purls": sum(bool(item["purl"]) for item in components),
            "components_with_valid_purls": sum(valid_purl(item["purl"]) for item in components),
            "components_by_ecosystem": dict(sorted(Counter(item["type"] for item in components).items())),
            "vulnerability_findings": len(rows),
            "unique_vulnerability_package_version_purl": len({
                (item["cve"], item["package"], item["installed_version"], item["purl"]) for item in rows}),
            "findings_by_ecosystem": dict(sorted(Counter(item["ecosystem"] for item in rows).items())),
        },
        "components": components, "findings": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-dir", type=Path, required=True)
    parser.add_argument("--scanner-image", default="cats:1.67")
    parser.add_argument("--grype-db-volume", default="cats_security_grype_db")
    parser.add_argument("--image-key", action="append")
    parser.add_argument("--image-ref", action="append", default=[], metavar="KEY=REFERENCE")
    parser.add_argument("--cataloger-mode", choices=("default", "image"), default="default")
    parser.add_argument("--resume", action="store_true")
    options = parser.parse_args()
    images = dict(IMAGES)
    for override in options.image_ref:
        key, separator, reference = override.partition("=")
        if not separator or not re.fullmatch(r"[a-z0-9-]+", key) or not reference:
            parser.error("--image-ref requires a safe lowercase KEY=REFERENCE")
        images[key] = reference
    selected = options.image_key or list(images)
    if any(key not in images for key in selected):
        parser.error("--image-key must refer to a default image or --image-ref key")
    output, summary_dir = options.output.resolve(), options.summary_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summary_dir.mkdir(parents=True, exist_ok=True)
    scanner = json.loads(run(["docker", "image", "inspect", options.scanner_image]).stdout)[0]
    scanner_id = scanner["Id"]
    prior_manifest = (json.loads((summary_dir / "manifest.json").read_text(encoding="utf-8"))
                      if (summary_dir / "manifest.json").exists() else {})
    prior_images = {item["image_key"]: item for item in prior_manifest.get("images", [])}
    if any(not re.fullmatch(r"[a-z0-9-]+", key) for key in prior_images):
        parser.error("Existing manifest contains an unsafe image key")
    if prior_images and prior_manifest.get("scanner_image_id") != scanner_id:
        parser.error("Existing evidence uses a different scanner image; choose fresh output and summary directories")
    base = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh",
            "--mount", f"type=bind,src={output},dst=/evidence",
            "--mount", f"type=volume,src={options.grype_db_volume},dst=/opt/catscan/grype-db,readonly",
            "-e", "GRYPE_DB_AUTO_UPDATE=false", "-e", "GRYPE_DB_VALIDATE_AGE=false",
            "-e", "GRYPE_CHECK_FOR_APP_UPDATE=false", "-e", "SYFT_CHECK_FOR_APP_UPDATE=false",
            scanner_id]
    if prior_images:
        current_db = json.loads(run(base + ["-c", "grype db status -o json"]).stdout)
        prior_db = prior_manifest.get("grype_database", {})
        if any(current_db.get(field) != prior_db.get(field) for field in ("schemaVersion", "from", "built")):
            parser.error("Existing evidence uses a different Grype database; choose fresh output and summary directories")
    provenance_command = (
        "set -eu; syft version -o json > /evidence/syft-version.json; "
        "grype version -o json > /evidence/grype-version.json; "
        "grype db status -o json > /evidence/grype-db.json; "
        "trivy --version > /evidence/trivy-version.txt"
    )
    run(base + ["-c", provenance_command])
    manifest = {
        "schema_version": 1, "capture_kind": "live_scan", "captured_at": utc(),
        "scanner_image": options.scanner_image, "scanner_image_id": scanner_id,
        "scanner_repo_digests": scanner.get("RepoDigests", []),
        "syft": json.loads((output / "syft-version.json").read_text()),
        "grype": json.loads((output / "grype-version.json").read_text()),
        "grype_database": json.loads((output / "grype-db.json").read_text()),
        "trivy_version": (output / "trivy-version.txt").read_text().strip(),
        "raw_evidence_directory": str(output),
        "method": "docker create/export without execution; Syft directory catalog; Grype sbom --only-fixed",
        "network": "disabled during scanner execution; no external intelligence retrieval",
        "finding_denominator": "Grype --only-fixed matches; includes separate package occurrences and aliases exactly as emitted",
        "purl_validation": "syntax checks: pkg scheme, ecosystem/name/version, percent escapes, unique nonempty qualifiers; no inferred identity equivalence",
        "images": [value for key, value in prior_images.items() if key not in selected],
    }
    for key in selected:
        ref = images[key]
        image_inspect = json.loads(run(["docker", "image", "inspect", ref]).stdout)[0]
        image_id = image_inspect["Id"]
        prefix = output / key
        capture_path = prefix.with_suffix(".capture.json")
        if options.resume and capture_path.exists():
            captured_inspect = json.loads(prefix.with_suffix(".image-inspect.json").read_text(encoding="utf-8"))
            if captured_inspect["Id"] != image_id:
                raise RuntimeError(f"{key}: image tag changed since capture; choose a distinct evidence key")
            captured_mode = json.loads(capture_path.read_text(encoding="utf-8")).get("cataloger_mode", "default")
            if captured_mode != options.cataloger_mode:
                raise RuntimeError(f"{key}: cataloger mode differs from retained capture; choose a distinct evidence key")
            image_inspect = captured_inspect
        if not (options.resume and capture_path.exists()):
            started = utc()
            timer = time.perf_counter()
            container_name = "cats-vex-audit-" + uuid.uuid4().hex[:16]
            archive = prefix.with_suffix(".rootfs.tar")
            print(f"{key}: materializing {ref} {image_id}", flush=True)
            run(["docker", "create", "--name", container_name, image_id, "true"])
            try:
                run(["docker", "export", "--output", str(archive), container_name])
            finally:
                run(["docker", "rm", "--volumes", container_name])
            write(prefix.with_suffix(".image-inspect.json"), image_inspect)
            cataloger_flag = " --override-default-catalogers image" if options.cataloger_mode == "image" else ""
            command = (
                "set -eu; mkdir /tmp/cats-rootfs; "
                f"tar -xf /evidence/{key}.rootfs.tar -C /tmp/cats-rootfs; "
                f"syft dir:/tmp/cats-rootfs{cataloger_flag} -o syft-json > /evidence/{key}.syft.json; "
                f"grype sbom:/evidence/{key}.syft.json --only-fixed -o json > /evidence/{key}.grype.json"
            )
            print(f"{key}: offline Syft / Grype scan", flush=True)
            result = run(base + ["-c", command], check=False)
            prefix.with_suffix(".scanner.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            # The only deleted file is the exact archive just created for this image.
            archive.unlink()
            capture = {"started_at": started, "completed_at": utc(),
                       "seconds": round(time.perf_counter() - timer, 3),
                       "scanner_exit_code": result.returncode,
                       "cataloger_mode": options.cataloger_mode,
                       "scanner_commands": command}
            write(capture_path, capture)
            if result.returncode:
                print(f"{key}: scanner failed: {result.stderr[-1000:]}", flush=True)
                manifest["images"].append({"image_key": key, "image": ref, "capture": capture})
                write(summary_dir / "manifest.json", manifest)
                continue
        capture = json.loads(capture_path.read_text())
        if capture["scanner_exit_code"]:
            raise RuntimeError(f"Prior {key} capture failed; omit --resume to retry after diagnosing")
        sbom = json.loads(prefix.with_suffix(".syft.json").read_text(encoding="utf-8"))
        findings = json.loads(prefix.with_suffix(".grype.json").read_text(encoding="utf-8"))
        normalized = summarize(key, ref, image_inspect, sbom, findings, capture)
        evidence_files = [file_provenance(prefix.with_suffix(suffix)) for suffix in
                          (".syft.json", ".grype.json", ".image-inspect.json", ".scanner.log", ".capture.json")]
        normalized["raw_evidence"] = evidence_files
        write(summary_dir / f"{key}.json", normalized)
        manifest["images"].append({
            field: normalized[field] for field in (
                "image_key", "image", "image_digest", "image_id", "distro", "counts", "capture", "raw_evidence")})
        write(summary_dir / "manifest.json", manifest)
        print(f"{key}: {normalized['counts']}", flush=True)
    if manifest["images"]:
        key = manifest["images"][0]["image_key"]
        attempt = run(base + ["-c",
            f"trivy sbom --skip-db-update --skip-java-db-update --offline-scan --format json "
            f"--output /evidence/{key}.trivy.json /evidence/{key}.syft.json"], check=False)
        (output / "trivy-offline-attempt.log").write_text(attempt.stdout + attempt.stderr, encoding="utf-8")
        manifest["trivy_offline_attempt"] = {
            "exit_code": attempt.returncode,
            "log": file_provenance(output / "trivy-offline-attempt.log"),
            "diagnostic": attempt.stderr[-2000:],
            "limitation": "No embedded Trivy vulnerability database; production pipeline uses Trivy for misconfigurations.",
        }
        write(summary_dir / "manifest.json", manifest)


if __name__ == "__main__":
    main()
