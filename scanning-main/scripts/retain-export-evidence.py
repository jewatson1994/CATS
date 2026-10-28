#!/usr/bin/env python3
"""Retain original scanner bytes and all supported SBOM serializations.

The portal cannot reconstruct raw reports from normalized findings. Compression
keeps these immutable documents within the bounded pipeline ingestion envelope.
Oversized/unreadable evidence is recorded as unavailable, never substituted.
"""
import argparse
import base64
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile


spec = importlib.util.spec_from_file_location("sbom_formats", Path(__file__).with_name("generate-sbom-formats.py"))
formats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(formats)


def safe_name(name):
    if len(name) <= 240 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        return name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", name).lstrip(".-") or "evidence"
    return cleaned[:210] + "-" + sha256(name.encode()).hexdigest()[:16]


def read_file(path, root, limit):
    if (not path.resolve().is_relative_to(root.resolve())
            or any(item.is_symlink() for item in [path, *path.parents] if item != root.parent)):
        raise ValueError("Evidence paths must remain inside the scan workspace without symlinks")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Evidence file exceeds the retention byte limit")
    return data


def collect(root):
    root = root.resolve()
    limit = max(1, int(os.getenv("CATS_INGEST_MAX_EVIDENCE_BYTES", str(64 * 1024 * 1024))))
    encoded_limit = max(1, int(os.getenv("CATS_INGEST_MAX_EVIDENCE_ENCODED_BYTES", str(8 * 1024 * 1024))))
    count_limit = max(1, int(os.getenv("CATS_INGEST_MAX_EVIDENCE_FILES", "2048")))
    documents, unavailable = [], []
    total = encoded_total = 0

    def identity(category, format_name, name, image=""):
        return {"category": category, "format": format_name, "name": safe_name(name), "image": image[:1000]}

    def absent(item, reason):
        unavailable.append({**item, "reason": reason})

    def retain(item, raw, derived=None):
        nonlocal total, encoded_total
        content = base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii")
        if total + len(raw) > limit or encoded_total + len(content) > encoded_limit:
            absent(item, "Evidence exceeds the configured aggregate retention byte limit")
            return
        documents.append({**item, "encoding": "gzip+base64", "content": content,
                          "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
                          "derived_from_sha256": derived,
                          "conversion_timestamp_source": "source-file-mtime" if derived else None})
        total += len(raw)
        encoded_total += len(content)

    def bounded_count():
        if len(documents) + len(unavailable) > count_limit:
            raise OverflowError("Evidence exceeds the configured retention file limit")

    try:
        for directory, pattern, scanner in (("results", "*-results.json", "grype"),
                                             ("trivy-results/raw", "*.json", "trivy")):
            for path in sorted((root / directory).glob(pattern)):
                # Dockle shares Trivy's output directory but is a different tool.
                if scanner == "trivy" and path.name.endswith("-dockle.json"):
                    continue
                item = identity("scanner", scanner + "-json", path.name)
                try:
                    retain(item, read_file(path, root, limit))
                except (OSError, ValueError):
                    absent(item, "Original scanner output could not be retained within safe file/byte limits")
                bounded_count()

        for path in sorted((root / "sboms").glob("*.json")):
            image = digest = ""
            handled = set()
            try:
                for suffix in (".image", ".digest"):
                    sidecar = path.with_suffix(suffix)
                    value = read_file(sidecar, root, 1000).decode("utf-8").strip() if sidecar.exists() else ""
                    if suffix == ".image":
                        image = value
                    else:
                        digest = value
                raw = read_file(path, root, limit)
                source_hash = sha256(raw).hexdigest()
                retain(identity("sbom", "syft-json", path.name, image), raw)
                handled.add("syft-json")
                # Work on an isolated copy so the selected downloadable scan
                # formats and their manifest are not changed by portal retention.
                with tempfile.TemporaryDirectory(prefix="cats-retained-sbom-") as temporary:
                    staging = Path(temporary)
                    source = staging / safe_name(path.name)
                    source.write_bytes(raw)
                    provenance = path.with_suffix(".provenance")
                    if provenance.exists():
                        source.with_suffix(".provenance").write_bytes(read_file(provenance, root, 32768))
                    entries = formats.serialize_formats(source, staging / "formats", image=image, digest=digest,
                        formats="cyclonedx-json,cyclonedx-xml,spdx-json",
                        cyclonedx_spec_version=os.getenv("SBOM_CYCLONEDX_SPEC_VERSION", "1.5"),
                        timestamp=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
                        timestamp_source="Source inventory file modification time for reproducibility; not conversion wall time")
                    for entry in entries:
                        target = Path(entry["path"])
                        retain(identity("sbom", entry["format"], target.name, image),
                               read_file(target, staging, limit), source_hash)
                        handled.add(entry["format"])
            except (OSError, ValueError, TypeError, AttributeError):
                # Keep a successfully retained Syft source even if conversion fails.
                for format_name in sorted(formats.SUPPORTED):
                    if format_name not in handled:
                        name = safe_name(path.stem) + "." + format_name + (".xml" if format_name.endswith("xml") else ".json")
                        candidate = identity("sbom", format_name, name, image)
                        if not any(item["category"] == "sbom" and item["format"] == format_name
                                   and item["name"] == candidate["name"] for item in unavailable):
                            absent(candidate, "Original inventory or SBOM conversion was unavailable within safe file/byte limits")
            bounded_count()
    except OverflowError:
        return {"evidence_documents": [], "evidence_unavailable": [
            {"category": category, "format": format_name, "name": "retention-limit.txt", "image": "",
             "reason": "Evidence exceeds the configured retention file limit; increase it and rescan"}
            for category, format_name in (("scanner", "grype-json"), ("sbom", "syft-json"))][:count_limit]}
    return {"evidence_documents": documents, "evidence_unavailable": unavailable}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(collect(args.workspace), separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    main()
