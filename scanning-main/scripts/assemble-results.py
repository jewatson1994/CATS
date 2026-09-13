#!/usr/bin/env python3
"""Assemble native scanner reports into one manually exportable results tree."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tarfile


def copy_report(source: Path, destination: Path) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    return {"path": destination.as_posix(), "source": source.as_posix(), "sha256": digest}


def report_entry(tool: str, scan_type: str, copied: dict, source: Path) -> dict:
    return {
        "tool": tool,
        "scan_type": scan_type,
        "format": "json",
        "path": copied["path"],
        "source": copied["source"],
        "sha256": copied["sha256"],
        "test_title": source.stem,
    }


def generic_findings_report(source: Path) -> dict:
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = []
    rows = raw if isinstance(raw, list) else raw.get("findings", []) if isinstance(raw, dict) else []
    findings = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("finding") or item.get("id") or "CATS-CONFIG").strip()
        severity = str(item.get("severity") or "Info").title()
        if severity not in {"Critical", "High", "Medium", "Low", "Info"}:
            severity = "Info"
        findings.append({
            "title": str(item.get("title") or finding_id),
            "description": str(item.get("description") or ""),
            "severity": severity,
            "mitigation": str(item.get("remediation") or ""),
            "cve": item.get("cve"),
            "vulnerability_ids": [finding_id],
            "component_name": item.get("target") or item.get("framework") or "CATS configuration",
            "unique_id_from_tool": item.get("fingerprint") or f"cats:{finding_id}",
            "fix_available": bool(item.get("remediation")),
            "tags": [str(value) for value in (item.get("scanner"), item.get("framework")) if value],
        })
    return {"name": source.stem, "type": "CATS Configuration", "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="results")
    parser.add_argument("--archive", default="")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    # The legacy root-level files remain in place for existing report and
    # portal stages.  The organized subdirectories are the manual handoff.
    for directory in ("grype", "trivy", "dockle", "cats"):
        shutil.rmtree(output / directory, ignore_errors=True)
        (output / directory).mkdir(parents=True, exist_ok=True)

    reports: list[dict] = []
    legacy_grype = sorted(
        path for path in output.glob("*-results.json") if path.is_file()
    )
    for source in legacy_grype:
        copied = copy_report(source, output / "grype" / source.name)
        reports.append(report_entry("grype", "Anchore Grype", copied, source))

    raw_root = root / "trivy-results" / "raw"
    for source in sorted(raw_root.glob("*.json")) if raw_root.is_dir() else []:
        if not source.is_file():
            continue
        is_dockle = "dockle" in source.name.lower()
        tool = "dockle" if is_dockle else "trivy"
        scan_type = "Dockle Report" if is_dockle else "Trivy"
        copied = copy_report(source, output / tool / source.name)
        reports.append(report_entry(tool, scan_type, copied, source))

    # Keep the CATS-normalized policy stream available for a single generic
    # import when a reviewer wants one combined configuration test.
    policy_path = root / "portal-policy-findings.json"
    if policy_path.is_file():
        cats_path = output / "cats" / "cats-findings.json"
        cats_path.write_text(json.dumps(generic_findings_report(policy_path), indent=2) + "\n", encoding="utf-8")
        copied = {
            "path": cats_path.as_posix(),
            "source": policy_path.as_posix(),
            "sha256": hashlib.sha256(cats_path.read_bytes()).hexdigest(),
        }
        reports.append({
            **report_entry("cats", "Generic Findings Import", copied, policy_path),
            "purpose": "CATS-normalized configuration findings",
        })

    metadata = {}
    for name in ("service.yml", "service-overview.json", "configuration-scan-status.json", "scan-summary.json"):
        path = root / name
        if path.is_file():
            try:
                metadata[name] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                metadata[name] = {"path": name, "valid_json": False}

    manifest = {
        "schema_version": "cats.results/v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "root": str(root),
        "manual_import": True,
        "reports": reports,
        "metadata": metadata,
    }
    archive = Path(args.archive).resolve() if args.archive else root / "results-export.tar.gz"
    manifest["archive"] = archive.as_posix()
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "README.txt").write_text(
        "CATS scanner results\n\n"
        "Import the JSON files under grype, trivy, and dockle manually in DefectDojo "
        "using the scan type named in manifest.json. The cats directory contains "
        "a CATS configuration report formatted for Generic Findings Import.\n",
        encoding="utf-8",
    )
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(output, arcname=output.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
