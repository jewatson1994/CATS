"""Convert synthetic Grype fixtures to CATS pipeline payloads and ingest them."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def payload(report: dict, path: Path, project_id: str) -> dict:
    metadata = report["cats_test"]
    service = metadata["service"]
    findings = []
    for match in report.get("matches", []):
        vuln = match.get("vulnerability", {})
        fixed = (vuln.get("fix") or {}).get("versions") or []
        if not fixed:
            continue
        artifact = match.get("artifact", {})
        findings.append({
            "cve": vuln.get("id", "UNKNOWN"), "severity": vuln.get("severity", "Unknown"),
            "image": report["source"]["target"].get("userInput", report["artifact"]["name"]),
            "image_digest": None, "package": artifact.get("name"),
            "installed_version": artifact.get("version"), "fixed_version": ", ".join(fixed),
            "evidence": {
                "description": vuln.get("description", ""), "data_source": vuln.get("dataSource", ""),
                "urls": vuln.get("urls", []), "cvss": vuln.get("cvss", []),
                "namespace": vuln.get("namespace"), "package_type": artifact.get("type"),
                "locations": artifact.get("locations", []), "synthetic": True,
            },
        })
    return {
        "schema_version": "1.0", "execution_id": f"cats-test:{project_id}:{path.stem}",
        "scanned_at": metadata["scanned_at"], "complete": True, "fixable_only": True,
        "pipeline_url": "https://example.invalid/cats-test-pipeline", "commit_sha": "cats-test-fixture",
        "service": service, "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, default=Path("test-grype-reports"))
    parser.add_argument("--url", default=os.getenv("CATS_PORTAL_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("PIPELINE_API_TOKEN"))
    parser.add_argument("--project-id", default="local")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    reports = sorted(args.reports.glob("*.json"))
    if len(reports) != 40:
        raise SystemExit(f"Expected 40 JSON reports in {args.reports}, found {len(reports)}")
    if not args.dry_run and not args.token:
        raise SystemExit("Set PIPELINE_API_TOKEN or pass --token; use --dry-run to only build payloads")
    for report_path in reports:
        with report_path.open(encoding="utf-8") as handle:
            body = json.load(handle)
        data = json.dumps(payload(body, report_path, args.project_id)).encode()
        if args.dry_run:
            print(f"{report_path.name}: {len(json.loads(data)['findings'])} fixable findings")
            continue
        request = urllib.request.Request(
            f"{args.url.rstrip('/')}/api/v1/pipeline-results", data=data,
            headers={"Authorization": f"Bearer {args.token}", "Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                print(f"{report_path.name}: {response.status}")
        except urllib.error.HTTPError as error:
            print(error.read().decode(errors="replace"), file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
