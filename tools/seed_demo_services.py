"""Seed clearly labelled CATS demo services for local UI/policy testing.

This uses the same pipeline-results API as the scanning job. Run only against a
throwaway/local CATS instance; all services and image references are synthetic.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen


def finding(cve: str, severity: str, image: str, *, kev: bool = False, epss: float | None = None) -> dict:
    evidence = {
        "description": "Synthetic CATS demo finding; not production evidence.",
        "data_source": "https://example.invalid/cats-demo",
        "synthetic": True,
        "kev": kev,
    }
    if epss is not None:
        evidence["epss"] = epss
    return {
        "cve": cve,
        "severity": severity,
        "image": image,
        "package": "demo-package",
        "installed_version": "1.0.0",
        "fixed_version": "2.0.0",
        "kev": kev,
        "epss": epss,
        "evidence": evidence,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--token", required=True)
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=120)).isoformat()
    recent = (now - timedelta(days=7)).isoformat()
    run_id = now.strftime("%Y%m%d%H%M%S")
    demo_registry = "registry.example.invalid/demo"
    services = [
        {
            "id": "demo-overdue",
            "name": "DEMO · Overdue CVE",
            "version": "demo-1.0",
            "owner": "Platform Engineering",
            "poc": "platform-demo@example.invalid",
            "groups": ["Group A", "Cybersecurity"] ,
            "scanned_at": old,
            "findings": [finding("CVE-2099-0001", "High", f"{demo_registry}/overdue:demo")],
        },
        {
            "id": "demo-kev",
            "name": "DEMO · KEV Risk",
            "version": "demo-1.0",
            "owner": "Security Engineering",
            "poc": "security-demo@example.invalid",
            "groups": ["Group A"],
            "scanned_at": recent,
            "findings": [finding("CVE-2024-3400", "High", f"{demo_registry}/kev:demo", kev=True)],
        },
        {
            "id": "demo-epss",
            "name": "DEMO · High EPSS Risk",
            "version": "demo-1.0",
            "owner": "Application Services",
            "poc": "app-demo@example.invalid",
            "groups": ["Group B"],
            "scanned_at": recent,
            "findings": [finding("CVE-2021-44228", "Critical", f"{demo_registry}/epss:demo", epss=0.99)],
        },
        {
            "id": "demo-skipped",
            "name": "DEMO · Incomplete Evidence",
            "version": "demo-1.0",
            "owner": "Observability",
            "poc": "observability-demo@example.invalid",
            "groups": ["Group B", "Cybersecurity"],
            "scanned_at": recent,
            "complete": False,
            "skipped_images": [f"{demo_registry}/unavailable:demo", f"{demo_registry}/distroless:demo"],
            "findings": [],
        },
        {
            "id": "demo-compliant",
            "name": "DEMO · Compliant Recent Scan",
            "version": "demo-1.0",
            "owner": "Data Engineering",
            "poc": "data-demo@example.invalid",
            "groups": ["Group B"],
            "scanned_at": recent,
            "findings": [finding("CVE-2099-0002", "Medium", f"{demo_registry}/compliant:demo")],
        },
        {
            "id": "demo-multi-image",
            "name": "DEMO · Multi-image Service",
            "version": "demo-2.4",
            "owner": "Edge Services",
            "poc": "edge-demo@example.invalid",
            "groups": ["Group A", "Group B"],
            "scanned_at": old,
            "findings": [
                finding("CVE-2099-0003", "Critical", f"{demo_registry}/api:demo"),
                finding("CVE-2099-0004", "Low", f"{demo_registry}/worker:demo"),
            ],
        },
    ]

    for service in services:
        payload = {
            "schema_version": "1.0",
            "execution_id": f"cats-demo:{service['id']}:{run_id}",
            "scanned_at": service["scanned_at"],
            "complete": service.get("complete", True),
            "skipped_images": service.get("skipped_images", []),
            "fixable_only": True,
            "pipeline_url": "https://example.invalid/cats-demo",
            "commit_sha": "cats-demo-fixture",
            "service": {key: service[key] for key in ("id", "name", "version", "owner", "poc", "groups")},
            "findings": service["findings"],
        }
        request = Request(
            args.url.rstrip("/") + "/api/v1/pipeline-results",
            data=json.dumps(payload).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {args.token}", "Content-Type": "application/json"},
        )
        with urlopen(request, timeout=30) as response:
            print(f"{service['id']}: {response.status}")


if __name__ == "__main__":
    main()
