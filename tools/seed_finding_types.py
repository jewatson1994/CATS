"""Seed a local service with representative CATS finding types.

This is a synthetic fixture for local UI testing only. It creates one service
with a KEV vulnerability, policy findings from several scanners/frameworks,
and incomplete evidence from skipped images.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from urllib.request import Request, urlopen


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", required=True)
    parser.add_argument("--service", default="demo-finding-types")
    args = parser.parse_args()

    image = "registry.example.invalid/demo/finding-types:latest"
    payload = {
        "schema_version": "1.0",
        "execution_id": f"cats-finding-types:{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "complete": False,
        "skipped_images": ["registry.example.invalid/demo/unavailable:demo"],
        "fixable_only": True,
        "pipeline_url": "https://example.invalid/cats-finding-types",
        "commit_sha": "synthetic-finding-types",
        "service": {
            "id": args.service,
            "name": "DEMO · Finding Types",
            "version": "demo-1.0",
            "owner": "CATS UI Testing",
            "poc": "cats-demo@example.invalid",
            "groups": ["Performance Test"],
        },
        "findings": [{
            "cve": "CVE-2099-9001",
            "severity": "Critical",
            "image": image,
            "package": "demo-package",
            "installed_version": "1.0.0",
            "fixed_version": "2.0.0",
            "kev": True,
            "epss": 0.98,
            "evidence": {"synthetic": True, "description": "Synthetic vulnerability fixture."},
        }],
        "policy_findings": [
            {
                "type": "Configuration",
                "finding": "KSV014",
                "severity": "High",
                "scanner": "Trivy",
                "framework": "CIS Kubernetes",
                "target": "Deployment/demo-api",
                "title": "Privilege escalation is enabled",
                "description": "Synthetic configuration fixture.",
                "remediation": "Set allowPrivilegeEscalation to false.",
            },
            {
                "type": "Compliance",
                "finding": "CIS-1.2.3",
                "severity": "Medium",
                "scanner": "Trivy",
                "framework": "CIS Docker Benchmark",
                "target": image,
                "title": "Container is running as root",
                "remediation": "Configure a non-root container user.",
            },
            {
                "type": "Hardening",
                "finding": "DS-0001",
                "severity": "Low",
                "scanner": "Dockle",
                "framework": "Container Hardening",
                "target": image,
                "title": "Add a healthcheck to the image",
                "remediation": "Add a HEALTHCHECK instruction.",
            },
        ],
    }
    request = Request(
        args.url.rstrip("/") + "/api/v1/pipeline-results",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {args.token}", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=30) as response:
        print(f"{args.service}: HTTP {response.status}")


if __name__ == "__main__":
    main()
