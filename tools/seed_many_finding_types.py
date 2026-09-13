"""Seed 100 synthetic findings across several local test services."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from urllib.request import Request, urlopen


POLICY_TYPES = (
    ("Configuration", "KSV014", "CIS Kubernetes"),
    ("Compliance", "CIS-1.2.3", "CIS Docker Benchmark"),
    ("Hardening", "DS-0001", "Container Hardening"),
    ("Configuration", "TRIVY-AVD-001", "Trivy Misconfiguration"),
)


def post(url: str, token: str, payload: dict) -> None:
    request = Request(
        url.rstrip("/") + "/api/v1/pipeline-results",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=60) as response:
        print(f"{payload['service']['id']}: HTTP {response.status}; findings={len(payload['findings']) + len(payload['policy_findings'])}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--services", type=int, default=4)
    args = parser.parse_args()
    if args.count < 1 or args.count > 1000:
        raise SystemExit("--count must be between 1 and 1000")
    if args.services < 1 or args.services > args.count:
        raise SystemExit("--services must be between 1 and --count")

    now = datetime.now(timezone.utc).isoformat()
    base = args.count // args.services
    remainder = args.count % args.services
    remaining = args.count
    for service_number in range(1, args.services + 1):
        service_count = base + (1 if service_number <= remainder else 0)
        cve_count = max(1, service_count // 5)
        policy_count = service_count - cve_count
        service_id = f"demo-finding-types-{service_number}"
        image = f"registry.example.invalid/demo/finding-types-{service_number}:latest"
        cves = []
        for index in range(cve_count):
            cves.append({
                "cve": f"CVE-2099-{service_number:02d}{index:03d}",
                "severity": ("Critical", "High", "Medium", "Low")[index % 4],
                "image": image,
                "package": f"demo-package-{index + 1}",
                "installed_version": "1.0.0",
                "fixed_version": "2.0.0",
                "kev": index % 3 == 0,
                "epss": round(0.75 + (index % 5) * 0.05, 2),
                "evidence": {"synthetic": True, "description": "Synthetic vulnerability fixture."},
            })
        policies = []
        for index in range(policy_count):
            finding_type, prefix, framework = POLICY_TYPES[index % len(POLICY_TYPES)]
            policies.append({
                "type": finding_type,
                "finding": f"{prefix}-{service_number:02d}{index + 1:03d}",
                "severity": ("High", "Medium", "Low")[index % 3],
                "scanner": "Trivy" if index % 2 == 0 else "Dockle",
                "framework": framework,
                "target": image,
                "title": f"Synthetic {finding_type.lower()} finding {index + 1}",
                "description": "Synthetic local UI fixture; not production evidence.",
                "remediation": "Apply the documented remediation guidance.",
            })
        skipped = [f"registry.example.invalid/demo/skipped-{service_number}:latest"] if service_number == args.services else []
        payload = {
            "schema_version": "1.0",
            "execution_id": f"cats-many-types:{service_id}:{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
            "scanned_at": now,
            "complete": not bool(skipped),
            "skipped_images": skipped,
            "fixable_only": True,
            "pipeline_url": "https://example.invalid/cats-many-types",
            "commit_sha": "synthetic-many-finding-types",
            "service": {
                "id": service_id,
                "name": f"DEMO · Finding Types {service_number}",
                "version": "demo-1.0",
                "owner": "CATS UI Testing",
                "poc": "cats-demo@example.invalid",
                "groups": ["Performance Test"],
            },
            "findings": cves,
            "policy_findings": policies,
        }
        post(args.url, args.token, payload)
        remaining -= service_count


if __name__ == "__main__":
    main()
