"""Seed large synthetic services through the CATS pipeline API for local testing."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen


SEVERITIES = ("Critical", "High", "Medium", "Low")


def findings_for(service_number: int, count: int, images: int) -> list[dict]:
    results = []
    for number in range(1, count + 1):
        severity = SEVERITIES[(number - 1) % len(SEVERITIES)]
        image_number = ((number - 1) % images) + 1
        cve = f"CVE-20{80 + service_number}-{number:04d}"
        results.append({
            "cve": cve,
            "severity": severity,
            "image": f"registry.example.invalid/performance/service-{service_number}/image-{image_number}:test",
            "package": f"synthetic-package-{number:04d}",
            "installed_version": "1.0.0",
            "fixed_version": "2.0.0",
            "kev": number % 101 == 0,
            "epss": round((number % 100) / 100, 2),
            "evidence": {
                "description": "Synthetic performance-test finding; not production evidence.",
                "data_source": "https://example.invalid/cats-performance-test",
                "synthetic": True,
            },
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", required=True)
    parser.add_argument("--findings", type=int, default=500)
    parser.add_argument("--services", type=int, default=3)
    parser.add_argument("--images", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.findings <= 5000:
        raise SystemExit("--findings must be between 1 and 5000")
    if not 1 <= args.services <= 10:
        raise SystemExit("--services must be between 1 and 10")

    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%d%H%M%S")
    for service_number in range(1, args.services + 1):
        age_days = 7 if service_number == 1 else (120 if service_number == 2 else 45)
        service_id = f"perf-findings-500-{service_number}"
        body = {
            "schema_version": "1.0",
            "execution_id": f"cats-performance:{service_id}:{run_id}",
            "scanned_at": (now - timedelta(days=age_days)).isoformat(),
            "complete": True,
            "skipped_images": [],
            "fixable_only": True,
            "pipeline_url": "https://example.invalid/cats-performance-test",
            "commit_sha": "synthetic-performance-fixture",
            "service": {
                "id": service_id,
                "name": f"PERF TEST · 500 Findings · Service {service_number}",
                "version": "performance-test-1.0",
                "owner": "CATS Performance Testing",
                "poc": "performance-test@example.invalid",
                "groups": ["Performance Test"],
            },
            "findings": findings_for(service_number, args.findings, args.images),
        }
        request = Request(
            args.url.rstrip("/") + "/api/v1/pipeline-results",
            data=json.dumps(body).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {args.token}", "Content-Type": "application/json"},
        )
        with urlopen(request, timeout=180) as response:
            result = json.loads(response.read())
            print(f"{service_id}: HTTP {response.status}; findings={args.findings}; accepted={result.get('accepted')}")


if __name__ == "__main__":
    main()
