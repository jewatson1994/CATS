"""Seed synthetic Helm/configuration findings for local CATS UI testing.

Creates 36 policy findings across four services. Findings target rendered Helm
resources and include both complete scans and incomplete chart evidence. This
fixture is local-only; it does not represent real security evidence.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen


CHARTS = (
    ("Trivy", "Kubernetes Security Check", "KSV014", "Privilege escalation is enabled"),
    ("Trivy", "Kubernetes Security Check", "KSV018", "Container runs as root"),
    ("Trivy", "CIS Kubernetes", "KSV021", "Host networking is enabled"),
    ("Trivy", "CIS Kubernetes", "KSV030", "A writable host path is mounted"),
    ("Trivy", "Helm Best Practices", "HELM-001", "Chart is missing a resource limit"),
    ("Trivy", "Helm Best Practices", "HELM-002", "Chart is missing a readiness probe"),
    ("Trivy", "Kubernetes Security Check", "KSV041", "Network policy is not defined"),
    ("Trivy", "Kubernetes Security Check", "KSV046", "Service account token is auto-mounted"),
    ("Trivy", "CIS Kubernetes", "KSV057", "Image uses a mutable tag"),
)


def post(url: str, token: str, payload: dict) -> None:
    request = Request(
        url.rstrip("/") + "/api/v1/pipeline-results",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=60) as response:
        total = len(payload["findings"]) + len(payload["policy_findings"])
        print(f"{payload['service']['id']}: HTTP {response.status}; findings={total}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", required=True)
    parser.add_argument("--services", type=int, default=4)
    parser.add_argument("--findings-per-service", type=int, default=9)
    args = parser.parse_args()
    if not 1 <= args.services <= 8:
        raise SystemExit("--services must be between 1 and 8")
    if not 1 <= args.findings_per_service <= len(CHARTS):
        raise SystemExit(f"--findings-per-service must be between 1 and {len(CHARTS)}")

    now = datetime.now(timezone.utc)
    for service_number in range(1, args.services + 1):
        service_id = f"demo-helm-findings-{service_number}"
        image = f"registry.example.invalid/demo/helm-service-{service_number}:latest"
        # Older evidence makes the first services useful for testing overdue
        # policy rows; the last service is recent but incomplete.
        scanned_at = now - timedelta(days=120 if service_number < args.services else 2)
        policies = []
        for index, (scanner, framework, finding_id, title) in enumerate(CHARTS[: args.findings_per_service]):
            severity = ("Critical", "High", "Medium", "Low")[index % 4]
            chart = ("umbrella", "api", "worker")[index % 3]
            policies.append(
                {
                    "type": "Configuration",
                    "finding": f"{finding_id}-{service_number:02d}",
                    "severity": severity,
                    "scanner": scanner,
                    "framework": framework,
                    "target": f"charts/{chart} :: Deployment/helm-demo-{service_number}-{index + 1}",
                    "title": title,
                    "description": "Synthetic Helm chart finding for local UI testing only.",
                    "remediation": "Update the chart values or templates and rerun the Helm scan.",
                }
            )

        skipped_charts = []
        skipped_images = []
        if service_number == args.services:
            skipped_charts = [
                "charts/broken-release\thelm template failed",
                "charts/missing-dependency\tHelm dependencies are unavailable for mode vendored",
            ]
            skipped_images = ["registry.example.invalid/demo/unavailable-helm:latest"]

        payload = {
            "schema_version": "1.0",
            "execution_id": f"cats-helm-fixture:{service_id}:{now:%Y%m%d%H%M%S%f}",
            "scanned_at": scanned_at.isoformat(),
            "complete": not bool(skipped_charts or skipped_images),
            "skipped_images": skipped_images,
            "skipped_charts": skipped_charts,
            "fixable_only": True,
            "pipeline_url": "https://example.invalid/cats-helm-fixture",
            "commit_sha": "synthetic-helm-findings",
            "service": {
                "id": service_id,
                "name": f"DEMO - Helm Findings {service_number}",
                "version": "helm-fixture-1.0",
                "owner": "CATS Helm Testing",
                "poc": "cats-demo@example.invalid",
                "groups": ["Performance Test"],
            },
            "findings": [],
            "policy_findings": policies,
        }
        post(args.url, args.token, payload)


if __name__ == "__main__":
    main()
