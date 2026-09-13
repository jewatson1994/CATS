"""Seed realistic public-product services for local CATS demonstrations.

The products, image references, and chart repositories are public. Findings are
explicitly synthetic UI fixtures and must not be treated as security advice.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen


SERVICES = (
    {
        "id": "grafana", "name": "Grafana", "owner": "Grafana Labs",
        "version": "public-chart-fixture", "chart": "grafana-community/grafana",
        "chart_repo": "https://github.com/grafana/helm-charts/tree/main/charts/grafana",
        "image": "grafana/grafana:latest", "port": "3000/TCP", "ingress": "Optional Grafana web UI",
    },
    {
        "id": "prometheus", "name": "Prometheus", "owner": "Prometheus Authors",
        "version": "public-chart-fixture", "chart": "prometheus-community/prometheus",
        "chart_repo": "https://github.com/prometheus-community/helm-charts/tree/main/charts/prometheus",
        "image": "prom/prometheus:latest", "port": "9090/TCP", "ingress": "Optional Prometheus web UI",
    },
    {
        "id": "kube-prometheus-stack", "name": "Kube Prometheus Stack", "owner": "Prometheus Community",
        "version": "public-chart-fixture", "chart": "prometheus-community/kube-prometheus-stack",
        "chart_repo": "https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack",
        "image": "quay.io/prometheus-operator/prometheus-operator:latest", "port": "9090/TCP", "ingress": "Prometheus and Alertmanager routes",
    },
    {
        "id": "opentelemetry-collector", "name": "OpenTelemetry Collector", "owner": "OpenTelemetry Authors",
        "version": "public-chart-fixture", "chart": "open-telemetry/opentelemetry-collector",
        "chart_repo": "https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-collector",
        "image": "otel/opentelemetry-collector:latest", "port": "4317/TCP, 4318/TCP", "ingress": "OTLP gRPC and HTTP receivers",
    },
    {
        "id": "cert-manager", "name": "cert-manager", "owner": "cert-manager Project",
        "version": "public-chart-fixture", "chart": "jetstack/cert-manager",
        "chart_repo": "https://github.com/cert-manager/cert-manager",
        "image": "quay.io/jetstack/cert-manager-controller:latest", "port": "9402/TCP", "ingress": "Metrics only; no public ingress",
    },
    {
        "id": "ingress-nginx", "name": "Ingress-NGINX", "owner": "Kubernetes Community",
        "version": "public-chart-fixture", "chart": "ingress-nginx/ingress-nginx",
        "chart_repo": "https://github.com/kubernetes/ingress-nginx/tree/main/charts/ingress-nginx",
        "image": "registry.k8s.io/ingress-nginx/controller:latest", "port": "80/TCP, 443/TCP", "ingress": "Cluster ingress controller",
    },
    {
        "id": "argo-cd", "name": "Argo CD", "owner": "Argo Project",
        "version": "public-chart-fixture", "chart": "argo/argo-cd",
        "chart_repo": "https://github.com/argoproj/argo-helm/tree/main/charts/argo-cd",
        "image": "quay.io/argoproj/argocd:latest", "port": "8080/TCP, 8083/TCP", "ingress": "Argo CD API and UI",
    },
    {
        "id": "harbor", "name": "Harbor", "owner": "CNCF Harbor Project",
        "version": "public-chart-fixture", "chart": "harbor/harbor",
        "chart_repo": "https://github.com/goharbor/harbor-helm",
        "image": "goharbor/harbor-core:latest", "port": "80/TCP", "ingress": "Harbor registry and portal",
    },
)


def post(url: str, token: str, payload: dict) -> None:
    request = Request(
        url.rstrip("/") + "/api/v1/pipeline-results",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=60) as response:
            print(f"{payload['service']['id']}: HTTP {response.status}; "
                  f"findings={len(payload['findings'])}; configs={len(payload['policy_findings'])}")
    except HTTPError as error:
        body = error.read().decode(errors="replace")
        raise SystemExit(f"{payload['service']['id']}: HTTP {error.code}: {body}") from error


def payload_for(product: dict, run_id: str, age_days: int) -> dict:
    scanned_at = datetime.now(timezone.utc) - timedelta(days=age_days)
    image = product["image"]
    findings = [
        {
            "cve": f"TEST-CVE-{index:04d}-{product['id'].upper()}",
            "severity": severity,
            "image": image,
            "package": package,
            "installed_version": "fixture-version",
            "fixed_version": "fixture-fixed-version",
            "kev": index == 1,
            "epss": 0.95 if index == 1 else 0.42,
            "evidence": {"synthetic_fixture": True, "source": product["chart_repo"]},
        }
        for index, (severity, package) in enumerate((("Critical", "fixture-runtime"), ("High", "fixture-http")), 1)
    ]
    policies = [
        {
            "type": "Configuration", "finding": f"KSV{index:03d}-{product['id'][:8].upper()}",
            "severity": severity, "scanner": "Trivy", "framework": "Kubernetes Security Check",
            "target": f"{product['chart']} :: Deployment/{product['id']}",
            "title": title,
            "description": f"Synthetic configuration fixture for {product['name']}; not a verified advisory.",
            "remediation": remediation, "fingerprint": f"public-fixture-{product['id']}-{index}",
        }
        for index, (severity, title, remediation) in enumerate((
            ("High", "Container security context needs review", "Set an explicit non-root security context."),
            ("Medium", "Resource limits are not declared", "Declare CPU and memory requests and limits."),
        ), 1)
    ]
    overview = {
        "source": product["chart_repo"],
        "workloads": [{"name": product["name"], "details": f"Helm chart: {product['chart']}"}],
        "ports": [{"name": product["port"], "details": "Declared service port; runtime reachability not asserted."}],
        "ingresses": [{"name": product["ingress"], "details": "Declared/public-product fixture metadata."}],
        "dependencies": [{"name": "Kubernetes", "details": "Helm-rendered workload dependency"}],
        "storage": [{"name": "Chart-defined persistence", "details": "Review values.yaml for enabled persistence."}],
        "rbac": [{"name": "Service account and RBAC", "details": "Extracted from rendered chart in a real scan."}],
        "network_policies": [], "external_endpoints": [{"name": product["chart_repo"]}],
    }
    return {
        "schema_version": "1.0", "execution_id": f"public-fixtures:{run_id}:{product['id']}",
        "scanned_at": scanned_at.isoformat(), "complete": True, "fixable_only": True,
        "skipped_images": [], "skipped_charts": [], "pipeline_url": product["chart_repo"],
        "commit_sha": "public-fixture", "service": {
            "id": product["id"], "name": product["name"], "version": product["version"],
            "owner": product["owner"], "poc": None, "groups": ["Public Test Services"],
        }, "findings": findings, "policy_findings": policies, "service_overview": overview,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", required=True)
    parser.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    parser.add_argument("--age-days", type=int, default=0, help="Age all evidence to exercise overdue policy behavior")
    args = parser.parse_args()
    if args.age_days < 0 or args.age_days > 3650:
        raise SystemExit("--age-days must be between 0 and 3650")
    for product in SERVICES:
        post(args.url, args.token, payload_for(product, args.run_id, args.age_days))


if __name__ == "__main__":
    main()
