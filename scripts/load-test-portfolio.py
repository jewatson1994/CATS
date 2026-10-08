#!/usr/bin/env python3
"""Load a CATS instance with a varied synthetic portfolio for hands-on testing.

Creates N services (default 100) through the real pipeline ingest endpoint
(POST /api/v1/pipeline-results), exactly as a CI pipeline would. The mix covers
the kinds of evidence CATS handles:

  helm-app        Helm chart (source files + rendered resources), several
                  images, vulnerabilities, configuration findings, SBOM.
  helm-config     Helm chart scanned for configuration only (no CVEs).
  kubernetes      Plain Kubernetes manifests, configuration findings and
                  vulnerabilities.
  container       A container image only: vulnerabilities and SBOM, no chart.
  incomplete      Helm app whose latest scan is incomplete (an image could not
                  be scanned), to exercise missing-evidence handling.
  clean           Few or no findings at all.

Each service gets a finding volume tier (none / low / medium / high / very
high), several scans of history spaced 2-60 days apart (so findings range
from new to well past CATS's default 90-day due date; later scans resolve some findings and introduce others; some services
change version between scans), KEV and EPSS markings, fixes that are a patch or a major version
away, owners, POCs and groups (team-a ... team-e) for
testing group-scoped users.

Everything is synthetic and deterministic for a given --seed. CVE identifiers
use the form CVE-<year>-9xxxxxx so they look realistic (years 2019-2026) but
cannot collide with real CVEs. Service ids start with --prefix (default
"load-") so they are easy to find and remove.

Usage (standard library only; no installs needed):

    python scripts/load-test-portfolio.py --url https://cats.example.local \\
        --token "$PIPELINE_API_TOKEN"

    # see what would be sent, without contacting CATS:
    python scripts/load-test-portfolio.py --dry-run --out ./load-payloads

    # smaller, faster run:
    python scripts/load-test-portfolio.py --url http://localhost:8000 --token ... \\
        --services 20 --max-findings 2000 --scans 2

Options worth knowing:
  --token       The pipeline API token configured in CATS (PIPELINE_API_TOKEN).
                Also read from the CATS_PIPELINE_TOKEN environment variable.
  --ca-file     PEM bundle to trust for HTTPS (e.g. your internal CA).
  --insecure    Skip TLS verification (lab use only).
  --max-findings  Upper bound for the largest tier (default 20000). Very large
                scans are trimmed to stay under --max-bytes (default 15 MB),
                because CATS rejects pipeline bodies over
                CATS_PIPELINE_MAX_REQUEST_BYTES (16 MB by default).
  --start-at    Resume a partially completed run at service number N.

Re-running on the same day with the same --seed and --prefix sends the same
execution ids; CATS treats them as duplicates and accepts them without
creating new scans, so an interrupted run can simply be repeated (or resumed
with --start-at). Running again on a later day adds newer scans to the same
services (history grows). To create a separate set of services, change
--prefix.

All vulnerabilities carry a fixed version: CATS accepts fixable-only
assessments (the pipeline reports only vulnerabilities that have a fix).

Removing the services afterwards: archive and then delete them in CATS
(Service > Actions), with ALLOW_SERVICE_DELETE=true on the portal, or load
into a disposable CATS database.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROFILES = [  # (profile, share of services)
    ("helm-app", 0.40), ("container", 0.20), ("kubernetes", 0.12),
    ("helm-config", 0.10), ("incomplete", 0.08), ("clean", 0.10),
]
TIERS = [  # (name, share, minimum, maximum) - maximum is scaled to --max-findings
    ("none", 0.08, 0, 0), ("low", 0.30, 1, 50), ("medium", 0.30, 50, 500),
    ("high", 0.22, 500, 5000), ("very-high", 0.10, 5000, 20000),
]
SEVERITY_WEIGHTS = [("Critical", 6), ("High", 22), ("Medium", 40), ("Low", 25), ("Unknown", 7)]
GROUPS = ["team-a", "team-b", "team-c", "team-d", "team-e"]
OWNERS = ["Platform Engineering", "Payments", "Identity", "Data Services", "Mobile Backend", "Internal Tools"]
WORDS = ["ledger", "gateway", "orders", "inventory", "billing", "catalog", "search", "notify", "auth", "profile",
         "reports", "ingest", "scheduler", "metrics", "audit", "pricing", "checkout", "shipping", "support", "media"]
BASE_IMAGES = [
    ("debian", "12.5", "deb"), ("ubuntu", "22.04", "deb"), ("alpine", "3.19", "apk"),
    ("python", "3.11-slim", "deb"), ("node", "20-bookworm", "deb"), ("eclipse-temurin", "21-jre", "deb"),
    ("nginx", "1.25", "deb"), ("redis", "7.2", "deb"), ("postgres", "16", "deb"), ("golang", "1.22", "deb"),
]
PACKAGES = {
    "deb": ["openssl", "libssl3", "zlib1g", "libc6", "libxml2", "curl", "libcurl4", "openssh-client", "perl-base",
            "libgnutls30", "libsqlite3-0", "libexpat1", "libtiff6", "libpng16-16", "gzip", "tar", "bash", "systemd",
            "libkrb5-3", "libldap-2.5-0", "libpam0g", "util-linux", "ncurses-base", "libgcrypt20", "libxslt1.1"],
    "apk": ["openssl", "libcrypto3", "libssl3", "zlib", "busybox", "musl", "curl", "libcurl", "expat", "libxml2"],
    "pypi": ["requests", "urllib3", "jinja2", "cryptography", "pyyaml", "django", "flask", "werkzeug", "pillow", "idna"],
    "npm": ["lodash", "express", "axios", "minimist", "semver", "ws", "jsonwebtoken", "qs", "tough-cookie", "follow-redirects"],
    "maven": ["log4j-core", "jackson-databind", "spring-core", "netty-codec-http", "commons-text", "snakeyaml", "guava"],
    "golang": ["golang.org/x/net", "golang.org/x/crypto", "google.golang.org/grpc", "github.com/gin-gonic/gin"],
}
APP_ECOSYSTEM = {"python": "pypi", "node": "npm", "eclipse-temurin": "maven", "golang": "golang"}
CONFIG_CHECKS = [  # Trivy Kubernetes misconfiguration checks (real identifiers)
    ("KSV-0001", "Medium", "Can elevate its own privileges", "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'."),
    ("KSV-0003", "Low", "Default capabilities not dropped", "Add 'ALL' to containers[].securityContext.capabilities.drop."),
    ("KSV-0011", "Low", "CPU not limited", "Set a limit value under 'containers[].resources.limits.cpu'."),
    ("KSV-0012", "Medium", "Runs as root user", "Set 'containers[].securityContext.runAsNonRoot' to true."),
    ("KSV-0014", "High", "Root file system is not read-only", "Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'."),
    ("KSV-0015", "Low", "CPU requests not specified", "Set 'containers[].resources.requests.cpu'."),
    ("KSV-0016", "Low", "Memory requests not specified", "Set 'containers[].resources.requests.memory'."),
    ("KSV-0018", "Low", "Memory not limited", "Set a limit value under 'containers[].resources.limits.memory'."),
    ("KSV-0020", "Low", "Runs with UID <= 10000", "Set 'containers[].securityContext.runAsUser' to an integer > 10000."),
    ("KSV-0021", "Low", "Runs with GID <= 10000", "Set 'containers[].securityContext.runAsGroup' to an integer > 10000."),
    ("KSV-0030", "Low", "Runtime/Default Seccomp profile not set", "Set 'spec.securityContext.seccompProfile.type' to 'RuntimeDefault'."),
    ("KSV-0104", "Medium", "Seccomp policies disabled", "Specify a seccomp profile for the container."),
    ("KSV-0106", "Low", "Container capabilities must only include NET_BIND_SERVICE", "Drop all capabilities and add only NET_BIND_SERVICE if needed."),
    ("KSV-0110", "Low", "Workloads in the default namespace", "Set 'metadata.namespace' to a namespace other than 'default'."),
    ("KSV-0117", "Medium", "Prevent binding to privileged ports", "Do not map the container to ports below 1024."),
    ("KSV-0125", "Medium", "Restrict container images to trusted registries", "Use images from trusted registries."),
]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", help="CATS base URL, e.g. https://cats.example.local")
    parser.add_argument("--token", default=os.getenv("CATS_PIPELINE_TOKEN"), help="pipeline API token (or CATS_PIPELINE_TOKEN)")
    parser.add_argument("--services", type=int, default=100)
    parser.add_argument("--scans", type=int, default=3, help="scans of history per service (default 3)")
    parser.add_argument("--max-findings", type=int, default=20000, help="largest vulnerability count for one scan")
    parser.add_argument("--max-bytes", type=int, default=15 * 1024 * 1024, help="trim scans whose JSON body would exceed this")
    parser.add_argument("--seed", type=int, default=20261008)
    parser.add_argument("--prefix", default="load-", help="service id prefix")
    parser.add_argument("--registry", default="registry.example.internal", help="registry host used in image references")
    parser.add_argument("--start-at", type=int, default=1, help="resume at service number N")
    parser.add_argument("--ca-file", help="PEM bundle to trust for HTTPS")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (lab use only)")
    parser.add_argument("--timeout", type=float, default=300, help="seconds per request")
    parser.add_argument("--dry-run", action="store_true", help="build payloads without sending them")
    parser.add_argument("--out", type=Path, help="also write each payload as JSON into this folder")
    args = parser.parse_args()
    if not args.dry_run and (not args.url or not args.token):
        parser.error("--url and --token are required unless --dry-run is given")
    if args.services < 1 or args.scans < 1 or args.max_findings < 0:
        parser.error("--services and --scans must be at least 1; --max-findings must not be negative")
    return args


def weighted(rng, items):
    """Pick one (name, weight) pair with probability proportional to weight."""
    pick = rng.random() * sum(weight for _, weight in items)
    for item in items:
        if pick < item[1]:
            return item
        pick -= item[1]
    return items[-1]


def assign(count, shares, rng):
    """Deterministic allocation of `count` items to categories by share."""
    labels = []
    for name, share, *_ in shares:
        labels += [name] * int(round(share * count))
    while len(labels) < count:
        labels.append(shares[0][0])
    labels = labels[:count]
    rng.shuffle(labels)
    return labels


def digest(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class ServicePlan:
    def __init__(self, number, profile, tier, args, rng):
        self.number, self.profile, self.tier = number, profile, tier
        word = WORDS[(number - 1) % len(WORDS)]
        self.key = f"{args.prefix}{word}-{number:03d}"
        self.name = f"{word.title()} Service {number:03d}"
        self.owner = rng.choice(OWNERS) if rng.random() < 0.85 else None
        self.poc = f"{word}.team@example.internal" if rng.random() < 0.9 else None
        self.groups = rng.sample(GROUPS, 1 if rng.random() < 0.8 else 2)
        image_count = {"container": 1, "clean": rng.randint(1, 2)}.get(profile, rng.randint(2, 5))
        self.images = []
        for index in range(image_count):
            base, tag, ecosystem = BASE_IMAGES[(number + index) % len(BASE_IMAGES)]
            component = ["api", "worker", "web", "migrate", "sidecar"][index % 5]
            self.images.append({"name": f"{args.registry}/{word}/{component}", "base": base, "tag": tag,
                                "ecosystem": ecosystem, "component": component,
                                "app_ecosystem": APP_ECOSYSTEM.get(base)})
        low, high = next((lo, hi) for name, _, lo, hi in TIERS if name == tier)
        high = min(high, args.max_findings)
        low = min(low, high)
        self.vulnerabilities = 0 if profile in {"helm-config"} else rng.randint(low, high) if high else 0
        if profile == "clean":
            self.vulnerabilities = min(self.vulnerabilities, rng.randint(0, 5))
        self.config_count = {"helm-app": rng.randint(5, 60), "helm-config": rng.randint(10, 90),
                             "kubernetes": rng.randint(5, 50), "incomplete": rng.randint(5, 40),
                             "clean": rng.randint(0, 2)}.get(profile, 0)
        self.version_change = rng.random() < 0.35
        # Days between scans. With CATS's default 90-day due date and 14-day
        # warning window this gives a mix of compliant, approaching-due
        # (warning) and overdue (non-compliant) services.
        self.spacing = rng.choice([2, 7, 20, 38, 45, 60])


def severity(rng):
    return weighted(rng, SEVERITY_WEIGHTS)[0]


def build_vulnerabilities(plan, scan, scans, rng_seed):
    """Stable vulnerability population with churn between scans."""
    rng = random.Random(rng_seed)
    population = []
    total = plan.vulnerabilities
    for index in range(int(total * 1.1) + (1 if total else 0)):
        image = plan.images[index % len(plan.images)]
        ecosystem = image["app_ecosystem"] if image["app_ecosystem"] and index % 3 == 0 else image["ecosystem"]
        package = PACKAGES[ecosystem][index % len(PACKAGES[ecosystem])]
        year = 2019 + (index * 7 + plan.number) % 8
        sev = severity(rng)
        # CATS accepts fixable-only assessments: every vulnerability has a fix.
        # Some fixes are a patch release away, others a major version.
        major = rng.random() < 0.25
        population.append({
            # 9-digit sequence numbers (valid format, outside any real range).
            "cve": f"CVE-{year}-9{plan.number:03d}{index:05d}",
            "severity": sev,
            "image": f"{image['name']}:{image['base']}-{image['tag']}",
            "image_digest": digest(f"{plan.key}/{image['component']}"),
            "package": package,
            "installed_version": f"{1 + index % 4}.{index % 10}.{index % 7}",
            "fixed_version": f"{2 + index % 4}.0.0" if major else f"{1 + index % 4}.{index % 10}.{index % 7 + 1}",
            "kev": sev in {"Critical", "High"} and rng.random() < 0.06,
            "epss": round(min(1.0, rng.random() ** 3 + (0.3 if sev == "Critical" else 0)), 4) if rng.random() < 0.8 else None,
            "evidence": {"description": f"Synthetic {sev.lower()} vulnerability in {package} (load-test data).",
                         "scanner": "Trivy" if index % 2 else "Grype", "synthetic": True},
        })
    # Scan s sees a sliding window: older scans include findings later fixed,
    # newer scans add findings that did not exist before.
    shift = int(total * 0.06) * (scan - 1)
    return population[shift:shift + total]


def build_config_findings(plan, scan, rng_seed):
    rng = random.Random(rng_seed)
    findings = []
    resources = [f"Deployment/{plan.key}-{image['component']}" for image in plan.images]
    # One finding per (check, resource) pair, as a scanner reports them.
    count = min(len(CONFIG_CHECKS) * len(resources), max(0, plan.config_count - (scan - 1) * rng.randint(0, 3)))
    for index in range(count):
        check, sev, title, remediation = CONFIG_CHECKS[(index + plan.number) % len(CONFIG_CHECKS)]
        target = resources[(index // len(CONFIG_CHECKS)) % len(resources)]
        container = target.split("-")[-1]
        findings.append({
            "type": "Configuration", "finding": check, "severity": sev, "scanner": "Trivy",
            "framework": "Kubernetes Security Check", "target": target,
            "namespace": "default" if check == "KSV-0110" else plan.key, "title": title,
            "description": f"{title} (load-test data).", "remediation": remediation,
            "evidence": {"cause_metadata": {"Provider": "Kubernetes", "Resource": target, "Container": container}, "synthetic": True},
        })
    return findings


def build_resources(plan, version):
    """Rendered Kubernetes resources consistent with the service's images."""
    namespace = plan.key
    resources = [{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": plan.key, "namespace": namespace}}]
    for image in plan.images:
        name = f"{plan.key}-{image['component']}"
        port = 8080 if image["component"] in {"api", "web"} else None
        container = {"name": image["component"], "image": f"{image['name']}:{image['base']}-{image['tag']}",
                     "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}} if plan.number % 2 else {}}
        if port:
            container["ports"] = [{"containerPort": port, "protocol": "TCP"}]
        container["envFrom"] = [{"configMapRef": {"name": f"{plan.key}-config"}}]
        kind = "CronJob" if image["component"] == "migrate" else "Deployment"
        pod = {"metadata": {"labels": {"app": name}},
               "spec": {"serviceAccountName": plan.key, "containers": [container]}}
        if kind == "CronJob":
            spec = {"schedule": "0 3 * * *", "jobTemplate": {"spec": {"template": pod}}}
        else:
            spec = {"replicas": 2, "selector": {"matchLabels": {"app": name}}, "template": pod}
        resources.append({"apiVersion": "batch/v1" if kind == "CronJob" else "apps/v1", "kind": kind,
                          "metadata": {"name": name, "namespace": namespace,
                                       "labels": {"app.kubernetes.io/name": plan.key, "app.kubernetes.io/version": version}},
                          "spec": spec})
        if port:
            resources.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": namespace},
                              "spec": {"selector": {"app": name}, "ports": [{"port": 80, "targetPort": port, "protocol": "TCP"}]}})
    resources.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{plan.key}-config", "namespace": namespace},
                      "data": {"LOG_LEVEL": "info", "SERVICE_NAME": plan.key}})
    web = next((image for image in plan.images if image["component"] in {"web", "api"}), None)
    if web:
        resources.append({"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
                          "metadata": {"name": plan.key, "namespace": namespace},
                          "spec": {"rules": [{"host": f"{plan.key}.apps.example.internal", "http": {"paths": [{
                              "path": "/", "pathType": "Prefix", "backend": {"service": {
                                  "name": f"{plan.key}-{web['component']}", "port": {"number": 80}}}}]}}]}})
    return resources


def chart_files(plan, version, resources):
    """A small Helm chart whose templates are the rendered resources (JSON is valid YAML)."""
    root = plan.key
    files = {
        f"{root}/Chart.yaml": (f"apiVersion: v2\nname: {root}\ndescription: Load-test chart for {plan.name}\n"
                               f"type: application\nversion: {version}\nappVersion: \"{version}\"\n"),
        f"{root}/values.yaml": "replicaCount: 2\nimages:\n" + "".join(
            f"  {image['component']}:\n    repository: {image['name']}\n    tag: \"{image['base']}-{image['tag']}\"\n"
            for image in plan.images),
    }
    for index, resource in enumerate(resources):
        files[f"{root}/templates/{index:02d}-{resource['kind'].lower()}.yaml"] = json.dumps(resource, indent=2) + "\n"
    return files


def build_payload(plan, scan, scans, args, now):
    version_index = scan if plan.version_change else 1
    version = f"1.{version_index}.0"
    scanned_at = now - timedelta(days=(scans - scan) * plan.spacing, hours=plan.number % 9)
    seed = args.seed * 1000 + plan.number
    vulnerabilities = [] if plan.profile in {"helm-config"} else build_vulnerabilities(plan, scan, scans, seed)
    helm = plan.profile in {"helm-app", "helm-config", "incomplete", "clean"}
    resources = build_resources(plan, version) if plan.profile != "container" else []
    incomplete = plan.profile == "incomplete" and scan == scans
    skipped = [f"{plan.images[-1]['name']}:{plan.images[-1]['base']}-{plan.images[-1]['tag']}"] if incomplete else []
    if incomplete:
        vulnerabilities = [item for item in vulnerabilities if item["image"] not in skipped]
    components = []
    seen = set()
    for item in vulnerabilities:
        key = (item["package"], item["installed_version"], item["image"])
        if key not in seen:
            seen.add(key)
            ecosystem = next((name for name, packages in PACKAGES.items() if item["package"] in packages), "generic")
            components.append({"name": item["package"], "version": item["installed_version"], "ecosystem": ecosystem,
                               "purl": f"pkg:{ecosystem}/{item['package']}@{item['installed_version']}", "image": item["image"],
                               "license_declared": ["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-2.0-only", ""][len(seen) % 5]})
    for image in plan.images:  # components without known vulnerabilities
        reference = f"{image['name']}:{image['base']}-{image['tag']}"
        for package in PACKAGES[image["ecosystem"]][:8]:
            key = (package, "9.9.9", reference)
            if key not in seen:
                seen.add(key)
                components.append({"name": package, "version": "9.9.9", "ecosystem": image["ecosystem"],
                                   "purl": f"pkg:{image['ecosystem']}/{package}@9.9.9", "image": reference, "license_declared": "MIT"})
    images = [f"{image['name']}:{image['base']}-{image['tag']}" for image in plan.images]
    body = {
        "schema_version": "1.0",
        "execution_id": f"{args.prefix}seed{args.seed}:{now.date().isoformat()}:{plan.key}:scan{scan}",
        "scanned_at": scanned_at.isoformat(),
        "complete": not incomplete,
        "scan_scope": "service",
        "skipped_images": skipped,
        "skipped_charts": [],
        "fixable_only": True,
        "pipeline_url": f"https://ci.example.internal/{plan.key}/pipelines/{1000 + scan}",
        "commit_sha": hashlib.sha1(f"{plan.key}{scan}".encode()).hexdigest()[:12],
        "service": {"id": plan.key, "name": plan.name, "version": version,
                    "description": f"Load-test {plan.profile} service ({plan.tier} finding volume).",
                    "owner": plan.owner, "poc": plan.poc, "groups": plan.groups},
        "findings": vulnerabilities,
        "policy_findings": build_config_findings(plan, scan, seed) if plan.profile not in {"container"} else [],
        "sbom_components": components[:50000],
        "sbom_images": [image for image in images if image not in skipped],
        "artifact_type": "helm" if helm else ("kubernetes" if plan.profile == "kubernetes" else "image"),
        "service_overview": {
            "description": f"{plan.name}: synthetic {plan.profile} workload for load testing.",
            "source": "Helm rendered manifests" if helm else ("Kubernetes manifests" if resources else "Image metadata"),
            "images": [{"image": image, "discovered_from": f"Deployment/{plan.key}-{plan.images[index]['component']}"}
                       for index, image in enumerate(images)],
            "rendered_resources": resources,
            "ports": [{"port": 80, "target_port": 8080, "protocol": "TCP", "service": f"{plan.key}-{image['component']}"}
                      for image in plan.images if image["component"] in {"api", "web"}],
        },
    }
    if helm:
        body["helm_source_files"] = chart_files(plan, version, resources)
    if plan.profile == "container":
        body["service_overview"].pop("rendered_resources")
    # Stay under the portal's pipeline request-size limit.
    trimmed = False
    while len(json.dumps(body)) > args.max_bytes and body["findings"]:
        body["findings"] = body["findings"][: int(len(body["findings"]) * 0.85)]
        trimmed = True
    return body, trimmed


def sender(args):
    context = None
    if args.url and args.url.lower().startswith("https"):
        context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else ssl.create_default_context()
        if args.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    endpoint = args.url.rstrip("/") + "/api/v1/pipeline-results" if args.url else None

    def send(body):
        data = json.dumps(body).encode("utf-8")
        for attempt in range(1, 4):
            request = urllib.request.Request(endpoint, data=data, method="POST", headers={
                "Content-Type": "application/json", "Authorization": f"Bearer {args.token}"})
            try:
                with urllib.request.urlopen(request, timeout=args.timeout, context=context) as response:
                    return response.status, response.read(400).decode("utf-8", "replace")
            except urllib.error.HTTPError as error:
                detail = error.read(600).decode("utf-8", "replace")
                if error.code >= 500 and attempt < 3:
                    time.sleep(2 * attempt)
                    continue
                return error.code, detail
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                if attempt < 3:
                    time.sleep(2 * attempt)
                    continue
                return 0, str(error)
        return 0, "unreachable"
    return send


def main():
    args = parse_args()
    rng = random.Random(args.seed)
    profiles = assign(args.services, PROFILES, rng)
    tiers = assign(args.services, TIERS, rng)
    plans = [ServicePlan(number, profile, "none" if profile == "helm-config" else tier, args, random.Random(args.seed + number))
             for number, (profile, tier) in enumerate(zip(profiles, tiers), start=1)]
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
    send = None if args.dry_run else sender(args)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    summary = {"services": 0, "scans": 0, "vulnerabilities": 0, "configuration": 0, "failed": 0, "trimmed": 0}
    started = time.time()
    print(f"{'#':>4}  {'service':<28} {'profile':<12} {'tier':<10} {'scan':>4}  {'vulns':>6} {'config':>6}  result", flush=True)
    for plan in plans:
        if plan.number < args.start_at:
            continue
        ok = True
        for scan in range(1, args.scans + 1):
            body, trimmed = build_payload(plan, scan, args.scans, args, now)
            summary["trimmed"] += trimmed
            if args.out:
                (args.out / f"{plan.key}-scan{scan}.json").write_text(json.dumps(body, indent=1), encoding="utf-8")
            result = "built" if args.dry_run else None
            if send:
                status, detail = send(body)
                result = f"{status}" if status in (200, 201) else f"FAILED {status}: {detail[:300]}"
                if status not in (200, 201):
                    ok = False
                    summary["failed"] += 1
            print(f"{plan.number:>4}  {plan.key:<28} {plan.profile:<12} {plan.tier:<10} {scan:>4}  {len(body['findings']):>6} "
                  f"{len(body['policy_findings']):>6}  {result}{'  (trimmed to fit --max-bytes)' if trimmed else ''}", flush=True)
            summary["scans"] += 1
            if scan == args.scans:
                summary["vulnerabilities"] += len(body["findings"])
                summary["configuration"] += len(body["policy_findings"])
            if not ok:
                break
        summary["services"] += 1
    elapsed = time.time() - started
    print(f"\n{summary['services']} services, {summary['scans']} scans in {elapsed:.0f}s; latest scans carry "
          f"{summary['vulnerabilities']:,} vulnerability and {summary['configuration']:,} configuration findings. "
          f"Failed requests: {summary['failed']}. Trimmed scans: {summary['trimmed']}.")
    if summary["failed"]:
        print("Some scans were rejected; fix the cause shown above and re-run with --start-at to resume.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
