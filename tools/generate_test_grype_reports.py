"""Generate deterministic, synthetic Grype reports for local CATS testing.

These reports are deliberately non-production fixtures. They use CVE-2099 IDs
and metadata under the cats_test key so they cannot be mistaken for real scan
evidence.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


SERVICES = [
    ("atlas-api", "Atlas API", "Platform Engineering"),
    ("beacon-worker", "Beacon Worker", "Operations"),
    ("comet-gateway", "Comet Gateway", "Edge Services"),
    ("delta-events", "Delta Events", "Data Engineering"),
    ("ember-console", "Ember Console", "Security Operations"),
    ("forge-billing", "Forge Billing", "Commerce"),
    ("harbor-sync", "Harbor Sync", "Integration"),
    ("lumen-search", "Lumen Search", "Product"),
    ("nova-auth", "Nova Auth", "Identity"),
    ("orbit-metrics", "Orbit Metrics", "Observability"),
]

PACKAGES = [
    ("openssl", "3.0.13", "3.0.15", "High"),
    ("curl", "8.4.0", "8.8.0", "Medium"),
    ("zlib", "1.2.13", "1.3.1", "High"),
    ("libxml2", "2.10.3", "2.12.7", "Critical"),
    ("glibc", "2.35", "2.38", "High"),
    ("python", "3.11.6", "3.11.9", "Medium"),
    ("expat", "2.5.0", "2.6.2", "High"),
    ("busybox", "1.36.1", "1.36.1-r19", "Low"),
]


def make_match(index: int, package_index: int, service_id: str, scan: int) -> dict:
    package, installed, fixed, severity = PACKAGES[package_index % len(PACKAGES)]
    cve = f"CVE-2099-{index:04d}"
    return {
        "vulnerability": {
            "id": cve,
            "severity": severity,
            "namespace": "cats-test.synthetic",
            "description": f"Synthetic CATS test vulnerability {cve} for lifecycle testing.",
            "dataSource": "https://example.invalid/cats-test-data",
            "urls": [f"https://example.invalid/advisories/{cve.lower()}"],
            "fix": {"versions": [fixed]},
            "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", "metrics": {"baseScore": 7.5}}],
        },
        "artifact": {
            "name": package,
            "version": installed,
            "type": "deb",
            "locations": [{"path": f"/usr/lib/{package}/package.list"}],
        },
        "relatedVulnerabilities": [],
        "matchDetails": [{"type": "synthetic-cats-test", "matcher": "cats-fixture", "searchedBy": {"package": package}}],
        "cats_test": {"service": service_id, "scan": scan},
    }


def build_report(service_index: int, scan: int, rng: random.Random, root: Path) -> Path:
    service_id, service_name, owner = SERVICES[service_index]
    base = service_index * 100 + 1
    # Later scans resolve some earlier findings and introduce a few new ones.
    count = rng.randint(2, 6)
    indices = [base + n for n in range(count)]
    if scan == 2:
        indices = indices[: max(1, count - 2)]
    elif scan == 3:
        indices = indices + [base + 50, base + 51]
    elif scan == 4:
        indices = indices[1:]
    matches = [make_match(number, rng.randrange(len(PACKAGES)), service_id, scan) for number in indices]
    scanned_at = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc) + timedelta(hours=service_index * 2 + scan)
    payload = {
        "schema": {"version": "5.0.0"},
        "artifact": {"name": f"cyber-approved/{service_id}", "version": f"test-{scan}"},
        "source": {"type": "image", "target": {"userInput": f"cyber-approved/{service_id}:test-{scan}"}},
        "distro": {"name": "debian", "version": "12"},
        "descriptor": {"name": "grype", "version": "0.99.0-cats-test"},
        "matches": matches,
        "cats_test": {
            "synthetic": True,
            "service": {"id": service_id, "name": service_name, "version": f"test-{scan}", "owner": owner},
            "scan": scan,
            "scanned_at": scanned_at.isoformat().replace("+00:00", "Z"),
        },
    }
    path = root / f"{service_id}-scan-{scan:02d}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("test-grype-reports"))
    parser.add_argument("--seed", type=int, default=2099)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    for service_index in range(len(SERVICES)):
        for scan in range(1, 5):
            build_report(service_index, scan, rng, args.output)
    print(f"Generated {len(SERVICES) * 4} synthetic Grype reports in {args.output}")


if __name__ == "__main__":
    main()
