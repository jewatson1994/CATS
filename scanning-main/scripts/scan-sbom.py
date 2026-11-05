#!/usr/bin/env python3
"""CLI adapter for the same retained-inventory action used by Patch."""
from pathlib import Path
import sys

# Installed scanner scripts live separately from the portal package. Local
# checkouts use the sibling portal directory; neither path comes from a job.
for location in (Path(__file__).resolve().parents[2] / "portal", Path("/opt/portal"), Path("/app")):
    if (location / "app/scanner_actions.py").is_file():
        sys.path.insert(0, str(location))
        break

from app.scanner_actions import scan_sbom_evidence


def scan(sbom_path, result_path):
    try:
        result_path = Path(result_path)
        scan_sbom_evidence(Path(sbom_path), result_path, result_path.parent / "full" / result_path.name)
    except (RuntimeError, OSError, ValueError):
        print("Offline SBOM scan failed; no completed evidence was retained", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(scan(*sys.argv[1:]))
