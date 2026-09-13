"""Validate normalized CATS policy findings before portal ingestion."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


REQUIRED_TEXT = ("finding", "severity", "scanner", "target", "title", "fingerprint")
ALLOWED_SEVERITIES = {"unknown", "negligible", "low", "medium", "high", "critical"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    data = json.loads(args.path.read_text(encoding="utf-8"))
    findings = data.get("policy_findings", []) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        raise SystemExit("policy_findings must be a JSON array")

    fingerprints: set[str] = set()
    errors: list[str] = []
    for index, item in enumerate(findings):
        location = f"policy_findings[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{location}: must be an object")
            continue
        if str(item.get("type", "Configuration")).casefold() != "configuration":
            errors.append(f"{location}.type: normalized scanner findings must use Configuration")
        for field in REQUIRED_TEXT:
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append(f"{location}.{field}: non-empty text is required")
        severity = str(item.get("severity", "Unknown")).casefold()
        if severity not in ALLOWED_SEVERITIES:
            errors.append(f"{location}.severity: unsupported value {item.get('severity')!r}")
        fingerprint = item.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            if fingerprint in fingerprints:
                errors.append(f"{location}.fingerprint: duplicate {fingerprint}")
            fingerprints.add(fingerprint)

    if errors:
        raise SystemExit("Invalid CATS policy findings:\n- " + "\n- ".join(errors))
    print(f"Validated {len(findings)} policy finding(s) from {args.path}")


if __name__ == "__main__":
    main()
