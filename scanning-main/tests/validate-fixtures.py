#!/usr/bin/env python3

"""Dependency-free validation for committed Trivy and Helm test fixtures."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    trivy = json.loads((ROOT / "tests/fixtures/trivy-config.json").read_text(encoding="utf-8"))
    failures = [
        finding
        for result in trivy.get("Results", [])
        for finding in result.get("Misconfigurations", [])
        if finding.get("Status", "FAIL").upper() == "FAIL"
    ]
    assert {finding["ID"] for finding in failures} == {"KSV014", "DS002"}

    umbrella = ROOT / "tests/fixtures/helm/umbrella"
    required = [
        umbrella / "Chart.yaml",
        umbrella / "templates/deployment.yaml",
        umbrella / "charts/worker/Chart.yaml",
        umbrella / "charts/worker/templates/deployment.yaml",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    assert not missing, f"Missing fixture files: {missing}"
    print("Fixture contract passed: 2 failing checks and a vendored nested chart.")


if __name__ == "__main__":
    main()
