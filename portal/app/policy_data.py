"""Local risk intelligence lookups bundled with the CATS image."""

from __future__ import annotations

import csv
import gzip
import json
import os
from functools import lru_cache
from pathlib import Path


DATA_DIR = Path(os.getenv("CATS_POLICY_DATA_DIR", "/app/policy"))


@lru_cache(maxsize=1)
def kev_cves() -> set[str]:
    path = DATA_DIR / "kev.json"
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return {item.get("cveID", "").upper() for item in payload.get("vulnerabilities", []) if item.get("cveID")}
    except (OSError, ValueError, TypeError):
        return set()


@lru_cache(maxsize=1)
def epss_scores() -> dict[str, float]:
    path = DATA_DIR / "epss.csv"
    if not path.exists():
        return {}
    try:
        opener = gzip.open if path.read_bytes()[:2] == b"\x1f\x8b" else open
        with opener(path, "rt", encoding="utf-8", newline="") as stream:
            rows = (row for row in csv.DictReader(stream) if row.get("cve"))
            return {row["cve"].upper(): float(row["epss"]) for row in rows if row.get("epss")}
    except (OSError, ValueError, TypeError):
        return {}


def risk_metadata(cve: str) -> tuple[bool, float | None]:
    key = cve.upper()
    return key in kev_cves(), epss_scores().get(key)
