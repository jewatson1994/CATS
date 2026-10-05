"""Local risk intelligence lookups bundled with the CATS image."""

from __future__ import annotations

import csv
import gzip
import json
import os
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from collections.abc import Mapping
from hashlib import sha256


DATA_DIR = Path(os.getenv("CATS_POLICY_DATA_DIR", "/app/policy"))


def _data_file(name: str) -> Path:
    configured = DATA_DIR / name
    return configured if configured.exists() else Path("/app/policy") / name


@lru_cache(maxsize=1)
def kev_cves() -> frozenset[str]:
    path = _data_file("kev.json")
    if not path.exists():
        return frozenset()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return frozenset(item.get("cveID", "").upper() for item in payload.get("vulnerabilities", []) if item.get("cveID"))
    except (OSError, ValueError, TypeError):
        return frozenset()


@lru_cache(maxsize=1)
def epss_scores() -> Mapping[str, float]:
    path = _data_file("epss.csv")
    if not path.exists():
        return MappingProxyType({})
    try:
        opener = gzip.open if path.read_bytes()[:2] == b"\x1f\x8b" else open
        with opener(path, "rt", encoding="utf-8", newline="") as stream:
            rows = (row for row in csv.DictReader(stream) if row.get("cve"))
            return MappingProxyType({row["cve"].upper(): float(row["epss"]) for row in rows if row.get("epss")})
    except (OSError, ValueError, TypeError):
        return MappingProxyType({})


def risk_metadata(cve: str) -> tuple[bool, float | None]:
    key = cve.upper()
    return key in kev_cves(), epss_scores().get(key)


_catalog_snapshot = None
_catalog_token = None


def risk_catalog_token():
    """Stable content token, computed once per immutable catalog refresh."""
    global _catalog_snapshot, _catalog_token
    kev, epss = kev_cves(), epss_scores()
    if _catalog_snapshot is None or _catalog_snapshot[0] is not kev or _catalog_snapshot[1] is not epss:
        digest = sha256()
        for cve in sorted(kev):
            digest.update(json.dumps(["kev", cve]).encode())
        for cve, score in sorted(epss.items()):
            digest.update(json.dumps(["epss", cve, score]).encode())
        _catalog_snapshot = (kev, epss)
        _catalog_token = digest.hexdigest()
    return _catalog_token


risk_metadata.cache_token = risk_catalog_token
