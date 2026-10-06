"""Local risk intelligence lookups bundled with the CATS image.

KEV and EPSS catalogs are read from ``CATS_POLICY_DATA_DIR`` (default
``/app/policy``).  Both parsers are shared with the security-data refresh
validator so a feed accepted by an administrator is read the same way at
runtime.  Loaded catalogs are immutable snapshots; a changed file (refresh in
this or another worker, or an offline file replacement) is detected by its
size/modification time and reloaded, which also changes the catalog token.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
import gzip
import io
import json
import logging
import math
import os
from pathlib import Path
import threading
import time
from types import MappingProxyType
from collections.abc import Mapping
from hashlib import sha256


DATA_DIR = Path(os.getenv("CATS_POLICY_DATA_DIR", "/app/policy"))
# File signatures are re-checked at most this often per process.
STAT_INTERVAL_SECONDS = 5.0
_logger = logging.getLogger("cats.intelligence")


def _data_file(name: str) -> Path:
    configured = DATA_DIR / name
    return configured if configured.exists() else Path("/app/policy") / name


@dataclass(frozen=True)
class EpssCatalog:
    scores: Mapping[str, float]
    percentiles: Mapping[str, float]
    metadata: Mapping[str, str]
    records: int
    rejected: int


@dataclass(frozen=True)
class KevCatalog:
    cves: frozenset
    metadata: Mapping[str, str]
    records: int


def _decode(data: bytes | str) -> str:
    if isinstance(data, str):
        return data
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf-8-sig")


def _metadata_line(line: str) -> dict[str, str]:
    """Parse FIRST.org style ``#model_version:v2025.03.14,score_date:...``."""
    values = {}
    for part in line.lstrip("#").split(","):
        key, separator, value = part.partition(":")
        key = key.strip().lower()
        if separator and key and all(character.isalnum() or character == "_" for character in key):
            values[key] = value.strip()[:120]
    return values


def _probability(value) -> float | None:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0 <= number <= 1 else None


def parse_epss(data: bytes | str, *, strict: bool) -> EpssCatalog:
    """Parse an EPSS CSV feed, optionally gzip compressed.

    Comment/metadata lines start with ``#`` and may precede the header (the
    published feed begins with ``#model_version:...,score_date:...``).  The
    header must contain ``cve`` and ``epss`` columns; ``percentile`` is kept
    when present.  ``strict`` rejects the whole feed on any malformed record
    (administrator refresh validation); otherwise malformed rows are counted
    and skipped so one bad row cannot blank an installed catalog.
    """
    metadata: dict[str, str] = {}
    content: list[str] = []
    for line in _decode(data).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            metadata.update(_metadata_line(stripped))
            continue
        content.append(line)
    if not content:
        raise ValueError("EPSS feed must contain CVE and score columns")
    reader = csv.reader(io.StringIO("\n".join(content)))
    header = [column.strip().lower() for column in next(reader)]
    if "cve" not in header or "epss" not in header:
        raise ValueError("EPSS feed must contain CVE and score columns")
    cve_index, score_index = header.index("cve"), header.index("epss")
    percentile_index = header.index("percentile") if "percentile" in header else None
    scores: dict[str, float] = {}
    percentiles: dict[str, float] = {}
    rejected = 0
    for line_number, row in enumerate(reader, start=2):
        cve = row[cve_index].strip().upper() if len(row) > cve_index else ""
        score = _probability(row[score_index]) if len(row) > score_index else None
        raw_percentile = row[percentile_index].strip() if percentile_index is not None and len(row) > percentile_index else ""
        percentile = _probability(raw_percentile) if raw_percentile else None
        if not cve or score is None or (raw_percentile and percentile is None):
            if strict:
                raise ValueError(f"EPSS feed record {line_number} must contain a CVE and scores between 0 and 1")
            rejected += 1
            continue
        scores[cve] = score
        if percentile is not None:
            percentiles[cve] = percentile
    if not scores:
        raise ValueError("EPSS feed must contain CVE and score columns")
    return EpssCatalog(MappingProxyType(scores), MappingProxyType(percentiles),
                       MappingProxyType(metadata), len(scores), rejected)


def parse_kev(data: bytes | str, *, strict: bool) -> KevCatalog:
    payload = json.loads(_decode(data))
    rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError("KEV feed must contain vulnerability records with cveID")
    if strict and any(not isinstance(row, dict) or not row.get("cveID") for row in rows):
        raise ValueError("KEV feed must contain vulnerability records with cveID")
    cves = frozenset(str(row["cveID"]).strip().upper() for row in rows
                     if isinstance(row, dict) and str(row.get("cveID") or "").strip())
    if not cves:
        raise ValueError("KEV feed must contain vulnerability records with cveID")
    metadata = {key: str(payload.get(source))[:120] for key, source in
                (("catalog_version", "catalogVersion"), ("date_released", "dateReleased"))
                if payload.get(source)}
    return KevCatalog(cves, MappingProxyType(metadata), len(cves))


@dataclass
class _Cached:
    name: str
    loader: object
    empty: object
    lock: threading.Lock = field(default_factory=threading.Lock)
    signature: tuple | None = None
    checked: float = 0.0
    value: object = None
    status: dict = field(default_factory=dict)

    def get(self):
        now = time.monotonic()
        if self.value is not None and now - self.checked < STAT_INTERVAL_SECONDS:
            return self.value
        with self.lock:
            path = _data_file(self.name)
            try:
                stat = path.stat()
                signature = (str(path), stat.st_mtime_ns, stat.st_size)
            except OSError:
                signature = (str(path), None, None)
            if self.value is None or signature != self.signature:
                self.value, self.status = self._load(path, signature)
                self.signature = signature
            self.checked = now
            return self.value

    def _load(self, path: Path, signature: tuple):
        status = {"path": str(path), "loaded_at": time.time(), "records": 0, "rejected": 0, "metadata": {}}
        if signature[1] is None:
            return self.empty, {**status, "state": "MISSING"}
        try:
            catalog = self.loader(path.read_bytes(), strict=False)
        except (OSError, ValueError, TypeError, UnicodeDecodeError, EOFError, gzip.BadGzipFile) as exc:
            # An installed but unusable catalog must be visible, never an
            # apparently successful empty intelligence set.
            _logger.error("%s intelligence catalog %s could not be loaded: %s", self.name, path, exc)
            return self.empty, {**status, "state": "INVALID", "error": str(exc)[:300]}
        if getattr(catalog, "rejected", 0):
            _logger.warning("%s intelligence catalog %s: %s malformed records skipped",
                            self.name, path, catalog.rejected)
        return catalog, {**status, "state": "LOADED", "records": catalog.records,
                         "rejected": getattr(catalog, "rejected", 0), "metadata": dict(catalog.metadata)}

    def cache_clear(self):
        with self.lock:
            self.value, self.signature, self.checked, self.status = None, None, 0.0, {}


_EMPTY_EPSS = EpssCatalog(MappingProxyType({}), MappingProxyType({}), MappingProxyType({}), 0, 0)
_EMPTY_KEV = KevCatalog(frozenset(), MappingProxyType({}), 0)
_epss = _Cached("epss.csv", parse_epss, _EMPTY_EPSS)
_kev = _Cached("kev.json", parse_kev, _EMPTY_KEV)


def kev_cves() -> frozenset[str]:
    return _kev.get().cves


def epss_scores() -> Mapping[str, float]:
    return _epss.get().scores


def epss_percentiles() -> Mapping[str, float]:
    return _epss.get().percentiles


kev_cves.cache_clear = _kev.cache_clear
epss_scores.cache_clear = _epss.cache_clear


def intelligence_status() -> dict[str, dict]:
    """Loaded-catalog state for administrators; never reports an empty load as success."""
    _kev.get(), _epss.get()
    return {"kev": dict(_kev.status), "epss": dict(_epss.status)}


def risk_metadata(cve: str) -> tuple[bool, float | None]:
    key = cve.upper()
    return key in kev_cves(), epss_scores().get(key)


_catalog_snapshot = None
_catalog_token = None


def risk_catalog_token():
    """Stable content token, computed once per immutable catalog snapshot."""
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
