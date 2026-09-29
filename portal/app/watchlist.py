"""Precise, provider-neutral matching of configured dependencies to Syft SBOMs."""

from __future__ import annotations

import csv
import io
import re

import yaml


MAX_ENTRIES = 2000
MAX_COMPONENTS = 50000
_VERSION = re.compile(r"^(==|>=|<=|>|<)?\s*([0-9]+(?:\.[0-9A-Za-z_-]+)*)$")


def normalized(value: str) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "").strip().lower())


def parse_entries(data: str, format_name: str) -> list[dict]:
    if len(data.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Watchlist import exceeds 1 MiB")
    if format_name == "txt":
        rows = [{"purl": line.strip()} if line.strip().startswith("pkg:") else {"name": line.strip()}
                for line in data.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    elif format_name == "csv":
        rows = list(csv.DictReader(io.StringIO(data)))
    elif format_name in {"yaml", "yml"}:
        parsed = yaml.safe_load(data)
        rows = parsed.get("entries") if isinstance(parsed, dict) else parsed
        if not isinstance(rows, list):
            raise ValueError("YAML must contain an entries list")
    else:
        raise ValueError("Supported watchlist formats are txt, csv, and yaml")
    if len(rows) > MAX_ENTRIES:
        raise ValueError("Too many watchlist entries")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Every watchlist entry must be a mapping")
        entry = {key: str(row.get(key) or "").strip() for key in ("purl", "ecosystem", "name", "version_constraint")}
        if not entry["purl"] and not entry["name"]:
            raise ValueError("A watchlist entry needs a PURL or component name")
        if entry["purl"] and not entry["purl"].startswith("pkg:"):
            raise ValueError("PURL must begin with pkg:")
        if entry["version_constraint"] and not _VERSION.fullmatch(entry["version_constraint"]):
            raise ValueError("Version constraint must use a numeric dotted version and optional comparison operator")
        result.append(entry)
    return result


def _version_parts(value: str):
    parts = re.split(r"[.+_-]", value)
    return tuple(int(part) if part.isdigit() else part.lower() for part in parts)


def version_matches(version: str, constraint: str) -> bool:
    if not constraint:
        return True
    match = _VERSION.fullmatch(constraint)
    if not match or not version:
        return False
    operator, expected = match.groups()
    operator = operator or "=="
    actual_parts, expected_parts = _version_parts(version), _version_parts(expected)
    if any(not isinstance(part, int) for part in actual_parts + expected_parts):
        return operator == "==" and normalized(version) == normalized(expected)
    size = max(len(actual_parts), len(expected_parts))
    actual = actual_parts + (0,) * (size - len(actual_parts))
    target = expected_parts + (0,) * (size - len(expected_parts))
    return {"==": actual == target, ">=": actual >= target, "<=": actual <= target,
            ">": actual > target, "<": actual < target}[operator]


def component_matches(entry: dict, component: dict) -> bool:
    purl = str(component.get("purl") or "").split("?", 1)[0]
    wanted_purl = str(entry.get("purl") or "").split("?", 1)[0]
    if wanted_purl:
        if "@" in wanted_purl:
            if purl != wanted_purl:
                return False
        elif purl.split("@", 1)[0] != wanted_purl:
            return False
    else:
        if normalized(component.get("name")) != normalized(entry.get("name")):
            return False
        if entry.get("ecosystem") and normalized(component.get("ecosystem")) != normalized(entry["ecosystem"]):
            return False
    return version_matches(str(component.get("version") or ""), str(entry.get("version_constraint") or ""))


def syft_components(sbom: dict, image: str) -> list[dict]:
    result = []
    artifacts = sbom.get("artifacts") if isinstance(sbom, dict) else []
    if not isinstance(artifacts, list) or len(artifacts) > MAX_COMPONENTS:
        raise ValueError("Syft artifact inventory is invalid or too large")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        purls = artifact.get("purl") or artifact.get("purls") or ""
        if isinstance(purls, list):
            purls = purls[0] if purls else ""
        result.append({"name": str(artifact.get("name") or "")[:300],
                       "version": str(artifact.get("version") or "")[:200],
                       "ecosystem": str(artifact.get("type") or "")[:80],
                       "purl": str(purls)[:700], "image": image[:1000]})
    return result


def reconcile_matches(db, execution) -> int:
    """Rebuild warning evidence for one immutable scan; never create findings."""
    from sqlalchemy import delete, select
    from .models import DependencyWatchlistEntry, DependencyWatchlistMatch

    db.execute(delete(DependencyWatchlistMatch).where(DependencyWatchlistMatch.execution_id == execution.id))
    entries = db.scalars(select(DependencyWatchlistEntry).where(DependencyWatchlistEntry.enabled.is_(True))).all()
    components = (execution.raw_payload or {}).get("sbom_components") or []
    seen = set()
    count = 0
    for component in components:
        if not isinstance(component, dict):
            continue
        for entry in entries:
            if not component_matches(entry.__dict__, component):
                continue
            identity = (entry.id, component.get("purl"), component.get("name"), component.get("version"), component.get("image"))
            if identity in seen:
                continue
            seen.add(identity)
            db.add(DependencyWatchlistMatch(entry_id=entry.id, execution_id=execution.id,
                service_id=execution.service_id, component_name=component.get("name") or "",
                component_version=component.get("version") or "", component_purl=component.get("purl") or "",
                ecosystem=component.get("ecosystem") or "", image=component.get("image") or ""))
            count += 1
    return count
