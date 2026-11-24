"""Precise, provider-neutral matching of configured dependencies to Syft SBOMs."""

from __future__ import annotations

import csv
import io
import re
from collections import defaultdict
from itertools import chain

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


def index_entries(entries):
    """Group rules by their required identity before traversing any SBOMs."""
    by_purl = defaultdict(list)
    by_name = defaultdict(list)
    for entry in entries:
        purl = (entry.purl or "").partition("?")[0]
        if purl:
            by_purl[purl].append(entry)
        else:
            by_name[normalized(entry.name)].append(entry)
    return by_purl, by_name


def match_rows(components, indexed_entries, execution_id, service_id):
    by_purl, by_name = indexed_entries
    rows = {}
    if not (by_purl or by_name):
        return rows
    for component in components or ():
        if not isinstance(component, dict):
            continue
        full_purl = component.get("purl") or ""
        purl = full_purl.partition("?")[0]
        base_purl, separator, _ = purl.partition("@")
        name = component.get("name") or ""
        version = component.get("version") or ""
        image = component.get("image") or ""
        ecosystem = component.get("ecosystem") or ""
        candidates = chain(by_name.get(normalized(name), ()), by_purl.get(purl, ()),
                           by_purl.get(base_purl, ()) if separator else ())
        for entry in candidates:
            # Keep the canonical predicate, including the PURL and ecosystem
            # precedence used by existing rules and imported SBOMs.
            if not component_matches(entry.__dict__, component):
                continue
            identity = (entry.id, full_purl, name, version, image)
            if identity not in rows:
                rows[identity] = dict(entry_id=entry.id, execution_id=execution_id, service_id=service_id,
                                      component_purl=full_purl, component_name=name, component_version=version,
                                      image=image, ecosystem=ecosystem)
    return rows


def publish_matches(db, execution_id, service_id, rows):
    """Commit match changes and their two cache invalidations in the caller's transaction."""
    from sqlalchemy import bindparam, delete, insert, select, update
    from .models import DependencyProjection, DependencyWatchlistMatch as Match
    from .service_posture import invalidate_services

    existing = db.execute(select(Match.id, Match.entry_id, Match.component_purl, Match.component_name,
                                 Match.component_version, Match.image, Match.ecosystem)
                          .where(Match.execution_id == execution_id, Match.service_id == service_id))
    retained = set()
    removed = []
    changed = []
    for match in existing:
        key = (match.entry_id, match.component_purl, match.component_name, match.component_version, match.image)
        if key not in rows:
            removed.append(match.id)
        else:
            retained.add(key)
            if match.ecosystem != rows[key]["ecosystem"]:
                changed.append({"match_id": match.id, "new_ecosystem": rows[key]["ecosystem"]})
    added = [row for key, row in rows.items() if key not in retained]
    if not (added or removed or changed):
        return len(rows)

    # The general ORM bulk-write hooks conservatively invalidate *all* dependency
    # projections. Here every row belongs to one known execution and service.
    connection = db.connection()
    table = Match.__table__
    for i in range(0, len(removed), 500):
        connection.execute(delete(table).where(table.c.id.in_(removed[i:i+500])))
    for i in range(0, len(changed), 500):
        connection.execute(update(table).where(table.c.id == bindparam("match_id"))
                           .values(ecosystem=bindparam("new_ecosystem")), changed[i:i+500])
    for i in range(0, len(added), 500):
        connection.execute(insert(table), added[i:i+500])
    connection.execute(delete(DependencyProjection.__table__).where(DependencyProjection.execution_id == execution_id))
    invalidate_services(connection, [service_id])
    return len(rows)


def reconcile_matches(db, execution, *, entries=None) -> int:
    """Reconcile warning evidence for one immutable scan in the caller's transaction."""
    from sqlalchemy import select
    from .models import DependencyWatchlistEntry
    from .settings_worker import editable_watchlist_entry

    if entries is None:
        entries = db.scalars(select(DependencyWatchlistEntry).where(
            DependencyWatchlistEntry.enabled.is_(True), editable_watchlist_entry()))
    rows = match_rows((execution.raw_payload or {}).get("sbom_components"), index_entries(entries),
                      execution.id, execution.service_id)
    return publish_matches(db, execution.id, execution.service_id, rows)
