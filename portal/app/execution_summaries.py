"""Versioned, durable summaries of authoritative execution evidence.

Reads select summaries and scalar execution metadata first. Only missing/stale
summaries fetch payloads, in batches of at most PAYLOAD_BATCH_SIZE. Direct SQL
payload writers must clear/update executions.payload_digest in the same write.
"""
from copy import deepcopy
from collections.abc import Sequence
from hashlib import sha256
import json
from weakref import WeakSet

from sqlalchemy import event, inspect, select
from .models import Execution, ExecutionSummary
from .overview import normalize_overview

# v4 adds immutable architecture/Helm-source metadata used to select evidence
# without reparsing every retained payload.
SUMMARY_VERSION = 4
PAYLOAD_BATCH_SIZE = 32
_installed = WeakSet()
_PENDING = "cats_execution_summaries"


class CountOnly(Sequence):
    """Constant-memory equivalent of a list of None for overview count consumers."""
    __slots__ = ("_count",)

    def __init__(self, count):
        self._count = max(0, int(count))

    def __len__(self):
        return self._count

    def __getitem__(self, key):
        if isinstance(key, slice):
            return CountOnly(len(range(self._count)[key]))
        if not -self._count <= key < self._count:
            raise IndexError("count sequence index out of range")
        return None

    def __eq__(self, other):
        if isinstance(other, CountOnly):
            return self._count == other._count
        return isinstance(other, Sequence) and len(other) == self._count and all(item is None for item in other)


def payload_digest(payload):
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")).hexdigest()


def build_summary(payload, complete):
    payload = payload if isinstance(payload, dict) else {}
    levels = ("Critical", "High", "Medium", "Low", "Unknown")
    findings = {}
    for item in payload.get("findings", []):
        cve = str(item.get("cve") or "").strip()
        if not cve:
            continue
        severity = str(item.get("severity") or "Unknown").title()
        severity = severity if severity in levels else "Unknown"
        if cve not in findings or levels.index(severity) < levels.index(findings[cve]):
            findings[cve] = severity
    version = str((payload.get("service") or {}).get("version") or "").strip()
    if not version or version.lower() in {"unknown", "unversioned"}:
        version = "Unversioned"
    skipped_images = payload.get("skipped_images", []) or []
    skipped_charts = payload.get("skipped_charts", []) or []
    missing = normalize_overview(payload.get("service_overview") or {},
        skipped_images=skipped_images, skipped_charts=skipped_charts,
        incomplete=not complete)["missing_evidence"]
    service = payload.get("service")
    overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
    declared = overview.get("rendered_resources") or payload.get("rendered_resources") or []
    helm_sources = payload.get("helm_source_files")
    architecture = {
        # Same truthiness as the legacy per-request payload scans.
        "has_architecture": bool(overview.get("rendered_resources") or payload.get("rendered_resources") or helm_sources),
        "declared_resources": len(declared) if isinstance(declared, (list, tuple, dict, str)) else 0,
        "applicable": bool(helm_sources or declared) and str(payload.get("artifact_type") or "helm").lower() == "helm",
        "helm_original": payload.get("artifact_type") == "helm" and bool(helm_sources),
        "has_resources": architecture_has_resources(payload),
    }
    return {"version": version, "architecture": architecture,
            "raw_version": service.get("version") if isinstance(service, dict) else None,
            "counts": {level: sum(value == level for value in findings.values()) for level in levels},
            "total": len(findings),
            "missing_evidence_count": len(missing),
            "skipped_image_count": len(skipped_images), "skipped_chart_count": len(skipped_charts),
            # Bounded header previews: omit inventory, findings and large
            # overview graphs. Count-only consumers never retrieve this field.
            "header": {"skipped_images": deepcopy(skipped_images[:10]),
                       "skipped_charts": deepcopy(skipped_charts[:10]),
                       "missing_evidence": missing[:10], "missing_evidence_count": len(missing)}}


def _store(db, execution_id, digest, complete, data):
    summary = db.get(ExecutionSummary, execution_id)
    if summary is None:
        summary = ExecutionSummary(execution_id=execution_id)
        db.add(summary)
    summary.payload_digest = digest
    summary.summary_version = SUMMARY_VERSION
    summary.source_complete = bool(complete)
    summary.data = data


def refresh_execution_summary(db, execution):
    """For explicit ingestion/rebuild. Caller owns flush/commit/rollback."""
    if execution.id is None:
        db.flush()
    digest = payload_digest(execution.raw_payload)
    execution.payload_digest = digest
    data = build_summary(execution.raw_payload, execution.complete)
    _store(db, execution.id, digest, execution.complete, data)
    return data


def install_execution_summary_hooks(session_class):
    """Assigned/nested JSON edits refresh atomically; bulk writes clear the digest."""
    if session_class in _installed:
        return
    _installed.add(session_class)

    def before_flush(db, context, instances):
        pending = []
        for execution in list(db.new) + list(db.dirty):
            if not isinstance(execution, Execution):
                continue
            state = inspect(execution)
            if execution not in db.new and not any(state.attrs[key].history.has_changes()
                    for key in ("raw_payload", "complete", "payload_digest")):
                continue
            digest = payload_digest(execution.raw_payload)
            execution.payload_digest = digest
            pending.append((execution, digest, bool(execution.complete),
                            build_summary(execution.raw_payload, execution.complete)))
        if pending:
            db.info[_PENDING] = pending

    def after_flush(db, context):
        for execution, digest, complete, data in db.info.pop(_PENDING, []):
            _store(db, execution.id, digest, complete, data)

    def rollback(db):
        db.info.pop(_PENDING, None)

    def bulk_payload_write(state):
        if not state.is_update:
            return
        table = getattr(state.statement, "table", None)
        if table is None or table.name != Execution.__tablename__:
            return
        parameters = state.parameters or []
        parameters = [parameters] if isinstance(parameters, dict) else parameters
        # SQLAlchemy's public compilation API exposes assignment bind names.
        assigned = state.statement.compile().params
        if {"raw_payload", "complete"}.intersection(assigned) or any(
                {"raw_payload", "complete"}.intersection(item) for item in parameters):
            # Bulk updates bypass flush hooks. Invalidate in that same UPDATE;
            # subsequent summary/projection reads rebuild authoritative evidence.
            state.statement = state.statement.values(payload_digest=None)
            for item in parameters:
                if "payload_digest" in item:
                    item["payload_digest"] = None

    event.listen(session_class, "do_orm_execute", bulk_payload_write)

    event.listen(session_class, "before_flush", before_flush)
    event.listen(session_class, "after_flush_postexec", after_flush)
    event.listen(session_class, "after_rollback", rollback)


def architecture_has_resources(payload) -> bool:
    payload = payload if isinstance(payload, dict) else {}
    overview = payload.get("service_overview") or {}
    overview = overview if isinstance(overview, dict) else {}
    return bool(payload.get("rendered_resources") or payload.get("kubernetes_resources") or payload.get("resources")
                or overview.get("resources") or overview.get("rendered_resources") or overview.get("kubernetes_resources"))


def load_execution_summaries(db, execution_ids, *, include_header=False):
    """Return independent dictionaries. Legacy fallback does not write on reads."""
    ids = list(dict.fromkeys(execution_ids))
    results = {}
    for offset in range(0, len(ids), PAYLOAD_BATCH_SIZE):
        batch = ids[offset:offset + PAYLOAD_BATCH_SIZE]
        rows = db.execute(select(Execution.id, Execution.scanned_at, Execution.complete,
            Execution.payload_digest, ExecutionSummary.payload_digest.label("summary_digest"),
            ExecutionSummary.summary_version, ExecutionSummary.source_complete, ExecutionSummary.data)
            .outerjoin(ExecutionSummary, ExecutionSummary.execution_id == Execution.id)
            .where(Execution.id.in_(batch))).all()
        stale = []
        for row in rows:
            if (row.payload_digest and row.payload_digest == row.summary_digest
                    and row.summary_version == SUMMARY_VERSION
                    and row.source_complete == row.complete and isinstance(row.data, dict)):
                data = deepcopy({key: value for key, value in row.data.items()
                                 if include_header or key != "header"})
                data.update(execution_id=row.id, scanned_at=row.scanned_at.isoformat(), complete=bool(row.complete))
                results[row.id] = data
            else:
                stale.append(row.id)
        if stale:
            for row in db.execute(select(Execution.id, Execution.scanned_at, Execution.complete,
                    Execution.raw_payload).where(Execution.id.in_(stale))):
                data = build_summary(row.raw_payload, row.complete)
                if not include_header:
                    data.pop("header", None)
                data.update(execution_id=row.id, scanned_at=row.scanned_at.isoformat(), complete=bool(row.complete))
                results[row.id] = data
    return results


def snapshot_from_summary(data):
    return {key: deepcopy(data[key]) for key in
            ("execution_id", "version", "scanned_at", "complete", "counts", "total")}


def rebuild_execution_summaries(db, *, after_id=0, limit=PAYLOAD_BATCH_SIZE):
    """Bounded maintenance page; returns last ID and number rebuilt, never commits."""
    if not 1 <= limit <= PAYLOAD_BATCH_SIZE:
        raise ValueError("Summary rebuild limit must be between 1 and 32")
    executions = db.scalars(select(Execution).where(Execution.id > after_id)
                           .order_by(Execution.id).limit(limit)).all()
    for execution in executions:
        refresh_execution_summary(db, execution)
    return (executions[-1].id if executions else after_id), len(executions)


def backfill_stale_summaries(session_factory, *, batch_size=PAYLOAD_BATCH_SIZE, limit=None):
    """Rebuild missing/outdated summaries in bounded, separately committed batches.

    Readers stay correct meanwhile (stale rows fall back to the authoritative
    payload without writing); this only restores the fast path after upgrades.
    Returns the number of executions refreshed.
    """
    from sqlalchemy import or_
    done, after_id = 0, 0
    while limit is None or done < limit:
        with session_factory() as db:
            ids = db.scalars(select(Execution.id).outerjoin(ExecutionSummary, ExecutionSummary.execution_id == Execution.id)
                .where(Execution.id > after_id, or_(ExecutionSummary.execution_id.is_(None),
                       ExecutionSummary.summary_version != SUMMARY_VERSION,
                       Execution.payload_digest.is_(None),
                       ExecutionSummary.payload_digest != Execution.payload_digest,
                       ExecutionSummary.source_complete != Execution.complete))
                .order_by(Execution.id).limit(batch_size)).all()
            if not ids:
                return done
            for execution in db.scalars(select(Execution).where(Execution.id.in_(ids)).order_by(Execution.id)):
                refresh_execution_summary(db, execution)
            db.commit()
            after_id, done = ids[-1], done + len(ids)
    return done
