"""Read-only access to retained scan evidence for page and API reads.

``Execution.raw_payload`` is a mutation-tracked JSON column.  Loading it through
the ORM wraps every nested value in tracking containers (megabytes of JSON become
large object graphs) and any in-place edit dirties the session, so a later flush
would rewrite the evidence.  Read paths therefore select the column directly,
which returns plain, untracked Python structures that callers may freely
transform without affecting persisted evidence.

Execution selection uses the durable ``ExecutionSummary`` metadata (version,
architecture and Helm-source presence) instead of parsing every retained payload.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from types import SimpleNamespace

from sqlalchemy import select

from .models import Execution, ServiceArtifact, ServiceArtifactRevision


def execution_payload(db, execution_id) -> dict:
    """Plain, untracked copy of one execution's evidence ({} when absent)."""
    if execution_id is None:
        return {}
    value = db.execute(select(Execution.raw_payload).where(Execution.id == execution_id)).scalar_one_or_none()
    return value if isinstance(value, dict) else {}


_COLUMNS = (Execution.id, Execution.execution_key, Execution.service_id, Execution.service_version_id,
            Execution.scanned_at, Execution.complete, Execution.scan_scope, Execution.payload_digest)


def execution_metadata(db, service_id, *, execution_ids=None) -> list[SimpleNamespace]:
    """Scalar execution rows with summary metadata, newest first (scanned_at, id).

    Current summaries supply the architecture flags.  Executions whose summary
    is missing or outdated (before the startup backfill finishes) are classified
    with the equivalent JSON predicates in SQL, so no retained payload is read;
    their remaining metadata is resolved on demand by ``architecture_metadata``.
    """
    from sqlalchemy import and_, or_
    from .artifact_tab_queries import helm_original_expression
    from .execution_summaries import SUMMARY_VERSION
    from .models import ExecutionSummary
    from .overview_queries import ArchitectureValueTruth
    from .sql_sets import member_of
    fresh = and_(ExecutionSummary.execution_id.is_not(None), Execution.payload_digest.is_not(None),
                 ExecutionSummary.payload_digest == Execution.payload_digest,
                 ExecutionSummary.summary_version == SUMMARY_VERSION,
                 ExecutionSummary.source_complete == Execution.complete)
    statement = select(*_COLUMNS, fresh.label("fresh"), ExecutionSummary.data["architecture"].label("architecture")).outerjoin(
        ExecutionSummary, ExecutionSummary.execution_id == Execution.id).where(Execution.service_id == service_id)
    if execution_ids is not None:
        statement = statement.where(member_of(Execution.id, execution_ids, numeric=True))
    rows = db.execute(statement.order_by(Execution.scanned_at.desc(), Execution.id.desc())).mappings().all()
    stale = [row["id"] for row in rows if not row["fresh"]]
    flags = {}
    if stale:
        has_architecture = or_(*(ArchitectureValueTruth(Execution.raw_payload, path) for path in
                                 ("service_overview.rendered_resources", "rendered_resources", "helm_source_files")))
        helm_original = helm_original_expression(db.get_bind().dialect.name)
        for row in db.execute(select(Execution.id, has_architecture, helm_original)
                              .where(member_of(Execution.id, stale, numeric=True))):
            flags[row[0]] = {"has_architecture": bool(row[1]), "helm_original": bool(row[2])}
    result = []
    for row in rows:
        values = {key: row[key] for key in row.keys() if key not in {"fresh", "architecture"}}
        if row["fresh"] and isinstance(row["architecture"], dict):
            summary = {"architecture": dict(row["architecture"])}
        else:
            summary = {"architecture": flags.get(row["id"], {}), "stale": True}
        result.append(SimpleNamespace(**values, summary=summary))
    return result


def architecture_metadata(db, row) -> dict:
    """Complete architecture metadata for one selected execution row."""
    if row is None:
        return {}
    meta = row.summary.get("architecture") or {}
    if row.summary.get("stale") or "has_resources" not in meta:
        from .execution_summaries import build_summary
        meta = build_summary(execution_payload(db, row.id), row.complete)["architecture"]
    return meta


def _first_matching(rows, predicate):
    # Legacy selection used max(scanned_at) keeping the first (lowest id) of ties.
    candidates = [row for row in rows if predicate(row)]
    if not candidates:
        return None
    newest = max(row.scanned_at for row in candidates)
    return min((row for row in candidates if row.scanned_at == newest), key=lambda row: row.id)


def architecture_execution(rows):
    """Newest execution carrying rendered resources or Helm sources."""
    return _first_matching(rows, lambda row: (row.summary.get("architecture") or {}).get("has_architecture"))


def original_helm_execution(rows):
    """Newest service-scope Helm execution that retained its source files."""
    return _first_matching(rows, lambda row: row.scan_scope == "service"
                           and (row.summary.get("architecture") or {}).get("helm_original"))


def versions(rows) -> list[str]:
    values = [str(row.summary.get("raw_version") or "Unknown") for row in rows]
    return list(dict.fromkeys(values))


def latest_working_revision_id(db, service_id):
    """Identity of the newest edited architecture subject, without its file contents."""
    return db.scalar(
        select(ServiceArtifactRevision.id).join(ServiceArtifact)
        .where(ServiceArtifact.service_id == service_id,
               ServiceArtifact.artifact_type.in_(("helm", "kubernetes")),
               ServiceArtifact.lifecycle_status == "active",
               ServiceArtifactRevision.revision_label == "WORKING")
        .order_by(ServiceArtifactRevision.created_at.desc(), ServiceArtifactRevision.id.desc()).limit(1))


def version_rows(db, service_id) -> list[tuple[int, object]]:
    """``(execution id, raw service version)`` newest first, without reading scan payloads.

    Current summaries carry the version scalar; executions whose summary is
    missing or outdated fall back to extracting the one JSON path in SQL, so the
    result is always identical to reading ``raw_payload["service"]["version"]``.
    """
    from sqlalchemy import and_
    from .execution_summaries import SUMMARY_VERSION
    from .models import ExecutionSummary
    fresh = and_(ExecutionSummary.execution_id.is_not(None), Execution.payload_digest.is_not(None),
                 ExecutionSummary.payload_digest == Execution.payload_digest,
                 ExecutionSummary.summary_version == SUMMARY_VERSION)
    rows = db.execute(select(Execution.id, fresh.label("fresh"), ExecutionSummary.data["raw_version"].label("summary_version"))
        .outerjoin(ExecutionSummary, ExecutionSummary.execution_id == Execution.id)
        .where(Execution.service_id == service_id)
        .order_by(Execution.scanned_at.desc(), Execution.id.desc())).all()
    stale = [row.id for row in rows if not row.fresh]
    fallback = {}
    if stale:
        from .sql_sets import member_of
        fallback = dict(db.execute(select(Execution.id, Execution.raw_payload["service"]["version"])
                                   .where(member_of(Execution.id, stale, numeric=True))).all())
    return [(row.id, fallback.get(row.id) if not row.fresh else row.summary_version) for row in rows]


def version_execution_ids(db, service, version) -> list[int]:
    """Execution ids of one retained version (``exchange.selected_evidence`` coercion)."""
    rows = version_rows(db, service.id)
    available = list(dict.fromkeys(str(value or "Unknown") for _, value in rows)) or [service.manual_version or "Unknown"]
    version = version or available[0]
    if version not in available:
        raise ValueError("Service version not found")
    return [identifier for identifier, value in rows if str(value or "Unknown") == version]


_FINDING_IMAGES_SQLITE = (
    "SELECT json_extract(f.value, '$.image'), json_extract(f.value, '$.image_digest'), "
    "json_extract(f.value, '$.discovered_from') FROM executions AS e, json_each(e.raw_payload, '$.findings') AS f "
    "WHERE e.id = :id AND json_type(e.raw_payload, '$.findings') = 'array' AND f.type = 'object' "
    "ORDER BY f.key")
_FINDING_IMAGES_POSTGRESQL = (
    "SELECT f.value ->> 'image', f.value ->> 'image_digest', f.value ->> 'discovered_from' "
    "FROM executions AS e CROSS JOIN LATERAL json_array_elements(CASE WHEN json_typeof(CAST(e.raw_payload AS json) -> 'findings') = 'array' "
    "THEN CAST(e.raw_payload AS json) -> 'findings' ELSE CAST('[]' AS json) END) WITH ORDINALITY AS f(value, position) "
    "WHERE e.id = :id AND json_typeof(f.value) = 'object' ORDER BY f.position")


def overview_payload(db, execution_id) -> tuple[dict, list[dict]]:
    """The parts of one scan that Service Overview renders, without the full payload.

    Returns a plain payload subset (service overview, skipped evidence and
    whether configuration findings exist) and the per-finding image references
    in payload order.  Large finding and inventory arrays are never transferred.
    """
    from sqlalchemy import text
    from .overview_queries import ArchitectureValueTruth
    if execution_id is None:
        return {}, []
    row = db.execute(select(Execution.raw_payload["service_overview"], Execution.raw_payload["skipped_images"],
                            Execution.raw_payload["skipped_charts"],
                            ArchitectureValueTruth(Execution.raw_payload, "policy_findings"))
                     .where(Execution.id == execution_id)).one_or_none()
    if row is None:
        return {}, []
    payload = {}
    for key, value in zip(("service_overview", "skipped_images", "skipped_charts"), row[:3]):
        if value is not None:
            payload[key] = value
    if row[3]:
        payload["policy_findings"] = True
    statement = finding_images_statement(db.get_bind().dialect.name)
    if statement is None:
        # Unsupported dialect: derive the same rows from the payload in Python.
        full = execution_payload(db, execution_id)
        findings = full.get("findings")
        rows = [(item.get("image"), item.get("image_digest"), item.get("discovered_from"))
                for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []
    else:
        rows = db.execute(text(statement), {"id": execution_id}).all()
    images = [{"image": image, "digest": digest, "discovered_from": discovered or "Submitted"}
              for image, digest, discovered in rows if image]
    return payload, images


def finding_images_statement(dialect_name):
    """Dialect-specific JSON array expansion for per-finding image references.

    Table-valued JSON functions differ between engines, so each supported
    dialect has an explicit statement (both return rows in array order and only
    for object elements; ``findings`` that is not an array yields no rows):

    * SQLite: ``json_each`` over ``$.findings``; ``json_extract`` returns the
      JSON string values as text and JSON null as NULL.
    * PostgreSQL: ``json_array_elements ... WITH ORDINALITY`` with ``->>``,
      which also returns string values as text and JSON null as NULL.

    The ingest schema types ``image``/``image_digest`` as strings, so both match
    the legacy ``item.get(...)`` values.  Other dialects return ``None`` and the
    caller falls back to reading the payload.
    """
    return {"sqlite": _FINDING_IMAGES_SQLITE, "postgresql": _FINDING_IMAGES_POSTGRESQL}.get(dialect_name)


_OVERVIEW_CACHE: "OrderedDict[tuple, tuple]" = OrderedDict()
_OVERVIEW_LOCK = threading.Lock()


def normalized_overview(db, execution) -> tuple[dict, dict]:
    """``(payload subset, normalized overview)`` for one scan, content-keyed.

    The normalized overview is a pure function of the retained evidence and its
    completeness, so it is cached by (execution id, payload digest, complete);
    a new or replaced scan produces a new key.  Callers receive private copies.
    """
    from copy import deepcopy
    from .overview import normalize_overview

    if execution is None:
        return {}, normalize_overview({"source": "Image metadata"}, digest_resolver=None)
    key = (execution.id, execution.payload_digest, bool(execution.complete))
    if execution.payload_digest is None:
        return _build_overview(db, execution.id, execution.complete)
    with _OVERVIEW_LOCK:
        if key in _OVERVIEW_CACHE:
            _OVERVIEW_CACHE.move_to_end(key)
            return deepcopy(_OVERVIEW_CACHE[key])
    value = _stored_overview(db, *key) or _build_overview(db, execution.id, execution.complete)
    with _OVERVIEW_LOCK:
        _OVERVIEW_CACHE[key] = value
        while len(_OVERVIEW_CACHE) > 32:
            _OVERVIEW_CACHE.popitem(last=False)
    return deepcopy(value)


# Version of the stored normalized overview; bump when normalize_overview or
# overview_payload changes what they return, so stored rows are recomputed.
OVERVIEW_ALGORITHM = 1


def _build_overview(db, execution_id, complete) -> tuple[dict, dict]:
    from .overview import normalize_overview
    payload, images = overview_payload(db, execution_id)
    raw = payload.get("service_overview", {})
    # Normalization never edits the retained evidence (plain copy, not tracked).
    raw = dict(raw) if isinstance(raw, dict) else {}
    raw.setdefault("source", "Helm rendered manifests" if payload.get("policy_findings") else "Image metadata")
    return payload, normalize_overview(raw, skipped_images=payload.get("skipped_images", []) or [],
        skipped_charts=payload.get("skipped_charts", []) or [], findings_images=images,
        incomplete=not complete,
        # The persisted scan overview is the source of truth for this
        # page.  Do not run docker manifest inspect while navigating.
        digest_resolver=None)


def _stored_overview(db, execution_id, payload_digest, complete):
    """The stored overview when it was built from exactly this evidence."""
    from .models import ExecutionOverview
    row = db.execute(select(ExecutionOverview.data).where(
        ExecutionOverview.execution_id == execution_id, ExecutionOverview.payload_digest == payload_digest,
        ExecutionOverview.complete.is_(bool(complete)), ExecutionOverview.algorithm == OVERVIEW_ALGORITHM)).scalar_one_or_none()
    if isinstance(row, dict) and isinstance(row.get("payload"), dict) and isinstance(row.get("overview"), dict):
        return row["payload"], row["overview"]
    return None


def store_overview(bind, execution_id) -> bool:
    """Background: build and store one scan's normalized overview.

    Reads the execution's current digest and completeness first and stores
    them with the result, so a concurrent change leaves a row that readers
    reject (they then recompute from the evidence).
    """
    import json
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session
    from .models import ExecutionOverview
    with Session(bind=bind) as db:
        current = db.execute(select(Execution.payload_digest, Execution.complete)
                             .where(Execution.id == execution_id)).one_or_none()
        if current is None or current.payload_digest is None:
            return False
        if _stored_overview(db, execution_id, current.payload_digest, current.complete) is not None:
            return False
        payload, overview = _build_overview(db, execution_id, current.complete)
        # Plain JSON (the same values readers receive), independent of ORM state.
        data = json.loads(json.dumps({"payload": payload, "overview": overview}, default=str))
        row = db.get(ExecutionOverview, execution_id)
        if row is None:
            db.add(ExecutionOverview(execution_id=execution_id, payload_digest=current.payload_digest,
                                     complete=bool(current.complete), algorithm=OVERVIEW_ALGORITHM, data=data))
        else:
            row.payload_digest, row.complete, row.algorithm, row.data = (
                current.payload_digest, bool(current.complete), OVERVIEW_ALGORITHM, data)
        try:
            db.commit()
        except IntegrityError:  # a concurrent writer stored it (or the execution was deleted)
            db.rollback()
            return False
        return True


_overview_executor = None
_overview_lock = threading.Lock()


def schedule_overview(bind, execution_ids) -> None:
    """Prepare stored overviews off the request path (single worker)."""
    global _overview_executor
    from concurrent.futures import ThreadPoolExecutor
    import logging
    ids = [identifier for identifier in dict.fromkeys(execution_ids) if identifier is not None]
    if not ids:
        return None
    with _overview_lock:
        if _overview_executor is None:
            _overview_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cats-overview")

    def run():
        for identifier in ids:
            try:
                store_overview(bind, identifier)
            except Exception:
                logging.getLogger("cats.evidence").exception("Overview preparation failed; readers recompute on demand")
    return _overview_executor.submit(run)


def warm_overviews(bind, limit=500) -> int:
    """Bounded startup preparation for each service's newest scan."""
    from sqlalchemy import func
    from sqlalchemy.orm import Session
    from .models import ExecutionOverview
    with Session(bind=bind) as db:
        ranked = select(Execution.id.label("id"), Execution.payload_digest.label("digest"), Execution.complete.label("complete"),
                        func.row_number().over(partition_by=Execution.service_id,
                                               order_by=(Execution.scanned_at.desc(), Execution.id.desc())).label("rank")).subquery()
        ids = list(db.scalars(select(ranked.c.id).outerjoin(ExecutionOverview, ExecutionOverview.execution_id == ranked.c.id).where(
            ranked.c.rank == 1, ranked.c.digest.is_not(None),
            (ExecutionOverview.execution_id.is_(None)) | (ExecutionOverview.payload_digest != ranked.c.digest)
            | (ExecutionOverview.complete != ranked.c.complete) | (ExecutionOverview.algorithm != OVERVIEW_ALGORITHM))
            .order_by(ranked.c.id).limit(limit)))
    return sum(bool(store_overview(bind, identifier)) for identifier in ids)
