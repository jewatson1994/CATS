"""Bounded Deployment Validation reads for service pages.

Validation runs carry large immutable evidence (observed topology, events,
diagnostics).  Pages need the latest status, one applicable run for
architecture verification, a selected run's evidence, and a paged history list,
so each is fetched with its own bounded query instead of hydrating many full
runs.  Authoritative evidence is never altered; full rows load only on demand.
"""
from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from .models import DeploymentValidationRun, Execution

Run = DeploymentValidationRun
HISTORY_PAGE_SIZE = 50
_HISTORY_COLUMNS = ("id", "run_key", "artifact_type", "artifact_reference", "status", "phase",
                    "completed_at", "started_at", "created_at", "duration_seconds", "cleanup_status", "engine")


def _scoped(service_id, execution_ids=None):
    from .sql_sets import member_of
    statement = select(Run).where(Run.service_id == service_id)
    if execution_ids is not None:
        # A selected release's architecture is bound to its immutable scans.
        statement = statement.where(member_of(Run.execution_id, execution_ids, numeric=True),
                                    Run.artifact_revision_id.is_(None))
    return statement.options(selectinload(Run.execution).defer(Execution.raw_payload))


def latest_run(db, service_id, *, execution_ids=None):
    """Newest run (full evidence) for status, polling and warning decisions."""
    return db.scalar(_scoped(service_id, execution_ids).order_by(Run.created_at.desc(), Run.id.desc()).limit(1))


def run_by_key(db, service_id, run_key):
    return db.scalar(_scoped(service_id).where(Run.run_key == run_key).limit(1))


def applicable_run(db, service_id, *, execution_id=None, artifact_revision_id=None, execution_ids=None):
    """Latest completed VERIFIED/PARTIALLY_VERIFIED run for one architecture subject.

    Mirrors ``architecture_evidence.applicable_validation_run`` in SQL; the
    caller still passes the row through that function, which remains the
    authoritative rule.
    """
    statement = _scoped(service_id, execution_ids).where(
        func.upper(Run.phase) == "COMPLETE", func.upper(Run.status).in_(("VERIFIED", "PARTIALLY_VERIFIED")))
    if artifact_revision_id is not None:
        statement = statement.where(Run.artifact_revision_id == artifact_revision_id)
    elif execution_id is not None:
        statement = statement.where(func.upper(Run.artifact_type) == "ORIGINAL", Run.execution_id == execution_id)
    else:
        return None
    return db.scalar(statement.order_by(Run.completed_at.desc().nulls_last(), Run.id.desc()).limit(1))


def history_page(db, service_id, page=1, page_size=HISTORY_PAGE_SIZE):
    """Paged history rows with display columns only (no evidence payloads)."""
    page_size = max(1, min(int(page_size or HISTORY_PAGE_SIZE), 200))
    total = db.scalar(select(func.count()).select_from(Run).where(Run.service_id == service_id)) or 0
    pages = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(int(page or 1), pages))
    rows = db.execute(select(*(getattr(Run, name) for name in _HISTORY_COLUMNS))
        .where(Run.service_id == service_id).order_by(Run.created_at.desc(), Run.id.desc())
        .offset((page - 1) * page_size).limit(page_size)).mappings().all()
    return [SimpleNamespace(**dict(row)) for row in rows], {"page": page, "pages": pages, "total": total, "page_size": page_size}


def runtime_identity(run):
    """Cache identity of a completed run's evidence as consumed by architecture graphs."""
    if run is None:
        return None
    return (run.id, run.status, run.phase, run.cleanup_status, str(run.completed_at))
