"""Lightweight STATUS contracts for active work.

Polling clients ask "is it still running, and did anything change?" many
times; they must not pay for evidence, logs, comparisons or delivery history
to get that answer. Each status read selects scalar columns only (plus the
small stage map for remediation) and returns a ``revision``: a digest of
every field that changes when the corresponding detail view would change.
Clients fetch detail only when the revision changes, and once more at a
terminal state.

Authorization is enforced by the routes (service-scoped ``service.view``),
exactly as for the detail endpoints these contracts summarize.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json

from sqlalchemy import select

from .models import DeploymentValidationRun, RemediationExecution, Service

VALIDATION_CLEANUP_TERMINAL = {"COMPLETE", "FAILED", "NOT_REQUIRED", "NOT_ATTEMPTED", "UNKNOWN"}
REMEDIATION_ACTIVE = {"queued", "running"}
_DETAIL_LIMIT = 240


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def revision(*parts) -> str:
    """Stable short digest; only equality is meaningful to clients."""
    encoded = json.dumps(parts, sort_keys=True, default=_iso, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()[:20]


def _short(value):
    text = "" if value is None else str(value)
    return text if len(text) <= _DETAIL_LIMIT else text[:_DETAIL_LIMIT - 1] + "…"


def validation_revision(run) -> str:
    """Same digest for the detail view and the status contract."""
    return revision(run.status, run.phase, run.cleanup_status, run.reason_category, run.reason,
                    run.started_at, run.completed_at, run.updated_at, run.duration_seconds)


def validation_status(db, service_key: str, run_key: str, terminal_statuses: set[str]) -> dict | None:
    row = db.execute(select(
        DeploymentValidationRun.run_key, DeploymentValidationRun.status, DeploymentValidationRun.phase,
        DeploymentValidationRun.cleanup_status, DeploymentValidationRun.engine, DeploymentValidationRun.artifact_type,
        DeploymentValidationRun.reason_category, DeploymentValidationRun.reason,
        DeploymentValidationRun.created_at, DeploymentValidationRun.started_at,
        DeploymentValidationRun.completed_at, DeploymentValidationRun.updated_at,
        DeploymentValidationRun.duration_seconds,
    ).join(Service, Service.id == DeploymentValidationRun.service_id).where(
        Service.service_key == service_key, DeploymentValidationRun.run_key == run_key)).one_or_none()
    if row is None:
        return None
    status, phase, cleanup = (str(row.status or "").upper(), str(row.phase or "").upper(),
                              str(row.cleanup_status or "").upper())
    cleanup_terminal = cleanup in VALIDATION_CLEANUP_TERMINAL
    terminal = status in terminal_statuses and phase == "COMPLETE" and cleanup_terminal
    return {
        "kind": "deployment_validation", "run_key": row.run_key, "run_id": row.run_key,
        "status": row.status, "phase": row.phase, "cleanup_status": row.cleanup_status,
        "cleanup_terminal": cleanup_terminal, "terminal": terminal,
        "engine": row.engine, "artifact_type": row.artifact_type,
        "reason_category": row.reason_category, "reason": _short(row.reason),
        "created_at": row.created_at, "started_at": row.started_at,
        "completed_at": row.completed_at, "updated_at": row.updated_at,
        "duration_seconds": row.duration_seconds,
        "revision": validation_revision(row),
    }


def remediation_status(db, service_key: str, job_key: str, attempts_model) -> dict | None:
    row = db.execute(select(
        RemediationExecution.id, RemediationExecution.job_key, RemediationExecution.status,
        RemediationExecution.phase, RemediationExecution.stages, RemediationExecution.remediation_status,
        RemediationExecution.delivery_status, RemediationExecution.verification_status,
        RemediationExecution.signing_status, RemediationExecution.artifact_digest,
        RemediationExecution.failure_reason, RemediationExecution.created_at, RemediationExecution.started_at,
        RemediationExecution.completed_at, RemediationExecution.updated_at,
    ).join(Service, Service.id == RemediationExecution.service_id).where(
        Service.service_key == service_key, RemediationExecution.job_key == job_key)).one_or_none()
    if row is None:
        return None
    attempts = [{"id": attempt.id, "status": attempt.status, "started_at": attempt.started_at,
                 "completed_at": attempt.completed_at}
                for attempt in db.execute(select(attempts_model.id, attempts_model.status, attempts_model.started_at,
                                                 attempts_model.completed_at)
                                          .where(attempts_model.remediation_id == row.id)
                                          .order_by(attempts_model.id.desc()).limit(10))]
    stages = {str(name): {"status": (stage or {}).get("status"), "started_at": (stage or {}).get("started_at"),
                          "completed_at": (stage or {}).get("completed_at"), "detail": _short((stage or {}).get("detail"))}
              for name, stage in (row.stages or {}).items() if isinstance(stage, dict) or stage is None}
    active = any(str(value or "").lower() in REMEDIATION_ACTIVE
                 for value in (row.status, row.delivery_status, row.verification_status))
    return {
        "kind": "remediation", "job_key": row.job_key, "status": row.status, "phase": row.phase,
        "remediation_status": row.remediation_status, "delivery_status": row.delivery_status,
        "verification_status": row.verification_status, "signing_status": row.signing_status,
        "artifact_digest": row.artifact_digest, "failure_reason": _short(row.failure_reason),
        "stages": stages, "delivery_attempts": attempts,
        "created_at": row.created_at, "started_at": row.started_at, "completed_at": row.completed_at,
        "updated_at": row.updated_at, "active": active, "terminal": not active,
        "revision": revision(row.status, row.phase, row.remediation_status, row.delivery_status,
                             row.verification_status, row.signing_status, row.artifact_digest,
                             row.failure_reason, row.stages, row.completed_at, row.updated_at, attempts),
    }
