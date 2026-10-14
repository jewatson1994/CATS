"""A scoped projection over existing work records, not a second source of truth."""
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, defer

from .auth import AuthContext, record_audit, require_user
from .database import get_db
from .durable_jobs import DurableJob, aware, now
from .models import ManagedValidator, RemediationExecution, Service, User, ValidatorProvisioningAttempt
from .scan_coordination import ScanJob

router = APIRouter(tags=["jobs"])


def _permission(kind):
    return "service.export" if kind.startswith("export") or kind == "remediation_deliver" else "remediation.execute"


def authorized(job, auth, db):
    if job.kind.startswith("export"):
        scopes = (job.payload or {}).get("scopes")
        return (job.requested_by_id == auth.user.id and isinstance(scopes, dict)
                and all(db.get(Service, int(sid)) is not None and permissions and all(auth.has(permission, int(sid)) for permission in permissions)
                        for sid, permissions in scopes.items()))
    permission = _permission(job.kind)
    if job.service_id is not None:
        return auth.has(permission, job.service_id) and all(
            auth.has(required, job.service_id) for required in (job.payload or {}).get("required_permissions", []))
    return auth.has(permission)


def _iso(value):
    return aware(value).isoformat() if value else None


def _elapsed(start, end=None):
    return max(0, int(((aware(end) or now()) - aware(start)).total_seconds())) if start else 0


def _person(db, user_id):
    user = db.get(User, user_id) if user_id else None
    return (user.display_name or user.username) if user else "System"


def dto(db, job, auth, list_result=None):
    service = db.get(Service, job.service_id) if job.service_id else None
    stage = job.stage
    if job.status == "running" and job.kind == "remediation_execute":
        phase = db.scalar(select(RemediationExecution.phase).where(
            RemediationExecution.id == (job.payload or {}).get("record_id")))
        if phase:
            stage = phase.replace("_", " ").capitalize()
    # Artifacts, filesystem locations, approved requests and credentials are
    # never part of this generic status API.
    result = {key: value for key, value in (list_result if list_result is not None else job.result or {}).items()
              if key in {"result_url", "download_url", "plan", "preview", "filename", "size_bytes", "sha256"}}
    for key in ("result_url", "download_url"):
        value = result.get(key)
        if value and (not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or "\\" in value):
            result.pop(key, None)
    return {"id": job.id, "job_id": job.id, "kind": job.kind, "status": job.status,
        "stage": stage, "progress": job.progress, "error": job.error,
        "correlation_id": job.correlation_id, "requested_by": _person(db, job.requested_by_id),
        "service": service.name if service else None, "version": job.version,
        "created_at": _iso(job.created_at), "started_at": _iso(job.started_at),
        "completed_at": _iso(job.completed_at), "elapsed_seconds": _elapsed(job.started_at or job.created_at, job.completed_at),
        "attempts": job.attempts, "result": result, "result_url": result.get("result_url"),
        "download_url": result.get("download_url"),
        "can_cancel": job.status == "queued" and (job.kind.startswith("export") or job.kind == "remediation_plan") and authorized(job, auth, db),
        "can_retry": job.status in {"failed", "cancelled"} and (job.kind.startswith("export") or job.kind == "remediation_plan")
                     and job.attempts < job.max_attempts and authorized(job, auth, db)}


def _durable_filter(auth):
    expressions = []
    for prefix, permission in (("remediation", "remediation.execute"),):
        ids = auth.accessible_service_ids(permission)
        scope = DurableJob.service_id.is_not(None) if ids is None else DurableJob.service_id.in_(ids)
        expressions.append(DurableJob.kind.startswith(prefix) & scope & (DurableJob.kind != "remediation_deliver"))
    export_ids = auth.accessible_service_ids("service.export")
    delivery_scope = DurableJob.service_id.is_not(None) if export_ids is None else DurableJob.service_id.in_(export_ids)
    expressions.append((DurableJob.kind == "remediation_deliver") & delivery_scope)
    # Portfolio ownership is only the first filter: authorize its complete
    # frozen service set below before adding the row OR its count.
    expressions.append(DurableJob.kind.startswith("export") & (DurableJob.requested_by_id == auth.user.id))
    return or_(*expressions)


def _scan_filter(db, auth):
    ids = auth.accessible_service_ids("scan.ingest")
    keys = select(Service.service_key)
    if ids is not None:
        keys = keys.where(Service.id.in_(ids))
    return or_(ScanJob.service_key.in_(keys),
        (ScanJob.service_key == "") & (ScanJob.payload["owner_user_id"].as_integer() == auth.user.id))


def scan_dto(db, job):
    payload = job.payload or {}
    status = {"complete": "completed", "incomplete": "completed", "error": "failed"}.get(job.status, job.status)
    if status not in {"completed", "failed", "cancelled", "queued"}:
        status = "running"
    return {"id": "scan:" + job.id, "kind": "scan", "service": job.service_key or "Standalone scan",
        "version": job.service_version, "requested_by": _person(db, payload.get("owner_user_id")),
        "status": status, "stage": str(payload.get("phase") or job.status),
        "created_at": _iso(job.created_at), "elapsed_seconds": _elapsed(job.created_at, job.finished_at),
        "error": "Scan did not finish successfully; open its result for diagnostics." if status == "failed" else None,
        "result_url": f"/api/public/jobs/{job.id}/results/view", "can_cancel": False, "can_retry": False}


def validator_dto(db, attempt):
    validator = db.get(ManagedValidator, attempt.validator_id)
    return {"id": "validator:" + attempt.id, "kind": "validator." + attempt.action,
        "validator": validator.name if validator else "Retired validator", "requested_by": _person(db, attempt.operator_id),
        "status": {"succeeded": "completed", "success": "completed"}.get(attempt.status.lower(), attempt.status.lower()),
        "stage": attempt.stage, "created_at": _iso(attempt.created_at),
        "elapsed_seconds": _elapsed(attempt.started_at or attempt.created_at, attempt.completed_at),
        "error": attempt.failure, "correlation_id": attempt.id,
        "result_url": "/admin/validators", "can_cancel": False, "can_retry": False}


@router.get("/api/v1/jobs")
def jobs(db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    # Limited metadata projections. Never fetch retained assessment payloads.
    recent = []
    counts = {key: 0 for key in ("queued", "running", "completed", "failed", "cancelled")}
    scoped = _durable_filter(auth)
    # Portfolio outputs must be rechecked individually to exclude revoked grants
    # from counts too. Service jobs are counted by SQL without loading payloads.
    for status, count in db.execute(select(DurableJob.status, func.count()).where(scoped,
            ~DurableJob.kind.startswith("export"), DurableJob.kind != "remediation_deliver").group_by(DurableJob.status)):
        counts[status] = counts.get(status, 0) + count
    portfolios = db.scalars(select(DurableJob).options(defer(DurableJob.result)).where(scoped,
        or_(DurableJob.kind.startswith("export"), DurableJob.kind == "remediation_deliver"))
        .order_by(DurableJob.created_at.desc())).all()
    visible = []
    for row in portfolios:
        if authorized(row, auth, db):
            counts[row.status] = counts.get(row.status, 0) + 1
            if len(visible) < 100:
                visible.append(row.id)
    query = select(DurableJob, DurableJob.result["result_url"].as_string(),
        DurableJob.result["download_url"].as_string()).options(defer(DurableJob.result)).where(scoped,
        or_(DurableJob.id.in_(visible), (~DurableJob.kind.startswith("export")) & (DurableJob.kind != "remediation_deliver")))
    for row, result_url, download_url in db.execute(query.order_by(DurableJob.created_at.desc()).limit(100)):
        recent.append(dto(db, row, auth, {"result_url": result_url, "download_url": download_url}))
    scan_scope = _scan_filter(db, auth)
    for status, count in db.execute(select(ScanJob.status, func.count()).where(scan_scope).group_by(ScanJob.status)):
        state = {"complete": "completed", "incomplete": "completed", "error": "failed", "cancelled": "cancelled", "queued": "queued"}.get(status, "running")
        counts[state] += count
    for row in db.scalars(select(ScanJob).where(scan_scope).order_by(ScanJob.created_at.desc()).limit(100)):
        recent.append(scan_dto(db, row))
    if auth.has("validator.view"):
        for status, count in db.execute(select(ValidatorProvisioningAttempt.status, func.count()).group_by(ValidatorProvisioningAttempt.status)):
            state = {"succeeded": "completed", "success": "completed"}.get(status.lower(), status.lower())
            counts[state] = counts.get(state, 0) + count
        for row in db.scalars(select(ValidatorProvisioningAttempt).order_by(ValidatorProvisioningAttempt.created_at.desc()).limit(100)):
            recent.append(validator_dto(db, row))
    recent.sort(key=lambda row: row["created_at"] or "", reverse=True)
    return JSONResponse({"jobs": recent[:100], "counts": counts, "limit": 100}, headers={"Cache-Control": "no-store"})


@router.get("/api/v1/jobs/{job_id}")
def job_detail(job_id: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    if job_id.startswith("scan:"):
        row = db.scalar(select(ScanJob).where(ScanJob.id == job_id[5:], _scan_filter(db, auth)))
        data = scan_dto(db, row) if row else None
    elif job_id.startswith("validator:"):
        row = db.get(ValidatorProvisioningAttempt, job_id[10:]) if auth.has("validator.view") else None
        data = validator_dto(db, row) if row else None
    else:
        row = db.get(DurableJob, job_id)
        data = dto(db, row, auth) if row and authorized(row, auth, db) else None
    if data is None:
        raise HTTPException(404, "Job not found")
    return JSONResponse(data, headers={"Cache-Control": "no-store"})


class JobAction(BaseModel):
    csrf_token: str


@router.post("/api/v1/jobs/{job_id}/{action}")
def job_action(job_id: str, action: str, body: JobAction, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    if not hmac.compare_digest(auth.csrf_token, body.csrf_token):
        raise HTTPException(403, "Invalid CSRF token")
    row = db.scalar(select(DurableJob).where(DurableJob.id == job_id).with_for_update())
    if not row or not authorized(row, auth, db):
        raise HTTPException(404, "Job not found")
    actions = dto(db, row, auth)
    if action == "cancel" and actions["can_cancel"]:
        row.cancel_requested, row.status, row.stage, row.completed_at = True, "cancelled", "Cancelled before execution", now()
    elif action == "retry" and actions["can_retry"]:
        row.status, row.stage, row.error, row.completed_at, row.available_at = "queued", "Queued for retry", None, None, now()
        row.cancel_requested = False
    else:
        raise HTTPException(409, "This job does not support that action in its current state")
    record_audit(db, auth, "job." + action, "job", row.id, kind=row.kind)
    db.commit()
    return dto(db, row, auth)


@router.get("/jobs")
def jobs_page(request: Request, auth: AuthContext = Depends(require_user)):
    from .main import templates, page_context
    return templates.TemplateResponse(request, "jobs.html", page_context(auth))
