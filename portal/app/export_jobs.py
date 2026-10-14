"""Durable export submission and permission-scoped, immutable downloads.

Builders remain shared with release delivery. Only HTTP entry points are queued.
An assessment that advances before a worker starts is rejected, never substituted.
"""
from __future__ import annotations

from functools import wraps
import inspect
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from sqlalchemy import func, select

from .auth import AuthContext, require_user
from .database import get_db
from .models import Execution, Service, ServiceVersion, utcnow

router = APIRouter()
BUILDERS = {}


def output_root():
    return Path(os.getenv("CATS_EXPORT_JOB_ROOT", "/data/export-jobs"))


def snapshots(db, ids):
    """Scalar identities only: submission must never hydrate retained evidence."""
    latest = select(Execution.id).where(Execution.service_id == Service.id).order_by(
        Execution.scanned_at.desc(), Execution.id.desc()).limit(1).correlate(Service).scalar_subquery()
    newest = select(func.max(Execution.id)).where(Execution.service_id == Service.id).correlate(Service).scalar_subquery()
    return [{"service_id": row.id, "service_key": row.service_key,
             "version_id": row.current_version_id, "manual_version": row.manual_version,
             "version": row.version or row.manual_version or "Unknown",
             "execution_id": row.execution_id, "newest_execution_id": row.newest_execution_id}
            for row in db.execute(select(Service.id, Service.service_key, Service.current_version_id,
                Service.manual_version, ServiceVersion.version, latest.label("execution_id"), newest.label("newest_execution_id"))
                .outerjoin(ServiceVersion, ServiceVersion.id == Service.current_version_id)
                .where(Service.id.in_(ids)).order_by(Service.id))]


class ScopedExportAuth:
    """Intersect submission grants with current grants; never broaden queued jobs."""
    def __init__(self, auth, scopes):
        self.auth, self.scopes = auth, scopes
        self.user, self.session = auth.user, auth.session

    def has(self, permission, service_id=None):
        return permission in self.scopes.get(str(service_id), []) and self.auth.has(permission, service_id)

    def accessible_service_ids(self, permission):
        return {int(key) for key in self.scopes if self.has(permission, int(key))}


def assert_access(db, auth, payload):
    # Global role grants do not establish that a retained service still exists.
    # Portfolio jobs have no service FK, so check every frozen scope explicitly.
    ids = {int(key) for key in payload["scopes"]}
    existing = set(db.scalars(select(Service.id).where(Service.id.in_(ids))))
    if existing != ids:
        raise HTTPException(403, "Export access has been revoked; a source service is no longer available")
    for key, permissions in payload["scopes"].items():
        if not all(auth.has(permission, int(key)) for permission in permissions):
            raise HTTPException(403, "Export access has been revoked; request a new export with your current permissions")


def queued_export(name, permission="service.export"):
    """Keep existing builder signatures while turning all HTTP use into jobs."""
    def decorate(builder):
        BUILDERS[name] = builder
        signature = inspect.signature(builder, eval_str=True)

        @wraps(builder)
        def enqueue(*args, **kwargs):
            request = kwargs.pop("_export_request", None)
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            values = dict(bound.arguments)
            db, auth = values.pop("db"), values.pop("auth")
            required = permission
            if name == "exchange":
                from .exchange_routes import template_for
                required = template_for(db, values["template"])["dataset"] + ".export"
            if name == "workbook" and values.get("version"):
                raise HTTPException(422, "This workbook is current-state only. Use version-selected spreadsheet exchange")
            if name == "purpose":
                from .purpose_exports import CATALOG
                if values["kind"] not in CATALOG:
                    raise HTTPException(404)
            service_key = values.get("service_key")
            if service_key:
                service = db.scalar(select(Service).where(Service.service_key == service_key))
                if not service:
                    raise HTTPException(404)
                if not auth.has(required, service.id):
                    raise HTTPException(403, "Permission denied")
                ids = [service.id]
            else:
                allowed = auth.accessible_service_ids(required)
                if allowed == set():
                    raise HTTPException(403, "Permission denied")
                ids = list(db.scalars(select(Service.id))) if allowed is None else sorted(allowed)
            scope = {str(sid): [required] for sid in ids}
            if name == "all":
                for sid in ids:
                    if auth.has("bundle.export", sid):
                        scope[str(sid)].append("bundle.export")
            snapshot = snapshots(db, ids)
            from .durable_jobs import submit
            job = submit(db, kind="export", requested_by_id=auth.user.id,
                service_id=ids[0] if service_key else None,
                source_execution_id=snapshot[0]["execution_id"] if service_key else None,
                version=str(values.get("version") or snapshot[0]["version"]) if service_key else "",
                payload={"builder": name, "arguments": values, "scopes": scope, "snapshot": snapshot},
                max_attempts=3)
            location = f"/jobs?job={job.id}"
            if request is not None and "text/html" in request.headers.get("accept", ""):
                return RedirectResponse(location, status_code=303)
            return JSONResponse({"job_id": job.id, "status": job.status,
                "status_url": f"/api/v1/jobs/{job.id}", "result_url": location}, status_code=202,
                headers={"Location": f"/api/v1/jobs/{job.id}"})

        enqueue.__signature__ = signature.replace(parameters=[*signature.parameters.values(),
            inspect.Parameter("_export_request", inspect.Parameter.KEYWORD_ONLY, annotation=Request)])
        return enqueue
    return decorate


@router.get("/api/v1/exports/{job_id}/download")
def download_export(job_id: str, db=Depends(get_db), auth=Depends(require_user)):
    from .durable_jobs import DurableJob
    job = db.get(DurableJob, job_id)
    if not job or job.kind != "export" or job.requested_by_id != auth.user.id:
        raise HTTPException(404)
    assert_access(db, auth, job.payload)
    result = job.result or {}
    if job.status != "completed":
        raise HTTPException(409, "Export is not complete")
    from .auth import aware
    if not job.completed_at or (utcnow() - aware(job.completed_at)).total_seconds() >= int(os.getenv("CATS_EXPORT_RETENTION_HOURS", "24")) * 3600:
        raise HTTPException(410, "Export expired; request a new export")
    original_root = output_root()
    if any(item.is_symlink() for item in (original_root, *original_root.parents)):
        raise HTTPException(410, "Export file is no longer available")
    root = original_root.resolve()
    path = root / str(job.id) / "output"
    if any(item.is_symlink() for item in (path, *path.parents)) or not path.is_file() or path.resolve().parent.parent != root:
        raise HTTPException(410, "Export file is no longer available")
    if path.stat().st_size != result.get("bytes"):
        raise HTTPException(409, "Export integrity check failed")
    return FileResponse(path, filename=result["filename"], media_type=result["media_type"])
