"""Administrative history; access never implies permission to mutate a resource."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .auth import AuthContext, require_user
from .database import get_db
from .diagnostics import public_diagnostic
from .diagnostic_store import DiagnosticEvent, retention_days

router = APIRouter(tags=["diagnostics"])


def may_view_diagnostics(auth):
    # config.manage alone can be scoped. Require both global capabilities.
    return bool(auth and auth.has("audit.view") and auth.has("config.manage"))


def administrator(auth: AuthContext = Depends(require_user)):
    if not may_view_diagnostics(auth):
        raise HTTPException(403, "Administrative diagnostic access is required")
    return auth


def filters(q=None, component=None, service_id=None, job_id=None, severity=None, since=None, until=None, correlation_id=None):
    clauses = [DiagnosticEvent.timestamp >= datetime.now(timezone.utc) - timedelta(days=retention_days())]
    for column, value in ((DiagnosticEvent.component, component), (DiagnosticEvent.service_id, service_id),
                          (DiagnosticEvent.job_id, job_id), (DiagnosticEvent.severity, severity),
                          (DiagnosticEvent.correlation_id, correlation_id)):
        if value is not None and value != "":
            clauses.append(column == value)
    if since:
        clauses.append(DiagnosticEvent.timestamp >= since)
    if until:
        clauses.append(DiagnosticEvent.timestamp <= until)
    if q:
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        clauses.append(or_(*(column.ilike(pattern, escape="\\") for column in
            (DiagnosticEvent.summary, DiagnosticEvent.code, DiagnosticEvent.operation, DiagnosticEvent.correlation_id, DiagnosticEvent.error_id))))
    return clauses


@router.get("/api/diagnostics/summary")
def recurring(db: Session = Depends(get_db), auth=Depends(administrator)):
    count = func.count(DiagnosticEvent.error_id)
    rows = db.execute(select(DiagnosticEvent.code, DiagnosticEvent.component, func.max(DiagnosticEvent.summary),
                             count, func.max(DiagnosticEvent.timestamp)).where(*filters())
        .group_by(DiagnosticEvent.code, DiagnosticEvent.component).order_by(count.desc()).limit(100)).all()
    return {"items": [{"code": code, "component": component, "summary": summary, "count": total,
                       "last_seen": last.replace(tzinfo=timezone.utc).isoformat() if last.tzinfo is None else last.isoformat()}
                      for code, component, summary, total, last in rows],
            "total": db.scalar(select(func.count()).select_from(DiagnosticEvent).where(*filters())) or 0}


@router.get("/api/diagnostics")
def history(q: str | None = Query(None, max_length=200), component: str | None = Query(None, max_length=160),
            service_id: int | None = None, job_id: str | None = Query(None, max_length=128),
            severity: str | None = Query(None, max_length=16), since: datetime | None = None, until: datetime | None = None,
            correlation_id: str | None = Query(None, max_length=64), limit: int = Query(50, ge=1, le=200),
            offset: int = Query(0, ge=0, le=200000), db: Session = Depends(get_db), auth=Depends(administrator)):
    clauses = filters(q, component, service_id, job_id, severity, since, until, correlation_id)
    rows = db.scalars(select(DiagnosticEvent).where(*clauses).order_by(DiagnosticEvent.timestamp.desc(), DiagnosticEvent.error_id.desc()).offset(offset).limit(limit)).all()
    return {"items": [public_diagnostic(row.diagnostic, technical=True) for row in rows],
            "total": db.scalar(select(func.count()).select_from(DiagnosticEvent).where(*clauses)) or 0,
            "retention_days": retention_days()}


@router.get("/api/diagnostics/{error_id}")
def detail(error_id: str, db: Session = Depends(get_db), auth=Depends(administrator)):
    row = db.scalar(select(DiagnosticEvent).where(DiagnosticEvent.error_id == error_id, *filters()))
    if row is None:
        raise HTTPException(404, "Diagnostic event not found or no longer retained")
    return public_diagnostic(row.diagnostic, technical=True)


@router.get("/admin/diagnostics")
def page(request: Request, auth=Depends(administrator)):
    from . import main
    return main.templates.TemplateResponse(request, "diagnostics.html", main.page_context(auth))
