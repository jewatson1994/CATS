"""Scoped catalog views and explicitly proposed recommendation selections."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Form, File, UploadFile
from sqlalchemy import func, or_, select
from .auth import require_user, record_audit
from .database import get_db
from .models import Service
from .service_oci import _csrf
from .artifact_catalog import (GlobalArtifact, ServiceArtifactAssignment,
    ArtifactRecommendation, artifact_eligibility, has_current_source_image)

from .artifact_evidence_summary import vulnerability_evidence

router = APIRouter()


def _service(db, auth, key):
    service = db.scalar(select(Service).where(Service.service_key == key))
    if service is None or not auth.has("service.view", service.id):
        raise HTTPException(404, "Service unavailable")
    return service


def _can_propose(auth, service):
    return service.lifecycle_status == "active" and auth.has("service.edit", service.id) and auth.has("approval.request", service.id)


def _artifact(row):
    return {key: getattr(row, key) for key in ("id", "digest", "media_type", "platform")}


@router.get("/artifact-catalog")
def catalog_page(request: Request, db=Depends(get_db), auth=Depends(require_user)):
    from .main import templates, page_context
    return templates.TemplateResponse(request, "artifact_catalog.html", page_context(auth))


@router.get("/services/{service_key}/artifact-recommendations")
def recommendations_page(service_key: str, request: Request, db=Depends(get_db), auth=Depends(require_user)):
    from .main import templates, page_context
    service = _service(db, auth, service_key)
    return templates.TemplateResponse(request, "artifact_recommendations.html", page_context(auth, service=service))


@router.get("/api/artifact-catalog")
def catalog(db=Depends(get_db), auth=Depends(require_user), search: str = Query("", max_length=200), page: int = Query(1, ge=1)):
    allowed = auth.accessible_service_ids("service.view")
    assignment = select(ServiceArtifactAssignment.artifact_id)
    if allowed is not None:
        assignment = assignment.where(ServiceArtifactAssignment.service_id.in_(allowed))
    query = select(GlobalArtifact).where(GlobalArtifact.id.in_(assignment))
    if search.strip():
        term = "%" + search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.where(or_(*(column.ilike(term, escape="\\") for column in (GlobalArtifact.digest, GlobalArtifact.media_type, GlobalArtifact.platform))))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(GlobalArtifact.id.desc()).offset((page - 1) * 25).limit(25)).all()
    result = []
    for row in rows:
        services = select(Service).join(ServiceArtifactAssignment, ServiceArtifactAssignment.service_id == Service.id).where(ServiceArtifactAssignment.artifact_id == row.id)
        if allowed is not None:
            services = services.where(Service.id.in_(allowed))
        visible = db.scalars(services.distinct()).all()
        # Only expose eligibility tied to a service this reader can inspect.
        checks = [artifact_eligibility(db, row.id, service_id=item.id) for item in visible]
        eligibility = next((item for item in checks if item["eligible"]), checks[0] if checks else {"eligible": False, "reasons": ["No accessible service evidence"]})
        result.append({**_artifact(row), "eligibility": eligibility,
            "services": [{"service_key": item.service_key, "name": item.name} for item in visible]})
    return {"items": result, "total": total, "page": page, "page_size": 25}


@router.get("/api/services/{service_key}/artifact-recommendations")
def recommendations(service_key: str, db=Depends(get_db), auth=Depends(require_user)):
    service = _service(db, auth, service_key)
    rows = db.scalars(select(ArtifactRecommendation).where(ArtifactRecommendation.service_id == service.id).order_by(ArtifactRecommendation.id.desc())).all()
    from .release_revisions import ReleaseAmendmentProposal
    proposals = {p.recommendation_id: p.id for p in db.scalars(select(ReleaseAmendmentProposal).where(ReleaseAmendmentProposal.service_id == service.id))}
    items = []
    for row in rows:
        source, target = db.get(GlobalArtifact, row.source_artifact_id), db.get(GlobalArtifact, row.target_artifact_id)
        items.append({"id": row.id, "status": row.status, "amendment_proposal_id": proposals.get(row.id), "source_artifact": _artifact(source),
            "target_artifact": _artifact(target), "vulnerability_evidence": vulnerability_evidence(db, source_id=source.id, target_id=target.id), "eligibility": artifact_eligibility(db, target.id, service_id=service.id),
            "can_adopt": _can_propose(auth, service) and row.status == "pending_verification" and has_current_source_image(db, service_id=service.id, artifact_id=source.id, target_artifact_id=target.id)})
    return {"items": items, "can_adopt": _can_propose(auth, service)}


@router.post("/api/services/{service_key}/artifact-recommendations/{recommendation_id}/adopt")
async def propose_selection(service_key: str, recommendation_id: int, request: Request, db=Depends(get_db), auth=Depends(require_user)):
    _csrf(request, auth)
    service = _service(db, auth, service_key)
    if not _can_propose(auth, service):
        raise HTTPException(403, "Service edit and approval request permissions required")
    row = db.scalar(select(ArtifactRecommendation).where(ArtifactRecommendation.id == recommendation_id,
        ArtifactRecommendation.service_id == service.id).with_for_update())
    if row is None:
        raise HTTPException(404, "Recommendation unavailable")
    if row.status not in {"pending_verification", "proposed"}:
        raise HTTPException(409, "Recommendation is no longer available for proposal")
    if not has_current_source_image(db, service_id=service.id, artifact_id=row.source_artifact_id, target_artifact_id=row.target_artifact_id):
        raise HTTPException(409, "The original artifact is no longer in this service inventory")
    from .release_revisions import propose_recommendation
    try:
        proposal = propose_recommendation(db, auth, row)
    except (ValueError, PermissionError) as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from None
    if row.status != "proposed":
        row.status = "proposed"
        record_audit(db, auth, "artifact.recommendation.proposed", "artifact_recommendation", row.id,
            service_id=service.id, source_artifact_id=row.source_artifact_id, target_artifact_id=row.target_artifact_id)
    from .proposal_scans import enqueue
    assessment_job = enqueue(db, proposal, auth.user.id) if proposal else None
    db.commit()
    return {"assessment_job_id": assessment_job.id if assessment_job else None, "amendment_proposal_id": proposal.id if proposal else None, "proposal": proposal.intent if proposal else None, "id": row.id, "status": "proposed", "active_release_changed": False,
        "message": "Selection proposed and isolated assessment queued. Complete service validation and Cyber approval before activating a release revision."}


@router.post("/api/services/{service_key}/artifact-recommendations/{recommendation_id}/decision")
async def recommendation_decision(service_key: str, recommendation_id: int, request: Request, db=Depends(get_db), auth=Depends(require_user)):
    _csrf(request, auth)
    service = _service(db, auth, service_key)
    if not _can_propose(auth, service):
        raise HTTPException(403, "Service edit and approval request permissions required")
    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(422, "A JSON decision object is required") from None
    if not isinstance(payload, dict):
        raise HTTPException(422, "A JSON decision object is required")
    action = payload.get("action")
    reason = str(payload.get("reason") or "").strip()
    if action not in {"defer", "dismiss", "reopen"} or len(reason) > 2000 or (action == "dismiss" and not reason):
        raise HTTPException(422, "Choose defer, dismiss, or reopen; dismissal requires a reason (maximum 2000 characters)")
    row = db.scalar(select(ArtifactRecommendation).where(ArtifactRecommendation.id == recommendation_id,
        ArtifactRecommendation.service_id == service.id).with_for_update())
    if row is None:
        raise HTTPException(404, "Recommendation unavailable")
    if row.status == "proposed":
        raise HTTPException(409, "This recommendation already has an adoption proposal; use Cyber review")
    row.status = {"defer": "deferred", "dismiss": "dismissed", "reopen": "pending_verification"}[action]
    record_audit(db, auth, "artifact.recommendation." + action, "artifact_recommendation", row.id,
                 service_id=service.id, reason=reason)
    db.commit()
    return {"id": row.id, "status": row.status, "active_release_changed": False}


def replacement_notifications(db, auth):
    """Use the existing bell; scope every recommendation to a service manager."""
    allowed = auth.accessible_service_ids("service.view")
    query = select(ArtifactRecommendation, Service).join(Service, Service.id == ArtifactRecommendation.service_id).where(
        ArtifactRecommendation.status == "pending_verification", Service.lifecycle_status == "active")
    if allowed is not None:
        query = query.where(Service.id.in_(allowed))
    result = []
    for row, service in db.execute(query.order_by(ArtifactRecommendation.id.desc()).limit(100)):
        if _can_propose(auth, service) and has_current_source_image(db, service_id=service.id, artifact_id=row.source_artifact_id, target_artifact_id=row.target_artifact_id) and artifact_eligibility(db, row.target_artifact_id)["eligible"]:
            result.append({"label": "Verified replacement available", "service": service.name,
                           "href": f"/services/{service.service_key}/artifact-recommendations"})
    return result


@router.get("/api/services/{service_key}/amendment-proposals/{proposal_id}/readiness")
def proposal_readiness(service_key: str, proposal_id: int, db=Depends(get_db), auth=Depends(require_user)):
    from .release_revisions import amendment_readiness
    service = _service(db, auth, service_key)
    if not _can_propose(auth, service):
        raise HTTPException(403, "Service edit and approval request permissions required")
    try:
        from .proposal_scans import state
        return {**amendment_readiness(db, auth, proposal_id, service.id), **state(db, proposal_id),
            "automatic_assessment_available": True}
    except (ValueError, PermissionError) as exc:
        raise HTTPException(409, str(exc)) from None


@router.post("/api/services/{service_key}/amendment-proposals/{proposal_id}/assessment")
def request_proposal_assessment(service_key: str, proposal_id: int, request: Request,
        db=Depends(get_db), auth=Depends(require_user)):
    _csrf(request, auth)
    service = _service(db, auth, service_key)
    if not _can_propose(auth, service):
        raise HTTPException(403, "Service edit and approval request permissions required")
    from .proposal_assessments import proposal
    from .proposal_scans import enqueue, state
    try:
        row = proposal(db, proposal_id, service.id)
        current = state(db, proposal_id)
        if current['assessment_status'] in {'queued', 'running', 'preparing', 'evidence_ready'}:
            return current
        enqueue(db, row, auth.user.id, fresh=True)
        db.commit()
        return state(db, proposal_id)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from None


@router.post('/api/services/{service_key}/artifacts/{artifact_id}/image-validation')
def image_validation(service_key: str, artifact_id: int, request: Request,
                     version_id: int = Form(),
                     reference: str = Form(),
                     bundle: UploadFile = File(),
                     db=Depends(get_db), auth=Depends(require_user)):
    _csrf(request, auth)
    service = _service(db, auth, service_key)
    if service.lifecycle_status != 'active' or not auth.has('remediation.execute', service.id):
        raise HTTPException(403, 'Active service remediation permission required')
    from .artifact_image_validation import validate_image
    return validate_image(db, auth, service, artifact_id, version_id, reference, bundle)
