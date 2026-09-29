"""Service-scoped definition previews and retained catalog processing."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import secrets
import threading
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update

from .auth import require_user, record_audit
from .database import SessionLocal, get_db
from .models import BundlePreview, Service, ServiceArtifact, ServiceArtifactRevision, User
from .service_definitions import DefinitionError, parse_definition

router = APIRouter()
_status_lock = threading.RLock()


def _service(db, auth, key, permission):
    service = db.scalar(select(Service).where(Service.service_key == key))
    if service is None:
        raise HTTPException(404)
    if not auth.has(permission, service.id):
        raise HTTPException(403, detail="Service permission required")
    return service


def _page(request, auth, **values):
    from .main import templates, page_context
    return templates.TemplateResponse(request, "service_definitions.html", page_context(auth, **values))


def _list(db, service_id):
    return list(db.scalars(select(ServiceArtifact).where(
        ServiceArtifact.service_id == service_id,
        ServiceArtifact.artifact_type == "service_definition",
    ).order_by(ServiceArtifact.created_at.desc(), ServiceArtifact.id.desc())))


@router.get("/services/{service_key}/definitions")
def definitions_page(service_key: str, request: Request, db=Depends(get_db), auth=Depends(require_user)):
    service = _service(db, auth, service_key, "service.view")
    return _page(request, auth, service=service, definitions=_list(db, service.id))


@router.post("/services/{service_key}/definitions/preview")
def definition_preview(service_key: str, request: Request, upload: UploadFile = File(),
                       adapter: str = Form("auto"), csrf_token: str = Form(),
                       db=Depends(get_db), auth=Depends(require_user)):
    from .main import check_csrf
    check_csrf(auth, csrf_token)
    service = _service(db, auth, service_key, "service.edit")
    filename = (upload.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    if not filename.lower().endswith((".yaml", ".yml")) or not filename or len(filename) > 240:
        raise HTTPException(422, detail="Upload a YAML or YML service definition")
    from .service_definitions import _limit
    limit = _limit("BYTES", 10 * 1024 * 1024)
    raw = upload.file.read(limit + 1)
    if len(raw) > limit:
        raise HTTPException(413, detail="Service definition exceeds byte limit")
    try:
        source = raw.decode("utf-8-sig")
        parsed = parse_definition(source, adapter)
    except UnicodeDecodeError:
        raise HTTPException(422, detail="Service definition must be UTF-8") from None
    except DefinitionError as exc:
        raise HTTPException(422, detail=str(exc)) from None
    token = secrets.token_hex(24)
    db.add(BundlePreview(token=token, user_id=auth.user.id, target_key=service_key,
                         payload={"kind": "service_definition", "filename": filename,
                                  "source": source, "parsed": parsed, "service_id": service.id},
                         expires_at=datetime.now(timezone.utc) + timedelta(minutes=30)))
    record_audit(db, auth, "definition.previewed", "service", service.id,
                 adapter=parsed["adapter"], declared=parsed["counts"]["declared"])
    db.commit()
    return _page(request, auth, service=service, definitions=_list(db, service.id),
                 preview=parsed, preview_token=token, preview_filename=filename)


@router.post("/services/{service_key}/definitions/confirm/{token}")
def definition_confirm(service_key: str, token: str, csrf_token: str = Form(),
                       db=Depends(get_db), auth=Depends(require_user)):
    from .main import check_csrf, PUBLIC_WORKERS
    check_csrf(auth, csrf_token)
    service = _service(db, auth, service_key, "service.edit")
    now = datetime.now(timezone.utc)
    claimed = db.execute(update(BundlePreview).where(
        BundlePreview.token == token, BundlePreview.user_id == auth.user.id,
        BundlePreview.target_key == service_key, BundlePreview.consumed.is_(False),
        BundlePreview.expires_at > now,
    ).values(consumed=True))
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, detail="Definition preview expired or already used")
    preview = db.get(BundlePreview, token)
    payload = preview.payload or {}
    if payload.get("kind") != "service_definition" or payload.get("service_id") != service.id:
        db.rollback()
        raise HTTPException(409, detail="Definition preview does not match this service")
    parsed = parse_definition(payload["source"], payload["parsed"]["adapter"])
    if parsed != payload["parsed"]:
        db.rollback()
        raise HTTPException(409, detail="Definition preview changed")
    artifact = ServiceArtifact(service_id=service.id, artifact_type="service_definition",
        artifact_name=f"definition:{uuid.uuid4().hex[:12]}", source_type="upload",
        source_reference=payload["filename"],
        source_metadata={"adapter": parsed["adapter"], "counts": parsed["counts"],
                         "components": parsed["components"], "run_id": uuid.uuid4().hex})
    db.add(artifact)
    db.flush()
    source = {payload["filename"]: payload["source"]}
    digest = sha256(__import__("json").dumps(source, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    db.add(ServiceArtifactRevision(artifact_id=artifact.id, revision_number=1,
        revision_label="ORIGINAL", files=source, checksum=digest, immutable=True,
        created_by_id=auth.user.id, source_metadata={"adapter": parsed["adapter"]}))
    service.assessment_status = "assessment_pending"
    record_audit(db, auth, "definition.imported", "service_artifact", artifact.id,
                 service_id=service.id, adapter=parsed["adapter"], declared=parsed["counts"]["declared"])
    artifact_id, user_id = artifact.id, auth.user.id
    db.commit()
    PUBLIC_WORKERS.submit(process_definition, artifact_id, user_id)
    return RedirectResponse(f"/services/{service_key}/definitions", status_code=303)


@router.post("/services/{service_key}/definitions/{artifact_id}/reprocess")
def definition_reprocess(service_key: str, artifact_id: int, csrf_token: str = Form(),
                         db=Depends(get_db), auth=Depends(require_user)):
    from .main import check_csrf, PUBLIC_WORKERS
    check_csrf(auth, csrf_token)
    service = _service(db, auth, service_key, "service.edit")
    with _status_lock:
        artifact = db.get(ServiceArtifact, artifact_id)
        if not artifact or artifact.service_id != service.id or artifact.artifact_type != "service_definition":
            raise HTTPException(404)
        if any(c.get("status") in {"queued", "acquiring", "scanning"} for c in (artifact.source_metadata or {}).get("components", [])):
            raise HTTPException(409, detail="Definition is already processing")
        original = artifact.revisions[0].files
        parsed = parse_definition(next(iter(original.values())), (artifact.source_metadata or {}).get("adapter", "auto"))
        meta = dict(artifact.source_metadata or {})
        meta.update(components=parsed["components"], counts=parsed["counts"], run_id=uuid.uuid4().hex)
        artifact.source_metadata = meta
        service.assessment_status = "assessment_pending"
        record_audit(db, auth, "definition.reprocess_requested", "service_artifact", artifact.id,
                     service_id=service.id, revision=artifact.revisions[0].id)
        db.commit()
    PUBLIC_WORKERS.submit(process_definition, artifact_id, auth.user.id)
    return RedirectResponse(f"/services/{service_key}/definitions", status_code=303)


def _status(artifact_id, run_id, index, status, reason=None, **detail):
    with _status_lock, SessionLocal() as db:
        artifact = db.get(ServiceArtifact, artifact_id)
        if artifact is None:
            return
        meta = dict(artifact.source_metadata or {})
        if meta.get("run_id") != run_id:
            return
        components = [dict(item) for item in meta.get("components", [])]
        if index >= len(components):
            return
        if components[index].get("status") in {"complete", "render_failed", "scan_failed"} and status == "scanning":
            components[index].update(**detail)
        else:
            components[index].update(status=status, reason=reason, **detail)
        meta["components"] = components
        artifact.source_metadata = meta
        artifact.updated_at = datetime.now(timezone.utc)
        db.commit()


def complete_scan(job_id, job):
    context = job.get("definition_context") or {}
    if not context:
        return
    status = ("render_failed" if job.get("skipped_charts") else
              "complete" if job.get("status") == "complete" and not job.get("ingest_error") else
              "scan_failed")
    reason = (None if status == "complete" else
              "Chart rendering did not complete" if status == "render_failed" else
              "Scanner or local ingest did not complete")
    _status(context["artifact_id"], context["run_id"], context["index"], status,
            reason, scan_job_id=job_id)


def acquire_component(component, certificates):
    """Resolve one normalized declaration through the shared guarded Helm path."""
    from . import main
    if component["source_type"] == "helm":
        catalog = main._discover_helm_repository(component["repository"], certificates)
        entry = next((item for item in catalog.get("charts", []) if item.get("name") == component["chart_name"]), None)
        version = next((v for v in (entry or {}).get("versions", []) if str(v.get("version")) == component["version"]), None)
        if not version or not version.get("url"):
            raise ValueError("Exact chart version is absent from repository catalog")
        source_url = version["url"]
    else:
        source_url = component["reference"]
    archives = main._download_public_chart(source_url, certificates)
    files, count = main._retained_helm_sources(archives)
    actual_name, actual_version = main._chart_identity(files)
    if count != 1 or actual_version != component["version"] or (
        component["source_type"] == "helm" and actual_name != component["chart_name"]
    ):
        raise ValueError("Retrieved chart identity or exact version did not match the declaration")
    return source_url, files, actual_name, actual_version


def process_definition(artifact_id, user_id):
    """Acquire each declared chart independently; all network I/O uses existing Helm helpers."""
    from . import main
    with SessionLocal() as db:
        artifact = db.get(ServiceArtifact, artifact_id)
        if artifact is None:
            return
        meta = dict(artifact.source_metadata or {})
        run_id = meta.get("run_id")
        components = list(meta.get("components") or [])
        service_key = artifact.service.service_key
        service_id = artifact.service_id
    for index, component in enumerate(components):
        if component.get("status") != "normalized":
            continue
        _status(artifact_id, run_id, index, "acquiring")
        try:
            with SessionLocal() as db:
                configuration = main.get_global_configuration(db)
                certificates = main.parse_json(configuration.get("trusted_ca_certificates"), [])
                certificates = certificates if isinstance(certificates, list) else []
            source_url, files, actual_name, actual_version = acquire_component(component, certificates)
            with SessionLocal() as db:
                definition = db.get(ServiceArtifact, artifact_id)
                if (definition.source_metadata or {}).get("run_id") != run_id:
                    return
                service = db.get(Service, service_id)
                chart = ServiceArtifact(service_id=service_id, artifact_type="helm_chart",
                    artifact_name=f"definition-{artifact_id}-{index}-{uuid.uuid4().hex[:8]}",
                    source_type="repository" if component["source_type"] == "helm" else "oci",
                    source_reference=component["reference"], chart_name=actual_name,
                    chart_version=actual_version,
                    source_metadata={"definition_artifact_id": artifact_id,
                        "definition_revision": definition.revisions[0].revision_number,
                        "component_index": index, "logical_name": component["logical_name"],
                        "declared_chart_name": component["chart_name"],
                        "declared_version": component["version"]})
                db.add(chart); db.flush()
                db.add(main._artifact_revision(files, artifact_id=chart.id, number=1,
                    label="ORIGINAL", user_id=user_id, source_metadata=chart.source_metadata))
                user = db.get(User, user_id)
                if user:
                    class _AuditAuth:
                        def __init__(self, user): self.user = user
                    record_audit(db, _AuditAuth(user), "definition.chart_acquired", "service_artifact", chart.id,
                                 service_id=service.id, definition_id=artifact_id,
                                 component_index=index, chart_version=actual_version)
                chart_id = chart.id
                db.commit()
            _status(artifact_id, run_id, index, "scanning", chart_artifact_id=chart_id)
            scan_archives = main._download_public_chart(source_url, certificates)
            job_id = main._start_public_scan("", chart_archives=scan_archives,
                ingest_service_id=service_key, trusted_ca_certificates=certificates,
                definition_context={"artifact_id": artifact_id, "run_id": run_id,
                                    "index": index, "chart_artifact_id": chart_id})
            _status(artifact_id, run_id, index, "scanning", chart_artifact_id=chart_id, scan_job_id=job_id)
        except Exception as exc:
            # Source URL, worker command and private credentials are never copied into UI or audit.
            category = "acquisition_failed" if not isinstance(exc, HTTPException) else "acquisition_failed"
            reason = str(exc) if isinstance(exc, ValueError) and str(exc).startswith(("Exact chart", "Retrieved chart")) else type(exc).__name__
            _status(artifact_id, run_id, index, category, reason)
