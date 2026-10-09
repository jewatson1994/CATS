"""Service-scoped definition previews and retained catalog processing."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import secrets
import threading
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update
import yaml

from .auth import require_user, record_audit
from .database import SessionLocal, get_db
from .models import BundlePreview, Service, ServiceArtifact, ServiceArtifactRevision, User
from .oci_diagnostics import OciPullFailure
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
        history = list(meta.get("run_history") or [])
        history.append({"run_id": meta.get("run_id"), "components": meta.get("components", [])})
        meta.update(components=parsed["components"], counts=parsed["counts"],
                    run_id=uuid.uuid4().hex, run_history=history)
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
        if (components[index].get("status") == "scanning" and status == "queued") or (
            components[index].get("status") == "acquisition_failed" and status != "acquisition_failed") or (
            components[index].get("status") in {"complete", "render_failed", "scan_failed"} and status in {"scanning", "queued"}):
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
    """Compatibility adapter to the worker's shared acquisition implementation."""
    from .definition_acquisition import acquire_component as acquire
    return acquire(component, certificates)


def _chart_app_version(files):
    """Retain chart application version separately from the Helm chart version."""
    from .definition_acquisition import _primary_chart_markers
    markers = [(name, files[name]) for name in _primary_chart_markers(files)]
    if len(markers) != 1:
        return None
    try:
        chart = yaml.safe_load(markers[0][1])
    except (yaml.YAMLError, TypeError, UnicodeDecodeError):
        return None
    return str(chart.get("appVersion")) if isinstance(chart, dict) and chart.get("appVersion") is not None else None


def process_definition(artifact_id, user_id):
    """Queue normalized declarations for acquisition by the dedicated worker."""
    from . import main
    with SessionLocal() as db:
        artifact = db.get(ServiceArtifact, artifact_id)
        if artifact is None:
            return
        meta = dict(artifact.source_metadata or {})
        run_id = meta.get("run_id")
        components = list(meta.get("components") or [])
        service_key = artifact.service.service_key
        service_version = ((artifact.service.current_version.version if artifact.service.current_version else None)
                           or artifact.service.manual_version or "")
        configuration = main.get_global_configuration(db)
        certificates = main.parse_json(configuration.get("trusted_ca_certificates"), [])
        certificates = certificates if isinstance(certificates, list) else []
    for index, component in enumerate(components):
        if component.get("status") != "normalized":
            continue
        try:
            job_id = main._start_public_scan("", definition_component=component,
                ingest_service_id=service_key, ingest_service_version=service_version,
                trusted_ca_certificates=certificates, owner_user_id=user_id,
                definition_context={"artifact_id": artifact_id, "run_id": run_id,
                                    "index": index, "user_id": user_id})
            _status(artifact_id, run_id, index, "queued", scan_job_id=job_id)
        except Exception:
            _status(artifact_id, run_id, index, "scan_failed", "Scan could not be queued")


def finalize_definition_result(job_id, job, files, resolution):
    """Persist a verified chart snapshot once, before authoritative local ingest."""
    from . import main
    from .definition_acquisition import _chart_identity
    context = job.get("definition_context") or {}
    if not context:
        return
    actual_name, actual_version = _chart_identity(files)
    with _status_lock, SessionLocal() as db:
        definition = db.get(ServiceArtifact, context["artifact_id"])
        if definition is None or (definition.source_metadata or {}).get("run_id") != context["run_id"]:
            raise ValueError("Definition run no longer matches this scan")
        meta = dict(definition.source_metadata or {})
        components = [dict(item) for item in meta.get("components", [])]
        component = components[context["index"]]
        if (actual_name != component["chart_name"] or actual_version != resolution.get("actual_version") or
                (component["version"] != "latest" and actual_version != component["version"])):
            raise ValueError("Retrieved chart identity or exact version did not match the declaration")
        artifact_name = f"definition-{definition.id}-{context['run_id']}-{context['index']}"
        chart = db.scalar(select(ServiceArtifact).where(
            ServiceArtifact.service_id == definition.service_id,
            ServiceArtifact.artifact_name == artifact_name,
            ServiceArtifact.artifact_type == "helm_chart"))
        app_version = _chart_app_version(files)
        if chart is None:
            chart = ServiceArtifact(service_id=definition.service_id, artifact_type="helm_chart",
                artifact_name=artifact_name,
                source_type="repository" if component["source_type"] == "helm" else "oci",
                source_reference=component["reference"], chart_name=actual_name, chart_version=actual_version,
                source_metadata={"definition_artifact_id": definition.id,
                    "definition_revision": definition.revisions[0].revision_number,
                    "component_index": context["index"], "logical_name": component["logical_name"],
                    "declared_chart_name": component["chart_name"], "declared_version": component["version"],
                    "resolved_version": actual_version, "chart_yaml_version": actual_version,
                    "chart_app_version": app_version, "run_id": context["run_id"]})
            db.add(chart)
            db.flush()
            db.add(main._artifact_revision(files, artifact_id=chart.id, number=1,
                label="ORIGINAL", user_id=context["user_id"], source_metadata=chart.source_metadata))
            user = db.get(User, context["user_id"])
            if user:
                class AuditAuth:
                    def __init__(self, user): self.user = user
                record_audit(db, AuditAuth(user), "definition.chart_acquired", "service_artifact", chart.id,
                    service_id=definition.service_id, definition_id=definition.id,
                    component_index=context["index"], chart_version=actual_version)
        context["chart_artifact_id"] = chart.id
        job["definition_context"] = context
        component.update(status="scanning", reason=None, chart_artifact_id=chart.id, scan_job_id=job_id,
                         resolved_version=actual_version, chart_yaml_version=actual_version,
                         chart_app_version=app_version)
        meta["components"] = components
        definition.source_metadata = meta
        definition.updated_at = datetime.now(timezone.utc)
        db.commit()
