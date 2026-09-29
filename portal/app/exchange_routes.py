"""Scoped, CSRF-protected exchange routes. Previews never change domain data."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
import json
import secrets
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy import select, update, func
from sqlalchemy.exc import IntegrityError

from .auth import require_user, record_audit
from .database import get_db
from .models import Service, Execution, ExportTemplate, ServiceMetadata, InventoryRecord, ExchangePreview, BundlePreview, PoamEntry, PoamHistory, ServiceTransferProvenance
from .exchange import META, FIELDS, builtins, validate_template, versions, selected_evidence, context_and_rows, missing_fields, workbook, parse_workbook
from .exchange_ui import metadata_groups, export_preview

router = APIRouter()


@router.get("/services/{service_key}/bundle.zip")
def bundle_export(service_key: str, db=Depends(get_db), auth=Depends(require_user)):
    from .service_transfer import export_service
    service = service_for(db, auth, service_key, "bundle.export")
    execution_count = db.scalar(select(func.count()).select_from(Execution).where(Execution.service_id == service.id))
    try:
        data = export_service(db, service, auth.user.username)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    record_audit(db, auth, "bundle.export", "service", service.id, executions=execution_count, format="service-input-v3")
    db.commit()
    return StreamingResponse(BytesIO(data), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="cats-service.zip"'})


@router.get("/exchange/bundles")
def bundle_page(request: Request, db=Depends(get_db), auth=Depends(require_user)):
    return page(request, auth, bundle_mode=True)


@router.post("/exchange/bundles/preview")
def bundle_preview(request: Request, target_key: str = Form(), csrf_token: str = Form(), mode: str = Form("create"), upload: UploadFile = File(), db=Depends(get_db), auth=Depends(require_user)):
    from .service_bundle import parse_bundle
    from .service_transfer import parse_service, plan_history
    from .exchange_limits import bundle_bytes
    from .schemas import ServicePayload
    csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == target_key))
    if not auth.has("bundle.import", service.id if service else None):
        raise HTTPException(403)
    if mode not in {"create", "add_history", "replace_metadata"}:
        raise HTTPException(422, detail="Choose a supported conflict strategy")
    if (mode == "create") == bool(service):
        raise HTTPException(409, detail="Create requires a new key; history/metadata strategies require an existing target")
    if mode == "replace_metadata" and not auth.has("metadata.edit", service.id):
        raise HTTPException(403)
    try:
        data = upload.file.read(bundle_bytes() + 1)
        try:
            manifest, state = parse_service(data)
            payload = {"state": state}
            source_name = state["records"]["services"][0]["name"]
        except ValueError as full_error:
            try:
                manifest, payloads = parse_bundle(data)
            except ValueError:
                raise full_error
            if mode != "create":
                raise ValueError("Legacy evidence bundles support new-service import only")
            payload = {"executions": [p.model_dump(mode="json") for p in payloads]}
            source_name = payloads[0].service.name
        ServicePayload.model_validate({"id": target_key, "name": source_name, "version": manifest.get("current_version") or "Unknown"})
        if mode == "add_history":
            missing, duplicates = plan_history(db, state, service)
            payload["history_counts"] = {"new": len(missing), "duplicates": duplicates}
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    payload.update(manifest=manifest, mode=mode, target_id=service.id if service else None)
    if mode == "replace_metadata":
        payload["baseline"] = metadata_digest(db, service.id)
    token = secrets.token_hex(24)
    db.add(BundlePreview(token=token, user_id=auth.user.id, target_key=target_key,
        payload=payload,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30)))
    db.commit()
    return page(request, auth, bundle_mode=True, bundle_manifest=manifest, token=token, target_key=target_key, import_mode=mode, history_counts=payload.get("history_counts"))


def metadata_digest(db, service_id):
    row = db.get(ServiceMetadata, service_id)
    return sha256(json.dumps(row.values if row else {}, sort_keys=True).encode()).hexdigest()


def lock_service(db, service_id):
    # A write lock serializes confirmation on SQLite as well as PostgreSQL.
    db.execute(update(Service).where(Service.id == service_id).values(name=Service.name))
    db.expire_all()


@router.post("/exchange/bundles/confirm/{token}")
def bundle_confirm(token: str, csrf_token: str = Form(), confirm: bool = Form(False), db=Depends(get_db), auth=Depends(require_user)):
    csrf(auth, csrf_token)
    preview = db.get(BundlePreview, token)
    if preview is None or preview.user_id != auth.user.id:
        raise HTTPException(404)
    expiry = preview.expires_at.replace(tzinfo=timezone.utc) if preview.expires_at.tzinfo is None else preview.expires_at
    if not confirm or preview.consumed or expiry <= datetime.now(timezone.utc):
        raise HTTPException(409, detail="Confirmation required or preview expired/consumed")
    service = db.scalar(select(Service).where(Service.service_key == preview.target_key))
    mode = preview.payload.get("mode", "create")
    if not auth.has("bundle.import", service.id if service else None):
        raise HTTPException(403)
    if (mode == "create" and service) or (mode != "create" and (not service or service.id != preview.payload["target_id"])):
        raise HTTPException(409, detail="Target changed; preview again")
    if mode == "replace_metadata" and not auth.has("metadata.edit", service.id):
        raise HTTPException(403)
    if service:
        lock_service(db, service.id)
    if db.execute(update(BundlePreview).where(BundlePreview.token == token, BundlePreview.consumed == False, BundlePreview.expires_at > datetime.now(timezone.utc)).values(consumed=True), execution_options={"synchronize_session": False}).rowcount != 1:
        raise HTTPException(409, detail="Preview already consumed")
    try:
        if "state" in preview.payload:
            from .service_transfer import restore_service, add_history
            state = preview.payload["state"]
            if mode == "create":
                service = restore_service(db, state, preview.target_key, auth.user.id)
            elif mode == "add_history":
                add_history(db, state, service)
            else:
                if metadata_digest(db, service.id) != preview.payload["baseline"]:
                    raise HTTPException(409, detail="Metadata changed since preview; preview again")
                row = db.get(ServiceMetadata, service.id)
                values = state["records"]["service_metadata"]
                # Only known manual metadata, never scanner-owned identity.
                values = {k: v for k, v in (values[0]["values"] if values else {}).items() if k in META and not k.startswith(("export.", "service.")) and k != "system.name"}
                if row is None:
                    row = ServiceMetadata(service_id=service.id)
                    db.add(row)
                row.values = values
        else:
            from .models import ServiceArtifact, ServiceArtifactRevision, ServiceTransferProvenance
            from .service_transfer import safe_sources, scrub
            payloads = preview.payload["executions"]
            source = payloads[-1]["service"]
            service = Service(service_key=preview.target_key, name=source["name"],
                              description=source.get("description"), owner=source.get("owner"),
                              poc=source.get("poc"), manual_version=source.get("version"),
                              assessment_status="assessment_pending", lifecycle_status="active")
            db.add(service)
            db.flush()
            retained = safe_sources(payloads[-1].get("helm_source_files") or {}, [])
            if retained:
                artifact = ServiceArtifact(service_id=service.id, artifact_type="helm",
                    artifact_name="Retained original source", source_type="upload",
                    source_metadata={"origin": "legacy_bundle"}, lifecycle_status="active")
                db.add(artifact)
                db.flush()
                db.add(ServiceArtifactRevision(artifact_id=artifact.id, revision_number=1,
                    revision_label="ORIGINAL", files=retained,
                    checksum=sha256(json.dumps(retained, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                    immutable=True, source_metadata={"origin": "legacy_bundle"}))
            db.add(ServiceTransferProvenance(service_id=service.id,
                detail={"historical_executions": scrub(payloads), "assessment_role": "informational_only"}))
        record_audit(db, auth, "bundle.import", "service", service.id,
            original_service=preview.payload["manifest"]["service_key"], mode=mode, format=preview.payload["manifest"]["schema_version"])
        preview.payload = {"manifest": preview.payload["manifest"], "executions": []}
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, detail="Target or record identity changed; preview again. Nothing imported.") from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return RedirectResponse(f"/services/{preview.target_key}/history", status_code=303)


@router.get("/services/{service_key}/history")
def history_page(service_key: str, request: Request, version: str = "", db=Depends(get_db), auth=Depends(require_user)):
    service = service_for(db, auth, service_key, "service.view")
    imported = [item for provenance in db.scalars(select(ServiceTransferProvenance).where(
        ServiceTransferProvenance.service_id == service.id))
        for item in provenance.detail.get("historical_executions", [])]
    imported_versions = list(dict.fromkeys(str((item.get("raw_payload", item).get("service") or {}).get("version") or "Unknown") for item in imported))
    local_versions = versions(db, service)
    choices = list(dict.fromkeys(local_versions + imported_versions))
    if not version and imported and not db.scalar(select(Execution.id).where(Execution.service_id == service.id).limit(1)):
        version = imported_versions[0]
    try:
        selected, executions = selected_evidence(db, service, version)
    except ValueError as exc:
        if version not in imported_versions:
            raise HTTPException(404, detail=str(exc)) from exc
        selected, executions = version, []
    from .main import templates, page_context
    # Only immutable payloads belonging to this version are exposed. Mutable
    # current workspaces, approvals and remediation state are deliberately absent.
    snapshots = [{"key": e.execution_key, "at": e.scanned_at, "scope": e.scan_scope,
        "complete": e.complete, "data": {k: e.raw_payload.get(k) for k in (
            "service", "findings", "policy_findings", "service_overview", "sbom_images",
            "sbom_components", "skipped_images", "skipped_charts")},
        "source_files": sorted((e.raw_payload.get("helm_source_files") or {}).keys())} for e in executions]
    imported_snapshots = []
    for index, item in enumerate(imported):
        raw = item.get("raw_payload", item)
        if str((raw.get("service") or {}).get("version") or "Unknown") != selected:
            continue
        imported_snapshots.append({"key": item.get("execution_key", raw.get("execution_id", f"imported-{index}")),
            "at": item.get("scanned_at", raw.get("scanned_at")), "scope": item.get("scan_scope", raw.get("scan_scope", "service")),
            "complete": item.get("complete", raw.get("complete", False)),
            "data": {key: raw.get(key) for key in ("service", "findings", "policy_findings", "service_overview", "sbom_images", "sbom_components")},
            "source_files": sorted((raw.get("helm_source_files") or {}).keys())})
    return templates.TemplateResponse(request, "service_history.html", page_context(auth,
        service=service, version=selected, versions=choices, snapshots=snapshots,
        imported_snapshots=imported_snapshots))


def page(request, auth, **values):
    from .main import templates, page_context
    return templates.TemplateResponse(request, "exchange.html", page_context(auth, **values))


def service_for(db, auth, service_key, permission):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    if not auth.has(permission, service.id):
        raise HTTPException(403, detail="Permission denied")
    return service


def csrf(auth, value):
    from .main import check_csrf
    check_csrf(auth, value)


def catalog(db):
    entries = builtins()
    for entry in db.scalars(select(ExportTemplate).order_by(ExportTemplate.name)):
        entries[str(entry.id)] = {**entry.definition, "name": entry.name, "enabled": entry.enabled}
    return entries


def template_for(db, key):
    value = catalog(db).get(key)
    if not value or not value.get("enabled", True):
        raise HTTPException(404, detail="Template not available")
    return value


def state_hash(context, rows):
    stable = {k: v for k, v in context.items() if not k.startswith("export.")}
    return sha256(json.dumps([stable, rows], sort_keys=True, default=str).encode()).hexdigest()


@router.get("/services/{service_key}/exchange")
def exchange_page(service_key: str, request: Request, version: str = "", template: str = "ppsm", db=Depends(get_db), auth=Depends(require_user)):
    service = service_for(db, auth, service_key, "service.view")
    definition = template_for(db, template)
    try:
        selected, _ = selected_evidence(db, service, version)
        context, rows = context_and_rows(db, service, selected, definition["dataset"], auth.user.username)
    except ValueError as exc:
        raise HTTPException(404, detail=str(exc)) from exc
    return page(request, auth, service=service, version=selected, versions=versions(db, service),
        catalog=catalog(db), selected_template=template, definition=definition,
        missing=missing_fields(definition, context, rows), row_count=len(rows),
        metadata_groups=metadata_groups(), export_preview=export_preview(definition, context, rows, db.get(ServiceMetadata, service.id).values if db.get(ServiceMetadata, service.id) else {}),
        metadata=(db.get(ServiceMetadata, service.id).values if db.get(ServiceMetadata, service.id) else {}) if auth.has("metadata.view", service.id) else None)


@router.get("/services/{service_key}/exchange/{template}/export.xlsx")
def export_xlsx(service_key: str, template: str, version: str = "", acknowledge_missing: bool = False, db=Depends(get_db), auth=Depends(require_user)):
    definition = template_for(db, template)
    service = service_for(db, auth, service_key, definition["dataset"] + ".export")
    try:
        version, _ = selected_evidence(db, service, version)
        context, rows = context_and_rows(db, service, version, definition["dataset"], auth.user.username)
        missing = missing_fields(definition, context, rows)
        if missing and (definition.get("block_missing") or not acknowledge_missing):
            raise HTTPException(422, detail={"missing": missing, "message": "Review missing required fields before export"})
        book = workbook(definition, context, rows)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    output = BytesIO()
    book.save(output)
    output.seek(0)
    record_audit(db, auth, "exchange.export", "service", service.id, dataset=definition["dataset"], version=version, rows=len(rows), missing_count=len(missing))
    db.commit()
    return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f'attachment; filename="cats-{definition["dataset"]}.xlsx"'})


@router.post("/services/{service_key}/exchange/{template}/preview")
def preview_import(service_key: str, template: str, request: Request, version: str = Form(), csrf_token: str = Form(), upload: UploadFile = File(), db=Depends(get_db), auth=Depends(require_user)):
    csrf(auth, csrf_token)
    definition = template_for(db, template)
    dataset = definition["dataset"]
    service = service_for(db, auth, service_key, dataset + ".import")
    try:
        version, _ = selected_evidence(db, service, version)
        from .exchange_limits import workbook_bytes
        preview = parse_workbook(upload.file.read(workbook_bytes() + 1), definition)
        context, rows = context_and_rows(db, service, version, dataset, auth.user.username)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    from .exchange import record_key
    existing = {record_key(dataset, row): row for row in rows}
    preview["conflicts"] = [item["key"] for item in preview["rows"] if item["key"] in existing]
    preview["new"] = len(preview["rows"]) - len(preview["conflicts"])
    preview["baseline"] = state_hash(context, rows)
    token = secrets.token_hex(24)
    db.add(ExchangePreview(token=token, service_id=service.id, user_id=auth.user.id, version=version, dataset=dataset, payload=preview, expires_at=datetime.now(timezone.utc) + timedelta(minutes=30)))
    db.commit()
    return page(request, auth, service=service, version=version, preview=preview, token=token)


@router.post("/services/{service_key}/exchange/confirm/{token}")
def confirm_import(service_key: str, token: str, csrf_token: str = Form(), conflict_action: str = Form("cancel"), db=Depends(get_db), auth=Depends(require_user)):
    csrf(auth, csrf_token)
    preview = db.get(ExchangePreview, token)
    if preview is None or preview.user_id != auth.user.id:
        raise HTTPException(404)
    service = service_for(db, auth, service_key, preview.dataset + ".import")
    now = datetime.now(timezone.utc)
    expiry = preview.expires_at.replace(tzinfo=timezone.utc) if preview.expires_at.tzinfo is None else preview.expires_at
    if preview.service_id != service.id or preview.consumed or expiry <= now:
        raise HTTPException(409, detail="Preview expired or already consumed")
    payload = preview.payload
    if payload["errors"]:
        raise HTTPException(422, detail="Resolve validation errors before importing")
    if conflict_action not in {"skip", "update"}:
        raise HTTPException(422, detail="Explicitly select skip or update")
    lock_service(db, service.id)
    context, rows = context_and_rows(db, service, preview.version, preview.dataset, auth.user.username)
    if state_hash(context, rows) != payload["baseline"]:
        raise HTTPException(409, detail="Service data changed; upload again for a fresh preview")
    claimed = db.execute(update(ExchangePreview).where(ExchangePreview.token == token, ExchangePreview.consumed == False, ExchangePreview.expires_at > datetime.now(timezone.utc)).values(consumed=True), execution_options={"synchronize_session": False})
    if claimed.rowcount != 1:
        raise HTTPException(409, detail="Preview already consumed")
    count = 0
    try:
        for row in payload["rows"]:
            if row["key"] in payload["conflicts"] and conflict_action == "skip":
                continue
            values = row["values"]
            if preview.dataset == "poam":
                item = db.scalar(select(PoamEntry).where(PoamEntry.service_id == service.id, PoamEntry.service_version == preview.version, PoamEntry.exchange_key == row["key"]))
                if item is None:
                    item = PoamEntry(service_id=service.id, service_version=preview.version, exchange_key=row["key"], item_type="Imported", created_by_id=auth.user.id, status="pending_approval")
                    db.add(item)
                # Imports do not bypass approval or grant an approved status.
                item.status = "pending_approval"
                item.approved_by_id = None
                item.approved_at = None
                item.title = str(values.get("finding.identifier") or "")[:240]
                item.description = str(values.get("finding.description") or "")
                item.remediation = str(values.get("finding.mitigation") or values.get("finding.recommendation") or "")
                item.supplemental_fields = {k: v for k, v in values.items() if k not in {"finding.identifier", "finding.description", "finding.mitigation", "finding.status"}}
                if values.get("finding.due_date"):
                    item.due_date = datetime.fromisoformat(str(values["finding.due_date"]))
                else:
                    item.due_date = None
                db.flush()
                db.add(PoamHistory(poam_id=item.id, actor_user_id=auth.user.id, action="imported", detail={"version": preview.version}))
            else:
                item = db.scalar(select(InventoryRecord).where(InventoryRecord.service_id == service.id, InventoryRecord.version == preview.version, InventoryRecord.dataset == preview.dataset, InventoryRecord.record_key == row["key"]))
                if item is None:
                    item = InventoryRecord(service_id=service.id, version=preview.version, dataset=preview.dataset, record_key=row["key"], updated_by_id=auth.user.id)
                    db.add(item)
                item.values = values
                item.updated_by_id = auth.user.id
                item.updated_at = now
            count += 1
        record_audit(db, auth, "exchange.import", "service", service.id, dataset=preview.dataset, version=preview.version, rows=count, conflict_action=conflict_action)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return RedirectResponse(f"/services/{service_key}/exchange?version={quote(preview.version, safe='')}", status_code=303)


@router.post("/services/{service_key}/exchange/metadata")
def save_metadata(service_key: str, values: str = Form(), csrf_token: str = Form(), db=Depends(get_db), auth=Depends(require_user)):
    csrf(auth, csrf_token)
    service = service_for(db, auth, service_key, "metadata.edit")
    lock_service(db, service.id)
    try:
        parsed = json.loads(values)
        if not isinstance(parsed, dict) or len(values) > 20000:
            raise ValueError()
        for key, value in parsed.items():
            if key not in META or key.startswith(("export.", "service.")) or key == "system.name" or not isinstance(value, (str, int, float, bool)) or len(str(value)) > 2000:
                raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(422, detail="Use catalog metadata keys with bounded scalar values; authoritative export/service identity cannot be edited here")
    record = db.get(ServiceMetadata, service.id)
    if record is None:
        record = ServiceMetadata(service_id=service.id)
        db.add(record)
    record.values = parsed
    record_audit(db, auth, "metadata.updated", "service", service.id, fields=sorted(parsed))
    db.commit()
    return RedirectResponse(f"/services/{service_key}/exchange", status_code=303)


@router.get("/exchange/templates")
def templates_page(request: Request, db=Depends(get_db), auth=Depends(require_user)):
    if not auth.has("template.view"):
        raise HTTPException(403)
    return page(request, auth, template_catalog=catalog(db), field_catalog={"metadata": META, "datasets": FIELDS})


@router.post("/exchange/templates")
def save_template(definition: str = Form(), template_id: str = Form(""), enabled: bool = Form(False), csrf_token: str = Form(), db=Depends(get_db), auth=Depends(require_user)):
    csrf(auth, csrf_token)
    if not auth.has("template.manage"):
        raise HTTPException(403)
    try:
        if len(definition) > 100000:
            raise ValueError("Template exceeds size limit")
        parsed = validate_template(json.loads(definition))
        record = db.get(ExportTemplate, int(template_id)) if template_id else None
        if template_id and record is None:
            raise ValueError("Custom template not found; built-ins must be duplicated")
        if db.scalar(select(ExportTemplate).where(ExportTemplate.name == parsed["name"], ExportTemplate.id != (record.id if record else -1))):
            raise ValueError("Template name already exists")
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    if record is None:
        record = ExportTemplate(name=parsed["name"], definition=parsed)
        db.add(record)
    record.name, record.definition, record.enabled = parsed["name"], parsed, enabled
    db.flush()
    record_audit(db, auth, "template.updated", "export_template", record.id, name=record.name, enabled=enabled)
    db.commit()
    return RedirectResponse("/exchange/templates", status_code=303)
