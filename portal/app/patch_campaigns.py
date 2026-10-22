"""Bounded durable service image campaigns using the existing patch engine."""
from __future__ import annotations
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base, get_db
from .models import Service, ServiceImage, PatchExecution, User
from .auth import AuthContext, require_user, record_audit
from .service_oci import _csrf
from . import durable_jobs
from .artifact_evidence_summary import vulnerability_evidence
from .artifact_catalog import validate_digest, GlobalArtifact, assign_artifact, ArtifactPatchLineage
from .patch_recipes import recipe_fingerprint, claim_recipe, reusable_patch, wait_for_recipe

MAX_IMAGES = 20
KIND = "patch_campaign_item"
router = APIRouter()


class PatchCampaign(Base):
    __tablename__ = "patch_campaigns"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    requested_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    destination_registry_id: Mapped[str] = mapped_column(String(160))
    destination_prefix: Mapped[str] = mapped_column(String(240))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class PatchCampaignItem(Base):
    __tablename__ = "patch_campaign_items"
    __table_args__ = (UniqueConstraint("campaign_id", "image_id", name="uq_campaign_image"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("patch_campaigns.id"), index=True)
    image_id: Mapped[int] = mapped_column(ForeignKey("service_images.id"))
    image_reference: Mapped[str] = mapped_column(String(1024))
    job_id: Mapped[str] = mapped_column(ForeignKey("durable_jobs.id"), unique=True)
    patch_execution_id: Mapped[int | None] = mapped_column(ForeignKey("patch_executions.id"))


def _service(db, auth, key):
    row = db.scalar(select(Service).where(Service.service_key == key))
    if row is None or not auth.has("service.view", row.id):
        raise HTTPException(404, "Service unavailable")
    return row


def can_patch(auth, service):
    return service.lifecycle_status == "active" and all(auth.has(permission, service.id) for permission in ("service.view", "remediation.execute", "scan.ingest"))


def _registries(db):
    from . import main
    rows = main.parse_json(main.get_global_configuration(db).get("oci_registries"), [])
    return {str(row["id"]): row for row in rows if isinstance(row, dict) and row.get("id")}


def immutable_source(image):
    reference = image.image_reference.strip()
    digest = validate_digest(image.image_digest or (reference.rsplit("@", 1)[1] if "@" in reference else ""))
    if "@" in reference:
        if reference.rsplit("@", 1)[1].lower() != digest:
            raise ValueError("Image evidence has conflicting digests")
        reference = reference.rsplit("@", 1)[0]
    # Remove a mutable tag but preserve registry ports.
    if reference.rfind(":") > reference.rfind("/"):
        reference = reference.rsplit(":", 1)[0]
    if not reference or "://" in reference or any(c.isspace() for c in reference):
        raise ValueError("Image reference is invalid")
    return reference + "@" + digest


def submit_campaign(db, auth, service, data, registries):
    if not can_patch(auth, service):
        raise HTTPException(403, "Service patch permissions required")
    ids = data.get("image_ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_IMAGES or any(type(i) is not int for i in ids) or len(set(ids)) != len(ids):
        raise HTTPException(422, f"Select 1 to {MAX_IMAGES} distinct images")
    registry_id = str(data.get("destination_registry_id") or "")
    if registry_id not in registries:
        raise HTTPException(422, "Select a configured destination registry")
    prefix = str(data.get("destination_prefix") or "").strip().strip("/")
    if len(prefix) > 200 or (prefix and not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*", prefix)):
        raise HTTPException(422, "Destination prefix must be a relative OCI repository path")
    images = list(db.scalars(select(ServiceImage).where(ServiceImage.id.in_(ids), ServiceImage.service_id == service.id, ServiceImage.lifecycle_status == "active")))
    if len(images) != len(ids):
        raise HTTPException(422, "Select active images owned by this service")
    try:
        sources = {image.id: immutable_source(image) for image in images}
    except ValueError as exc:
        raise HTTPException(422, "Selected images require consistent immutable digest evidence") from exc
    campaign = PatchCampaign(service_id=service.id, requested_by_id=auth.user.id,
        destination_registry_id=registry_id, destination_prefix=prefix)
    db.add(campaign); db.flush()
    for image in images:
        job = durable_jobs.submit(db, kind=KIND, payload={"campaign_id": campaign.id, "image_id": image.id},
            service_id=service.id, requested_by_id=auth.user.id, dedupe_key=f"patch-campaign:{campaign.id}:{image.id}",
            max_attempts=1, commit=False)
        db.add(PatchCampaignItem(campaign_id=campaign.id, image_id=image.id, image_reference=sources[image.id], job_id=job.id))
    record_audit(db, auth, "patch.campaign.submitted", "patch_campaign", campaign.id, service_id=service.id, image_count=len(images))
    db.flush()
    return campaign


def campaign_status(statuses):
    if any(value == "running" for value in statuses):
        return "running"
    if any(value == "queued" for value in statuses):
        return "queued"
    if statuses and all(value == "completed" for value in statuses):
        return "completed"
    return "partial" if "completed" in statuses else "failed"


def item_controls(item, job, allowed):
    return {
        "can_cancel": bool(allowed and job and job.status in ("queued", "running") and not job.cancel_requested),
        "can_retry": bool(allowed and job and job.status in ("failed", "cancelled")
            and item.patch_execution_id is None and not job.lease_token
            and int((job.payload or {}).get("retry_count", 0)) < 2),
        "cancel_requested": bool(job and job.cancel_requested),
    }


def campaign_data(db, campaign, auth=None):
    service = db.get(Service, campaign.service_id)
    allowed = bool(auth and auth.user.id == campaign.requested_by_id and service and can_patch(auth, service))
    items = []
    for item in db.scalars(select(PatchCampaignItem).where(PatchCampaignItem.campaign_id == campaign.id).order_by(PatchCampaignItem.id)):
        job = db.get(durable_jobs.DurableJob, item.job_id)
        patch = db.get(PatchExecution, item.patch_execution_id) if item.patch_execution_id else None
        items.append({"id": item.id, **item_controls(item, job, allowed), "image_id": item.image_id, "image_reference": item.image_reference,
            "status": job.status if job else "failed", "error": job.error if job else "Job unavailable",
            "job_id": patch.job_key if patch else None,
            "result": {**{key: (job.result or {}).get(key) for key in ("patch_status", "signature_status", "immutable_destination", "reused")}, "vulnerability_evidence": vulnerability_evidence(db, patch_id=patch.id) if patch else None} if job else {}})
    return {"id": campaign.id, "status": campaign_status([item["status"] for item in items]), "created_at": campaign.created_at.isoformat(), "items": items}


@router.get("/patch-campaigns")
def page(request: Request, service_id: str = "", db=Depends(get_db), auth=Depends(require_user)):
    from . import main
    services = [service for service in db.scalars(select(Service).order_by(Service.name)) if auth.has("service.view", service.id)]
    if service_id:
        _service(db, auth, service_id)
    return main.templates.TemplateResponse(request, "patch_campaigns.html", main.page_context(auth,
        services=services, selected_service_id=service_id,
        configured_registries=main.configured_registries(main.get_global_configuration(db))))


@router.get("/api/services/{service_key}/patch-campaigns")
def service_campaigns(service_key: str, db=Depends(get_db), auth=Depends(require_user)):
    service = _service(db, auth, service_key)
    images = db.scalars(select(ServiceImage).where(ServiceImage.service_id == service.id, ServiceImage.lifecycle_status == "active").order_by(ServiceImage.id)).all()
    campaigns = db.scalars(select(PatchCampaign).where(PatchCampaign.service_id == service.id).order_by(PatchCampaign.id.desc()).limit(50)).all()
    return {"images": [{key: getattr(image, key) for key in ("id", "image_reference", "image_digest", "lifecycle_status")} for image in images],
        "campaigns": [{key: value for key, value in campaign_data(db, item).items() if key != "items"} for item in campaigns],
        "can_patch": can_patch(auth, service), "max_images": MAX_IMAGES}


@router.post("/api/services/{service_key}/patch-campaigns")
async def create(service_key: str, request: Request, db=Depends(get_db), auth=Depends(require_user)):
    _csrf(request, auth)
    service = _service(db, auth, service_key)
    data = await request.json()
    if not isinstance(data, dict):
        raise HTTPException(422, "Campaign request must be an object")
    campaign = submit_campaign(db, auth, service, data, _registries(db))
    db.commit()
    return {"id": campaign.id}


@router.get("/api/patch-campaigns/{campaign_id}")
def detail(campaign_id: int, db=Depends(get_db), auth=Depends(require_user)):
    campaign = db.get(PatchCampaign, campaign_id)
    if campaign is None or not auth.has("service.view", campaign.service_id):
        raise HTTPException(404, "Campaign unavailable")
    return campaign_data(db, campaign, auth)


@router.post("/api/patch-campaigns/{campaign_id}/items/{item_id}/{action}")
def item_action(campaign_id: int, item_id: int, action: str, request: Request,
                db=Depends(get_db), auth=Depends(require_user)):
    _csrf(request, auth)
    campaign = db.get(PatchCampaign, campaign_id)
    if not campaign or not auth.has("service.view", campaign.service_id):
        raise HTTPException(404, "Campaign unavailable")
    service = db.get(Service, campaign.service_id)
    if campaign.requested_by_id != auth.user.id or not service or not can_patch(auth, service):
        raise HTTPException(403, "Campaign owner and current patch permissions required")
    item = db.scalar(select(PatchCampaignItem).where(PatchCampaignItem.id == item_id,
        PatchCampaignItem.campaign_id == campaign_id).with_for_update())
    job = db.scalar(select(durable_jobs.DurableJob).where(durable_jobs.DurableJob.id == item.job_id).with_for_update()) if item else None
    if not item or not job or job.kind != KIND or job.service_id != campaign.service_id or job.requested_by_id != campaign.requested_by_id:
        raise HTTPException(404, "Campaign item unavailable")
    controls = item_controls(item, job, True)
    if action == "cancel":
        if not controls["can_cancel"]:
            raise HTTPException(409, "Item cannot be cancelled")
        job.cancel_requested = True
        if job.status == "queued":
            job.status = "cancelled"
            job.stage = "Cancelled before dispatch"
            job.completed_at = durable_jobs.now()
    elif action == "retry":
        if not controls["can_retry"]:
            raise HTTPException(409, "Retry requires an undispatched terminal item with retries remaining")
        # Keep prior attempts immutable; a dispatched patch may already have published.
        retry_count = int((job.payload or {}).get("retry_count", 0)) + 1
        replacement = durable_jobs.submit(db, kind=KIND,
            payload={"campaign_id": campaign.id, "image_id": item.image_id,
                "retry_count": retry_count, "retry_of": job.id},
            service_id=campaign.service_id, requested_by_id=campaign.requested_by_id,
            dedupe_key=f"patch-campaign:{campaign.id}:{item.image_id}:retry:{retry_count}",
            max_attempts=1, commit=False)
        item.job_id = replacement.id
    else:
        raise HTTPException(404, "Unknown campaign action")
    record_audit(db, auth, "patch.campaign.item." + action, "patch_campaign", campaign.id,
        service_id=campaign.service_id, image_id=item.image_id, durable_job_id=job.id)
    db.commit()
    return campaign_data(db, campaign, auth)


def handle(ctx, payload):
    """Durable worker entry point. One attempt prevents replay of registry writes."""
    from . import main
    ctx.check()
    with main.SessionLocal() as db:
        campaign = db.get(PatchCampaign, payload.get("campaign_id"))
        item = db.scalar(select(PatchCampaignItem).where(PatchCampaignItem.job_id == ctx.job.id).with_for_update())
        actor = db.get(User, ctx.job.requested_by_id)
        service = db.get(Service, ctx.job.service_id)
        auth = AuthContext(actor, None) if actor and actor.enabled else None
        if not campaign or not item or item.campaign_id != campaign.id or item.image_id != payload.get("image_id") or campaign.service_id != ctx.job.service_id or campaign.requested_by_id != ctx.job.requested_by_id:
            raise durable_jobs.JobError("Campaign ownership is inconsistent")
        if not auth or not service or not can_patch(auth, service):
            raise durable_jobs.JobError("Service patch authorization is no longer available")
        image = db.get(ServiceImage, item.image_id)
        if not image or image.service_id != service.id or image.lifecycle_status != "active":
            raise durable_jobs.JobError("Selected image is no longer active in this service")
        if item.patch_execution_id:
            raise durable_jobs.JobError("Patch already dispatched; inspect retained results before submitting a new campaign")
        registries = _registries(db)
        destination_registry = registries.get(campaign.destination_registry_id)
        if not destination_registry:
            raise durable_jobs.JobError("Configured destination registry is no longer available")
        source = item.image_reference
        main._validate_image_reference(source)
        endpoint = str(destination_registry.get("endpoint") or "").rstrip("/")
        host = urlparse(endpoint if "://" in endpoint else "https://" + endpoint).netloc
        namespace = str(destination_registry.get("namespace") or "").strip("/")
        key = uuid.uuid4().hex
        destination = "/".join(part for part in (host, namespace, campaign.destination_prefix, f"image-{item.image_id}") if part) + ":cats-" + key
        main._validate_image_reference(destination)
        signing_config, signing_credentials = main._portal_signing_material(db, auth, "push", service)
        policy = main.configuration_for_service(db, service)
        config = {"job_id": key, "source_mode": "oci", "source_image": source, "output_mode": "push",
            "destination_image": destination, "reuse_source_credentials": False, "remediation_evidence": True,
            **signing_config, **{name: main.parse_json(policy.get(name), [] if name == "trusted_ca_certificates" else {})
                for name in ("trusted_ca_certificates", "repository_policies", "os_definitions")}}
        # The worker may expose a complete immutable-input manifest. Older
        # engines continue normally, with reuse disabled rather than guessing.
        identity_provider = getattr(main, "patch_recipe_identity", None)
        identity = identity_provider(config) if callable(identity_provider) else None
        candidates = list(db.scalars(select(GlobalArtifact).where(
            GlobalArtifact.digest == source.rsplit("@", 1)[-1])))
        source_artifact = candidates[0] if len(candidates) == 1 else None
        fingerprint = recipe_fingerprint(source=source_artifact, config=config,
            identity=identity, destination_scope={"registry": campaign.destination_registry_id,
                "host": host, "namespace": namespace, "prefix": campaign.destination_prefix})
        recipe_claim = None
        if fingerprint:
            recipe_claim = claim_recipe(db, fingerprint, ctx.job.id)
            if recipe_claim.owner_job_id != ctx.job.id:
                previous = reusable_patch(db, recipe_claim, source_artifact,
                    signing_fingerprint=signing_config.get("signing_fingerprint"),
                    destination_scope={"host": host, "namespace": namespace,
                                       "prefix": campaign.destination_prefix})
                if previous is None:
                    pending = db.get(PatchExecution, recipe_claim.patch_execution_id) if recipe_claim.patch_execution_id else None
                    if pending is not None and pending.status == "complete":
                        raise durable_jobs.JobError("Equivalent patch lacks verified retained output; inspect its original campaign")
                    # Release the item lock and snapshot before waiting. Re-enter
                    # to revalidate authorization, policy and receipts afterwards.
                    db.rollback()
                    wait_for_recipe(main.SessionLocal, fingerprint, ctx)
                    return handle(ctx, payload)
                item.patch_execution_id = previous.id
                lineage = db.scalar(select(ArtifactPatchLineage).where(
                    ArtifactPatchLineage.patch_execution_id == previous.id,
                    ArtifactPatchLineage.source_artifact_id == source_artifact.id))
                assign_artifact(db, service_id=service.id, artifact_id=source_artifact.id)
                assign_artifact(db, service_id=service.id, artifact_id=lineage.output_artifact_id, role="patched")
                record_audit(db, auth, "patch.campaign.reused", "patch_campaign", campaign.id,
                    service_id=service.id, patch_execution_id=previous.id)
                receipt = previous.summary["artifact_receipt"]
                reused = {"patch_job_id": previous.job_key, "reused": True,
                    **{name: receipt.get(name) for name in ("patch_status", "signature_status", "immutable_destination")}}
                ctx.check()
                db.commit()
                return reused
        def credentials(registry):
            return (str(registry.get("username") or ""), main.decrypt_secret(str(registry["password"])) if registry.get("password") else "") if registry else ("", "")
        source_user, source_password = credentials(main._configured_registry_for_image(source, list(registries.values())))
        destination_user, destination_password = credentials(destination_registry)
        root = main.PATCH_JOB_ROOT / key
        (root / "input").mkdir(parents=True, exist_ok=False)
        (root / "job-config.json").write_text(json.dumps(main.safe_job_config(config), indent=2), encoding="utf-8")
        patch = PatchExecution(job_key=key, service_id=service.id, requested_by_id=actor.id,
            source_mode="oci", source_image=source, output_mode="push", destination_image=destination)
        db.add(patch); db.flush()
        item.patch_execution_id = patch.id
        if recipe_claim is not None:
            recipe_claim.patch_execution_id = patch.id
        public = {"job_id": key, "patch_execution_id": patch.id, "status": "queued", "phase": "queued",
            "source_mode": "oci", "source_image": source, "output_mode": "push", "destination_image": destination,
            "signing_enabled": bool(signing_config), "signing_fingerprint": signing_config.get("signing_fingerprint"),
            "stages": main.initial_patch_stages("push"), "created_at": main.utcnow().isoformat()}
        with main.PATCH_JOB_LOCK:
            main.PATCH_JOBS[key] = public
        db.commit()
        main._audit_signing_request(db, key, actor.id, config)
    ctx.stage("Patching retained image", 10)
    ctx.check()
    credentials_env = {**signing_credentials, "CATS_PATCH_SOURCE_USERNAME": source_user, "CATS_PATCH_SOURCE_PASSWORD": source_password,
        "CATS_PATCH_DEST_USERNAME": destination_user, "CATS_PATCH_DEST_PASSWORD": destination_password}
    try:
        main._run_patch_job(key, credentials_env)
    finally:
        credentials_env.clear()
    ctx.check()
    result = main._load_patch_job(key)
    receipt = result.get("result") or {}
    if result.get("status") != "complete" or receipt.get("delivery_status") != "delivered":
        raise durable_jobs.JobError("Image patch or delivery did not complete; inspect the retained patch result")
    return {"patch_job_id": key, **{name: receipt.get(name) for name in ("patch_status", "signature_status", "immutable_destination")}}
