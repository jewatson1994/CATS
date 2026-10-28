"""Digest-bound patch provenance for working images, independent of releases."""
from datetime import timezone
from sqlalchemy import func, or_, select
from sqlalchemy.orm import aliased

from .artifact_catalog import ArtifactPatchLineage, GlobalArtifact, _verified_receipt, validate_digest
from .models import PatchExecution, ServiceImage


def image_digest(image):
    """Reject conflicting or mutable identities instead of inferring from tags."""
    reference = str(image.image_reference or "")
    embedded = reference.rsplit("@", 1)[1] if "@" in reference else None
    try:
        digest = validate_digest(image.image_digest or embedded)
        return digest if not embedded or validate_digest(embedded) == digest else None
    except ValueError:
        return None


def verified_lineage(db, patch, source_reference):
    """Require the existing signature, load, scan and immutable catalog gates."""
    if patch is None:
        return None
    receipt = (patch.summary or {}).get("artifact_receipt") or {}
    if not isinstance(receipt, dict) or receipt.get("source_image") != source_reference:
        return None
    source, output = aliased(GlobalArtifact), aliased(GlobalArtifact)
    rows = db.execute(select(source, output).join(
        ArtifactPatchLineage, ArtifactPatchLineage.source_artifact_id == source.id).join(
        output, ArtifactPatchLineage.output_artifact_id == output.id).where(
        ArtifactPatchLineage.patch_execution_id == patch.id)).all()
    for original, result in rows:
        if (original.digest != result.digest and original.platform == result.platform
                and source_reference.endswith("@" + original.digest)
                and _verified_receipt(patch, result)):
            return original, result
    return None


def image_patch_history(db, service_id, images):
    """Bounded, service-scoped history; replacement pointers alone prove nothing.

    Ancestor rows retain earlier patches after repeated replacement. Existing
    catalogued worker outputs (including remediation image jobs) use the same
    receipt checks, even when they predate campaign inventory replacement.
    """
    from .patch_campaigns import PatchCampaign, PatchCampaignItem
    from .durable_jobs import DurableJob

    images = {row.id: row for row in images if row.service_id == service_id}
    result = {identity: [] for identity in images}
    # Artifact workspaces load active images only. Fetch just their predecessors,
    # with explicit depth/row limits so corrupt ancestry cannot expand a read.
    pending = {row.replacement_of_id for row in images.values()} - {None} - images.keys()
    remaining = 200
    for _ in range(20):
        if not pending or remaining <= 0:
            break
        ancestors = db.scalars(select(ServiceImage).where(ServiceImage.service_id == service_id,
            ServiceImage.id.in_(pending)).limit(remaining)).all()
        remaining -= len(ancestors)
        images.update({row.id: row for row in ancestors})
        pending = {row.replacement_of_id for row in ancestors} - {None} - images.keys()
    digests = {identity: image_digest(row) for identity, row in images.items()}
    matching = {digest for digest in digests.values() if digest}
    if not matching:
        return result
    associated = select(PatchCampaignItem.patch_execution_id).join(
        PatchCampaign, PatchCampaign.id == PatchCampaignItem.campaign_id).join(
        DurableJob, DurableJob.id == PatchCampaignItem.job_id).where(
        PatchCampaign.service_id == service_id, DurableJob.status == "completed",
        DurableJob.cancel_requested.is_(False))
    source, output = aliased(GlobalArtifact), aliased(GlobalArtifact)
    # Bound each requested output separately: newer jobs for other active
    # images must not evict an older image's retained provenance.
    ranked = select(ArtifactPatchLineage.id.label("lineage_id"),
        func.row_number().over(partition_by=output.digest,
            order_by=ArtifactPatchLineage.id.desc()).label("position")).join(
        PatchExecution, PatchExecution.id == ArtifactPatchLineage.patch_execution_id).join(
        output, output.id == ArtifactPatchLineage.output_artifact_id).where(
        output.digest.in_(matching),
        or_(PatchExecution.service_id == service_id, PatchExecution.id.in_(associated))).subquery()
    rows = db.execute(select(ArtifactPatchLineage, PatchExecution, source, output).join(
        PatchExecution, PatchExecution.id == ArtifactPatchLineage.patch_execution_id).join(
        source, source.id == ArtifactPatchLineage.source_artifact_id).join(
        output, output.id == ArtifactPatchLineage.output_artifact_id).join(
        ranked, ranked.c.lineage_id == ArtifactPatchLineage.id).where(ranked.c.position <= 200)
        .order_by(ArtifactPatchLineage.id.desc())).all()
    patch_ids = {patch.id for _, patch, _, _ in rows}
    campaign_states = {}
    if patch_ids:
        for patch_id, status, cancelled in db.execute(select(
                PatchCampaignItem.patch_execution_id, DurableJob.status, DurableJob.cancel_requested)
                .join(DurableJob, DurableJob.id == PatchCampaignItem.job_id)
                .join(PatchCampaign, PatchCampaign.id == PatchCampaignItem.campaign_id)
                .where(PatchCampaignItem.patch_execution_id.in_(patch_ids),
                    PatchCampaign.service_id == service_id)):
            campaign_states.setdefault(patch_id, []).append(status == "completed" and not cancelled)
    histories, source_digests = {}, {}
    for lineage, patch, original, target in rows:
        receipt = (patch.summary or {}).get("artifact_receipt") or {}
        if (not _verified_receipt(patch, target) or original.digest == target.digest
                or original.platform != target.platform
                or not str(receipt.get("source_image") or "").endswith("@" + original.digest)
                or (patch.id in campaign_states and not any(campaign_states[patch.id]))):
            continue
        patched_at = patch.completed_at or lineage.created_at
        patched_at = patched_at.replace(tzinfo=timezone.utc) if patched_at.tzinfo is None else patched_at.astimezone(timezone.utc)
        histories.setdefault(target.digest, []).append({
            "original_image": receipt["source_image"],
            "patched_at": patched_at.isoformat(),
            "job_id": patch.job_key, "result_image": receipt["immutable_destination"],
        })
        source_digests[patch.job_key] = original.digest
    for identity in result:
        image = images[identity]
        seen, seen_jobs = set(), set()
        while image is not None and image.id not in seen:
            seen.add(image.id)
            own_history = histories.get(digests.get(image.id), [])
            for entry in own_history:
                if entry["job_id"] not in seen_jobs:
                    result[identity].append(entry)
                    seen_jobs.add(entry["job_id"])
            parent = images.get(image.replacement_of_id)
            image = parent if parent and any(source_digests[entry["job_id"]] == digests.get(parent.id)
                for entry in own_history) else None
        result[identity].sort(key=lambda row: row["patched_at"], reverse=True)
    return result


def has_campaign_replacement(db, *, service_id, source_artifact, target_artifact_id):
    """Keep recommendation selection available after this exact working change.

    A manual replacement or an unrelated historical assignment cannot satisfy
    this check. Assessment, Cyber approval and release activation remain separate.
    """
    from .models import ServiceImage
    from .patch_campaigns import PatchCampaign, PatchCampaignItem
    from .durable_jobs import DurableJob

    target = db.get(GlobalArtifact, target_artifact_id)
    if target is None:
        return False
    rows = db.execute(select(PatchCampaignItem, DurableJob, PatchExecution).join(
        PatchCampaign, PatchCampaign.id == PatchCampaignItem.campaign_id).join(
        DurableJob, DurableJob.id == PatchCampaignItem.job_id).join(
        PatchExecution, PatchExecution.id == PatchCampaignItem.patch_execution_id).join(
        ArtifactPatchLineage, ArtifactPatchLineage.patch_execution_id == PatchExecution.id).where(
        ArtifactPatchLineage.source_artifact_id == source_artifact.id,
        ArtifactPatchLineage.output_artifact_id == target.id,
        PatchCampaign.service_id == service_id, DurableJob.status == "completed",
        DurableJob.cancel_requested.is_(False)).order_by(PatchCampaignItem.id.desc()).limit(200))
    for item, job, patch in rows:
        retained = job.result or {}
        if retained.get("inventory_updated") is not True:
            continue
        original = db.get(ServiceImage, item.image_id)
        replacement = db.get(ServiceImage, retained.get("inventory_image_id")) if retained.get("inventory_image_id") else None
        if (not original or not replacement or original.service_id != service_id
                or replacement.service_id != service_id or original.lifecycle_status != "replaced"
                or replacement.lifecycle_status != "active" or replacement.replacement_of_id != original.id
                or image_digest(original) != source_artifact.digest or image_digest(replacement) != target.digest):
            continue
        lineage = verified_lineage(db, patch, item.image_reference)
        if lineage and lineage[0].id == source_artifact.id and lineage[1].id == target.id:
            return True
    return False
