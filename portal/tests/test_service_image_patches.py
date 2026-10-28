from datetime import timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app import patch_campaigns as campaigns
from app import durable_jobs, release_revisions
from app.artifact_catalog import (ArtifactPatchLineage, ArtifactRecommendation, GlobalArtifact, artifact_eligibility,
    has_current_source_image, register_patch_artifacts)
from app.database import Base
from app.models import PatchExecution, Service, ServiceImage, User
from app.service_image_patches import image_patch_history


@pytest.fixture
def workspace(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(campaigns, "record_audit", lambda *a, **k: None)
    with Session(engine) as db:
        user = User(username="patch-owner", display_name="Patch owner")
        service = Service(service_key="patched", name="Patched")
        other = Service(service_key="other", name="Other")
        db.add_all([user, service, other]); db.flush()
        image = ServiceImage(service_id=service.id, image_reference="registry/source:original",
            image_digest="sha256:" + "a" * 64)
        db.add(image); db.commit()
        auth = SimpleNamespace(user=user, has=lambda permission, identity: identity == service.id)
        monkeypatch.setattr(campaigns, "AuthContext", lambda *a: auth)
        yield db, service, other, image, auth
    engine.dispose()


def ready(workspace, image=None, digest_char="b"):
    db, service, _, original, auth = workspace
    image = image or original
    campaign = campaigns.submit_campaign(db, auth, service, {
        "image_ids": [image.id], "destination_registry_id": "destination"}, {"destination": {}})
    item = db.scalar(select(campaigns.PatchCampaignItem).where(
        campaigns.PatchCampaignItem.campaign_id == campaign.id))
    job = db.get(durable_jobs.DurableJob, item.job_id)
    reference = "registry/patched@sha256:" + digest_char * 64
    receipt = {"status": "complete", "source_image": item.image_reference,
        "immutable_destination": reference, "patch_status": "PATCHED", "delivery_status": "delivered",
        "signature_status": "verified", "signature": {"image": reference, "generator": "cosign",
            "key_fingerprint": "trusted-key", "verified_at": "2026-10-25T00:00:00Z"},
        "artifact_validation": "docker-load", "validated_source": "flattened-rootfs",
        "vulnerabilities_before": 5, "vulnerabilities_after": 1}
    patch = PatchExecution(job_key="patch-" + str(campaign.id), service_id=service.id,
        requested_by_id=auth.user.id, source_mode="oci", output_mode="push", status="complete",
        source_image=item.image_reference, destination_image=reference,
        summary={"artifact_receipt": receipt}, completed_at=durable_jobs.now())
    db.add(patch); db.flush()
    source, target = register_patch_artifacts(db, patch_execution_id=patch.id,
        media_type="application/vnd.oci.image.manifest.v1+json", platform="linux/amd64")
    item.patch_execution_id = patch.id
    job.status, job.lease_token = "running", "test-lease"
    job.lease_until = durable_jobs.now() + timedelta(minutes=2)
    db.commit()
    return campaign, item, job, patch, source, target


def finish(db, job, **kwargs):
    durable_jobs.JobContext(job, lambda: Session(db.get_bind())).finish(
        result={"patch_status": "PATCHED"}, **kwargs)
    db.expire_all()


def test_success_replaces_only_working_image_and_retains_evidence(workspace):
    db, service, other, original, _ = workspace
    unrelated = ServiceImage(service_id=other.id, image_reference=original.image_reference,
        image_digest=original.image_digest)
    db.add(unrelated)
    _, item, job, patch, source, target = ready(workspace)
    original_ref, original_digest = original.image_reference, original.image_digest
    finish(db, job)
    assert job.status == "completed" and job.result["inventory_updated"] is True
    replacement = db.get(ServiceImage, job.result["inventory_image_id"])
    assert original.lifecycle_status == "replaced" and unrelated.lifecycle_status == "active"
    assert (original.image_reference, original.image_digest) == (original_ref, original_digest)
    assert replacement.lifecycle_status == "active" and replacement.replacement_of_id == original.id
    assert replacement.image_digest == target.digest
    assert replacement.scan_status == "never_scanned"
    assert db.scalar(select(func.count()).select_from(release_revisions.ServiceActiveRelease)) == 0
    assert artifact_eligibility(db, target.id, service.id)["eligible"] is False
    assert not has_current_source_image(db, service_id=service.id, artifact_id=source.id)
    assert has_current_source_image(db, service_id=service.id, artifact_id=source.id, target_artifact_id=target.id)
    history = image_patch_history(db, service.id, [original, replacement, unrelated])
    assert history[original.id] == [] and unrelated.id not in history
    assert history[replacement.id] == [{"original_image": item.image_reference,
        "patched_at": patch.completed_at.replace(tzinfo=timezone.utc).isoformat(), "job_id": patch.job_key,
        "result_image": patch.summary["artifact_receipt"]["immutable_destination"]}]


@pytest.mark.parametrize("outcome", ["cancelled", "failed", "lease_lost"])
def test_terminal_or_unowned_jobs_never_replace(workspace, outcome):
    db, _, _, original, _ = workspace
    _, _, job, _, _, _ = ready(workspace)
    if outcome == "cancelled":
        job.cancel_requested = True; db.commit()
        finish(db, job)
    elif outcome == "failed":
        finish(db, job, error="Delivery failed")
    else:
        job.lease_until = durable_jobs.now() - timedelta(seconds=1); db.commit()
        with pytest.raises(durable_jobs.LeaseLost):
            finish(db, job)
    assert original.lifecycle_status == "active"
    assert db.scalar(select(func.count()).select_from(ServiceImage)) == 1
    assert job.result.get("inventory_updated") is not True


@pytest.mark.parametrize("failure", ["signature", "load", "no_op", "delivery", "digest", "source",
    "patch_failed", "permission", "retired", "source_changed", "source_replaced", "ownership"])
def test_unverified_or_stale_results_do_not_replace(workspace, failure):
    db, service, _, original, auth = workspace
    _, item, job, patch, _, _ = ready(workspace)
    receipt = dict(patch.summary["artifact_receipt"])
    if failure == "signature": receipt["signature_status"] = "failed"
    elif failure == "load": receipt["artifact_validation"] = "unverified"
    elif failure == "no_op": receipt["patch_status"] = "NO_APPLICABLE_FIXES"
    elif failure == "delivery": receipt["delivery_status"] = "failed"
    elif failure == "digest": receipt["immutable_destination"] = "registry/patched@sha256:" + "d" * 64
    elif failure == "source": receipt["source_image"] = "registry/other@sha256:" + "a" * 64
    elif failure == "patch_failed": patch.status = "failed"
    elif failure == "permission": auth.has = lambda permission, identity: permission != "service.edit"
    elif failure == "retired": service.lifecycle_status = "retired"
    elif failure == "source_changed": original.image_digest = "sha256:" + "e" * 64
    elif failure == "source_replaced": original.lifecycle_status = "replaced"
    elif failure == "ownership": job.payload = {"campaign_id": item.campaign_id, "image_id": 999}
    patch.summary = {"artifact_receipt": receipt}; db.commit()
    finish(db, job)
    assert job.status == "completed"
    assert job.result["inventory_updated"] is False and job.result["inventory_message"]
    assert db.scalar(select(func.count()).select_from(ServiceImage)) == 1


def test_repeated_completion_is_idempotent_and_ancestry_survives(workspace):
    db, service, _, original, _ = workspace
    _, _, first_job, first_patch, _, _ = ready(workspace)
    finish(db, first_job)
    first_result = db.get(ServiceImage, first_job.result["inventory_image_id"])
    # A repeated call with the original retained outcome cannot add a second row.
    first_job.status = "running"
    assert campaigns.complete_inventory(db, first_job)["inventory_image_id"] == first_result.id
    first_job.status = "completed"; db.commit()
    _, _, second_job, second_patch, _, _ = ready(workspace, first_result, "c")
    finish(db, second_job)
    second_result = db.get(ServiceImage, second_job.result["inventory_image_id"])
    history = image_patch_history(db, service.id, [original, first_result, second_result])
    assert [row["job_id"] for row in history[second_result.id]] == [second_patch.job_key, first_patch.job_key]
    assert image_patch_history(db, service.id, [second_result])[second_result.id] == history[second_result.id]
    assert db.scalar(select(func.count()).select_from(ServiceImage)) == 3
    manual = ServiceImage(service_id=service.id, image_reference="registry/manual:tag",
        image_digest="sha256:" + "d" * 64, replacement_of_id=second_result.id)
    db.add(manual); db.flush()
    assert image_patch_history(db, service.id, [original, first_result, second_result, manual])[manual.id] == []


def test_history_needs_exact_verified_digest_and_service_scope(workspace):
    db, service, other, original, _ = workspace
    _, _, job, patch, _, target = ready(workspace)
    finish(db, job)
    replacement = db.get(ServiceImage, job.result["inventory_image_id"])
    foreign = ServiceImage(service_id=other.id, image_reference=replacement.image_reference, image_digest=target.digest)
    mutable = ServiceImage(service_id=service.id, image_reference=replacement.image_reference)
    conflicting = ServiceImage(service_id=service.id, image_reference="registry/other@sha256:" + "e" * 64,
        image_digest=target.digest)
    db.add_all([foreign, mutable, conflicting]); db.flush()
    assert image_patch_history(db, other.id, [foreign])[foreign.id] == []
    projection = image_patch_history(db, service.id, [replacement, mutable, conflicting])
    assert projection[replacement.id] and projection[mutable.id] == [] and projection[conflicting.id] == []
    patch.summary = {"artifact_receipt": {**patch.summary["artifact_receipt"], "signature_status": "failed"}}
    db.flush()
    assert image_patch_history(db, service.id, [replacement])[replacement.id] == []


def test_shared_output_claimed_by_another_original_keeps_successful_job(workspace):
    db, service, _, original, _ = workspace
    other_occurrence = ServiceImage(service_id=service.id, image_reference="registry/source:another-tag",
        image_digest=original.image_digest)
    db.add(other_occurrence); db.commit()
    _, _, first_job, _, _, _ = ready(workspace)
    finish(db, first_job)
    replacement = db.get(ServiceImage, first_job.result["inventory_image_id"])
    _, _, second_job, _, _, _ = ready(workspace, other_occurrence)
    finish(db, second_job)
    assert second_job.status == "completed" and second_job.result["inventory_updated"] is False
    assert "another image history" in second_job.result["inventory_message"]
    assert other_occurrence.lifecycle_status == "active"
    assert replacement.replacement_of_id == original.id
    assert db.scalar(select(func.count()).select_from(ServiceImage)) == 3


def test_newer_unrelated_jobs_do_not_hide_each_image_history_or_exact_adoption(workspace):
    db, service, _, original, auth = workspace
    _, item, job, patch, source, target = ready(workspace)
    finish(db, job)
    replacement = db.get(ServiceImage, job.result["inventory_image_id"])
    unrelated_target = GlobalArtifact(digest="sha256:" + "c" * 64,
        media_type=target.media_type, platform=target.platform)
    unrelated_image = ServiceImage(service_id=service.id, image_reference="registry/unrelated",
        image_digest=unrelated_target.digest)
    db.add_all([unrelated_target, unrelated_image]); db.flush()
    destination = unrelated_image.image_reference + "@" + unrelated_target.digest
    for index in range(201):
        receipt = {**patch.summary["artifact_receipt"], "immutable_destination": destination,
            "signature": {**patch.summary["artifact_receipt"]["signature"], "image": destination}}
        later_patch = PatchExecution(job_key=f"later-{index}", service_id=service.id,
            requested_by_id=auth.user.id, source_mode="oci", output_mode="push",
            source_image=item.image_reference, destination_image=destination,
            status="complete", summary={"artifact_receipt": receipt},
            completed_at=durable_jobs.now())
        later_campaign = campaigns.PatchCampaign(service_id=service.id, requested_by_id=auth.user.id,
            destination_registry_id="destination", destination_prefix="")
        later_job = durable_jobs.DurableJob(id=f"later-{index}", kind=campaigns.KIND,
            service_id=service.id, requested_by_id=auth.user.id, status="completed")
        db.add_all([later_patch, later_campaign, later_job]); db.flush()
        db.add_all([ArtifactPatchLineage(patch_execution_id=later_patch.id,
            source_artifact_id=source.id, output_artifact_id=unrelated_target.id),
            campaigns.PatchCampaignItem(campaign_id=later_campaign.id, image_id=original.id,
                image_reference=item.image_reference, job_id=later_job.id, patch_execution_id=later_patch.id)])
    db.commit()
    history = image_patch_history(db, service.id, [replacement, unrelated_image])
    assert [row["job_id"] for row in history[replacement.id]] == [patch.job_key]
    assert len(history[unrelated_image.id]) == 200
    assert has_current_source_image(db, service_id=service.id, artifact_id=source.id, target_artifact_id=target.id)


def test_exact_campaign_compatibility_preserves_review_permissions(workspace, monkeypatch):
    import asyncio
    from app import artifact_catalog_routes as routes
    db, service, _, original, auth = workspace
    _, _, job, _, source, target = ready(workspace)
    finish(db, job)
    recommendation = ArtifactRecommendation(service_id=service.id,
        source_artifact_id=source.id, target_artifact_id=target.id)
    db.add(recommendation); db.commit()
    monkeypatch.setattr(routes, "_csrf", lambda *args: None)
    limited = SimpleNamespace(user=auth.user, has=lambda permission, identity: permission != "approval.request")
    with pytest.raises(HTTPException) as failure:
        asyncio.run(routes.propose_selection(service.service_key, recommendation.id, None, db, limited))
    assert failure.value.status_code == 403 and recommendation.status == "pending_verification"
    response = asyncio.run(routes.propose_selection(service.service_key, recommendation.id, None, db, auth))
    assert response["status"] == "proposed" and response["active_release_changed"] is False
    assert db.scalar(select(func.count()).select_from(release_revisions.ServiceActiveRelease)) == 0
    # Manual pointers with no successful retained campaign outcome cannot qualify.
    job.result = {}; db.flush()
    assert not has_current_source_image(db, service_id=service.id, artifact_id=source.id, target_artifact_id=target.id)
