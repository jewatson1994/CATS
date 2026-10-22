"""Global immutable artifact identities; caller-owned transactions and fail-closed reuse.

Import before Base.metadata.create_all. Locations and service associations are
separate from content identity. Registry tags never serve as artifact identity.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, UniqueConstraint, event, select
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.exc import IntegrityError
from .database import Base
from .models import DeploymentValidationRun, PatchExecution, Service, ServiceImage


def _now():
    return datetime.now(timezone.utc)


class GlobalArtifact(Base):
    __tablename__ = "global_artifacts"
    __table_args__ = (UniqueConstraint("digest", "media_type", "platform", name="uq_global_artifact_identity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    digest: Mapped[str] = mapped_column(String(80), index=True)
    media_type: Mapped[str] = mapped_column(String(160))
    platform: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ArtifactLocation(Base):
    __tablename__ = "global_artifact_locations"
    __table_args__ = (UniqueConstraint("artifact_id", "reference", name="uq_global_artifact_location"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("global_artifacts.id"), index=True)
    reference: Mapped[str] = mapped_column(String(1024))
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ServiceArtifactAssignment(Base):
    __tablename__ = "service_artifact_assignments"
    __table_args__ = (UniqueConstraint("service_id", "artifact_id", "role", name="uq_service_artifact_assignment"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("global_artifacts.id"), index=True)
    role: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ArtifactPatchLineage(Base):
    __tablename__ = "artifact_patch_lineage"
    __table_args__ = (UniqueConstraint("patch_execution_id", "source_artifact_id", "output_artifact_id", name="uq_artifact_patch_lineage"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    patch_execution_id: Mapped[int] = mapped_column(ForeignKey("patch_executions.id"), index=True)
    source_artifact_id: Mapped[int] = mapped_column(ForeignKey("global_artifacts.id"), index=True)
    output_artifact_id: Mapped[int] = mapped_column(ForeignKey("global_artifacts.id"), index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ArtifactRecommendation(Base):
    __tablename__ = "artifact_recommendations"
    __table_args__ = (UniqueConstraint("service_id", "source_artifact_id", "target_artifact_id", name="uq_artifact_recommendation"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    source_artifact_id: Mapped[int] = mapped_column(ForeignKey("global_artifacts.id"))
    target_artifact_id: Mapped[int] = mapped_column(ForeignKey("global_artifacts.id"))
    status: Mapped[str] = mapped_column(String(30), default="pending_verification")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


def _immutable(mapper, connection, target):
    raise ValueError("Artifact identity and lineage are immutable")


for _model in (GlobalArtifact, ArtifactPatchLineage):
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)


def validate_digest(value):
    value = str(value or "").strip().lower()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("An immutable sha256 digest is required")
    return value


def _require(db, model, identifier):
    row = db.get(model, identifier)
    if row is None:
        raise ValueError(f"Unknown {model.__name__}")
    return row


def _get_or_add(db, model, *, defaults=None, **values):
    query = select(model).filter_by(**values)
    row = db.scalar(query)
    if row is not None:
        return row
    # Only the candidate insert rolls back on a racing unique-key winner.
    # begin_nested flushes caller work first, outside this recovery boundary.
    connection = db.connection()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        # sqlite3 legacy transaction mode does not BEGIN for SELECT/SAVEPOINT.
        connection.exec_driver_sql("BEGIN")
    savepoint = db.begin_nested()
    try:
        with savepoint:
            row = model(**{**(defaults or {}), **values})
            db.add(row)
            db.flush()
        return row
    except IntegrityError:
        row = db.scalar(query)
        if row is None:
            raise
        return row


def register_artifact(db, *, digest, media_type, platform="unknown", reference=None, provenance=None):
    digest = validate_digest(digest)
    media_type = str(media_type or "").strip().lower()
    platform = str(platform or "unknown").strip().lower()
    if not media_type or len(media_type) > 160 or len(platform) > 100:
        raise ValueError("Valid media type and platform are required")
    if reference is not None:
        reference = str(reference).strip()
        if not reference or len(reference) > 1024 or "://" in reference or any(c.isspace() for c in reference):
            raise ValueError("A credential-free artifact reference is required")
        if "@" in reference and reference.rsplit("@", 1)[1].lower() != digest:
            raise ValueError("Reference digest does not match artifact identity")
    row = _get_or_add(db, GlobalArtifact, digest=digest, media_type=media_type, platform=platform)
    if reference:
        _get_or_add(db, ArtifactLocation, artifact_id=row.id, reference=reference,
            defaults={"provenance": dict(provenance or {})})
    return row


def assign_artifact(db, *, service_id, artifact_id, role="source"):
    _require(db, Service, service_id)
    _require(db, GlobalArtifact, artifact_id)
    if role not in {"source", "patched", "release"}:
        raise ValueError("Unknown artifact assignment role")
    return _get_or_add(db, ServiceArtifactAssignment, service_id=service_id, artifact_id=artifact_id, role=role)


def record_patch_lineage(db, *, patch_execution_id, source_artifact_id, output_artifact_id):
    patch = _require(db, PatchExecution, patch_execution_id)
    source = _require(db, GlobalArtifact, source_artifact_id)
    output = _require(db, GlobalArtifact, output_artifact_id)
    if source.id == output.id or source.platform != output.platform:
        raise ValueError("Patch lineage requires distinct compatible artifact identities")
    # The execution must itself retain immutable input/output references. A tag
    # or an archive checksum cannot establish an OCI manifest relationship.
    receipt = (patch.summary or {}).get("artifact_receipt") or {}
    source_reference = receipt.get("source_image") or patch.source_image or ""
    output_reference = receipt.get("immutable_destination") or patch.destination_image or ""
    if patch.status not in {"complete", "completed"} or not source_reference.endswith("@" + source.digest) or not output_reference.endswith("@" + output.digest):
        raise ValueError("Patch execution lacks completed digest-bound lineage")
    return _get_or_add(db, ArtifactPatchLineage, patch_execution_id=patch.id,
        source_artifact_id=source.id, output_artifact_id=output.id,
        defaults={"evidence": {"job_key": patch.job_key, "source_image": source_reference,
            "destination_image": output_reference, "status": patch.status}})


def _verified_receipt(patch, artifact):
    """Read authenticated worker output retained on its execution, never caller flags."""
    receipt = (patch.summary or {}).get("artifact_receipt") or {}
    if not isinstance(receipt, dict):
        return False
    signature = receipt.get("signature") or {}
    if not isinstance(signature, dict):
        return False
    reference = receipt.get("immutable_destination") or ""
    counters = [receipt.get("vulnerabilities_before"), receipt.get("vulnerabilities_after")]
    return bool(patch.status in {"complete", "completed"} and receipt.get("status") == "complete"
        and receipt.get("patch_status") in {"PATCHED", "PARTIALLY_PATCHED"}
        and receipt.get("delivery_status") == "delivered"
        and reference.endswith("@" + artifact.digest)
        and receipt.get("signature_status") == "verified"
        and signature.get("image") == reference and signature.get("generator") == "cosign"
        and signature.get("key_fingerprint") and signature.get("verified_at")
        and receipt.get("artifact_validation") == "docker-load"
        and receipt.get("validated_source") == "flattened-rootfs"
        and all(type(value) is int and value >= 0 for value in counters))


def _original_artifact_eligibility(db, artifact, service_id):
    """Accept original bytes only from the trusted publication worker's receipt.

    Scanner identity alone is insufficient. Authorization and validation remain
    service-specific, even when another service publishes identical bytes.
    """
    from .cyber_approvals import CyberApproval, digest
    from .execution_summaries import payload_digest
    from .models import Execution
    from .release_validity import require_current

    if service_id is None:
        return None
    approvals = db.scalars(select(CyberApproval).where(
        CyberApproval.service_id == service_id, CyberApproval.variant == "current_service")
        .order_by(CyberApproval.id.desc()))
    for approval in approvals:
        snapshot = approval.snapshot or {}
        originals = [item for item in snapshot.get("artifacts", [])
            if item.get("kind") == "image" and item.get("digest") == artifact.digest
            and str(item.get("reference", "")).endswith("@" + artifact.digest)]
        if not originals:
            continue
        # A newer decision for these exact original bytes supersedes older ones.
        denied = {"eligible": False, "reasons": ["Original artifact requires current published authorization and exact service validation"]}
        if (approval.status != "approved" or approval.revoked_at
                or not approval.decided_by_id or not approval.decision_rationale
                or approval.publish_status != "published"
                or digest(snapshot) != approval.snapshot_digest):
            return denied
        try:
            require_current(approval)
        except ValueError:
            return denied
        execution = db.get(Execution, approval.source_execution_id)
        if (not execution or not execution.complete or execution.service_id != service_id
                or snapshot.get("service_id") != service_id
                or snapshot.get("source_execution_id") != execution.id
                or snapshot.get("source_payload_digest") != payload_digest(execution.raw_payload)):
            return denied
        publication = approval.publication or {}
        manifest = publication.get("manifest") or {}
        fingerprint = snapshot.get("signing_fingerprint")
        if (publication.get("status") != "published"
                or publication.get("verification_status") != "verified"
                or publication.get("signature_status") != "verified"
                or publication.get("approval_id") != approval.id
                or publication.get("release_key") != approval.release_key
                or not fingerprint or publication.get("signing_fingerprint") != fingerprint
                or manifest.get("approval_id") != approval.id
                or manifest.get("snapshot_digest") != approval.snapshot_digest
                or manifest.get("artifacts") != publication.get("artifacts")):
            return denied
        for item in publication.get("artifacts", []):
            reference = str(item.get("reference", ""))
            signed = item.get("signature") or {}
            signature = signed.get("signature") or {}
            if (item.get("kind") != "image" or item.get("digest") != artifact.digest
                    or item.get("source_digest") != artifact.digest
                    or item.get("source_reference") not in {row["reference"] for row in originals}
                    or item.get("scan_identity_retained") is not True
                    or item.get("verification_status") != "verified"
                    or not reference.endswith("@" + artifact.digest)
                    or signed.get("signature_status") != "verified"
                    or signature.get("image") != reference
                    or signature.get("generator") != "cosign"
                    or signature.get("key_fingerprint") != fingerprint
                    or not signature.get("verified_at")):
                continue
            validation = db.scalar(select(DeploymentValidationRun).where(
                DeploymentValidationRun.service_id == service_id,
                DeploymentValidationRun.artifact_reference == reference)
                .order_by(DeploymentValidationRun.id.desc()))
            if validation is not None and validation.status == "VERIFIED":
                return {"eligible": True, "reasons": [], "approval_id": approval.id,
                        "validation_run_id": validation.id}
        return denied
    return None


def artifact_eligibility(db, artifact_id, service_id=None):
    artifact = _require(db, GlobalArtifact, artifact_id)
    lineages = list(db.scalars(select(ArtifactPatchLineage).where(ArtifactPatchLineage.output_artifact_id == artifact_id)))
    for lineage in lineages:
        patch = db.get(PatchExecution, lineage.patch_execution_id)
        if patch and _verified_receipt(patch, artifact):
            receipt = patch.summary["artifact_receipt"]
            source = db.get(GlobalArtifact, lineage.source_artifact_id)
            if source and receipt.get("source_image", "").endswith("@" + source.digest):
                validation = db.scalar(select(DeploymentValidationRun).where(
                    DeploymentValidationRun.service_id == (service_id if service_id is not None else patch.service_id),
                    DeploymentValidationRun.artifact_reference == receipt["immutable_destination"]).order_by(DeploymentValidationRun.id.desc()))
                if validation is not None and validation.status == "VERIFIED":
                    return {"eligible": True, "reasons": [], "patch_execution_id": patch.id,
                            "validation_run_id": validation.id}
                return {"eligible": False, "reasons": ["Patched artifact signature and scan verified; exact artifact service validation required"]}
    original = _original_artifact_eligibility(db, artifact, service_id)
    if original is not None:
        return original
    reasons = [] if lineages else ["No digest-bound completed patch lineage"]
    reasons.append("No durable digest-bound patch scan and verified signature receipt")
    return {"eligible": False, "reasons": reasons}


def register_patch_artifacts(db, *, patch_execution_id, media_type, platform="unknown", source_media_type=None, source_platform=None):
    """Import a retained worker receipt. The caller must not accept receipt JSON."""
    patch = _require(db, PatchExecution, patch_execution_id)
    receipt = (patch.summary or {}).get("artifact_receipt") or {}
    source_ref, output_ref = receipt.get("source_image", ""), receipt.get("immutable_destination", "")
    if patch.status not in {"complete", "completed"} or "@" not in source_ref or "@" not in output_ref:
        raise ValueError("Completed immutable worker artifact receipt required")
    source_digest, output_digest = validate_digest(source_ref.rsplit("@", 1)[1]), validate_digest(output_ref.rsplit("@", 1)[1])
    source = register_artifact(db, digest=source_digest, media_type=source_media_type or media_type, platform=source_platform or platform, reference=source_ref)
    output = register_artifact(db, digest=output_digest, media_type=media_type, platform=platform, reference=output_ref)
    assign_artifact(db, service_id=patch.service_id, artifact_id=source.id)
    assign_artifact(db, service_id=patch.service_id, artifact_id=output.id, role="patched")
    record_patch_lineage(db, patch_execution_id=patch.id, source_artifact_id=source.id, output_artifact_id=output.id)
    return source, output


def recommend_artifact(db, *, service_id, source_artifact_id, target_artifact_id):
    _require(db, Service, service_id)
    source = _require(db, GlobalArtifact, source_artifact_id)
    target = _require(db, GlobalArtifact, target_artifact_id)
    if source.id == target.id or source.platform != target.platform:
        raise ValueError("Recommendation requires distinct compatible artifacts")
    assignment = db.scalar(select(ServiceArtifactAssignment).filter_by(service_id=service_id, artifact_id=source.id))
    lineage = db.scalar(select(ArtifactPatchLineage).filter_by(source_artifact_id=source.id, output_artifact_id=target.id))
    if assignment is None or lineage is None:
        raise ValueError("Recommendation requires service source assignment and patch lineage")
    return _get_or_add(db, ArtifactRecommendation, service_id=service_id, source_artifact_id=source.id, target_artifact_id=target.id)

def associate_known_source_images(db, *, artifact_id):
    """Reuse existing manifest metadata; scanner digests cannot create identities."""
    artifact = _require(db, GlobalArtifact, artifact_id)
    identities = list(db.scalars(select(GlobalArtifact).where(GlobalArtifact.digest == artifact.digest)))
    if len(identities) != 1 or artifact.platform == "unknown":
        return []
    assignments = []
    for image in db.scalars(select(ServiceImage).join(Service, Service.id == ServiceImage.service_id).where(
        ServiceImage.image_digest == artifact.digest, ServiceImage.lifecycle_status == "active",
        Service.lifecycle_status == "active")):
        reference = str(image.image_reference or "")
        if "@" in reference and reference.rsplit("@", 1)[1] != artifact.digest:
            continue
        assignments.append(assign_artifact(db, service_id=image.service_id, artifact_id=artifact.id))
    return assignments


def has_current_source_image(db, *, service_id, artifact_id):
    """Historical assignments alone cannot prove current service inventory."""
    artifact = _require(db, GlobalArtifact, artifact_id)
    images = db.scalars(select(ServiceImage).join(Service, Service.id == ServiceImage.service_id).where(
        ServiceImage.service_id == service_id, ServiceImage.image_digest == artifact.digest,
        ServiceImage.lifecycle_status == "active", Service.lifecycle_status == "active"))
    return any("@" not in str(image.image_reference or "") or
        image.image_reference.rsplit("@", 1)[1] == artifact.digest for image in images)


def generate_shared_recommendations(db, *, validation_run_id):
    """Propose reuse only after the producing service verifies the exact output.

    Receiving services still require their own validation and release approval.
    Existing decisions are preserved; callers own the transaction.
    """
    validation = _require(db, DeploymentValidationRun, validation_run_id)
    if validation.status != "VERIFIED" or not validation.artifact_reference:
        return []
    rows = []
    seen = set()
    for lineage in db.scalars(select(ArtifactPatchLineage).join(PatchExecution,
        PatchExecution.id == ArtifactPatchLineage.patch_execution_id).where(
        PatchExecution.service_id == validation.service_id).order_by(ArtifactPatchLineage.id)):
        patch = db.get(PatchExecution, lineage.patch_execution_id)
        target = db.get(GlobalArtifact, lineage.output_artifact_id)
        source = db.get(GlobalArtifact, lineage.source_artifact_id)
        if not patch or patch.service_id != validation.service_id or not target or not source:
            continue
        receipt = (patch.summary or {}).get("artifact_receipt") or {}
        if receipt.get("immutable_destination") != validation.artifact_reference or not _verified_receipt(patch, target):
            continue
        if not receipt.get("source_image", "").endswith("@" + source.digest):
            continue
        eligibility = artifact_eligibility(db, target.id, service_id=patch.service_id)
        if not eligibility["eligible"] or eligibility.get("validation_run_id") != validation.id:
            continue
        associate_known_source_images(db, artifact_id=source.id)
        services = db.scalars(select(Service).join(ServiceArtifactAssignment,
            ServiceArtifactAssignment.service_id == Service.id).where(
            ServiceArtifactAssignment.artifact_id == source.id,
            ServiceArtifactAssignment.role == "source", Service.id != patch.service_id,
            Service.lifecycle_status == "active").distinct())
        for service in services:
            if not has_current_source_image(db, service_id=service.id, artifact_id=source.id):
                continue
            key = (service.id, source.id, target.id)
            if key in seen:
                continue
            seen.add(key)
            rows.append(recommend_artifact(db, service_id=service.id,
                source_artifact_id=source.id, target_artifact_id=target.id))
    return rows


RECOMMENDATION_JOB_KIND = "artifact_recommendations"


def enqueue_recommendation_reconciliation(db, *, validation_run_id):
    """Enqueue with the validation transaction; no external effects or commits."""
    from . import durable_jobs
    validation = _require(db, DeploymentValidationRun, validation_run_id)
    if validation.status != "VERIFIED":
        return None
    # Internal transactional outbox: terminal validation must survive user queue
    # saturation. One row per validation; normal leases still bound execution.
    return _get_or_add(db, durable_jobs.DurableJob,
        dedupe_key=f"artifact-recommendations:{validation.id}",
        defaults={"id": uuid.uuid4().hex, "kind": RECOMMENDATION_JOB_KIND,
            "payload": {"validation_run_id": validation.id},
            "service_id": validation.service_id, "max_attempts": 5})


def handle_recommendation_reconciliation(ctx, payload):
    """Replay-safe internal projection from authenticated retained evidence."""
    from .database import SessionLocal
    from .durable_jobs import JobError
    ctx.check()
    with SessionLocal() as db:
        validation = db.get(DeploymentValidationRun, payload.get("validation_run_id"))
        if not validation or validation.service_id != ctx.job.service_id:
            raise JobError("Retained validation is unavailable")
        rows = generate_shared_recommendations(db, validation_run_id=validation.id)
        ctx.check()
        db.commit()
        return {"validation_run_id": validation.id, "recommendation_count": len(rows)}
