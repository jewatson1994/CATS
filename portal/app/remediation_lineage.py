"""Artifact provenance for intentional ingestion; never promotes a candidate.

Import before metadata.create_all. Call record_reingestion_provenance after the
ingested Execution is flushed, in the same transaction. Worker output inventory
belongs in validation_results.artifact_identities (kind, digest, reference,
identity_type); archive hashes must never be substituted for OCI image digests.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, JSON, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import Execution, RemediationExecution, ServiceVersion


class ArtifactProvenance(Base):
    __tablename__ = "remediation_artifact_provenance"
    __table_args__ = (UniqueConstraint("execution_id", "remediation_id", "artifact_kind", "artifact_digest", "identity_type", name="uq_remediation_artifact_provenance"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    execution_id: Mapped[int] = mapped_column(ForeignKey("executions.id"), index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    service_version_id: Mapped[int | None] = mapped_column(ForeignKey("service_versions.id"))
    remediation_id: Mapped[int] = mapped_column(ForeignKey("remediation_executions.id"), index=True)
    artifact_kind: Mapped[str] = mapped_column(String(30))
    artifact_digest: Mapped[str] = mapped_column(String(80))
    identity_type: Mapped[str] = mapped_column(String(30))
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def immutable_digest(value):
    value = str(value or "").strip().lower()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value if re.fullmatch(r"sha256:[0-9a-f]{64}", value) else None


def _identity(row, kind=None, identity_type=None):
    if not isinstance(row, dict):
        row = {"reference": row}
    kind = str(kind or row.get("kind") or row.get("type") or "").lower()
    kind = "helm" if kind in {"chart", "helm_chart"} else kind
    reference = row.get("reference") or row.get("image") or row.get("candidate") or row.get("name") or ""
    digest = immutable_digest(row.get("digest") or row.get("image_digest") or reference)
    identity_type = identity_type or row.get("identity_type") or "oci_manifest"
    if row.get("sha256") and not digest and kind == "helm":
        digest = immutable_digest("sha256:" + str(row["sha256"]).removeprefix("sha256:"))
        identity_type = "package_sha256"
    return {"kind": kind, "digest": digest, "reference": str(reference), "identity_type": identity_type,
            "verification": row.get("verification"), "signature_status": row.get("signature_status"),
            "post_remediation_scan": row.get("post_remediation_scan")} if digest and kind in {"image", "helm"} else None


def ingested_artifacts(payload):
    overview = payload.get("service_overview") or {}
    rows = []
    for key in ("images", "container_images"):
        rows.extend(_identity(row, "image") for row in overview.get(key, []) or [])
    rows.extend(_identity(row) for row in overview.get("artifacts", []) or [])
    rows.extend(_identity(row, "image") for row in payload.get("findings", []) or [])
    rows.extend(_identity(row, "helm") for row in overview.get("charts", []) or [])
    return { (row["kind"], row["digest"], row["identity_type"]): row for row in rows if row }


def remediation_artifacts(record):
    results = record.validation_results or {}
    rows = []
    if record.output_mode == "publish":
        rows.extend(_identity(row, "image") for row in record.patched_images or [] if row.get("candidate"))
    for chart in results.get("charts", []) or []:
        if chart.get("package_status") == "PACKAGED":
            rows.append(_identity({"sha256": chart.get("sha256"), "reference": chart.get("name")}, "helm"))
        if chart.get("publish_status") == "PUBLISHED":
            rows.append(_identity(chart, "helm"))
    # Explicit delivery identities carry their own verification/signature snapshot.
    rows.extend(_identity(row) for row in results.get("artifact_identities", []) or [])
    return {(row["kind"], row["digest"], row["identity_type"]): row for row in rows if row}


def record_reingestion_provenance(db, execution, payload):
    """Snapshot evidence per matched artifact within this service, idempotently.

    Runtime verification and signatures are candidate-level historical evidence;
    they do not certify the newly ingested release or any unmatched artifacts.
    """
    incoming = ingested_artifacts(payload)
    if not incoming:
        return []
    existing = {(row.remediation_id, row.artifact_kind, row.artifact_digest, row.identity_type)
                for row in db.scalars(select(ArtifactProvenance).where(ArtifactProvenance.execution_id == execution.id))}
    for record in db.scalars(select(RemediationExecution).where(RemediationExecution.service_id == execution.service_id)):
        source_version = db.get(ServiceVersion, record.source_version_id) if record.source_version_id else None
        source_execution = db.get(Execution, record.source_execution_id) if record.source_execution_id else None
        if source_version and source_version.service_id != execution.service_id:
            continue
        if source_execution and (source_execution.service_id != execution.service_id or
                (record.source_version_id and source_execution.service_version_id != record.source_version_id)):
            continue
        outputs = remediation_artifacts(record)
        for key in incoming.keys() & outputs.keys():
            marker = (record.id, *key)
            if marker in existing:
                continue
            artifact_evidence = outputs[key]
            verification = artifact_evidence.get("verification")
            runtime_status = verification.get("status", "not_verified") if isinstance(verification, dict) else record.verification_status
            # Keep producer service/version and evidence as an immutable snapshot.
            db.add(ArtifactProvenance(execution_id=execution.id, service_id=execution.service_id,
                service_version_id=execution.service_version_id, remediation_id=record.id,
                artifact_kind=key[0], artifact_digest=key[1], identity_type=key[2], evidence={
                    "label": "Known Artifact", "source_execution_id": record.source_execution_id,
                    "source_version_id": record.source_version_id,
                    "source_version": source_version.version if source_version else record.original_revision,
                    "revision_number": record.revision_number, "job_key": record.job_key,
                    "post_remediation_scan": artifact_evidence.get("post_remediation_scan") or (record.validation_results or {}).get("status", "NOT RUN"),
                    "remediation_status": record.remediation_status,
                    "runtime_verification": runtime_status,
                    "verification_artifact_digest": verification.get("artifact_digest") if isinstance(verification, dict) else record.artifact_digest,
                    "signature": artifact_evidence.get("signature_status") or record.signing_status,
                    "evidence_scope": "producing_candidate", "release_lineage": False,
                }))
            existing.add(marker)
    db.flush()
    return provenance_for_execution(db, execution.id)


def provenance_for_execution(db, execution_id):
    return [{"artifact_kind": row.artifact_kind, "digest": row.artifact_digest,
             "identity_type": row.identity_type, "remediation_id": row.remediation_id,
             **row.evidence} for row in db.scalars(select(ArtifactProvenance).where(
                 ArtifactProvenance.execution_id == execution_id).order_by(ArtifactProvenance.id))]
