"""Small remediation history projections; report evidence stays on its own route."""
from types import SimpleNamespace

from sqlalchemy import select

from .models import RemediationExecution, ServiceImage


def remediation_history(db, service_id, limit=100):
    names = (
        "id", "job_key", "finding_type", "original_revision", "resulting_revision",
        "retry_of_id", "status", "output_mode", "failure_reason", "rollback_reference",
        "source_execution_id", "source_version_id", "revision_number", "remediation_status",
        "delivery_status", "verification_status", "signing_status", "artifact_digest",
        "started_at", "completed_at", "artifact_path", "created_at",
    )
    statement = select(*(getattr(RemediationExecution, name) for name in names)).where(
        RemediationExecution.service_id == service_id).order_by(
        RemediationExecution.created_at.desc(), RemediationExecution.id.desc()).limit(limit)
    return [SimpleNamespace(**dict(row)) for row in db.execute(statement).mappings()]


def active_image_references(db, service_id):
    return set(db.scalars(select(ServiceImage.image_reference).where(
        ServiceImage.service_id == service_id, ServiceImage.lifecycle_status == "active")))
