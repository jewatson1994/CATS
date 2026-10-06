"""Artifact workspace projections bounded to current revisions and evidence."""
from types import SimpleNamespace
from sqlalchemy import String, and_, case, cast, func, literal, or_, select
from .models import (DeploymentValidationRun, Execution, ServiceArtifact,
                     ServiceArtifactRevision, ServiceImage)


def load_artifact_workspace(db, service_id):
    artifacts = list(db.scalars(select(ServiceArtifact).where(ServiceArtifact.service_id == service_id)
                               .order_by(ServiceArtifact.created_at.desc())))
    ranked = select(ServiceArtifactRevision.id, func.row_number().over(
        partition_by=ServiceArtifactRevision.artifact_id,
        order_by=ServiceArtifactRevision.revision_number.desc()).label("rank")).join(
            ServiceArtifact, ServiceArtifact.id == ServiceArtifactRevision.artifact_id).where(
                ServiceArtifact.service_id == service_id).subquery()
    revisions = {row.artifact_id: row for row in db.scalars(select(ServiceArtifactRevision).where(
        ServiceArtifactRevision.id.in_(select(ranked.c.id).where(ranked.c.rank == 1))))}
    selected_ids = [revision.id for revision in revisions.values()]
    run_rank = select(DeploymentValidationRun.id, func.row_number().over(
        partition_by=DeploymentValidationRun.artifact_revision_id,
        order_by=(DeploymentValidationRun.created_at.desc(), DeploymentValidationRun.id.desc())).label("rank")
        ).where(DeploymentValidationRun.service_id == service_id,
                DeploymentValidationRun.artifact_revision_id.in_(selected_ids)).subquery()
    columns = [getattr(DeploymentValidationRun, key) for key in
        ("artifact_revision_id", "run_key", "status", "reason_category", "security_policy_violations",
         "completed_at", "started_at", "created_at", "reason")]
    validations = {row["artifact_revision_id"]: SimpleNamespace(**dict(row)) for row in db.execute(
        select(*columns).where(DeploymentValidationRun.id.in_(
            select(run_rank.c.id).where(run_rank.c.rank == 1)))).mappings()} if selected_ids else {}
    images = list(db.scalars(select(ServiceImage).where(ServiceImage.service_id == service_id)))
    return artifacts, revisions, validations, images


def helm_original_expression(dialect):
    """SQL truth of ``artifact_type == "helm" and bool(helm_source_files)`` on retained JSON."""
    source = Execution.raw_payload["helm_source_files"]
    kind = func.json_typeof(source) if dialect == "postgresql" else func.json_type(Execution.raw_payload, "$.helm_source_files")
    # Preserve Python truthiness of retained JSON, including legacy scalar shapes.
    text = cast(source.as_string(), String)
    object_nonempty, array_nonempty = text != "{}", text != "[]"
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import JSONB
        object_nonempty = cast(source, JSONB) != cast(literal("{}"), JSONB)
        array_nonempty = cast(source, JSONB) != cast(literal("[]"), JSONB)
    truthy = or_(and_(kind == "object", object_nonempty),
        and_(kind == "array", array_nonempty),
        and_(kind.in_(("string", "text")), text != ""),
        case((kind.in_(("number", "integer", "real")), source.as_float() != 0), else_=False),
        kind == "true" if dialect != "postgresql" else and_(kind == "boolean", text == "true"))
    return and_(Execution.raw_payload["artifact_type"].as_string() == "helm", truthy)


def latest_original_helm(db, service_id):
    truthy = helm_original_expression(db.get_bind().dialect.name)
    return db.scalar(select(Execution).where(Execution.service_id == service_id,
        Execution.scan_scope == "service",
        truthy).order_by(Execution.scanned_at.desc(), Execution.id.asc()).limit(1))


def latest_validation_warning(db, service_id):
    keys = ("id", "run_key", "status", "reason", "reason_category")
    row = db.execute(select(*(getattr(DeploymentValidationRun, key) for key in keys)).where(
        DeploymentValidationRun.service_id == service_id).order_by(
            DeploymentValidationRun.created_at.desc()).limit(1)).mappings().first()
    return [SimpleNamespace(**dict(row))] if row else []
