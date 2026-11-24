"""Keep automatically scanned GitLab projects private until a group claims them."""
from __future__ import annotations

import secrets
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, case, event, func, literal, select, text, update
from sqlalchemy.orm import with_loader_criteria

from .auth import AuthContext, record_audit, require_user
from .database import get_db
from .models import Execution, Group, Service, ServiceGroup, utcnow
from .operating_mode import is_replica
from .replica_models import reserve_sqlite_writer
from .topic_intake_models import GitLabTopicSource, TopicIntakeGroup, TopicProject, TopicRevision
from .topic_scope_rules import effective_project_claim_group, scope_sources

router = APIRouter(prefix="/api/unclaimed-services", tags=["Unclaimed services"])
INCLUDE_HELD = {"include_topic_intake": True}


def _filter_ordinary_reads(state):
    if state.is_select and not state.execution_options.get("include_topic_intake"):
        state.statement = state.statement.options(
            with_loader_criteria(Service, Service.lifecycle_status.is_distinct_from("unclaimed"),
                                 include_aliases=True, propagate_to_loaders=False),
            with_loader_criteria(Group, ~Group.id.in_(select(TopicIntakeGroup.group_id)),
                                 include_aliases=True, propagate_to_loaders=False))


def scope_user_session(db):
    """Apply to human requests; worker ingestion and the explicit claim have their own authority."""
    if not db.info.get("topic_intake_filtered"):
        event.listen(db, "do_orm_execute", _filter_ordinary_reads)
        db.info["topic_intake_filtered"] = True


def held_for_user_request(db, service_id):
    row = db.identity_map.get(db.identity_key(Service, service_id))
    if row is not None:
        return row.lifecycle_status == "unclaimed"
    if service_id in db.info.get("topic_visible_service_ids", ()):
        return False
    # One indexed, bounded probe covers ordinary site sizes and empty intake.
    if "topic_held_ids" not in db.info:
        ids = list(db.scalars(select(Service.id).where(Service.lifecycle_status == "unclaimed")
                              .limit(257).execution_options(**INCLUDE_HELD)))
        db.info["topic_held_ids"] = set(ids) if len(ids) < 257 else None
    if db.info["topic_held_ids"] is not None:
        return service_id in db.info["topic_held_ids"]
    if db.scalar(select(Service.id).where(Service.id == service_id)) is None:
        return True
    db.info.setdefault("topic_visible_service_ids", set()).add(service_id)
    return False


def exact_execution():
    return and_(Execution.id == TopicRevision.execution_id, Execution.service_id == TopicProject.service_id,
                Execution.execution_key == literal("public:") + TopicRevision.scan_job_id,
                Execution.commit_sha == TopicRevision.commit_sha)


def _project_claim_group():
    # Only historical single-namespace sources have an implicit destination.
    return func.coalesce(TopicProject.claim_group_id,
                         case((GitLabTopicSource.namespace != "", GitLabTopicSource.claim_group_id)))


def _claim_scope(auth):
    return [a for a in auth.effective_assignments if a.service_id is None and
            {"service.edit", "config.manage"}.intersection(a.role.permissions or [])]


def may_view_unclaimed(auth):
    return bool(auth and not is_replica() and _claim_scope(auth))


def claim_groups(db, auth):
    if not may_view_unclaimed(auth):
        raise HTTPException(403, "Group service management permission required")
    assignments = _claim_scope(auth)
    query = select(Group.id, Group.name).where(~Group.id.in_(select(TopicIntakeGroup.group_id)))
    if not any(a.group_id is None for a in assignments):
        query = query.where(Group.id.in_({a.group_id for a in assignments}))
    return [dict(row) for row in db.execute(query.order_by(Group.name, Group.id)).mappings()]


def _holding_group(db):
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(73488343)"))
    marker = db.get(TopicIntakeGroup, 1)
    if marker is None:
        # An existing group with a similar display name can never become the holding group.
        group = Group(name="CATS Discovery intake " + uuid4().hex, description="System-managed unclaimed services")
        db.add(group)
        db.flush()
        db.add(TopicIntakeGroup(id=1, group_id=group.id))
        db.flush()
        return group
    return db.get(Group, marker.group_id, execution_options=INCLUDE_HELD)


def ensure_intake_service(db, project):
    """A new, opaque service identity; repeated observations keep its evidence and owner."""
    reserve_sqlite_writer(db)
    project = db.scalar(select(TopicProject).where(TopicProject.id == project.id)
                        .with_for_update().execution_options(populate_existing=True))
    if project.service_id is not None:
        service = db.get(Service, project.service_id, execution_options=INCLUDE_HELD)
        if service is None:
            raise ValueError("The topic project service is unavailable")
        return service
    group = _holding_group(db)
    service = Service(service_key="gitlab-" + uuid4().hex, name=project.project_path.rsplit("/", 1)[-1][:240],
                      lifecycle_status="unclaimed")
    db.add(service)
    db.flush()
    # Both endpoints of this new membership are private. Writing it directly keeps
    # existing browser caches valid. The ordinary ownership update on claim rotates them.
    db.connection().execute(ServiceGroup.__table__.insert().values(service_id=service.id, group_id=group.id))
    db.expire(group, ["services"])
    project.service_id = service.id
    db.flush()
    return service


@router.get("")
def unclaimed_services(page: int = Query(1, ge=1), db=Depends(get_db),
                       auth: AuthContext = Depends(require_user)):
    groups = claim_groups(db, auth)
    allowed = [g["id"] for g in groups]
    source, project, rev = GitLabTopicSource, TopicProject, TopicRevision
    destination = _project_claim_group()
    query = (select(project.id, project.project_path, project.web_url, source.name.label("source_name"),
                    destination.label("claim_group_id"), rev.commit_sha, rev.status, Execution.id.label("execution_id"),
                    Execution.scanned_at, Execution.complete)
             .join(source, source.id == project.source_id)
             .join(rev, and_(rev.id == project.latest_revision_id, rev.project_id == project.id))
             .join(Execution, exact_execution())
             .join(Service, Service.id == project.service_id)
             .join(ServiceGroup, ServiceGroup.service_id == Service.id)
             .join(TopicIntakeGroup, TopicIntakeGroup.group_id == ServiceGroup.group_id)
             .where(project.claimed_at.is_(None), project.eligible.is_(True),
                    source.enabled.is_(True), destination.in_(allowed),
                    Service.lifecycle_status == "unclaimed", rev.status == "ready", Execution.complete.is_(True))
             .execution_options(**INCLUDE_HELD))
    total = db.scalar(query.with_only_columns(func.count(project.id))) or 0
    pages = max(1, (total + 49) // 50)
    page = min(page, pages)
    query = query.order_by(project.id.desc()).offset((page - 1) * 50).limit(50)
    items = []
    for row in db.execute(query).mappings():
        item = dict(row)
        item["project_name"] = row.project_path.rsplit("/", 1)[-1]
        item["scanned"] = True
        item["claim_group_ids"] = allowed if auth.can_manage_group(None) else [row.claim_group_id]
        items.append(item)
    return {"items": items, "groups": groups, "total": total, "pages": pages, "page": page}


class ClaimInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group_id: int = Field(gt=0, strict=True)
    execution_id: int = Field(gt=0, strict=True)
    csrf_token: str


@router.post("/{project_id}/claim")
def claim_service(project_id: int, body: ClaimInput, db=Depends(get_db), auth: AuthContext = Depends(require_user)):
    if not secrets.compare_digest(body.csrf_token.encode(), auth.csrf_token.encode()):
        raise HTTPException(403, "Invalid CSRF token")
    allowed = {row["id"] for row in claim_groups(db, auth)}
    reserve_sqlite_writer(db)
    # The poller locks its source before it updates a project or advances its revision.
    source = db.scalar(select(GitLabTopicSource).join(TopicProject, TopicProject.source_id == GitLabTopicSource.id)
                       .where(TopicProject.id == project_id, GitLabTopicSource.enabled.is_(True),
                              _project_claim_group().in_(allowed))
                       .with_for_update(of=GitLabTopicSource, read=True))
    if source is None:
        raise HTTPException(404, "Unclaimed service not found")
    project = db.scalar(select(TopicProject).where(TopicProject.id == project_id, TopicProject.source_id == source.id,
                                                 TopicProject.eligible.is_(True))
                        .with_for_update(of=TopicProject).execution_options(populate_existing=True))
    if project is None:
        raise HTTPException(404, "Unclaimed service not found")
    route_group = effective_project_claim_group(source, project, None, scope_sources(db, source))
    if route_group not in allowed:
        raise HTTPException(404, "Unclaimed service not found")
    if body.group_id not in allowed or (body.group_id != route_group and not auth.can_manage_group(None)):
        raise HTTPException(403, "You cannot claim this service for the selected group")
    service = db.scalar(select(Service).where(Service.id == project.service_id).with_for_update()
                        .execution_options(**INCLUDE_HELD, populate_existing=True))
    if project.claimed_at is not None:
        # Only an exact retry by the original claimant may replay its receipt.
        owner = db.scalar(select(ServiceGroup.group_id).where(ServiceGroup.service_id == project.service_id))
        if (service and project.claimed_by_id == auth.user.id and owner == body.group_id
                and project.claimed_execution_id == body.execution_id):
            return {"service_id": service.id, "service_key": service.service_key}
        raise HTTPException(409, "Another claim already completed")
    ready_execution_id = db.scalar(select(Execution.id).select_from(TopicProject)
        .join(TopicRevision, TopicRevision.project_id == TopicProject.id).join(Execution, exact_execution())
        .where(TopicRevision.id == project.latest_revision_id, TopicRevision.project_id == project.id,
               TopicRevision.status == "ready", TopicProject.id == project.id, Execution.complete.is_(True)))
    if service is None or service.lifecycle_status != "unclaimed" or ready_execution_id is None:
        raise HTTPException(409, "Refresh the list after the latest project revision finishes scanning and ingestion.")
    if ready_execution_id != body.execution_id:
        raise HTTPException(409, "The reviewed scan has changed. Refresh the list and review the latest scan before claiming.")
    current = db.execute(update(ServiceGroup).where(ServiceGroup.service_id == service.id,
        ServiceGroup.group_id.in_(select(TopicIntakeGroup.group_id))).values(group_id=body.group_id))
    if current.rowcount != 1:
        raise HTTPException(409, "The service is outside the unclaimed intake group")
    service.lifecycle_status = "active"
    project.claimed_at, project.claimed_by_id = utcnow(), auth.user.id
    project.claimed_execution_id = ready_execution_id
    record_audit(db, auth, "discovery.service_claimed", "service", service.id, topic_project_id=project.id,
                 group_id=body.group_id, execution_id=ready_execution_id)
    db.commit()
    return {"service_id": service.id, "service_key": service.service_key}
