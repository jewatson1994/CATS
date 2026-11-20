"""Configure trusted GitLab sources and inspect their asynchronous intake progress."""
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import load_only

from .auth import AuthContext, record_audit, require_user
from .database import get_db
from .discovery_gitlab import GitLabSourceError
from .durable_jobs import DurableJob
from .models import Group
from .remediation_list_queries import page_window
from .replica_models import reserve_sqlite_writer
from .secrets import encrypt_secret, secret_configured
from .topic_intake_models import GitLabTopicSource, TopicIntakeGroup, TopicProject, TopicRevision

router = APIRouter(tags=["GitLab topic intake"])
SOURCES = "/api/admin/topic-polling/sources"


def administrator(auth: AuthContext = Depends(require_user)):
    if not auth.can_manage_group(None):
        raise HTTPException(403, "Global configuration permission is required")
    return auth


def administrator_write(request: Request, auth=Depends(administrator)):
    from .main import check_csrf
    token = request.headers.get("X-CSRF-Token", "")
    check_csrf(auth, token if token.isascii() else "")
    return auth


class SourceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=160)
    origin: str = Field(min_length=1, max_length=255)
    namespace: str = Field(min_length=1, max_length=255)
    topic: str = Field(min_length=1, max_length=255)
    claim_group_id: int = Field(gt=0)
    poll_seconds: int = Field(default=300, ge=30, le=86400)
    enabled: bool = False
    token: SecretStr | None = None
    clear_token: bool = False


def _view(source, job=None):
    fields = ("id", "name", "origin", "namespace", "topic", "claim_group_id", "enabled", "poll_seconds",
              "last_attempt_at", "last_success_at", "last_error")
    result = {key: getattr(source, key) for key in fields}
    result["has_token"] = secret_configured(source.token)
    result["latest_job"] = None
    if job:
        errors = (job.result or {}).get("project_errors", [])
        result["latest_job"] = {"id": job.id, "status": job.status, "stage": job.stage,
                                "project_errors": [{"gitlab_project_id": e.get("gitlab_project_id"),
                                                    "message": e["message"]} for e in errors[:20]]}
    return result


def _source(db, source_id, *, lock=False):
    if lock:
        reserve_sqlite_writer(db)
    source = db.get(GitLabTopicSource, source_id, with_for_update=lock)
    if source is None:
        raise HTTPException(404, "GitLab topic source not found")
    return source


def _save(db, auth, value, source=None):
    from .discovery_gitlab import validate_topic_scope
    identity = (value.origin.rstrip("/"), value.namespace, value.topic, value.claim_group_id)
    if source and identity != (source.origin, source.namespace, source.topic, source.claim_group_id):
        raise HTTPException(409, "A source's GitLab scope and claim group are fixed when it is created")
    if source is None or value.enabled:
        try:
            origin, namespace, topic = validate_topic_scope(*identity[:3])
        except GitLabSourceError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
    if not source:
        reserved = db.scalar(select(TopicIntakeGroup.group_id).where(TopicIntakeGroup.id == 1))
        if value.claim_group_id == reserved or db.get(Group, value.claim_group_id) is None:
            raise HTTPException(422, "Choose an existing destination group")
        source = GitLabTopicSource(origin=origin, namespace=namespace, topic=topic,
                                   claim_group_id=value.claim_group_id)
        db.add(source)
    token = value.token.get_secret_value() if value.token else ""
    if token and (value.clear_token or len(token) > 4096 or any(not 33 <= ord(c) <= 126 for c in token)):
        raise HTTPException(422, "Enter a valid GitLab token or choose to clear the stored token")
    if token:
        try:
            source.token = encrypt_secret(token)
        except ValueError:
            raise HTTPException(503, "The portal encryption key must be configured to store a GitLab token") from None
    elif value.clear_token:
        source.token = ""
    source.name, source.enabled, source.poll_seconds = value.name, value.enabled, value.poll_seconds
    source.authorized_by_id, source.config_revision = auth.user.id, uuid4().hex
    try:
        db.flush()
        record_audit(db, auth, "topic.source.configured", "gitlab_topic_source", source.id,
                     origin=source.origin, namespace=source.namespace, topic=source.topic,
                     claim_group_id=source.claim_group_id, enabled=source.enabled, poll_seconds=source.poll_seconds)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A source already uses this name or GitLab scope") from None
    return _view(source)


@router.get("/admin/topic-polling")
def settings_page(request: Request, auth=Depends(administrator)):
    from .main import page_context, templates
    return templates.TemplateResponse(request, "topic_polling.html", page_context(auth))


@router.get(SOURCES)
def source_list(auth=Depends(administrator), db=Depends(get_db)):
    sources = db.execute(
        select(GitLabTopicSource, DurableJob)
        .options(load_only(DurableJob.id, DurableJob.status, DurableJob.stage, DurableJob.result))
        .outerjoin(DurableJob, DurableJob.id == GitLabTopicSource.latest_job_id)
        .order_by(GitLabTopicSource.name))
    groups = db.execute(select(Group.id, Group.name).where(
        ~Group.id.in_(select(TopicIntakeGroup.group_id))).order_by(Group.name))
    return {"sources": [_view(source, job) for source, job in sources],
            "groups": [dict(row) for row in groups.mappings()]}


@router.post(SOURCES, status_code=201)
def create_source(value: SourceInput, auth=Depends(administrator_write), db=Depends(get_db)):
    return _save(db, auth, value)


@router.put(SOURCES + "/{source_id}")
def update_source(source_id: int, value: SourceInput, auth=Depends(administrator_write), db=Depends(get_db)):
    return _save(db, auth, value, _source(db, source_id, lock=True))


@router.post(SOURCES + "/{source_id}/poll", status_code=202)
def poll_now(source_id: int, auth=Depends(administrator_write), db=Depends(get_db)):
    from .gitlab_topic_poll import enqueue
    source = _source(db, source_id, lock=True)
    if not source.enabled:
        raise HTTPException(409, "Enable this source before polling it")
    job = enqueue(db, source, actor_id=auth.user.id)
    record_audit(db, auth, "topic.poll.requested", "gitlab_topic_source", source.id, job_id=job.id)
    db.commit()
    return {"job_id": job.id, "status": job.status}


@router.get(SOURCES + "/{source_id}/projects")
def projects(source_id: int, page: int = 1, auth=Depends(administrator), db=Depends(get_db)):
    source = _source(db, source_id)
    total = db.scalar(select(func.count(TopicProject.id)).where(TopicProject.source_id == source_id)) or 0
    page, pages, offset = page_window(total, page, 50)
    records = db.execute(select(TopicProject, TopicRevision)
        .outerjoin(TopicRevision, (TopicRevision.id == TopicProject.latest_revision_id) &
                   (TopicRevision.project_id == TopicProject.id))
        .where(TopicProject.source_id == source_id)
        .order_by(TopicProject.project_path, TopicProject.id).limit(50).offset(offset))
    items = []
    for project, revision in records:
        status = revision.status if revision else "pending"
        if not project.eligible:
            status = "out_of_scope"
        items.append({"id": project.id, "project_path": project.project_path, "web_url": project.web_url,
                      "default_branch": project.default_branch, "commit_sha": revision.commit_sha if revision else None,
                      "status": status, "error": revision.error if revision and project.eligible else None,
                      "revision_id": revision.id if revision else None, "can_retry": source.enabled and status == "failed"})
    return {"page": page, "pages": pages, "total": total, "projects": items}


@router.post(SOURCES + "/{source_id}/revisions/{revision_id}/retry", status_code=202)
def retry(source_id: int, revision_id: int, auth=Depends(administrator_write), db=Depends(get_db)):
    from .topic_intake_processing import retry_revision
    source = _source(db, source_id, lock=True)
    if not source.enabled:
        raise HTTPException(409, "Enable this source before retrying")
    row = db.scalar(select(TopicRevision).join(TopicProject, TopicProject.id == TopicRevision.project_id)
        .where(TopicProject.source_id == source_id, TopicProject.eligible.is_(True),
               TopicProject.latest_revision_id == revision_id,
               TopicRevision.id == revision_id).with_for_update())
    if row is None:
        raise HTTPException(404, "Current project revision not found")
    if row.status != "failed":
        raise HTTPException(409, "Only a failed intake can be retried")
    job = retry_revision(db, row)
    record_audit(db, auth, "topic.intake.retried", "topic_revision", revision_id, job_id=job.id)
    db.commit()
    return {"job_id": job.id, "status": job.status}
