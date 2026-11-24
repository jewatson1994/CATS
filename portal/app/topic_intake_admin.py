"""Configure trusted GitLab sources and inspect their asynchronous intake progress."""
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import JSON, cast, func, or_, select, text, type_coerce, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased, load_only, selectinload

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


class NamespaceRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    namespace: str = Field(min_length=1, max_length=255)
    claim_group_id: int = Field(gt=0)


class SourceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=160)
    origin: str = Field(min_length=1, max_length=255)
    scope_mode: Literal["group", "instance"] = "group"
    namespace: str = Field(default="", max_length=255)
    namespace_routes: list[NamespaceRoute] = Field(default_factory=list)
    topic: str = Field(min_length=1, max_length=255)
    claim_group_id: int | None = Field(default=None, gt=0)
    poll_seconds: int = Field(default=300, ge=30, le=86400)
    enabled: bool = False
    token: SecretStr | None = None
    clear_token: bool = False


def _job_view(job, result, *, include_details=False):
    if job is None:
        return None
    result = result or {}
    detail_keys = ("gitlab_project_id", "project_path", "web_url", "default_branch", "commit_sha",
                   "claim_group_id", "status", "reason")
    counts = ("matched", "new_commits", "unchanged_commits", "conflicts", "skipped", "observed", "excluded",
              "failed_projects", "no_longer_eligible")
    excluded = result.get("excluded_by_reason") or {}
    view = {"id": job.id, "status": job.status, "stage": job.stage, "error": job.error,
            **{key: result[key] for key in counts if type(result.get(key)) is int},
            "excluded_by_reason": {key: excluded[key] for key in ("outside_namespace", "no_default_branch", "archived")
                                   if type(excluded.get(key)) is int},
            "truncated": result.get("truncated") is True,
            "project_errors": [{"gitlab_project_id": row.get("gitlab_project_id"), "message": row["message"]}
                               for row in result.get("project_errors", [])[:20]
                               if isinstance(row, dict) and isinstance(row.get("message"), str)]}
    if include_details:
        view["details"] = [{key: row[key] for key in detail_keys if key in row}
                           for row in result.get("details", [])[:100] if isinstance(row, dict)]
    return view


def _view(source, job=None, preview=None, poll_summary=None, preview_summary=None):
    fields = ("id", "name", "origin", "namespace", "topic", "claim_group_id", "enabled", "poll_seconds",
              "last_attempt_at", "last_success_at", "last_error")
    result = {key: getattr(source, key) for key in fields}
    result["scope_mode"] = "group" if source.namespace else "instance"
    result["namespace_routes"] = source.namespace_routes
    if not source.namespace:
        result["claim_group_id"] = None
    result["has_token"] = secret_configured(source.token)
    result["latest_job"] = _job_view(job, poll_summary)
    result["latest_preview"] = _job_view(preview, preview_summary)
    return result


def _source(db, source_id, *, lock=False):
    if lock:
        reserve_sqlite_writer(db)
    source = db.get(GitLabTopicSource, source_id, with_for_update=lock)
    if source is None:
        raise HTTPException(404, "GitLab topic source not found")
    return source


def _route_pairs(source):
    if source.namespace:
        return {(source.namespace, source.claim_group_id)}
    return {(r["namespace"], r["claim_group_id"]) for r in source.namespace_routes}


def _overlap(left, right):
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _invalidate_routing(db, source, previous, current):
    """Fence active overlapping polls and withdraw ambiguous, unclaimed entries before commit."""
    changed = previous ^ current
    if not changed:
        return
    peers = db.scalars(select(GitLabTopicSource)
        .where(GitLabTopicSource.origin == source.origin, GitLabTopicSource.id != source.id)
        .options(load_only(GitLabTopicSource.id, GitLabTopicSource.namespace, GitLabTopicSource.claim_group_id),
                 selectinload(GitLabTopicSource.routes))
        .order_by(GitLabTopicSource.id))
    affected = [peer.id for peer in peers if any(
        group != other_group and _overlap(ns, other_ns)
        for ns, group in changed for other_ns, other_group in _route_pairs(peer))]
    if not affected:
        return
    # Every read of the previous rules must finish before reactivation is possible.
    # Mark every affected source due, even if a previous conflict prevented the
    # worker from ever creating a TopicProject for the matching repository.
    db.execute(update(GitLabTopicSource).where(GitLabTopicSource.id.in_(affected))
               .values(config_revision=uuid4().hex, latest_preview_job_id=None, latest_job_id=None,
                       last_attempt_at=None, last_error=None))
    if not current - previous:
        return
    project = TopicProject
    peer_group = select(GitLabTopicSource.claim_group_id).where(GitLabTopicSource.id == project.source_id,
                                                               GitLabTopicSource.namespace != "").scalar_subquery()
    resolved = func.coalesce(project.claim_group_id, peer_group)
    # Older intake records did not retain the other GitLab topics. Recheck them
    # conservatively. New records only need a hold when they carried this topic.
    if db.get_bind().dialect.name == "postgresql":
        stored = cast(project.observed_topics, JSONB)
        has_topic = stored.contains([source.topic])
        unknown_topics = func.jsonb_typeof(stored).is_distinct_from("array")
    else:
        topics = func.json_each(project.observed_topics).table_valued("value").alias()
        has_topic = select(1).select_from(topics).where(topics.c.value == source.topic).exists()
        unknown_topics = func.json_type(project.observed_topics).is_distinct_from("array")
    predicate = or_(unknown_topics, has_topic)
    for namespace, group_id in current - previous:
        db.execute(update(project).where(project.source_id.in_(affected), project.claimed_at.is_(None),
            project.eligible.is_(True), project.project_path.startswith(namespace + "/", autoescape=True),
            resolved.is_distinct_from(group_id), predicate).values(eligible=False)
            .execution_options(synchronize_session=False))


def _configuration_lock(db):
    reserve_sqlite_writer(db)
    if db.get_bind().dialect.name == "postgresql":
        # Serialize route changes before acquiring individual source locks.
        db.execute(text("SELECT pg_advisory_xact_lock(73488368)"))


def _hold_unclaimed_projects(db, source_id, namespaces=None):
    project = TopicProject
    hold = update(project).where(project.source_id == source_id, project.eligible.is_(True),
                                 project.claimed_at.is_(None)).values(eligible=False).execution_options(synchronize_session=False)
    if namespaces is None:
        db.execute(hold)
        return
    # Bound query size for large changes; compare the exact namespace segment,
    # including case and literal underscores, on either supported database.
    roots = sorted(namespaces)
    for start in range(0, len(roots), 50):
        db.execute(hold.where(or_(*(func.substr(project.project_path, 1, len(root) + 1) == root + "/"
                                    for root in roots[start:start + 50]))))


def _save(db, auth, value, source=None):
    from .discovery_gitlab import validate_topic_scope
    if value.scope_mode == "group":
        if not value.namespace or value.claim_group_id is None or value.namespace_routes:
            raise HTTPException(422, "A group source requires one namespace and its claim group")
        pairs = {(value.namespace, value.claim_group_id)}
    else:
        if value.namespace or value.claim_group_id is not None or not value.namespace_routes:
            raise HTTPException(422, "An instance source requires a namespace and claim group mapping for each allowed namespace")
        pairs = {(route.namespace, route.claim_group_id) for route in value.namespace_routes}
        if len(pairs) != len(value.namespace_routes):
            raise HTTPException(422, "Remove duplicate namespace and claim group mappings")
    origin, namespace, topic = value.origin.rstrip("/"), value.namespace, value.topic
    if source and ((origin, namespace, topic) != (source.origin, source.namespace, source.topic)
                   or (source.namespace and source.claim_group_id != value.claim_group_id)):
        raise HTTPException(409, "The source's origin, topic and group scope are fixed when it is created")
    old_pairs = _route_pairs(source) if source else set()
    previous = old_pairs if source and source.enabled else set()
    routing_changed = pairs != old_pairs
    if source is None or value.enabled or routing_changed:
        try:
            if namespace:
                origin, namespace, topic = validate_topic_scope(origin, namespace, topic)
            else:
                origin, namespace, topic = validate_topic_scope(origin, namespace, topic,
                    namespaces=[name for name, _ in pairs])
        except GitLabSourceError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
    if routing_changed:
        groups = {group_id for _, group_id in pairs}
        valid = db.scalars(select(Group.id).where(Group.id.in_(groups),
                          ~Group.id.in_(select(TopicIntakeGroup.group_id))))
        if set(valid) != groups:
            raise HTTPException(422, "Choose an existing destination group")
    if not source:
        source = GitLabTopicSource(origin=origin, namespace=namespace, topic=topic)
        db.add(source)
    if routing_changed:
        # Legacy schema requires a source group. An instance source authorizes
        # exclusively through the per-project mapping, never this compatibility value.
        source.claim_group_id = sorted(pairs)[0][1]
        if not namespace:
            source.namespace_routes = [{"namespace": n, "claim_group_id": g} for n, g in sorted(pairs)]
    token = value.token.get_secret_value() if value.token else ""
    if token and (value.clear_token or len(token) > 4096 or any(not 33 <= ord(c) <= 126 for c in token)):
        raise HTTPException(422, "Enter a valid GitLab token or choose to clear the stored token")
    credentials_changed = bool(token or (value.clear_token and source.token))
    if token:
        try:
            source.token = encrypt_secret(token)
        except ValueError:
            raise HTTPException(503, "The portal encryption key must be configured to store a GitLab token") from None
    elif value.clear_token:
        source.token = ""
    access_changed = credentials_changed or value.enabled != source.enabled
    if routing_changed or access_changed:
        if source.id is not None:
            changed_roots = None if access_changed else {root for root, _ in old_pairs ^ pairs}
            _hold_unclaimed_projects(db, source.id, changed_roots)
        source.last_attempt_at = source.last_error = None
        source.latest_job_id = None
    source.latest_preview_job_id = None
    source.name, source.enabled, source.poll_seconds = value.name, value.enabled, value.poll_seconds
    source.authorized_by_id, source.config_revision = auth.user.id, uuid4().hex
    try:
        db.flush()
        _invalidate_routing(db, source, previous, pairs if value.enabled else set())
        record_audit(db, auth, "topic.source.configured", "gitlab_topic_source", source.id,
                     origin=source.origin, namespace=source.namespace, topic=source.topic, scope_mode=value.scope_mode,
                     claim_group_id=value.claim_group_id, namespace_routes=source.namespace_routes,
                     enabled=source.enabled, poll_seconds=source.poll_seconds)
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
    preview = aliased(DurableJob)
    def job_fields(model):
        return load_only(model.id, model.status, model.stage, model.error)

    def summary(model):
        if db.get_bind().dialect.name == "postgresql":
            return cast(model.result, JSONB).op("-")("details")
        return type_coerce(func.json_remove(model.result, "$.details"), JSON)

    sources = db.execute(
        select(GitLabTopicSource, DurableJob, preview, summary(DurableJob), summary(preview))
        .options(job_fields(DurableJob), job_fields(preview), selectinload(GitLabTopicSource.routes))
        .outerjoin(DurableJob, DurableJob.id == GitLabTopicSource.latest_job_id)
        .outerjoin(preview, preview.id == GitLabTopicSource.latest_preview_job_id)
        .order_by(GitLabTopicSource.name))
    groups = db.execute(select(Group.id, Group.name).where(
        ~Group.id.in_(select(TopicIntakeGroup.group_id))).order_by(Group.name))
    return {"sources": [_view(*row) for row in sources],
            "groups": [dict(row) for row in groups.mappings()]}


@router.get(SOURCES + "/{source_id}/results")
def source_results(source_id: int, auth=Depends(administrator), db=Depends(get_db)):
    source = _source(db, source_id)
    job_ids = {id_ for id_ in (source.latest_job_id, source.latest_preview_job_id) if id_}
    jobs = {job.id: _job_view(job, job.result, include_details=True)
            for job in db.scalars(select(DurableJob).where(DurableJob.id.in_(job_ids))
            .options(load_only(DurableJob.id, DurableJob.status, DurableJob.stage, DurableJob.error, DurableJob.result)))}
    return {"latest_job": jobs.get(source.latest_job_id), "latest_preview": jobs.get(source.latest_preview_job_id)}


@router.post(SOURCES, status_code=201)
def create_source(value: SourceInput, auth=Depends(administrator_write), db=Depends(get_db)):
    _configuration_lock(db)
    return _save(db, auth, value)


@router.put(SOURCES + "/{source_id}")
def update_source(source_id: int, value: SourceInput, auth=Depends(administrator_write), db=Depends(get_db)):
    _configuration_lock(db)
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


@router.post(SOURCES + "/{source_id}/preview", status_code=202)
def preview_matches(source_id: int, auth=Depends(administrator_write), db=Depends(get_db)):
    from .gitlab_topic_poll import enqueue
    source = _source(db, source_id, lock=True)
    job = enqueue(db, source, actor_id=auth.user.id, preview=True)
    record_audit(db, auth, "topic.preview.requested", "gitlab_topic_source", source.id, job_id=job.id)
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
