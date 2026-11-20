"""GitLab topic sources, stable project bindings and per-commit intake history."""
from datetime import datetime
from uuid import uuid4

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base
from .models import TopicIntakeGroup, utcnow


class GitLabTopicSource(Base):
    """An empty namespace selects instance search; its routes assign claim groups."""
    __tablename__ = "gitlab_topic_sources"
    __table_args__ = (UniqueConstraint("origin", "namespace", "topic"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    origin: Mapped[str] = mapped_column(String(255))
    namespace: Mapped[str] = mapped_column(String(255))
    topic: Mapped[str] = mapped_column(String(255))
    claim_group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), index=True)
    authorized_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    token: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    poll_seconds: Mapped[int] = mapped_column(Integer, default=300)
    config_revision: Mapped[str] = mapped_column(String(32), default=lambda: uuid4().hex)
    latest_job_id: Mapped[str | None] = mapped_column(ForeignKey("durable_jobs.id"))
    latest_preview_job_id: Mapped[str | None] = mapped_column(ForeignKey("durable_jobs.id"))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    routes: Mapped[list["GitLabTopicRoute"]] = relationship(
        cascade="all, delete-orphan", order_by="GitLabTopicRoute.namespace, GitLabTopicRoute.claim_group_id")

    @property
    def namespace_routes(self):
        if self.namespace:
            return []
        return [{"namespace": route.namespace, "claim_group_id": route.claim_group_id} for route in self.routes]

    @namespace_routes.setter
    def namespace_routes(self, values):
        existing = {(r.namespace, r.claim_group_id): r for r in self.routes}
        self.routes = [existing.get((row["namespace"], row["claim_group_id"]))
                       or GitLabTopicRoute(namespace=row["namespace"], claim_group_id=row["claim_group_id"])
                       for row in values]


class GitLabTopicRoute(Base):
    __tablename__ = "gitlab_topic_routes"
    source_id: Mapped[int] = mapped_column(ForeignKey("gitlab_topic_sources.id"), primary_key=True)
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    claim_group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), primary_key=True)


class TopicProject(Base):
    __tablename__ = "topic_projects"
    __table_args__ = (UniqueConstraint("origin", "gitlab_project_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("gitlab_topic_sources.id"), index=True)
    origin: Mapped[str] = mapped_column(String(255))
    gitlab_project_id: Mapped[int] = mapped_column(BigInteger)
    eligible: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    last_seen_poll_id: Mapped[str | None] = mapped_column(String(32))
    claim_group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"))
    observed_topics: Mapped[list[str] | None] = mapped_column(JSON)
    project_path: Mapped[str] = mapped_column(String(1024))
    web_url: Mapped[str] = mapped_column(Text)
    default_branch: Mapped[str] = mapped_column(String(1024))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), unique=True)
    latest_revision_id: Mapped[int | None] = mapped_column(ForeignKey(
        "topic_revisions.id", use_alter=True, name="fk_topic_projects_latest_revision"))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    claimed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    claimed_execution_id: Mapped[int | None] = mapped_column(ForeignKey("executions.id"))


class TopicRevision(Base):
    __tablename__ = "topic_revisions"
    __table_args__ = (UniqueConstraint("project_id", "commit_sha"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("topic_projects.id"), index=True)
    commit_sha: Mapped[str] = mapped_column(String(64))
    ref: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    processing_job_id: Mapped[str | None] = mapped_column(ForeignKey("durable_jobs.id"), unique=True)
    discovery_job_id: Mapped[str | None] = mapped_column(ForeignKey("durable_jobs.id"), unique=True)
    inventory_id: Mapped[str | None] = mapped_column(ForeignKey("discovery_inventories.id"))
    scan_job_id: Mapped[str | None] = mapped_column(ForeignKey("scan_jobs.id"), unique=True)
    execution_id: Mapped[int | None] = mapped_column(ForeignKey("executions.id"), unique=True)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
