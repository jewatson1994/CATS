from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(240))
    description: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(240))
    poc: Mapped[str | None] = mapped_column(String(240))
    manual_version: Mapped[str | None] = mapped_column(String(120))
    lifecycle_status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    executions: Mapped[list["Execution"]] = relationship(back_populates="service")
    findings: Mapped[list["Finding"]] = relationship(back_populates="service")
    archive_events: Mapped[list["ServiceArchiveEvent"]] = relationship(back_populates="service")
    groups: Mapped[list["Group"]] = relationship(secondary="service_groups", back_populates="services")
    poam_entries: Mapped[list["PoamEntry"]] = relationship(back_populates="service")
    policy_findings: Mapped[list["PolicyFinding"]] = relationship(back_populates="service")
    patch_executions: Mapped[list["PatchExecution"]] = relationship(back_populates="service")
    remediation_executions: Mapped[list["RemediationExecution"]] = relationship(back_populates="service")
    images: Mapped[list["ServiceImage"]] = relationship(back_populates="service")


class Group(Base):
    __tablename__ = "groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    services: Mapped[list[Service]] = relationship(secondary="service_groups", back_populates="groups")


class ServiceGroup(Base):
    __tablename__ = "service_groups"
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), primary_key=True)


class Execution(Base):
    __tablename__ = "executions"
    id: Mapped[int] = mapped_column(primary_key=True)
    execution_key: Mapped[str] = mapped_column(String(240), unique=True, index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    complete: Mapped[bool] = mapped_column(Boolean)
    scan_scope: Mapped[str] = mapped_column(String(20), default="service", index=True)
    scope_image: Mapped[str | None] = mapped_column(Text)
    pipeline_url: Mapped[str | None] = mapped_column(Text)
    commit_sha: Mapped[str | None] = mapped_column(String(80))
    scanner_db_built_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw_payload: Mapped[dict] = mapped_column(JSON)
    service: Mapped["Service"] = relationship(back_populates="executions")


class ServiceImage(Base):
    """Historical container evidence and its explicit lifecycle state."""

    __tablename__ = "service_images"
    __table_args__ = (UniqueConstraint("service_id", "image_reference", "image_digest", name="uq_service_image_identity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    image_reference: Mapped[str] = mapped_column(Text)
    image_digest: Mapped[str | None] = mapped_column(String(180))
    lifecycle_status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    replacement_of_id: Mapped[int | None] = mapped_column(ForeignKey("service_images.id"), index=True)
    lifecycle_reason: Mapped[str | None] = mapped_column(Text)
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    service: Mapped["Service"] = relationship(back_populates="images")
    replacement_of: Mapped["ServiceImage | None"] = relationship(remote_side=[id], foreign_keys=[replacement_of_id])


class PatchExecution(Base):
    """Nonsensitive governance record for an authenticated patch job.

    Registry credentials and temporary authentication state intentionally have
    no columns here.  They remain ephemeral worker inputs only.
    """

    __tablename__ = "patch_executions"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    requested_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    source_mode: Mapped[str] = mapped_column(String(20))
    source_image: Mapped[str | None] = mapped_column(Text)
    output_mode: Mapped[str] = mapped_column(String(20))
    destination_image: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(40), default="queued")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    service: Mapped["Service"] = relationship(back_populates="patch_executions")


class RemediationExecution(Base):
    """Durable, nonsensitive record for a transactional remediation candidate."""

    __tablename__ = "remediation_executions"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    requested_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    finding_type: Mapped[str | None] = mapped_column(String(30))
    finding_id: Mapped[int | None] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(50), default="queued")
    original_revision: Mapped[str | None] = mapped_column(String(240))
    resulting_revision: Mapped[str | None] = mapped_column(String(240))
    before_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    after_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    changed_artifacts: Mapped[list] = mapped_column(JSON, default=list)
    patched_images: Mapped[list] = mapped_column(JSON, default=list)
    configuration_changes: Mapped[list] = mapped_column(JSON, default=list)
    validation_results: Mapped[dict] = mapped_column(JSON, default=dict)
    scan_results: Mapped[dict] = mapped_column(JSON, default=dict)
    logs: Mapped[list] = mapped_column(JSON, default=list)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    rollback_reference: Mapped[str | None] = mapped_column(Text)
    artifact_path: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    service: Mapped["Service"] = relationship(back_populates="remediation_executions")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("service_id", "cve", name="uq_service_cve"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    cve: Mapped[str] = mapped_column(String(80), index=True)
    severity: Mapped[str] = mapped_column(String(30))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    episode_started: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recurrence_count: Mapped[int] = mapped_column(Integer, default=0)
    service: Mapped["Service"] = relationship(back_populates="findings")
    observations: Mapped[list["FindingObservation"]] = relationship(back_populates="finding")
    exceptions: Mapped[list["ExceptionRecord"]] = relationship(back_populates="finding")


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    execution_id: Mapped[int] = mapped_column(ForeignKey("executions.id"), index=True)
    image: Mapped[str] = mapped_column(Text)
    image_digest: Mapped[str | None] = mapped_column(String(180))
    package: Mapped[str | None] = mapped_column(String(300))
    installed_version: Mapped[str | None] = mapped_column(String(200))
    fixed_version: Mapped[str | None] = mapped_column(String(200))
    evidence: Mapped[dict] = mapped_column(JSON)
    finding: Mapped["Finding"] = relationship(back_populates="observations")


class ExceptionRecord(Base):
    __tablename__ = "exceptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    justification: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str] = mapped_column(String(240))
    ticket: Mapped[str | None] = mapped_column(String(240))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finding: Mapped["Finding"] = relationship(back_populates="exceptions")


class PolicyFinding(Base):
    __tablename__ = "policy_findings"
    __table_args__ = (UniqueConstraint("service_id", "identity_key", name="uq_service_policy_finding"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    identity_key: Mapped[str] = mapped_column(String(64), index=True)
    finding: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(30), default="Unknown")
    scanner: Mapped[str | None] = mapped_column(String(120))
    framework: Mapped[str | None] = mapped_column(String(240))
    target: Mapped[str | None] = mapped_column(Text)
    namespace: Mapped[str | None] = mapped_column(String(240))
    title: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    fingerprint: Mapped[str | None] = mapped_column(String(240))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    episode_started: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recurrence_count: Mapped[int] = mapped_column(Integer, default=0)
    service: Mapped[Service] = relationship(back_populates="policy_findings")
    exceptions: Mapped[list["PolicyExceptionRecord"]] = relationship(back_populates="policy_finding")

    @property
    def type(self) -> str:
        return "Configuration"


class PolicyExceptionRecord(Base):
    __tablename__ = "policy_exceptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_finding_id: Mapped[int] = mapped_column(ForeignKey("policy_findings.id"), index=True)
    justification: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str] = mapped_column(String(240))
    ticket: Mapped[str | None] = mapped_column(String(240))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    policy_finding: Mapped[PolicyFinding] = relationship(back_populates="exceptions")


class ServiceArchiveEvent(Base):
    __tablename__ = "service_archive_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    action: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text)
    performed_by: Mapped[str] = mapped_column(String(240))
    ticket: Mapped[str | None] = mapped_column(String(240))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    service: Mapped["Service"] = relationship(back_populates="archive_events")


class ServiceDeletionAudit(Base):
    __tablename__ = "service_deletion_audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_key: Mapped[str] = mapped_column(String(120), index=True)
    service_name: Mapped[str] = mapped_column(String(240))
    reason: Mapped[str] = mapped_column(Text)
    deleted_by: Mapped[str] = mapped_column(String(240))
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(240))
    theme: Mapped[str] = mapped_column(String(30), default="cats")
    password_hash: Mapped[str | None] = mapped_column(Text)
    auth_source: Mapped[str] = mapped_column(String(30), default="local", index=True)
    external_subject: Mapped[str | None] = mapped_column(String(240), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    role_assignments: Mapped[list["UserRoleAssignment"]] = relationship(back_populates="user")
    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    system: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assignments: Mapped[list["UserRoleAssignment"]] = relationship(back_populates="role")


class UserRoleAssignment(Base):
    __tablename__ = "user_role_assignments"
    __table_args__ = (UniqueConstraint("user_id", "role_id", "service_id", name="uq_user_role_scope"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id"), index=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user: Mapped["User"] = relationship(back_populates="role_assignments")
    role: Mapped["Role"] = relationship(back_populates="assignments")
    service: Mapped[Service | None] = relationship()
    group: Mapped[Group | None] = relationship()


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(120))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user_agent: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(80))
    user: Mapped["User"] = relationship(back_populates="sessions")


class WorkflowRequest(Base):
    __tablename__ = "workflow_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    request_type: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), index=True)
    policy_finding_id: Mapped[int | None] = mapped_column(ForeignKey("policy_findings.id"), index=True)
    bulk_group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), index=True)
    poam_id: Mapped[int | None] = mapped_column(ForeignKey("poam_entries.id"), index=True)
    service_image_id: Mapped[int | None] = mapped_column(ForeignKey("service_images.id"), index=True)
    replacement_reference: Mapped[str | None] = mapped_column(Text)
    requested_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    justification: Mapped[str] = mapped_column(Text)
    requested_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ticket: Mapped[str | None] = mapped_column(String(240))
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    review_reason: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    service: Mapped["Service"] = relationship()
    finding: Mapped[Finding | None] = relationship()
    policy_finding: Mapped[PolicyFinding | None] = relationship()
    requested_by: Mapped["User"] = relationship(foreign_keys=[requested_by_id])
    reviewed_by: Mapped[User | None] = relationship(foreign_keys=[reviewed_by_id])
    poam: Mapped["PoamEntry | None"] = relationship(back_populates="workflows")
    bulk_group: Mapped["Group | None"] = relationship(foreign_keys=[bulk_group_id])
    service_image: Mapped["ServiceImage | None"] = relationship()


class PoamEntry(Base):
    __tablename__ = "poam_entries"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), index=True)
    policy_finding_id: Mapped[int | None] = mapped_column(ForeignKey("policy_findings.id"), index=True)
    item_type: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    ticket: Mapped[str | None] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(30), default="pending_approval", index=True)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    service: Mapped[Service] = relationship(back_populates="poam_entries")
    finding: Mapped[Finding | None] = relationship()
    policy_finding: Mapped[PolicyFinding | None] = relationship()
    created_by: Mapped[User] = relationship(foreign_keys=[created_by_id])
    approved_by: Mapped[User | None] = relationship(foreign_keys=[approved_by_id])
    workflows: Mapped[list[WorkflowRequest]] = relationship(back_populates="poam")


class PoamHistory(Base):
    __tablename__ = "poam_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    poam_id: Mapped[int] = mapped_column(ForeignKey("poam_entries.id"), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(60), index=True)
    note: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    poam: Mapped[PoamEntry] = relationship()
    actor: Mapped[User | None] = relationship()


class PoamChangeRequest(Base):
    __tablename__ = "poam_change_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    workflow_id: Mapped[int] = mapped_column(ForeignKey("workflow_requests.id"), unique=True, index=True)
    poam_id: Mapped[int] = mapped_column(ForeignKey("poam_entries.id"), index=True)
    change_type: Mapped[str] = mapped_column(String(30), index=True)
    proposed: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    workflow: Mapped[WorkflowRequest] = relationship()
    poam: Mapped[PoamEntry] = relationship()


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    target_type: Mapped[str] = mapped_column(String(80), index=True)
    target_id: Mapped[str | None] = mapped_column(String(240))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[User | None] = relationship()


class PortalSetting(Base):
    __tablename__ = "portal_settings"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), index=True)
    value: Mapped[str] = mapped_column(Text)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[User | None] = relationship()
