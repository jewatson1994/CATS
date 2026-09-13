from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class ServicePayload(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,119}$")
    name: str = Field(min_length=1, max_length=240)
    version: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    owner: str | None = None
    poc: str | None = None
    groups: list[str] = Field(default_factory=list)


class FindingPayload(BaseModel):
    cve: str
    severity: str = "Unknown"
    image: str
    image_digest: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    evidence: dict = Field(default_factory=dict)
    kev: bool = False
    epss: float | None = Field(default=None, ge=0, le=1)

    @field_validator("cve")
    @classmethod
    def normalize_cve(cls, value: str):
        return value.strip().upper()


class PolicyFindingPayload(BaseModel):
    type: str = "Configuration"
    finding: str = Field(min_length=1, max_length=120)
    severity: str = "Unknown"
    scanner: str | None = None
    framework: str | None = None
    target: str | None = None
    namespace: str | None = None
    title: str | None = None
    description: str | None = None
    remediation: str | None = None
    fingerprint: str | None = None


class ExecutionPayload(BaseModel):
    schema_version: str = "1.0"
    execution_id: str
    scanned_at: datetime
    complete: bool
    scan_scope: str = Field(default="service", pattern=r"^(service|image|evidence)$")
    scope_image: str | None = None
    skipped_images: list[str] = Field(default_factory=list)
    skipped_charts: list[str] = Field(default_factory=list)
    fixable_only: bool
    pipeline_url: str | None = None
    commit_sha: str | None = None
    scanner_db_built_at: datetime | None = None
    service: ServicePayload
    findings: list[FindingPayload] = Field(default_factory=list)
    policy_findings: list[PolicyFindingPayload] = Field(default_factory=list)
    # Optional normalized architecture metadata produced by Helm/configuration scans.
    service_overview: dict = Field(default_factory=dict)
    # Source files are optional because CI/API producers may submit evidence
    # without an uploaded chart. When present they are preserved for isolated
    # remediation candidates; rendered manifests remain evidence only.
    artifact_type: str = Field(default="helm", pattern=r"^(helm|kubernetes|manifest|raw|image)$")
    helm_source_files: dict[str, str] = Field(default_factory=dict)
