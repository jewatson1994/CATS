from datetime import datetime
import os
from pathlib import PurePosixPath

from pydantic import BaseModel, Field, field_validator, model_validator
from .retained_documents import EvidenceDocument, UnavailableDocument, validate_documents


class ServicePayload(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,119}$")
    name: str = Field(min_length=1, max_length=240)
    version: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    owner: str | None = None
    poc: str | None = None
    groups: list[str] = Field(default_factory=list)

    @field_validator("groups")
    @classmethod
    def validate_owning_group(cls, value: list[str]) -> list[str]:
        names = list(dict.fromkeys(name.strip() for name in value if name.strip()))
        if len(names) > 1:
            raise ValueError("A service must have exactly one owning group")
        return names

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("Service version must be nonblank and contain no control characters")
        return value


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
    # Preserve scanner identity/lineage in the retained execution payload.
    # The finding index remains unchanged; remediation reads this evidence.
    evidence: dict = Field(default_factory=dict)


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
    sbom_components: list[dict[str, str]] = Field(default_factory=list, max_length=50000)
    sbom_images: list[str] = Field(default_factory=list, max_length=5000)
    evidence_documents: list[EvidenceDocument] = Field(default_factory=list, max_length=2048)
    evidence_unavailable: list[UnavailableDocument] = Field(default_factory=list, max_length=2048)
    # Optional normalized architecture metadata produced by Helm/configuration scans.
    service_overview: dict = Field(default_factory=dict)
    # Source files are optional because CI/API producers may submit evidence
    # without an uploaded chart. When present they are preserved for isolated
    # remediation candidates; rendered manifests remain evidence only.
    artifact_type: str = Field(default="helm", pattern=r"^(helm|kubernetes|manifest|raw|image|compose)$")
    helm_source_files: dict[str, str] = Field(default_factory=dict)
    # Ordered, artifact-relative files passed with Helm --values. Producers
    # using non-default values must declare them so runtime validation deploys
    # the exact configuration that static analysis rendered.
    helm_values_files: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_retained_documents(self):
        validate_documents(self.evidence_documents, self.evidence_unavailable)
        return self

    @field_validator("sbom_components")
    @classmethod
    def validate_sbom_components(cls, components: list[dict[str, str]]) -> list[dict[str, str]]:
        allowed = {"name": 300, "version": 200, "ecosystem": 80, "purl": 1500, "image": 1000,
                   "image_digest": 180, "cpe": 700, "supplier": 300, "author": 300,
                   "architecture": 120, "hashes": 1000, "copyright": 500,
                   "license_declared": 500, "license_detected": 500,
                   "license_expression": 500, "license_source": 120,
                     "location": 1000, "sbom": 300, "dependency_parents": 1000,
                     "dependency_children": 1000,
                   "component_id": 1500, "distro_id": 120, "distro_version": 200,
                   "distro_codename": 120, "distro_cpe": 700, "distro_variant": 200,
                   "package_origin": 300, "source_package": 300, "source_version": 200,
                   "source_rpm": 700, "package_vendor": 300, "package_epoch": 80,
                   "package_release": 200, "package_modularity": 300,
                   "scanner_source_type": 80, "scanner_source_name": 1000,
                   "image_id": 180, "image_manifest_digest": 180,
                   "image_architecture": 120, "image_os": 120,
                   "package_metadata_type": 120, "package_found_by": 200,
                   "package_db_path": 1000, "package_db_name": 300, "package_db_version": 200,
                   "package_nevra": 1000, "package_metadata": 8192,
                   "scanner_name": 80, "scanner_version": 120, "scanner_timestamp": 120, "scanner_schema_version": 80}
        for component in components:
            if any(key not in allowed or len(value) > allowed[key] for key, value in component.items()):
                raise ValueError("SBOM component field is invalid or too long")
        return components

    @field_validator("sbom_images")
    @classmethod
    def validate_sbom_images(cls, images: list[str]) -> list[str]:
        if any(len(image) > 1000 for image in images):
            raise ValueError("SBOM image reference is too long")
        return images

    @field_validator("helm_source_files")
    @classmethod
    def validate_helm_sources(cls, files: dict[str, str]) -> dict[str, str]:
        try:
            # Retaining authoritative static evidence is a different concern
            # from materializing it inside an ephemeral validation cluster.
            # Deployment Validation keeps its tighter independent limits.
            max_bytes = max(1, int(os.getenv("CATS_INGEST_MAX_SOURCE_BYTES", str(100 * 1024 * 1024))))
            max_files = max(1, int(os.getenv("CATS_INGEST_MAX_SOURCE_FILES", "5000")))
        except ValueError:
            max_bytes, max_files = 100 * 1024 * 1024, 5000
        if len(files) > max_files:
            raise ValueError(f"Helm source file count exceeds limit {max_files}")
        total = 0
        for name, content in files.items():
            normalized = str(name).replace("\\", "/"); path = PurePosixPath(normalized)
            if len(normalized) > 500 or path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError(f"Unsafe Helm source path: {name}")
            total += len(normalized.encode("utf-8")) + len(content.encode("utf-8"))
            if total > max_bytes:
                raise ValueError(f"Helm source content exceeds limit {max_bytes} bytes")
        return files

    @field_validator("helm_values_files")
    @classmethod
    def validate_helm_values_files(cls, files: list[str]) -> list[str]:
        if len(files) > 50 or len(set(files)) != len(files):
            raise ValueError("Helm values file list is too large or contains duplicates")
        for name in files:
            normalized = name.replace("\\", "/"); path = PurePosixPath(normalized)
            if len(normalized) > 500 or path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError(f"Unsafe Helm values path: {name}")
        return files

    @model_validator(mode="after")
    def validate_helm_values_are_retained(self):
        retained = {name.replace("\\", "/") for name in self.helm_source_files}
        missing = [name for name in self.helm_values_files if name.replace("\\", "/") not in retained]
        if missing:
            raise ValueError(f"Helm values files are not retained in source evidence: {', '.join(missing)}")
        return self
