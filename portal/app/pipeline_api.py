"""Contract shared by CI evidence producers and the portal ingestion routes."""
from functools import lru_cache
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .database import get_db
from .project_credentials import ProjectCredential, TOKEN_PREFIX, authenticate_project
from .schemas import ExecutionPayload


pipeline_bearer = HTTPBearer(
    scheme_name="PipelineBearer", auto_error=False,
    description="Service project credential with evidence.write, or a separately enabled deployment-wide PIPELINE_API_TOKEN.",
)
project_bearer = HTTPBearer(
    scheme_name="ProjectBearer", auto_error=False,
    description="A service manager issues this credential to one project with explicit scopes and an expiry.",
)


def require_pipeline(credentials: HTTPAuthorizationCredentials | None = Depends(pipeline_bearer),
                     db: Session = Depends(get_db)) -> ProjectCredential | None:
    if credentials and credentials.credentials.startswith(TOKEN_PREFIX):
        return authenticate_project(db, "Bearer " + credentials.credentials, scope="evidence.write")
    expected = os.getenv("PIPELINE_API_TOKEN", "")
    if expected.strip() in {"", "development-token", "replace-with-a-long-random-token",
                            "replace-with-a-long-random-pipeline-token"}:
        if credentials is None:
            raise HTTPException(401, "A pipeline bearer credential is required", headers={"WWW-Authenticate": "Bearer"})
        raise HTTPException(503, "Deployment-wide pipeline ingestion credentials are not configured")
    if credentials is None or not secrets.compare_digest(credentials.credentials.encode(), expected.encode()):
        raise HTTPException(401, "Invalid pipeline token", headers={"WWW-Authenticate": "Bearer"})
    return None


def bound_project_payload(payload: ExecutionPayload, credential: ProjectCredential | None) -> ExecutionPayload:
    """Take service identity and editable metadata from the authorized service."""
    if credential is None:
        return payload
    if not payload.execution_id.strip() or len(payload.execution_id) > 240:
        raise HTTPException(422, "Provide a nonblank execution ID of at most 240 characters")
    service = credential.service
    if payload.service.id != service.service_key:
        raise HTTPException(403, "Project credential cannot submit evidence for this service")
    groups = [group.name for group in service.groups]
    if len(groups) != 1 or (payload.service.groups and payload.service.groups != groups):
        raise HTTPException(403, "Evidence must use the service's owning group")
    metadata = payload.service.model_copy(update={
        "name": service.name, "owner": service.owner, "poc": service.poc,
        "description": service.description, "groups": groups,
    })
    return payload.model_copy(update={"service": metadata})


class PipelineReceipt(BaseModel):
    accepted: bool
    duplicate: bool
    execution_id: int = Field(description="CATS database ID of the retained execution")
    deployment_validation_run_id: int | None = None


class AmendmentReceipt(BaseModel):
    accepted: bool
    proposal_id: int
    assessment_id: int
    active_release_changed: bool


class PipelineError(BaseModel):
    detail: str | list[dict] | dict
    diagnostic: dict | None = None
    code: str | None = None


router = APIRouter(
    tags=["Pipeline ingestion"],
    responses={status: {"model": PipelineError, "description": description} for status, description in {
        400: "Invalid request length",
        401: "Missing or invalid pipeline bearer credential",
        403: "Operation forbidden for this resource or deployment mode",
        409: "Conflicting evidence, service ownership, or proposal state",
        413: "Evidence request exceeds the configured byte limit",
        422: "Invalid input or unsupported assessment",
        503: "Pipeline ingestion is unavailable",
    }.items()},
)


@lru_cache(maxsize=1)
def pipeline_openapi():
    from .artifact_submissions import router as submissions
    return get_openapi(
        title="CATS producer API", version="1.1", routes=[*router.routes, *submissions.routes],
        description="Submit evidence or queue artifact scans on the authoritative portal. Each operation declares its bearer credential.",
    )
