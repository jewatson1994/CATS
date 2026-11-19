"""Contract shared by CI evidence producers and the portal ingestion routes."""
from functools import lru_cache
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field


pipeline_bearer = HTTPBearer(
    scheme_name="PipelineBearer", auto_error=False,
    description="The full portal's configured PIPELINE_API_TOKEN for trusted evidence producers.",
)


def require_pipeline(credentials: HTTPAuthorizationCredentials | None = Depends(pipeline_bearer)):
    expected = os.getenv("PIPELINE_API_TOKEN", "")
    if not expected.strip():
        raise HTTPException(503, "Pipeline ingestion credentials are not configured")
    if credentials is None or not secrets.compare_digest(credentials.credentials.encode(), expected.encode()):
        raise HTTPException(401, "Invalid pipeline token", headers={"WWW-Authenticate": "Bearer"})


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
    tags=["Pipeline ingestion"], dependencies=[Depends(require_pipeline)],
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
    return get_openapi(
        title="CATS pipeline ingestion", version="1.0", routes=router.routes,
        description="Post CI scan evidence to the authoritative portal. Both operations require a pipeline bearer credential.",
    )
