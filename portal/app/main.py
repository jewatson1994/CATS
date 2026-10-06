import os
import asyncio
from copy import deepcopy
import re
import logging
import secrets
import json
import hashlib
import urllib.parse
import urllib.request
import urllib.error
import shutil
import ssl
import socket
import subprocess
import sys
import tempfile
import threading
from collections import OrderedDict
import time
import tarfile
import uuid
from contextlib import asynccontextmanager, ExitStack
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from zipfile import ZIP_DEFLATED, ZipFile
from io import BytesIO
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from types import SimpleNamespace
from zoneinfo import ZoneInfo, available_timezones

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from .frontend import FrontendTemplates as Jinja2Templates
from starlette.middleware.gzip import GZipMiddleware
from sqlalchemy import and_, case, delete, false, func, inspect, or_, select, text, true
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer, selectinload
from pydantic import ValidationError
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
import yaml

from .database import Base, engine, get_db, SessionLocal
from .performance import PerformanceMiddleware, install_sqlalchemy_diagnostics
from .execution_summaries import install_execution_summary_hooks
install_sqlalchemy_diagnostics(engine, SessionLocal.class_)
install_execution_summary_hooks(SessionLocal.class_)
from .simplified_queries import upgrade_projection
from . import dependency_queries
from .helm_sources import normalize_chart_reference, oci_pull_arguments
from .helm_archives import extract_chart, compressed_limit
from .runtime_diagnostics import runtime_failure_details
from .helm_downloads import DownloadedChart, copy_bounded, close_downloads, check_space
from .auth import (
    PERMISSIONS, SESSION_COOKIE, AuthContext, hash_password, record_audit,
    require_permission, require_user, optional_user, seed_auth, token_hash, utcnow as auth_utcnow,
    verify_password, oidc_enabled, oidc_authorization_url, oidc_exchange_code,
    provision_oidc_user, verify_oidc_id_token,
)
from .models import (
    ExceptionRecord, Execution, Finding, FindingObservation, PolicyFinding, ServiceVersion,
    PolicyExceptionRecord, Service, Group,
    ServiceArchiveEvent, ServiceDeletionAudit, ServiceImage, User, UserSession, Role,
    UserRoleAssignment, WorkflowRequest, AuditEvent, PortalSetting, PoamEntry,
    ServiceGroup,
    PoamHistory, PoamChangeRequest,
    PatchExecution,
    RemediationExecution,
    DeploymentValidationRun, ServiceArtifact, ServiceArtifactRevision,
    DependencyWatchlistEntry, DependencyWatchlistMatch,
    OidcClaimMapping,
    SecurityDataSource,
)
from .security_data import SOURCE_KEYS as SECURITY_DATA_KEYS, refresh as refresh_security_data, MAX_UPLOAD as MAX_SECURITY_DATA_UPLOAD
from .validator_client import validate as validate_remote_artifact, health as validator_health
from .validator_protocol import SCHEMA_VERSION as VALIDATION_PACKAGE_VERSION
from . import managed_validators as validator_management
from .watchlist import parse_entries as parse_watchlist_entries, reconcile_matches as reconcile_watchlist_matches
from .schemas import ExecutionPayload
from .policy_data import epss_scores, intelligence_status, kev_cves, risk_metadata
from .overview import normalize_overview
from .service_export import build_service_workbook, service_export_filename
from .purpose_exports import CATALOG as PURPOSE_CATALOG, NAMES as PURPOSE_NAMES, default_template as purpose_default_template, template_for as purpose_template_for, template_policy as purpose_template_policy, template_for_service as purpose_template_for_service, policy_key as purpose_policy_key, validate_template as validate_purpose_template, setting_key as purpose_setting_key, workbook_for as purpose_workbook_for
from .helm_diagram import build_helm_diagram
from .architecture import build_architecture_graph
from .architecture_evidence import architecture_summary_json, architecture_verification
from .capability_evidence import WORKLOAD_KINDS, pod_spec
from .architecture_export import build_architecture_svg
from .report_html import build_public_scan_report
from .patching import PATCH_PHASES, advance_patch_stages, initial_patch_stages, redact, registry_host, safe_job_config
from .secrets import encrypt_secret, decrypt_secret, secret_configured
from . import signing
from .admin_config import OS_DEFINITIONS, PACKAGE_MANAGERS, certificate_bundle_metadata, merge_certificate_metadata, normalize_policy, parse_json, policy_bool, test_repository, validate_os_definition, validate_policy
from .trusted_ca import ephemeral_trust, write_additive_bundle
from .runtime_version import deployed_version
from .remediation import build_plan, candidate_files, classify_policy_finding, plan_yaml, static_validation, versioned_charts, summarize_grype_reports, summarize_configuration_report, resolve_decisions, plan_digest
from .remediation_summary import build_summary as build_remediation_summary, artifacts as remediation_summary_artifacts
from . import service_oci
from .remediation_lineage import record_reingestion_provenance, provenance_for_execution
from .remediation_delivery import DeliveryAttempt, attempt_dto, retained_candidate, deliver, checked_values_files
from .remediation_retention import cleanup_remediation_artifacts
from .deployment_validation import (
    KindDeploymentValidator, ValidationArtifact, ValidationConfig,
    ValidationStatus, capability_assessment_groups, cleanup_stale_clusters, validation_names,
)


from .managed_validator_migrations import upgrade_connection as upgrade_validators
from .exchange_migrations import migration_transaction, upgrade_connection
from .preview_cleanup import preview_cleanup_lifespan
# Lightweight additive upgrade for deployments created before service POC
# metadata existed. This keeps the existing create_all-based deployment model
# upgrade-safe without touching or deleting evidence.
with migration_transaction(engine) as connection:
    Base.metadata.create_all(bind=connection)
    upgrade_connection(connection)
    upgrade_validators(connection)
    upgrade_projection(connection)
    dependency_queries.upgrade_dependency_schema(connection)
    if "payload_digest" not in {column["name"] for column in inspect(connection).get_columns("executions")}:
        connection.execute(text("ALTER TABLE executions ADD COLUMN payload_digest VARCHAR(64)"))
    if "current_version_id" not in {column["name"] for column in inspect(connection).get_columns("services")}:
        connection.execute(text("ALTER TABLE services ADD COLUMN current_version_id INTEGER REFERENCES service_versions(id)"))
    if "service_version_id" not in {column["name"] for column in inspect(connection).get_columns("executions")}:
        connection.execute(text("ALTER TABLE executions ADD COLUMN service_version_id INTEGER REFERENCES service_versions(id)"))
    # Legacy evidence keeps its recorded release when one exists. A missing or
    # fabricated Unknown release is explicitly unversioned, never guessed.
    for legacy in connection.execute(text(
        "SELECT id, service_id, raw_payload FROM executions WHERE service_version_id IS NULL ORDER BY id"
    )).mappings():
        raw = legacy["raw_payload"]
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (TypeError, ValueError):
                raw = {}
        service_data = raw.get("service") if isinstance(raw, dict) else None
        recorded = str((service_data or {}).get("version") or "").strip() if isinstance(service_data, dict) else ""
        version_label = recorded if recorded and recorded.lower() != "unknown" else "Unversioned"
        version_id = connection.execute(text(
            "SELECT id FROM service_versions WHERE service_id = :service_id AND version = :version"
        ), {"service_id": legacy["service_id"], "version": version_label}).scalar_one_or_none()
        if version_id is None:
            version_id = connection.execute(text(
                "INSERT INTO service_versions (service_id, version, created_at) "
                "VALUES (:service_id, :version, :created_at) RETURNING id"
            ), {"service_id": legacy["service_id"], "version": version_label,
                "created_at": datetime.now(timezone.utc)}).scalar_one()
        connection.execute(text(
            "UPDATE executions SET service_version_id = :version_id WHERE id = :id"
        ), {"version_id": version_id, "id": legacy["id"]})
    for service_row in connection.execute(text(
        "SELECT id, manual_version FROM services WHERE current_version_id IS NULL"
    )).mappings():
        latest = connection.execute(text(
            "SELECT service_version_id FROM executions WHERE service_id = :service_id "
            "AND complete = TRUE AND scan_scope = 'service' AND service_version_id IS NOT NULL "
            "ORDER BY scanned_at DESC, id DESC LIMIT 1"
        ), {"service_id": service_row["id"]}).scalar_one_or_none()
        if latest is not None:
            connection.execute(text("UPDATE services SET current_version_id = :version_id WHERE id = :id"),
                               {"version_id": latest, "id": service_row["id"]})
    if "parent_id" not in {column["name"] for column in inspect(connection).get_columns("groups")}:
        connection.execute(text("ALTER TABLE groups ADD COLUMN parent_id INTEGER REFERENCES groups(id)"))
    if "poc" not in {column["name"] for column in inspect(connection).get_columns("services") }:
        connection.execute(text("ALTER TABLE services ADD COLUMN poc VARCHAR(240)"))
    if "manual_version" not in {column["name"] for column in inspect(connection).get_columns("services") }:
        connection.execute(text("ALTER TABLE services ADD COLUMN manual_version VARCHAR(120)"))
    if "description" not in {column["name"] for column in inspect(connection).get_columns("services") }:
        connection.execute(text("ALTER TABLE services ADD COLUMN description TEXT"))
    if "lifecycle_status" not in {column["name"] for column in inspect(connection).get_columns("services") }:
        connection.execute(text("ALTER TABLE services ADD COLUMN lifecycle_status VARCHAR(20) DEFAULT 'active'"))
        connection.execute(text("UPDATE services SET lifecycle_status = 'staged' WHERE name LIKE 'Staged %' AND (lifecycle_status IS NULL OR lifecycle_status = 'active')"))
    service_columns = {column["name"] for column in inspect(connection).get_columns("services")}
    if "staging_original_name" not in service_columns:
        connection.execute(text("ALTER TABLE services ADD COLUMN staging_original_name VARCHAR(240)"))
    if "staging_name_generated" not in service_columns:
        connection.execute(text("ALTER TABLE services ADD COLUMN staging_name_generated BOOLEAN DEFAULT FALSE"))
        # This exact legacy shape was generated by CATS staging. Do not infer
        # ownership from the prefix alone: users may legitimately choose it.
        connection.execute(text(
            "UPDATE services SET staging_original_name = service_key, staging_name_generated = TRUE "
            "WHERE lifecycle_status = 'staged' AND name = 'Staged — ' || service_key"
        ))
    if "staging_name_upgrade_v2" not in service_columns:
        connection.execute(text("ALTER TABLE services ADD COLUMN staging_name_upgrade_v2 BOOLEAN DEFAULT FALSE"))
        # One-time repair marker for records created before staging ownership
        # metadata existed. Exact equality to CATS' generated shape is required.
        connection.execute(text(
            "UPDATE services SET staging_original_name = service_key, staging_name_generated = TRUE "
            "WHERE lifecycle_status IN ('staged', 'active') AND name = 'Staged — ' || service_key"
        ))
        connection.execute(text("UPDATE services SET staging_name_upgrade_v2 = TRUE"))
    if "theme" not in {column["name"] for column in inspect(connection).get_columns("users") }:
        connection.execute(text("ALTER TABLE users ADD COLUMN theme VARCHAR(30) DEFAULT 'cats'"))
    if "last_login_at" not in {column["name"] for column in inspect(connection).get_columns("users") }:
        connection.execute(text("ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP"))
    if "group_id" not in {column["name"] for column in inspect(connection).get_columns("user_role_assignments") }:
        connection.execute(text("ALTER TABLE user_role_assignments ADD COLUMN group_id INTEGER"))
    if "source" not in {column["name"] for column in inspect(connection).get_columns("user_role_assignments") }:
        connection.execute(text("ALTER TABLE user_role_assignments ADD COLUMN source VARCHAR(20) DEFAULT 'local'"))
    if "group_id" not in {column["name"] for column in inspect(connection).get_columns("portal_settings") }:
        connection.execute(text("ALTER TABLE portal_settings ADD COLUMN group_id INTEGER"))
    if "poam_id" not in {column["name"] for column in inspect(connection).get_columns("workflow_requests") }:
        connection.execute(text("ALTER TABLE workflow_requests ADD COLUMN poam_id INTEGER"))
    if "policy_finding_id" not in {column["name"] for column in inspect(connection).get_columns("workflow_requests") }:
        connection.execute(text("ALTER TABLE workflow_requests ADD COLUMN policy_finding_id INTEGER"))
    if "bulk_group_id" not in {column["name"] for column in inspect(connection).get_columns("workflow_requests") }:
        connection.execute(text("ALTER TABLE workflow_requests ADD COLUMN bulk_group_id INTEGER"))
    if "scan_scope" not in {column["name"] for column in inspect(connection).get_columns("executions") }:
        connection.execute(text("ALTER TABLE executions ADD COLUMN scan_scope VARCHAR(20) DEFAULT 'service'"))
    image_columns = {column["name"] for column in inspect(connection).get_columns("service_images")}
    if "scan_status" not in image_columns:
        connection.execute(text("ALTER TABLE service_images ADD COLUMN scan_status VARCHAR(20) DEFAULT 'never_scanned'"))
    if "scan_job_id" not in image_columns:
        connection.execute(text("ALTER TABLE service_images ADD COLUMN scan_job_id VARCHAR(64)"))
    if "last_scanned_at" not in image_columns:
        connection.execute(text("ALTER TABLE service_images ADD COLUMN last_scanned_at TIMESTAMP"))
    if "scan_error" not in image_columns:
        connection.execute(text("ALTER TABLE service_images ADD COLUMN scan_error TEXT"))
    if "scope_image" not in {column["name"] for column in inspect(connection).get_columns("executions") }:
        connection.execute(text("ALTER TABLE executions ADD COLUMN scope_image TEXT"))
    if "service_image_id" not in {column["name"] for column in inspect(connection).get_columns("workflow_requests") }:
        connection.execute(text("ALTER TABLE workflow_requests ADD COLUMN service_image_id INTEGER"))
    if "replacement_reference" not in {column["name"] for column in inspect(connection).get_columns("workflow_requests") }:
        connection.execute(text("ALTER TABLE workflow_requests ADD COLUMN replacement_reference TEXT"))
    if "policy_finding_id" not in {column["name"] for column in inspect(connection).get_columns("poam_entries") }:
        connection.execute(text("ALTER TABLE poam_entries ADD COLUMN policy_finding_id INTEGER"))
    if "security_policy_violations" not in {column["name"] for column in inspect(connection).get_columns("deployment_validation_runs") }:
        connection.execute(text("ALTER TABLE deployment_validation_runs ADD COLUMN security_policy_violations JSON"))
    if "resource_isolation" not in {column["name"] for column in inspect(connection).get_columns("deployment_validation_runs") }:
        connection.execute(text("ALTER TABLE deployment_validation_runs ADD COLUMN resource_isolation JSON"))
    if "warnings" not in {column["name"] for column in inspect(connection).get_columns("deployment_validation_runs") }:
        connection.execute(text("ALTER TABLE deployment_validation_runs ADD COLUMN warnings JSON"))
    if "capability_preflight" not in {column["name"] for column in inspect(connection).get_columns("deployment_validation_runs") }:
        connection.execute(text("ALTER TABLE deployment_validation_runs ADD COLUMN capability_preflight JSON"))
    if "capability_bootstrap" not in {column["name"] for column in inspect(connection).get_columns("deployment_validation_runs") }:
        connection.execute(text("ALTER TABLE deployment_validation_runs ADD COLUMN capability_bootstrap JSON"))
    if "classification_reasons" not in {column["name"] for column in inspect(connection).get_columns("deployment_validation_runs") }:
        connection.execute(text("ALTER TABLE deployment_validation_runs ADD COLUMN classification_reasons JSON"))
    if "artifact_revision_id" not in {column["name"] for column in inspect(connection).get_columns("deployment_validation_runs") }:
        connection.execute(text("ALTER TABLE deployment_validation_runs ADD COLUMN artifact_revision_id INTEGER"))
    artifact_columns = {column["name"] for column in inspect(connection).get_columns("service_artifacts")}
    for column_name, definition in (
        ("parent_repository_id", "INTEGER"), ("source_type", "VARCHAR(30)"),
        ("chart_name", "VARCHAR(240)"), ("chart_version", "VARCHAR(120)"),
        ("source_metadata", "JSON"), ("last_refreshed_at", "TIMESTAMP"),
    ):
        if column_name not in artifact_columns:
            connection.execute(text(f"ALTER TABLE service_artifacts ADD COLUMN {column_name} {definition}"))
    revision_columns = {column["name"] for column in inspect(connection).get_columns("service_artifact_revisions")}
    if "source_metadata" not in revision_columns:
        connection.execute(text("ALTER TABLE service_artifact_revisions ADD COLUMN source_metadata JSON"))
    remediation_columns = {column["name"] for column in inspect(connection).get_columns("remediation_executions")}
    if "output_mode" not in remediation_columns:
        connection.execute(text("ALTER TABLE remediation_executions ADD COLUMN output_mode VARCHAR(20) DEFAULT 'publish'"))
    if "stages" not in remediation_columns:
        connection.execute(text("ALTER TABLE remediation_executions ADD COLUMN stages JSON"))
    if "retry_of_id" not in remediation_columns:
        connection.execute(text("ALTER TABLE remediation_executions ADD COLUMN retry_of_id INTEGER"))
    for column_name, definition in (
        ("source_execution_id", "INTEGER"), ("source_version_id", "INTEGER"),
        ("revision_number", "INTEGER"), ("artifact_digest", "VARCHAR(80)"),
        ("workflow_inputs", "JSON"),
        ("remediation_status", "VARCHAR(30) DEFAULT 'pending'"),
        ("delivery_status", "VARCHAR(30) DEFAULT 'not_delivered'"),
        ("verification_status", "VARCHAR(30) DEFAULT 'not_verified'"),
        ("signing_status", "VARCHAR(30) DEFAULT 'not_requested'"),
    ):
        if column_name not in remediation_columns:
            connection.execute(text(f"ALTER TABLE remediation_executions ADD COLUMN {column_name} {definition}"))
            if column_name in {"remediation_status", "delivery_status", "verification_status", "signing_status"}:
                # Historic combined statuses cannot prove any individual lifecycle.
                connection.execute(text(f"UPDATE remediation_executions SET {column_name} = 'legacy_unknown'"))
    # Conservatively link legacy WORKING rows only when their strict historical
    # reference resolves to one exact revision owned by the same service.
    legacy_working = connection.execute(text(
        "SELECT id, service_id, artifact_reference FROM deployment_validation_runs "
        "WHERE artifact_type = 'WORKING' AND artifact_revision_id IS NULL"
    )).mappings().all()
    for legacy in legacy_working:
        match = re.fullmatch(r"artifact:(\d+):r(\d+)", str(legacy["artifact_reference"] or ""))
        if not match:
            continue
        revision_id = connection.execute(text(
            "SELECT r.id FROM service_artifact_revisions r JOIN service_artifacts a ON a.id = r.artifact_id "
            "WHERE a.id = :artifact_id AND a.service_id = :service_id AND r.revision_number = :revision_number"
        ), {"artifact_id": int(match.group(1)), "service_id": legacy["service_id"], "revision_number": int(match.group(2))}).scalar_one_or_none()
        if revision_id:
            connection.execute(text("UPDATE deployment_validation_runs SET artifact_revision_id = :revision_id WHERE id = :run_id"),
                               {"revision_id": revision_id, "run_id": legacy["id"]})
    # Composite indexes match the summary dashboard's bulk filters and latest-
    # execution lookup. They are idempotent and safe for existing deployments.
    for statement in (
        "CREATE INDEX IF NOT EXISTS ix_findings_service_active ON findings (service_id, active)",
        "CREATE INDEX IF NOT EXISTS ix_policy_findings_service_active ON policy_findings (service_id, active)",
        "CREATE INDEX IF NOT EXISTS ix_executions_service_scanned ON executions (service_id, scanned_at)",
        "CREATE INDEX IF NOT EXISTS ix_poam_service_status_due ON poam_entries (service_id, status, due_date)",
        "CREATE INDEX IF NOT EXISTS ix_finding_observations_finding_id_id ON finding_observations (finding_id, id)",
        # One (finding_id, execution_id, id) index is sufficient: keep the model's
        # ix_obs_finding_execution_id and drop the identical legacy duplicate,
        # which only doubled observation write and storage cost.
        "CREATE INDEX IF NOT EXISTS ix_obs_finding_execution_id ON finding_observations (finding_id, execution_id, id)",
        "DROP INDEX IF EXISTS ix_finding_observations_finding_execution_id",
        "CREATE INDEX IF NOT EXISTS ix_findings_service_active_order ON findings (service_id, active, episode_started, cve, id)",
        "CREATE INDEX IF NOT EXISTS ix_policy_findings_service_active_order ON policy_findings (service_id, active, episode_started, finding, id)",
        "CREATE INDEX IF NOT EXISTS ix_deployment_validation_artifact_revision ON deployment_validation_runs (artifact_revision_id)",
        "CREATE INDEX IF NOT EXISTS ix_exceptions_finding_active ON exceptions (finding_id, revoked_at, starts_at, expires_at)",
        "CREATE INDEX IF NOT EXISTS ix_policy_exceptions_finding_active ON policy_exceptions (policy_finding_id, revoked_at, starts_at, expires_at)",
    ):
        connection.execute(text(statement))
seed_auth()


def _start_read_model_maintenance():
    """Restore derived read models after an upgrade without blocking startup.

    Loads the KEV/EPSS catalogs once (status is reported on Configuration) and
    rebuilds outdated execution summaries in small committed batches.  Readers
    stay correct meanwhile: a stale summary falls back to the authoritative
    payload.  In-memory databases (tests) are skipped.
    """
    database = engine.url.database
    if engine.url.get_backend_name() == "sqlite" and database in (None, "", ":memory:"):
        return None
    def run():
        log = logging.getLogger("cats.maintenance")
        try:
            intelligence_status()
        except Exception:
            log.exception("Risk intelligence warm-up failed")
        try:
            from .execution_summaries import backfill_stale_summaries
            refreshed = backfill_stale_summaries(SessionLocal)
            if refreshed:
                log.info("Rebuilt %s execution summaries", refreshed)
        except Exception:
            log.exception("Execution summary backfill failed; readers continue with payload fallback")
    thread = threading.Thread(target=run, name="cats-read-model-maintenance", daemon=True)
    thread.start()
    return thread


@asynccontextmanager
async def app_lifespan(_app: FastAPI):
    # Recovery is a safety obligation even when administrators disable new runs.
    validator_management.recover_operations()
    DEPLOYMENT_VALIDATION_WORKERS.submit(recover_stale_validation_runs)
    REMEDIATION_WORKERS.submit(_recover_retained_candidate_validations)
    async def monitor_validators():
        while True:
            try:
                await asyncio.to_thread(validator_management.maintenance)
            except Exception:
                logging.getLogger(__name__).exception('Managed validator maintenance failed')
            await asyncio.sleep(30)
    monitor = asyncio.create_task(monitor_validators())
    _start_read_model_maintenance()
    try:
        async with preview_cleanup_lifespan(SessionLocal):
            yield
    finally:
        monitor.cancel()
        try:
            await monitor
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Continuous Assessment & Tracking System", version="2.0.0", lifespan=app_lifespan)
app.include_router(validator_management.router)
app.add_middleware(PerformanceMiddleware)
from .exchange_routes import router as exchange_router
app.include_router(exchange_router)
app.include_router(service_oci.router)
from .definition_routes import router as definition_router
app.include_router(definition_router)
from .upload_limits import UploadLimitMiddleware
app.add_middleware(UploadLimitMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=5)
app.add_middleware(PerformanceMiddleware)
snapshot_logger = logging.getLogger("cats.snapshot")
PIPELINE_MAX_REQUEST_BYTES = max(1024, int(os.getenv("CATS_PIPELINE_MAX_REQUEST_BYTES", str(16 * 1024 * 1024))))


@app.middleware("http")
async def pipeline_request_size_middleware(request: Request, call_next):
    if request.url.path == "/api/v1/pipeline-results":
        try:
            content_length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
        if content_length > PIPELINE_MAX_REQUEST_BYTES:
            return JSONResponse({"detail": "Pipeline evidence exceeds the configured request-size limit"}, status_code=413)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > PIPELINE_MAX_REQUEST_BYTES:
                return JSONResponse({"detail": "Pipeline evidence exceeds the configured request-size limit"}, status_code=413)
            body.extend(chunk)
        # Starlette's cached request wrapper replays this bounded body to the
        # downstream JSON parser, including for chunked/missing-length input.
        request._body = bytes(body)
    return await call_next(request)


@app.middleware("http")
async def snapshot_timing_middleware(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    if request.url.path in {"/", "/cybersecurity", "/api/dashboard/services", "/api/dashboard/cybersecurity"} or request.url.path.startswith("/api/dashboard/cybersecurity/services/"):
        timings = getattr(request.state, "snapshot_timings", {})
        timings["http_total_ms"] = round((time.perf_counter() - started) * 1000, 2)
        snapshot_logger.debug("service_snapshot_timing", extra={"path": request.url.path, "status": response.status_code, "timings_ms": timings})
    return response
root = Path(__file__).parent
app.mount("/static", StaticFiles(directory=root / "static"), name="static")
templates = Jinja2Templates(directory=root / "templates")
templates.env.globals["cats_deployed_version"] = deployed_version()


def _api_error_request(request: Request) -> bool:
    return request.url.path.startswith("/api/") or (
        "application/json" in request.headers.get("accept", "")
        and "text/html" not in request.headers.get("accept", "")
    )


@app.exception_handler(StarletteHTTPException)
async def expected_http_error(request: Request, exc: StarletteHTTPException):
    if _api_error_request(request):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
    descriptions = {403: "You do not have permission to access this page or perform this action.",
                    404: "The requested page or item was not found."}
    detail = descriptions.get(exc.status_code, str(exc.detail) if isinstance(exc.detail, str) else "The request could not be completed.")
    return templates.TemplateResponse(request, "request_error.html",
                                      {"detail": detail, "home_url": request.url_for("dashboard")},
                                      status_code=exc.status_code, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def expected_validation_error(request: Request, exc: RequestValidationError):
    if _api_error_request(request):
        return JSONResponse({"detail": jsonable_encoder(exc.errors())}, status_code=422)
    return templates.TemplateResponse(request, "request_error.html",
                                      {"detail": "Please check the submitted fields and try again.",
                                       "home_url": request.url_for("dashboard")}, status_code=422)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    logging.getLogger("cats.portal").exception("Unexpected request failure", exc_info=exc)
    if _api_error_request(request):
        return JSONResponse({"detail": "Something went wrong while processing your request."}, status_code=500)
    return templates.TemplateResponse(request, "boozled.html", {"home_url": request.url_for("dashboard")}, status_code=500)

# Public scan jobs are deliberately ephemeral. The worker writes only to a
# temporary job directory and the in-memory index is lost on process restart.
PUBLIC_JOB_ROOT = Path(os.getenv("CATS_PUBLIC_JOB_ROOT", Path(tempfile.gettempdir()) / "cats-public-jobs"))
PUBLIC_JOB_ROOT.mkdir(parents=True, exist_ok=True)
PUBLIC_JOBS: dict[str, dict] = {}
PUBLIC_PROCESSES: dict[str, subprocess.Popen] = {}
PUBLIC_JOB_LOCK = threading.Lock()
PUBLIC_WORKERS = ThreadPoolExecutor(max_workers=max(1, int(os.getenv("CATS_PUBLIC_WORKERS", "2"))))
SBOM_OUTPUT_FORMATS = {
    "syft-json": "Syft JSON",
    "cyclonedx-json": "CycloneDX JSON",
    "cyclonedx-xml": "CycloneDX XML",
    "spdx-json": "SPDX JSON",
}
CYCLONEDX_SPEC_VERSIONS = ("1.4", "1.5", "1.6")
PATCH_JOB_ROOT = Path(os.getenv("CATS_PATCH_JOB_ROOT", Path(tempfile.gettempdir()) / "cats-patch-jobs"))
PATCH_JOB_ROOT.mkdir(parents=True, exist_ok=True)
PATCH_JOBS: dict[str, dict] = {}
PATCH_PROCESSES: dict[str, subprocess.Popen] = {}
PATCH_JOB_LOCK = threading.Lock()
PATCH_WORKER_URL = os.getenv("CATS_PATCH_WORKER_URL", "").rstrip("/")
PATCH_WORKER_TOKEN = os.getenv("CATS_PATCH_WORKER_TOKEN", "")
REMEDIATION_JOB_ROOT = Path(os.getenv("CATS_REMEDIATION_JOB_ROOT", Path(tempfile.gettempdir()) / "cats-remediation-jobs"))
REMEDIATION_JOB_ROOT.mkdir(parents=True, exist_ok=True)
REMEDIATION_WORKERS = ThreadPoolExecutor(max_workers=max(1, int(os.getenv("CATS_REMEDIATION_WORKERS", "2"))))
DEPLOYMENT_VALIDATION_WORKERS = ThreadPoolExecutor(max_workers=max(1, int(os.getenv("CATS_DEPLOYMENT_VALIDATION_WORKERS", "1"))))


@lru_cache(maxsize=1024)
def _resolve_manifest_digest(reference: str) -> str | None:
    """Best-effort OCI enrichment; failure never changes assessment state."""
    if os.getenv("CATS_RESOLVE_IMAGE_DIGESTS", "true").lower() not in {"1", "true", "yes"}:
        return None
    try:
        completed = subprocess.run(
            ["docker", "manifest", "inspect", "--verbose", reference],
            capture_output=True, text=True, timeout=4, check=False,
        )
        if completed.returncode:
            return None
        candidate = json.loads(completed.stdout)
        candidates = candidate if isinstance(candidate, list) else [candidate]
        for manifest in candidates:
            if not isinstance(manifest, dict):
                continue
            digest = (manifest.get("Descriptor") or {}).get("digest") or manifest.get("digest")
            if str(digest or "").startswith("sha256:"):
                return str(digest)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def utcnow():
    return datetime.now(timezone.utc)


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def deployment_validation_enabled() -> bool:
    return os.getenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


VALIDATION_TERMINAL_STATUSES = {item.value for item in ValidationStatus} | {"FAILED", "ERROR", "CANCELLED", "TIMED_OUT"}


def deployment_validation_view(run: DeploymentValidationRun | None) -> dict | None:
    if not run:
        return None
    terminal_statuses = VALIDATION_TERMINAL_STATUSES
    cleanup_terminal = str(run.cleanup_status or "").upper() in {"COMPLETE", "FAILED", "NOT_REQUIRED", "NOT_ATTEMPTED", "UNKNOWN"}
    terminal = str(run.status or "").upper() in terminal_statuses and str(run.phase or "").upper() == "COMPLETE" and cleanup_terminal
    return {
        "id": run.id, "run_id": run.run_key, "run_key": run.run_key,
        "status": run.status, "phase": run.phase, "engine": run.engine,
        "artifact_type": run.artifact_type, "artifact_reference": run.artifact_reference,
        "artifact_revision_id": run.artifact_revision_id,
        "execution_key": run.execution.execution_key if run.execution else None,
        "execution_scanned_at": run.execution.scanned_at if run.execution else None,
        "static_scan_complete": run.execution.complete if run.execution else None,
        "created_at": run.created_at, "started_at": run.started_at,
        "completed_at": run.completed_at, "checked_at": run.completed_at or run.started_at or run.created_at,
        "duration_seconds": run.duration_seconds, "reason_category": run.reason_category,
        "classification": run.status, "classification_reasons": run.classification_reasons or [],
        "classification_summary": (run.diagnostics or {}).get("classification_summary") or (run.diagnostics or {}).get("classification", {}),
        "capability_assessment": capability_assessment_groups(run.capability_preflight or []),
        "reason": run.reason, "detail": run.reason,
        "failure_details": runtime_failure_details({**((run.diagnostics or {}).get("runtime_evidence") or {"events": run.events or []}), "helm_failures": (run.diagnostics or {}).get("helm_failures") or []}) if run.status != "VERIFIED" else [],
        # Security boundary violations remain preflight blocks; optional
        # resource-governance warnings are exposed separately below.
        "preflight_blocked": run.reason_category == "SECURITY_POLICY_VIOLATION" or bool(run.security_policy_violations or []),
        "cluster_name": run.cluster_name,
        "namespace": run.namespace, "cleanup_status": run.cleanup_status,
        "helm": run.helm_result or {}, "helm_result": run.helm_result or {},
        "resources": run.resource_summary or {}, "resource_summary": run.resource_summary or {},
        "conditions": run.conditions or {}, "dependencies": run.dependencies or {},
        "observed_topology": run.observed_topology or {}, "comparison": run.comparison or {},
        "events": run.events or [], "unhealthy_resources": run.unhealthy_resources or [],
        "capability_preflight": run.capability_preflight or [],
        "capability_bootstrap": run.capability_bootstrap or {},
        "security_policy_violations": run.security_policy_violations or [],
        "sandbox_sensitive_behaviors": (run.diagnostics or {}).get("sandbox_preflight", []),
        "policy_violations": run.security_policy_violations or [],
        "resource_isolation": run.resource_isolation or {},
        "warnings": run.warnings or [],
        "diagnostics": run.diagnostics or {},
        "checks": {"helm_template": (run.helm_result or {}).get("template", "NOT_ATTEMPTED"),
                   "helm_install": (run.helm_result or {}).get("install", "NOT_ATTEMPTED"),
                   "cleanup": run.cleanup_status},
        "cleanup_terminal": cleanup_terminal,
        "terminal": terminal,
    }


def artifact_validation_summary(run: DeploymentValidationRun | None) -> dict:
    """Small, exact-revision display summary for the Artifacts workspace."""
    if not run:
        return {"key": "not-validated", "label": "Not Validated", "symbol": "\u2014", "run_key": None}
    status = str(run.status or "").upper()
    blocked = run.reason_category == "SECURITY_POLICY_VIOLATION" or bool(run.security_policy_violations or [])
    if status == ValidationStatus.VERIFIED.value:
        key, label, symbol = "validated", "Validated", "\u2713"
    elif status == ValidationStatus.PARTIALLY_VERIFIED.value:
        key, label, symbol = "partially-validated", "Partially Validated", "\u25d0"
    elif blocked:
        key, label, symbol = "blocked", "Blocked", "!"
    elif status in {ValidationStatus.COULD_NOT_VALIDATE.value, "FAILED"}:
        key, label, symbol = "failed", "Validation Failed", "\u00d7"
    elif status in {"ERROR", "TIMED_OUT", "CANCELLED"}:
        key, label, symbol = "unable", "Unable to Validate", "!"
    elif status == ValidationStatus.NOT_ATTEMPTED.value:
        key, label, symbol = "not-validated", "Not Validated", "\u2014"
    else:
        key, label, symbol = "in-progress", "Validation In Progress", "\u2026"
    return {
        "key": key, "label": label, "symbol": symbol, "run_key": run.run_key,
        "checked_at": run.completed_at or run.started_at or run.created_at,
        "reason": run.reason,
    }


def latest_eligible_helm_execution(executions: list[Execution]) -> Execution | None:
    eligible = [execution for execution in executions if execution.scan_scope == "service" and isinstance(execution.raw_payload, dict)
                and execution.raw_payload.get("artifact_type") == "helm" and execution.raw_payload.get("helm_source_files")]
    return max(eligible, key=lambda item: aware(item.scanned_at), default=None)


def latest_architecture_execution(executions: list[Execution]) -> Execution | None:
    def has_architecture(execution: Execution) -> bool:
        payload = execution.raw_payload if isinstance(execution.raw_payload, dict) else {}
        overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
        return bool(overview.get("rendered_resources") or payload.get("rendered_resources") or payload.get("helm_source_files"))
    return max((item for item in executions if has_architecture(item)), key=lambda item: aware(item.scanned_at), default=None)


_REMEDIATION_PREVIEW_CACHE: "OrderedDict[tuple, tuple]" = OrderedDict()
_REMEDIATION_PREVIEW_LOCK = threading.Lock()


def _remediation_preview_cached(key, compute):
    """Small LRU for the display-only remediation preview counts.

    The key holds the evidence digest and every active policy finding field,
    so any new scan or finding change computes a fresh preview.
    """
    if key[1] is None:
        return compute()
    with _REMEDIATION_PREVIEW_LOCK:
        if key in _REMEDIATION_PREVIEW_CACHE:
            _REMEDIATION_PREVIEW_CACHE.move_to_end(key)
            return _REMEDIATION_PREVIEW_CACHE[key]
    value = compute()
    with _REMEDIATION_PREVIEW_LOCK:
        _REMEDIATION_PREVIEW_CACHE[key] = value
        while len(_REMEDIATION_PREVIEW_CACHE) > 64:
            _REMEDIATION_PREVIEW_CACHE.popitem(last=False)
    return value


def _architecture_has_resources(payload) -> bool:
    """Whether retained evidence declares any Kubernetes resources (Architecture READY)."""
    from .execution_summaries import architecture_has_resources
    return architecture_has_resources(payload)


def latest_architecture_working_revision(db: Session, service_id: int) -> ServiceArtifactRevision | None:
    """Return the newest edited architecture subject, never an untouched copy of scan evidence."""
    return db.scalar(
        select(ServiceArtifactRevision)
        .join(ServiceArtifact)
        .where(
            ServiceArtifact.service_id == service_id,
            ServiceArtifact.artifact_type.in_(("helm", "kubernetes")),
            ServiceArtifact.lifecycle_status == "active",
            ServiceArtifactRevision.revision_label == "WORKING",
        )
        .order_by(ServiceArtifactRevision.created_at.desc(), ServiceArtifactRevision.id.desc())
        .limit(1)
    )


def _validation_audit(db: Session, run: DeploymentValidationRun, action: str, **detail) -> None:
    db.add(AuditEvent(
        action=action, target_type="deployment_validation", target_id=str(run.id),
        detail={"service_id": run.service_id, "run_key": run.run_key,
                "artifact_type": run.artifact_type, **detail},
    ))


def _new_validation_run(
    db: Session, service: Service, execution: Execution | None, *, requested_by_id: int | None = None,
    artifact_type: str = "ORIGINAL", artifact_reference: str | None = None,
    artifact_revision_id: int | None = None, source_files_override: dict[str, str] | None = None,
) -> tuple[DeploymentValidationRun, bool]:
    source_files = source_files_override if source_files_override is not None else (
        execution.raw_payload.get("helm_source_files") if execution and isinstance(execution.raw_payload, dict) else {}
    )
    enabled = deployment_validation_enabled()
    can_attempt = enabled and isinstance(source_files, dict) and bool(source_files)
    reason = None
    if not enabled:
        reason = "Deployment Validation is disabled by configuration. Static scan state remains unchanged and authoritative."
    elif not source_files:
        reason = "The scan did not retain Helm source files required for Deployment Validation."
    run = DeploymentValidationRun(
        run_key=f"DV-{uuid.uuid4().hex[:20].upper()}", service_id=service.id,
        execution_id=execution.id if execution else None, requested_by_id=requested_by_id,
        artifact_revision_id=artifact_revision_id,
        artifact_type=artifact_type, artifact_reference=artifact_reference or (execution.execution_key if execution else None),
        engine="kind", status="QUEUED" if can_attempt else ValidationStatus.NOT_ATTEMPTED.value,
        phase="QUEUED" if can_attempt else "COMPLETE", reason_category=None, reason=reason,
        cleanup_status="NOT_ATTEMPTED",
    )
    db.add(run); db.flush()
    _validation_audit(db, run, "deployment_validation.queued" if can_attempt else "deployment_validation.not_attempted", reason=reason)
    return run, can_attempt


def _validation_progress(run_id: int, phase: str) -> None:
    if phase not in {"PREFLIGHT", "RENDERING", "CREATING_CLUSTER", "INSTALLING", "WAITING_FOR_READY", "COLLECTING", "COMPARING", "CLEANING_UP", "COMPLETE"}:
        return
    actions = {
        "PREFLIGHT": ["deployment_validation.started"],
        "CREATING_CLUSTER": ["deployment_validation.cluster_creation_started"],
        "INSTALLING": ["deployment_validation.cluster_created", "deployment_validation.helm_installation_started"],
        "WAITING_FOR_READY": ["deployment_validation.helm_installation_completed"],
        "COLLECTING": ["deployment_validation.workload_readiness_completed", "deployment_validation.evidence_collection_started"],
        "COMPARING": ["deployment_validation.topology_captured"],
        "CLEANING_UP": ["deployment_validation.cleanup_started"],
    }
    with SessionLocal() as db:
        run = db.get(DeploymentValidationRun, run_id)
        if not run:
            return
        run.phase = phase
        if phase != "COMPLETE":
            run.status = phase
        run.updated_at = utcnow()
        if not run.started_at and phase != "COMPLETE":
            run.started_at = utcnow()
        for action in actions.get(phase, []):
            _validation_audit(db, run, action, phase=phase, cluster_name=run.cluster_name)
        db.commit()


def _run_deployment_validation(run_id: int) -> None:
    try:
        _execute_deployment_validation(run_id)
    except Exception as exc:
        logging.getLogger("cats.deployment_validation").exception("Deployment Validation setup failed", extra={"run_id": run_id})
        with SessionLocal() as db:
            run = db.get(DeploymentValidationRun, run_id)
            if not run or run.phase == "COMPLETE":
                return
            run.status = ValidationStatus.COULD_NOT_VALIDATE.value if run.started_at else "NOT_ATTEMPTED"
            run.phase = "COMPLETE"
            run.reason_category = "INTERNAL_VALIDATION_ERROR"
            run.reason = f"Validation could not complete: {type(exc).__name__}. Inspect the portal logs for this validation run."
            run.cleanup_status = "UNKNOWN" if run.started_at else "NOT_REQUIRED"
            run.classification_reasons = [{"code": run.reason_category, "severity": "blocking", "explanation": run.reason}]
            run.completed_at = utcnow()
            run.updated_at = utcnow()
            _validation_audit(db, run, "deployment_validation.completed", status=run.status, reason_category=run.reason_category)
            db.commit()


def _execute_deployment_validation(run_id: int) -> None:
    config = ValidationConfig.from_env()
    with SessionLocal() as db:
        run = db.get(DeploymentValidationRun, run_id)
        if not run:
            return
        execution = db.get(Execution, run.execution_id) if run.execution_id else None
        if (not execution or not isinstance(execution.raw_payload, dict)) and not run.artifact_revision_id:
            run.status = ValidationStatus.COULD_NOT_VALIDATE.value
            run.phase = "COMPLETE"
            run.reason_category = "SOURCE_EVIDENCE_UNAVAILABLE"
            run.reason = "The source scan evidence is no longer available."
            run.classification_reasons = [{
                "code": "SOURCE_EVIDENCE_UNAVAILABLE", "severity": "blocking",
                "expected_state": "Retained Helm source evidence",
                "observed_state": "Unavailable",
                "explanation": run.reason,
            }]
            run.diagnostics = {
                "classification_summary": {
                    "expected_resources": 0, "observed_expected": 0,
                    "expected_only": 0, "runtime_generated": 0,
                    "observed_only": 0, "failed": 0,
                },
                "classification": {
                    "status": run.status, "reason_category": run.reason_category,
                    "reason_count": 1,
                },
            }
            run.completed_at = utcnow(); run.updated_at = utcnow(); db.commit()
            return
        payload = dict(execution.raw_payload) if execution and isinstance(execution.raw_payload, dict) else {}
        source_files = dict(payload.get("helm_source_files") or {})
        if run.artifact_type == "WORKING":
            revision = db.scalar(select(ServiceArtifactRevision).join(ServiceArtifact).where(
                ServiceArtifactRevision.id == run.artifact_revision_id,
                ServiceArtifact.service_id == run.service_id,
            )) if run.artifact_revision_id else None
            if not revision:
                run.status = ValidationStatus.COULD_NOT_VALIDATE.value
                run.phase = "COMPLETE"
                run.reason_category = "SOURCE_EVIDENCE_UNAVAILABLE"
                run.reason = "The exact immutable artifact revision selected for validation is unavailable. Original evidence was not substituted."
                run.completed_at = utcnow(); run.updated_at = utcnow(); db.commit()
                return
            source_files = dict(revision.files or {})
        overview = payload.get("service_overview") if isinstance(payload.get("service_overview"), dict) else {}
        declared = overview.get("rendered_resources") or payload.get("rendered_resources") or []
        configuration = get_global_configuration(db)
        remote_validator = validator_management.select_configuration(db, parse_json(configuration.get("validator_configuration"), {}), 'helm-chart')
        if not remote_validator.get("endpoint"):
            run.status = "NOT_ATTEMPTED"
            run.phase = "COMPLETE"
            run.reason_category = "VALIDATOR_UNAVAILABLE"
            run.reason = "No available validator can run this Helm validation. Check validator health, self-test, and available capacity, then retry."
            run.cleanup_status = "NOT_REQUIRED"
            run.completed_at = utcnow()
            run.updated_at = utcnow()
            _validation_audit(db, run, "deployment_validation.completed", status=run.status, reason_category=run.reason_category)
            db.commit()
            return
        service_key_for_validation = db.get(Service, run.service_id).service_key
        retained_version = db.get(ServiceVersion, execution.service_version_id) if execution and execution.service_version_id else None
        validation_service = {"id": service_key_for_validation, "version": retained_version.version if retained_version else "Unversioned"}
        trusted_cas = parse_json(configuration.get("trusted_ca_certificates"), [])
        artifact = ValidationArtifact(
            source_files=source_files, artifact_type=run.artifact_type,
            values_files=list(payload.get("helm_values_files") or []),
            declared_resources=[item for item in declared if isinstance(item, dict)],
            job_id=run.run_key, reference=run.artifact_reference,
            trusted_ca_certificates=trusted_cas if isinstance(trusted_cas, list) else [], require_helm_lifecycle=True,
        )
        cluster_name, namespace = validation_names(config, run.run_key)
        run.cluster_name = cluster_name; run.namespace = namespace; run.started_at = utcnow(); run.updated_at = utcnow()
        db.commit()
    try:
        from .deployment_bundle import build_helm_archive, file_digest
        from .validator_protocol import REQUEST_SCHEMA_VERSION
        with tempfile.TemporaryDirectory(prefix="cats-original-validation-") as transport:
            archive = Path(transport) / "prepared-helm.zip"
            build_helm_archive(archive, source_files, artifact.values_files, service=validation_service)
            declaration = {"schema_version": REQUEST_SCHEMA_VERSION, "request_id": uuid.uuid4().hex, "validation_type": "helm-chart",
                "service": validation_service, "artifact": {"reference": run.run_key, "digest": file_digest(archive)},
                "deployment": {"type": "helm"}, "validation_profile": "default"}
            result = validate_remote_artifact(remote_validator, declaration, artifact_path=archive,
                progress_callback=lambda value: _validation_progress(run_id, value))
        result["diagnostics"] = {**(result.get("diagnostics") or {}), "schrodinger": {
            key: result.get(key) for key in ("schema_version", "validator", "validation_type", "service", "artifact", "artifact_digest", "deployment", "helm", "network", "offlineVerified")},
            "evidence_scope": run.artifact_type, "source_execution_id": run.execution_id,
            "validated_at": utcnow().isoformat(), "validation_run_id": run.run_key}
    except Exception as exc:  # The optional pass must never escape into scan state.
        logging.getLogger("cats.deployment_validation").exception("Deployment Validation worker failed", extra={"run_id": run_id})
        error_reason = f"Deployment Validation encountered an internal error: {type(exc).__name__}"
        result = {
            "status": ValidationStatus.COULD_NOT_VALIDATE.value, "phase": "COMPLETE",
            "reason_category": "INTERNAL_VALIDATION_ERROR", "reason": error_reason,
            "classification_reasons": [{
                "code": "INTERNAL_VALIDATION_ERROR", "severity": "blocking",
                "expected_state": "Validation completed", "observed_state": "Internal error",
                "explanation": error_reason,
            }],
            "diagnostics": {
                "classification_summary": {
                    "expected_resources": 0, "observed_expected": 0,
                    "expected_only": 0, "runtime_generated": 0,
                    "observed_only": 0, "failed": 0,
                },
                "classification": {
                    "status": ValidationStatus.COULD_NOT_VALIDATE.value,
                    "reason_category": "INTERNAL_VALIDATION_ERROR",
                    "reason_count": 1,
                },
            },
            "cleanup_status": "UNKNOWN",
        }
    with SessionLocal() as db:
        run = db.get(DeploymentValidationRun, run_id)
        if not run:
            return
        for field, key, default in (
            ("status", "status", ValidationStatus.COULD_NOT_VALIDATE.value), ("phase", "phase", "COMPLETE"),
            ("reason_category", "reason_category", None), ("reason", "reason", None),
            ("classification_reasons", "classification_reasons", []),
            ("helm_result", "helm_result", {}), ("resource_summary", "resource_summary", {}),
            ("conditions", "conditions", {}), ("dependencies", "dependencies", {}),
            ("capability_preflight", "capability_preflight", []), ("capability_bootstrap", "capability_bootstrap", {}),
            ("observed_topology", "observed_topology", {}), ("comparison", "comparison", {}),
            ("events", "events", []), ("unhealthy_resources", "unhealthy_resources", []),
            ("security_policy_violations", "security_policy_violations", []),
            ("resource_isolation", "resource_isolation", {}),
            ("warnings", "warnings", []),
            ("diagnostics", "diagnostics", {}), ("cluster_name", "cluster_name", run.cluster_name),
            ("namespace", "namespace", run.namespace), ("cleanup_status", "cleanup_status", "UNKNOWN"),
            ("duration_seconds", "duration_seconds", None),
        ):
            setattr(run, field, result.get(key, default))
        run.completed_at = utcnow(); run.updated_at = utcnow(); run.phase = "COMPLETE"
        terminal_action = {
            ValidationStatus.VERIFIED.value: "deployment_validation.verified",
            ValidationStatus.PARTIALLY_VERIFIED.value: "deployment_validation.partially_verified",
            ValidationStatus.COULD_NOT_VALIDATE.value: "deployment_validation.could_not_validate",
        }.get(run.status, "deployment_validation.completed")
        _validation_audit(db, run, terminal_action, status=run.status, reason_category=run.reason_category, cleanup_status=run.cleanup_status)
        if run.cleanup_status == "COMPLETE":
            _validation_audit(db, run, "deployment_validation.cluster_destroyed", cluster_name=run.cluster_name)
        db.commit()


def _submit_validation_run(run_id: int) -> None:
    try:
        DEPLOYMENT_VALIDATION_WORKERS.submit(_run_deployment_validation, run_id)
    except Exception:
        logging.getLogger("cats.deployment_validation").exception("Deployment Validation could not be scheduled", extra={"run_id": run_id})
        with SessionLocal() as db:
            run = db.get(DeploymentValidationRun, run_id)
            if run:
                run.status = ValidationStatus.NOT_ATTEMPTED.value; run.phase = "COMPLETE"
                run.reason = "Deployment Validation could not be scheduled. Static scan results are unaffected."
                run.completed_at = utcnow(); run.updated_at = utcnow()
                _validation_audit(db, run, "deployment_validation.not_attempted", reason=run.reason)
                db.commit()


def recover_stale_validation_runs() -> None:
    """Reconcile expired attempts and retry exact-name failed cleanup."""
    config = ValidationConfig.from_env(); cutoff = utcnow() - timedelta(seconds=config.total_timeout_seconds * 2)
    terminal_statuses = tuple(VALIDATION_TERMINAL_STATUSES)
    with SessionLocal() as db:
        runs = db.scalars(select(DeploymentValidationRun).where(
            DeploymentValidationRun.created_at < cutoff,
            or_(DeploymentValidationRun.status.not_in(terminal_statuses), DeploymentValidationRun.cleanup_status.in_(("FAILED", "UNKNOWN"))),
        )).all()
        run_ids = [run.id for run in runs]
        names = [run.cluster_name for run in runs if run.cluster_name]
    if not runs:
        return
    cleanup = cleanup_stale_clusters(names, config=config) if names else {"deleted": [], "failed": []}
    with SessionLocal() as db:
        for run in db.scalars(select(DeploymentValidationRun).where(DeploymentValidationRun.id.in_(run_ids))).all():
            cleanup_retry = run.status in terminal_statuses and run.cleanup_status in {"FAILED", "UNKNOWN"}
            if cleanup_retry:
                run.cleanup_status = "FAILED" if run.cluster_name in cleanup["failed"] else "COMPLETE"
                run.reason = "Stale ephemeral resources were removed during recovery; the original validation outcome is retained." if run.cleanup_status == "COMPLETE" else "Stale ephemeral resources still require administrator cleanup."
                run.updated_at = utcnow()
                _validation_audit(db, run, "deployment_validation.cleanup_retried", cleanup_status=run.cleanup_status)
                continue
            never_started = not run.cluster_name and not run.started_at
            run.status = ValidationStatus.NOT_ATTEMPTED.value if never_started else ValidationStatus.COULD_NOT_VALIDATE.value; run.phase = "COMPLETE"
            run.reason_category = None if never_started else ("CLEANUP_FAILURE" if run.cluster_name in cleanup["failed"] else "WORKLOAD_TIMEOUT")
            run.reason = "A queued validation could not be scheduled before the worker stopped." if never_started else "A stale validation attempt was recovered after the worker stopped unexpectedly."
            run.cleanup_status = "NOT_REQUIRED" if never_started else ("FAILED" if run.cluster_name in cleanup["failed"] else ("COMPLETE" if run.cluster_name else "NOT_REQUIRED"))
            run.completed_at = utcnow(); run.updated_at = utcnow()
            _validation_audit(db, run, "deployment_validation.stale_recovered", cleanup_status=run.cleanup_status)
        db.commit()


def cybersecurity_group(service: Service):
    """Choose the service's Cybersecurity scope for an optional bulk request."""
    groups = list(getattr(service, "groups", []) or [])
    named = [group for group in groups if "cyber" in group.name.lower()]
    if len(named) == 1:
        return named[0]
    return groups[0] if len(groups) == 1 else None


def policy_finding_values(item) -> dict:
    raw = item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
    optional_fields = ("scanner", "framework", "target", "namespace", "title", "description", "remediation", "fingerprint")
    field_limits = {"scanner": 120, "framework": 240, "namespace": 240, "title": 500, "fingerprint": 240}
    finding_name = str(raw.get("finding") or "Unknown").strip() or "Unknown"
    values = {
        "finding": finding_name[:120],
        "severity": str(raw.get("severity") or "Unknown").strip()[:30],
    }
    for field in optional_fields:
        value = raw.get(field)
        values[field] = str(value).strip() if value is not None and str(value).strip() else None
        if values[field] and field in field_limits:
            values[field] = values[field][:field_limits[field]]
    return values


def policy_finding_identity(values: dict) -> str:
    if values.get("fingerprint"):
        source = {"fingerprint": values["fingerprint"]}
    else:
        source = {
            key: values.get(key)
            for key in ("scanner", "framework", "finding", "target", "namespace")
        }
    encoded = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=True).casefold()
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def sync_policy_findings(db: Session, service: Service, items, scanned_at: datetime, complete: bool) -> None:
    existing = {
        item.identity_key: item
        for item in db.scalars(select(PolicyFinding).where(PolicyFinding.service_id == service.id))
    }
    observed = set()
    for payload_item in items:
        values = policy_finding_values(payload_item)
        identity_key = policy_finding_identity(values)
        observed.add(identity_key)
        finding = existing.get(identity_key)
        if not finding:
            finding = PolicyFinding(
                service_id=service.id, identity_key=identity_key,
                first_seen=scanned_at, episode_started=scanned_at,
                last_seen=scanned_at, active=True, **values,
            )
            db.add(finding)
            existing[identity_key] = finding
        else:
            if not finding.active:
                finding.active = True
                finding.episode_started = scanned_at
                finding.resolved_at = None
                finding.recurrence_count += 1
            finding.last_seen = scanned_at
            for field, value in values.items():
                setattr(finding, field, value)
    if complete:
        for finding in existing.values():
            if finding.active and finding.identity_key not in observed:
                finding.active = False
                finding.resolved_at = scanned_at


def backfill_policy_findings() -> None:
    """Materialize the latest legacy JSON policy findings without changing evidence."""
    with SessionLocal() as db:
        latest_id = select(Execution.id).where(Execution.service_id == Service.id).order_by(
            Execution.scanned_at.desc(), Execution.id.desc()).limit(1).correlate(Service).scalar_subquery()
        services = db.execute(select(Service.id, latest_id.label("execution_id"))).all()
        changed = False
        for offset in range(0, len(services), 32):
            ids = [row.execution_id for row in services[offset:offset + 32] if row.execution_id]
            for latest in db.scalars(select(Execution).where(Execution.id.in_(ids))):
                items = latest.raw_payload.get("policy_findings", []) if isinstance(latest.raw_payload, dict) else []
                if items:
                    sync_policy_findings(db, SimpleNamespace(id=latest.service_id), items, latest.scanned_at, complete=False)
                    changed = True
            db.flush()
        if changed:
            db.commit()


backfill_policy_findings()


def restore_generated_staging_name(service: Service) -> bool:
    """Restore a name only when CATS recorded that it generated the staging label."""
    if not service.staging_name_generated or not service.staging_original_name:
        return False
    changed = service.name != service.staging_original_name
    service.name = service.staging_original_name
    service.staging_original_name = None
    service.staging_name_generated = False
    return changed


def reconcile_generated_active_names() -> int:
    """One-way startup repair for active services affected by the old promotion bug."""
    restored = 0
    with SessionLocal() as db:
        services = db.scalars(select(Service).where(
            Service.lifecycle_status == "active", Service.staging_name_generated.is_(True),
        )).all()
        for service in services:
            previous_name = service.name
            if not restore_generated_staging_name(service):
                continue
            db.add(AuditEvent(
                action="service.name_restored", target_type="service", target_id=str(service.id),
                detail={"service_id": service.id, "reason": "generated_staging_name_reconciliation",
                        "previous_name": previous_name, "name": service.name},
            ))
            restored += 1
        if restored:
            db.commit()
    return restored


reconcile_generated_active_names()


def promote_staged_services_with_evidence() -> int:
    """Repair staged records that were populated before lifecycle promotion existed.

    Staging is an empty pre-ingest state. A service that already has an
    execution, finding, policy finding, or image is no longer staged, even if
    the original ingest happened before the automatic promotion logic.
    """
    promoted = 0
    with SessionLocal() as db:
        services = db.scalars(
            select(Service)
            .where(Service.lifecycle_status == "staged")
            .options(
                selectinload(Service.executions),
                selectinload(Service.findings),
                selectinload(Service.policy_findings),
                selectinload(Service.images),
            )
        ).all()
        for service in services:
            if not (service.executions or service.findings or service.policy_findings or service.images):
                continue
            previous_name = service.name
            restore_generated_staging_name(service)
            service.lifecycle_status = "active"
            db.add(AuditEvent(
                action="service.promoted", target_type="service", target_id=str(service.id),
                detail={"service_id": service.id, "reason": "existing_ingested_evidence",
                        "previous_name": previous_name, "name": service.name},
            ))
            promoted += 1
        if promoted:
            db.commit()
    return promoted


promote_staged_services_with_evidence()


def optional_form_datetime(value: str, field_name: str) -> datetime | None:
    if not value.strip():
        return None
    try:
        return aware(datetime.fromisoformat(value.strip()))
    except ValueError as exc:
        raise HTTPException(422, detail=f"{field_name} must be a valid date and time") from exc


def excel_datetime(value):
    return aware(value).astimezone(timezone.utc).replace(tzinfo=None) if value else None


def page_context(auth: AuthContext, **values):
    # Keep the global navigation useful without making each individual page
    # route calculate workflow state.  The count is limited to pending
    # requests for services visible to the signed-in account.
    pending_request_count = 0
    pending_poam_count = 0
    actionable_notifications = []
    try:
        allowed_services = auth.accessible_service_ids("service.view")
        with SessionLocal() as nav_db:
            request_query = select(
                WorkflowRequest.request_type, WorkflowRequest.service_id,
                WorkflowRequest.requested_by_id, Service.name,
            ).join(Service, Service.id == WorkflowRequest.service_id).where(WorkflowRequest.status == "pending")
            if allowed_services is not None:
                request_query = request_query.where(
                    WorkflowRequest.service_id.in_(allowed_services)
                )
            permission_by_type = {"exception": "exception.review", "poam": "poam.review", "poam_update": "poam.review", "poam_complete": "poam.review", "poam_reopen": "poam.review", "archive": "archive.review", "image_remove": "archive.review", "image_replace": "archive.review"}
            pending_items = nav_db.execute(request_query).all()
            for item in pending_items:
                if item.requested_by_id == auth.user.id:
                    continue
                permission = permission_by_type.get(item.request_type, "exception.review")
                if not auth.has(permission, item.service_id):
                    continue
                actionable_notifications.append({"label": item.request_type.replace("_", " ").title(), "service": item.name or "Service"})
            pending_request_count = len(actionable_notifications)
            # The pending rows already use the same status and service scope
            # as the navigation count, so counting them in memory avoids a
            # second query against workflow_requests.
            pending_poam_count = sum(str(item.request_type).startswith("poam") for item in pending_items)
    except Exception:
        # Navigation must never prevent a page from rendering if an older
        # deployment is still applying its database migrations.
        pending_request_count = 0
    return {
        "current_user": auth.user,
        "csrf_token": auth.csrf_token,
        "can": auth.has,
        "themes": THEMES,
        "pending_request_count": pending_request_count,
        "pending_poam_count": pending_poam_count,
        "actionable_notifications": actionable_notifications[:8],
        **values,
    }


CONFIG_DEFAULTS = {
    "overdue_days": "90",
    "hardening_overdue_days": "90",
    "hardening_noncompliant": "true",
    "warning_days": "14",
    "exception_max_days": "365",
    "skipped_images_incomplete": "true",
    "incomplete_noncompliant": "true",
    "kev_enabled": "true",
    "kev_noncompliant": "true",
    "epss_enabled": "true",
    "epss_threshold": "0.90",
    "epss_rules": '[{"severity":"Critical","threshold":0.90,"noncompliant":true},{"severity":"High","threshold":0.80,"noncompliant":true},{"severity":"Medium","threshold":0.95,"noncompliant":true}]',
    "minimum_severity": "None",
    "compliance_mode": "raw",
    "raw_due_rules": '[{"severity":"Critical","days":30},{"severity":"High","days":60},{"severity":"Medium","days":90},{"severity":"Low","days":120}]',
    "display_timezone": "UTC",
    "date_format": "%d %b %Y",
    "time_format": "%H:%M UTC",
    "log_level": "INFO",
    "audit_retention_days": "365",
    "identity_mode": "local",
    "trusted_ca_certificates": "[]",
    "repository_policies": "{}",
    "os_definitions": "{}",
    "oidc_configuration": "{}",
    "oci_registries": "[]",
    "image_signing": "{}",
    "validator_configuration": "{}",
    "cyber_warning_policy": '{"critical_high":true,"kev":true,"watchlist":true,"poam":true,"kind":true,"missing_evidence":true}',
    "remediation_enabled": "false",
}

# These settings describe the CATS runtime itself.  They are intentionally
# global; service/group governance remains scoped in configuration_for_service
# and the policy pages.
GLOBAL_CONFIGURATION_KEYS = {
    "display_timezone", "date_format", "time_format", "identity_mode",
    "trusted_ca_certificates", "repository_policies", "os_definitions", "log_level",
    "oidc_configuration", "oci_registries", "image_signing",
    "validator_configuration",
    "cyber_warning_policy",
    "remediation_enabled",
}

DISPLAY_TIMEZONE_FALLBACKS = (
    "UTC", "America/New_York", "America/Chicago", "America/Denver",
    "America/Los_Angeles", "Europe/London", "Europe/Paris", "Asia/Tokyo",
)


def supported_display_timezones() -> list[str]:
    zones = sorted(zone for zone in available_timezones() if "/" in zone or zone == "UTC")
    return zones or list(DISPLAY_TIMEZONE_FALLBACKS)


def scoped_setting_key(key: str, group_id: int | None = None) -> str:
    return f"group:{group_id}:{key}" if group_id is not None else key


def get_configuration(db: Session, group_id: int | None = None) -> dict[str, str]:
    configuration = dict(CONFIG_DEFAULTS)
    for setting in db.scalars(select(PortalSetting).where(PortalSetting.group_id.is_(None) if group_id is None else PortalSetting.group_id == group_id)):
        if group_id is None and setting.group_id is None and not setting.key.startswith("group:"):
            configuration[setting.key] = setting.value
        elif group_id is not None and setting.group_id == group_id:
            configuration[setting.key.split(":", 2)[-1]] = setting.value
    return configuration


def get_global_configuration(db: Session) -> dict[str, str]:
    """Return runtime configuration and safely promote legacy group values.

    Older deployments stored runtime settings under group scopes.  We retain
    those rows for audit/history, but promote the first deterministic value to
    the global key so changing the UI scope cannot silently discard it.
    """
    settings = db.scalars(select(PortalSetting)).all()
    configuration = dict(CONFIG_DEFAULTS)
    configuration.update({setting.key: setting.value for setting in settings
                          if setting.group_id is None and not setting.key.startswith("group:")})
    global_keys = {
        setting.key for setting in settings if setting.group_id is None
    }
    migrated = False
    for key in GLOBAL_CONFIGURATION_KEYS:
        if key in global_keys:
            continue
        legacy = sorted(
            (setting for setting in settings
             if setting.group_id is not None and setting.key.split(":", 2)[-1] == key and setting.value not in (None, "")),
            key=lambda setting: (setting.group_id or 0, setting.id or 0),
        )
        if legacy:
            source = legacy[0]
            setting = PortalSetting(key=key, group_id=None, value=source.value,
                                    updated_by_id=source.updated_by_id, updated_at=utcnow())
            db.add(setting)
            configuration[key] = source.value
            migrated = True
    if migrated:
        db.commit()
    return configuration


def remediation_enabled(db: Session) -> bool:
    return get_global_configuration(db).get("remediation_enabled") == "true"


def configuration_for_service(db: Session, service: Service) -> dict[str, str]:
    """Apply explicit policies for every group assigned to the service.

    Services can belong to more than one group. Using only the numerically
    smallest group caused a policy saved for another assigned group to be
    silently ignored. Later group IDs win deterministically when settings
    overlap.
    """
    configuration = get_configuration(db, None)
    for group_id in sorted(group.id for group in service.groups):
        for setting in db.scalars(select(PortalSetting).where(PortalSetting.group_id == group_id)):
            key = setting.key.split(":", 2)[-1]
            # Runtime settings are global. Ignore legacy group-scoped copies so
            # old rows cannot override the instance-wide configuration.
            if key in GLOBAL_CONFIGURATION_KEYS:
                continue
            configuration[key] = setting.value
    return configuration


def configurations_for_services(
    db: Session,
    services: list[Service],
    global_configuration: dict[str, str] | None = None,
) -> dict[int, dict[str, str]]:
    """Resolve service configuration overrides in bulk.

    The Services overview renders several services in one request. Loading
    the same global settings and then querying each service's groups inside
    the render loop created a database round trip per service. Fetch the
    relevant group settings once and apply the same deterministic override
    rules in memory instead.
    """
    base = dict(global_configuration) if global_configuration is not None else get_configuration(db)
    group_ids = sorted({group.id for service in services for group in service.groups})
    settings_by_group: dict[int, list[PortalSetting]] = {group_id: [] for group_id in group_ids}
    if group_ids:
        for setting in db.scalars(
            select(PortalSetting).where(PortalSetting.group_id.in_(group_ids))
        ):
            settings_by_group.setdefault(setting.group_id, []).append(setting)

    resolved: dict[int, dict[str, str]] = {}
    for service in services:
        configuration = dict(base)
        for group_id in sorted(group.id for group in service.groups):
            for setting in settings_by_group.get(group_id, []):
                key = setting.key.split(":", 2)[-1]
                if key in GLOBAL_CONFIGURATION_KEYS:
                    continue
                configuration[key] = setting.value
        resolved[service.id] = configuration
    return resolved


def manageable_groups(db: Session, auth: AuthContext) -> list[Group]:
    groups = db.scalars(select(Group).order_by(Group.name)).all()
    if any(a.service_id is None and a.group_id is None and a.role.name == "Administrator" for a in auth.user.role_assignments):
        return groups
    allowed = {
        a.group_id for a in auth.user.role_assignments
        if a.group_id is not None and a.role.name == "Cybersecurity" and "config.manage" in (a.role.permissions or [])
    }
    return [group for group in groups if group.id in allowed]


def requested_group_scope(group_id: str | int | None, db: Session, auth: AuthContext) -> int | None:
    try:
        selected = int(group_id) if group_id not in (None, "", "global") else None
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, detail="Invalid group scope") from exc
    if selected is None and auth.can_manage_group(None):
        return None
    if selected is None or not auth.can_manage_group(selected):
        raise HTTPException(403, detail="You cannot administer this group scope")
    return selected


def require_config_scope(request: Request, auth: AuthContext = Depends(require_user)) -> AuthContext:
    """Authorize global or group-scoped administration before form parsing."""
    raw_group = request.query_params.get("group_id")
    try:
        group_id = int(raw_group) if raw_group else None
    except ValueError as exc:
        raise HTTPException(422, detail="Invalid group scope") from exc
    if group_id is None and auth.can_manage_group(None):
        return auth
    if group_id is None or not auth.can_manage_group(group_id):
        raise HTTPException(403, detail="You cannot administer this group scope")
    return auth


def require_global_config_scope(auth: AuthContext = Depends(require_user)) -> AuthContext:
    if not auth.can_manage_group(None):
        raise HTTPException(403, detail="Only global administrators may change runtime configuration")
    return auth


def _json_setting(configuration: dict, key: str, fallback):
    value = parse_json(configuration.get(key), fallback)
    return value if isinstance(value, type(fallback)) else fallback


def configured_oidc(configuration: dict) -> dict:
    value = _json_setting(configuration, "oidc_configuration", {})
    if not isinstance(value, dict):
        value = {}
    safe = {key: str(value.get(key) or "") for key in (
        "provider_name", "issuer", "client_id", "scopes", "username_claim",
        "email_claim", "groups_claim", "roles_claim", "redirect_uri",
        "post_logout_redirect_uri", "browser_issuer",
    )}
    safe["client_secret_configured"] = secret_configured(str(value.get("client_secret") or ""))
    return safe


def configured_registries(configuration: dict) -> list[dict]:
    value = _json_setting(configuration, "oci_registries", [])
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if not isinstance(item, dict):
            continue
        endpoint = str(item.get("endpoint") or "").strip().rstrip("/")
        namespace = str(item.get("namespace") or "").strip().strip("/")
        parsed = urllib.parse.urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
        resolved_path = "/".join(part for part in (parsed.netloc, namespace) if part)
        result.append({
            "id": str(item.get("id") or ""),
            "display_name": str(item.get("display_name") or item.get("endpoint") or "Registry"),
            "endpoint": endpoint,
            "namespace": namespace,
            "resolved_path": resolved_path,
            "auth_mode": str(item.get("auth_mode") or "none"),
            "username": str(item.get("username") or ""),
            "secret_configured": secret_configured(str(item.get("password") or "")),
            "status": str(item.get("status") or "Not tested"),
            "status_detail": str(item.get("status_detail") or ""),
            "use_for_remediation": item.get("use_for_remediation") is True,
        })
    return result


def _configured_registry_for_image(reference: str, registries: list[dict]) -> dict | None:
    """Find centrally configured connection settings for an OCI image host."""
    try:
        host = registry_host(reference).lower()
    except ValueError:
        return None
    for registry in registries:
        if not isinstance(registry, dict):
            continue
        endpoint = str(registry.get("endpoint") or "").strip()
        parsed = urllib.parse.urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
        if (parsed.netloc or "").lower() == host:
            return registry
    return None


def configured_ca_bundle(configuration: dict) -> str | None:
    """Return administrator-added PEM trust material without replacing system trust."""
    certificates = _json_setting(configuration, "trusted_ca_certificates", [])
    pem = [str(item.get("pem") or "") for item in certificates if isinstance(item, dict)]
    value = "\n".join(item for item in pem if "BEGIN CERTIFICATE" in item)
    return value + ("\n" if value else "") or None


def _validate_endpoint(value: str) -> str:
    raw = value.strip().rstrip("/")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, detail="Registry endpoint must be an HTTP or HTTPS URL")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"


def configured_time(
    value,
    include_time: bool = False,
    configuration: dict[str, str] | None = None,
) -> str:
    if not value:
        return ""
    try:
        if configuration is None:
            with SessionLocal() as db:
                configuration = get_configuration(db)
        zone = ZoneInfo(configuration.get("display_timezone", "UTC"))
        date_pattern = configuration.get("date_format", "%d %b %Y")
        if include_time:
            pattern = f"{date_pattern}, {configuration.get('time_format', '%H:%M UTC')}"
        else:
            pattern = date_pattern
        return aware(value).astimezone(zone).strftime(pattern)
    except Exception:
        return aware(value).strftime("%d %b %Y, %H:%M UTC" if include_time else "%d %b %Y")


templates.env.globals["cats_date"] = lambda value, configuration=None: configured_time(value, configuration=configuration)
templates.env.globals["cats_datetime"] = lambda value, configuration=None: configured_time(value, include_time=True, configuration=configuration)


def check_csrf(auth: AuthContext, supplied: str):
    if not secrets.compare_digest(auth.csrf_token, supplied):
        raise HTTPException(403, detail="Invalid CSRF token")


def require_pipeline(authorization: str | None = Header(default=None)):
    expected = os.getenv("PIPELINE_API_TOKEN", "development-token")
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not secrets.compare_digest(supplied.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid pipeline token")


def active_exception(finding: Finding, now: datetime):
    return next((e for e in finding.exceptions if not e.revoked_at and aware(e.starts_at) <= now < aware(e.expires_at)), None)


def archive_state(service: Service):
    latest = max(service.archive_events, key=lambda event: aware(event.created_at), default=None)
    return latest if latest and latest.action == "archive" else None


def service_lifecycle(service: Service) -> str:
    """Return the lifecycle used by the shared service snapshot filters."""
    if archive_state(service):
        return "archived"
    status = str(getattr(service, "lifecycle_status", "active") or "active").lower()
    return status if status in {"active", "staged"} else "active"


def workbook_response(workbook: Workbook, filename: str):
    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def format_sheet(sheet):
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    sheet.sheet_view.showGridLines = False
    header_fill = PatternFill("solid", fgColor="17312B")
    for cell in sheet[1]:
        cell.fill = header_fill
        cell.font = Font(color="FFFFFF", bold=True)
        cell.alignment = Alignment(vertical="center")
    for column in sheet.columns:
        width = min(max(len(str(cell.value or "")) for cell in column) + 2, 55)
        sheet.column_dimensions[get_column_letter(column[0].column)].width = max(width, 12)
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)


def service_view(service: Service, now: datetime, configuration: dict[str, str] | None = None):
    configuration = configuration or CONFIG_DEFAULTS
    overdue_days = max(1, int(configuration.get("overdue_days", "90")))
    warning_days = max(1, int(configuration.get("warning_days", "14")))
    active_all = [f for f in service.findings if f.active]
    resolved = [f for f in service.findings if not f.active]
    vulnerability_exceptions = {f.id: active_exception(f, now) for f in active_all}
    try:
        raw_due_rules = json.loads(configuration.get("raw_due_rules", "[]"))
    except (TypeError, ValueError):
        raw_due_rules = []
    raw_due_by_severity = {str(rule.get("severity", "")).lower(): max(1, int(rule.get("days", overdue_days))) for rule in raw_due_rules}
    def due_days_for(finding):
        return raw_due_by_severity.get(finding.severity.lower(), overdue_days) if configuration.get("compliance_mode") == "raw" else overdue_days
    due_dates = {f.id: aware(f.episode_started) + timedelta(days=due_days_for(f)) for f in active_all}
    overdue = [f for f in active_all if now >= due_dates[f.id] and not vulnerability_exceptions[f.id]]
    warning_items = []
    warning_cutoff = now + timedelta(days=warning_days)
    for finding in active_all:
        exception = vulnerability_exceptions[finding.id]
        due_date = due_dates[finding.id]
        if not exception and now < due_date <= warning_cutoff:
            warning_items.append({"type": "CVE", "item": finding.cve, "reason": "Due date approaching", "due": due_date,
                                  "href": f"/services/{service.service_key}/findings/{finding.id}"})
        elif exception and now < aware(exception.expires_at) <= warning_cutoff:
            warning_items.append({"type": "Exception", "item": finding.cve, "reason": "Exception expires soon", "due": aware(exception.expires_at),
                                  "href": f"/services/{service.service_key}/findings/{finding.id}"})
    current_executions = [e for e in service.executions if
                          service.current_version_id is None or e.service_version_id == service.current_version_id]
    last_execution = max((aware(e.scanned_at) for e in current_executions), default=None)
    latest_execution = max(current_executions, key=lambda e: (aware(e.scanned_at), e.id), default=None)
    version = (service.current_version.version if service.current_version else None) or service.manual_version or (latest_execution.raw_payload.get("service", {}).get("version") if latest_execution else None)
    skipped_images = latest_execution.raw_payload.get("skipped_images", []) if latest_execution else []
    skipped_charts = latest_execution.raw_payload.get("skipped_charts", []) if latest_execution else []
    policy_active_all = [finding for finding in service.policy_findings if finding.active]
    hardening_overdue_days = max(1, int(configuration.get("hardening_overdue_days", "90")))
    hardening_noncompliant = configuration.get("hardening_noncompliant", "true") == "true"
    policy_due_dates = {
        finding.id: aware(finding.episode_started) + timedelta(days=hardening_overdue_days)
        for finding in policy_active_all
    }


    policy_exceptions = {finding.id: active_exception(finding, now) for finding in policy_active_all}
    policy_excepted = [finding for finding in policy_active_all if policy_exceptions[finding.id]]
    policy_noncompliant = [
        finding for finding in policy_active_all
        if hardening_noncompliant and not policy_exceptions[finding.id] and now >= policy_due_dates[finding.id]
    ]
    policy_noncompliant_ids = {finding.id for finding in policy_noncompliant}
    policy_findings = [
        finding for finding in policy_active_all
        if not policy_exceptions[finding.id] and finding.id not in policy_noncompliant_ids
    ]
    policy_resolved = [finding for finding in service.policy_findings if not finding.active]
    poam_active = [entry for entry in service.poam_entries if entry.status == "active"]
    latest_payload = latest_execution.raw_payload if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
    missing_evidence = normalize_overview(
        latest_payload.get("service_overview") or {},
        skipped_images=skipped_images or [], skipped_charts=skipped_charts or [],
        incomplete=bool(latest_execution and not latest_execution.complete),
        digest_resolver=None,
    )["missing_evidence"]
    incomplete = bool(latest_execution and (not latest_execution.complete or missing_evidence))
    try:
        epss_rules = json.loads(configuration.get("epss_rules", "[]"))
    except (TypeError, ValueError):
        epss_rules = []
    if not epss_rules:
        epss_rules = [{"severity": "Any", "threshold": float(configuration.get("epss_threshold", "0.90")), "noncompliant": True}]
    compliance_mode = configuration.get("compliance_mode", "risk_based")
    # Raw mode evaluates every fixable finding. Risk-based mode first builds the
    # overlay-visible set from KEV, EPSS, and minimum-severity matches; age only
    # determines when a visible finding becomes non-compliant.
    risk_eligible = set(f.id for f in active_all) if compliance_mode == "raw" else set()
    risk_findings = set(f.id for f in overdue) if compliance_mode == "raw" else set()
    risk_metadata_by_finding = {}
    severity_rank = {"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    minimum_severity = configuration.get("minimum_severity", "None").lower()
    if compliance_mode != "raw" and minimum_severity in severity_rank:
        severity_matches = {
            finding.id for finding in active_all
            if severity_rank.get(finding.severity.lower(), 0) >= severity_rank[minimum_severity]
        }
        risk_eligible.update(severity_matches)
        risk_findings.update(
            finding.id for finding in active_all
            if finding.id in severity_matches and now >= due_dates[finding.id]
            and not vulnerability_exceptions[finding.id]
        )
    for finding in active_all:
        observation = max(finding.observations, key=lambda item: item.id, default=None)
        evidence = observation.evidence if observation else {}
        catalog_kev, catalog_epss = risk_metadata(finding.cve)
        kev = bool(evidence.get("kev", evidence.get("known_exploited", catalog_kev))) or catalog_kev
        try:
            epss = float(evidence.get("epss", evidence.get("epss_score", catalog_epss or 0)) or 0)
        except (TypeError, ValueError):
            epss = 0
        risk_metadata_by_finding[finding.id] = {"kev": kev, "epss": epss}
        if compliance_mode != "raw" and configuration.get("kev_enabled") == "true" and kev:
            risk_eligible.add(finding.id)
            if configuration.get("kev_noncompliant") == "true" and now >= due_dates[finding.id] and not vulnerability_exceptions[finding.id]:
                risk_findings.add(finding.id)
        if compliance_mode != "raw" and configuration.get("epss_enabled") == "true" and epss is not None and now >= due_dates[finding.id] and not vulnerability_exceptions[finding.id]:
            for rule in epss_rules:
                severity = str(rule.get("severity", "Any")).lower()
                threshold = float(rule.get("threshold", 1))
                if severity in {"any", finding.severity.lower()} and epss >= threshold:
                    risk_eligible.add(finding.id)
                    if bool(rule.get("noncompliant", True)):
                        risk_findings.add(finding.id)
                    break
        elif compliance_mode != "raw" and configuration.get("epss_enabled") == "true" and epss is not None:
            for rule in epss_rules:
                severity = str(rule.get("severity", "Any")).lower()
                threshold = float(rule.get("threshold", 1))
                if severity in {"any", finding.severity.lower()} and epss >= threshold:
                    risk_eligible.add(finding.id)
                    break
    excepted = [f for f in active_all if f.id in risk_eligible and vulnerability_exceptions[f.id]]
    active = [
        finding for finding in active_all
        if finding.id in risk_eligible and finding.id not in risk_findings
        and not vulnerability_exceptions[finding.id]
    ]
    eligible_cves = {finding.cve for finding in active_all if finding.id in risk_eligible}
    warning_items = [
        item for item in warning_items
        if item.get("type") not in {"CVE", "Exception"} or item.get("item") in eligible_cves
    ]
    evidence_state = "No evidence"
    if latest_execution:
        evidence_state = "Incomplete" if incomplete else "Complete"
    if skipped_images and evidence_state == "Incomplete":
        evidence_state = f"Incomplete · {len(skipped_images)} skipped"
    if skipped_charts and evidence_state == "Incomplete":
        if skipped_images:
            evidence_state = f"Incomplete · {len(skipped_images)} skipped images, {len(skipped_charts)} skipped charts"
        else:
            evidence_state = f"Incomplete · {len(skipped_charts)} skipped charts"
    if incomplete and configuration.get("incomplete_noncompliant") != "true":
        warning_items.append({"type": "Evidence", "item": "Incomplete evidence", "reason": "Latest assessment is incomplete", "due": None,
                              "href": f"/services/{service.service_key}?overview=true"})
    evidence_noncompliant = bool(incomplete and configuration.get("incomplete_noncompliant") == "true")
    noncompliant = [finding for finding in active_all if finding.id in risk_findings and not vulnerability_exceptions[finding.id]]
    noncompliance_items = [
        {
            "type": "CVE",
            "item": finding.cve,
            "finding_id": finding.id,
            "reason": "Overdue fixable vulnerability",
            "due": due_dates.get(finding.id),
            "status": "Non-Compliant",
        }
        for finding in noncompliant
    ]
    noncompliance_items.extend({
        "type": "Configuration",
        "item": finding.finding,
        "policy_finding_id": finding.id,
        "evidence_image": finding.target or "No target reported",
        "reason": finding.title or "Overdue configuration finding",
        "due": policy_due_dates[finding.id],
        "status": "Non-Compliant",
    } for finding in policy_noncompliant)
    # Use the same canonical observations as Overview, including explicit
    # missing evidence and unresolved dependencies, with identical deduplication.
    if evidence_noncompliant:
        noncompliance_items.extend({
            "type": "Evidence", "item": row["type"] if row["item"] != "Assessment" else "Assessment",
            "evidence_image": row["item"] if row["item"] != "Assessment" else "",
            "source_file": row.get("source_file", ""),
            "reason": row["reason"], "due": None, "status": "Non-Compliant",
        } for row in missing_evidence)
    noncompliance_items.sort(key=lambda item: (str(item.get("item", "")).casefold(), str(item.get("type", "")).casefold()))
    return {
        "service": service, "compliant": not risk_findings and not policy_noncompliant and not (incomplete and configuration.get("incomplete_noncompliant") == "true"), "overdue": overdue,
        "excepted": excepted, "active": active, "resolved": resolved,
        "last_execution": last_execution,
        "evidence_state": evidence_state, "version": version, "skipped_images": skipped_images, "skipped_charts": skipped_charts,
        "incomplete": incomplete, "risk_findings": risk_findings, "risk_metadata": risk_metadata_by_finding,
        "risk_eligible": risk_eligible,
        "noncompliant": noncompliant, "evidence_noncompliant": evidence_noncompliant,
        "policy_findings": policy_findings,
        "policy_excepted": policy_excepted, "policy_noncompliant": policy_noncompliant,
        "policy_resolved": policy_resolved,
        "policy_due_dates": policy_due_dates,
        "noncompliance_items": noncompliance_items,
        "due_dates": due_dates,
        "compliance_mode": compliance_mode,
        "archive": archive_state(service),
        "oldest_age": max(((now - aware(f.episode_started)).days for f in [*active_all, *policy_active_all]), default=None),
        "overdue_days": overdue_days, "hardening_overdue_days": hardening_overdue_days,
        "hardening_noncompliant": hardening_noncompliant,
        "poam_active": poam_active,
        "warning_days": warning_days, "warning_items": warning_items,
    }

def service_overview_rows_detailed(
    db: Session,
    auth: AuthContext,
    now: datetime,
    configuration: dict[str, str],
) -> tuple[list[dict], dict[int, dict[str, int]]]:
    """Build the Services page from summary columns instead of full ORM graphs.

    The detail and export paths still use ``service_view``.  The dashboard only
    needs counts and a few service metadata fields, so loading complete
    findings, observations, POA&M bodies, and scan payload history here is both
    unnecessary and a major source of latency as evidence grows.
    """
    allowed = auth.accessible_service_ids("service.view")
    if allowed == set():
        raise HTTPException(403, detail="Permission denied")
    service_query = select(Service).order_by(Service.name, Service.service_key)
    if allowed is not None:
        service_query = service_query.where(Service.id.in_(allowed))
    services = list(db.scalars(service_query))
    if not services:
        return [], {}
    service_ids = [service.id for service in services]
    service_id_set = set(service_ids)

    # Resolve group-scoped settings with two bulk queries; never query a group
    # while rendering an individual service row.
    service_group_rows = db.execute(
        select(ServiceGroup.service_id, ServiceGroup.group_id)
        .where(ServiceGroup.service_id.in_(service_ids))
    ).all()
    groups_by_service: dict[int, list[int]] = {}
    group_ids = set()
    for row in service_group_rows:
        groups_by_service.setdefault(row.service_id, []).append(row.group_id)
        group_ids.add(row.group_id)
    settings_by_group: dict[int, list[PortalSetting]] = {group_id: [] for group_id in group_ids}
    if group_ids:
        for setting in db.scalars(select(PortalSetting).where(PortalSetting.group_id.in_(group_ids))):
            settings_by_group.setdefault(setting.group_id, []).append(setting)
    configurations: dict[int, dict[str, str]] = {}
    for service_id in service_ids:
        resolved = dict(configuration)
        for group_id in sorted(groups_by_service.get(service_id, [])):
            for setting in settings_by_group.get(group_id, []):
                key = setting.key.split(":", 2)[-1]
                if key not in GLOBAL_CONFIGURATION_KEYS:
                    resolved[key] = setting.value
        configurations[service_id] = resolved

    # Fetch only the latest execution payload per service.  Raw history is not
    # needed by this page and is intentionally excluded from the query.
    latest_execution_time = (
        select(Execution.service_id, func.max(Execution.scanned_at).label("latest_scanned_at"))
        .where(Execution.service_id.in_(service_ids))
        .group_by(Execution.service_id)
        .subquery()
    )
    latest_executions = db.execute(
        select(Execution.service_id, Execution.scanned_at, Execution.complete, Execution.raw_payload)
        .join(
            latest_execution_time,
            and_(Execution.service_id == latest_execution_time.c.service_id,
                 Execution.scanned_at == latest_execution_time.c.latest_scanned_at),
        )
    ).all()
    latest_by_service = {row.service_id: row for row in latest_executions}

    # The dashboard needs only the active finding fields used by compliance,
    # plus the latest observation's risk metadata.  No package/CVE description
    # or historical observation payload is hydrated.
    finding_rows = db.execute(select(
        Finding.id, Finding.service_id, Finding.cve, Finding.severity, Finding.episode_started,
    ).where(Finding.service_id.in_(service_ids), Finding.active.is_(True))).all()
    finding_by_service: dict[int, list] = {}
    finding_ids = []
    for row in finding_rows:
        finding_by_service.setdefault(row.service_id, []).append(row)
        finding_ids.append(row.id)
    latest_observation_by_finding: dict[int, dict] = {}
    if finding_ids:
        latest_observation = (
            select(FindingObservation.finding_id, func.max(FindingObservation.id).label("latest_id"))
            .join(Finding, Finding.id == FindingObservation.finding_id)
            .where(Finding.service_id.in_(service_ids), Finding.active.is_(True))
            .group_by(FindingObservation.finding_id)
            .subquery()
        )
        for row in db.execute(
            select(FindingObservation.finding_id, FindingObservation.evidence)
            .join(latest_observation, FindingObservation.id == latest_observation.c.latest_id)
        ):
            latest_observation_by_finding[row.finding_id] = row.evidence or {}
    active_exception_ids = set()
    if finding_ids:
        active_exception_ids = set(db.scalars(select(ExceptionRecord.finding_id).join(
            Finding, Finding.id == ExceptionRecord.finding_id,
        ).where(
            Finding.service_id.in_(service_ids), Finding.active.is_(True),
            ExceptionRecord.revoked_at.is_(None),
            ExceptionRecord.starts_at <= now,
            ExceptionRecord.expires_at > now,
        )))

    policy_rows = db.execute(select(
        PolicyFinding.id, PolicyFinding.service_id, PolicyFinding.severity, PolicyFinding.episode_started,
    ).where(PolicyFinding.service_id.in_(service_ids), PolicyFinding.active.is_(True))).all()
    policy_by_service: dict[int, list] = {}
    policy_ids = []
    for row in policy_rows:
        policy_by_service.setdefault(row.service_id, []).append(row)
        policy_ids.append(row.id)
    active_policy_exception_ids = set()
    if policy_ids:
        active_policy_exception_ids = set(db.scalars(select(PolicyExceptionRecord.policy_finding_id).join(
            PolicyFinding, PolicyFinding.id == PolicyExceptionRecord.policy_finding_id,
        ).where(
            PolicyFinding.service_id.in_(service_ids), PolicyFinding.active.is_(True),
            PolicyExceptionRecord.revoked_at.is_(None),
            PolicyExceptionRecord.starts_at <= now,
            PolicyExceptionRecord.expires_at > now,
        )))

    # Archive and POA&M summaries are grouped once for all visible services.
    archive_events = db.execute(select(
        ServiceArchiveEvent.service_id, ServiceArchiveEvent.action, ServiceArchiveEvent.created_at,
    ).where(ServiceArchiveEvent.service_id.in_(service_ids)).order_by(ServiceArchiveEvent.created_at.desc())).all()
    archive_by_service: dict[int, str] = {}
    for row in archive_events:
        archive_by_service.setdefault(row.service_id, row.action)
    poam_counts: dict[int, dict[str, int]] = {}
    for row in db.execute(select(
        PoamEntry.service_id, PoamEntry.status, func.count(PoamEntry.id),
    ).where(PoamEntry.service_id.in_(service_ids)).group_by(PoamEntry.service_id, PoamEntry.status)):
        counts = poam_counts.setdefault(row.service_id, {"active": 0, "pending": 0, "overdue": 0})
        status_name = row.status
        count = int(row[2] or 0)
        if status_name == "active":
            counts["active"] += count
        elif status_name == "pending_approval":
            counts["pending"] += count
    overdue_poams = db.execute(select(PoamEntry.service_id).where(
        PoamEntry.service_id.in_(service_ids), PoamEntry.status == "active",
        PoamEntry.due_date.is_not(None), PoamEntry.due_date < now,
    )).all()
    for row in overdue_poams:
        poam_counts.setdefault(row.service_id, {"active": 0, "pending": 0, "overdue": 0})["overdue"] += 1
    severity_rank = {"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    rows: list[dict] = []
    for service in services:
        cfg = configurations[service.id]
        overdue_days = max(1, int(cfg.get("overdue_days", "90")))
        warning_days = max(1, int(cfg.get("warning_days", "14")))
        try:
            raw_due_rules = json.loads(cfg.get("raw_due_rules", "[]"))
        except (TypeError, ValueError):
            raw_due_rules = []
        raw_due_by_severity = {
            str(rule.get("severity", "")).lower(): max(1, int(rule.get("days", overdue_days)))
            for rule in raw_due_rules
        }
        active_findings = finding_by_service.get(service.id, [])
        due_dates = {
            row.id: aware(row.episode_started) + timedelta(days=(
                raw_due_by_severity.get(str(row.severity or "").lower(), overdue_days)
                if cfg.get("compliance_mode") == "raw" else overdue_days
            )) for row in active_findings
        }
        exception_ids = {row.id for row in active_findings if row.id in active_exception_ids}
        overdue_ids = {row.id for row in active_findings if now >= due_dates[row.id] and row.id not in exception_ids}
        compliance_mode = cfg.get("compliance_mode", "risk_based")
        risk_eligible = {row.id for row in active_findings} if compliance_mode == "raw" else set()
        risk_findings = set(overdue_ids) if compliance_mode == "raw" else set()
        try:
            epss_rules = json.loads(cfg.get("epss_rules", "[]"))
        except (TypeError, ValueError):
            epss_rules = []
        if not epss_rules:
            epss_rules = [{"severity": "Any", "threshold": float(cfg.get("epss_threshold", "0.90")), "noncompliant": True}]
        minimum_severity = cfg.get("minimum_severity", "None").lower()
        severity_matches = {
            row.id for row in active_findings
            if minimum_severity in severity_rank and severity_rank.get(str(row.severity or "").lower(), 0) >= severity_rank[minimum_severity]
        }
        if compliance_mode != "raw":
            risk_eligible.update(severity_matches)
            risk_findings.update(row.id for row in active_findings if row.id in severity_matches and now >= due_dates[row.id] and row.id not in exception_ids)
        for row in active_findings:
            evidence = latest_observation_by_finding.get(row.id, {})
            catalog_kev, catalog_epss = risk_metadata(row.cve)
            kev = bool(evidence.get("kev", evidence.get("known_exploited", catalog_kev))) or catalog_kev
            try:
                epss = float(evidence.get("epss", evidence.get("epss_score", catalog_epss or 0)) or 0)
            except (TypeError, ValueError):
                epss = 0
            if compliance_mode != "raw" and cfg.get("kev_enabled") == "true" and kev:
                risk_eligible.add(row.id)
                if cfg.get("kev_noncompliant") == "true" and now >= due_dates[row.id] and row.id not in exception_ids:
                    risk_findings.add(row.id)
            if compliance_mode != "raw" and cfg.get("epss_enabled") == "true" and epss is not None and now >= due_dates[row.id]:
                for rule in epss_rules:
                    severity = str(rule.get("severity", "Any")).lower()
                    if severity in {"any", str(row.severity or "").lower()} and epss >= float(rule.get("threshold", 1)):
                        risk_eligible.add(row.id)
                        if bool(rule.get("noncompliant", True)) and row.id not in exception_ids:
                            risk_findings.add(row.id)
                        break
            elif compliance_mode != "raw" and cfg.get("epss_enabled") == "true" and epss is not None:
                for rule in epss_rules:
                    severity = str(rule.get("severity", "Any")).lower()
                    if severity in {"any", str(row.severity or "").lower()} and epss >= float(rule.get("threshold", 1)):
                        risk_eligible.add(row.id)
                        break
        excepted_count = len(risk_eligible & exception_ids)
        active_count = len(risk_eligible - risk_findings - exception_ids)
        policy_active = policy_by_service.get(service.id, [])
        hardening_overdue_days = max(1, int(cfg.get("hardening_overdue_days", "90")))
        hardening_noncompliant = cfg.get("hardening_noncompliant", "true") == "true"
        policy_due = {row.id: aware(row.episode_started) + timedelta(days=hardening_overdue_days) for row in policy_active}
        policy_excepted_count = sum(row.id in active_policy_exception_ids for row in policy_active)
        policy_noncompliant_count = sum(
            hardening_noncompliant and row.id not in active_policy_exception_ids and now >= policy_due[row.id]
            for row in policy_active
        )
        policy_visible_count = len(policy_active) - policy_excepted_count - policy_noncompliant_count
        latest = latest_by_service.get(service.id)
        raw_payload = latest.raw_payload if latest and isinstance(latest.raw_payload, dict) else {}
        skipped_images = raw_payload.get("skipped_images", []) or []
        skipped_charts = raw_payload.get("skipped_charts", []) or []
        missing = normalize_overview(raw_payload.get("service_overview") or {}, skipped_images=skipped_images,
                                     skipped_charts=skipped_charts, incomplete=bool(latest and not latest.complete))["missing_evidence"]
        incomplete = bool(latest and (not latest.complete or missing))
        evidence_state = "No evidence" if not latest else ("Incomplete" if incomplete else "Complete")
        if skipped_images and evidence_state == "Incomplete":
            evidence_state = f"Incomplete · {len(skipped_images)} skipped"
        if skipped_charts and evidence_state == "Incomplete":
            evidence_state = f"Incomplete · {len(skipped_images)} skipped images, {len(skipped_charts)} skipped charts" if skipped_images else f"Incomplete · {len(skipped_charts)} skipped charts"
        evidence_noncompliant = bool(incomplete and cfg.get("incomplete_noncompliant") == "true")
        compliant = not risk_findings and not policy_noncompliant_count and not evidence_noncompliant
        oldest_dates = [row.episode_started for row in active_findings] + [row.episode_started for row in policy_active]
        oldest_age = max(((now - aware(value)).days for value in oldest_dates), default=None)
        rows.append({
            "service": service,
            "compliant": compliant,
            "version": service.manual_version or (raw_payload.get("service", {}).get("version") if isinstance(raw_payload.get("service"), dict) else None),
            "evidence_state": evidence_state,
            "active": [None] * (active_count + policy_visible_count),
            "policy_findings": [],
            "noncompliant": [None] * len(risk_findings),
            "policy_noncompliant": [None] * policy_noncompliant_count,
            "excepted": [None] * excepted_count,
            "policy_excepted": [None] * policy_excepted_count,
            "oldest_age": oldest_age,
            "archive": archive_by_service.get(service.id) == "archive",
            "poam": poam_counts.get(service.id, {"active": 0, "pending": 0, "overdue": 0}),
            "overdue": [None] * len(overdue_ids),
            "warning_days": warning_days,
        })
    return rows, poam_counts


def _overview_services_and_configurations(db: Session, auth: AuthContext, configuration: dict[str, str], *, projected: bool = False):
    from .sql_sets import member_of
    allowed = auth.accessible_service_ids("service.view")
    if allowed == set():
        raise HTTPException(403, detail="Permission denied")
    columns = (Service.id, Service.name, Service.service_key, Service.owner, Service.poc,
               Service.manual_version, Service.lifecycle_status)
    query = select(*columns) if projected else select(Service)
    query = query.order_by(Service.name, Service.service_key)
    if allowed is not None:
        query = query.where(member_of(Service.id, allowed, numeric=True))
    services = ([SimpleNamespace(**row._mapping) for row in db.execute(query)]
                if projected else list(db.scalars(query)))
    service_ids = [service.id for service in services]
    groups_by_service: dict[int, list[int]] = {}
    group_ids: set[int] = set()
    if service_ids:
        for row in db.execute(select(ServiceGroup.service_id, ServiceGroup.group_id).where(member_of(ServiceGroup.service_id, service_ids, numeric=True))):
            groups_by_service.setdefault(row.service_id, []).append(row.group_id)
            group_ids.add(row.group_id)
    settings_by_group: dict[int, list[PortalSetting]] = {group_id: [] for group_id in group_ids}
    if group_ids:
        for setting in db.scalars(select(PortalSetting).where(member_of(PortalSetting.group_id, group_ids, numeric=True))):
            settings_by_group.setdefault(setting.group_id, []).append(setting)
    configurations: dict[int, dict[str, str]] = {}
    for service_id in service_ids:
        resolved = dict(configuration)
        for group_id in sorted(groups_by_service.get(service_id, [])):
            for setting in settings_by_group.get(group_id, []):
                key = setting.key.split(":", 2)[-1]
                if key not in GLOBAL_CONFIGURATION_KEYS:
                    resolved[key] = setting.value
        configurations[service_id] = resolved
    return services, configurations


def _raw_due_groups(configurations: dict[int, dict[str, str]], now: datetime):
    grouped: dict[tuple, list[int]] = {}
    for service_id, cfg in configurations.items():
        overdue_days = max(1, int(cfg.get("overdue_days", "90")))
        try:
            rules = json.loads(cfg.get("raw_due_rules", "[]"))
        except (TypeError, ValueError):
            rules = []
        due_by_severity = tuple(sorted(
            (str(rule.get("severity", "")).lower(), max(1, int(rule.get("days", overdue_days))))
            for rule in rules if isinstance(rule, dict)
        ))
        grouped.setdefault((overdue_days, due_by_severity), []).append(service_id)
    return grouped


def _raw_overdue_expression(model, configurations: dict[int, dict[str, str]], now: datetime):
    from .sql_sets import member_of
    parts = []
    grouped = {}
    for service_id, cfg in configurations.items():
        default_days = max(1, int(cfg.get("overdue_days", "90")))
        due_by_severity = {}
        if cfg.get("compliance_mode") == "raw":
            try:
                rules = json.loads(cfg.get("raw_due_rules", "[]"))
            except (TypeError, ValueError):
                rules = []
            for rule in rules:
                due_by_severity[str(rule.get("severity", "")).lower()] = max(1, int(rule.get("days", default_days)))
        grouped.setdefault((default_days, tuple(sorted(due_by_severity.items()))), []).append(service_id)
    severity_value = func.lower(model.severity)
    for (default_days, due_by_severity), service_ids in grouped.items():
        scope = member_of(model.service_id, service_ids, numeric=True)
        known = []
        for severity, days in due_by_severity:
            known.append(severity)
            parts.append(and_(
                scope, severity_value == severity,
                model.episode_started <= now - timedelta(days=days),
            ))
        parts.append(and_(
            scope,
            (or_(~severity_value.in_(known), model.severity.is_(None)) if known else true()),
            model.episode_started <= now - timedelta(days=default_days),
        ))
    return or_(*parts) if parts else false()


def _hardening_overdue_expression(configurations: dict[int, dict[str, str]], now: datetime):
    from .sql_sets import member_of
    parts = []
    grouped: dict[tuple[int, bool], list[int]] = {}
    for service_id, cfg in configurations.items():
        grouped.setdefault((max(1, int(cfg.get("hardening_overdue_days", "90"))), cfg.get("hardening_noncompliant", "true") == "true"), []).append(service_id)
    for (days, enabled), service_ids in grouped.items():
        if enabled:
            parts.append(and_(member_of(PolicyFinding.service_id, service_ids, numeric=True),
                              PolicyFinding.episode_started <= now - timedelta(days=days)))
    return or_(*parts) if parts else false()


def _risk_finding_expressions(
    configurations: dict[int, dict[str, str]],
    now: datetime,
    finding_exception,
):
    """Build database expressions for risk-based finding summaries.

    The detailed dashboard historically evaluated these rules in Python after
    loading every active finding.  The expressions below keep the same rule
    precedence while allowing the database to count eligible/non-compliant
    rows directly.  Catalog KEV/EPSS data is represented as CVE membership
    predicates; observation evidence remains JSON-native in PostgreSQL and
    SQLite.

    Services sharing an effective configuration share one predicate, and every
    catalog or service-id set is bound as a single JSON value (``member_of``),
    so statement size and bind counts stay constant as services and catalogs
    grow.  The catalogs remain the live in-memory intelligence snapshot.
    """
    from .risk_sql import evidence_score, evidence_truth, key_present
    from .sql_sets import catalog_subset, member_of
    eligible_parts = []
    noncompliant_parts = []
    needs_observations = False
    catalog_kev = kev_cves()
    catalog_epss = epss_scores()
    severity_rank = {"unknown": 0, "negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    severity_value = func.lower(Finding.severity)
    severity_order = case(*((severity_value == name, rank) for name, rank in severity_rank.items()), else_=0)
    cve_key = func.upper(func.trim(Finding.cve))
    evidence = FindingObservation.evidence
    groups: dict[tuple, list[int]] = {}
    for service_id, cfg in configurations.items():
        groups.setdefault(tuple(sorted((str(key), str(value)) for key, value in cfg.items())), []).append(service_id)
    for group_key, service_ids in groups.items():
        cfg = dict(group_key)
        group_configurations = {service_id: configurations[service_id] for service_id in service_ids}
        service_scope = member_of(Finding.service_id, service_ids, numeric=True)
        if cfg.get("compliance_mode", "risk_based") == "raw":
            eligible_parts.append(service_scope)
            noncompliant_parts.append(and_(service_scope, _raw_overdue_expression(Finding, group_configurations, now)))
            continue
        overdue = _raw_overdue_expression(Finding, group_configurations, now)
        eligible = []
        noncompliant = []
        minimum = str(cfg.get("minimum_severity", "None")).lower()
        if minimum in severity_rank:
            match = severity_order >= severity_rank[minimum]
            eligible.append(match)
            noncompliant.append(and_(match, overdue))
        if cfg.get("kev_enabled") == "true":
            needs_observations = True
            kev_match = []
            if catalog_kev:
                kev_match.append(member_of(cve_key, catalog_kev))
            kev_match.append(evidence_truth(evidence))
            if kev_match:
                match = or_(*kev_match)
                eligible.append(match)
                if cfg.get("kev_noncompliant") == "true":
                    noncompliant.append(and_(match, overdue))
        try:
            epss_rules = json.loads(cfg.get("epss_rules", "[]"))
        except (TypeError, ValueError):
            epss_rules = []
        if not epss_rules:
            epss_rules = [{"severity": "Any", "threshold": float(cfg.get("epss_threshold", "0.90")), "noncompliant": True}]
        if cfg.get("epss_enabled") == "true":
            needs_observations = True
            prior_match = false()
            for rule in epss_rules:
                try:
                    threshold = float(rule.get("threshold", 1))
                except (TypeError, ValueError):
                    threshold = 1.0
                severity = str(rule.get("severity", "Any")).lower()
                severity_match = true() if severity == "any" else severity_value == severity
                catalog_match = catalog_subset(catalog_epss, ("epss>=", threshold), lambda score: score >= threshold)
                has_score = or_(key_present(evidence, "epss"), key_present(evidence, "epss_score"))
                explicit_match = func.coalesce(evidence_score(evidence) >= threshold, false())
                catalog_matches = member_of(cve_key, catalog_match) if catalog_match else false()
                if threshold <= 0:
                    nonzero_catalog = catalog_subset(catalog_epss, ("epss<", threshold), lambda score: score < threshold)
                    catalog_matches = ~member_of(cve_key, nonzero_catalog) if nonzero_catalog else true()
                score_match = or_(and_(has_score, explicit_match), and_(~func.coalesce(has_score, false()), catalog_matches))
                match = and_(severity_match, score_match, ~prior_match)
                eligible.append(match)
                if bool(rule.get("noncompliant", True)):
                    noncompliant.append(and_(match, overdue))
                prior_match = or_(prior_match, and_(severity_match, score_match))
        if eligible:
            eligible_parts.append(and_(service_scope, or_(*eligible)))
        if noncompliant:
            noncompliant_parts.append(and_(service_scope, or_(*noncompliant)))
    return (or_(*eligible_parts) if eligible_parts else false(), or_(*noncompliant_parts) if noncompliant_parts else false(), needs_observations)


def service_overview_rows_aggregated(
    db: Session,
    auth: AuthContext,
    now: datetime,
    configuration: dict[str, str],
    services: list[Service] | None = None,
    configurations: dict[int, dict[str, str]] | None = None,
) -> tuple[list[dict], dict[int, dict[str, int]]]:
    """Summary path that never transfers individual findings to Python.

    PostgreSQL/SQLite perform the counts, exception checks, due-date and
    risk-overlay comparisons, and oldest-finding calculation.  This keeps
    page cost tied to the number of services rather than finding history.
    """
    from .sql_sets import member_of
    from .execution_summaries import CountOnly, load_execution_summaries
    if services is None or configurations is None:
        services, configurations = _overview_services_and_configurations(db, auth, configuration)
    if not services:
        return [], {}
    service_ids = [service.id for service in services]
    latest_execution_time = select(Execution.id, func.row_number().over(
        partition_by=Execution.service_id,
        order_by=(Execution.scanned_at.desc(), Execution.id.desc()),
    ).label("position")).where(member_of(Execution.service_id, service_ids, numeric=True)).subquery()
    latest_by_service = {
        row.service_id: row for row in db.execute(select(
            Execution.id, Execution.service_id, Execution.scanned_at, Execution.complete,
        ).join(latest_execution_time, Execution.id == latest_execution_time.c.id)
        .where(latest_execution_time.c.position == 1))
    }
    execution_summaries = load_execution_summaries(db, [row.id for row in latest_by_service.values()])
    finding_exception = select(ExceptionRecord.id).where(
        ExceptionRecord.finding_id == Finding.id,
        ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now,
        ExceptionRecord.expires_at > now,
    ).exists()
    finding_eligible, finding_noncompliant, needs_observations = _risk_finding_expressions(configurations, now, finding_exception)
    finding_query = select(
        Finding.service_id,
        func.sum(case((finding_eligible, 1), else_=0)).label("total"),
        func.sum(case((and_(finding_eligible, finding_exception), 1), else_=0)).label("excepted"),
        func.sum(case((and_(finding_noncompliant, ~finding_exception), 1), else_=0)).label("noncompliant"),
        func.min(Finding.episode_started).label("oldest"),
    ).where(member_of(Finding.service_id, service_ids, numeric=True), Finding.active.is_(True)).group_by(Finding.service_id)
    if needs_observations:
        # Only the requested services' active findings need evidence; an
        # unscoped GROUP BY would scan every retained observation globally.
        latest_observation = select(
            FindingObservation.finding_id,
            func.max(FindingObservation.id).label("latest_id"),
        ).join(Finding, Finding.id == FindingObservation.finding_id).where(
            member_of(Finding.service_id, service_ids, numeric=True), Finding.active.is_(True),
        ).group_by(FindingObservation.finding_id).subquery()
        finding_query = finding_query.outerjoin(
            latest_observation, latest_observation.c.finding_id == Finding.id,
        ).outerjoin(
            FindingObservation, FindingObservation.id == latest_observation.c.latest_id,
        )
    finding_aggregate = {row.service_id: row for row in db.execute(finding_query)}
    policy_exception = select(PolicyExceptionRecord.id).where(
        PolicyExceptionRecord.policy_finding_id == PolicyFinding.id,
        PolicyExceptionRecord.revoked_at.is_(None), PolicyExceptionRecord.starts_at <= now,
        PolicyExceptionRecord.expires_at > now,
    ).exists()
    policy_overdue = _hardening_overdue_expression(configurations, now)
    policy_aggregate = {
        row.service_id: row for row in db.execute(select(
            PolicyFinding.service_id,
            func.count(PolicyFinding.id).label("total"),
            func.sum(case((policy_exception, 1), else_=0)).label("excepted"),
            func.sum(case((and_(policy_overdue, ~policy_exception), 1), else_=0)).label("noncompliant"),
            func.min(PolicyFinding.episode_started).label("oldest"),
        ).where(member_of(PolicyFinding.service_id, service_ids, numeric=True), PolicyFinding.active.is_(True)).group_by(PolicyFinding.service_id))
    }
    archive_by_service: dict[int, str] = {}
    latest_archive = select(ServiceArchiveEvent.service_id, ServiceArchiveEvent.action,
        func.row_number().over(partition_by=ServiceArchiveEvent.service_id,
            order_by=(ServiceArchiveEvent.created_at.desc(), ServiceArchiveEvent.id.desc())).label("position")
    ).where(member_of(ServiceArchiveEvent.service_id, service_ids, numeric=True)).subquery()
    for row in db.execute(select(latest_archive.c.service_id, latest_archive.c.action)
            .where(latest_archive.c.position == 1)):
        archive_by_service[row.service_id] = row.action
    poam_counts: dict[int, dict[str, int]] = {}
    for row in db.execute(select(
        PoamEntry.service_id, PoamEntry.status, func.count(PoamEntry.id),
    ).where(member_of(PoamEntry.service_id, service_ids, numeric=True)).group_by(PoamEntry.service_id, PoamEntry.status)):
        counts = poam_counts.setdefault(row.service_id, {"active": 0, "pending": 0, "overdue": 0})
        if row.status == "active":
            counts["active"] += int(row[2] or 0)
        elif row.status == "pending_approval":
            counts["pending"] += int(row[2] or 0)
    for row in db.execute(select(PoamEntry.service_id, func.count(PoamEntry.id)).where(
        member_of(PoamEntry.service_id, service_ids, numeric=True), PoamEntry.status == "active",
        PoamEntry.due_date.is_not(None), PoamEntry.due_date < now,
    ).group_by(PoamEntry.service_id)):
        poam_counts.setdefault(row.service_id, {"active": 0, "pending": 0, "overdue": 0})["overdue"] = int(row[1])
    rows = []
    for service in services:
        cfg = configurations[service.id]
        findings = finding_aggregate.get(service.id)
        policies = policy_aggregate.get(service.id)
        finding_total = int(findings.total or 0) if findings else 0
        finding_excepted = int(findings.excepted or 0) if findings else 0
        finding_noncompliant = int(findings.noncompliant or 0) if findings else 0
        policy_total = int(policies.total or 0) if policies else 0
        policy_excepted = int(policies.excepted or 0) if policies else 0
        policy_noncompliant = int(policies.noncompliant or 0) if policies else 0
        latest = latest_by_service.get(service.id)
        summary = execution_summaries.get(latest.id, {}) if latest else {}
        skipped_images = summary.get("skipped_image_count", 0)
        skipped_charts = summary.get("skipped_chart_count", 0)
        incomplete = bool(latest and (not latest.complete or summary.get("missing_evidence_count", 0)))
        evidence_state = "No evidence" if not latest else ("Incomplete" if incomplete else "Complete")
        if skipped_images and evidence_state == "Incomplete":
            evidence_state = f"Incomplete · {skipped_images} skipped"
        if skipped_charts and evidence_state == "Incomplete":
            evidence_state = f"Incomplete · {skipped_images} skipped images, {skipped_charts} skipped charts" if skipped_images else f"Incomplete · {skipped_charts} skipped charts"
        evidence_noncompliant = bool(incomplete and cfg.get("incomplete_noncompliant") == "true")
        oldest_values = [value for value in ((findings.oldest if findings else None), (policies.oldest if policies else None)) if value is not None]
        oldest_age = max(((now - aware(value)).days for value in oldest_values), default=None)
        rows.append({
            "service": service,
            "compliant": not finding_noncompliant and not policy_noncompliant and not evidence_noncompliant,
            "version": service.manual_version or summary.get("raw_version"),
            "evidence_state": evidence_state,
            "active": CountOnly(finding_total - finding_excepted - finding_noncompliant + policy_total - policy_excepted - policy_noncompliant),
            "policy_findings": [],
            "noncompliant": CountOnly(finding_noncompliant),
            "policy_noncompliant": CountOnly(policy_noncompliant),
            "excepted": CountOnly(finding_excepted),
            "policy_excepted": CountOnly(policy_excepted),
            "oldest_age": oldest_age,
            "archive": archive_by_service.get(service.id) == "archive",
            "poam": poam_counts.get(service.id, {"active": 0, "pending": 0, "overdue": 0}),
            "overdue": CountOnly(finding_noncompliant),
        })
    return rows, poam_counts


def service_overview_rows(db: Session, auth: AuthContext, now: datetime, configuration: dict[str, str]):
    services, configurations = _overview_services_and_configurations(db, auth, configuration)
    if not services:
        return [], {}
    return service_overview_rows_aggregated(db, auth, now, configuration, services, configurations)

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    configuration = get_global_configuration(db)
    mode = configuration.get("identity_mode", os.getenv("CATS_IDENTITY_MODE", "local"))
    return templates.TemplateResponse(request, "login.html", {
        "error": request.query_params.get("error"), "next": request.query_params.get("next", "/"),
        "oidc_available": oidc_enabled(mode), "local_available": mode in {"local", "both"},
        "oidc_provider_name": configured_oidc(configuration).get("provider_name") or "OIDC",
    })


@app.get("/auth/oidc/login")
def oidc_login(request: Request, next: str = "/", db: Session = Depends(get_db)):
    configuration = get_global_configuration(db)
    if not oidc_enabled(configuration.get("identity_mode")):
        raise HTTPException(404, detail="OIDC login is not enabled")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    try:
        oidc_config = parse_json(configuration.get("oidc_configuration"), {})
        if isinstance(oidc_config, dict) and oidc_config.get("client_secret"):
            try: oidc_config["client_secret"] = decrypt_secret(oidc_config["client_secret"])
            except ValueError: raise HTTPException(503, detail="OIDC client secret is unavailable")
        ca_bundle = configured_ca_bundle(configuration)
        location = oidc_authorization_url(state, nonce, oidc_config, ca_bundle)
    except Exception as exc:
        raise HTTPException(503, detail=f"OIDC is not configured: {redact(exc)}") from exc
    response = RedirectResponse(location, status_code=303)
    response.set_cookie("cats_oidc_state", state, httponly=True, secure=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true", samesite="lax", max_age=600)
    response.set_cookie("cats_oidc_nonce", nonce, httponly=True, secure=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true", samesite="lax", max_age=600)
    response.set_cookie("cats_oidc_next", next if next.startswith("/") and not next.startswith("//") else "/", httponly=True, secure=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true", samesite="lax", max_age=600)
    return response


@app.get("/auth/oidc/callback")
def oidc_callback(request: Request, db: Session = Depends(get_db)):
    if request.query_params.get("state") != request.cookies.get("cats_oidc_state"):
        raise HTTPException(400, detail="Invalid OIDC state")
    error = request.query_params.get("error")
    if error:
        return RedirectResponse(f"/login?error={urllib.parse.quote(redact(error))}", status_code=303)
    code = request.query_params.get("code", "")
    if not code:
        raise HTTPException(400, detail="OIDC callback did not include an authorization code")
    try:
        oidc_config = parse_json(get_global_configuration(db).get("oidc_configuration"), {})
        if isinstance(oidc_config, dict) and oidc_config.get("client_secret"):
            oidc_config["client_secret"] = decrypt_secret(oidc_config["client_secret"])
        configuration = get_global_configuration(db)
        ca_bundle = configured_ca_bundle(configuration)
        tokens, discovery = oidc_exchange_code(code, oidc_config, ca_bundle)
        id_claims = verify_oidc_id_token(tokens, discovery, request.cookies.get("cats_oidc_nonce"), oidc_config, ca_bundle)
        access_token = tokens.get("access_token")
        if not access_token:
            raise ValueError("OIDC token response did not include an access token")
        userinfo_request = urllib.request.Request(discovery["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}"})
        try:
            if ca_bundle:
                import ssl
                context = ssl.create_default_context()
                if "BEGIN CERTIFICATE" in ca_bundle:
                    context.load_verify_locations(cadata=ca_bundle)
                else:
                    context.load_verify_locations(cafile=ca_bundle)
                with urllib.request.urlopen(userinfo_request, timeout=15, context=context) as response:
                    userinfo = json.load(response)
            else:
                with urllib.request.urlopen(userinfo_request, timeout=15) as response:
                    userinfo = json.load(response)
            if not isinstance(userinfo, dict) or userinfo.get("sub") != id_claims.get("sub"):
                raise ValueError("OIDC UserInfo subject does not match the validated ID token")
            # Authorization claims must come from the validated ID token.
            claims = dict(id_claims)
            for display_claim in ("name", "email", "preferred_username"):
                if display_claim not in claims and isinstance(userinfo.get(display_claim), str):
                    claims[display_claim] = userinfo[display_claim]
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                # UserInfo is supplementary. The ID token has already been
                # signature-, audience-, issuer-, and nonce-validated, so its
                # claims are a safe fallback for providers that do not permit
                # this client to call UserInfo.
                claims = id_claims
            else:
                raise ValueError(f"OIDC user-info endpoint returned HTTP {exc.code}") from exc
        user = provision_oidc_user(db, claims, oidc_config)
    except Exception as exc:
        db.rollback()
        # Never reflect provider responses, token payloads, or configuration
        # values into the browser.  They may contain credentials or claims.
        return RedirectResponse(f"/login?error={urllib.parse.quote(f'OIDC login failed: {redact(exc)}')}", status_code=303)
    if not user.enabled:
        record_audit(db, AuthContext(user, None), "auth.oidc_denied_disabled", "user", user.id)
        db.commit()
        response = RedirectResponse("/login?error=CATS%20account%20is%20disabled", status_code=303)
        response.delete_cookie("cats_oidc_state")
        response.delete_cookie("cats_oidc_nonce")
        response.delete_cookie("cats_oidc_next")
        return response
    now = utcnow()
    user.last_login_at = now
    raw_token = secrets.token_urlsafe(48)
    session = UserSession(token_hash=token_hash(raw_token), csrf_token=secrets.token_urlsafe(32), user=user,
                          expires_at=now + timedelta(hours=int(os.getenv("SESSION_HOURS", "8"))),
                          user_agent=request.headers.get("user-agent"), source_ip=request.client.host if request.client else None)
    db.add(session)
    record_audit(db, AuthContext(user, session), "auth.oidc_login", "user", user.id)
    db.commit()
    response = RedirectResponse(request.cookies.get("cats_oidc_next", "/"), status_code=303)
    response.set_cookie(SESSION_COOKIE, raw_token, httponly=True, samesite="strict", secure=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true", max_age=int(os.getenv("SESSION_HOURS", "8")) * 3600)
    response.delete_cookie("cats_oidc_state")
    response.delete_cookie("cats_oidc_nonce")
    response.delete_cookie("cats_oidc_next")
    return response


@app.post("/login")
def login(
    request: Request, username: str = Form(), password: str = Form(),
    next: str = Form(default="/"), db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.username == username.strip().lower()))
    now = utcnow()
    configuration = get_global_configuration(db)
    if configuration.get("identity_mode", os.getenv("CATS_IDENTITY_MODE", "local")) not in {"local", "both"}:
        return templates.TemplateResponse(request, "login.html", {
            "error": "Local account login is disabled. Use the organizational sign-in button.", "next": next,
            "oidc_available": True, "local_available": False,
            "oidc_provider_name": configured_oidc(configuration).get("provider_name") or "OIDC",
        }, status_code=403)
    valid = bool(user and user.enabled and (not user.locked_until or aware(user.locked_until) <= now))
    valid = valid and verify_password(password, user.password_hash)
    if not valid:
        if user and user.enabled:
            user.failed_login_count += 1
            if user.failed_login_count >= 5:
                user.locked_until = now + timedelta(minutes=15)
                user.failed_login_count = 0
            db.commit()
        return templates.TemplateResponse(request, "login.html", {
            "error": "Invalid username or password.", "next": next,
            "oidc_available": oidc_enabled(configuration.get("identity_mode")),
            "local_available": configuration.get("identity_mode") in {"local", "both"},
            "oidc_provider_name": configured_oidc(configuration).get("provider_name") or "OIDC",
        }, status_code=401)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    raw_token = secrets.token_urlsafe(48)
    session = UserSession(
        token_hash=token_hash(raw_token), csrf_token=secrets.token_urlsafe(32), user=user,
        expires_at=now + timedelta(hours=int(os.getenv("SESSION_HOURS", "8"))),
        user_agent=request.headers.get("user-agent"),
        source_ip=request.client.host if request.client else None,
    )
    db.add(session)
    record_audit(db, AuthContext(user, session), "auth.login", "user", user.id)
    db.commit()
    destination = "/account/password" if user.must_change_password else (next if next.startswith("/") and not next.startswith("//") else "/")
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        SESSION_COOKIE, raw_token, httponly=True, samesite="strict",
        secure=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
        max_age=int(os.getenv("SESSION_HOURS", "8")) * 3600,
    )
    return response


@app.post("/logout")
def logout(csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    check_csrf(auth, csrf_token)
    record_audit(db, auth, "auth.logout", "user", auth.user.id)
    db.delete(auth.session)
    db.commit()
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/account/password", response_class=HTMLResponse)
def password_page(request: Request, auth: AuthContext = Depends(require_user)):
    return templates.TemplateResponse(request, "password.html", page_context(auth, error=None))


THEMES = {
    "cats": "CATS Green",
    "blue": "Ocean Blue",
    "red": "Warm Red",
    "gray": "Slate Gray",
    "light": "High-contrast Light",
}


@app.get("/account/appearance", response_class=HTMLResponse)
def appearance_page(request: Request, auth: AuthContext = Depends(require_user)):
    return templates.TemplateResponse(request, "appearance.html", page_context(auth, themes=THEMES, saved=request.query_params.get("saved") == "1" or request.query_params.get("theme_saved") == "1"))


@app.post("/account/appearance")
def save_appearance(
    theme: str = Form(), csrf_token: str = Form(), next_path: str = Form("/"), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    if theme not in THEMES:
        raise HTTPException(422, detail="Unsupported theme")
    auth.user.theme = theme
    record_audit(db, auth, "user.theme_changed", "user", auth.user.id, theme=theme)
    db.commit()
    if not next_path.startswith("/") or next_path.startswith("//"):
        next_path = "/"
    separator = "&" if "?" in next_path else "?"
    return RedirectResponse(f"{next_path}{separator}theme_saved=1", status_code=303)


@app.post("/account/password")
def change_password(
    current_password: str = Form(), new_password: str = Form(), confirmation: str = Form(),
    csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    if not verify_password(current_password, auth.user.password_hash):
        raise HTTPException(422, detail="Current password is incorrect")
    if new_password != confirmation:
        raise HTTPException(422, detail="New passwords do not match")
    try:
        auth.user.password_hash = hash_password(new_password)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    auth.user.must_change_password = False
    db.execute(delete(UserSession).where(UserSession.user_id == auth.user.id, UserSession.id != auth.session.id))
    record_audit(db, auth, "user.password_changed", "user", auth.user.id)
    db.commit()
    return RedirectResponse("/", status_code=303)


def _image_identity(reference: str | None, digest: str | None = None) -> tuple[str, str | None]:
    value = str(reference or "").strip()
    digest_value = str(digest or "").strip() or None
    if "@" in value:
        value, embedded_digest = value.rsplit("@", 1)
        digest_value = digest_value or embedded_digest.strip() or None
    return value, digest_value


def _ensure_service_image(db: Session, service: Service, reference: str | None, digest: str | None = None) -> ServiceImage | None:
    image_reference, image_digest = _image_identity(reference, digest)
    if not image_reference:
        return None
    # A scan often observes the tag first and learns the manifest digest from
    # a later source.  Reconcile that occurrence in place so the service has
    # one canonical image and remediation cannot patch it twice.
    if image_digest:
        resolved = db.scalar(select(ServiceImage).where(
            ServiceImage.service_id == service.id,
            ServiceImage.image_reference == image_reference,
            ServiceImage.image_digest == image_digest,
        ))
        if resolved:
            stale = db.scalars(select(ServiceImage).where(
                ServiceImage.service_id == service.id,
                ServiceImage.image_reference == image_reference,
                ServiceImage.image_digest.is_(None),
            )).all()
            for occurrence in stale:
                db.delete(occurrence)
            return resolved
        unresolved = db.scalar(select(ServiceImage).where(
            ServiceImage.service_id == service.id,
            ServiceImage.image_reference == image_reference,
            ServiceImage.image_digest.is_(None),
        ))
        if unresolved:
            unresolved.image_digest = image_digest
            unresolved.updated_at = utcnow()
            return unresolved
    else:
        resolved = db.scalar(select(ServiceImage).where(
            ServiceImage.service_id == service.id,
            ServiceImage.image_reference == image_reference,
            ServiceImage.image_digest.is_not(None),
        ))
        if resolved:
            return resolved
    image = db.scalar(select(ServiceImage).where(
        ServiceImage.service_id == service.id,
        ServiceImage.image_reference == image_reference,
        ServiceImage.image_digest == image_digest,
    ))
    if not image:
        image = ServiceImage(service=service, image_reference=image_reference, image_digest=image_digest)
        db.add(image)
        db.flush()
    return image


def _reconcile_image_scope(db: Session, service: Service, target_image: str, observed_cves: set[str], scanned_at: datetime) -> None:
    """Resolve only findings whose evidence belongs to the scanned image."""
    target = target_image.strip()
    if not target:
        return
    other_active_image = select(FindingObservation.id).join(ServiceImage, and_(
        ServiceImage.service_id == service.id,
        ServiceImage.image_reference == FindingObservation.image,
        ServiceImage.lifecycle_status == "active",
    )).where(FindingObservation.finding_id == Finding.id,
             FindingObservation.image != target).exists()
    for finding in db.scalars(select(Finding).where(
        Finding.service_id == service.id, Finding.active.is_(True), ~other_active_image,
    )):
        if finding.cve in observed_cves:
            continue
        finding.active = False
        finding.resolved_at = scanned_at


@app.post("/api/v1/pipeline-results", status_code=201, dependencies=[Depends(require_pipeline)])
def ingest(payload: ExecutionPayload, db: Session = Depends(get_db), background_tasks: BackgroundTasks = None):
    result = ingest_payload(payload, db)
    if background_tasks is not None and isinstance(result, dict) and result.get("accepted") and not result.get("duplicate"):
        queue_dependency_projection(db, background_tasks, result.get("execution_id"))
    return result


def _ingest_projection_enabled() -> bool:
    configured = os.getenv("CATS_DEPENDENCY_PROJECTION_ON_INGEST", "").strip().lower()
    if configured:
        return configured in {"1", "true", "yes"}
    # Disposable in-memory databases (tests) share one connection; build on demand there.
    return not (engine.url.get_backend_name() == "sqlite" and engine.url.database in (None, "", ":memory:"))


def queue_dependency_projection(db: Session, background_tasks: BackgroundTasks, execution_id) -> dict | None:
    """Prepare the newly ingested scan's dependency read model after the commit.

    The projection is claimed with a durable token and built on the bounded
    projection executor after the response is sent, so the first Dependencies
    view no longer pays for (or writes) it.  Failures never affect ingestion;
    the Dependencies tab still requests the projection on demand.
    """
    if execution_id is None or not _ingest_projection_enabled():
        return None
    try:
        from .dependency_queries import request_current_projection, schedule_projection
        execution = db.scalar(select(Execution).options(defer(Execution.raw_payload)).where(Execution.id == execution_id))
        if execution is None:
            return None
        state = request_current_projection(db, execution, risk_metadata)
        if state and state["status"] == "pending":
            background_tasks.add_task(schedule_projection, db.get_bind(), execution.id, state["build_token"], risk_metadata)
        return state
    except Exception:
        logging.getLogger("cats.dependencies").exception(
            "Dependency projection could not be queued after ingest", extra={"execution_id": execution_id})
        return None


def ingest_payload(payload: ExecutionPayload, db: Session, *, commit: bool = True):
    if not payload.fixable_only:
        raise HTTPException(status_code=422, detail="Portal accepts fixable-only assessments")
    existing = db.scalar(select(Execution).where(Execution.execution_key == payload.execution_id))
    if existing:
        incoming_payload = payload.model_dump(mode="json")
        def evidence_identity(value: dict) -> dict:
            normalized = dict(value)
            service_value = normalized.get("service") if isinstance(normalized.get("service"), dict) else {}
            # Display metadata is authoritative on Service and can legitimately
            # change during staged -> active promotion. The stable service key
            # remains part of the immutable execution identity.
            normalized["service"] = {"id": service_value.get("id")}
            return normalized
        if evidence_identity(existing.raw_payload) != evidence_identity(incoming_payload):
            raise HTTPException(status_code=409, detail="Execution ID already exists with different evidence")
        return {"accepted": True, "duplicate": True, "execution_id": existing.id}

    service = db.scalar(select(Service).where(Service.service_key == payload.service.id))
    if not service:
        service = Service(service_key=payload.service.id, name=payload.service.name, lifecycle_status="active")
        db.add(service)
        db.flush()
    elif archive_state(service):
        raise HTTPException(status_code=409, detail="Service is archived; restore it before accepting new evidence")
    staged_name_before_ingest = service.name
    service.name = payload.service.name
    if payload.service.description is not None:
        service.description = payload.service.description
    service.owner = payload.service.owner
    service.poc = payload.service.poc
    promoted_from_staged = service_lifecycle(service) == "staged"
    if promoted_from_staged:
        restore_generated_staging_name(service)
        service.lifecycle_status = "active"
    known_service_image_ids = set(db.scalars(select(ServiceImage.id).where(ServiceImage.service_id == service.id)).all())
    requested_groups = {name.strip() for name in payload.service.groups if name.strip()}
    existing_groups = {group.name: group for group in service.groups}
    for group_name in requested_groups:
        group = db.scalar(select(Group).where(Group.name == group_name))
        if not group:
            group = Group(name=group_name)
            db.add(group)
            db.flush()
        if group_name not in existing_groups:
            service.groups.append(group)
    scan_scope = payload.scan_scope or "service"
    scope_image = (payload.scope_image or "").strip() or None
    finding_images = {str(item.image).strip() for item in payload.findings if str(item.image).strip()}
    if scan_scope == "image" and not scope_image:
        if len(finding_images) == 1:
            scope_image = next(iter(finding_images))
        else:
            raise HTTPException(status_code=422, detail="Image-scoped scans must identify exactly one image")
    configuration = configuration_for_service(db, service)
    effective_complete = payload.complete and not (
        (bool(payload.skipped_images)
         and configuration.get("skipped_images_incomplete", "true") == "true")
        or bool(payload.skipped_charts)
    )
    incoming_version = payload.service.version.strip()
    version_label = incoming_version if incoming_version.lower() != "unknown" else "Unversioned"
    service_version = db.scalar(select(ServiceVersion).where(
        ServiceVersion.service_id == service.id, ServiceVersion.version == version_label,
    ))
    version_created = service_version is None
    if service_version is None:
        service_version = ServiceVersion(service_id=service.id, version=version_label)
        db.add(service_version)
        db.flush()
        db.add(AuditEvent(action="service.version_created", target_type="service_version",
                          target_id=str(service_version.id),
                          detail={"service_id": service.id, "version": version_label}))
    previous_current_version_id = service.current_version_id
    current_version_execution = db.scalar(select(Execution).where(
        Execution.service_id == service.id,
        Execution.service_version_id == previous_current_version_id,
        Execution.complete.is_(True),
        Execution.scan_scope == "service",
    ).order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1)) if previous_current_version_id else None
    # A delayed upload of an older release is historical evidence, even when
    # that release has never been seen before. Arrival order is not release order.
    may_promote = (
        previous_current_version_id is None
        or previous_current_version_id == service_version.id
        or (version_created and (
            current_version_execution is None
            or aware(payload.scanned_at) > aware(current_version_execution.scanned_at)
        ))
    )
    if effective_complete and scan_scope == "service" and may_promote:
        service.current_version_id = service_version.id
        if previous_current_version_id != service_version.id:
            db.add(AuditEvent(action="service.current_version_changed", target_type="service",
                              target_id=str(service.id), detail={"previous_version_id": previous_current_version_id,
                                                                "version_id": service_version.id,
                                                                "version": version_label}))
    # Keep an out-of-order scan as evidence without rolling back the current
    # release's reconciled posture. This applies within a version as well as
    # across versions.
    current_ingest = (
        service.current_version_id == service_version.id
        and (current_version_execution is None
             or aware(payload.scanned_at) >= aware(current_version_execution.scanned_at))
    )
    if effective_complete and scan_scope == "service" and current_ingest:
        service.assessment_status = "assessed"
    if isinstance(payload.service_overview, dict):
        _enrich_rendered_resource_lineage({"service_overview": payload.service_overview,
            "policy_findings": [item.model_dump(mode="json") for item in payload.policy_findings]})
    if payload.helm_source_files and isinstance(payload.service_overview, dict):
        _enrich_values_source_mappings({"service_overview": payload.service_overview}, payload.helm_source_files)
    execution = Execution(
        execution_key=payload.execution_id, service=service, service_version=service_version,
        scanned_at=payload.scanned_at,
        complete=effective_complete, scan_scope=scan_scope, scope_image=scope_image,
        pipeline_url=payload.pipeline_url,
        commit_sha=payload.commit_sha, scanner_db_built_at=payload.scanner_db_built_at,
        raw_payload=payload.model_dump(mode="json"),
    )
    db.add(execution)
    db.flush()
    reconcile_watchlist_matches(db, execution)
    observed = set()
    finding_by_cve: dict[str, Finding] = {}
    requested_cves = sorted({item.cve for item in payload.findings})
    # Keep each IN clause comfortably below SQLite's common bind limit while
    # avoiding one SELECT (and often one flush) per observation in production.
    for offset in range(0, len(requested_cves), 500):
        for finding in db.scalars(select(Finding).where(
            Finding.service_id == service.id,
            Finding.cve.in_(requested_cves[offset:offset + 500]),
        )):
            finding_by_cve[finding.cve] = finding
    image_cache: dict[tuple[str, str | None], ServiceImage | None] = {}

    def ensure_ingest_image(reference: str | None, digest: str | None = None) -> ServiceImage | None:
        if not current_ingest:
            return None
        identity = _image_identity(reference, digest)
        if identity not in image_cache:
            image_cache[identity] = _ensure_service_image(db, service, reference, digest)
        return image_cache[identity]

    for item in payload.findings:
        observed.add(item.cve)
        finding = finding_by_cve.get(item.cve)
        if not finding:
            finding = Finding(service=service, cve=item.cve, severity=item.severity,
                              first_seen=payload.scanned_at, episode_started=payload.scanned_at,
                              last_seen=payload.scanned_at, active=current_ingest)
            db.add(finding)
            finding_by_cve[item.cve] = finding
        elif current_ingest and not finding.active:
            finding.active = True
            finding.episode_started = payload.scanned_at
            finding.resolved_at = None
            finding.recurrence_count += 1
        if current_ingest:
            finding.last_seen = payload.scanned_at
            finding.severity = item.severity
        evidence = dict(item.evidence or {})
        evidence.setdefault("kev", item.kev)
        if item.epss is not None:
            evidence.setdefault("epss", item.epss)
        db.add(FindingObservation(
            finding=finding, execution_id=execution.id, image=item.image,
            image_digest=item.image_digest, package=item.package,
            installed_version=item.installed_version, fixed_version=item.fixed_version,
            evidence=evidence,
        ))
        ensure_ingest_image(item.image, item.image_digest)
    overview_payload = payload.service_overview if isinstance(payload.service_overview, dict) else {}
    for raw_image in [*(overview_payload.get("images") or []), *(overview_payload.get("container_images") or [])]:
        if isinstance(raw_image, dict):
            ensure_ingest_image(raw_image.get("image") or raw_image.get("reference") or raw_image.get("name"), raw_image.get("digest") or raw_image.get("image_digest"))
        else:
            ensure_ingest_image(str(raw_image), None)
    for artifact in overview_payload.get("artifacts") or []:
        if isinstance(artifact, dict) and str(artifact.get("type") or "").lower() == "image":
            registry = str(artifact.get("registry") or "").strip()
            repository = str(artifact.get("repository") or "").strip("/")
            name = str(artifact.get("artifact") or "").strip()
            version = str(artifact.get("version") or "").strip()
            reference = "/".join(part for part in (registry, repository, name) if part and part != "—")
            if version and version != "—":
                reference = f"{reference}:{version}"
            ensure_ingest_image(reference, artifact.get("digest"))
    if effective_complete and current_ingest:
        if scan_scope == "image":
            ensure_ingest_image(scope_image)
            _reconcile_image_scope(db, service, scope_image or "", observed, payload.scanned_at)
        else:
            for finding in db.scalars(select(Finding).where(Finding.service_id == service.id, Finding.active.is_(True))):
                if finding.cve not in observed:
                    finding.active = False
                    finding.resolved_at = payload.scanned_at
    if current_ingest:
        sync_policy_findings(db, service, payload.policy_findings, payload.scanned_at, effective_complete)
    for image in db.scalars(select(ServiceImage).where(ServiceImage.service_id == service.id)).all():
        if image.id not in known_service_image_ids:
            db.add(AuditEvent(
                action="image_added", target_type="service_image", target_id=str(image.id),
                detail={"service_id": service.id, "image": image.image_reference, "digest": image.image_digest},
            ))
    db.add(AuditEvent(
        action="scan.ingested", target_type="execution", target_id=str(execution.id),
        detail={"service_id": service.id, "scan_scope": scan_scope, "scope_image": scope_image,
                "complete": effective_complete},
    ))
    if promoted_from_staged:
        db.add(AuditEvent(
            action="service.promoted", target_type="service", target_id=str(service.id),
            detail={"service_id": service.id, "execution_id": execution.id, "reason": "ingested_evidence",
                    "previous_name": staged_name_before_ingest, "name": service.name},
        ))
    record_reingestion_provenance(db, execution, payload.model_dump(mode="json"))
    should_record_validation = payload.artifact_type == "helm" and scan_scope == "service"
    service_id, execution_id = service.id, execution.id
    if not commit:
        db.flush()
        return {"accepted": True, "duplicate": False, "execution_id": execution_id}
    db.commit()
    validation_run_id = None
    schedule_validation = False
    if should_record_validation:
        try:
            with SessionLocal() as validation_db:
                validation_service = validation_db.get(Service, service_id)
                validation_execution = validation_db.get(Execution, execution_id)
                if validation_service and validation_execution:
                    validation_run, schedule_validation = _new_validation_run(validation_db, validation_service, validation_execution)
                    validation_db.commit()
                    validation_run_id = validation_run.id
        except Exception:
            # Deployment Validation is optional evidence. Its persistence can
            # never roll back or change the already-committed static scan.
            logging.getLogger("cats.deployment_validation").exception(
                "Deployment Validation record could not be created", extra={"execution_id": execution_id})
    if schedule_validation and validation_run_id:
        _submit_validation_run(validation_run_id)
    return {"accepted": True, "duplicate": False, "execution_id": execution_id,
            "deployment_validation_run_id": validation_run_id}


@app.get("/home", response_class=HTMLResponse)
def public_home(request: Request, auth: AuthContext | None = Depends(optional_user)):
    if auth:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "home.html", {
        "current_user": auth.user if auth else None,
        "csrf_token": auth.csrf_token if auth else "",
        "can": auth.has if auth else (lambda _permission: False),
        "themes": THEMES,
        "pending_request_count": 0,
        "pending_poam_count": 0,
    })


def self_service_context(request: Request, mode: str, image_list: str = "", chart_url: str = "", status_message: str | None = None, job_id: str | None = None, auth: AuthContext | None = None, services: list[Service] | None = None, ingest_service_id: str = "", archive_names: list[str] | None = None, sbom_formats: list[str] | None = None, cyclonedx_spec_version: str = "1.5", ingest_service_version: str = ""):
    with PUBLIC_JOB_LOCK:
        job_snapshot = dict(PUBLIC_JOBS.get(job_id, {})) if job_id else {}
    descriptions = {
        "scan": "Review public container images without creating a persistent service record.",
        "sbom": "Generate one or more standard SBOM documents from a single image inventory.",
        "patch": "Request patched image outputs for public container images without changing a persistent service record.",
    }
    progress_phases = (
        [("prepare_inputs", "Prepare"), ("generate_sboms", "Generate")]
        if mode == "sbom"
        else [("prepare_inputs", "Prepare"), ("generate_sboms", "SBOM"), ("scan_sboms", "Scan"), ("configuration_scan", "Configuration"), ("report_results", "Report")]
    )
    return templates.TemplateResponse(request, "self_service.html", {
        "current_user": auth.user if auth else None, "csrf_token": auth.csrf_token if auth else "", "can": auth.has if auth else (lambda _permission: False),
        "themes": THEMES, "pending_request_count": 0, "pending_poam_count": 0,
        "mode": mode, "description": descriptions[mode], "image_list": image_list, "chart_url": chart_url,
        "archive_names": archive_names or [],
        "authenticated_services": services or [], "authenticated_ingest": bool(auth and auth.accessible_service_ids("scan.ingest") != set()),
        "service_version_options": {service.service_key: [version.version for version in service.versions]
                                    for service in (services or [])},
        "ingest_service_id": ingest_service_id,
        "ingest_service_version": ingest_service_version,
        "status_message": status_message, "job_id": job_id, "job": job_snapshot,
        "sbom_output_formats": SBOM_OUTPUT_FORMATS,
        "selected_sbom_formats": sbom_formats or ["cyclonedx-json"],
        "cyclonedx_spec_versions": CYCLONEDX_SPEC_VERSIONS,
        "cyclonedx_spec_version": cyclonedx_spec_version,
        "progress_phases": progress_phases,
        "progress_order": ["queued", *(phase for phase, _label in progress_phases)],
    })


def _stamp_job_transition(current: dict, values: dict, terminal_statuses: set[str]) -> None:
    """Attach stable lifecycle timestamps without persisting elapsed counters."""
    next_status = str(values.get("status") or current.get("status") or "").lower()
    timestamp = utcnow().isoformat()
    if next_status == "running" and not (values.get("started_at") or current.get("started_at")):
        values["started_at"] = timestamp
    if next_status in terminal_statuses and not (values.get("finished_at") or current.get("finished_at")):
        values["finished_at"] = timestamp


def _public_job_update(job_id: str, **values):
    with PUBLIC_JOB_LOCK:
        if job_id in PUBLIC_JOBS:
            _stamp_job_transition(
                PUBLIC_JOBS[job_id], values,
                {"complete", "incomplete", "error", "cancelled"},
            )
            PUBLIC_JOBS[job_id].update(values)


def _safe_chart_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return bool(normalized) and not normalized.startswith("/") and ".." not in normalized.split("/")


def _stage_public_chart(input_dir: Path, archive: bytes, filename: str, *, close_archive: bool = True) -> None:
    """Extract one uploaded Helm archive into the ephemeral charts directory."""
    try:
        extract_chart(archive, filename or "chart.tgz", input_dir / "charts")
    except ValueError as exc:
        raise HTTPException(status_code=413 if "exceeds configured" in str(exc) else 400, detail=str(exc)) from exc
    finally:
        if close_archive and isinstance(archive, DownloadedChart):
            archive.close()


def _helm_request_detail(stage: str, requested: str, final: str | None = None) -> str:
    """Never retain credentials, signed queries, headers or response bodies."""
    def safe(value):
        try:
            parsed = urllib.parse.urlsplit(str(value))
            host = parsed.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            if parsed.port:
                host += f":{parsed.port}"
            return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path, "", ""))[:240].replace("\r", "").replace("\n", "")
        except ValueError:
            return "[invalid URL]"
    detail = f"stage={stage}; requested={safe(requested)}"
    if final:
        detail += f"; final={safe(final)}; redirected={'yes' if requested != final else 'no'}"
    return detail


def _helm_index_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, detail="Helm repository URL must use http or https")
    path = parsed.path
    if not path.endswith("/index.yaml"):
        path = path.rstrip("/") + "/index.yaml"
    return urllib.parse.urlunsplit(parsed._replace(path=path, fragment=""))


def _fetch_public_stream(url: str, certificates: list[dict] | None = None):
    """Fetch into a bounded temporary file, preserving urllib TLS and redirects."""
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Chart URL must use http or https")
    max_bytes = compressed_limit()
    stage = "repository index retrieval" if parsed.path.endswith("/index.yaml") else "chart archive retrieval"
    final_url = None
    try:
        request = urllib.request.Request(url.strip(), headers={"User-Agent": "CATS/standalone-scanner"})
        context = ssl.create_default_context()
        for item in certificates or []:
            pem = str(item.get("pem") or "") if isinstance(item, dict) else ""
            if pem:
                context.load_verify_locations(cadata=pem)
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            content_length = int(response.headers.get("Content-Length") or 0)
            if content_length > max_bytes:
                raise HTTPException(status_code=413, detail="Helm chart archive is too large")
            final_url = response.geturl()
            data = copy_bounded(response, max_bytes)
    except HTTPException as exc:
        raise HTTPException(exc.status_code, detail=f"{exc.detail} [{_helm_request_detail(stage, url, final_url)}]") from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=408, detail=f"Helm source acquisition timed out [{_helm_request_detail(stage, url, final_url)}]") from exc
    except urllib.error.HTTPError as exc:
        explanations = {
            401: "authentication required or denied",
            403: "request rejected; check repository authorization and proxy/firewall policy",
            404: "repository index or chart archive not found; check the source URL and exact version",
            429: "repository rate limit reached; retry later",
        }
        explanation = explanations.get(exc.code, "repository or intermediary returned an HTTP error")
        # Do not expose response bodies, headers, URL credentials or signed queries.
        exc.close()
        category = "redirect rejected by CATS policy" if 300 <= exc.code < 400 else explanation
        raise HTTPException(status_code=400, detail=f"Helm source request failed (HTTP {exc.code}): {category} [{_helm_request_detail(stage, url, exc.geturl())}]") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (ssl.SSLError, ssl.SSLCertVerificationError)):
            raise HTTPException(
                status_code=400,
                detail=f"Helm source TLS certificate verification failed. Configure the issuing CA in CATS Trusted CA settings if this source is authorized. [{_helm_request_detail(stage, url)}]",
            ) from exc
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise HTTPException(status_code=408, detail=f"Helm source acquisition timed out [{_helm_request_detail(stage, url)}]") from exc
        raise HTTPException(status_code=400, detail=f"Helm source DNS/network failure: source is unreachable [{_helm_request_detail(stage, url)}]") from exc
    except ssl.SSLError as exc:
        raise HTTPException(400, detail=f"Helm source TLS certificate verification failed [{_helm_request_detail(stage, url)}]") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Chart URL could not be downloaded [{_helm_request_detail(stage, url, final_url)}]") from exc
    return data, final_url


def _fetch_public_url(url: str, certificates: list[dict] | None = None) -> tuple[bytes, str]:
    """Compatibility metadata reader; archive transfers use the disk-backed path."""
    stream, final_url = _fetch_public_stream(url, certificates)
    try:
        return stream.read(), final_url
    finally:
        stream.close()


def _download_oci_chart(reference: str, certificates: list[dict] | None = None) -> list[tuple[DownloadedChart, str]]:
    """Pull one public OCI Helm chart using the bundled Helm executable."""
    from .oci_diagnostics import OciPullFailure
    helm = shutil.which("helm") or "/usr/local/bin/helm"
    if not Path(helm).exists() and shutil.which(helm) is None:
        raise OciPullFailure(reference, category="helm_execution_failure")
    max_bytes = compressed_limit()
    output = []
    try:
        with tempfile.TemporaryDirectory(prefix="cats-oci-chart-") as destination:
            check_space(destination, max_bytes)
            with ephemeral_trust(certificates) as (ca_file, trust_env):
                command = [helm, "pull", *oci_pull_arguments(reference), "--destination", destination]
                if ca_file:
                    command.extend(["--ca-file", str(ca_file)])
                result = subprocess.run(
                    command, capture_output=True, text=True,
                    timeout=int(os.getenv("CATS_PUBLIC_HELM_PULL_TIMEOUT", "180")),
                    check=False, env={**os.environ, **trust_env},
                )
            check_space(destination)
            if result.returncode != 0:
                raise OciPullFailure(reference, exit_code=result.returncode,
                                     stderr=result.stderr or "", stdout=result.stdout or "",
                                     ca_file_used=bool(ca_file))
            archives = sorted(Path(destination).glob("*.tgz")) + sorted(Path(destination).glob("*.tar.gz"))
            if not archives:
                raise HTTPException(status_code=400, detail="Helm did not produce an OCI chart archive")
            for archive_path in archives:
                if archive_path.stat().st_size > max_bytes:
                    raise HTTPException(status_code=413, detail="Helm chart archive is too large")
                with archive_path.open("rb") as source:
                    data = copy_bounded(source, max_bytes)
                output.append((data, archive_path.name))
            return output
    except HTTPException:
        close_downloads(output)
        raise
    except subprocess.TimeoutExpired as exc:
        close_downloads(output)
        raise OciPullFailure(reference, category="timeout") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        close_downloads(output)
        raise OciPullFailure(reference, category="helm_execution_failure" if isinstance(exc, OSError)
                             else "unknown_acquisition_failure") from exc
    except BaseException:
        close_downloads(output)
        raise


def _download_public_chart(url: str, certificates: list[dict] | None = None) -> list[tuple[DownloadedChart, str]]:
    """Download a chart archive or expand a Helm repository/index URL."""
    try:
        raw_url = normalize_chart_reference(url)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    if raw_url.lower().startswith("oci://"):
        return _download_oci_chart(raw_url, certificates)
    parsed = urllib.parse.urlparse(raw_url)
    selector = parsed.fragment.strip()
    fetch_url = urllib.parse.urlunparse(parsed._replace(fragment=""))
    if selector or not parsed.path or parsed.path.endswith("/"):
        fetch_url = _helm_index_url(fetch_url)
    data, final_url = _fetch_public_stream(fetch_url, certificates)
    final_path = urllib.parse.urlparse(final_url).path.lower()
    signature = data.read(4)
    data.seek(0)
    if final_path.endswith((".tgz", ".tar.gz", ".tar", ".zip")) or signature.startswith((b"\x1f\x8b", b"PK\x03\x04")):
        return [(data, Path(final_path).name or "chart.tgz")]

    try:
        index_data, index_url = data.read(), final_url
    finally:
        data.close()
    try:
        index = yaml.safe_load(index_data.decode("utf-8-sig"))
    except (UnicodeDecodeError, yaml.YAMLError):
        index = None
    if not isinstance(index, dict) or not isinstance(index.get("entries"), dict):
        candidate_index_url = _helm_index_url(final_url)
        if candidate_index_url != final_url:
            try:
                index_data, index_url = _fetch_public_url(candidate_index_url, certificates)
                index = yaml.safe_load(index_data.decode("utf-8-sig"))
            except (UnicodeDecodeError, yaml.YAMLError):
                index = None
    if not isinstance(index, dict) or not isinstance(index.get("entries"), dict):
        raise HTTPException(status_code=400, detail=f"Malformed Helm index: Helm URL must point to a chart archive or Helm repository index.yaml [{_helm_request_detail('repository index retrieval', fetch_url, index_url)}]")

    entries = index["entries"]
    names = [selector] if selector else list(entries)
    if selector and selector not in entries:
        raise HTTPException(status_code=400, detail=f"Requested chart missing [stage=chart selection; {_helm_request_detail('chart selection', fetch_url, index_url)}]")
    archives: list[tuple[DownloadedChart, str]] = []
    with ExitStack() as cleanup:
        for chart_name in names:
            versions = entries.get(chart_name)
            if not isinstance(versions, list) or not versions:
                continue
            version = next((item for item in versions if isinstance(item, dict)
                            and isinstance(item.get("urls"), list) and item["urls"]
                            and isinstance(item["urls"][0], str)), None)
            if not version:
                continue
            archive_url = urllib.parse.urljoin(index_url, version["urls"][0])
            archive_data, archive_final_url = _fetch_public_stream(archive_url, certificates)
            cleanup.callback(archive_data.close)
            archive_name = Path(urllib.parse.urlparse(archive_final_url).path).name
            if not archive_name.lower().endswith((".tgz", ".tar.gz", ".tar", ".zip")):
                archive_name = f"{chart_name}-{version.get('version', 'latest')}.tgz"
            archives.append((archive_data, archive_name))
        cleanup.pop_all()
    if not archives:
        raise HTTPException(status_code=400, detail="Helm repository index contains no downloadable chart archives")
    return archives


def _discover_helm_repository(url: str, certificates: list[dict] | None = None) -> dict:
    """Fetch repository metadata only; chart packages are materialized separately."""
    raw_url = str(url or "").strip()
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, detail="Helm repository URL must use http or https")
    index_url = _helm_index_url(raw_url)
    data, final_url = _fetch_public_url(index_url, certificates)
    try:
        index = yaml.safe_load(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, yaml.YAMLError):
        index = None
    if not isinstance(index, dict) or not isinstance(index.get("entries"), dict):
        raise HTTPException(400, detail=f"Malformed Helm index: repository does not provide a valid index.yaml [{_helm_request_detail('repository index retrieval', index_url, final_url)}]")
    charts = []
    for chart_name, raw_versions in sorted(index["entries"].items(), key=lambda item: str(item[0])):
        versions = []
        for item in raw_versions if isinstance(raw_versions, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("urls"), list) or not item["urls"] or not isinstance(item["urls"][0], str):
                continue
            versions.append({
                "version": str(item.get("version") or ""),
                "app_version": str(item.get("appVersion") or ""),
                "created": str(item.get("created") or ""),
                "digest": str(item.get("digest") or ""),
                "url": urllib.parse.urljoin(final_url, item["urls"][0]),
            })
        if versions:
            charts.append({"name": str(chart_name), "versions": versions, "latest": versions[0]})
    if not charts:
        raise HTTPException(400, detail=f"Helm repository index contains no chart versions [{_helm_request_detail('chart selection', index_url, final_url)}]")
    return {
        "repository_url": _safe_artifact_source_reference(raw_url, "repository"),
        "index_url": _safe_artifact_source_reference(final_url, "repository"),
        "api_version": str(index.get("apiVersion") or ""),
        "generated": str(index.get("generated") or ""),
        "charts": charts,
    }


def _primary_chart_markers(source: dict[str, str]) -> list[str]:
    """Exclude chart dependencies nested below another chart root."""
    markers = {PurePosixPath(name) for name in source if PurePosixPath(name).name == "Chart.yaml"}
    return sorted(str(marker) for marker in markers if not any(
        parent / "Chart.yaml" in markers for parent in marker.parent.parents
    ))


def _chart_identity(source: dict[str, str]) -> tuple[str, str]:
    markers = _primary_chart_markers(source)
    if len(markers) != 1:
        raise HTTPException(422, detail="A Helm Chart artifact must contain exactly one chart root")
    try:
        metadata = yaml.safe_load(source[markers[0]]) or {}
    except yaml.YAMLError as exc:
        raise HTTPException(422, detail="Helm Chart.yaml is invalid") from exc
    name, version = str(metadata.get("name") or "").strip(), str(metadata.get("version") or "").strip()
    if not name or not version:
        raise HTTPException(422, detail="Helm Chart.yaml must declare name and version")
    return name, version


def _run_public_scan(job_id: str, image_list: str):
    job_dir = PUBLIC_JOB_ROOT / job_id
    input_dir = job_dir / "input"
    output_dir = job_dir / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    if image_list.strip():
        input_dir.joinpath("images.txt").write_text(image_list, encoding="utf-8")
    runner = os.getenv("CATS_SCANNER_RUNNER", "cats-scan")
    with PUBLIC_JOB_LOCK:
        job_configuration = dict(PUBLIC_JOBS.get(job_id, {}))
        if job_configuration.get("status") == "cancelled":
            return
    job_kind = str(job_configuration.get("job_kind") or "scan")
    process_environment = os.environ.copy()
    trust_bundle = input_dir / ".cats-trust" / "ca-bundle.pem"
    if trust_bundle.is_file():
        for key in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
            process_environment[key] = str(trust_bundle)
    process_environment["CATS_JOB_MODE"] = job_kind
    if job_kind == "sbom":
        process_environment["SBOM_FORMATS"] = ",".join(job_configuration.get("sbom_formats") or ["cyclonedx-json"])
        process_environment["SBOM_CYCLONEDX_SPEC_VERSION"] = str(job_configuration.get("cyclonedx_spec_version") or "1.5")
    _public_job_update(job_id, status="running", phase="prepare_inputs")
    try:
        log_path = output_dir / "worker.log"
        with log_path.open("w", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                [runner, str(input_dir), str(output_dir)],
                stdout=log_file, stderr=subprocess.STDOUT, text=True, env=process_environment,
            )
            with PUBLIC_JOB_LOCK:
                if PUBLIC_JOBS.get(job_id, {}).get("status") == "cancelled":
                    process.terminate()
                else:
                    PUBLIC_PROCESSES[job_id] = process
            phases = (("prepare_inputs", "generate_sboms") if job_kind == "sbom" else
                      ("prepare_inputs", "generate_sboms", "scan_sboms", "configuration_scan", "report_results"))
            deadline = time.monotonic() + int(os.getenv("CATS_PUBLIC_JOB_TIMEOUT", "3600"))
            while process.poll() is None:
                if time.monotonic() > deadline:
                    process.kill()
                    process.wait()
                    raise TimeoutError("public scan exceeded its timeout")
                for phase in phases:
                    phase_path = output_dir / f"phase-{phase}.json"
                    if phase_path.exists():
                        try:
                            phase_state = json.loads(phase_path.read_text(encoding="utf-8"))
                        except (OSError, ValueError):
                            continue
                        if phase_state.get("status") == "running":
                            _public_job_update(job_id, status="running", phase=phase)
                            break
                time.sleep(0.25)
            returncode = process.returncode
        with PUBLIC_JOB_LOCK:
            PUBLIC_PROCESSES.pop(job_id, None)
            cancelled = PUBLIC_JOBS.get(job_id, {}).get("status") == "cancelled"
        if cancelled:
            return
        completed_returncode = returncode
        fatal_scan = (output_dir / "scan-failure.json").exists()
        failure = {}
        if fatal_scan:
            try:
                failure = json.loads((output_dir / "scan-failure.json").read_text(encoding="utf-8"))
                if not isinstance(failure, dict):
                    failure = {}
            except (ValueError, OSError):
                pass
        summary = {}
        summary_path = output_dir / "scan-summary.json"
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                summary = {}
        _public_job_update(
            job_id,
            status="error" if fatal_scan else ("complete" if completed_returncode == 0 else "incomplete"),
            phase=failure.get("phase") or ("generate_sboms" if job_kind == "sbom" else "report_results"), returncode=completed_returncode,
            error=(f"Scanner phase {failure.get('phase', 'unknown')} failed (exit {failure.get('exit_code', completed_returncode)}). See phase log and worker.log." if fatal_scan else None),
            summary=summary,
        )
        # Image scans launched from the service workspace are attached through
        # the same existing ingest pipeline once the worker has produced its
        # durable portal result.  They never create a second findings store.
        service_key = str(job_configuration.get("ingest_service_id") or "")
        if not fatal_scan and service_key and job_kind == "scan" and (output_dir / "portal-result.json").exists():
            try:
                with SessionLocal() as ingest_db:
                    class _InternalScanAuth:
                        def accessible_service_ids(self, _permission): return None
                        def has(self, _permission, _service_id=None): return True
                    ingest_public_scan(job_id, service_key, ingest_db, _InternalScanAuth())
                    images = ingest_db.scalars(select(ServiceImage).where(ServiceImage.scan_job_id == job_id)).all()
                    for image in images:
                        image.scan_status = "scanned" if completed_returncode == 0 else "failed"
                        image.last_scanned_at = utcnow() if completed_returncode == 0 else image.last_scanned_at
                        image.scan_error = None if completed_returncode == 0 else "Scanner completed with incomplete evidence."
                    ingest_db.commit()
            except Exception as exc:
                _public_job_update(job_id, ingest_error=str(exc)[:500])
    except Exception as exc:
        with PUBLIC_JOB_LOCK:
            PUBLIC_PROCESSES.pop(job_id, None)
            cancelled = PUBLIC_JOBS.get(job_id, {}).get("status") == "cancelled"
        if cancelled:
            return
        _public_job_update(job_id, status="error", phase="worker", error=str(exc))
    finally:
        shutil.rmtree(input_dir / ".cats-trust", ignore_errors=True)
        with PUBLIC_JOB_LOCK:
            final_job = dict(PUBLIC_JOBS.get(job_id, {}))
        if final_job.get("definition_context"):
            from .definition_routes import complete_scan
            complete_scan(job_id, final_job)


def _public_chart_skip_entry(source: str, error: object) -> str:
    """Return a compact, human-readable missing-evidence entry.

    The value is deliberately stored as one line because the same file is
    consumed by the GitLab report-to-portal script and by the standalone
    worker.  Keep the source first so it remains useful even when the error
    text is abbreviated.
    """
    from .oci_diagnostics import OciPullFailure

    source = str(source).replace("\r", " ").replace("\n", " ")
    if "://" in source:
        source = _helm_request_detail("source", source).split("requested=", 1)[1]
    if isinstance(error, OciPullFailure):
        diagnostic = error.diagnostic
        exit_code = diagnostic["helm_exit_code"]
        exit_detail = f"; Helm exit {exit_code}" if exit_code is not None else ""
        reference_detail = _helm_request_detail('oci_acquisition', diagnostic['attempted_reference']).replace(
            '; requested=', '; reference=', 1)
        detail = (f"{error.detail} [category={diagnostic['failure_category']}"
                  f"{exit_detail}; {reference_detail}]")
        return f"{source} :: {detail}"
    detail = str(getattr(error, "detail", error)).strip().replace("\r", " ").replace("\n", " ")
    return f"{source} :: {detail[-500:] or 'chart could not be retrieved'}"


def _collect_helm_source_files(charts_dir: Path) -> dict[str, str]:
    """Collect editable text sources with bounded size and stable paths."""
    if not charts_dir.is_dir():
        return {}
    limit = int(os.getenv("CATS_ARTIFACT_SOURCE_MAX_BYTES", str(100 * 1024 * 1024)))
    total = 0
    files: dict[str, str] = {}
    allowed_names = {"Chart.yaml", "Chart.lock", "values.yaml", "values.yml"}
    allowed_suffixes = {".yaml", ".yml", ".tpl", ".txt"}
    for path in sorted(charts_dir.rglob("*")):
        if not path.is_file() or (path.name not in allowed_names and path.suffix.lower() not in allowed_suffixes):
            continue
        if path.stat().st_size + total > limit:
            raise HTTPException(413, detail="Retained Helm text sources exceed CATS_ARTIFACT_SOURCE_MAX_BYTES; scan archive size and retained-source size are separate limits")
        raw = path.read_bytes()
        total += len(raw)
        try:
            files[path.relative_to(charts_dir).as_posix()] = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            continue
    return files


def _retained_helm_sources(archives: list[tuple[bytes, str]], *, preserve_archives: bool = False) -> tuple[dict[str, str], int]:
    """Use the scanner's guarded archive staging to produce one retained snapshot."""
    if not archives:
        raise HTTPException(status_code=422, detail="No Helm chart archives were supplied")
    with ExitStack() as cleanup, tempfile.TemporaryDirectory(prefix="cats-artifact-helm-") as temporary:
        if not preserve_archives:
            cleanup.callback(close_downloads, archives)
        root = Path(temporary)
        for archive, filename in archives:
            _stage_public_chart(root, archive, filename, close_archive=not preserve_archives)
        charts_dir = root / "charts"
        source = _collect_helm_source_files(charts_dir)
        if not source:
            raise HTTPException(status_code=422, detail="Helm source could not be retained within the configured source-size policy")
        chart_count = len(_primary_chart_markers(source))
        return source, chart_count


def _safe_artifact_source_reference(value: str, source_method: str) -> str:
    """Persist useful provenance without retaining URL credentials or tokens."""
    raw = str(value or "").strip()
    if source_method == "upload":
        return "upload"
    parsed = urllib.parse.urlsplit(raw)
    hostname = parsed.hostname or ""
    if parsed.port:
        hostname = f"{hostname}:{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, hostname, parsed.path, "", ""))[:240]


def _persist_uploaded_artifact(
    db: Session, auth: AuthContext, service: Service, artifact_type: str,
    source: dict[str, str], *, source_reference: str, artifact_name: str,
    source_type: str | None = None, chart_name: str | None = None,
    chart_version: str | None = None, parent_repository_id: int | None = None,
    source_metadata: dict | None = None,
) -> ServiceArtifact:
    artifact = ServiceArtifact(
        service_id=service.id, artifact_type=artifact_type,
        artifact_name=artifact_name[:240], source_reference=source_reference[:240],
        source_type=source_type, chart_name=chart_name, chart_version=chart_version,
        parent_repository_id=parent_repository_id, source_metadata=source_metadata or {},
    )
    db.add(artifact)
    db.flush()
    db.add(_artifact_revision(source, artifact_id=artifact.id, number=1, label="ORIGINAL", user_id=auth.user.id,
                              source_metadata=source_metadata))
    record_audit(
        db, auth, "artifact.uploaded", "service_artifact", artifact.id,
        service_id=service.id, artifact_type=artifact_type,
        source_reference=source_reference, file_count=len(source), revision=1,
    )
    return artifact


def _reconcile_repository_catalog(db: Session, auth: AuthContext, service: Service,
                                  repository: ServiceArtifact, catalog: dict) -> list[ServiceArtifact]:
    existing = {item.chart_name: item for item in db.scalars(select(ServiceArtifact).where(
        ServiceArtifact.service_id == service.id,
        ServiceArtifact.parent_repository_id == repository.id,
        ServiceArtifact.artifact_type == "helm_chart",
    )).all()}
    discovered = []
    for item in catalog.get("charts") or []:
        name = str(item.get("name") or "")
        latest = item.get("latest") or {}
        chart = existing.get(name)
        if not chart:
            chart = ServiceArtifact(
                service_id=service.id, artifact_type="helm_chart",
                artifact_name=f"repo-{repository.id}:{name}"[:240], chart_name=name,
                chart_version=str(latest.get("version") or ""), source_type="repository",
                source_reference=repository.source_reference,
                parent_repository_id=repository.id, source_metadata=item,
            )
            db.add(chart)
        else:
            chart.chart_version = str(latest.get("version") or chart.chart_version or "")
            chart.source_metadata = item
            chart.updated_at = utcnow()
            chart.lifecycle_status = "active"
        discovered.append(chart)
    repository.source_metadata = {
        key: value for key, value in catalog.items() if key != "charts"
    } | {"chart_count": len(discovered)}
    repository.last_refreshed_at = utcnow()
    repository.updated_at = utcnow()
    record_audit(db, auth, "artifact.repository_refreshed", "service_artifact", repository.id,
                 service_id=service.id, chart_count=len(discovered))
    return discovered


def _materialize_repository_chart(db: Session, auth: AuthContext, chart: ServiceArtifact,
                                  certificates: list[dict], version: str = "") -> ServiceArtifactRevision:
    if chart.artifact_type != "helm_chart" or chart.source_type != "repository":
        raise HTTPException(422, detail="Only a discovered repository chart can be materialized this way")
    versions = (chart.source_metadata or {}).get("versions") or []
    selected = next((item for item in versions if not version or str(item.get("version")) == version), None)
    if not selected or not selected.get("url"):
        raise HTTPException(404, detail="The selected chart version is not present in the retained repository catalog")
    archives = _download_public_chart(str(selected["url"]), certificates)
    source, _count = _retained_helm_sources(archives)
    actual_name, actual_version = _chart_identity(source)
    if actual_name != chart.chart_name or actual_version != str(selected.get("version") or ""):
        raise HTTPException(422, detail="Materialized chart identity does not match repository metadata")
    latest = max(chart.revisions, key=lambda item: item.revision_number, default=None)
    provenance = {
        "source_type": "repository", "repository_id": chart.parent_repository_id,
        "repository_url": chart.source_reference, "chart_name": actual_name,
        "chart_version": actual_version, "package_url": str(selected["url"]),
        "digest": str(selected.get("digest") or ""),
    }
    revision = _artifact_revision(
        source, artifact_id=chart.id, number=(latest.revision_number if latest else 0) + 1,
        label="ORIGINAL" if not latest else "SOURCE_REFRESH", user_id=auth.user.id,
        source_metadata=provenance,
    )
    db.add(revision)
    chart.chart_version = actual_version
    chart.updated_at = utcnow()
    record_audit(db, auth, "artifact.chart_materialized", "service_artifact", chart.id,
                 service_id=chart.service_id, chart_name=actual_name, chart_version=actual_version,
                 repository_id=chart.parent_repository_id, revision=revision.revision_number)
    return revision


def _enrich_rendered_resource_lineage(data: dict) -> None:
    """Join affirmative scanner identities to unique retained rendered objects.

    Release namespaces are applied only when the scanner recorded their Helm
    origin. Conflicting chart/document identities remain unresolved.
    """
    overview = data.get("service_overview") if isinstance(data.get("service_overview"), dict) else {}
    resources = overview.get("rendered_resources") or data.get("rendered_resources") or []
    resources = [item for item in resources if isinstance(item, dict)]
    def same_source(left: dict, right: dict) -> bool:
        return bool(left.get("chart_instance_id") and left.get("source_template") and
                    left.get("chart_instance_id") == right.get("chart_instance_id") and
                    str(left["source_template"]).replace("\\", "/") ==
                    str(right.get("source_template") or "").replace("\\", "/"))

    matches_by_resource = {}
    for finding in data.get("policy_findings") or []:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            continue
        lineages = [evidence.get("resource_lineage"), *(evidence.get("candidate_resources") or [])]
        for lineage in lineages:
            if not isinstance(lineage, dict) or not lineage.get("kind") or not lineage.get("name"):
                continue
            matched = []
            for index, resource in enumerate(resources):
                metadata = resource.get("metadata") or {}
                if (resource.get("kind") != lineage["kind"] or metadata.get("name") != lineage["name"] or
                        resource.get("apiVersion", "") != lineage.get("api_version", "")):
                    continue
                namespace = metadata.get("namespace")
                if namespace and namespace != lineage.get("namespace", ""):
                    continue
                if not namespace and lineage.get("namespace") and lineage.get("namespace_source") != "helm-release":
                    continue
                source = str(resource.get("_cats_source_file") or resource.get("source_file") or "").replace("\\", "/")
                template = str(lineage.get("source_template") or "").replace("\\", "/")
                if source and template and not (source == template or source.endswith("/" + template) or template.endswith("/" + source)):
                    continue
                existing = resource.get("_cats_resource_lineage") or resource.get("_cats_lineage") or {}
                if any(key in existing and key in lineage and existing[key] != lineage[key]
                       for key in ("chart_instance_id", "chart_id", "execution_id", "execution_key", "source_execution_id")):
                    continue
                if (existing.get("rendered_artifact") != lineage.get("rendered_artifact") and
                        existing.get("rendered_artifact") and not same_source(existing, lineage)):
                    continue
                if (existing.get("rendered_artifact") == lineage.get("rendered_artifact") and
                        "document_index" in existing and "document_index" in lineage and
                        existing["document_index"] != lineage["document_index"]):
                    continue
                matched.append(index)
            if len(matched) != 1:
                continue
            document = {key: value for key, value in lineage.items() if key not in {
                "container_type", "container_name", "yaml_path", "start_line", "end_line", "containers"}}
            matches_by_resource.setdefault(matched[0], {})[json.dumps(document, sort_keys=True)] = document
    for index, candidates in matches_by_resource.items():
        documents = list(candidates.values())
        lineage = documents[0]
        identity_keys = ("api_version", "kind", "name", "namespace", "namespace_source", "chart_id",
                         "execution_id", "execution_key", "source_execution_id")
        if any(not same_source(lineage, other) or
               any(lineage.get(key) != other.get(key) for key in identity_keys) or
               (lineage.get("rendered_artifact") == other.get("rendered_artifact") and
                lineage.get("document_index") != other.get("document_index"))
               for other in documents[1:]):
            continue
        resource = resources[index]
        resource["_cats_resource_lineage_evidence"] = documents
        resource["_cats_resource_lineage"] = lineage
        if lineage.get("namespace_source") == "helm-release" and lineage.get("namespace"):
            resource.setdefault("metadata", {}).setdefault("namespace", lineage["namespace"])
        if lineage.get("source_template"):
            resource.setdefault("_cats_source_file", lineage["source_template"])


def _enrich_values_source_mappings(data: dict, source_files: dict[str, str]) -> None:
    """Prove simple template-to-values mappings without guessing composites."""
    overview = data.get("service_overview") if isinstance(data.get("service_overview"), dict) else {}
    resources = overview.get("rendered_resources") if isinstance(overview.get("rendered_resources"), list) else []

    def value_exists(document: object, dotted: str) -> bool:
        cursor = document
        for key in dotted.split("."):
            if not isinstance(cursor, dict) or key not in cursor:
                return False
            cursor = cursor[key]
        return True

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        from .remediation_sources import retained_source_paths
        template_paths = retained_source_paths(resource.get("_cats_source_file"), source_files)
        template_path = template_paths[0] if len(template_paths) == 1 else None
        if not template_path or "/templates/" not in "/" + template_path:
            continue
        prefix = template_path.rsplit("/templates/", 1)[0] if "/templates/" in template_path else ""
        values_path = f"{prefix}/values.yaml" if prefix else "values.yaml"
        if values_path not in source_files:
            continue
        try:
            values_document = yaml.safe_load(source_files[values_path]) or {}
        except yaml.YAMLError:
            continue
        template = source_files[template_path]
        mappings = [item for item in (resource.get("_cats_source_mappings") or []) if isinstance(item, dict)]
        from .remediation_sources import container_entries
        # A whole-template expression cannot identify one of multiple containers.
        if len(container_entries(resource)) != 1:
            continue
        # An image value is proved by evidence rather than template shape: exactly
        # one `image: {{ .Values.<key> }}` line in the template, and the value at
        # that key equals the image this container actually rendered. Conditionals
        # or other documents in the same template cannot change that proof.
        image_pattern = r"(?m)^\s*image\s*:\s*['\"]?\s*{{-?\s*\.Values\.([A-Za-z0-9_.]+)(?:\s*\|\s*(?:quote|squote))*\s*-?}}\s*['\"]?\s*$"
        image_matches = re.findall(image_pattern, template)
        rendered_image = container_entries(resource)[0][1].get("image")

        def values_value(dotted):
            cursor = values_document
            for key in dotted.split("."):
                cursor = cursor.get(key) if isinstance(cursor, dict) else None
            return cursor
        simple = not (len(re.findall(r"(?m)^kind\s*:", template)) > 1 or re.search(r"{{-?\s*(?:range|if|with)\b", template))
        # Several image lines (sidecars, CronJobs, several workloads per template)
        # are resolved only when exactly one distinct values key holds this
        # container's rendered image; reuse of that key by other workloads renders
        # the same original image, so rewriting it remains exact.
        proven = sorted({key for key in image_matches if value_exists(values_document, key)
                         and isinstance(values_value(key), str) and values_value(key) == rendered_image})
        if simple and len(image_matches) == 1 and value_exists(values_document, image_matches[0]):
            proven = [image_matches[0]]
        if len(proven) == 1:
            image_matches = proven
            if not any(
                    item.get("field_path") == "spec.template.spec.containers[].image" for item in mappings):
                mappings.append({"field_path": "spec.template.spec.containers[].image", "template": template_path,
                                 "values_file": values_path, "values_key": f".Values.{image_matches[0]}", "ambiguous": False})
                resource["_cats_source_mappings"] = mappings
        if (len(re.findall(r"(?m)^kind\s*:", template)) > 1 or
                re.search(r"{{-?\s*(?:range|if|with)\b", template)):
            continue
        for yaml_key, field_path in (
            ("allowPrivilegeEscalation", "securityContext.allowPrivilegeEscalation"),
            ("privileged", "securityContext.privileged"),
            ("readOnlyRootFilesystem", "securityContext.readOnlyRootFilesystem"),
            ("runAsNonRoot", "securityContext.runAsNonRoot"),
        ):
            pattern = rf"(?m)^\s*{re.escape(yaml_key)}\s*:\s*['\"]?\s*{{{{-?\s*\.Values\.([A-Za-z0-9_.]+)(?:\s*\|\s*(?:quote|squote))*\s*-?}}}}\s*['\"]?\s*$"
            matches = re.findall(pattern, template)
            if len(matches) == 1 and value_exists(values_document, matches[0]) and not any(
                    item.get("field_path") == field_path for item in mappings):
                mappings.append({"field_path": field_path, "template": template_path, "values_file": values_path,
                                 "values_key": f".Values.{matches[0]}", "ambiguous": False})
        for object_key, fields in (
            ("securityContext", ("allowPrivilegeEscalation", "privileged", "readOnlyRootFilesystem",
                                 "runAsNonRoot", "runAsUser", "capabilities.drop")),
            ("resources", ("requests.cpu", "requests.memory", "limits.cpu", "limits.memory")),
        ):
            # Support only a direct object expansion immediately below its key.
            pattern = (rf"(?m)^([ \t]*){object_key}\s*:\s*\n[ \t]*{{{{-?\s*toYaml\s+"
                       r"\.Values\.([A-Za-z0-9_.]+)\s*\|\s*(?:nindent|indent)\s+\d+\s*-?}}[ \t]*$")
            object_matches = list(re.finditer(pattern, template))
            if len(object_matches) != 1:
                continue
            match = object_matches[0]
            container_name = container_entries(resource)[0][1].get("name")
            preceding = template[:match.start()].splitlines()
            # Reject pod-level objects and expansions inside loops/conditionals.
            if any(re.search(r"{{-?\s*(?:range|if|with)\b", line) for line in preceding):
                continue
            parent = next((line for line in reversed(preceding) if line.strip() and
                           len(line) - len(line.lstrip()) < len(match.group(1))), "")
            if not re.fullmatch(r"\s*-\s*name:\s*" + re.escape(str(container_name)) + r"\s*", parent):
                continue
            dotted = match.group(2)
            cursor = values_document
            for key in dotted.split("."):
                cursor = cursor.get(key) if isinstance(cursor, dict) else None
            if not isinstance(cursor, dict):
                continue
            for leaf in fields:
                field_path = f"{object_key}.{leaf}"
                if not any(item.get("field_path") == field_path for item in mappings):
                    mappings.append({"field_path": field_path, "template": template_path,
                                     "values_file": values_path, "values_key": f".Values.{dotted}.{leaf}",
                                     "ambiguous": False})
        resource["_cats_source_mappings"] = mappings


def _start_public_scan(image_list: str, chart_archives: list[tuple[bytes, str]] | None = None, chart_urls: list[str] | None = None, image_archive: tuple[bytes, str] | None = None, ingest_service_id: str | None = None, job_kind: str = "scan", sbom_formats: list[str] | None = None, cyclonedx_spec_version: str = "1.5", trusted_ca_certificates: list[dict] | None = None, definition_context: dict | None = None, definition_sources: list[str] | None = None, definition_skipped: list[str] | None = None, definition_summary: dict | None = None, ingest_service_version: str = "") -> str:
    lines = [line.strip() for line in image_list.splitlines() if line.strip()]
    chart_archives = chart_archives or []
    chart_urls = [url.strip() for url in (chart_urls or []) if url.strip()]
    definition_sources = [url.strip() for url in (definition_sources or []) if url.strip()]
    if job_kind not in {"scan", "sbom"}:
        raise HTTPException(status_code=400, detail="Unsupported analysis job type")
    format_values = sbom_formats if sbom_formats is not None else (["cyclonedx-json"] if job_kind == "sbom" else ["syft-json"])
    requested_sbom_formats = list(dict.fromkeys(format_values))
    if any(format_name not in SBOM_OUTPUT_FORMATS for format_name in requested_sbom_formats):
        raise HTTPException(status_code=400, detail="Select only supported SBOM formats")
    if job_kind == "sbom" and not requested_sbom_formats:
        raise HTTPException(status_code=400, detail="Select at least one SBOM format")
    if cyclonedx_spec_version not in CYCLONEDX_SPEC_VERSIONS:
        raise HTTPException(status_code=400, detail="Unsupported CycloneDX specification version")
    if job_kind == "sbom" and (chart_archives or chart_urls):
        raise HTTPException(status_code=400, detail="SBOM generation accepts container images or image archives")
    if not lines and not chart_archives and not chart_urls and not image_archive and not definition_sources:
        detail = "Provide an image reference or image archive" if job_kind == "sbom" else "Provide an image reference, image archive, or Helm chart"
        raise HTTPException(status_code=400, detail=detail)
    if len(lines) > int(os.getenv("CATS_PUBLIC_MAX_IMAGES", "50")):
        raise HTTPException(status_code=413, detail="Too many image references")
    job_id = uuid.uuid4().hex
    job_input = PUBLIC_JOB_ROOT / job_id / "input"
    job_input.mkdir(parents=True, exist_ok=True)
    write_additive_bundle(job_input / ".cats-trust" / "ca-bundle.pem", trusted_ca_certificates)
    skipped_charts: list[str] = list(definition_skipped or [])
    for chart_url in list(dict.fromkeys(chart_urls)):
        # A repository or OCI endpoint is external evidence.  Its failure
        # must not discard otherwise usable images/charts from this scan.
        # Preserve the failed source for report-to-portal, which turns it
        # into a Missing Evidence item on authenticated ingest.
        try:
            chart_archives.extend(_download_public_chart(chart_url, trusted_ca_certificates))
        except Exception as exc:
            skipped_charts.append(_public_chart_skip_entry(chart_url, exc))
    for archive, filename in chart_archives:
        try:
            _stage_public_chart(job_input, archive, filename)
        except Exception as exc:
            skipped_charts.append(_public_chart_skip_entry(filename or "uploaded chart", exc))
    if skipped_charts:
        (job_input / "skipped_charts.txt").write_text("\n".join(skipped_charts) + "\n", encoding="utf-8")
    if image_archive:
        image_dir = job_input / "image-archives"
        image_dir.mkdir(parents=True, exist_ok=True)
        image_bytes, image_filename = image_archive
        max_bytes = int(os.getenv("CATS_PUBLIC_MAX_IMAGE_ARCHIVE_BYTES", str(2 * 1024 * 1024 * 1024)))
        if len(image_bytes) > max_bytes:
            raise HTTPException(status_code=413, detail="Docker image archive is too large")
        safe_name = Path(image_filename or "images.tar").name
        if not safe_name.lower().endswith((".tar", ".tar.gz", ".tgz")):
            raise HTTPException(status_code=400, detail="Docker image upload must be a .tar, .tar.gz, or .tgz archive")
        (image_dir / safe_name).write_bytes(image_bytes)
    with PUBLIC_JOB_LOCK:
        PUBLIC_JOBS[job_id] = {"job_id": job_id, "job_kind": job_kind, "status": "queued", "phase": "queued", "summary": {}, "skipped_charts": skipped_charts, "ingest_service_id": ingest_service_id or "", "ingest_service_version": ingest_service_version, "image_list": "\n".join(lines), "chart_url": "\n".join(chart_urls), "chart_names": [name for _, name in chart_archives], "archive_names": [name for _, name in chart_archives] + ([image_archive[1]] if image_archive else []), "sbom_formats": requested_sbom_formats, "cyclonedx_spec_version": cyclonedx_spec_version, "definition_context": definition_context or {}, "definition_summary": definition_summary or {}, "created_at": utcnow().isoformat()}
    PUBLIC_WORKERS.submit(_run_public_scan, job_id, "\n".join(lines) + "\n")
    return job_id


@app.get("/scan", response_class=HTMLResponse)
def public_scan(request: Request, job_id: str | None = None, db: Session = Depends(get_db), auth: AuthContext | None = Depends(optional_user)):
    image_list = ""
    chart_url = ""
    archive_names: list[str] = []
    ingest_service_id = ""
    ingest_service_version = ""
    if job_id:
        job_input = PUBLIC_JOB_ROOT / job_id / "input" / "images.txt"
        if job_input.exists():
            try:
                image_list = job_input.read_text(encoding="utf-8")
            except OSError:
                image_list = ""
        with PUBLIC_JOB_LOCK:
            job = PUBLIC_JOBS.get(job_id, {})
            image_list = str(job.get("image_list") or image_list)
            chart_url = str(job.get("chart_url") or "")
            archive_names = [str(name) for name in (job.get("archive_names") or [])]
            ingest_service_id = str(job.get("ingest_service_id") or "")
            ingest_service_version = str(job.get("ingest_service_version") or "")
    services = []
    if auth and auth.accessible_service_ids("scan.ingest") != set():
        scoped = auth.accessible_service_ids("scan.ingest")
        query = select(Service).order_by(Service.name)
        services = list(db.scalars(query))
        if scoped is not None:
            services = [service for service in services if service.id in scoped]
    return self_service_context(request, "scan", image_list=image_list, chart_url=chart_url, archive_names=archive_names, job_id=job_id, auth=auth, services=services, ingest_service_id=ingest_service_id, ingest_service_version=ingest_service_version)


@app.post("/scan", response_class=HTMLResponse)
async def public_scan_submit(request: Request, image_list: str = Form(""), chart_url: str = Form(""), chart_archive: UploadFile | None = File(None), ingest_service_id: str = Form(""), ingest_service_version: str = Form(""), db: Session = Depends(get_db), auth: AuthContext | None = Depends(optional_user)):
    chart_archives = []
    try:
        chart_uploads = [chart_archive] if chart_archive and chart_archive.filename else []
        # FastAPI accepts repeated chart_archive fields as a list; inspect the
        # request form as well so the HTML multi-file input remains compatible
        # with clients that submit multiple parts.
        form = await request.form()
        chart_uploads = [value for value in form.getlist("chart_archives") if hasattr(value, "read") and getattr(value, "filename", None)] or chart_uploads
        # Starlette already spools multipart files to disk. Keep that seekable
        # stream through synchronous staging instead of allocating another copy.
        chart_archives = [(upload.file, upload.filename or "chart.tgz") for upload in chart_uploads]
        image_upload = form.get("image_archive")
        image_archive = None
        if hasattr(image_upload, "read") and getattr(image_upload, "filename", None):
            image_archive = (await image_upload.read(), image_upload.filename)
        definition_sources: list[str] = []
        definition_skipped: list[str] = []
        definition_summary: dict = {}
        definition_upload = form.get("service_definition")
        if hasattr(definition_upload, "read") and getattr(definition_upload, "filename", None):
            from .service_definitions import DefinitionError, _limit, parse_definition
            from .definition_routes import acquire_component
            filename = (definition_upload.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
            if not filename.lower().endswith((".yaml", ".yml")) or len(filename) > 240:
                raise HTTPException(status_code=422, detail="Upload a YAML or YML service definition")
            try:
                limit = _limit("BYTES", 10 * 1024 * 1024)
            except DefinitionError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from None
            raw = await definition_upload.read(limit + 1)
            if len(raw) > limit:
                raise HTTPException(status_code=413, detail="Service definition exceeds byte limit")
            try:
                parsed = parse_definition(raw.decode("utf-8-sig"), "auto")
            except UnicodeDecodeError:
                raise HTTPException(status_code=422, detail="Service definition must be UTF-8") from None
            except DefinitionError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from None
            definition_summary = {"filename": filename, "adapter": parsed["adapter"], "counts": parsed["counts"]}
        if ingest_service_id:
            if not auth or auth.accessible_service_ids("scan.ingest") == set():
                raise HTTPException(status_code=403, detail="Sign in with scan-ingest permission to select a service")
            service = db.scalar(select(Service).where(Service.service_key == ingest_service_id))
            if not service:
                raise HTTPException(status_code=404, detail="Selected service was not found")
            if not auth.has("scan.ingest", service.id):
                raise HTTPException(status_code=403, detail="Selected service is outside your scope")
            ingest_service_version = ingest_service_version.strip()
            if not ingest_service_version:
                current = db.get(ServiceVersion, service.current_version_id) if service.current_version_id else None
                ingest_service_version = current.version if current else (service.manual_version or "").strip()
            if not ingest_service_version or len(ingest_service_version) > 120 or any(ord(char) < 32 or ord(char) == 127 for char in ingest_service_version):
                raise HTTPException(status_code=422, detail="Choose or enter a valid service version before ingesting")
        trusted_cas = parse_json(get_global_configuration(db).get("trusted_ca_certificates"), [])
        trusted_cas = trusted_cas if isinstance(trusted_cas, list) else []
        if definition_summary:
            for component in parsed["components"]:
                if component["status"] != "normalized":
                    definition_skipped.append(_public_chart_skip_entry(component["logical_name"], component["reason"]))
                    continue
                try:
                    source_url, _, _, _, acquired_archives = acquire_component(component, trusted_cas)
                    definition_sources.append(source_url)
                    chart_archives.extend(acquired_archives)
                except Exception as exc:
                    definition_skipped.append(_public_chart_skip_entry(component["logical_name"], exc))
            if not definition_sources and not image_list.strip() and not image_archive and not chart_archives and not chart_url.strip():
                failures = "; ".join(definition_skipped[:3])
                if len(definition_skipped) > 3:
                    failures += f"; and {len(definition_skipped) - 3} more"
                raise HTTPException(status_code=422, detail=f"No service-definition components could be acquired. {failures}")
        job_id = _start_public_scan(image_list, chart_archives, chart_url.splitlines(), image_archive, ingest_service_id or None,
                                    trusted_ca_certificates=trusted_cas, definition_sources=definition_sources,
                                    definition_skipped=definition_skipped, definition_summary=definition_summary,
                                    ingest_service_version=ingest_service_version)
    except HTTPException as exc:
        scoped = auth.accessible_service_ids("scan.ingest") if auth else set()
        services = list(db.scalars(select(Service).order_by(Service.name))) if scoped != set() else []
        if scoped is not None:
            services = [service for service in services if service.id in scoped]
        return self_service_context(request, "scan", image_list, chart_url, str(exc.detail), auth=auth,
                                    services=services, ingest_service_id=ingest_service_id,
                                    ingest_service_version=ingest_service_version)
    finally:
        close_downloads(chart_archives)
    # Redirect after a successful submission so refreshing the browser only
    # reloads the existing job rather than replaying the POST and starting a
    # second scan.
    return RedirectResponse(url=f"/scan?job_id={urllib.parse.quote(job_id)}", status_code=303)


@app.get("/sbom", response_class=HTMLResponse)
def public_sbom(request: Request, job_id: str | None = None, auth: AuthContext | None = Depends(optional_user)):
    image_list = ""
    archive_names: list[str] = []
    formats = ["cyclonedx-json"]
    spec_version = "1.5"
    if job_id:
        with PUBLIC_JOB_LOCK:
            job = dict(PUBLIC_JOBS.get(job_id, {}))
        image_list = str(job.get("image_list") or "")
        archive_names = [str(name) for name in (job.get("archive_names") or [])]
        formats = [str(value) for value in (job.get("sbom_formats") or formats)]
        spec_version = str(job.get("cyclonedx_spec_version") or spec_version)
    return self_service_context(
        request, "sbom", image_list=image_list, archive_names=archive_names,
        job_id=job_id, auth=auth, sbom_formats=formats,
        cyclonedx_spec_version=spec_version,
    )


@app.post("/sbom", response_class=HTMLResponse)
async def public_sbom_submit(
    request: Request,
    image_list: str = Form(""),
    auth: AuthContext | None = Depends(optional_user),
):
    form = await request.form()
    formats = [str(value).strip() for value in form.getlist("sbom_formats") if str(value).strip()]
    spec_version = str(form.get("cyclonedx_spec_version") or "1.5").strip()
    image_upload = form.get("image_archive")
    image_archive = None
    if hasattr(image_upload, "read") and getattr(image_upload, "filename", None):
        image_archive = (await image_upload.read(), image_upload.filename)
    try:
        job_id = _start_public_scan(
            image_list,
            image_archive=image_archive,
            job_kind="sbom",
            sbom_formats=formats,
            cyclonedx_spec_version=spec_version,
        )
    except HTTPException as exc:
        return self_service_context(
            request, "sbom", image_list=image_list, status_message=str(exc.detail),
            auth=auth, sbom_formats=formats, cyclonedx_spec_version=spec_version,
        )
    return RedirectResponse(url=f"/sbom?job_id={urllib.parse.quote(job_id)}", status_code=303)


@app.post("/api/public/jobs")
def create_public_scan_job(payload: dict, db: Session = Depends(get_db)):
    chart_urls = payload.get("chart_urls") or ([payload.get("chart_url")] if payload.get("chart_url") else [])
    trusted_cas = parse_json(get_global_configuration(db).get("trusted_ca_certificates"), [])
    job_id = _start_public_scan(str(payload.get("images", "")), chart_urls=[str(value) for value in chart_urls],
                                trusted_ca_certificates=trusted_cas if isinstance(trusted_cas, list) else [])
    return {"job_id": job_id, "status_url": f"/api/public/jobs/{job_id}", "results_url": f"/api/public/jobs/{job_id}/results"}


@app.get("/api/public/jobs/{job_id}")
def public_scan_job_status(job_id: str):
    with PUBLIC_JOB_LOCK:
        job = dict(PUBLIC_JOBS.get(job_id, {}))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired")
    return job


@app.post("/api/public/jobs/{job_id}/cancel")
def cancel_public_scan_job(job_id: str):
    with PUBLIC_JOB_LOCK:
        job = PUBLIC_JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found or expired")
        if job.get("status") in {"complete", "incomplete", "error", "cancelled"}:
            return {"job_id": job_id, "status": job.get("status")}
        process = PUBLIC_PROCESSES.get(job_id)
    _public_job_update(job_id, status="cancelled", phase="cancelled")
    if process and process.poll() is None:
        process.terminate()
    return {"job_id": job_id, "status": "cancelled"}


@app.get("/api/public/jobs/{job_id}/results")
def public_scan_job_results(job_id: str):
    with PUBLIC_JOB_LOCK:
        job = dict(PUBLIC_JOBS.get(job_id, {}))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired")
    summary_path = PUBLIC_JOB_ROOT / job_id / "output" / "scan-summary.json"
    if summary_path.exists():
        try:
            return {**job, "summary": json.loads(summary_path.read_text(encoding="utf-8"))}
        except (ValueError, OSError):
            pass
    return job


@app.get("/api/public/jobs/{job_id}/results/view", response_class=HTMLResponse)
def public_scan_job_results_view(request: Request, job_id: str):
    """Render ephemeral results in a read-only, portal-style view.

    Public scans intentionally bypass the authenticated service view: there is
    no service record, policy gating, exception state, or action endpoint to
    mutate.  The page therefore displays the raw vulnerability payload and
    configuration findings without Request Exception/POA&M/Mitigation buttons.
    """
    with PUBLIC_JOB_LOCK:
        job = dict(PUBLIC_JOBS.get(job_id, {}))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired")
    output_dir = PUBLIC_JOB_ROOT / job_id / "output"
    result_path = output_dir / "portal-result.json"
    if not result_path.exists():
        raise HTTPException(status_code=409, detail="Scan results are not available yet")
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="Scan results are invalid") from exc
    # Public jobs can be interrupted between result fragments.  Treat a
    # malformed fragment as an empty section so the human-readable view stays
    # usable and never turns a partial scan into an unhandled 500.
    if not isinstance(payload, dict):
        payload = {}
    service = payload.get("service") if isinstance(payload.get("service"), dict) else {}
    overview_data = dict(payload.get("service_overview") or {})
    overview_path = output_dir / "service-overview.json"
    if overview_path.exists():
        try:
            candidate = json.loads(overview_path.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                overview_data.update(candidate)
        except (OSError, ValueError):
            pass
    vulnerabilities = [item for item in (payload.get("findings") or []) if isinstance(item, dict)]
    configurations = [item for item in (payload.get("policy_findings") or []) if isinstance(item, dict)]
    skipped_images = payload.get("skipped_images") or []
    skipped_charts = payload.get("skipped_charts") or []
    if not isinstance(skipped_images, list):
        skipped_images = [skipped_images]
    if not isinstance(skipped_charts, list):
        skipped_charts = [skipped_charts]
    overview_data.setdefault("source", "Helm rendered manifests" if overview_data else "Submitted scan evidence")
    overview_data.setdefault("description", service.get("description"))
    overview_data = normalize_overview(
        overview_data,
        skipped_images=skipped_images,
        skipped_charts=skipped_charts,
        findings_images=[{"image": item.get("image"), "digest": item.get("image_digest"), "discovered_from": item.get("discovered_from") or "Submitted"} for item in vulnerabilities if item.get("image")],
        submitted_charts=job.get("chart_names") or [],
        incomplete=job.get("status") == "incomplete",
        # Rendering must remain read-only and fast.  Digest enrichment is
        # performed by scan processing and persisted in service-overview.json;
        # never invoke Docker/registry lookups from this request path.
        digest_resolver=None,
    )
    rows = []
    for item in vulnerabilities:
        rows.append({
            "type": "Vulnerability", "finding": item.get("cve") or item.get("finding") or "Unknown",
            "title": "", "severity": item.get("severity") or "Unknown", "state": "Raw",
            "scanner": item.get("scanner") or "Grype",
            "image": item.get("image") or "—", "target": item.get("package") or "—",
            "details": (item.get("evidence") or {}).get("description") or "",
            "remediation": item.get("fixed_version") or "—",
            "kev": "Yes" if item.get("kev") else "No", "epss": item.get("epss"),
        })
    for item in configurations:
        rows.append({
            "type": "Configuration", "finding": item.get("finding") or "Unknown",
            "title": item.get("title") or "", "severity": item.get("severity") or "Unknown", "state": "Raw",
            "scanner": item.get("scanner") or ("Dockle" if str(item.get("framework") or "").lower().startswith("docker") else "Trivy"),
            "image": item.get("target") or "—", "target": item.get("framework") or "—",
            "details": item.get("description") or "", "remediation": item.get("remediation") or "—",
            "kev": "—", "epss": "—",
        })
    grouped = {}
    simplified_rows = []
    for index, item in enumerate(rows):
        key = (item["type"], item["image"], item["severity"], item["remediation"], item["scanner"])
        if key not in grouped:
            grouped[key] = {**item, "finding_ids": [item["finding"]], "finding_indices": [index], "count": 1}
            simplified_rows.append(grouped[key])
        else:
            # A CVE can occur in several packages/images. Show it once in the
            # simplified row while retaining the first detail record for the
            # clickable finding link.
            if item["finding"] not in grouped[key]["finding_ids"]:
                grouped[key]["finding_ids"].append(item["finding"])
                grouped[key]["finding_indices"].append(index)
                grouped[key]["count"] += 1
    return templates.TemplateResponse(request, "public_results.html", {
        "current_user": None, "csrf_token": "", "can": lambda *_permission: False,
        "themes": THEMES, "pending_request_count": 0, "pending_poam_count": 0,
        "job": job, "service": service, "view": {"service": {"id": None, "service_key": ""}},
        "service_images": [], "rows": rows, "simplified_rows": simplified_rows,
        "vulnerability_count": len(vulnerabilities), "configuration_count": len(configurations),
        "overview_data": overview_data, "skipped_images": skipped_images, "skipped_charts": skipped_charts,
    })


@app.get("/api/public/jobs/{job_id}/logs", response_class=PlainTextResponse)
def public_scan_job_logs(job_id: str):
    with PUBLIC_JOB_LOCK:
        if job_id not in PUBLIC_JOBS:
            raise HTTPException(status_code=404, detail="Job not found or expired")
    log_path = PUBLIC_JOB_ROOT / job_id / "output" / "worker.log"
    if not log_path.exists():
        return "The worker has not produced a log yet."
    return log_path.read_text(encoding="utf-8", errors="replace")


def _write_public_scan_workbook(output_dir: Path, workbook_path: Path) -> None:
    """Create an Excel export for an ephemeral scan using portal-style sheets."""
    result_path = output_dir / "portal-result.json"
    payload = {}
    if result_path.exists():
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
    findings = [item for item in (payload.get("findings") or []) if isinstance(item, dict)]
    policy_findings = [item for item in (payload.get("policy_findings") or []) if isinstance(item, dict)]
    service = payload.get("service") if isinstance(payload.get("service"), dict) else {}
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    summary.append(["Field", "Value"])
    summary_rows = [
        ("Service ID", service.get("id") or "Standalone scan"),
        ("Service", service.get("name") or "Standalone scan"),
        ("Version", service.get("version") or "Not provided"),
        ("Owner", service.get("owner") or "Not provided"),
        ("Active Findings", len(findings) + len(policy_findings)),
        ("Vulnerability Findings", len(findings)),
        ("Configuration Findings", len(policy_findings)),
        ("Evidence", "Complete" if payload.get("complete") else "Incomplete"),
        ("Exported At", excel_datetime(utcnow())),
    ]
    for row in summary_rows:
        summary.append(list(row))
    format_sheet(summary)

    vuln = workbook.create_sheet("Findings")
    vuln.append(["Finding", "Severity", "Image", "Package", "Installed Version", "Fixed Version", "Description", "References"])
    for item in findings:
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        vuln.append([
            item.get("cve") or item.get("finding"), item.get("severity"), item.get("image"),
            item.get("package"), item.get("installed_version"), item.get("fixed_version"),
            evidence.get("description"), "\n".join(evidence.get("urls") or []),
        ])
    format_sheet(vuln)

    config = workbook.create_sheet("Configuration Findings")
    config.append(["Finding", "Title", "Severity", "Framework", "Target", "Namespace", "Description", "Remediation"])
    for item in policy_findings:
        config.append([
            item.get("finding"), item.get("title"), item.get("severity"), item.get("framework"),
            item.get("target"), item.get("namespace"), item.get("description"), item.get("remediation"),
        ])
    format_sheet(config)
    workbook.save(workbook_path)


def _write_public_scan_html(output_dir: Path, report_path: Path, job: dict) -> None:
    payload = {}
    result_path = output_dir / "portal-result.json"
    if result_path.exists():
        try:
            candidate = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                payload = candidate
        except (OSError, ValueError):
            payload = {}
    output_root = output_dir.resolve()
    report_target = report_path.resolve()
    artifacts = []
    for path in sorted(output_dir.rglob("*")):
        try:
            resolved = path.resolve()
            if not path.is_file() or resolved == report_target or not resolved.is_relative_to(output_root):
                continue
            artifacts.append({
                "path": resolved.relative_to(output_root).as_posix(),
                "size": resolved.stat().st_size,
            })
        except OSError:
            continue
    report_path.write_text(build_public_scan_report(payload, job, artifacts), encoding="utf-8")


@app.get("/api/public/jobs/{job_id}/overview.html", response_class=HTMLResponse)
def public_scan_job_html_overview(job_id: str):
    with PUBLIC_JOB_LOCK:
        job = dict(PUBLIC_JOBS.get(job_id, {}))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or expired")
    output_dir = PUBLIC_JOB_ROOT / job_id / "output"
    if not (output_dir / "portal-result.json").exists():
        raise HTTPException(status_code=409, detail="Scan results are not available yet")
    _write_public_scan_workbook(output_dir, output_dir / "scan-results.xlsx")
    report_path = output_dir / "scan-overview.html"
    _write_public_scan_html(output_dir, report_path, job)
    return HTMLResponse(report_path.read_text(encoding="utf-8"))


@app.get("/api/public/jobs/{job_id}/artifacts")
def public_scan_job_artifacts(job_id: str):
    with PUBLIC_JOB_LOCK:
        job = dict(PUBLIC_JOBS.get(job_id, {}))
        if not job:
            raise HTTPException(status_code=404, detail="Job not found or expired")
    output_dir = PUBLIC_JOB_ROOT / job_id / "output"
    if not output_dir.exists():
        raise HTTPException(status_code=409, detail="Job has not produced results yet")
    # Keep the self-service download useful even without a persistent service:
    # materialize the same workbook-style export used by the authenticated UI.
    _write_public_scan_workbook(output_dir, output_dir / "scan-results.xlsx")
    _write_public_scan_html(output_dir, output_dir / "scan-overview.html", job)
    archive = PUBLIC_JOB_ROOT / f"{job_id}.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        for path in output_dir.rglob("*"):
            if path.is_file():
                bundle.write(path, path.relative_to(output_dir))
    return StreamingResponse(open(archive, "rb"), media_type="application/zip", headers={"Content-Disposition": f"attachment; filename={job_id}-results.zip"})


@app.get("/api/public/jobs/{job_id}/sboms")
def public_sbom_job_artifacts(job_id: str):
    """Download only the SBOM formats recorded by the serializer manifest."""
    with PUBLIC_JOB_LOCK:
        if job_id not in PUBLIC_JOBS:
            raise HTTPException(status_code=404, detail="Job not found or expired")
    output_dir = PUBLIC_JOB_ROOT / job_id / "output"
    manifest_path = output_dir / "sboms" / "formats" / "manifest.json"
    if not manifest_path.exists():
        raise HTTPException(status_code=409, detail="SBOM documents are not available yet")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail="SBOM manifest is invalid") from exc
    reports = manifest.get("reports") if isinstance(manifest, dict) else None
    if not isinstance(reports, list) or not reports:
        raise HTTPException(status_code=409, detail="No SBOM documents were generated")

    output_root = output_dir.resolve()
    archive = PUBLIC_JOB_ROOT / f"{job_id}-sboms.zip"
    written: set[str] = set()
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        bundle.write(manifest_path, "manifest.json")
        for report in reports:
            if not isinstance(report, dict) or not report.get("path"):
                continue
            relative = Path(str(report["path"]).replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts:
                continue
            candidate = (output_dir / relative).resolve()
            if not candidate.is_relative_to(output_root) or not candidate.is_file():
                continue
            archive_name = candidate.relative_to(output_root).as_posix()
            if archive_name not in written:
                bundle.write(candidate, archive_name)
                written.add(archive_name)
    if not written:
        archive.unlink(missing_ok=True)
        raise HTTPException(status_code=409, detail="Generated SBOM documents are missing")
    return FileResponse(archive, media_type="application/zip", filename=f"{job_id}-sboms.zip")


@app.get("/api/public/jobs/{job_id}/export.xlsx")
def public_scan_job_export(job_id: str):
    with PUBLIC_JOB_LOCK:
        if job_id not in PUBLIC_JOBS:
            raise HTTPException(status_code=404, detail="Job not found or expired")
    output_dir = PUBLIC_JOB_ROOT / job_id / "output"
    if not output_dir.exists():
        raise HTTPException(status_code=409, detail="Job has not produced results yet")
    workbook_path = output_dir / "scan-results.xlsx"
    _write_public_scan_workbook(output_dir, workbook_path)
    return FileResponse(
        workbook_path,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=f"{job_id}-scan-results.xlsx",
    )


@app.get("/api/public/jobs/{job_id}/results-export")
def public_scan_job_results_export(job_id: str):
    """Download the native scanner JSON bundle for manual ingestion."""
    with PUBLIC_JOB_LOCK:
        if job_id not in PUBLIC_JOBS:
            raise HTTPException(status_code=404, detail="Job not found or expired")
    archive = PUBLIC_JOB_ROOT / job_id / "output" / "results-export.tar.gz"
    if not archive.exists():
        raise HTTPException(status_code=409, detail="Scanner results export is not available yet")
    return FileResponse(archive, media_type="application/gzip", filename=f"{job_id}-results.tar.gz")


@app.post("/api/public/jobs/{job_id}/ingest")
def ingest_public_scan(
    job_id: str,
    service_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_user),
):
    """Attach an ephemeral scan to an existing service after login.

    A service selection on the authenticated scan form invokes this endpoint
    automatically after the temporary scan completes. It still requires an
    authenticated service administrator and an existing in-scope service, so
    a public request cannot create or overwrite portal scope by itself.
    """
    if auth.accessible_service_ids("scan.ingest") == set():
        raise HTTPException(status_code=403, detail="Scan ingest permission is required")
    with PUBLIC_JOB_LOCK:
        if job_id not in PUBLIC_JOBS:
            raise HTTPException(status_code=404, detail="Job not found or expired")
    result_path = PUBLIC_JOB_ROOT / job_id / "output" / "portal-result.json"
    if (result_path.parent / "scan-failure.json").exists():
        raise HTTPException(status_code=409, detail="A required scanner phase failed; this scan cannot be ingested. Review the retained scan logs.")
    if not result_path.exists():
        raise HTTPException(status_code=409, detail="The scan has not produced a portal result")
    service = db.scalar(select(Service).where(Service.service_key == service_id))
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    if not auth.has("scan.ingest", service.id):
        raise HTTPException(status_code=403, detail="The service is outside your scope")
    ingest_started = time.perf_counter()
    stage_started = ingest_started
    ingest_stage = "read_result"
    stage_timings: dict[str, float] = {}
    ingest_logger = logging.getLogger("cats.public_ingest")
    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
        # Use the same overview source as the Scan results page. Keep all
        # embedded sections when the companion file only supplies some fields.
        overview_path = result_path.parent / "service-overview.json"
        if overview_path.exists():
            overview = json.loads(overview_path.read_text(encoding="utf-8"))
            if isinstance(overview, dict):
                data["service_overview"] = {**(data.get("service_overview") or {}), **overview}
        stage_timings[ingest_stage] = round((time.perf_counter() - stage_started) * 1000, 2)
        ingest_stage = "normalize_result"; stage_started = time.perf_counter()
        # Public scans may include raw (non-fixable) vulnerabilities for
        # display, but the authenticated portal ingest contract stores only
        # actionable findings. Keep skipped evidence and policy findings
        # intact while normalizing the vulnerability list for ingest.
        data["findings"] = [
            item
            for item in (data.get("findings") or [])
            if isinstance(item, dict)
            and str(item.get("fixed_version") or "").strip() not in {"", "—", "-"}
        ]
        data["fixable_only"] = True
        data["execution_id"] = f"public:{job_id}"
        with PUBLIC_JOB_LOCK:
            definition_context = dict(PUBLIC_JOBS.get(job_id, {}).get("definition_context") or {})
        if definition_context:
            data["scan_scope"] = "evidence"
            data["complete"] = False
            overview = data.get("service_overview") if isinstance(data.get("service_overview"), dict) else {}
            overview["definition_provenance"] = definition_context
            data["service_overview"] = overview
        stage_timings[ingest_stage] = round((time.perf_counter() - stage_started) * 1000, 2)
        ingest_stage = "collect_helm_sources"; stage_started = time.perf_counter()
        source_files = _collect_helm_source_files(PUBLIC_JOB_ROOT / job_id / "input" / "charts")
        _enrich_rendered_resource_lineage(data)
        if source_files:
            data["artifact_type"] = "helm"
            data["helm_source_files"] = source_files
            _enrich_values_source_mappings(data, source_files)
        stage_timings[ingest_stage] = round((time.perf_counter() - stage_started) * 1000, 2)
        ingest_stage = "bind_service"; stage_started = time.perf_counter()
        with PUBLIC_JOB_LOCK:
            job_input_images = [line.strip() for line in str(PUBLIC_JOBS.get(job_id, {}).get("image_list") or "").splitlines() if line.strip()]
            selected_service_version = str(PUBLIC_JOBS.get(job_id, {}).get("ingest_service_version") or "").strip()
        candidate_images = {
            str(item.get("image") or "").strip()
            for item in (data.get("findings") or [])
            if isinstance(item, dict) and str(item.get("image") or "").strip()
        }
        # A one-image public scan is authoritative only for that image. A
        # multi-image result remains a service-scope execution unless its
        # producer explicitly supplied a scope.
        if data.get("scan_scope") not in {"service", "image", "evidence"}:
            data["scan_scope"] = "service"
        if not candidate_images and len(job_input_images) == 1:
            candidate_images = set(job_input_images)
        if data.get("scan_scope") == "service" and len(candidate_images) == 1 and not data.get("skipped_images") and not data.get("skipped_charts"):
            data["scan_scope"] = "image"
            data["scope_image"] = next(iter(candidate_images))
        data["service"] = {
            **data.get("service", {}),
            "id": service.service_key,
            "name": service.name,
            "version": (
                selected_service_version
                or (service.current_version.version if service.current_version else "")
                or service.manual_version
                or data.get("service", {}).get("version")
                or "Unversioned"
            ),
            "owner": service.owner,
            "poc": service.poc,
            "groups": [group.name for group in service.groups],
        }
        stage_timings[ingest_stage] = round((time.perf_counter() - stage_started) * 1000, 2)
        ingest_stage = "validate_payload"; stage_started = time.perf_counter()
        payload = ExecutionPayload.model_validate(data)
        stage_timings[ingest_stage] = round((time.perf_counter() - stage_started) * 1000, 2)
    except ValidationError as exc:
        db.rollback()
        error = exc.errors(include_url=False, include_input=False)[0] if exc.errors() else {}
        location = ".".join(str(part) for part in error.get("loc", ())) or "payload"
        detail = {
            "code": "PUBLIC_INGEST_VALIDATION_ERROR", "stage": ingest_stage,
            "error_type": str(error.get("type") or "validation_error"),
            "record": location, "message": str(error.get("msg") or "Invalid scan result"),
        }
        ingest_logger.warning("public_scan_ingest_failed job_id=%s service_id=%s stage=%s code=%s type=%s record=%s elapsed_ms=%.2f",
            job_id, service_id, ingest_stage, detail["code"], detail["error_type"], location,
            round((time.perf_counter() - ingest_started) * 1000, 2), extra={
            "job_id": job_id, "service_id": service_id, "ingest_stage": ingest_stage,
            "error_code": detail["code"], "error_type": detail["error_type"],
            "record_identifier": location, "elapsed_ms": round((time.perf_counter() - ingest_started) * 1000, 2),
            "stage_timings_ms": stage_timings,
        })
        raise HTTPException(status_code=422, detail=detail) from exc
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        db.rollback()
        detail = {"code": "PUBLIC_INGEST_INVALID_RESULT", "stage": ingest_stage,
                  "error_type": type(exc).__name__, "record": str(result_path.name),
                  "message": "The completed scan result could not be read safely."}
        ingest_logger.warning("public_scan_ingest_failed job_id=%s service_id=%s stage=%s code=%s type=%s record=%s elapsed_ms=%.2f",
            job_id, service_id, ingest_stage, detail["code"], type(exc).__name__, result_path.name,
            round((time.perf_counter() - ingest_started) * 1000, 2), extra={
            "job_id": job_id, "service_id": service_id, "ingest_stage": ingest_stage,
            "error_code": detail["code"], "error_type": type(exc).__name__,
            "record_identifier": str(result_path.name), "elapsed_ms": round((time.perf_counter() - ingest_started) * 1000, 2),
            "stage_timings_ms": stage_timings,
        })
        raise HTTPException(status_code=422, detail=detail) from exc
    ingest_stage = "database_ingest"; stage_started = time.perf_counter()
    try:
        response = ingest(payload, db)
    except Exception as exc:
        db.rollback()
        code = f"HTTP_{exc.status_code}" if isinstance(exc, HTTPException) else "PUBLIC_INGEST_DATABASE_ERROR"
        ingest_logger.exception("public_scan_ingest_failed job_id=%s service_id=%s stage=%s code=%s type=%s record=%s elapsed_ms=%.2f",
            job_id, service_id, ingest_stage, code, type(exc).__name__, payload.execution_id,
            round((time.perf_counter() - ingest_started) * 1000, 2), extra={
            "job_id": job_id, "service_id": service_id, "ingest_stage": ingest_stage,
            "error_code": code, "error_type": type(exc).__name__,
            "record_identifier": payload.execution_id,
            "elapsed_ms": round((time.perf_counter() - ingest_started) * 1000, 2), "stage_timings_ms": stage_timings,
        })
        raise
    stage_timings[ingest_stage] = round((time.perf_counter() - stage_started) * 1000, 2)
    stage_timings["total"] = round((time.perf_counter() - ingest_started) * 1000, 2)
    ingest_logger.info("public_scan_ingest_complete job_id=%s service_id=%s stage=complete record=%s elapsed_ms=%.2f findings=%d policy=%d helm_sources=%d",
        job_id, service_id, payload.execution_id, stage_timings["total"], len(payload.findings),
        len(payload.policy_findings), len(payload.helm_source_files), extra={
        "job_id": job_id, "service_id": service_id, "ingest_stage": "complete",
        "error_code": None, "error_type": None, "record_identifier": payload.execution_id,
        "elapsed_ms": stage_timings["total"], "stage_timings_ms": stage_timings,
        "finding_count": len(payload.findings), "policy_finding_count": len(payload.policy_findings),
        "helm_source_file_count": len(payload.helm_source_files),
    })
    return {**response, "ingest_timings_ms": stage_timings}


def _enforce_required_signature(current: dict, values: dict) -> None:
    if current.get("signing_enabled") and values.get("status") == "complete":
        result = values.get("result") if "result" in values else current.get("result")
        if result is None and "result" not in values:
            # Completion and the result can arrive in separate polls.
            values.update(status="running", phase="signing_image")
        else:
            result = result if isinstance(result, dict) else {}
            signature = result.get("signature")
            signature = signature if isinstance(signature, dict) else {}
            verified = result.get("signature_status") == "verified"
            verified = verified and signature.get("image") == result.get("immutable_destination") and bool(signature.get("image"))
            verified = verified and signature.get("key_fingerprint") == current.get("signing_fingerprint")
            if not verified:
                message = "Required signature verification was not reported by the patch worker. Upgrade both portal and worker and check signing configuration."
                values.update(status="failed", phase="signing_image", error=message,
                              failed_stage="signing_image",
                              stages=advance_patch_stages(values.get("stages") or current.get("stages"), "signing_image", "failed", "push"),
                              result={**result, "status": "failed", "delivery_status": "failed", "delivery_error": message, "signature_status": "failed"})


def _patch_job_update(job_id: str, **values):
    snapshot = None
    with PATCH_JOB_LOCK:
        if job_id in PATCH_JOBS:
            current = PATCH_JOBS[job_id]
            _enforce_required_signature(current, values)
            _stamp_job_transition(current, values, {"complete", "failed", "cancelled"})
            phase = values.get("phase") or current.get("phase")
            status = values.get("status") or current.get("status")
            if phase in PATCH_PHASES and status in {"running", "complete", "failed"}:
                values["stages"] = advance_patch_stages(
                    values.get("stages") or current.get("stages"), phase, status,
                    values.get("output_mode") or current.get("output_mode") or "download",
                )
                if status == "failed":
                    values.setdefault("failed_stage", phase)
            PATCH_JOBS[job_id].update(values)
            snapshot = dict(PATCH_JOBS[job_id])
    if snapshot:
        job_root = PATCH_JOB_ROOT / job_id
        job_root.mkdir(parents=True, exist_ok=True)
        temp = job_root / "public-job.json.tmp"
        temp.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        temp.replace(job_root / "public-job.json")
    if snapshot and snapshot.get("patch_execution_id"):
        with SessionLocal() as db:
            record = db.get(PatchExecution, int(snapshot["patch_execution_id"]))
            if record:
                record.status = str(snapshot.get("status") or record.status)
                record.phase = str(snapshot.get("phase") or record.phase)
                record.error = str(snapshot.get("error"))[:4000] if snapshot.get("error") else None
                result = snapshot.get("result") or {}
                summary = result if isinstance(result, dict) else {}
                record.summary = {
                    key: value for key, value in summary.items()
                    if key in {
                        "vulnerabilities_before", "vulnerabilities_after",
                        "vulnerabilities_removed", "vulnerabilities_remaining",
                        "could_not_be_patched", "patched_image", "destination_image",
                        "patch_status", "reason", "image_changed", "delivery_status", "delivery_error",
                        "immutable_destination", "signature_status", "signature", "artifact_sha256",
                        "stages", "failed_stage",
                    }
                }
                if snapshot.get("stages"):
                    record.summary["stages"] = snapshot["stages"]
                if snapshot.get("failed_stage"):
                    record.summary["failed_stage"] = snapshot["failed_stage"]
                if result and record.status == "complete" and str(result.get("patch_status") or "") in {"PATCHED", "PARTIALLY_PATCHED", "NO_APPLICABLE_FIXES"}:
                    associated_ref = str(result.get("destination_image") or result.get("patched_image") or "").strip()
                    service = db.get(Service, record.service_id)
                    if service and associated_ref:
                        _ensure_service_image(db, service, associated_ref)
                        existing_audit = db.scalar(select(func.count(AuditEvent.id)).where(
                            AuditEvent.action == "patch.completed", AuditEvent.target_id == str(record.id)
                        ))
                        if not existing_audit:
                            db.add(AuditEvent(actor_user_id=record.requested_by_id, action="patch.completed", target_type="patch_execution", target_id=str(record.id), detail={"service_id": record.service_id, "image": associated_ref, "patch_status": result.get("patch_status")}))
                audit_action = None
                if record.status == "failed":
                    audit_action = "patch.failed"
                elif result and record.status == "complete":
                    patch_status = str(result.get("patch_status") or "")
                    audit_action = {
                        "FAILED": "patch.failed",
                        "UNSUPPORTED": "patch.unsupported",
                    }.get(patch_status)
                if audit_action:
                    existing_audit = db.scalar(select(func.count(AuditEvent.id)).where(
                        AuditEvent.action == audit_action, AuditEvent.target_id == str(record.id)
                    ))
                    if not existing_audit:
                        db.add(AuditEvent(
                            actor_user_id=record.requested_by_id, action=audit_action,
                            target_type="patch_execution", target_id=str(record.id),
                            detail={"service_id": record.service_id, "reason": (result or {}).get("reason") or record.error},
                        ))
                if result and record.status == "complete" and str(result.get("output_mode") or "") == "push":
                    delivery_status = str(result.get("delivery_status") or "")
                    delivery_action = {
                        "delivered": "oci.publication.succeeded",
                        "failed": "oci.publication.failed",
                    }.get(delivery_status)
                    if delivery_action:
                        existing_audit = db.scalar(select(func.count(AuditEvent.id)).where(
                            AuditEvent.action == delivery_action, AuditEvent.target_id == str(record.id)
                        ))
                        if not existing_audit:
                            db.add(AuditEvent(
                                actor_user_id=record.requested_by_id, action=delivery_action,
                                target_type="patch_execution", target_id=str(record.id),
                                detail={"service_id": record.service_id, "destination_image": result.get("destination_image"),
                                        "error": result.get("delivery_error")},
                            ))
                record.updated_at = utcnow()
                if record.status in {"complete", "failed", "cancelled"} and not record.completed_at:
                    record.completed_at = utcnow()
                db.commit()


    if snapshot and (snapshot.get("status") in {"failed", "cancelled"} or (snapshot.get("status") == "complete" and snapshot.get("result"))):
        with SessionLocal() as db:
            requested = db.scalar(select(AuditEvent).where(AuditEvent.action == "signing.requested", AuditEvent.target_type == "patch_job", AuditEvent.target_id == job_id))
            if requested:
                result = snapshot.get("result") or {}
                action = "signing.verified" if result.get("signature_status") == "verified" else "signing.failed"
                exists = db.scalar(select(AuditEvent.id).where(AuditEvent.action.in_(["signing.verified", "signing.failed"]), AuditEvent.target_type == "patch_job", AuditEvent.target_id == job_id))
                if not exists:
                    db.add(AuditEvent(actor_user_id=requested.actor_user_id, action=action, target_type="patch_job", target_id=job_id,
                                      detail={"image": result.get("immutable_destination"), "signature": result.get("signature"),
                                              "key_fingerprint": requested.detail.get("key_fingerprint"), "job_status": snapshot.get("status")}))
                    db.commit()


def _portal_signing_material(db: Session, auth: AuthContext | None, output_mode: str, service: Service | None = None):
    settings = get_global_configuration(db)
    try:
        if output_mode == "push" and signing.configuration(settings).get("enabled") is True:
            if not auth or not auth.user.enabled or not auth.has("artifact.sign", service.id if service else None):
                raise HTTPException(status_code=403, detail="Sign in with image-signing permission to publish using the configured key")
        return signing.job_material(settings, output_mode)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _audit_signing_request(db: Session, job_id: str, actor_id: int, config: dict):
    if config.get("signing_enabled"):
        db.add(AuditEvent(actor_user_id=actor_id, action="signing.requested", target_type="patch_job", target_id=job_id,
                          detail={"destination": config.get("destination_image"), "key_fingerprint": config["signing_fingerprint"]}))
        db.commit()


def _load_patch_job(job_id: str) -> dict:
    """Load a nonsensitive patch snapshot from memory and durable job files."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(job_id or "")):
        return {}
    job_root = PATCH_JOB_ROOT / job_id
    snapshot = {}
    with PATCH_JOB_LOCK:
        snapshot.update(PATCH_JOBS.get(job_id, {}))
    for path in (job_root / "public-job.json", job_root / "output" / "patch-state.json"):
        if path.exists():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    snapshot.update(value)
            except (OSError, ValueError):
                pass
    result_path = job_root / "output" / "patch-result.json"
    if result_path.exists():
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(result, dict):
                snapshot["result"] = result
        except (OSError, ValueError):
            pass
    if snapshot:
        _enforce_required_signature(snapshot, snapshot)
        snapshot.setdefault("job_id", job_id)
        with PATCH_JOB_LOCK:
            PATCH_JOBS[job_id] = dict(snapshot)
    return snapshot


def _patch_worker_values(state: dict) -> tuple[dict, object | None]:
    """Normalize worker responses before forwarding them to the job store.

    The worker status endpoint includes its path identifier as ``job_id``.
    That identifier is already supplied positionally to ``_patch_job_update``;
    forwarding it again via ``**state`` raises Python's duplicate-argument
    error and leaves the UI stuck in a failed job state.
    """
    values = dict(state or {})
    values.pop("job_id", None)
    result = values.pop("result", None)
    return values, result


def _patch_worker_request(path: str, *, method: str = "GET", payload: dict | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if PATCH_WORKER_TOKEN:
        headers["X-CATS-Worker-Token"] = PATCH_WORKER_TOKEN
    request = urllib.request.Request(f"{PATCH_WORKER_URL}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("Internal patch worker is unavailable") from exc


def _patch_page_context(
    request: Request, auth: AuthContext | None, db: Session,
    job_id: str = "", error: str = "", selected_service_id: str = "",
):
    job = _load_patch_job(job_id) if job_id else {}
    services = []
    configuration = get_global_configuration(db)
    if auth and auth.accessible_service_ids("scan.ingest") != set():
        scoped = auth.accessible_service_ids("scan.ingest")
        services = list(db.scalars(select(Service).order_by(Service.name)))
        if scoped is not None:
            services = [service for service in services if service.id in scoped]
    return templates.TemplateResponse(request, "patch.html", {
        "current_user": auth.user if auth else None,
        "csrf_token": auth.csrf_token if auth else "",
        "can": auth.has if auth else (lambda _permission: False),
        "themes": THEMES,
        "pending_request_count": 0,
        "pending_poam_count": 0,
        "job_id": job_id,
        "job": job,
        "error": error,
        "patch_phases": PATCH_PHASES,
        "authenticated_services": services,
        "selected_service_id": selected_service_id,
        "configured_registries": configured_registries(configuration),
        "signing": signing.public_metadata(configuration),
    })


def _run_patch_job(job_id: str, credential_env: dict[str, str]) -> None:
    job_root = PATCH_JOB_ROOT / job_id
    output_dir = job_root / "output"
    state_path = output_dir / "patch-state.json"
    result_path = output_dir / "patch-result.json"
    process: subprocess.Popen | None = None
    timeout = int(os.getenv("CATS_PATCH_JOB_TIMEOUT", "3600"))
    started = time.monotonic()
    _patch_job_update(job_id, status="running", phase="queued")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        if PATCH_WORKER_URL:
            config = json.loads((job_root / "job-config.json").read_text(encoding="utf-8"))
            _patch_worker_request(
                f"/internal/patch-jobs/{job_id}", method="POST",
                payload={"config": config, "credentials": credential_env},
            )
            credential_env.clear()
            while True:
                with PATCH_JOB_LOCK:
                    cancelled = PATCH_JOBS.get(job_id, {}).get("status") == "cancelled"
                if cancelled:
                    _patch_worker_request(f"/internal/patch-jobs/{job_id}/cancel", method="POST")
                    return
                if time.monotonic() - started > timeout:
                    _patch_worker_request(f"/internal/patch-jobs/{job_id}/cancel", method="POST")
                    raise TimeoutError("Patch job exceeded its configured time limit")
                state = _patch_worker_request(f"/internal/patch-jobs/{job_id}")
                state, result = _patch_worker_values(state)
                _patch_job_update(job_id, **state, **({"result": result} if isinstance(result, dict) else {}))
                if state.get("status") == "complete":
                    _patch_job_update(job_id, status="complete", phase="completed", result=result or {}, error=None)
                    return
                if state.get("status") in {"failed", "cancelled"}:
                    return
                time.sleep(0.5)

        env = dict(os.environ)
        env.update(credential_env)
        process = subprocess.Popen(
            [sys.executable, "-m", "app.patch_worker", str(job_root / "job-config.json"), str(output_dir)],
            env=env, cwd=str(root.parent), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with PATCH_JOB_LOCK:
            PATCH_PROCESSES[job_id] = process
        last_state = None
        while process.poll() is None:
            with PATCH_JOB_LOCK:
                cancelled = PATCH_JOBS.get(job_id, {}).get("status") == "cancelled"
            if cancelled:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                return
            if time.monotonic() - started > timeout:
                process.kill()
                raise TimeoutError("Patch job exceeded its configured time limit")
            if state_path.exists():
                try:
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    if state != last_state:
                        last_state = state
                        _patch_job_update(job_id, **state)
                except (OSError, ValueError):
                    pass
            time.sleep(0.5)
        if state_path.exists():
            state = json.loads(state_path.read_text(encoding="utf-8"))
            _patch_job_update(job_id, **state)
        if process.returncode == 0 and result_path.exists():
            result = json.loads(result_path.read_text(encoding="utf-8"))
            _patch_job_update(job_id, status="complete", phase="completed", result=result, error=None)
        else:
            with PATCH_JOB_LOCK:
                cancelled = PATCH_JOBS.get(job_id, {}).get("status") == "cancelled"
            if cancelled:
                return
            state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
            if state.get("status") in {"failed", "cancelled"}:
                if result_path.exists():
                    _patch_job_update(job_id, result=json.loads(result_path.read_text(encoding="utf-8")))
                _patch_job_update(job_id, **state)
                return
            raise RuntimeError(state.get("error") or "Patch worker failed")
    except Exception as exc:
        with PATCH_JOB_LOCK:
            existing = dict(PATCH_JOBS.get(job_id, {}))
        _patch_job_update(
            job_id, status="failed", phase=existing.get("phase") or "queued",
            stages=existing.get("stages"), failed_stage=existing.get("phase") or "queued",
            error=redact(exc),
        )
    finally:
        credential_env.clear()
        shutil.rmtree(job_root / "input", ignore_errors=True)
        (job_root / "job-config.json").unlink(missing_ok=True)
        with PATCH_JOB_LOCK:
            PATCH_PROCESSES.pop(job_id, None)


@app.get("/patch", response_class=HTMLResponse)
def public_patch(
    request: Request, job_id: str = "", db: Session = Depends(get_db),
    auth: AuthContext | None = Depends(optional_user),
):
    return _patch_page_context(request, auth, db, job_id)


@app.post("/patch")
def public_patch_submit(
    request: Request,
    csrf_token: str = Form(""),
    source_mode: str = Form("oci"),
    source_image: str = Form(""),
    source_registry_id: str = Form(""),
    source_username: str = Form(""),
    source_password: str = Form(""),
    source_archive: UploadFile | None = File(None),
    output_mode: str = Form("download"),
    destination_image: str = Form(""),
    destination_registry_id: str = Form(""),
    destination_username: str = Form(""),
    destination_password: str = Form(""),
    reuse_source_credentials: bool = Form(False),
    service_id: str = Form(""),
    db: Session = Depends(get_db),
    auth: AuthContext | None = Depends(optional_user),
):
    source_mode = source_mode.strip().lower()
    output_mode = output_mode.strip().lower()
    # Registry credentials are administrator-managed. Ignore legacy form
    # fields so a Patch workspace submission can never override them.
    source_username = source_password = ""
    destination_username = destination_password = ""
    source_registry_id = source_registry_id.strip()
    destination_registry_id = destination_registry_id.strip()
    registry_rows = parse_json(get_global_configuration(db).get("oci_registries"), [])
    registry_map = {str(row.get("id")): row for row in registry_rows if isinstance(row, dict) and row.get("id")}
    selected_source_registry = registry_map.get(source_registry_id) if source_registry_id else None
    selected_destination_registry = registry_map.get(destination_registry_id) if destination_registry_id else None
    def resolve_registry_image(image: str, registry: dict | None) -> str:
        image = image.strip()
        if not registry or not image:
            return image
        endpoint = str(registry.get("endpoint") or "").strip().rstrip("/")
        host = urllib.parse.urlparse(endpoint if "://" in endpoint else f"https://{endpoint}").netloc
        prefix = str(registry.get("namespace") or "").strip().strip("/")
        first = image.split("/", 1)[0]
        already_qualified = "." in first or ":" in first or first == "localhost"
        return image if already_qualified else "/".join(part for part in (host, prefix, image.lstrip("/")) if part)
    if source_registry_id and not selected_source_registry:
        return _patch_page_context(request, auth, db, error="Selected source registry is not configured.", selected_service_id=service_id)
    if destination_registry_id and not selected_destination_registry:
        return _patch_page_context(request, auth, db, error="Selected destination registry is not configured.", selected_service_id=service_id)
    if source_mode == "oci" and not selected_source_registry:
        selected_source_registry = _configured_registry_for_image(source_image, list(registry_map.values()))
    def apply_registry_credentials(registry: dict | None, username: str, password: str) -> tuple[str, str]:
        if not registry:
            return username, password
        username = username or str(registry.get("username") or "")
        if not password and registry.get("password"):
            try:
                password = decrypt_secret(str(registry.get("password")))
            except Exception as exc:
                raise ValueError("Configured registry secret could not be decrypted.") from exc
        return username, password
    try:
        if source_mode == "oci":
            source_username, source_password = apply_registry_credentials(selected_source_registry, source_username, source_password)
        if output_mode == "push":
            destination_username, destination_password = apply_registry_credentials(selected_destination_registry, destination_username, destination_password)
    except ValueError as exc:
        return _patch_page_context(request, auth, db, error=str(exc), selected_service_id=service_id)
    if source_mode == "oci" and selected_source_registry:
        source_image = resolve_registry_image(source_image, selected_source_registry)
    if output_mode == "push" and selected_destination_registry:
        destination_image = resolve_registry_image(destination_image, selected_destination_registry)
    if source_mode not in {"oci", "upload"} or output_mode not in {"download", "push"}:
        return _patch_page_context(request, auth, db, error="Choose a valid image source and output mode.", selected_service_id=service_id)
    if source_mode == "oci" and not source_image.strip():
        return _patch_page_context(request, auth, db, error="Image URI is required for an OCI registry source.", selected_service_id=service_id)
    if source_mode == "upload" and (not source_archive or not source_archive.filename):
        return _patch_page_context(request, auth, db, error="Choose a Docker or OCI image .tar archive.", selected_service_id=service_id)
    if output_mode == "push" and not destination_image.strip():
        return _patch_page_context(request, auth, db, error="Destination image / repository / tag is required for OCI push.", selected_service_id=service_id)
    if output_mode == "push" and not selected_destination_registry:
        return _patch_page_context(request, auth, db, error="Failed to upload, OCI registry not configured. Please contact Cybersecurity.", selected_service_id=service_id)
    if bool(source_username) != bool(source_password):
        return _patch_page_context(request, auth, db, error="Provide both source registry username and password/token.", selected_service_id=service_id)
    if bool(destination_username) != bool(destination_password):
        return _patch_page_context(request, auth, db, error="Provide both destination registry username and password/token.", selected_service_id=service_id)

    selected_service = None
    if service_id:
        if not auth or auth.accessible_service_ids("scan.ingest") == set():
            raise HTTPException(status_code=403, detail="Sign in with scan-ingest permission to retain patch history")
        selected_service = db.scalar(select(Service).where(Service.service_key == service_id))
        if not selected_service:
            raise HTTPException(status_code=404, detail="Selected service was not found")
        if not auth.has("scan.ingest", selected_service.id):
            raise HTTPException(status_code=403, detail="Selected service is outside your scope")

    signing_config, signing_credentials = _portal_signing_material(db, auth, output_mode, selected_service)
    if signing_config:
        check_csrf(auth, csrf_token)
    job_id = uuid.uuid4().hex
    job_root = PATCH_JOB_ROOT / job_id
    input_dir = job_root / "input"
    input_dir.mkdir(parents=True, exist_ok=False)
    policy_configuration = configuration_for_service(db, selected_service) if selected_service else get_configuration(db)
    config = {
        "job_id": job_id,
        **signing_config,
        "source_mode": source_mode,
        "source_image": source_image.strip() if source_mode == "oci" else None,
        "output_mode": output_mode,
        "destination_image": destination_image.strip() if output_mode == "push" else None,
        "reuse_source_credentials": bool(reuse_source_credentials),
        # Non-secret administrative policy is copied into the isolated worker
        # job. Credentials continue to arrive only through its environment.
        "trusted_ca_certificates": parse_json(policy_configuration.get("trusted_ca_certificates"), []),
        "repository_policies": parse_json(policy_configuration.get("repository_policies"), {}),
        "os_definitions": parse_json(policy_configuration.get("os_definitions"), {}),
    }
    if source_mode == "upload":
        max_bytes = int(os.getenv("CATS_PATCH_MAX_UPLOAD_BYTES", str(4 * 1024 * 1024 * 1024)))
        archive_path = input_dir / "source-image.tar"
        total = 0
        with archive_path.open("wb") as target:
            while chunk := source_archive.file.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    shutil.rmtree(job_root, ignore_errors=True)
                    return _patch_page_context(request, auth, db, error="Uploaded image archive is too large.", selected_service_id=service_id)
                target.write(chunk)
        config["archive_path"] = str(archive_path)
    (job_root / "job-config.json").write_text(json.dumps(safe_job_config(config), indent=2), encoding="utf-8")
    public = {
        "job_id": job_id,
        "signing_enabled": bool(signing_config),
        "signing_fingerprint": signing_config.get("signing_fingerprint"),
        "status": "queued",
        "phase": "queued",
        "stages": initial_patch_stages(output_mode),
        "source_mode": source_mode,
        "source_image": source_image.strip() if source_mode == "oci" else "Uploaded image archive",
        "output_mode": output_mode,
        "destination_image": destination_image.strip() if output_mode == "push" else None,
        "created_at": utcnow().isoformat(),
    }
    if selected_service:
        record = PatchExecution(
            job_key=job_id, service_id=selected_service.id, requested_by_id=auth.user.id,
            source_mode=source_mode,
            source_image=source_image.strip() if source_mode == "oci" else None,
            output_mode=output_mode,
            destination_image=destination_image.strip() if output_mode == "push" else None,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        db.add(AuditEvent(actor_user_id=auth.user.id, action="patch.started", target_type="patch_execution", target_id=str(record.id), detail={"service_id": selected_service.id, "source_image": source_image.strip() if source_mode == "oci" else None, "output_mode": output_mode}))
        db.commit()
        public["patch_execution_id"] = record.id
        public["service_id"] = selected_service.service_key
    with PATCH_JOB_LOCK:
        PATCH_JOBS[job_id] = public
    _patch_job_update(job_id)
    credentials = {
        **signing_credentials,
        "CATS_PATCH_SOURCE_USERNAME": source_username,
        "CATS_PATCH_SOURCE_PASSWORD": source_password,
        "CATS_PATCH_DEST_USERNAME": destination_username,
        "CATS_PATCH_DEST_PASSWORD": destination_password,
    }
    _audit_signing_request(db, job_id, auth.user.id if auth else None, config)
    PUBLIC_WORKERS.submit(_run_patch_job, job_id, credentials)
    return RedirectResponse(f"/patch?job_id={job_id}", status_code=303)


@app.get("/api/public/patch-jobs/{job_id}")
def public_patch_job(job_id: str):
    job = _load_patch_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch job not found")
    return job


@app.post("/api/public/patch-jobs/{job_id}/cancel")
def cancel_public_patch_job(job_id: str):
    _load_patch_job(job_id)
    with PATCH_JOB_LOCK:
        job = PATCH_JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Patch job not found")
        if job.get("status") not in {"complete", "failed", "cancelled"}:
            job.update(status="cancelled", phase="cancelled", error=None)
    _patch_job_update(job_id)
    if PATCH_WORKER_URL:
        try:
            _patch_worker_request(f"/internal/patch-jobs/{job_id}/cancel", method="POST")
        except RuntimeError:
            pass
    with PATCH_JOB_LOCK:
        return {"job_id": job_id, "status": PATCH_JOBS[job_id]["status"]}


@app.get("/api/public/patch-jobs/{job_id}/logs", response_class=PlainTextResponse)
def public_patch_logs(job_id: str):
    if not _load_patch_job(job_id):
        raise HTTPException(status_code=404, detail="Patch job not found")
    path = PATCH_JOB_ROOT / job_id / "output" / "patch.log"
    return path.read_text(encoding="utf-8") if path.exists() else "Patch worker has not produced logs yet.\n"


@app.get("/api/public/patch-jobs/{job_id}/results", response_class=HTMLResponse)
def public_patch_results(request: Request, job_id: str, auth: AuthContext | None = Depends(optional_user)):
    job = _load_patch_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch job not found")
    if job.get("status") not in {"complete", "failed"} or not isinstance(job.get("result"), dict):
        raise HTTPException(status_code=409, detail="Patch job is not complete")
    return templates.TemplateResponse(request, "patch_results.html", {
        "current_user": auth.user if auth else None, "csrf_token": auth.csrf_token if auth else "",
        "can": auth.has if auth else (lambda _permission: False), "themes": THEMES,
        "pending_request_count": 0, "pending_poam_count": 0, "job": job, "result": job["result"],
    })


@app.get("/api/public/patch-jobs/{job_id}/patched-image.tar")
def download_patched_image(job_id: str):
    job = _load_patch_job(job_id)
    path = PATCH_JOB_ROOT / job_id / "output" / "patched-image.tar"
    result = job.get("result") if isinstance(job, dict) else {}
    if not job or job.get("status") not in {"complete", "failed"} or not path.exists() or not (result or {}).get("artifact_available"):
        raise HTTPException(status_code=404, detail="Patched image archive is not available")
    return FileResponse(path, media_type="application/x-tar", filename=f"cats-patched-{job_id[:12]}.tar")


def _validate_materialized_candidate(candidate_dir: Path, payload: dict, plan: dict, validation: dict) -> dict:
    """Run available Level 1 tools and keep missing tools explicit."""
    checks = validation["checks"]
    values_files = checked_values_files(payload.get("helm_values_files", []),
        {path.relative_to(candidate_dir).as_posix() for path in candidate_dir.rglob("*") if path.is_file()})
    overrides = [argument for value in values_files for argument in ("--values", str(candidate_dir / value))]
    chart_roots = sorted({path.parent for path in candidate_dir.rglob("Chart.yaml")
                          if "charts" not in path.relative_to(candidate_dir).parts[:-1]})
    rendered_parts: list[str] = []
    helm = shutil.which("helm")
    if chart_roots and helm:
        lint_results, template_results = [], []
        for chart_root in chart_roots:
            lint = subprocess.run([helm, "lint", str(chart_root), *overrides], capture_output=True, text=True, timeout=180, check=False)
            lint_results.append(lint)
            rendered = subprocess.run([helm, "template", "cats-remediation", str(chart_root), "--include-crds", *overrides],
                                      capture_output=True, text=True, timeout=180, check=False)
            template_results.append(rendered)
            if rendered.returncode == 0:
                rendered_parts.append(rendered.stdout)
        checks["helm_lint"] = {"status": "PASS" if all(item.returncode == 0 for item in lint_results) else "FAIL",
                               "detail": "Validated every discovered chart."}
        checks["helm_template"] = {"status": "PASS" if all(item.returncode == 0 for item in template_results) else "FAIL",
                                   "detail": "Rendered every discovered chart with CRDs."}
    elif chart_roots:
        checks["helm_lint"] = {"status": "FAIL", "detail": "Helm is unavailable in the remediation worker."}
        checks["helm_template"] = {"status": "FAIL", "detail": "Helm is unavailable in the remediation worker."}
    else:
        for raw in sorted(candidate_dir.rglob("*")):
            if raw.suffix in {".yaml", ".yml"} and not raw.name.startswith(".cats-"):
                rendered_parts.append(raw.read_text(encoding="utf-8"))

    rendered_text = "\n---\n".join(rendered_parts)
    if rendered_text:
        try:
            objects = [item for item in yaml.safe_load_all(rendered_text) if isinstance(item, dict) and item.get("kind")]
            checks["yaml_parsing"] = {"status": "PASS", "detail": f"Parsed {len(objects)} candidate Kubernetes resources."}
            expected_kinds = {str(value).split("/")[-2] for value in plan["before"].get("resource_identities", []) if "/" in str(value)}
            actual_kinds = {str(item.get("kind")) for item in objects}
            from .remediation_sources import verify_rendered_changes
            checks["intended_changes"] = verify_rendered_changes(objects, plan.get("configuration_changes", []))
            if "intended_changes" not in validation["required_checks"]:
                validation["required_checks"].append("intended_changes")
            checks["expected_resources"] = {"status": "PASS" if expected_kinds <= actual_kinds else "FAIL",
                                             "detail": "Expected resource kinds remain present in the candidate render."}
            rendered_path = candidate_dir / ".cats-rendered.yaml"
            rendered_path.write_text(rendered_text, encoding="utf-8")
            from .offline_schema import validate_resources
            checks["kubernetes_schema"] = validate_resources(objects)
        except (OSError, yaml.YAMLError) as exc:
            checks["yaml_parsing"] = {"status": "FAIL", "detail": str(exc)}
    trivy = shutil.which("trivy")
    if trivy:
        # Scan the rendered candidate once, not both chart sources and their render.
        scan_target = candidate_dir / ".cats-rendered.yaml"
        if not scan_target.is_file():
            checks["trivy_config_rescan"] = {"status": "FAIL", "detail": "No rendered candidate is available for configuration scanning."}
            validation["status"] = "FAIL"
            return validation
        result = subprocess.run([trivy, "config", "--format", "json", "--exit-code", "0", str(scan_target)], capture_output=True, text=True,
                                timeout=int(os.getenv("CATS_REMEDIATION_SCAN_TIMEOUT", "600")), check=False)
        checks["trivy_config_rescan"] = {"status": "FAIL", "detail": "Configuration scanner did not produce valid completed JSON evidence."}
        if result.returncode == 0:
            try:
                summary = summarize_configuration_report(json.loads(result.stdout))
                plan["after"].update(summary)
                checks["trivy_config_rescan"] = {"status": "PASS" if summary["configuration_findings"] == 0 else "FAIL",
                    "detail": f"Completed configuration rescan: {summary['configuration_findings']} unresolved findings."}
                (candidate_dir / ".cats-config-scan.json").write_text(result.stdout, encoding="utf-8")
            except (ValueError, TypeError):
                pass
    if not plan.get("images"):
        checks["vulnerability_rescan"] = {"status": "PASS", "detail": "No image references require vulnerability scanning."}
    elif all(item.get("candidate") and item.get("patch_status") in {"PATCHED", "PARTIALLY_PATCHED", "NO_APPLICABLE_FIXES"}
             for item in plan.get("images", [])):
        checks["vulnerability_rescan"] = {"status": "PASS", "detail": "Every staged image completed the existing patch worker's before/after vulnerability scan."}
    validation["status"] = "PASS" if all(checks[name]["status"] == "PASS" for name in validation["required_checks"]) else "FAIL"
    return validation


def _run_remediation_image_patches(db: Session, record: RemediationExecution, service: Service, plan: dict) -> None:
    """Run the existing patch worker for each distinct service image."""
    configuration = get_global_configuration(db)
    registries = [item for item in parse_json(configuration.get("oci_registries"), []) if isinstance(item, dict)]
    staging = [item for item in registries if item.get("use_for_remediation") is True]
    if len(staging) != 1 and record.output_mode != "bundle":
        reason = "Configure exactly one OCI registry as the remediation target or staging registry."
        for image in plan.get("images", []):
            if not image.get("candidate"):
                image["reason"] = reason
                image["patch_status"] = "BLOCKED"
        return
    requester = db.get(User, record.requested_by_id) if record.requested_by_id else None
    patch_mode = "push" if record.output_mode == "publish" else "download"
    signing_config, signing_credentials = _portal_signing_material(db, AuthContext(requester, None) if requester else None, patch_mode, service)
    destination_registry = staging[0] if len(staging) == 1 else {"endpoint": "https://candidate.invalid", "namespace": "retained"}
    endpoint = str(destination_registry.get("endpoint") or "").strip().rstrip("/")
    destination_host = urllib.parse.urlparse(endpoint if "://" in endpoint else f"https://{endpoint}").netloc
    destination_prefix = str(destination_registry.get("namespace") or "").strip("/")
    policy = configuration_for_service(db, service)
    repository_policies = parse_json(policy.get("repository_policies"), {})

    def credentials(registry: dict | None) -> tuple[str, str]:
        if not registry:
            return "", ""
        username = str(registry.get("username") or "")
        password = decrypt_secret(str(registry.get("password"))) if registry.get("password") else ""
        return username, password

    patched_by_source: dict[str, dict] = {}
    for image in plan.get("images", []):
        if image.get("candidate"):
            continue
        source = str(image.get("original") or "")
        if source in patched_by_source:
            image.update(patched_by_source[source])
            continue
        try:
            _validate_image_reference(source)
        except HTTPException:
            image.update(classification="NOT REMEDIABLE", patch_status="BLOCKED", reason="Discovered image reference is not a safe OCI reference")
            patched_by_source[source] = {"classification": image["classification"], "reason": image["reason"], "patch_status": "BLOCKED"}
            continue
        source_registry = _configured_registry_for_image(source, registries)
        # Match standalone Patch: configured connections supply credentials,
        # but an unconfigured source is pulled anonymously by the same worker.
        # Pull/authentication/network failures remain real worker failures; do
        # not rewrite the source or silently substitute a different registry.
        source_path = source.rsplit("@", 1)[0]
        last_slash, last_colon = source_path.rfind("/"), source_path.rfind(":")
        tag = source_path[last_colon + 1:] if last_colon > last_slash else "latest"
        repository = source_path[:last_colon] if last_colon > last_slash else source_path
        first, separator, remainder = repository.partition("/")
        if separator and ("." in first or ":" in first or first == "localhost"):
            repository = remainder
        destination = "/".join(part for part in (destination_host, destination_prefix, repository) if part) + f":{tag}-cats-{record.job_key.lower()}"
        patch_key = uuid.uuid4().hex
        patch_root = PATCH_JOB_ROOT / patch_key
        (patch_root / "input").mkdir(parents=True, exist_ok=False)
        config = {"job_id": patch_key, "source_mode": "oci", "source_image": source, "output_mode": patch_mode,
                  **signing_config,
                  "remediation_evidence": True,
                  # Default policies intentionally use repositories defined in the image.
                  "require_repository_policy": False,
                  "destination_image": destination, "reuse_source_credentials": False,
                  "trusted_ca_certificates": parse_json(policy.get("trusted_ca_certificates"), []),
                  "repository_policies": repository_policies,
                  "os_definitions": parse_json(policy.get("os_definitions"), {})}
        (patch_root / "job-config.json").write_text(json.dumps(safe_job_config(config), indent=2), encoding="utf-8")
        patch_record = PatchExecution(job_key=patch_key, service_id=service.id, requested_by_id=record.requested_by_id,
                                      source_mode="oci", source_image=source, output_mode=patch_mode,
                                      destination_image=destination, status="queued", phase="queued", summary={})
        db.add(patch_record); db.flush()
        public = {"job_id": patch_key, "patch_execution_id": patch_record.id, "status": "queued", "phase": "queued",
                  "signing_enabled": bool(signing_config), "signing_fingerprint": signing_config.get("signing_fingerprint"),
                  "stages": initial_patch_stages(patch_mode), "source_mode": "oci", "source_image": source,
                  "output_mode": patch_mode, "destination_image": destination, "created_at": utcnow().isoformat()}
        with PATCH_JOB_LOCK:
            PATCH_JOBS[patch_key] = public
        db.commit()
        source_user, source_password = credentials(source_registry)
        destination_user, destination_password = credentials(destination_registry) if patch_mode == "push" else ("", "")
        _audit_signing_request(db, patch_key, record.requested_by_id, config)
        try:
            _run_patch_job(patch_key, {**signing_credentials, "CATS_PATCH_SOURCE_USERNAME": source_user, "CATS_PATCH_SOURCE_PASSWORD": source_password,
                                       "CATS_PATCH_DEST_USERNAME": destination_user, "CATS_PATCH_DEST_PASSWORD": destination_password})
        except Exception as exc:
            image.update(classification="REVIEW REQUIRED", patch_job_id=patch_key, patch_status="FAILED",
                         reason=f"Image patch worker failed: {type(exc).__name__}")
            patched_by_source[source] = {"classification": image["classification"], "reason": image["reason"],
                                         "patch_job_id": patch_key, "patch_status": "FAILED"}
            continue
        patch_job = _load_patch_job(patch_key)
        result = (patch_job.get("result") or {})
        image["remediation_evidence"] = result.get("remediation_evidence") or {}
        image["vulnerabilities_before"] = result.get("vulnerabilities_before")
        image["vulnerabilities_after"] = result.get("vulnerabilities_after")
        immutable = result.get("immutable_destination")
        if result.get("delivery_status") == "delivered" and immutable:
            image.update(candidate=immutable, digest=str(immutable).split("@", 1)[-1], patch_status=result.get("patch_status"),
                         signature_status=result.get("signature_status", "not_configured"), patch_job_id=patch_key)
            mapping = image.get("source_mapping") or {}
            source_files = plan.get("_source_files") or {}
            editable = not mapping.get("ambiguous", True) and (mapping.get("values_file") or "") in source_files
            image["classification"] = "AUTO-REMEDIABLE" if editable else "REVIEW REQUIRED"
            image["reason"] = "Published and digest-qualified; source mapping is exact." if editable else "Published and digest-qualified, but the Helm source mapping needs review."
        elif patch_mode == "download" and result.get("delivery_status") == "download" and result.get("artifact_available"):
            image.update(candidate=destination, digest=result.get("artifact_sha256"), patch_status=result.get("patch_status"),
                         signature_status="not_applicable", patch_job_id=patch_key, delivery_status="bundled")
            mapping = image.get("source_mapping") or {}
            editable = not mapping.get("ambiguous", True) and (mapping.get("values_file") or "") in (plan.get("_source_files") or {})
            image["classification"] = "AUTO-REMEDIABLE" if editable else "REVIEW REQUIRED"
            image["reason"] = "Archive prepared for the configured target registry; import is required before deployment." if editable else "Archive prepared, but Helm source mapping needs review."
        else:
            terminal_status = result.get("patch_status") or ("FAILED" if patch_job.get("status") == "failed" else "BLOCKED")
            if str(terminal_status).upper() in {"PENDING", "QUEUED", "RUNNING"}:
                terminal_status = "FAILED"
            image.update(classification="REVIEW REQUIRED", patch_job_id=patch_key, patch_status=terminal_status,
                         reason=result.get("delivery_error") or result.get("reason") or patch_job.get("error") or "Image patch/publication did not produce an immutable staged reference.")
        patched_by_source[source] = {key: image[key] for key in (
            "candidate", "digest", "patch_status", "signature_status", "patch_job_id", "delivery_status", "remediation_evidence",
            "vulnerabilities_before", "vulnerabilities_after", "classification", "reason") if key in image}


REMEDIATION_STAGES = ("snapshot", "patch_images", "rewrite_artifacts", "static_validation", "final_rescan", "package", "output", "deployment_validation")


def _remediation_audit(db: Session, record: RemediationExecution, action: str, **details) -> None:
    db.add(AuditEvent(actor_user_id=record.requested_by_id, action=action,
        target_type="remediation_execution", target_id=str(record.id),
        detail={"service_id": record.service_id, "job_key": record.job_key, **details}))


def _remediation_stage(record: RemediationExecution, name: str, status: str, detail: str = "") -> None:
    stages = dict(record.stages or {})
    previous = stages.get(name) or {}
    current = utcnow()
    started = current.isoformat() if status == "running" else previous.get("started_at")
    duration = None
    if status != "running" and started:
        try:
            duration = max(0, round((current - datetime.fromisoformat(started)).total_seconds(), 1))
        except ValueError:
            pass
    stages[name] = {"status": status, "started_at": started,
                    "completed_at": None if status == "running" else current.isoformat(),
                    "duration_seconds": duration, "detail": detail[:500]}
    record.stages = stages
    record.phase = name


def _candidate_workload_images(resources: list[dict]) -> set[str]:
    images: set[str] = set()
    for resource in resources:
        if resource.get("kind") not in WORKLOAD_KINDS:
            continue
        spec = pod_spec(resource)
        if not isinstance(spec, dict):
            continue
        for field in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(field) or []:
                if isinstance(container, dict) and isinstance(container.get("image"), str):
                    images.add(container["image"])
    return images


_TEMPLATE_SOURCE_SUFFIXES = (".yaml", ".yml", ".tpl")


def _secret_document_has_literal_data(document: str) -> bool:
    """True when a Kubernetes Secret document carries literal (non-templated) data.

    Helm charts commonly template Secrets whose values come from ``.Values`` or
    ``lookup`` at install time; such templates contain no secret material and
    remain transferable. Any literal value under ``data``/``stringData`` (including
    block scalars) is treated as secret material and refused.
    """
    lines = document.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)(data|stringData):\s*(.*?)\s*$", lines[index])
        index += 1
        if not match:
            continue
        indent, inline = len(match.group(1)), match.group(3)
        if inline and not inline.startswith(("{{", "#")) and inline not in {"{}", "null", "~"}:
            return True
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("{{"):
                index += 1
                continue
            if len(line) - len(line.lstrip()) <= indent:
                break
            key, separator, value = stripped.partition(":")
            value = value.strip()
            if separator and value and "{{" not in value and value not in {'""', "''", "null", "~"}:
                # Block scalars (| or >) hold literal content unless every following line is templated.
                if value[0] in "|>":
                    block_indent = len(line) - len(line.lstrip())
                    block = []
                    index += 1
                    while index < len(lines) and (not lines[index].strip() or len(lines[index]) - len(lines[index].lstrip()) > block_indent):
                        if lines[index].strip():
                            block.append(lines[index].strip())
                        index += 1
                    if any("{{" not in item for item in block):
                        return True
                    continue
                return True
            index += 1
    return False


def _assert_bundle_sources_safe(files: dict[str, str]) -> None:
    """Refuse a transferable bundle when retained source may contain secrets.

    Literal secret material is refused: private keys, credential/env files,
    Secrets with literal data, and secret-named keys with literal values. A Helm
    template that only declares a Secret populated from values at install time is
    not secret material and is allowed.
    """
    sensitive_keys = {"password", "token", "clientsecret", "apikey", "privatekey", "credential", "secretkey", "secretaccesskey"}
    for path, content in files.items():
        normalized_path = path.replace("\\", "/").lower()
        parts = normalized_path.split("/")
        templated_source = normalized_path.endswith(_TEMPLATE_SOURCE_SUFFIXES)
        if any(part == ".env" or part.startswith(".env.") for part in parts) or (
                not templated_source and any("secret" in part or "credential" in part for part in parts)):
            raise ValueError("Bundle source contains a secret-bearing file")
        if re.search(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", content):
            raise ValueError("Bundle source contains a private key")
        for document in re.split(r"(?m)^---\s*$", content):
            if re.search(r"(?im)^\s*kind:\s*Secret\s*$", document) and _secret_document_has_literal_data(document):
                raise ValueError("Bundle source contains a Kubernetes Secret with literal data")
        for line in content.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip().lower().replace("_", "") in sensitive_keys:
                actual = value.strip().strip("\"'")
                if actual and actual.lower() not in {"null", "none"} and not actual.startswith("{{"):
                    raise ValueError("Bundle source contains a secret-like value")


def _publish_remediation_charts(db: Session, packaged_charts: list[tuple[Path, dict]]) -> None:
    """Publish packaged charts with Helm OCI using isolated credentials and trust."""
    if not packaged_charts:
        return
    configuration = get_global_configuration(db)
    registries = [row for row in parse_json(configuration.get("oci_registries"), [])
                  if isinstance(row, dict) and row.get("use_for_remediation") is True]
    if len(registries) != 1:
        for _, chart in packaged_charts:
            chart.update(publish_status="FAILED", reason="One remediation OCI registry must be configured")
        return
    registry = registries[0]
    endpoint = str(registry.get("endpoint") or "").strip()
    parsed = urllib.parse.urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        for _, chart in packaged_charts:
            chart.update(publish_status="FAILED", reason="Remediation registry must be a credential-free HTTPS endpoint")
        return
    helm_binary = shutil.which("helm")
    if not helm_binary:
        return
    prefix = str(registry.get("namespace") or "").strip("/")
    target = "oci://" + "/".join(part for part in (parsed.netloc, prefix) if part)
    username = str(registry.get("username") or "")
    password = decrypt_secret(str(registry.get("password"))) if registry.get("password") else ""
    trusted = parse_json(configuration.get("trusted_ca_certificates"), [])
    with tempfile.TemporaryDirectory(prefix="cats-remediation-helm-") as temporary:
        private = Path(temporary)
        private.chmod(0o700)
        registry_config = private / "registry.json"
        with ephemeral_trust(trusted if isinstance(trusted, list) else []) as (ca_path, trust_env):
            environment = {**os.environ, **trust_env, "HELM_REGISTRY_CONFIG": str(registry_config)}
            if username or password:
                if not username or not password:
                    for _, chart in packaged_charts:
                        chart.update(publish_status="FAILED", reason="Registry credentials are incomplete")
                    return
                command = [helm_binary, "registry", "login", parsed.netloc, "--username", username, "--password-stdin"]
                if ca_path:
                    command.extend(["--ca-file", str(ca_path)])
                login = subprocess.run(command, input=password + "\n", env=environment,
                    capture_output=True, text=True, timeout=60, check=False)
                if login.returncode:
                    for _, chart in packaged_charts:
                        chart.update(publish_status="FAILED", reason="Helm registry authentication failed")
                    return
            for archive, chart in packaged_charts:
                try:
                    push = subprocess.run([helm_binary, "push", str(archive), target], env=environment,
                        capture_output=True, text=True, timeout=300, check=False)
                    if push.returncode:
                        raise ValueError("Helm OCI push failed")
                    digest = re.search(r"(?im)^Digest:\s*(sha256:[0-9a-f]{64})\s*$", push.stdout)
                    if not digest:
                        raise ValueError("Helm did not report an immutable digest")
                    chart.update(publish_status="PUBLISHED", digest=digest.group(1),
                        published_reference=f"{target}/{chart['name']}:{chart['remediated_version']}")
                except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                    chart.update(publish_status="FAILED", reason=type(exc).__name__)


def _run_remediation_job(record_id: int) -> None:
    """Create an isolated candidate and persist every terminal outcome."""
    with SessionLocal() as db:
        record = db.get(RemediationExecution, record_id)
        if not record:
            return
        record.status, record.started_at, record.updated_at = "running", utcnow(), utcnow()
        record.remediation_status = "running"
        _remediation_stage(record, "snapshot", "running")
        record.logs = ["Captured immutable references to the original execution and service revision."]
        db.commit()
        try:
            service = db.scalar(select(Service).where(Service.id == record.service_id).options(
                selectinload(Service.executions), selectinload(Service.policy_findings), selectinload(Service.findings).selectinload(Finding.observations)
            ))
            if not service or not service.executions:
                raise ValueError("The service has no assessment execution to remediate")
            execution = next((item for item in service.executions if item.id == record.source_execution_id), None)
            if record.source_execution_id is None:
                # Legacy jobs retain their exact rollback execution when available.
                execution = next((item for item in service.executions if item.execution_key == record.rollback_reference), None)
            if execution is None:
                raise ValueError("The retained source assessment is unavailable; refusing to switch to a newer scan")
            payload = _remediation_source_payload(execution)
            retained_findings = []
            identities = {item.identity_key: item.id for item in service.policy_findings}
            for item in payload.get("policy_findings") or []:
                values = policy_finding_values(item)
                retained_findings.append(SimpleNamespace(
                    id=identities.get(policy_finding_identity(values)), **values))
            if record.finding_type == "configuration":
                findings = [item for item in retained_findings if item.id == record.finding_id]
                if not findings:
                    raise ValueError("The selected configuration finding is absent from the retained source scan")
            elif record.finding_type == "vulnerability":
                findings = []
            else:
                findings = retained_findings
            plan = build_plan(payload, findings, record.job_key)
            inputs = record.workflow_inputs or {}
            if inputs:
                plan = resolve_decisions(plan, inputs.get("remediation_mode", "automated"), inputs.get("decisions", {}), record.requested_by_id)
                _remediation_audit(db, record, "remediation.decisions_applied", mode=inputs.get("remediation_mode"), decisions=inputs.get("decisions", {}))
            plan["before"]["epss_max"] = max((score for finding in service.findings
                for _, score in [risk_metadata(finding.cve)]
                if any(item.execution_id == execution.id for item in finding.observations) and score is not None), default=None)
            _remediation_stage(record, "snapshot", "success")
            planned_references = {str(item.get("original")) for item in plan.get("images", [])}
            source_images = {item.image: item.image_digest for finding in service.findings
                             for item in finding.observations if item.execution_id == execution.id}
            for image_reference, image_digest in source_images.items():
                if image_reference in planned_references:
                    continue
                plan["images"].append({"original": image_reference,
                    "original_digest": image_digest,
                    "classification": "REVIEW REQUIRED", "candidate": None,
                    "source_mapping": {"ambiguous": True},
                    "reason": "Canonical service image has no exact Helm source mapping; patching can proceed, chart rewriting needs review."})
                planned_references.add(image_reference)
            plan["_source_files"] = payload.get("helm_source_files") or payload.get("source_files") or {}
            _assert_bundle_sources_safe(plan["_source_files"])
            _remediation_stage(record, "patch_images", "running")
            db.commit()
            _run_remediation_image_patches(db, record, service, plan)
            attempted = sum(bool(image.get("patch_job_id")) for image in plan["images"])
            produced = sum(bool(image.get("candidate")) for image in plan["images"])
            _remediation_stage(record, "patch_images", "success" if produced == len(plan["images"]) else "partial",
                f"{attempted}/{len(plan['images'])} images reached the patch worker; {produced} artifacts produced. See per-image diagnostics for blockers.")
            for image in plan["images"]:
                _remediation_audit(db, record, "remediation.image_result", original=image.get("original"),
                    remediated=image.get("candidate"), patch_status=image.get("patch_status"),
                    signature_status=image.get("signature_status"))
            distinct_patches = {image.get("patch_job_id"): image for image in plan["images"] if image.get("patch_job_id")}
            plan["before"]["patchable_vulnerabilities"] = sum(int(image.get("vulnerabilities_before") or 0) for image in distinct_patches.values())
            plan["after"]["patchable_vulnerabilities"] = sum(int(image.get("vulnerabilities_after") or 0) for image in distinct_patches.values())
            if distinct_patches:
                full_reports = []
                for patch_key in distinct_patches:
                    if not isinstance(patch_key, str) or not re.fullmatch(r"[0-9a-f]{32}", patch_key):
                        continue
                    path = PATCH_JOB_ROOT / patch_key / "output" / "grype-full-after.json"
                    if path.is_file():
                        try:
                            full_reports.append(json.loads(path.read_text(encoding="utf-8")))
                        except (OSError, ValueError):
                            pass
                if len(full_reports) == len(distinct_patches):
                    plan["after"].update(summarize_grype_reports(full_reports, risk_metadata))
                else:
                    plan["after"]["vulnerabilities"] = None
                    plan["after"]["kev"] = None
            plan.pop("_source_files", None)
            for image in plan["images"]:
                if image.get("classification") == "AUTO-REMEDIABLE":
                    source = (image.get("source_mapping") or {}).get("values_file") or (image.get("source_mapping") or {}).get("template")
                    artifact = next((item for item in plan["changed_artifacts"] if item["path"] == source), None)
                    if not artifact:
                        artifact = {"path": source, "changes": []}; plan["changed_artifacts"].append(artifact)
                    artifact["changes"].append(f"Image {image['original']} → {image['candidate']}")
            _remediation_stage(record, "rewrite_artifacts", "running")
            record.before_snapshot = plan["before"]
            record.configuration_changes = plan["configuration_changes"]
            record.changed_artifacts = plan["changed_artifacts"]
            record.patched_images = plan["images"]
            record.rollback_reference = str(plan.get("rollback_reference") or execution.execution_key)
            record.logs = [*record.logs, "Classified findings and images without changing the original artifacts."]
            db.commit()

            files, chart_mappings = versioned_charts(candidate_files(payload, plan), record.job_key)
            plan["charts"] = chart_mappings
            _assert_bundle_sources_safe(files)
            values_files = checked_values_files(payload.get("helm_values_files", []), files)
            _remediation_stage(record, "rewrite_artifacts", "success" if files else "skipped")
            job_root = REMEDIATION_JOB_ROOT / record.job_key
            job_root.mkdir(parents=True, exist_ok=True)
            artifact = job_root / "remediation-candidate.zip"
            candidate_dir = job_root / "candidate"
            candidate_dir.mkdir(parents=True, exist_ok=True)
            for relative, content in sorted(files.items()):
                safe = Path(relative.replace("\\", "/"))
                if safe.is_absolute() or ".." in safe.parts:
                    raise ValueError(f"Unsafe source path in uploaded artifact: {relative}")
                target = candidate_dir / safe
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            _remediation_stage(record, "static_validation", "running")
            # Validate retained originals separately; never mutate authoritative source.
            baseline_dir = job_root / "baseline"
            baseline_dir.mkdir(parents=True, exist_ok=True)
            baseline_files = payload.get("helm_source_files") or payload.get("source_files") or {}
            _assert_bundle_sources_safe(baseline_files)
            for relative, content in baseline_files.items():
                target = baseline_dir / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            baseline_parts, baseline_ok = [], bool(baseline_files)
            baseline_helm = shutil.which("helm")
            baseline_values = checked_values_files(payload.get("helm_values_files", []), baseline_files)
            baseline_overrides = [argument for value in baseline_values for argument in ("--values", str(baseline_dir / value))]
            roots = [path.parent for path in baseline_dir.rglob("Chart.yaml")
                     if "charts" not in path.relative_to(baseline_dir).parts[:-1]]
            if roots:
                baseline_ok = bool(baseline_helm)
                if baseline_helm:
                    for root in roots:
                        lint = subprocess.run([baseline_helm, "lint", str(root), *baseline_overrides], capture_output=True, text=True, timeout=180, check=False)
                        render = subprocess.run([baseline_helm, "template", "cats-remediation", str(root), "--include-crds", *baseline_overrides], capture_output=True, text=True, timeout=180, check=False)
                        baseline_ok = baseline_ok and lint.returncode == 0 and render.returncode == 0
                        if render.returncode == 0:
                            baseline_parts.append(render.stdout)
            else:
                baseline_parts = [content for name, content in baseline_files.items() if name.endswith((".yaml", ".yml"))]
            baseline_resources = [item for item in yaml.safe_load_all("\n---\n".join(baseline_parts)) if isinstance(item, dict) and item.get("kind")]
            (baseline_dir / ".cats-rendered.yaml").write_text("\n---\n".join(baseline_parts), encoding="utf-8")
            validation = _validate_materialized_candidate(candidate_dir, payload, plan, static_validation(payload, plan))
            rendered_path = candidate_dir / ".cats-rendered.yaml"
            rendered = []
            if rendered_path.is_file():
                rendered = [item for item in yaml.safe_load_all(rendered_path.read_text(encoding="utf-8")) if isinstance(item, dict)]
            from .remediation_sources import verify_rendered_scope
            validation["checks"]["baseline_render"] = {"status": "PASS" if baseline_ok and baseline_resources else "FAIL",
                "detail": "Original retained source lint/render completed." if baseline_ok and baseline_resources else "Original source render is unavailable or failed."}
            validation["checks"]["change_scope"] = (verify_rendered_scope(baseline_resources, rendered, plan["configuration_changes"], plan["images"])
                if baseline_resources and rendered else {"status": "WARNING_UNVERIFIED", "detail": "Source change scope cannot be proved without both renders."})
            validation["required_checks"].extend(["baseline_render", "change_scope"])
            if any(validation["checks"][key]["status"] != "PASS" for key in ("baseline_render", "change_scope")):
                validation["status"] = "FAIL"
            if rendered and plan["images"]:
                actual_images = _candidate_workload_images(rendered)
                # Only AUTO-REMEDIABLE images with a candidate are written into the chart
                # (candidate_files). A patched image whose source mapping needs review is
                # retained by reference until a person edits the chart, so it must still
                # render as the original rather than count as a missing rewrite.
                rewritten = [image for image in plan["images"]
                             if image.get("candidate") and image.get("classification") == "AUTO-REMEDIABLE"]
                rewritten_originals = {str(image["original"]) for image in rewritten}
                expected_images = {str(image["candidate"]) for image in rewritten}
                replaced_images = rewritten_originals
                # Images known only from vulnerability evidence (not rendered by this chart)
                # cannot be expected in the candidate render.
                baseline_images = _candidate_workload_images(baseline_resources) if baseline_resources else None
                retained_images = {str(image["original"]) for image in plan["images"]
                                   if str(image["original"]) not in rewritten_originals
                                   and (baseline_images is None or str(image["original"]) in baseline_images)}
                image_references_valid = (expected_images | retained_images) <= actual_images and not (replaced_images - expected_images) & actual_images
                validation["checks"]["image_references"] = {"status": "PASS" if image_references_valid else "FAIL",
                    "detail": "Candidate render uses the remediated image mappings." if image_references_valid else "Original or missing remediated image references remain in the candidate render."}
                if not image_references_valid:
                    validation["status"] = "FAIL"
            from .remediation_validation import classify_static
            classify_static(validation)
            _remediation_stage(record, "static_validation", "failed" if validation["status"] == "BLOCKING" else
                               "warning" if validation["status"] == "WARNING_UNVERIFIED" else "success")
            scan_statuses = [validation["checks"][name]["status"] for name in ("trivy_config_rescan", "vulnerability_rescan")]
            _remediation_stage(record, "final_rescan", "success" if all(value == "PASS" for value in scan_statuses) else "warning",
                               "Final scan results are independent of mutation and runtime validation.")
            _remediation_stage(record, "package", "running")
            packaged_charts: list[tuple[Path, dict]] = []
            helm_binary = shutil.which("helm")
            chart_output = job_root / "helm"
            chart_output.mkdir(exist_ok=True)
            for chart in chart_mappings:
                if chart.get("package_status") == "FAILED":
                    continue
                if not helm_binary:
                    chart["package_status"] = "UNAVAILABLE"
                    continue
                chart_root = candidate_dir / Path(chart["path"]).parent
                try:
                    packaged = subprocess.run([helm_binary, "package", str(chart_root), "--destination", str(chart_output)],
                        capture_output=True, text=True, timeout=180, check=False)
                    if packaged.returncode:
                        raise ValueError("Helm rejected candidate chart")
                    archive = chart_output / f"{chart['name']}-{chart['remediated_version']}.tgz"
                    if not archive.is_file():
                        raise ValueError("Helm did not create a chart package")
                    chart["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
                    chart["package_status"] = "PACKAGED"
                    packaged_charts.append((archive, chart))
                except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                    chart["package_status"] = "FAILED"
                    chart["reason"] = type(exc).__name__
            validation["packaging"] = {"status": "PACKAGED" if all(chart.get("package_status") == "PACKAGED" for chart in chart_mappings) else "PARTIAL",
                                      "charts": chart_mappings}
            _remediation_stage(record, "package", "success" if validation["packaging"]["status"] == "PACKAGED" else "warning")
            if record.output_mode == "publish" and validation["status"] != "BLOCKING":
                _publish_remediation_charts(db, packaged_charts)
                for chart in chart_mappings:
                    _remediation_audit(db, record, "remediation.chart_publication", name=chart.get("name"),
                        version=chart.get("remediated_version"), status=chart.get("publish_status"), digest=chart.get("digest"))
            record.changed_artifacts = [*(record.changed_artifacts or []), *({"path": chart["path"],
                "changes": [f"Chart {chart['original_version']} → {chart['remediated_version']}",
                            f"Package: {chart.get('package_status', 'NOT RUN')}",
                            f"OCI: {chart.get('publish_status', 'NOT REQUESTED')}"]} for chart in chart_mappings)]
            # Runtime validation consumes finalized retained bytes below, through v2.
            validation["deployment"] = {"status": "NOT RUN", "detail": "Candidate packaging pending."}
            record.validation_results = validation
            validation["charts"] = chart_mappings
            original_files = payload.get("helm_source_files") or payload.get("source_files") or {}
            summary = build_remediation_summary(plan, original_files, files, validation, baseline_resources, rendered)
            for change, evidence in zip(plan["configuration_changes"], summary["configuration_decisions"]):
                change["post_scan_result"] = evidence["post_scan_result"]
            record.configuration_changes = plan["configuration_changes"]
            summary_documents = remediation_summary_artifacts(summary, original_files, files)
            validation["summary_of_changes"] = summary
            record.validation_results = validation
            record.after_snapshot = plan["after"]
            _remediation_stage(record, "output", "running")
            db.commit()
            if record.output_mode == "bundle":
                bundle_sources = [archive for archive, _ in packaged_charts]
                bundle_sources.extend(PATCH_JOB_ROOT / image["patch_job_id"] / "output" / "patched-image.tar"
                    for image in plan["images"] if image.get("patch_job_id"))
                if sum(path.stat().st_size for path in bundle_sources if path.is_file()) > 8 * 1024 ** 3:
                    raise ValueError("Remediation bundle exceeds the transfer size limit")
            with ZipFile(artifact, "w", ZIP_DEFLATED) as bundle:
                for document_path, document_content in summary_documents.items():
                    bundle.writestr(document_path, document_content)
                candidate_manifest = {
                    "schema_version": "cats.remediation/v1", "job_key": record.job_key,
                    "service_key": service.service_key, "output_mode": record.output_mode,
                    "created_at": record.created_at.isoformat() if record.created_at else None,
                    "original_revision": record.original_revision,
                    "source_execution_id": record.source_execution_id,
                    "source_version_id": record.source_version_id,
                    "revision_number": record.revision_number,
                    "values_files": values_files,
                    "images": [{"original": item.get("original"), "original_digest": item.get("original_digest"),
                                "remediated": item.get("candidate"),
                                "artifact_sha256": item.get("digest") if record.output_mode == "bundle" else None,
                                "remediated_digest": item.get("digest") if record.output_mode == "publish" else None,
                                "patch_status": item.get("patch_status"), "signature_status": item.get("signature_status"),
                                "evidence": item.get("remediation_evidence"),
                                "archive_path": f"images/{item['patch_job_id']}.tar" if record.output_mode == "bundle" and item.get("patch_job_id") else None,
                                "loaded_tag": f"cats-canonical-{item['patch_job_id']}:validated" if record.output_mode == "bundle" and item.get("patch_job_id") else None}
                               for item in plan["images"]],
                    "charts": chart_mappings,
                    "validation": validation.get("deployment"),
                }
                bundle.writestr("remediation-plan.yaml", plan_yaml(plan))
                bundle.writestr("README.txt", (
                    "CATS retained remediation candidate\n\n"
                    "This candidate is not an authoritative application release.\n"
                    "Review remediation-plan.yaml and before-after.json for applied changes,\n"
                    "unresolved findings, and unavailable evidence. Missing scan evidence is\n"
                    "not a clean scan. manifest.json records source and candidate references.\n\n"
                    "candidate/ contains editable Helm/Kubernetes source; helm/ contains\n"
                    "packaged charts when packaging succeeded. scans/ and sbom/ contain\n"
                    "available retained scanner evidence. Download-mode images/ archives\n"
                    "can be loaded with docker load --input <archive>. Before deploying,\n"
                    "retag and push loaded images to your approved registry and update chart\n"
                    "references to those immutable image digests. Do not substitute unrelated\n"
                    "images and treat previous validation as verification of that new render.\n\n"
                    "Delivery, signing, and runtime verification are separate results.\n"
                    "Intentionally re-ingest a reviewed release to promote it in CATS.\n"
                ))
                config_scan = candidate_dir / ".cats-config-scan.json"
                if config_scan.is_file():
                    bundle.write(config_scan, "scans/trivy-config-after.json")
                if rendered_path.is_file():
                    bundle.write(rendered_path, "scans/rendered-after.yaml")
                baseline_render = baseline_dir / ".cats-rendered.yaml"
                if baseline_render.is_file():
                    bundle.write(baseline_render, "scans/rendered-before.yaml")
                bundle.writestr("before-after.json", json.dumps({"before": plan["before"], "after": plan["after"]}, indent=2))
                for relative, content in sorted(files.items()):
                    safe = Path(relative.replace("\\", "/"))
                    if safe.is_absolute() or ".." in safe.parts:
                        raise ValueError(f"Unsafe source path in uploaded artifact: {relative}")
                    bundle.writestr(f"candidate/{safe.as_posix()}", content)
                for archive, chart in packaged_charts:
                    bundle.write(archive, f"helm/{archive.name}")
                if plan["images"]:
                    for image in plan["images"]:
                        patch_key = image.get("patch_job_id")
                        if not isinstance(patch_key, str) or not re.fullmatch(r"[0-9a-f]{32}", patch_key):
                            continue
                        output = PATCH_JOB_ROOT / patch_key / "output"
                        for name, archive_name in (("patched-image.tar", f"images/{patch_key}.tar"),
                                                   ("grype-before.json", f"scans/{patch_key}-grype-before.json"),
                                                   ("grype-after.json", f"scans/{patch_key}-grype-after.json"),
                                                   ("grype-full-after.json", f"scans/{patch_key}-grype-full-after.json"),
                                                   ("remediated-sbom.json", f"sbom/{patch_key}.json")):
                            if name == "patched-image.tar" and record.output_mode != "bundle":
                                continue
                            path = output / name
                            if path.is_file():
                                bundle.write(path, archive_name)
                if rendered_path.is_file():
                    bundle.write(rendered_path, "rendered.yaml")
                else:
                    bundle.writestr("rendered.yaml", "")
            # Reopen completed ZIP entries so Windows archive member names are canonical.
            with ZipFile(artifact, "a", ZIP_DEFLATED) as bundle:
                from .remediation_validation import deployment_manifest
                source_version = db.get(ServiceVersion, record.source_version_id) if record.source_version_id else None
                try:
                    candidate_manifest["deployment_manifest"] = deployment_manifest(bundle, candidate_dir=candidate_dir,
                        values_files=values_files, rendered=rendered_path.read_text(encoding="utf-8") if rendered_path.is_file() else "",
                        service={"id": service.service_key, "version": source_version.version} if source_version and source_version.service_id == record.service_id else None,
                        images=plan["images"])
                except (ValueError, OSError, tarfile.TarError) as exc:
                    candidate_manifest["deployment_manifest"] = None
                    validation["checks"]["candidate_integrity"] = {"status": "FAIL", "detail": "Candidate deployment inventory failed integrity checks."}
                    validation["required_checks"].append("candidate_integrity")
                    classify_static(validation)
                bundle.writestr("manifest.json", json.dumps(candidate_manifest, indent=2))
            # Retain the completed artifact before subsequent bookkeeping can fail.
            record.artifact_path = str(artifact)
            with artifact.open("rb") as artifact_stream:
                record.artifact_digest = "sha256:" + hashlib.file_digest(artifact_stream, "sha256").hexdigest()
            record.resulting_revision = f"R{record.revision_number}" if record.revision_number else record.job_key
            db.commit()
            _remediation_stage(record, "output", "success" if artifact.is_file() else "failed")
            _remediation_audit(db, record, "remediation.bundle_created" if record.output_mode == "bundle" else "remediation.candidate_created",
                output_mode=record.output_mode)
            record.validation_results = validation
            record.after_snapshot = plan["after"]
            record.scan_results = {
                "configuration": validation["checks"]["trivy_config_rescan"],
                "vulnerabilities": validation["checks"]["vulnerability_rescan"],
                "images": {image.get("patch_job_id"): image.get("remediation_evidence")
                           for image in plan["images"] if image.get("patch_job_id")},
            }
            record.artifact_path = str(artifact)
            automatic = [item for item in plan["configuration_changes"] if item["classification"] == "AUTO-REMEDIABLE"]
            automatic.extend(item for item in plan["images"] if item["classification"] == "AUTO-REMEDIABLE")
            review = [item for item in plan["configuration_changes"] if item["classification"] == "REVIEW REQUIRED"]
            review.extend(item for item in plan["images"] if item["classification"] == "REVIEW REQUIRED")
            unresolved_images = [item for item in plan["images"] if not item.get("candidate")]
            evidence_complete = all(all(value == "complete" for value in (image.get("remediation_evidence") or {}).values())
                                    and bool(image.get("remediation_evidence"))
                                    for image in plan["images"] if image.get("candidate"))
            if automatic and not files:
                raise ValueError("An automatic change had no editable source artifact")
            if review or unresolved_images:
                record.status = "review_required"
                record.logs = [*record.logs, "Candidate created; ambiguous source or image changes require review before validation and promotion."]
            elif automatic and validation["status"] != "BLOCKING":
                deployment_status = (validation.get("deployment") or {}).get("status")
                charts_complete = all(chart.get("package_status") == "PACKAGED" for chart in chart_mappings)
                chart_publication_ok = all(chart.get("publish_status") == "PUBLISHED" for chart in chart_mappings)
                if record.output_mode == "bundle":
                    record.status = "bundle_ready" if evidence_complete and charts_complete else "bundle_partial"
                elif not chart_publication_ok:
                    record.status = "publication_partial"
                elif not evidence_complete:
                    record.status = "evidence_partial"
                elif deployment_status == "VERIFIED":
                    record.status = "validated"
                elif deployment_status in {"FAILED", "PARTIALLY_VERIFIED"}:
                    record.status = "validation_failed"
                else:
                    record.status = "validation_unavailable"
                record.resulting_revision = f"R{record.revision_number}" if record.revision_number else record.job_key
                record.logs = [*record.logs, "Candidate retained; static, scan, packaging, delivery and runtime results are reported separately."]
            elif not automatic:
                record.status = "not_remediable"
                record.logs = [*record.logs, "No registered deterministic remediation could be applied."]
            else:
                record.status = "validation_blocked"
                record.failure_reason = "Blocking static validation defect; retained candidate requires correction"
            record.phase = "complete" if record.status != "failed" else "failed"
            record.remediation_status = ("failed" if record.status in {"failed", "not_remediable"} else
                                         "partial" if review or unresolved_images or not evidence_complete else "complete")
            publication_results = [chart.get("publish_status") == "PUBLISHED" for chart in chart_mappings]
            publication_results.extend(bool(image.get("candidate")) and bool(image.get("digest"))
                                       for image in plan["images"])
            record.delivery_status = ("not_delivered" if record.output_mode == "bundle" else
                                      "published" if publication_results and all(publication_results) else
                                      "partial" if any(publication_results) else "failed")
            deployment_status = (validation.get("deployment") or {}).get("status")
            record.verification_status = ("verified" if deployment_status == "VERIFIED" else
                                          "failed" if deployment_status in {"FAILED", "PARTIALLY_VERIFIED"} else
                                          "not_verified" if deployment_status in {None, "NOT RUN"} else "unavailable")
            signatures = [image.get("signature_status") for image in plan["images"] if image.get("candidate")]
            record.signing_status = ("failed" if "failed" in signatures else
                                     "verified" if signatures and all(value == "verified" for value in signatures) else
                                     "partial" if "verified" in signatures else "not_requested")
            with artifact.open("rb") as artifact_stream:
                record.artifact_digest = "sha256:" + hashlib.file_digest(artifact_stream, "sha256").hexdigest()
            record.completed_at = record.updated_at = utcnow()
            db.add(AuditEvent(actor_user_id=record.requested_by_id, action=f"remediation.{record.status}",
                              target_type="remediation_execution", target_id=str(record.id),
                              detail={"service_id": record.service_id, "job_key": record.job_key, "status": record.status}))
            db.commit()
            _validate_retained_remediation(db, record)
            if inputs.get("requested_delivery") in {"oci", "standard-bundle", "offline-bundle"} and record.remediation_status in {"complete", "partial"} and validation["status"] != "BLOCKING":
                try:
                    _queue_delivery(db, record, record.requested_by_id, inputs["requested_delivery"], inputs.get("destination_id", ""), inputs.get("verify_runtime", False))
                except Exception as delivery_error:
                    db.rollback()
                    record.delivery_status = "failed"
                    _remediation_audit(db, record, "remediation.delivery_failed", error=type(delivery_error).__name__)
                    db.commit()
        except Exception as exc:
            db.rollback()
            record = db.get(RemediationExecution, record_id)
            if record:
                failed_phase = record.phase
                if failed_phase in REMEDIATION_STAGES:
                    _remediation_stage(record, failed_phase, "failed", type(exc).__name__)
                record.status, record.phase = "failed", "failed"
                record.remediation_status = "failed"
                record.failure_reason = f"Remediation failed during {failed_phase}: {type(exc).__name__}"
                record.logs = [*(record.logs or []), record.failure_reason]
                record.completed_at = record.updated_at = utcnow()
                _remediation_audit(db, record, "remediation.failed", reason=type(exc).__name__)
                db.commit()
        finally:
            _cleanup_completed_remediations(db)


def _validate_retained_remediation(db, record):
    """Validate the same retained revision; never reapply decisions or image patches."""
    from .remediation_validation import classify_static, validation_result
    from .deployment_bundle import validate_bundle, file_digest
    from .validator_client import validate as validate_remote
    from .validator_protocol import REQUEST_SCHEMA_VERSION
    validation = deepcopy(record.validation_results or {})
    classify_static(validation)
    prior = deepcopy(validation.get("deployment") or {})
    resume_id = prior.get("validation_id") if prior.get("cleanup_status") in {"UNKNOWN", "FAILED"} else None
    request = prior.get("request") if resume_id else None
    try:
        if validation["status"] == "BLOCKING":
            record.verification_status = "blocked"
            validation["deployment"] = {"status": "BLOCKED", "detail": "Blocking static defects prevent runtime deployment."}
            _remediation_stage(record, "deployment_validation", "blocked")
            return
        path = retained_candidate(record, REMEDIATION_JOB_ROOT)
        manifest = validate_bundle(path, expected_type="standard-bundle", expected_digest=record.artifact_digest)
        configuration = validator_management.select_configuration(db,
            parse_json(get_global_configuration(db).get("validator_configuration"), {}), "standard-bundle")
        if not configuration.get("endpoint"):
            record.verification_status = "unavailable"
            validation["deployment"] = {**prior, "status": "UNAVAILABLE", "detail": "No healthy compatible managed validator or configured fallback is available.",
                                         "artifact_digest": record.artifact_digest}
            _remediation_stage(record, "deployment_validation", "unavailable")
            return
        if resume_id and (not request or prior.get("validator_id") != configuration.get("expected_validator_id")):
            raise ValueError("Interrupted validation must resume on its original validator with bound request evidence")
        request = request or {"schema_version": REQUEST_SCHEMA_VERSION, "request_id": uuid.uuid4().hex,
            "validation_type": "standard-bundle", "service": manifest["service"],
            "artifact": {"reference": record.job_key, "digest": record.artifact_digest},
            "deployment": {"type": "helm", "namespace": manifest["deployment"]["namespace"]}, "validation_profile": "default"}
        record.verification_status = "running"
        validation["deployment"] = {**prior, "status": "RUNNING", "request": request, "request_id": request["request_id"],
            "artifact_digest": record.artifact_digest, "validation_type": "standard-bundle", "service": manifest["service"]}
        record.validation_results = deepcopy(validation)
        _remediation_stage(record, "deployment_validation", "running")
        db.commit()
        def progress(phase):
            _remediation_stage(record, "deployment_validation", "running", phase)
            db.commit()
        last_state = None
        def state_changed(state):
            nonlocal last_state
            public = {key: state.get(key) for key in ("status", "validation_id", "validator_id", "phase")}
            if public != last_state:
                last_state = public
                validation["deployment"] = {**validation["deployment"], **public}
                record.validation_results = deepcopy(validation)
                db.commit()
        options = {"resume_validation_id": resume_id} if resume_id else {}
        result = validate_remote(configuration, request, artifact_path=path, progress_callback=progress, state_callback=state_changed, **options)
        if file_digest(path) != record.artifact_digest:
            raise ValueError("Retained candidate integrity mismatch after validation")
        evidence = validation_result(result, request)
        evidence["request"] = request
        validation["deployment"] = evidence
        status = evidence["status"]
        record.verification_status = "verified" if status == "VERIFIED" else "failed" if status in {"FAILED", "PARTIALLY_VERIFIED"} else "unavailable"
        _remediation_stage(record, "deployment_validation", "success" if record.verification_status == "verified" else record.verification_status,
                           evidence.get("detail") or "")
    except Exception as exc:
        # A failed attempt preserves remediation, scan, packaging, signing and delivery evidence.
        record.verification_status = "unavailable"
        validation["deployment"] = {**(validation.get("deployment") or {}), "request": request, "status": "UNAVAILABLE", "detail": f"Candidate validation unavailable ({type(exc).__name__}); inspect validator availability, artifact integrity and cleanup evidence.",
            "artifact_digest": record.artifact_digest, "request_id": request["request_id"] if request else None,
            "validation_id": (validation.get("deployment") or {}).get("validation_id"),
            "validator_id": (validation.get("deployment") or {}).get("validator_id"),
            "cleanup_status": "UNKNOWN" if request else "NOT_REQUIRED"}
        _remediation_stage(record, "deployment_validation", "unavailable", type(exc).__name__)
    finally:
        history = list(validation.get("runtime_attempts") or [])
        history.append(deepcopy(validation.get("deployment") or {}))
        validation["runtime_attempts"] = history[-20:]
        record.validation_results = validation
        record.updated_at = utcnow()
        _remediation_audit(db, record, "remediation.candidate_validation", status=record.verification_status,
                           artifact_digest=record.artifact_digest)
        db.commit()


def _recover_retained_candidate_validations():
    """An interrupted client cannot claim completion or retry without cleanup evidence."""
    with SessionLocal() as db:
        records = db.scalars(select(RemediationExecution).where(
            RemediationExecution.verification_status.in_(["queued", "running"]))).all()
        for record in records:
            validation = deepcopy(record.validation_results or {})
            prior = validation.get("deployment") or {}
            validation["deployment"] = {**prior, "status": "UNAVAILABLE", "cleanup_status": "UNKNOWN" if prior.get("request_id") else "NOT_REQUIRED",
                "detail": "Validation interrupted by portal restart. Verify remote job cleanup before retrying."}
            record.validation_results = validation
            record.verification_status = "unavailable"
            _remediation_stage(record, "deployment_validation", "unavailable", "Interrupted; cleanup unconfirmed")
        db.commit()


def _run_retained_remediation_validation(record_id):
    with SessionLocal() as db:
        record = db.get(RemediationExecution, record_id)
        if record:
            _validate_retained_remediation(db, record)


_CANDIDATE_VALIDATION_LOCK = threading.Lock()


@app.post("/services/{service_key}/remediations/{job_key}/validate")
def validate_remediation_candidate(service_key: str, job_key: str, csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    check_csrf(auth, csrf_token)
    with _CANDIDATE_VALIDATION_LOCK:
        record = db.scalar(select(RemediationExecution).join(Service).where(
            RemediationExecution.job_key == job_key, Service.service_key == service_key))
        if not record:
            raise HTTPException(404)
        if record.status in {"queued", "running"} or record.verification_status in {"queued", "running"}:
            raise HTTPException(409, detail="Candidate validation or remediation is already active")
        try:
            retained_candidate(record, REMEDIATION_JOB_ROOT)
        except ValueError as exc:
            raise HTTPException(409, detail=str(exc)) from None
        if (record.validation_results or {}).get("status") == "BLOCKING":
            raise HTTPException(409, detail="Blocking static defects require a corrected candidate")
        prior = (record.validation_results or {}).get("deployment") or {}
        if prior.get("cleanup_status") == "UNKNOWN" and not prior.get("validation_id"):
            raise HTTPException(409, detail="Cleanup is unconfirmed and no bound remote job is available to resume; reconcile the interrupted validator request before retrying")
        record.verification_status = "queued"
        _remediation_stage(record, "deployment_validation", "queued")
        db.commit()
        REMEDIATION_WORKERS.submit(_run_retained_remediation_validation, record.id)
    return RedirectResponse(f"/services/{service_key}/remediations/{job_key}", status_code=303)


def _cleanup_completed_remediations(db):
    """Cleanup must never replace the outcome of completed work."""
    try:
        result = cleanup_remediation_artifacts(db, REMEDIATION_JOB_ROOT)
        if result["removed"]:
            db.add(AuditEvent(action="remediation.retention_cleanup", target_type="remediation_execution",
                target_id="retention", detail={"job_keys": result["removed"], "removed_bytes": result["removed_bytes"]}))
        db.commit()
    except Exception:
        db.rollback()


def _queue_remediation(db: Session, auth: AuthContext, service: Service, finding_type: str | None = None,
                       finding_id: int | None = None, output_mode: str = "publish",
                       retry_of_id: int | None = None, workflow_inputs: dict | None = None) -> RemediationExecution:
    if not remediation_enabled(db):
        raise HTTPException(403, detail="Remediation is disabled by the administrator")
    retention = cleanup_remediation_artifacts(db, REMEDIATION_JOB_ROOT)
    db.commit()
    if retention["over_quota"]:
        raise HTTPException(409, detail="Retained remediation storage is full; allow active jobs to finish before retrying")
    if output_mode not in {"publish", "bundle"}:
        raise HTTPException(422, detail="Choose OCI publish or downloadable bundle")
    db.execute(select(Service.id).where(Service.id == service.id).with_for_update()).scalar_one()
    existing = db.scalar(select(RemediationExecution).where(
        RemediationExecution.service_id == service.id,
        RemediationExecution.status.in_(["queued", "running"])))
    if existing:
        raise HTTPException(409, detail="A remediation is already running for this service")
    if retry_of_id is not None:
        prior = db.get(RemediationExecution, retry_of_id)
        if not prior or prior.service_id != service.id:
            raise HTTPException(404, detail="Remediation retry source is unavailable")
        latest = db.get(Execution, prior.source_execution_id) if prior.source_execution_id else db.scalar(
            select(Execution).where(Execution.service_id == service.id, Execution.execution_key == prior.rollback_reference))
        if not latest or latest.service_id != service.id:
            raise HTTPException(422, detail="The retained remediation source is unavailable; retry cannot use a newer scan")
    else:
        latest = db.scalar(select(Execution).where(Execution.service_id == service.id).order_by(Execution.scanned_at.desc()))
    if not latest:
        raise HTTPException(422, detail="The service has no assessment execution to remediate")
    if workflow_inputs and latest.id != workflow_inputs.get("source_execution_id"):
        raise HTTPException(409, detail="The source scan changed; rebuild the remediation plan")
    job_key = f"R-{uuid.uuid4().hex[:12].upper()}"
    revision_number = (db.scalar(select(func.max(RemediationExecution.revision_number)).where(
        RemediationExecution.service_id == service.id,
        RemediationExecution.source_version_id == latest.service_version_id)) or 0) + 1
    source_version = db.get(ServiceVersion, latest.service_version_id) if latest.service_version_id else None
    record = RemediationExecution(job_key=job_key, service_id=service.id, requested_by_id=auth.user.id,
                                  finding_type=finding_type, finding_id=finding_id, status="queued", phase="queued",
                                  output_mode=output_mode, stages={}, workflow_inputs=workflow_inputs or {},
                                  retry_of_id=retry_of_id,
                                  source_execution_id=latest.id, source_version_id=latest.service_version_id,
                                  revision_number=revision_number,
                                  original_revision=source_version.version if source_version else latest.commit_sha or latest.execution_key,
                                  rollback_reference=latest.execution_key, logs=["Remediation request queued."])
    db.add(record); db.flush()
    original_run = db.scalar(select(DeploymentValidationRun).where(
        DeploymentValidationRun.execution_id == latest.id,
        DeploymentValidationRun.service_id == service.id,
        DeploymentValidationRun.artifact_type == "ORIGINAL",
    ).order_by(DeploymentValidationRun.created_at.desc()))
    if original_run:
        record.validation_results = {"original": {
            **(original_run.diagnostics or {}).get("schrodinger", {}),
            "status": original_run.status, "reason": original_run.reason,
            "validation_run_id": original_run.run_key,
            "source_execution_id": latest.id, "source_version_id": latest.service_version_id,
            "validated_at": original_run.completed_at.isoformat() if original_run.completed_at else None,
        }}
    record_audit(db, auth, "remediation.queued", "remediation_execution", record.id,
                 service_id=service.id, job_key=job_key, finding_type=finding_type, finding_id=finding_id,
                 output_mode=output_mode, retry_of_id=retry_of_id)
    db.commit()
    REMEDIATION_WORKERS.submit(_run_remediation_job, record.id)
    return record


def _remediation_destinations(db, service_id):
    rows = [service_oci.public_destination(row) for row in db.scalars(select(service_oci.ServiceOCIDestination).where(
        service_oci.ServiceOCIDestination.service_id == service_id))]
    for row in parse_json(get_global_configuration(db).get("oci_registries"), []):
        if isinstance(row, dict) and row.get("use_for_remediation") is True:
            rows.append({"id": f"global:{row.get('id')}", "name": row.get("name", "CATS default"),
                         "scope": "global", "endpoint": row.get("endpoint"), "namespace": row.get("namespace"),
                         "is_default": not any(item.get("is_default") for item in rows)})
    return rows


def _remediation_source_payload(execution) -> dict:
    """The exact evidence a remediation plan and its job are built from.

    Older retained executions may predate ingestion-time lineage and values
    joins. Reapply the same evidence-only joins to a copy (never to stored scan
    evidence) so the plan a manager approves and the job that executes it are
    derived identically.
    """
    payload = deepcopy(execution.raw_payload) if isinstance(execution.raw_payload, dict) else {}
    _enrich_rendered_resource_lineage(payload)
    _enrich_values_source_mappings(payload, payload.get("helm_source_files") or payload.get("source_files") or {})
    return payload


def _source_remediation_plan(db, service):
    execution = db.scalar(select(Execution).where(Execution.service_id == service.id).order_by(Execution.scanned_at.desc()))
    if not execution:
        raise HTTPException(422, "No source assessment is available")
    payload = _remediation_source_payload(execution)
    identities = {item.identity_key: item.id for item in db.scalars(select(PolicyFinding).where(PolicyFinding.service_id == service.id))}
    findings = []
    for item in payload.get("policy_findings") or []:
        values = policy_finding_values(item)
        findings.append(SimpleNamespace(id=identities.get(policy_finding_identity(values)), **values))
    try:
        _assert_bundle_sources_safe(payload.get("helm_source_files") or payload.get("source_files") or {})
    except ValueError:
        raise HTTPException(422, "Retained source contains unsupported secret material") from None
    return execution, build_plan(payload, findings, "PREVIEW")


@app.get("/services/{service_key}/remediations/plan")
def remediation_plan(service_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    execution, plan = _source_remediation_plan(db, service)
    return {"source_execution_id": execution.id, "plan_digest": plan_digest(plan),
            "configuration_changes": plan["configuration_changes"], "images": plan["images"]}


@app.post("/services/{service_key}/remediations/start")
def start_remediation(service_key: str, csrf_token: str = Form(), remediation_mode: str = Form(),
    decisions: str = Form("{}"), plan_digest: str = Form(), source_execution_id: int = Form(),
    output_mode: str = Form("bundle"), destination_id: str = Form(""), verify_runtime: str = Form("no"),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    execution, plan = _source_remediation_plan(db, service)
    if execution.id != source_execution_id or not secrets.compare_digest(plan_digest, globals()["plan_digest"](plan)):
        raise HTTPException(409, "The source plan changed; rebuild it before executing")
    try:
        choices = json.loads(decisions)
        resolve_decisions(plan, remediation_mode, choices, auth.user.id)
    except (ValueError, TypeError):
        raise HTTPException(422, "Invalid or incomplete remediation decisions") from None
    if output_mode not in {"bundle", "oci", "standard-bundle", "offline-bundle"}:
        raise HTTPException(422, "Invalid delivery mode")
    if output_mode == "oci":
        service_oci.resolve_destination(db, service.id, destination_id,
            parse_json(get_global_configuration(db).get("oci_registries"), []))
    inputs = {"remediation_mode": remediation_mode, "decisions": choices, "source_execution_id": source_execution_id,
              "plan_digest": plan_digest, "requested_delivery": output_mode, "destination_id": destination_id,
              "verify_runtime": verify_runtime == "yes"}
    record = _queue_remediation(db, auth, service, output_mode="bundle", workflow_inputs=inputs)
    return RedirectResponse(f"/services/{service_key}/remediations/{record.job_key}", status_code=303)


def _queue_delivery(db, record, actor_id, output_mode, destination_id="", verify_runtime=False):
    if (record.validation_results or {}).get("status") == "BLOCKING":
        raise HTTPException(409, detail="Candidate has blocking static validation defects")
    try:
        retained_candidate(record, REMEDIATION_JOB_ROOT)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    if record.status in {"queued", "running"}:
        raise HTTPException(409, "Remediation is still running")
    if record.remediation_status not in {"complete", "partial"}:
        raise HTTPException(409, "No validated remediation candidate is available for delivery")
    db.execute(select(RemediationExecution.id).where(RemediationExecution.id == record.id).with_for_update()).scalar_one()
    if db.scalar(select(DeliveryAttempt.id).where(DeliveryAttempt.remediation_id == record.id, DeliveryAttempt.status.in_(["queued", "running"]))):
        raise HTTPException(409, "A delivery is already running")
    if output_mode == "oci":
        destination = service_oci.resolve_destination(db, record.service_id, destination_id,
            parse_json(get_global_configuration(db).get("oci_registries"), []))
        public = {key: destination.get(key) for key in ("id", "name", "endpoint", "namespace", "scope")}
    elif output_mode == "bundle":
        public = {"id": "download", "name": "Portable download", "scope": "download"}
    elif output_mode in {"standard-bundle", "offline-bundle"}:
        public = {"id": output_mode, "name": "Offline Bundle" if output_mode == "offline-bundle" else "Standard Bundle",
                  "scope": "download", "validation_type": output_mode}
    else:
        raise HTTPException(422, "Invalid delivery mode")
    attempt = DeliveryAttempt(remediation_id=record.id, actor_id=actor_id, destination=public,
        content_digest=record.artifact_digest, status="download_ready" if output_mode == "bundle" else "queued",
        result={"verification_requested": True, "delivery_mode": output_mode})
    db.add(attempt); db.flush()
    if output_mode != "bundle":
        record.delivery_status = "queued"
    _remediation_audit(db, record, "remediation.delivery_requested", attempt_id=attempt.id, actor_id=actor_id, destination=public)
    db.commit()
    if output_mode != "bundle":
        REMEDIATION_WORKERS.submit(_run_delivery_attempt, attempt.id)
    return attempt


def _run_bundle_delivery(db, record, attempt):
    """Validate final immutable delivery bytes before exposing their download."""
    from . import remediation_bundles, validator_client
    from .deployment_bundle import file_digest
    mode = attempt.destination["validation_type"]
    try:
        version = db.get(ServiceVersion, record.source_version_id) if record.source_version_id else None
        if not version or version.service_id != record.service_id:
            raise ValueError("Retained service version identity is unavailable")
        bundle_settings = get_global_configuration(db)
        # Classic repository URLs come only from saved, active repositories for this service.
        repository_urls = db.scalars(select(ServiceArtifact.source_reference).where(
            ServiceArtifact.service_id == record.service_id,
            ServiceArtifact.artifact_type == "helm_repository", ServiceArtifact.lifecycle_status == "active",
        )).all()
        with remediation_bundles.configured_material(bundle_settings, [url for url in repository_urls if url]) as material:
            result, path = remediation_bundles.assemble(record, REMEDIATION_JOB_ROOT, attempt.id, mode, version.version,
                                                       configuration=material)
        attempt.artifact_path = path
        attempt.result = {**result, "delivery_mode": mode, "verification_requested": True}
        request = {"schema_version": "cats.validation/v2", "request_id": uuid.uuid4().hex, "validation_type": mode,
                   "service": {"id": record.service.service_key, "version": version.version},
                   "artifact": {"reference": Path(path).name, "digest": result["materialized_digest"]},
                   "deployment": {"type": "helm", "namespace": "cats-validation"}, "validation_profile": "default"}
        # Persist the final representation before the independent runtime request.
        db.commit()
        configuration = validator_management.select_configuration(db, parse_json(get_global_configuration(db).get("validator_configuration"), {}), mode)
        try:
            verification = validator_client.validate(configuration, request, artifact_path=path)
            from .remediation_validation import validation_result
            validation_result(verification, request)
        except Exception as exc:
            verification = {"status": "COULD_NOT_VALIDATE", "reason": f"Independent validation unavailable ({type(exc).__name__})",
                            "validation_type": mode, "service": request["service"], "artifact_digest": request["artifact"]["digest"]}
        if file_digest(path) != result["materialized_digest"]:
            verification = {"status": "FAILED", "reason": "Final artifact changed after validation", "artifact_digest": result["materialized_digest"],
                            "validation_type": mode, "service": request["service"]}
        matched = (verification.get("artifact_digest") == request["artifact"]["digest"] and verification.get("service") == request["service"]
                   and verification.get("validation_type") == mode)
        ready = verification.get("status") == "VERIFIED" and matched
        if mode == "offline-bundle":
            ready = ready and verification.get("offlineVerified") is True
        attempt.result = {**result, "delivery_mode": mode, "verification_requested": True, "verification": verification,
                          "download_url": f"/services/{record.service.service_key}/remediations/{record.job_key}/deliveries/{attempt.id}/bundle.zip" if ready else None}
        attempt.status = record.delivery_status = "download_ready" if ready else "validation_failed"
        record.verification_status = "verified" if ready else "failed" if verification.get("status") == "FAILED" else "not_verified"
        validation = dict(record.validation_results or {})
        validation["final_delivery_validations"] = [*(validation.get("final_delivery_validations") or []),
            {"attempt_id": attempt.id, "validation_type": mode, "artifact_digest": result["materialized_digest"],
             "source_execution_id": record.source_execution_id, "source_version_id": record.source_version_id,
             "validated_at": utcnow().isoformat(), "result": verification}]
        record.validation_results = validation
        _remediation_audit(db, record, "remediation.delivery_validated", attempt_id=attempt.id, validation_type=mode,
                           verification_status=verification.get("status"), materialized_digest=result["materialized_digest"], ready=ready)
    except Exception as exc:
        attempt.status = record.delivery_status = "failed"
        detail = redact(exc) if isinstance(exc, ValueError) else "Unexpected preparation error; review worker diagnostics."
        detail = re.sub(r"(https?://)[^/\s@]+@", r"\1[REDACTED]@", detail)
        detail = re.sub(r"(https?://[^\s?#]+)[?#][^\s]*", r"\1", detail)[:1000]
        message = f"Final bundle preparation failed ({type(exc).__name__}): {detail}"
        attempt.result = {**(attempt.result or {}), "error": message}
        diagnostics = REMEDIATION_JOB_ROOT / record.job_key / f"delivery-{attempt.id}-diagnostics.json"
        try:
            diagnostics.parent.mkdir(parents=True, exist_ok=True)
            diagnostics.write_text(json.dumps({"attempt_id": attempt.id, "error": message}, indent=2), encoding="utf-8")
        except OSError:
            # The durable delivery record still preserves the diagnosis if the disk is full.
            pass
        _remediation_audit(db, record, "remediation.delivery_failed", attempt_id=attempt.id, error=type(exc).__name__)
    attempt.completed_at = utcnow()
    db.commit()
    _cleanup_completed_remediations(db)


def _run_delivery_attempt(attempt_id):
    with SessionLocal() as db:
        attempt = db.get(DeliveryAttempt, attempt_id)
        record = db.get(RemediationExecution, attempt.remediation_id) if attempt else None
        if not record:
            return
        attempt.status = "running"; record.delivery_status = "running"; db.commit()
        if attempt.destination.get("validation_type") in {"standard-bundle", "offline-bundle"}:
            _run_bundle_delivery(db, record, attempt)
            return
        try:
            destination = service_oci.resolve_destination(db, record.service_id, attempt.destination["id"],
                parse_json(get_global_configuration(db).get("oci_registries"), []))
            attempt.destination = {key: destination.get(key) for key in ("id", "name", "endpoint", "namespace", "scope")}
            settings = get_global_configuration(db)
            signing_config, signing_credentials = signing.job_material(settings, "push")
            delivery_options = {"signing_material": (signing_config, signing_credentials)} if signing_config else {}
            result, attempt.artifact_path = deliver(record, destination, attempt.id, REMEDIATION_JOB_ROOT, **delivery_options)
            record.signing_status = result.get("signing_status", "not_requested")
            attempt.result = {**result, "verification_requested": True, "delivery_mode": "oci"}
            attempt.status = "staged"; record.delivery_status = "staged"
            db.commit()
            # Registry upload is staging, not evidence of runtime validation.
            # Release exactly these immutable identities only after validation.
            from .remediation_verification import verify_delivery
            try:
                version = db.get(ServiceVersion, record.source_version_id) if record.source_version_id else None
                if not version or version.service_id != record.service_id:
                    raise ValueError("Retained service version identity is unavailable")
                verification = verify_delivery(record, {**result, "artifact_path": attempt.artifact_path,
                    "service": {"id": record.service.service_key, "version": version.version}},
                    validator_management.select_configuration(db, parse_json(get_global_configuration(db).get("validator_configuration"), {}), 'oci'), REMEDIATION_JOB_ROOT)
            except Exception:
                verification = {"status": "verification_unavailable", "detail": "Sandbox verification unavailable"}
            attempt.result = {**result, "verification_requested": True, "delivery_mode": "oci", "validation_type": "oci", "verification": verification}
            record.verification_status = verification["status"]
            attempt.status = record.delivery_status = "published" if verification["status"] == "verified" else "validation_failed"
            _remediation_audit(db, record, "remediation.verification_completed", attempt_id=attempt.id,
                verification_status=verification["status"], artifact_digest=verification.get("artifact_digest"))
            validation = dict(record.validation_results or {})
            validation["final_delivery_validations"] = [*(validation.get("final_delivery_validations") or []),
                {"attempt_id": attempt.id, "validation_type": "oci", "source_version_id": record.source_version_id,
                 "source_execution_id": record.source_execution_id, "validated_at": utcnow().isoformat(),
                 "artifact_digest": result.get("materialized_digest"), "verification": attempt.result.get("verification")}]
            validation["artifact_identities"] = [*(validation.get("artifact_identities") or []),
                *[{**identity, "signature_status": identity.get("signature_status", "not_requested"), "verification": attempt.result.get("verification") or {"status": "not_verified"}}
                  for identity in result.get("artifact_identities", [])]]
            record.validation_results = validation
            _remediation_audit(db, record, "remediation.delivery_published" if attempt.status == "published" else "remediation.delivery_validation_failed", attempt_id=attempt.id, destination=attempt.destination,
                content_digest=attempt.content_digest, materialized_digest=result.get("materialized_digest"))
        except Exception as exc:
            attempt.status = "failed"; record.delivery_status = "failed"
            attempt.result = {"error": f"Delivery failed ({type(exc).__name__}); check destination access, credentials, trust, and retained artifacts."}
            _remediation_audit(db, record, "remediation.delivery_failed", attempt_id=attempt.id, error=type(exc).__name__)
        attempt.completed_at = utcnow(); db.commit()
        _cleanup_completed_remediations(db)


@app.post("/services/{service_key}/remediations/{job_key}/delivery")
def redeliver_remediation(service_key: str, job_key: str, csrf_token: str = Form(), output_mode: str = Form(),
    destination_id: str = Form(""), verify_runtime: str = Form("no"), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    check_csrf(auth, csrf_token)
    record = db.scalar(select(RemediationExecution).join(Service).where(RemediationExecution.job_key == job_key,
        Service.service_key == service_key))
    if not record:
        raise HTTPException(404)
    _queue_delivery(db, record, auth.user.id, output_mode, destination_id, verify_runtime == "yes")
    target = "candidate.zip" if output_mode == "bundle" else ""
    return RedirectResponse(f"/services/{service_key}/remediations/{job_key}" + (f"/{target}" if target else ""), status_code=303)


@app.get("/services/{service_key}/remediations/{job_key}/deliveries/{attempt_id}/bundle.zip")
def remediation_delivery_bundle(service_key: str, job_key: str, attempt_id: int, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    from .deployment_bundle import file_digest
    record = db.scalar(select(RemediationExecution).join(Service).where(RemediationExecution.job_key == job_key, Service.service_key == service_key))
    attempt = db.get(DeliveryAttempt, attempt_id)
    if not record or not attempt or attempt.remediation_id != record.id or attempt.status != "download_ready" or not attempt.artifact_path:
        raise HTTPException(404, "Validated final delivery is not available")
    root = Path(REMEDIATION_JOB_ROOT).resolve()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", record.job_key or ""):
        raise HTTPException(409, "Final delivery ownership check failed")
    expected = root / record.job_key / f"delivery-{attempt.id}.zip"
    path = Path(attempt.artifact_path)
    result = attempt.result or {}
    evidence = result.get("verification") or {}
    digest = result.get("materialized_digest")
    if (path.is_symlink() or any(parent.is_symlink() for parent in path.parents) or not path.is_file() or path.resolve() != expected.resolve()
            or expected.resolve().parent.parent != root or not isinstance(digest, str)
            or evidence.get("status") != "VERIFIED" or evidence.get("artifact_digest") != digest
            or not secrets.compare_digest(file_digest(path), digest)):
        raise HTTPException(409, "Final delivery integrity check failed")
    return FileResponse(path, media_type="application/zip", filename=f"cats-{service_key}-{job_key}-{attempt.destination.get('validation_type', 'delivery')}.zip")


@app.post("/services/{service_key}/remediate")
def remediate_service(service_key: str, csrf_token: str = Form(), output_mode: str = Form("publish"), db: Session = Depends(get_db),
                      auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    record = _queue_remediation(db, auth, service, output_mode=output_mode)
    return RedirectResponse(f"/services/{service_key}/remediations/{record.job_key}", status_code=303)


@app.post("/services/{service_key}/policy-findings/{finding_id}/remediate")
def remediate_policy_finding(service_key: str, finding_id: int, csrf_token: str = Form(), db: Session = Depends(get_db),
                              auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    check_csrf(auth, csrf_token)
    finding = db.scalar(select(PolicyFinding).where(PolicyFinding.id == finding_id).options(selectinload(PolicyFinding.service)))
    if not finding or finding.service.service_key != service_key:
        raise HTTPException(404)
    record = _queue_remediation(db, auth, finding.service, "configuration", finding.id)
    return RedirectResponse(f"/services/{service_key}/remediations/{record.job_key}", status_code=303)


@app.post("/services/{service_key}/findings/{finding_id}/remediate")
def remediate_vulnerability_finding(service_key: str, finding_id: int, csrf_token: str = Form(), db: Session = Depends(get_db),
                                     auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    check_csrf(auth, csrf_token)
    finding = db.scalar(select(Finding).where(Finding.id == finding_id).options(selectinload(Finding.service)))
    if not finding or finding.service.service_key != service_key:
        raise HTTPException(404)
    record = _queue_remediation(db, auth, finding.service, "vulnerability", finding.id)
    return RedirectResponse(f"/services/{service_key}/remediations/{record.job_key}", status_code=303)


@app.get("/services/{service_key}/remediations/{job_key}", response_class=HTMLResponse)
def remediation_report(service_key: str, job_key: str, request: Request, db: Session = Depends(get_db),
                       auth: AuthContext = Depends(require_permission("service.view", scoped=True))):
    record = db.scalar(select(RemediationExecution).where(RemediationExecution.job_key == job_key).options(selectinload(RemediationExecution.service)))
    if not record or record.service.service_key != service_key:
        raise HTTPException(404)
    record.delivery_attempts = db.scalars(select(DeliveryAttempt).where(
        DeliveryAttempt.remediation_id == record.id).order_by(DeliveryAttempt.id.desc())).all()
    return templates.TemplateResponse(request, "remediation_report.html", page_context(auth, job=record, service=record.service,
        remediation_enabled=remediation_enabled(db), oci_destinations=_remediation_destinations(db, record.service_id)))


@app.post("/services/{service_key}/remediations/{job_key}/retry")
def retry_remediation(service_key: str, job_key: str, csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True))):
    check_csrf(auth, csrf_token)
    prior = db.scalar(select(RemediationExecution).join(Service).where(
        RemediationExecution.job_key == job_key, Service.service_key == service_key).options(selectinload(RemediationExecution.service)))
    if not prior:
        raise HTTPException(404)
    if prior.status in {"queued", "running"}:
        raise HTTPException(409, detail="The remediation job is still active")
    record = _queue_remediation(db, auth, prior.service, prior.finding_type, prior.finding_id,
                                prior.output_mode, retry_of_id=prior.id)
    return RedirectResponse(f"/services/{service_key}/remediations/{record.job_key}", status_code=303)


@app.get("/services/{service_key}/remediations/{job_key}/candidate.zip")
def remediation_candidate(service_key: str, job_key: str, db: Session = Depends(get_db),
                          auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    record = db.scalar(select(RemediationExecution).join(Service).where(
        RemediationExecution.job_key == job_key, Service.service_key == service_key))
    if not record or not record.artifact_path:
        raise HTTPException(404, detail="Remediation candidate is not available")
    try:
        path = retained_candidate(record, REMEDIATION_JOB_ROOT)
    except ValueError as error:
        if str(error) == "Retained candidate integrity mismatch":
            detail = "The retained candidate does not match its saved checksum. Download is blocked; create a new candidate using Retry as new job."
        else:
            detail = "The retained candidate file is missing or is outside this job's storage location. Check candidate storage availability, or create a new candidate using Retry as new job."
        raise HTTPException(409, detail=detail) from None
    return FileResponse(path, media_type="application/zip", filename=f"cats-{service_key}-{job_key}.zip")


@app.get("/api/v1/services/{service_key}/remediations/{job_key}")
def remediation_job_status(service_key: str, job_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.view", scoped=True))):
    record = db.scalar(select(RemediationExecution).join(Service).where(
        RemediationExecution.job_key == job_key, Service.service_key == service_key))
    if not record:
        raise HTTPException(404)
    return {"job_key": record.job_key, "status": record.status, "phase": record.phase,
            "revision_number": record.revision_number, "source_execution_id": record.source_execution_id,
            "source_version_id": record.source_version_id, "artifact_digest": record.artifact_digest,
            "remediation_status": record.remediation_status, "delivery_status": record.delivery_status,
            "verification_status": record.verification_status, "signing_status": record.signing_status,
            "output_mode": record.output_mode, "retry_of_id": record.retry_of_id, "stages": record.stages or {},
            "started_at": record.started_at, "completed_at": record.completed_at,
            "images": [{"original": row.get("original"), "remediated": row.get("candidate"),
                        "patch_status": row.get("patch_status"), "signature_status": row.get("signature_status")}
                       for row in record.patched_images or []],
            "validation": record.validation_results or {},
            "delivery_attempts": [attempt_dto(row) for row in db.scalars(select(DeliveryAttempt).where(
                DeliveryAttempt.remediation_id == record.id).order_by(DeliveryAttempt.id))],
            "download_url": f"/services/{service_key}/remediations/{job_key}/candidate.zip" if record.artifact_path else None}


@app.post("/services/{service_key}/deployment-validations")
def rerun_deployment_validation(
    request: Request, service_key: str, artifact_id: int | None = Form(default=None), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("remediation.execute", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.executions)))
    if not service:
        raise HTTPException(404)
    if not deployment_validation_enabled():
        raise HTTPException(409, detail="Deployment Validation is disabled by configuration")
    execution = latest_eligible_helm_execution(service.executions)
    artifact_type = "ORIGINAL"
    artifact_reference = execution.execution_key if execution else None
    artifact_revision_id = None
    source_files_override = None
    if artifact_id is not None:
        artifact = db.scalar(select(ServiceArtifact).where(ServiceArtifact.id == artifact_id, ServiceArtifact.service_id == service.id).options(selectinload(ServiceArtifact.revisions)))
        if not artifact or artifact.artifact_type not in {"helm", "helm_chart"}:
            raise HTTPException(404, detail="A concrete Helm chart artifact was not found")
        revision = max(artifact.revisions, key=lambda item: item.revision_number, default=None)
        if not revision:
            raise HTTPException(409, detail="Select and materialize a concrete chart version before Deployment Validation")
        _chart_identity(dict(revision.files or {}))
        artifact_type = "WORKING"
        artifact_reference = f"artifact:{artifact.id}:r{revision.revision_number}"
        artifact_revision_id = revision.id
        source_files_override = dict(revision.files or {})
    elif not execution:
        raise HTTPException(409, detail="No Helm scan with retained source files is available for Deployment Validation")
    run, schedule = _new_validation_run(db, service, execution, requested_by_id=auth.user.id,
                                        artifact_type=artifact_type, artifact_reference=artifact_reference,
                                        artifact_revision_id=artifact_revision_id,
                                        source_files_override=source_files_override)
    db.commit()
    if schedule:
        _submit_validation_run(run.id)
    if "application/json" in request.headers.get("accept", "").lower():
        return JSONResponse(jsonable_encoder({"run": deployment_validation_view(run), "run_id": run.run_key,
                             "url": f"/services/{service_key}?validation=true&validation_run={urllib.parse.quote(run.run_key)}"}))
    return RedirectResponse(f"/services/{service_key}?validation=true&validation_run={urllib.parse.quote(run.run_key)}", status_code=303)


@app.get("/api/v1/services/{service_key}/deployment-validations")
def deployment_validation_history(
    service_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.view", scoped=True)),
):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    runs = db.scalars(select(DeploymentValidationRun).where(
        DeploymentValidationRun.service_id == service.id,
    ).options(selectinload(DeploymentValidationRun.execution)).order_by(DeploymentValidationRun.created_at.desc()).limit(100)).all()
    return {"service_id": service.service_key, "latest_run_id": runs[0].run_key if runs else None,
            "runs": [deployment_validation_view(item) for item in runs]}


@app.get("/api/v1/services/{service_key}/deployment-validations/{run_key}")
def deployment_validation_result(
    service_key: str, run_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.view", scoped=True)),
):
    run = db.scalar(select(DeploymentValidationRun).join(Service).where(
        Service.service_key == service_key, DeploymentValidationRun.run_key == run_key,
    ).options(selectinload(DeploymentValidationRun.execution)))
    if not run:
        raise HTTPException(404)
    return deployment_validation_view(run)


@app.get("/api/v1/services/{service_key}/architecture-evidence")
def architecture_evidence_result(
    service_key: str, view_version: str = "", summary: bool = False, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.view", scoped=True)),
):
    """Architecture verification state, graph and active validation for polling.

    Selection uses execution summary metadata; at most one retained payload is
    read, and only when the content-keyed graph cache misses.  ``summary=true``
    returns graph summary counts without nodes, relationships or layouts.
    """
    from .evidence_reads import architecture_execution as select_architecture_execution
    from .evidence_reads import execution_metadata, execution_payload, latest_working_revision_id, version_execution_ids
    from .validation_queries import applicable_run, latest_run, runtime_identity
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    execution_ids = None
    if view_version:
        try:
            execution_ids = version_execution_ids(db, service, view_version)
        except ValueError as exc:
            raise HTTPException(404, detail=str(exc)) from exc
    execution = select_architecture_execution(execution_metadata(db, service.id, execution_ids=execution_ids))
    from .evidence_reads import architecture_metadata
    meta = architecture_metadata(db, execution)
    # A selected release is immutable evidence, including when its label is
    # currently deployed. Never attach today's mutable working revision.
    working_revision_id = None if view_version else latest_working_revision_id(db, service.id)
    subject = dict(execution_id=execution.id if execution and not working_revision_id else None,
                   artifact_revision_id=working_revision_id)
    run = applicable_run(db, service.id, execution_ids=execution_ids, **subject)
    state = architecture_verification(
        applicable=bool(meta.get("applicable")), declared_count=int(meta.get("declared_resources") or 0),
        runs=[run] if run else [], **subject)
    runtime = deployment_validation_view(state.get("run"))
    newest = deployment_validation_view(latest_run(db, service.id, execution_ids=execution_ids))
    if execution:
        graph = build_architecture_graph(lambda: execution_payload(db, execution.id), runtime_evidence=runtime,
            layouts=not summary,
            # No digest (bulk-edited evidence) means no content identity: never cache.
            cache_key=("execution", execution.id, execution.payload_digest, runtime_identity(state.get("run")))
            if execution.payload_digest else None)
    else:
        graph = build_architecture_graph({}, runtime_evidence=runtime, layouts=not summary)
    if summary:
        graph = {"summary": graph.get("summary", {})}
    return jsonable_encoder({
        "architecture": architecture_summary_json(state),
        "graph": graph,
        "active_validation": newest if newest and not newest.get("terminal") else None,
    })


@app.get("/cybersecurity", response_class=HTMLResponse)
def cybersecurity_dashboard(request: Request, q: str = "", status: str = "all", attention: str = "all",
    severity: str = "all", component: str = "", since: str = "",
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    if auth.accessible_service_ids("service.view") == set():
        raise HTTPException(403, detail="Permission denied")
    return templates.TemplateResponse(request, "cybersecurity.html", page_context(auth,
        dashboard_url="/api/dashboard/cybersecurity" + ("?" + str(request.query_params) if request.query_params else "")))


@app.get("/api/dashboard/cybersecurity")
def cybersecurity_portfolio_data(request: Request, q: str = "", status: str = "all", attention: str = "all",
    severity: str = "all", component: str = "", since: str = "", page: int = 1,
    page_size: int = 50, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    from .dashboard_portfolio import portfolio
    started = time.perf_counter()
    data = portfolio(db, auth, q=q, status=status, attention=attention, severity=severity,
                     component=component, since=since, page=page, page_size=page_size)
    data["timings"] = {"portfolio_ms": round((time.perf_counter() - started) * 1000, 2)}
    request.state.snapshot_timings = data["timings"]
    return JSONResponse(data, headers={"Cache-Control": "no-store"})


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, archived: bool = False, lifecycle: str = "active", q: str = "", sort: str = "name",
              page: int = 1, page_size: int = 50, db: Session = Depends(get_db), auth: AuthContext | None = Depends(optional_user)):
    if not auth:
        return templates.TemplateResponse(request, "home.html", {
            "current_user": None, "csrf_token": "", "can": lambda _permission: False,
            "themes": THEMES, "pending_request_count": 0, "pending_poam_count": 0,
        })
    return templates.TemplateResponse(request, "dashboard.html", page_context(auth,
        dashboard_url="/api/dashboard/services" + ("?" + str(request.query_params) if request.query_params else "")))


@app.get("/api/dashboard/services")
def dashboard_services_data(request: Request, archived: bool = False, lifecycle: str = "active", q: str = "", sort: str = "name",
                            page: int = 1, page_size: int = 50, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    request_started = time.perf_counter()
    stage_timings = {}
    now = utcnow()
    stage_started = time.perf_counter()
    configuration = get_configuration(db)
    stage_timings["configuration_ms"] = round((time.perf_counter() - stage_started) * 1000, 2)
    now_display = configured_time(now, include_time=True, configuration=configuration)
    stage_started = time.perf_counter()
    services, configurations = _overview_services_and_configurations(db, auth, configuration, projected=True)
    views, poam_counts = service_overview_rows_aggregated(db, auth, now, configuration, services, configurations)
    stage_timings["overview_aggregation_ms"] = round((time.perf_counter() - stage_started) * 1000, 2)
    stage_started = time.perf_counter()
    if archived:
        lifecycle = "archived"
    if lifecycle not in {"active", "staged", "archived"}:
        raise HTTPException(422, detail="Unknown service lifecycle")
    from .dashboard_paging import dashboard_page
    views, visible_all, lifecycle_counts, sort, page, page_size, total_pages = dashboard_page(
        db, views, lifecycle=lifecycle, query=q, sort=sort,
        descending=request.query_params.get("direction") == "desc", page=page, page_size=page_size)
    total_count = len(visible_all)
    dashboard_params = [("lifecycle", lifecycle), ("q", q), ("sort", sort), ("page_size", page_size)]
    pagination_base = "/?" + urllib.parse.urlencode([(key, value) for key, value in dashboard_params if value not in (None, "")])
    visible_ids = [view["service"].id for view in visible_all]
    visible_poam = [poam_counts.get(service_id, {"active": 0, "pending": 0, "overdue": 0}) for service_id in visible_ids]
    stage_timings["filter_sort_ms"] = round((time.perf_counter() - stage_started) * 1000, 2)
    stage_started = time.perf_counter()
    stage_groups = manageable_groups(db, auth) if auth.has("user.manage") else []
    stage_timings["authorization_groups_ms"] = round((time.perf_counter() - stage_started) * 1000, 2)
    stage_started = time.perf_counter()
    context = page_context(auth,
        views=views, now=now, now_display=now_display,
        compliant_count=sum(v["compliant"] for v in visible_all),
        noncompliant_count=sum(not v["compliant"] for v in visible_all),
        showing_archived=lifecycle == "archived", lifecycle=lifecycle, lifecycle_counts=lifecycle_counts,
        query=q, sort=sort, page=page, page_size=page_size, total_count=total_count, total_pages=total_pages,
        pagination_base=pagination_base,
        overdue_days=int(configuration["overdue_days"]),
        poam_active_count=sum(item["active"] for item in visible_poam),
        poam_pending_count=sum(item["pending"] for item in visible_poam),
        poam_overdue_count=sum(item["overdue"] for item in visible_poam),
        stage_groups=stage_groups if lifecycle == "active" else [],
    )
    stage_timings["page_context_ms"] = round((time.perf_counter() - stage_started) * 1000, 2)
    stage_timings["route_ms"] = round((time.perf_counter() - request_started) * 1000, 2)
    request.state.snapshot_timings = stage_timings
    from .frontend import page_data
    return JSONResponse(page_data(request, "dashboard.html", context)["data"], headers={"Cache-Control": "no-store"})


@app.get("/api/dashboard/cybersecurity/services/{service_key}/history")
def cybersecurity_service_history(service_key: str, request: Request, db: Session = Depends(get_db),
                                  auth: AuthContext = Depends(require_user)):
    started = time.perf_counter()
    allowed = auth.accessible_service_ids("service.view")
    query = select(Service).where(Service.service_key == service_key)
    if allowed is not None:
        query = query.where(Service.id.in_(allowed))
    service = db.scalar(query)
    if service is None:
        raise HTTPException(404, detail="Service not found")
    from .security_dashboard import bounded_service_history
    result = bounded_service_history(db, service)
    request.state.snapshot_timings = {"history_ms": round((time.perf_counter() - started) * 1000, 2)}
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/exports/services.xlsx")
def export_services(db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    now = utcnow()
    configuration = get_configuration(db)
    allowed = auth.accessible_service_ids("service.export")
    if allowed == set():
        raise HTTPException(403, detail="Permission denied")
    # Keep the exact Python name ordering without retaining every service graph.
    service_query = select(Service.id, Service.name)
    if allowed is not None:
        service_query = service_query.where(Service.id.in_(allowed))
    service_ids = [row.id for row in sorted(db.execute(service_query), key=lambda row: row.name.lower())]
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Service Snapshot"
    sheet.append([
        "Service ID", "Service", "Version", "Owner", "POC", "Groups", "Lifecycle", "Compliance",
        "Evidence", "Active Findings", "Overdue Findings", "Active Exceptions",
        "Resolved", "Oldest Active (Days)", "Last Execution",
    ])
    # Each batch owns a separate identity map, so completed evidence graphs
    # cannot accumulate in the request session while the workbook grows.
    for offset in range(0, len(service_ids), 50):
        batch_ids = service_ids[offset:offset + 50]
        with Session(bind=db.connection()) as export_db:
            services = export_db.scalars(select(Service).where(Service.id.in_(batch_ids)).options(
                selectinload(Service.findings).selectinload(Finding.exceptions),
                selectinload(Service.findings).selectinload(Finding.observations),
                selectinload(Service.policy_findings).selectinload(PolicyFinding.exceptions),
                selectinload(Service.executions).defer(Execution.raw_payload), selectinload(Service.archive_events),
                selectinload(Service.groups), selectinload(Service.current_version),
                selectinload(Service.poam_entries),
            )).all()
            configurations = configurations_for_services(export_db, services, configuration)
            services_by_id = {service.id: service for service in services}
            for service_id in batch_ids:
                view = service_view(services_by_id[service_id], now, configurations[service_id])
                sheet.append([
                    view["service"].service_key, view["service"].name, view["version"],
                    view["service"].owner, view["service"].poc, ", ".join(group.name for group in view["service"].groups), "Archived" if view["archive"] else "Active",
                    "Compliant" if view["compliant"] else "Non-Compliant",
                    view["evidence_state"], len(view["active"]) + len(view["policy_findings"]),
                    len(view["noncompliant"]) + len(view["policy_noncompliant"]),
                    len(view["excepted"]) + len(view["policy_excepted"]),
                    len(view["resolved"]) + len(view["policy_resolved"]), view["oldest_age"],
                    excel_datetime(view["last_execution"]),
                ])
        del services, services_by_id, view
    for cell in sheet["M"][1:]:
        cell.number_format = "yyyy-mm-dd hh:mm"
    format_sheet(sheet)
    return workbook_response(workbook, f"cats-service-posture-{now:%Y%m%d}.xlsx")


def _finding_search_text(finding: Finding) -> str:
    """Build a bounded, user-facing search surface for a vulnerability."""
    values = [finding.cve, finding.severity]
    for observation in sorted((finding.observations or []), key=lambda item: item.id, reverse=True)[:20]:
        values.extend((observation.image, observation.package, observation.installed_version, observation.fixed_version))
    return " ".join(str(value)[:500] for value in values if value).casefold()


def _policy_finding_search_text(finding: PolicyFinding) -> str:
    return " ".join(str(value) for value in (
        finding.finding, finding.severity, finding.scanner, finding.framework,
        finding.target, finding.namespace, finding.title, finding.description,
    ) if value).casefold()[:5000]


def _filter_service_finding_groups(groups: dict[str, list], *, query: str = "", severities: list[str] | None = None, resource: str = "") -> dict[str, list]:
    """Filter already-authorized service findings before sorting/pagination."""
    needle = query.strip().casefold()
    severity_set = {value.strip().casefold() for value in (severities or []) if value.strip()}
    resource_needle = resource.strip().casefold()

    def keep(item: Any) -> bool:
        if isinstance(item, Finding) or hasattr(item, "cve"):
            text_value = _finding_search_text(item)
            severity_value = str(item.severity or "").casefold()
        elif isinstance(item, PolicyFinding) or hasattr(item, "finding"):
            text_value = _policy_finding_search_text(item)
            severity_value = str(item.severity or "").casefold()
        elif isinstance(item, dict):
            text_value = " ".join(str(value)[:500] for value in (item.get("item"), item.get("reason"), item.get("type"), item.get("evidence_image"), item.get("target"), item.get("namespace"), *(item.get("images") or [])) if value).casefold()
            severity_value = str(item.get("severity") or "").casefold()
        else:
            return False
        return (not needle or needle in text_value) and (not severity_set or severity_value in severity_set) and (not resource_needle or resource_needle in text_value)

    return {key: [item for item in values if keep(item)] for key, values in groups.items()}


def _artifact_file_path(value: str) -> str:
    normalized = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(normalized)
    if not normalized or "\x00" in normalized or re.match(r"^[A-Za-z]:", normalized) or path.is_absolute() or ".." in path.parts or len(normalized) > 500:
        raise HTTPException(422, detail="Artifact file path is unsafe")
    return "/".join(part for part in path.parts if part not in {"", "."})


def _artifact_text(value: str, *, max_bytes: int = 2 * 1024 * 1024) -> str:
    text_value = str(value or "")
    encoded = text_value.encode("utf-8")
    if len(encoded) > max_bytes or b"\x00" in encoded:
        raise HTTPException(422, detail="Artifact files must be bounded UTF-8 text")
    return text_value


def _artifact_revision(files: dict[str, str], *, artifact_id: int, number: int, label: str, user_id: int | None,
                       source_metadata: dict | None = None) -> ServiceArtifactRevision:
    safe_files = {_artifact_file_path(name): _artifact_text(content) for name, content in files.items()}
    max_source_bytes = int(os.getenv("CATS_ARTIFACT_SOURCE_MAX_BYTES", str(100 * 1024 * 1024)))
    if sum(len(k.encode()) + len(v.encode()) for k, v in safe_files.items()) > max_source_bytes:
        raise HTTPException(422, detail="Artifact source exceeds the configured size limit")
    checksum = hashlib.sha256(json.dumps(safe_files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ServiceArtifactRevision(artifact_id=artifact_id, revision_number=number, revision_label=label,
                                   files=safe_files, checksum=checksum, immutable=True, created_by_id=user_id,
                                   source_metadata=source_metadata or {})


@app.get('/api/v1/services/{service_key}/findings/simplified/{group_id}/members')
def simplified_members(service_key: str, group_id: str, page: int = 1, page_size: int = 50,
        finding_state: str = 'active', finding_type: str = 'all', q: str = '', resource: str = '',
        severity: list[str] = Query(default=[]), db: Session = Depends(get_db),
        auth: AuthContext = Depends(require_permission('service.view', scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    if not auth.has('service.view', service.id):
        raise HTTPException(403)
    if page_size not in {50, 100, 250}:
        raise HTTPException(422, detail='Page size must be 50, 100, or 250')
    latest = db.scalar(select(Execution.id).where(Execution.service_id == service.id)
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    from .simplified_queries import member_page
    try:
        return member_page(db, service, SimpleNamespace(id=latest) if latest else None, utcnow(),
            configuration_for_service(db, service), group_id, page=page, page_size=page_size,
            state=finding_state, finding_type=finding_type, query=q, resource=resource,
            severities=[part.strip() for value in severity for part in value.split(',') if part.strip()])
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc


@app.get("/services/{service_key}", response_class=HTMLResponse)
def service_detail(
    service_key: str,
    request: Request,
    version: str = "",
    finding_state: str = "active",
    finding_type: str = "all",
    q: str = "",
    severity: list[str] = Query(default=[]),
    resource: str = "",
    page: int = 1,
    page_size: int = 50,
    overview: bool = False,
    simplified: bool = False,
    poam: bool = False,
    remediations: bool = False,
    tab: str = "poams",
    activity: bool = False,
    architecture: bool = False,
    artifacts: bool = False,
    dependencies: bool = False,
    dependency_execution: int | None = None,
    dependency_type: str = "",
    dependency_image: str = "",
    dependency_license: str = "",
    dependency_filter: str = "all",
    dependency_epss: float | None = None,
    validation: bool = False,
    validation_run: str | None = None,
    validation_page: int = 1,
    findings: bool = False,
    findings_view: str = "",
    layout_width: int | None = None,
    status_filter: str = "all",
    sort_by: str = "newest",
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.view", scoped=True)),
):
    if findings and not findings_view:
        findings_view = "simplified"
    if findings_view in {"raw", "simplified"}:
        simplified = findings_view == "simplified"
        overview = False
    narrow_findings = not any((overview, poam, remediations, activity, architecture, artifacts, dependencies, validation))
    # Activity rows have their own scoped query and never need evidence history.
    activity_only = activity and not any((poam, remediations, architecture, artifacts, dependencies, validation))
    dependencies_only = dependencies and not any((poam, remediations, activity, architecture, artifacts, validation))
    artifacts_only = artifacts and not any((poam, remediations, activity, architecture, dependencies, validation))
    remediations_only = remediations and not any((poam, activity, architecture, artifacts, dependencies, validation))
    poam_only = poam and not any((remediations, activity, architecture, artifacts, dependencies, validation))
    architecture_only = architecture and not any((poam, remediations, activity, artifacts, dependencies, validation))
    validation_only = validation and not any((poam, remediations, activity, architecture, artifacts, dependencies))
    overview_only = overview and finding_state != "warnings" and not any((poam, remediations, activity, architecture, artifacts, dependencies, validation))
    service_query = select(Service).where(Service.service_key == service_key)
    if not narrow_findings and not activity_only and not dependencies_only and not artifacts_only and not remediations_only and not poam_only and not overview_only and not architecture_only and not validation_only:
        service_query = service_query.options(
            selectinload(Service.findings).selectinload(Finding.exceptions),
            selectinload(Service.policy_findings).selectinload(PolicyFinding.exceptions),
            selectinload(Service.findings).selectinload(Finding.observations),
            selectinload(Service.executions),
            selectinload(Service.archive_events),
            selectinload(Service.groups),
            selectinload(Service.images),
        )
    service = db.scalar(service_query)
    if not service:
        raise HTTPException(404)
    now = utcnow()
    if version:
        return RedirectResponse(f"/services/{service_key}/history?version={urllib.parse.quote(version, safe='')}", status_code=303)
    # Canonical Findings selector; legacy ``overview=false`` and
    # ``simplified=true`` links remain valid for bookmarks and deep links.
    if findings and not findings_view:
        findings_view = "simplified"
    if findings_view == "simplified":
        simplified = True
        overview = False
    elif findings_view == "raw":
        simplified = False
        overview = False
    configuration = configuration_for_service(db, service)
    if narrow_findings and simplified:
        if page_size not in {50, 100, 250}:
            raise HTTPException(422, detail="Page size must be 50, 100, or 250")
        from .service_tab_queries import prepare_service_tab_view
        from .simplified_queries import group_page
        from .exchange_routes import history_version_choices
        view, service, _ = prepare_service_tab_view(db, service, now, configuration, service_view,
                                                   header_only=True)
        latest_execution = max(service.executions,
            key=lambda item: (aware(item.scanned_at), item.id), default=None)
        severity = [part.strip() for value in severity for part in value.split(',') if part.strip()]
        try:
            simplified_findings, pagination, severity_options = group_page(
                db, service, latest_execution, now, configuration, page=page, page_size=page_size,
                state=finding_state, finding_type=finding_type, severities=severity, query=q, resource=resource)
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc)) from exc
        archive_pending = bool(db.scalar(select(WorkflowRequest.id).where(
            WorkflowRequest.request_type == "archive", WorkflowRequest.service_id == service.id,
            WorkflowRequest.status == "pending")))
        params = [("overview", "false"), ("finding_state", finding_state),
                  ("finding_type", finding_type), ("page_size", page_size)]
        if findings or findings_view:
            params.insert(1, ("findings_view", "simplified"))
        params.append(("simplified", "true"))
        if q.strip(): params.append(('q', q.strip()))
        if resource.strip(): params.append(('resource', resource.strip()))
        params.extend(('severity', value) for value in severity)
        pagination_base = f"/services/{urllib.parse.quote(service_key, safe='')}?{urllib.parse.urlencode(params)}"
        selector = 'findings_view=simplified&' if findings or findings_view else ''
        clear_filters_url = f"/services/{urllib.parse.quote(service_key, safe='')}?overview=false&{selector}finding_state={urllib.parse.quote(finding_state)}&finding_type={urllib.parse.quote(finding_type)}&page_size={page_size}"
        return templates.TemplateResponse(request, "service_simplified.html", page_context(auth,
            _date_configuration=configuration, view=view,
            finding_state=finding_state,
            history_versions=history_version_choices(db, service), simplified_findings=simplified_findings,
            now=now, finding_type=finding_type, archive_pending=archive_pending,
            groups=db.scalars(select(Group).order_by(Group.name)).all(), query=q, resource=resource,
            severity=severity, severity_options=severity_options, pagination_base=pagination_base,
            clear_filters_url=clear_filters_url, selected_findings_view="simplified",
            page_size=page_size, **pagination))
    if narrow_findings and findings_view == "raw" and finding_state in {"noncompliant", "overdue", "warnings"}:
        # Non-Compliant and Warnings are ordered, filtered and paged in SQL; only
        # the displayed rows are projected (see raw_states for the exact rules).
        if finding_type not in {"all", "vulnerability", "configuration", "evidence", "watchlist"}:
            raise HTTPException(422, detail="Unknown finding type")
        if page_size not in {50, 100, 250}:
            raise HTTPException(422, detail="Page size must be 50, 100, or 250")
        from . import raw_states
        from .evidence_reads import execution_payload
        from .exchange_routes import history_version_choices
        from .findings_query import load_page_support
        from .service_tab_queries import prepare_service_tab_view
        from .validation_queries import latest_run
        severity = [part.strip() for value in severity for part in value.split(",") if part.strip()]
        view, service, current_scan = prepare_service_tab_view(db, service, now, configuration, service_view, header_only=True)
        latest_execution = max(service.executions, key=lambda item: (aware(item.scanned_at), item.id), default=None)
        if finding_state == "warnings":
            other_items = [item for item in view["warning_items"] if item.get("type") not in {"CVE", "Exception"}]
            if current_scan:
                other_items.extend({
                    "type": "Dependency Watchlist", "item": match.component_name,
                    "reason": f"Watched component {match.component_name} {match.component_version} in {match.image}",
                    "due": None, "href": f"/services/{service.service_key}/watchlist/{match.id}",
                } for match in db.scalars(select(DependencyWatchlistMatch).where(
                    DependencyWatchlistMatch.execution_id == current_scan.id).order_by(DependencyWatchlistMatch.id)))
            newest_run = latest_run(db, service.id)
            if newest_run and newest_run.status in {"FAILED", "ERROR", "COULD_NOT_VALIDATE", "PARTIALLY_VERIFIED"}:
                other_items.append({"type": "Kind Validation", "item": newest_run.status,
                    "reason": newest_run.reason or newest_run.reason_category or "Deployment validation needs review",
                    "due": None, "href": f"/services/{service.service_key}?validation=true&validation_run={newest_run.run_key}"})
            result = raw_states.warning_page(db, service.id, configuration, now, service.service_key, other_items,
                                             finding_type=finding_type, page=page, page_size=page_size)
        else:
            # The retained payload is read only when missing evidence is itself non-compliant.
            evidence = raw_states.evidence_rows(view, execution_payload(db, current_scan.id)
                                                if current_scan and view.get("evidence_noncompliant") else {}, current_scan)
            result = raw_states.noncompliant_page(db, service.id, configuration, now, evidence,
                finding_type=finding_type, query=q, resource=resource, severities=severity, page=page, page_size=page_size)
        severity_options = raw_states.severity_options(db, service.id, configuration, now)
        archive_pending = bool(db.scalar(select(WorkflowRequest.id).where(
            WorkflowRequest.request_type == "archive", WorkflowRequest.service_id == service.id,
            WorkflowRequest.status == "pending")))
        pagination_params = [("overview", "false"), ("findings_view", "raw"),
            ("finding_state", finding_state), ("finding_type", finding_type), ("page_size", page_size)]
        if q.strip(): pagination_params.append(("q", q.strip()))
        if resource.strip(): pagination_params.append(("resource", resource.strip()))
        pagination_params.extend(("severity", value) for value in severity)
        pagination_base = f"/services/{urllib.parse.quote(service_key, safe='')}?{urllib.parse.urlencode(pagination_params, doseq=True)}"
        clear_filters_url = f"/services/{urllib.parse.quote(service_key, safe='')}?overview=false&findings_view=raw&finding_state={urllib.parse.quote(finding_state)}&finding_type={urllib.parse.quote(finding_type)}&page_size={page_size}"
        noncompliance_items, warning_items, affected_images = [], [], {}
        if finding_state == "warnings":
            warning_items = result["items"]
        else:
            noncompliance_items = result["items"]
            affected_images = load_page_support(db, service.id, result["findings"], latest_execution)
            for item in noncompliance_items:
                if item["type"] == "CVE":
                    item["images"] = affected_images.get(item["finding_id"], [])
                else:
                    item["images"] = [item["evidence_image"]] if item.get("evidence_image") else []
        return templates.TemplateResponse(request, "service.html", page_context(auth,
            _date_configuration=configuration, remediation_enabled=remediation_enabled(db),
            view=view, history_versions=history_version_choices(db, service), findings=[], affected_images=affected_images,
            policy_findings=[], noncompliance_items=noncompliance_items, warning_items=warning_items, now=now,
            active_exception=active_exception, finding_state=finding_state,
            groups=db.scalars(select(Group).order_by(Group.name)).all(),
            overdue_days=view["overdue_days"], saved=request.query_params.get("saved") == "1",
            archive_pending=archive_pending, page=result["page"], page_size=page_size,
            total_items=result["total_items"], total_pages=result["total_pages"], finding_type=finding_type,
            remediation_classes={}, query=q, resource=resource, severity=severity, severity_options=severity_options,
            pagination_base=pagination_base, clear_filters_url=clear_filters_url, selected_findings_view="raw"))
    if narrow_findings and findings_view == "raw" and finding_state in {"active", "resolved"}:
        if finding_type not in {"all", "vulnerability", "configuration", "evidence", "watchlist"}:
            raise HTTPException(422, detail="Unknown finding type")
        if page_size not in {50, 100, 250}:
            raise HTTPException(422, detail="Page size must be 50, 100, or 250")
        from .service_read_model import prepare_raw_page
        from .exchange_routes import history_version_choices
        severity = [part.strip() for value in severity for part in value.split(",") if part.strip()]
        def raw_summary(session, item, instant, settings):
            return service_overview_rows_aggregated(session, auth, instant, settings,
                services=[item], configurations={item.id: settings})[0][0]
        current_exception = select(ExceptionRecord.id).where(
            ExceptionRecord.finding_id == Finding.id, ExceptionRecord.revoked_at.is_(None),
            ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now).exists()
        eligible, _, needs_observations = _risk_finding_expressions({service.id: configuration}, now, current_exception)
        severity_query = select(Finding.severity).where(Finding.service_id == service.id,
            or_(Finding.active.is_(False), ~current_exception, eligible))
        if needs_observations:
            latest_observation = select(FindingObservation.finding_id,
                func.max(FindingObservation.id).label("latest_id")).join(Finding, Finding.id == FindingObservation.finding_id).where(
                Finding.service_id == service.id).group_by(FindingObservation.finding_id).subquery()
            severity_query = severity_query.outerjoin(latest_observation,
                latest_observation.c.finding_id == Finding.id).outerjoin(FindingObservation,
                FindingObservation.id == latest_observation.c.latest_id)
        view, service, latest_execution, result, affected_images, severity_options = prepare_raw_page(
            db, service, now, configuration, service_view, raw_summary,
            state=finding_state, finding_type=finding_type, severities=severity,
            query=q, resource=resource, page=page, page_size=page_size, severity_query=severity_query)
        archive_pending = bool(db.scalar(select(WorkflowRequest.id).where(
            WorkflowRequest.request_type == "archive", WorkflowRequest.service_id == service.id,
            WorkflowRequest.status == "pending")))
        pagination_params = [("overview", "false"), ("findings_view", "raw"),
            ("finding_state", finding_state), ("finding_type", finding_type), ("page_size", page_size)]
        if q.strip(): pagination_params.append(("q", q.strip()))
        if resource.strip(): pagination_params.append(("resource", resource.strip()))
        pagination_params.extend(("severity", value) for value in severity)
        pagination_base = f"/services/{urllib.parse.quote(service_key, safe='')}?{urllib.parse.urlencode(pagination_params, doseq=True)}"
        clear_filters_url = f"/services/{urllib.parse.quote(service_key, safe='')}?overview=false&findings_view=raw&finding_state={urllib.parse.quote(finding_state)}&finding_type={urllib.parse.quote(finding_type)}&page_size={page_size}"
        from .evidence_reads import execution_payload
        # Untracked copy, read only when configuration rows need remediation classes.
        latest_payload = execution_payload(db, latest_execution.id) if result["policy_findings"] and latest_execution else {}
        return templates.TemplateResponse(request, "service.html", page_context(auth,
            _date_configuration=configuration, remediation_enabled=remediation_enabled(db),
            view=view, history_versions=history_version_choices(db, service),
            findings=result["findings"], policy_findings=result["policy_findings"],
            affected_images=affected_images, noncompliance_items=[], now=now,
            active_exception=active_exception, finding_state=finding_state,
            groups=db.scalars(select(Group).order_by(Group.name)).all(),
            overdue_days=view["overdue_days"], saved=request.query_params.get("saved") == "1",
            archive_pending=archive_pending, page=result["page"], page_size=page_size,
            total_items=result["total_items"], total_pages=result["total_pages"],
            finding_type=finding_type,
            remediation_classes={item.id: classify_policy_finding(item, latest_payload) for item in result["policy_findings"]},
            query=q, resource=resource, severity=severity, severity_options=severity_options,
            pagination_base=pagination_base, clear_filters_url=clear_filters_url, selected_findings_view="raw"))
    if activity_only or dependencies_only or artifacts_only or remediations_only or poam_only or overview_only or architecture_only or validation_only:
        from .service_tab_queries import prepare_service_tab_view
        view, service, latest_scan = prepare_service_tab_view(db, service, now, configuration, service_view,
                                                           include_global_latest=not (dependencies_only or artifacts_only),
                                                           header_only=architecture_only or validation_only or activity_only or poam_only or dependencies_only or artifacts_only or remediations_only or overview_only)
    elif narrow_findings:
        from .findings_query import prepare_findings_view
        view, service, latest_scan = prepare_findings_view(db, service, now, configuration, service_view)
    else:
        view = service_view(service, now, configuration)
    latest_scan = max((item for item in service.executions if
                       service.current_version_id is None or item.service_version_id == service.current_version_id),
                      key=lambda item: (aware(item.scanned_at), item.id), default=None)
    if latest_scan and not (dependencies_only or artifacts_only or remediations_only or activity_only or architecture_only or validation_only or poam_only):
        matches = db.scalars(select(DependencyWatchlistMatch).where(
            DependencyWatchlistMatch.execution_id == latest_scan.id).order_by(DependencyWatchlistMatch.id)).all()
        view["warning_items"].extend({
            "type": "Dependency Watchlist", "item": match.component_name,
            "reason": f"Watched component {match.component_name} {match.component_version} in {match.image}",
            "due": None, "href": f"/services/{service.service_key}/watchlist/{match.id}",
        } for match in matches)
    archive_pending = bool(db.scalar(select(WorkflowRequest.id).where(
        WorkflowRequest.request_type == "archive",
        WorkflowRequest.service_id == service.id,
        WorkflowRequest.status == "pending",
    )))
    if artifacts_only:
        from .artifact_tab_queries import latest_validation_warning
    if overview_only or architecture_only or validation_only or activity_only or poam_only or dependencies_only or remediations_only:
        # Header warnings and polling need only the newest run; architecture and
        # history read their own targeted rows below.
        from .validation_queries import latest_run
        newest_run = latest_run(db, service.id)
        validation_records = [newest_run] if newest_run else []
    else:
        validation_records = latest_validation_warning(db, service.id) if artifacts_only else db.scalars(select(DeploymentValidationRun).where(
            DeploymentValidationRun.service_id == service.id,
        ).options(selectinload(DeploymentValidationRun.execution)).order_by(DeploymentValidationRun.created_at.desc()).limit(100 if not narrow_findings else 1)).all()
    latest_validation = deployment_validation_view(validation_records[0]) if validation_records and not artifacts_only else None
    if validation_records and validation_records[0].status in {"FAILED", "ERROR", "COULD_NOT_VALIDATE", "PARTIALLY_VERIFIED"}:
        failed_run = validation_records[0]
        view["warning_items"].append({"type": "Kind Validation", "item": failed_run.status,
            "reason": failed_run.reason or failed_run.reason_category or "Deployment validation needs review",
            "due": None, "href": f"/services/{service.service_key}?validation=true&validation_run={failed_run.run_key}"})
    if overview_only:
        if finding_state not in {"active", "noncompliant", "overdue", "exceptions", "resolved"}:
            raise HTTPException(400, detail="Unknown finding state")
        if finding_type not in {"all", "vulnerability", "configuration", "evidence", "watchlist"}:
            raise HTTPException(422, detail="Unknown finding type")
        if page_size not in {50, 100, 250}:
            raise HTTPException(422, detail="Page size must be 50, 100, or 250")
        # Overview loads only what it renders: scalar execution metadata, one
        # untracked evidence payload, targeted validation runs, SQL counts and
        # a cached architecture summary (no layouts, no history hydration).
        from .evidence_reads import (architecture_execution as select_architecture_execution, execution_metadata,
                                     execution_payload, latest_working_revision_id)
        from .service_counts import overview_finding_counts
        from .validation_queries import applicable_run, runtime_identity
        execution_rows = execution_metadata(db, service.id)
        latest_execution = execution_rows[0] if execution_rows else None
        from .evidence_reads import normalized_overview
        # Reads only the rendered subset of the scan; normalization is content-keyed.
        latest_payload, overview_data = normalized_overview(db, latest_execution)
        if latest_execution:
            latest_execution.raw_payload = latest_payload
        removable_keys = _current_removable_evidence_keys(latest_payload, latest_execution.complete) if latest_execution else set()
        for row in overview_data["missing_evidence"]:
            row["removable"] = _missing_evidence_key(row) in removable_keys
        architecture_execution = select_architecture_execution(execution_rows)
        from .evidence_reads import architecture_metadata
        architecture_meta = architecture_metadata(db, architecture_execution)
        architecture_revision_id = latest_working_revision_id(db, service.id)
        architecture_subject = dict(
            execution_id=architecture_execution.id if architecture_execution and not architecture_revision_id else None,
            artifact_revision_id=architecture_revision_id)
        architecture_run = applicable_run(db, service.id, **architecture_subject)
        architecture_verification_state = architecture_verification(
            applicable=bool(architecture_meta.get("applicable")),
            declared_count=int(architecture_meta.get("declared_resources") or 0),
            runs=[architecture_run] if architecture_run else [], **architecture_subject)
        architecture_runtime = deployment_validation_view(architecture_verification_state.get("run"))
        if architecture_execution:
            architecture_graph = build_architecture_graph(
                lambda: execution_payload(db, architecture_execution.id),
                runtime_evidence=architecture_runtime, layouts=False,
                cache_key=("execution", architecture_execution.id, architecture_execution.payload_digest,
                           runtime_identity(architecture_verification_state.get("run")))
                if architecture_execution.payload_digest else None)
        else:
            architecture_graph = build_architecture_graph({}, runtime_evidence=architecture_runtime, layouts=False)
        finding_counts = overview_finding_counts(db, service.id, configuration, now, view)
        from .exchange_routes import history_version_choices
        return templates.TemplateResponse(request, "service_overview.html", page_context(auth,
            view=view, history_versions=history_version_choices(db, service), overview_data=overview_data, latest_execution=latest_execution,
            finding_counts=finding_counts,
            architecture_polling=bool(latest_validation and not latest_validation.get("terminal")),
            artifact_provenance=provenance_for_execution(db, latest_execution.id) if latest_execution else [],
            deployment_validation=architecture_runtime or latest_validation,
            architecture_verification=architecture_verification_state, architecture_graph=architecture_graph,
            service_images=db.scalars(select(ServiceImage).where(ServiceImage.service_id == service.id)).all(),
            now=now, finding_type=finding_type, archive_pending=archive_pending,
            groups=db.scalars(select(Group).order_by(Group.name)).all(),
        ))
    if validation:
        validation_history = None
        if validation_only:
            from .evidence_reads import execution_metadata, original_helm_execution
            from .validation_queries import history_page, run_by_key
            selected_record = (run_by_key(db, service.id, validation_run) if validation_run
                               else (validation_records[0] if validation_records else None))
            history_rows, validation_history = history_page(db, service.id, validation_page)
            history_views = [dict(vars(item)) for item in history_rows]
            eligible_execution = original_helm_execution(execution_metadata(db, service.id))
        else:
            selected_record = next((item for item in validation_records if item.run_key == validation_run), None) if validation_run else (validation_records[0] if validation_records else None)
            history_views = [deployment_validation_view(item) for item in validation_records]
            eligible_execution = latest_eligible_helm_execution(service.executions)
        if validation_run and not selected_record:
            raise HTTPException(404, detail="Deployment Validation run not found")
        validation_unavailable_reason = None
        if not deployment_validation_enabled():
            validation_unavailable_reason = "Deployment Validation is disabled by configuration."
        elif not eligible_execution:
            validation_unavailable_reason = "No Helm scan with retained source files is available to validate."
        return templates.TemplateResponse(request, "service_validation.html", page_context(auth,
            view=view, service=service, validation=deployment_validation_view(selected_record),
            validation_runs=history_views, validation_history=validation_history,
            can_validate=auth.has("remediation.execute", service.id) and not validation_unavailable_reason,
            validation_unavailable_reason=validation_unavailable_reason,
            archive_pending=archive_pending, now=now,
        ))
    if dependencies:
        from .dependency_queries import request_current_projection, pending_dependency_page, schedule_projection, dependency_page, dependency_version
        from .exchange_routes import history_version_choices
        if dependencies_only:
            from .service_tab_queries import prepare_dependency_evidence
            latest, dependency_executions = prepare_dependency_evidence(db, service, dependency_execution, latest_scan)
        else:
            dependency_executions = service.executions
            latest = (next((item for item in service.executions if item.id == dependency_execution), None)
                      if dependency_execution is not None else latest_scan)
        if dependency_execution is not None and latest is None:
            raise HTTPException(404, detail="Dependency evidence not found for this service")
        projection_state = request_current_projection(db, latest, risk_metadata,
            retry=request.query_params.get("dependency_retry") == "true") if latest else None
        dependency_result = (pending_dependency_page(projection_state)
            if projection_state and projection_state["status"] != "ready" else
            dependency_page(db, latest.id if latest else -1,
                q=q, component_type=dependency_type, image=dependency_image, license=dependency_license,
                filter=dependency_filter, epss=dependency_epss, page=page, page_size=page_size))
        size = max(10, min(page_size, 100))
        query_args = {"dependencies": "true", "q": q, "dependency_type": dependency_type,
                      "dependency_image": dependency_image, "dependency_license": dependency_license,
                      "dependency_filter": dependency_filter,
                      "page_size": size}
        if dependency_execution is not None:
            query_args["dependency_execution"] = dependency_execution
        if dependency_epss is not None:
            query_args["dependency_epss"] = dependency_epss
        page_url = f"/services/{service.service_key}?{urllib.parse.urlencode(query_args)}&page="
        response = templates.TemplateResponse(request, "service_dependencies.html", page_context(auth,
            view={**view, "version": dependency_version(db, latest)} if latest else view,
            service=service, **dependency_result, dependency_page_url=page_url,
            dependency_query={"q": q, "type": dependency_type, "image": dependency_image,
                              "license": dependency_license,
                              "filter": dependency_filter, "epss": dependency_epss},
            dependency_executions=sorted(dependency_executions, key=lambda item: (aware(item.scanned_at), item.id), reverse=True),
            dependency_selected_execution=latest,
            history_versions=history_version_choices(db, service),
            archive_pending=archive_pending, now=now,
        ))
        if projection_state and projection_state["status"] == "pending":
            from starlette.background import BackgroundTask
            response.background = BackgroundTask(schedule_projection, db.get_bind(), latest.id,
                projection_state["build_token"], risk_metadata)
        return response
    if architecture and architecture_only:
        # Selection from summary metadata; the payload is read only when the
        # content-keyed graph (or a new layout width) is not cached.
        from .evidence_reads import architecture_execution as select_architecture_execution
        from .evidence_reads import execution_metadata, execution_payload, latest_working_revision_id
        from .validation_queries import applicable_run, runtime_identity
        latest_execution = select_architecture_execution(execution_metadata(db, service.id))
        from .evidence_reads import architecture_metadata
        meta = architecture_metadata(db, latest_execution)
        architecture_state = (
            "NO_SOURCE" if not latest_execution else
            "ANALYSIS_INCOMPLETE" if latest_execution.complete is False else
            "NO_RELATIONSHIPS" if not meta.get("has_resources") else
            "READY"
        )
        working_revision_id = latest_working_revision_id(db, service.id)
        subject = dict(execution_id=latest_execution.id if latest_execution and not working_revision_id else None,
                       artifact_revision_id=working_revision_id)
        architecture_run = applicable_run(db, service.id, **subject)
        architecture_verification_state = architecture_verification(
            applicable=bool(meta.get("applicable")), declared_count=int(meta.get("declared_resources") or 0),
            runs=[architecture_run] if architecture_run else [], **subject)
        runtime_view = deployment_validation_view(architecture_verification_state.get("run"))
        def architecture_payload():
            payload = execution_payload(db, latest_execution.id) if latest_execution else {}
            if latest_execution:
                payload["complete"] = latest_execution.complete
            return payload
        graph_key = (("execution", latest_execution.id, latest_execution.payload_digest, latest_execution.complete,
                      runtime_identity(architecture_verification_state.get("run")))
                     if latest_execution and latest_execution.payload_digest else None)
        if layout_width is not None:
            if not 240 <= layout_width <= 10000:
                raise HTTPException(422, detail="Invalid architecture canvas width")
            return JSONResponse(build_architecture_graph(architecture_payload, layout_width, runtime_view,
                                                         cache_key=graph_key)["layouts"])
        return templates.TemplateResponse(request, "service_architecture.html", page_context(auth,
            view=view, architecture_graph=build_architecture_graph(architecture_payload, runtime_evidence=runtime_view,
                                                                   cache_key=graph_key),
            latest_execution=latest_execution,
            architecture_verification=architecture_verification_state,
            architecture_state=architecture_state,
            architecture_polling=bool(latest_validation and not latest_validation.get("terminal")),
            now=now, archive_pending=archive_pending,
        ))
    if architecture:
        latest_execution = latest_architecture_execution(service.executions)
        payload = dict(latest_execution.raw_payload) if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
        if latest_execution:
            payload["complete"] = latest_execution.complete
        architecture_state = (
            "NO_SOURCE" if not latest_execution else
            "ANALYSIS_INCOMPLETE" if latest_execution.complete is False else
            "NO_RELATIONSHIPS" if not _architecture_has_resources(payload) else
            "READY"
        )
        declared_resources = (payload.get("service_overview") or {}).get("rendered_resources") or payload.get("rendered_resources") or []
        applicable = bool(payload.get("helm_source_files") or declared_resources) and str(payload.get("artifact_type") or "helm").lower() == "helm"
        working_revision = latest_architecture_working_revision(db, service.id)
        architecture_verification_state = architecture_verification(
            applicable=applicable, declared_count=len(declared_resources), runs=validation_records,
            execution_id=latest_execution.id if latest_execution and not working_revision else None,
            artifact_revision_id=working_revision.id if working_revision else None,
        )
        runtime_view = deployment_validation_view(architecture_verification_state.get("run"))
        if layout_width is not None:
            if not 240 <= layout_width <= 10000:
                raise HTTPException(422, detail="Invalid architecture canvas width")
            return JSONResponse(build_architecture_graph(payload, layout_width, runtime_view)["layouts"])
        return templates.TemplateResponse(request, "service_architecture.html", page_context(auth,
            view=view, architecture_graph=build_architecture_graph(payload, runtime_evidence=runtime_view), latest_execution=latest_execution,
            architecture_verification=architecture_verification_state,
            architecture_state=architecture_state,
            architecture_polling=bool(latest_validation and not latest_validation.get("terminal")),
            now=now, archive_pending=archive_pending,
        ))
    if artifacts:
        from .artifact_tab_queries import load_artifact_workspace
        from .evidence_reads import execution_metadata, original_helm_execution
        # Summary metadata selects the original; only its Helm sources are read (untracked).
        latest_execution = original_helm_execution(execution_metadata(db, service.id))
        original_sources = db.scalar(select(Execution.raw_payload["helm_source_files"]).where(
            Execution.id == latest_execution.id)) if latest_execution else None
        original_files = dict(original_sources or {}) if isinstance(original_sources, dict) else {}
        artifact_rows = []
        persisted, latest_revisions, latest_validation_by_revision, service_images = load_artifact_workspace(db, service.id)
        for artifact in persisted:
            revision = latest_revisions.get(artifact.id)
            revision_files = revision.files if revision else {}
            chart_markers = [name for name in revision_files if str(name).endswith("Chart.yaml")]
            semantic_type = artifact.artifact_type
            if semantic_type == "helm_repository" and artifact.lifecycle_status != "active":
                semantic_type = "removed_repository"
            if semantic_type == "helm":
                semantic_type = "helm_chart" if len(chart_markers) == 1 else "legacy_helm_repository"
            source_reference = artifact.source_reference or ""
            parsed_source = urllib.parse.urlparse(source_reference)
            source_label = parsed_source.hostname or (
                "OCI" if (artifact.source_type or "").lower() == "oci" else
                "Upload" if (artifact.source_type or "").lower() == "upload" else
                source_reference or "Retained evidence"
            )
            artifact_rows.append({
                "artifact": artifact, "revision": revision, "files": revision_files,
                "chart_count": len(chart_markers), "semantic_type": semantic_type,
                "source_label": source_label,
                "validation": artifact_validation_summary(latest_validation_by_revision.get(revision.id) if revision else None),
            })
        helm_file_count = len(original_files) + sum(
            len(row["files"]) for row in artifact_rows if row["semantic_type"] in {"helm_chart", "legacy_helm_repository"}
        )
        image_inventory = []
        by_identity: dict[str, dict[str, Any]] = {}
        for image in service_images:
            identity = (image.image_digest or image.image_reference).casefold()
            row = by_identity.setdefault(identity, {"image": image, "references": [], "count": 0})
            row["references"].append(image.image_reference)
            row["count"] += 1
        for row in by_identity.values():
            row["references"] = sorted(set(row["references"]))
            image_inventory.append(row)
        image_inventory.sort(key=lambda row: row["image"].image_reference.casefold())
        artifact_rows.sort(key=lambda row: ((row["artifact"].chart_name or row["artifact"].artifact_name or "").casefold(), row["artifact"].id))
        repository_count = sum(row["semantic_type"] == "helm_repository" for row in artifact_rows)
        chart_count = sum(row["semantic_type"] == "helm_chart" for row in artifact_rows)
        manifest_count = sum(row["artifact"].artifact_type == "kubernetes" for row in artifact_rows)
        return templates.TemplateResponse(request, "service_artifacts.html", page_context(auth,
            service=service, view=view, now=now, archive_pending=archive_pending,
            original_execution=latest_execution, original_files=original_files,
            artifact_rows=artifact_rows, helm_file_count=helm_file_count, service_images=service_images,
            image_inventory=image_inventory,
            repository_count=repository_count, chart_count=chart_count, manifest_count=manifest_count,
            can_edit=auth.has("service.edit", service.id),
            can_image_workflow=auth.has("service.edit", service.id),
            can_validate=auth.has("remediation.execute", service.id) and deployment_validation_enabled(),
        ))
    if remediations:
        if tab not in {"pipeline", "poams", "exceptions", "mitigations"}:
            raise HTTPException(422, detail="Unknown remediation tab")
        # Only the selected collection is loaded, counted and paged in the
        # database; every record remains reachable through pagination.
        from .remediation_list_queries import (REMEDIATION_PAGE_SIZES, active_image_references, exceptions_page,
                                               poam_entries_page, remediation_jobs_page)
        if page_size not in REMEDIATION_PAGE_SIZES:
            raise HTTPException(422, detail="Page size must be 25, 50, 100, or 250")
        poams, mitigations, exceptions, remediation_jobs = [], [], [], []
        if tab == "pipeline":
            remediation_jobs, remediation_pages = remediation_jobs_page(db, service.id, page, page_size)
        elif tab == "exceptions":
            exceptions, remediation_pages = exceptions_page(db, service, now, aware, page, page_size)
        else:
            entries, remediation_pages = poam_entries_page(db, service.id, mitigations=tab == "mitigations",
                                                           page=page, page_size=page_size)
            if tab == "mitigations":
                mitigations = entries
            else:
                poams = entries
        if remediations_only:
            # The tab header carries no finding rows: read the active policy
            # findings as scalar rows; the newest evidence (untracked copy) is
            # read only when the content-keyed preview is not cached.
            from .evidence_reads import execution_payload
            from .findings_query import _rows
            preview_id = db.scalar(select(Execution.id).where(Execution.service_id == service.id)
                                   .order_by(Execution.scanned_at.desc(), Execution.id.asc()).limit(1))
            preview_payload = lambda: execution_payload(db, preview_id)
            preview_policy = _rows(db, PolicyFinding, PolicyFinding.service_id == service.id,
                                   PolicyFinding.active.is_(True), order_by=PolicyFinding.id)
        else:
            preview_execution = max(service.executions, key=lambda item: aware(item.scanned_at), default=None)
            loaded_payload = preview_execution.raw_payload if preview_execution and isinstance(preview_execution.raw_payload, dict) else {}
            preview_payload = lambda: loaded_payload
            preview_policy = [item for item in service.policy_findings if item.active]
        def compute_preview():
            payload = _remediation_source_payload(SimpleNamespace(raw_payload=preview_payload()))
            plan = build_plan(payload, preview_policy, "PREVIEW")
            files = payload.get("helm_source_files") or payload.get("source_files") or {}
            return ({str(item.get("original")) for item in plan.get("images", [])},
                    sum(str(path).replace("\\", "/").endswith("Chart.yaml") for path in files) if isinstance(files, dict) else 0,
                    sum(item.get("classification") == "AUTO-REMEDIABLE" for item in plan.get("configuration_changes", [])),
                    sum(item.get("classification") == "REVIEW REQUIRED" for item in plan.get("configuration_changes", [])))
        # The preview is informational: a planner defect must never make the tab
        # (and with it POA&M, exception and candidate history) unreachable.
        preview_error = None
        try:
            if remediations_only:
                # Content-keyed (evidence digest + exact finding fields); never time-based.
                preview_key = (preview_id, db.scalar(select(Execution.payload_digest).where(Execution.id == preview_id)),
                               tuple(tuple(sorted((key, str(value)) for key, value in vars(item).items())) for item in preview_policy))
                plan_images, plan_charts, plan_changes, plan_review = _remediation_preview_cached(preview_key, compute_preview)
            else:
                plan_images, plan_charts, plan_changes, plan_review = compute_preview()
        except Exception as exc:
            logging.getLogger("cats.remediation").exception(
                "Remediation plan preview failed", extra={"service_id": service.id})
            plan_images, plan_charts, plan_changes, plan_review = set(), 0, 0, 0
            preview_error = f"The remediation plan preview could not be built ({type(exc).__name__}). Remediation history remains available."
        preview_images = set(plan_images)
        preview_images.update(active_image_references(db, service.id))
        remediation_preview = {"images": len(preview_images), "charts": plan_charts,
            "configuration_changes": plan_changes, "manual_review": plan_review, "error": preview_error}
        return templates.TemplateResponse(request, "service_remediations.html", page_context(auth,
            service=service, view=view, tab=tab, poams=poams, exceptions=exceptions, mitigations=mitigations,
            remediation_jobs=remediation_jobs, can_remediate=remediation_enabled(db) and auth.has("remediation.execute", service.id),
            remediation_enabled=remediation_enabled(db),
            remediation_preview=remediation_preview, oci_destinations=_remediation_destinations(db, service.id),
            **remediation_pages, pagination_base=f"/services/{urllib.parse.quote(service.service_key, safe='')}?"
                f"{urllib.parse.urlencode({'remediations': 'true', 'tab': tab, 'page_size': page_size})}",
            can_create_poam=auth.has("poam.request", service.id), now=now,
        ))
    if poam:
        from .poam_query import service_poam_page as load_poam_page, pagination_base as poam_pagination_base
        entries, pagination = load_poam_page(db, service.id, now, status_filter, sort_by, page, page_size)
        return templates.TemplateResponse(request, "poam_service.html", page_context(auth,
            service=service, view=view, embedded=True, entries=entries, can_create_poam=auth.has("poam.request", service.id),
            status_filter=status_filter, sort_by=sort_by, now=now, **pagination,
            pagination_base=poam_pagination_base(service.service_key, status_filter, sort_by, page_size),
            overdue_entry_ids={entry.id for entry in entries if entry.status == "active" and entry.due_date and aware(entry.due_date) < now},
        ))
    if activity:
        from .activity_queries import service_activity_page
        activity_result = service_activity_page(db, service.id, page=page, page_size=page_size)
        return templates.TemplateResponse(request, "service_activity.html", page_context(auth,
            service=service, view=view, **activity_result, embedded=True, now=now,
            pagination_base=f'/services/{service.service_key}?activity=true&page_size={page_size}',
        ))
    finding_groups = {
        "active": view["active"],
        "noncompliant": view["noncompliant"],
        # Keep the old query value working for bookmarked links.
        "overdue": view["noncompliant"],
        "exceptions": view["excepted"],
        "resolved": view["resolved"],
        "warnings": view["warning_items"],
    }
    # Raw findings must not silently inherit the risk-policy visibility filter.
    # Lifecycle and exceptions are still explicit, independent service states.
    if findings_view == "raw":
        finding_groups["active"] = [f for f in service.findings if f.active and not active_exception(f, now)]
    severity = [part.strip() for value in severity for part in value.split(",") if part.strip()]
    all_policy_items = [*view["policy_findings"], *view["policy_excepted"], *view["policy_resolved"]]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    severity_options = sorted({str(item.severity) for item in [*finding_groups["active"], *finding_groups["exceptions"], *finding_groups["resolved"], *all_policy_items] if getattr(item, "severity", None)}, key=lambda value: (severity_order.get(value.casefold(), 4), value.casefold()))
    requested_page = page
    sql_page = narrow_findings and not simplified and finding_state in {"active", "exceptions", "resolved"}
    if narrow_findings and simplified and (q.strip() or resource.strip()):
        from .findings_query import load_filter_support
        load_filter_support(db, service.id, finding_groups["active"])
    if not sql_page:
        finding_groups = _filter_service_finding_groups(finding_groups, query=q, severities=severity, resource=resource)
    policy_groups = {} if sql_page else _filter_service_finding_groups({
        "active": [*view["policy_findings"], *view["policy_noncompliant"]] if findings_view == "raw" else view["policy_findings"], "exceptions": view["policy_excepted"], "resolved": view["policy_resolved"],
    }, query=q, severities=severity, resource=resource)
    selected_findings_view = "simplified" if simplified else "raw"
    canonical_findings = bool(findings or findings_view)
    pagination_params = [("overview", "false"), ("finding_state", finding_state), ("finding_type", finding_type), ("page_size", page_size)]
    if canonical_findings:
        pagination_params.insert(1, ("findings_view", selected_findings_view))
    if simplified: pagination_params.append(("simplified", "true"))
    if q.strip(): pagination_params.append(("q", q.strip()))
    if resource.strip(): pagination_params.append(("resource", resource.strip()))
    pagination_params.extend(("severity", value) for value in severity)
    pagination_base = f"/services/{urllib.parse.quote(service_key, safe='') }?{urllib.parse.urlencode(pagination_params, doseq=True)}"
    clear_filters_url = f"/services/{urllib.parse.quote(service_key, safe='')}?overview=false&{'findings_view=' + selected_findings_view + '&' if canonical_findings else ''}finding_state={urllib.parse.quote(finding_state)}&finding_type={urllib.parse.quote(finding_type)}&page_size={page_size}"
    if finding_state not in finding_groups:
        raise HTTPException(400, detail="Unknown finding state")
    if finding_type not in {"all", "vulnerability", "configuration", "evidence", "watchlist"}:
        raise HTTPException(422, detail="Unknown finding type")
    if page_size not in {50, 100, 250}:
        raise HTTPException(422, detail="Page size must be 50, 100, or 250")
    if finding_state == "warnings":
        all_items = list(finding_groups["warnings"])
        if finding_type != "all":
            warning_types = {"vulnerability": "CVE", "configuration": "Configuration", "evidence": "Evidence", "watchlist": "Dependency Watchlist"}
            all_items = [item for item in all_items if item.get("type") == warning_types[finding_type]]
        total_items = len(all_items)
        total_pages = max(1, (total_items + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        page_start = (page - 1) * page_size
        displayed_warning_items = all_items[page_start:page_start + page_size]
        from .exchange_routes import history_version_choices
        return templates.TemplateResponse(request, "service.html", page_context(auth,
            _date_configuration=configuration,
            remediation_enabled=remediation_enabled(db),
            view=view, history_versions=history_version_choices(db, service), findings=[], affected_images={}, policy_findings=[], noncompliance_items=[],
            warning_items=displayed_warning_items, now=now, active_exception=active_exception,
            finding_state=finding_state, groups=db.scalars(select(Group).order_by(Group.name)).all(),
            overdue_days=view["overdue_days"], saved=request.query_params.get("saved") == "1",
            page=page, page_size=page_size, total_items=total_items, total_pages=total_pages,
            finding_type=finding_type,
            query=q, resource=resource, severity=severity, severity_options=severity_options,
            pagination_base=pagination_base, clear_filters_url=clear_filters_url, selected_findings_view=selected_findings_view,
        ))
    all_findings = [] if sql_page else sorted(finding_groups[finding_state], key=lambda finding: (aware(finding.episode_started), finding.cve))
    policy_items = policy_groups.get(finding_state, [])
    mixed_state = finding_state in {"active", "exceptions", "resolved"}
    if mixed_state:
        active_entries = [("vulnerability", finding) for finding in all_findings]
        active_entries.extend(("configuration", item) for item in sorted(
            policy_items, key=lambda finding: (aware(finding.episode_started), finding.finding)
        ))
        if finding_type != "all":
            active_entries = [entry for entry in active_entries if entry[0] == finding_type]
        total_items = len(active_entries)
    else:
        all_items = view["noncompliance_items"] if finding_state in {"noncompliant", "overdue"} else all_findings
        all_items = _filter_service_finding_groups({"items": all_items}, query=q, severities=severity, resource=resource)["items"]
        if finding_type != "all":
            item_type = {"evidence": "Evidence", "configuration": "Configuration", "vulnerability": "CVE", "watchlist": "Dependency Watchlist"}[finding_type]
            all_items = [item for item in all_items if (item.get("type") if isinstance(item, dict) else "CVE") == item_type]
        total_items = len(all_items)
    total_pages = max(1, (total_items + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    page_start = (page - 1) * page_size
    if mixed_state:
        displayed_entries = active_entries[page_start:page_start + page_size]
        findings = [item for kind, item in displayed_entries if kind == "vulnerability"]
        displayed_policy_findings = [item for kind, item in displayed_entries if kind == "configuration"]
        displayed_items = findings
    else:
        displayed_items = all_items[page_start:page_start + page_size]
        findings = [] if finding_state in {"noncompliant", "overdue"} else displayed_items
        displayed_policy_findings = []
    if sql_page:
        from .findings_sql import get_raw_finding_page
        result = get_raw_finding_page(db, service.id, view, now, state=finding_state,
            finding_type=finding_type, severities=severity, query=q, resource=resource,
            page=requested_page, page_size=page_size, raw_selector=findings_view == "raw")
        findings, displayed_policy_findings = result["findings"], result["policy_findings"]
        total_items, total_pages, page = result["total_items"], result["total_pages"], result["page"]
        displayed_items = findings
    latest_execution = max(service.executions, key=lambda execution: (aware(execution.scanned_at), execution.id), default=None)
    if overview:
        raw_overview = latest_execution.raw_payload.get("service_overview", {}) if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
        # Copy: normalization must never edit the tracked, retained evidence.
        raw_overview = dict(raw_overview) if isinstance(raw_overview, dict) else {}
        latest_payload = latest_execution.raw_payload if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
        raw_overview.setdefault("source", "Helm rendered manifests" if latest_payload.get("policy_findings") else "Image metadata")
        overview_data = normalize_overview(
            raw_overview,
            skipped_images=latest_payload.get("skipped_images", []) or [],
            skipped_charts=latest_payload.get("skipped_charts", []) or [],
            findings_images=[{"image": item.get("image"), "digest": item.get("image_digest"), "discovered_from": item.get("discovered_from") or "Submitted"} for item in latest_payload.get("findings", []) if isinstance(item, dict) and item.get("image")],
            incomplete=bool(latest_execution and not latest_execution.complete),
            # The persisted scan overview is the source of truth for this
            # page.  Do not run docker manifest inspect while navigating.
            digest_resolver=None,
        )
        removable_keys = _current_removable_evidence_keys(latest_payload, latest_execution.complete) if latest_execution else set()
        for row in overview_data["missing_evidence"]:
            row["removable"] = _missing_evidence_key(row) in removable_keys
        architecture_execution = latest_architecture_execution(service.executions)
        architecture_payload = dict(architecture_execution.raw_payload) if architecture_execution and isinstance(architecture_execution.raw_payload, dict) else {}
        architecture_overview = architecture_payload.get("service_overview") if isinstance(architecture_payload.get("service_overview"), dict) else {}
        declared_resources = architecture_overview.get("rendered_resources") or architecture_payload.get("rendered_resources") or []
        architecture_revision = latest_architecture_working_revision(db, service.id)
        architecture_verification_state = architecture_verification(
            applicable=bool(architecture_payload.get("helm_source_files") or declared_resources) and str(architecture_payload.get("artifact_type") or "helm").lower() == "helm",
            declared_count=len(declared_resources), runs=validation_records,
            execution_id=architecture_execution.id if architecture_execution and not architecture_revision else None,
            artifact_revision_id=architecture_revision.id if architecture_revision else None,
        )
        architecture_graph = build_architecture_graph(architecture_payload, runtime_evidence=deployment_validation_view(architecture_verification_state.get("run")))
        from .exchange_routes import history_version_choices
        return templates.TemplateResponse(request, "service_overview.html", page_context(auth,
            view=view, history_versions=history_version_choices(db, service), overview_data=overview_data, latest_execution=latest_execution,
            artifact_provenance=provenance_for_execution(db, latest_execution.id) if latest_execution else [],
            deployment_validation=deployment_validation_view(architecture_verification_state.get("run")) or latest_validation,
            architecture_verification=architecture_verification_state, architecture_graph=architecture_graph,
            service_images=service.images,
            now=now, finding_type=finding_type, archive_pending=archive_pending,
            groups=db.scalars(select(Group).order_by(Group.name)).all(),
        ))
    if simplified:
        from .findings_query import page_simplified_findings
        simplified_findings, simplified_pagination = page_simplified_findings(
            db, service.id, finding_groups["active"], latest_execution, view["due_dates"], requested_page, page_size)
        total_items = simplified_pagination["total_items"]
        total_pages = simplified_pagination["total_pages"]
        page = simplified_pagination["page"]
        groups = db.scalars(select(Group).order_by(Group.name)).all()
        from .exchange_routes import history_version_choices
        return templates.TemplateResponse(request, "service_simplified.html", page_context(auth,
            _date_configuration=configuration,
            view=view, history_versions=history_version_choices(db, service), simplified_findings=simplified_findings, now=now, finding_type=finding_type, archive_pending=archive_pending, groups=groups,
            query=q, resource=resource, severity=severity, severity_options=severity_options,
            pagination_base=pagination_base, clear_filters_url=clear_filters_url, selected_findings_view=selected_findings_view,
            page=page, page_size=page_size, total_items=total_items, total_pages=total_pages,
        ))
    groups = db.scalars(select(Group).order_by(Group.name)).all()
    affected_images = {}
    image_finding_ids = {finding.id for finding in findings}
    image_finding_ids.update(item["finding_id"] for item in displayed_items if isinstance(item, dict) and item.get("finding_id"))
    if narrow_findings:
        from .findings_query import load_page_support
        affected_images = load_page_support(db, service.id,
            [item for item in service.findings if item.id in image_finding_ids], latest_execution)
    for finding in service.findings:
        if narrow_findings or finding.id not in image_finding_ids:
            continue
        if finding.active and latest_execution:
            observations = [
                observation for observation in finding.observations
                if observation.execution_id == latest_execution.id
            ]
        else:
            latest_observation = max(finding.observations, key=lambda observation: observation.id, default=None)
            observations = [
                observation for observation in finding.observations
                if latest_observation and observation.execution_id == latest_observation.execution_id
            ]
        affected_images[finding.id] = sorted({observation.image for observation in observations})
    for item in displayed_items if finding_state in {"noncompliant", "overdue"} else []:
        if item["type"] == "CVE":
            item["images"] = affected_images.get(item["finding_id"], [])
        else:
            item["images"] = [item["evidence_image"]] if item.get("evidence_image") else []
    latest_payload = latest_execution.raw_payload if latest_execution and isinstance(latest_execution.raw_payload, dict) else {}
    remediation_classes = {item.id: classify_policy_finding(item, latest_payload) for item in displayed_policy_findings}
    from .exchange_routes import history_version_choices
    return templates.TemplateResponse(request, "service.html", page_context(auth,
        _date_configuration=configuration,
        remediation_enabled=remediation_enabled(db),
        view=view, history_versions=history_version_choices(db, service), findings=findings, affected_images=affected_images,
        policy_findings=displayed_policy_findings,
        noncompliance_items=displayed_items if finding_state in {"noncompliant", "overdue"} else [],
        now=now, active_exception=active_exception, finding_state=finding_state, groups=groups,
        overdue_days=view["overdue_days"], saved=request.query_params.get("saved") == "1",
        archive_pending=archive_pending,
        page=page, page_size=page_size, total_items=total_items, total_pages=total_pages,
        finding_type=finding_type, remediation_classes=remediation_classes,
        query=q, resource=resource, severity=severity, severity_options=severity_options,
        pagination_base=pagination_base, clear_filters_url=clear_filters_url, selected_findings_view=selected_findings_view,
    ))


@app.post("/services/{service_key}/artifacts/from-original")
def create_artifact_workspace(
    service_key: str, execution_id: int = Form(), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    execution = db.scalar(select(Execution).where(Execution.id == execution_id, Execution.service_id == service.id if service else False)) if service else None
    if not service or not execution:
        raise HTTPException(404, detail="Service evidence was not found")
    payload = execution.raw_payload if isinstance(execution.raw_payload, dict) else {}
    files = dict(payload.get("helm_source_files") or {})
    if not files:
        raise HTTPException(422, detail="No retained Helm source files are available")
    existing = db.scalar(select(ServiceArtifact).where(ServiceArtifact.service_id == service.id, ServiceArtifact.artifact_type == "helm"))
    if existing:
        return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)
    artifact = ServiceArtifact(service_id=service.id, artifact_type="helm", artifact_name="Helm chart",
                               source_execution_id=execution.id, source_reference=execution.execution_key)
    db.add(artifact); db.flush()
    db.add(_artifact_revision(files, artifact_id=artifact.id, number=1, label="ORIGINAL", user_id=auth.user.id))
    record_audit(db, auth, "artifact.workspace_created", "service_artifact", artifact.id,
                 service_id=service.id, artifact_type="helm", source_execution_id=execution.id)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)


@app.post("/services/{service_key}/artifacts/upload")
def upload_artifact_workspace(
    service_key: str, artifact_type: str = Form(default="helm"), files: list[UploadFile] = File(default=[]),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    check_csrf(auth, csrf_token)
    if artifact_type not in {"helm", "kubernetes"} or not files:
        raise HTTPException(422, detail="Choose a bounded Helm or Kubernetes text artifact")
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    source = {}
    total = 0
    for uploaded in files:
        name = _artifact_file_path(uploaded.filename or "")
        # UploadFile is synchronous under the TestClient and async under ASGI;
        # the route is intentionally kept sync, so use its underlying file.
        raw = uploaded.file.read()
        total += len(raw)
        if total > int(os.getenv("CATS_ARTIFACT_SOURCE_MAX_BYTES", str(100 * 1024 * 1024))):
            raise HTTPException(422, detail="Artifact source exceeds the configured size limit")
        try:
            source[name] = _artifact_text(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise HTTPException(422, detail="Binary artifact files are not supported") from exc
    _persist_uploaded_artifact(
        db, auth, service, artifact_type, source, source_reference="upload",
        artifact_name=f"Uploaded {artifact_type.title()} artifact {uuid.uuid4().hex[:8]}",
    )
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)


@app.post("/services/{service_key}/artifacts/acquire")
def acquire_artifact_workspace(
    service_key: str,
    artifact_type: str = Form(),
    source_method: str = Form(default="upload"),
    source_reference: str = Form(default=""),
    files: list[UploadFile] = File(default=[]),
    csrf_token: str = Form(),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    """Acquire first-class Helm or Kubernetes evidence into an immutable revision."""
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    if artifact_type == "kubernetes":
        if source_method != "upload" or not files:
            raise HTTPException(422, detail="Choose one or more Kubernetes manifest files")
        source: dict[str, str] = {}
        total = 0
        for uploaded in files:
            name = _artifact_file_path(uploaded.filename or "")
            raw = uploaded.file.read()
            total += len(raw)
            if total > 10 * 1024 * 1024:
                raise HTTPException(413, detail="Kubernetes manifest source exceeds the configured 10 MB limit")
            try:
                source[name] = _artifact_text(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise HTTPException(422, detail=f"Kubernetes manifest is not UTF-8 text: {name}") from exc
        _persist_uploaded_artifact(
            db, auth, service, "kubernetes", source, source_reference="upload",
            artifact_name=f"Uploaded Kubernetes artifact {uuid.uuid4().hex[:8]}",
        )
        db.commit()
        return RedirectResponse(f"/services/{service_key}?artifacts=true&artifact_added=kubernetes", status_code=303)

    if artifact_type not in {"helm", "helm_repository", "helm_chart"} or source_method not in {"repository", "oci", "upload"}:
        raise HTTPException(422, detail="Choose Helm Chart or Kubernetes Manifest and a supported source")
    configuration = get_global_configuration(db)
    certificates = parse_json(configuration.get("trusted_ca_certificates"), [])
    certificates = certificates if isinstance(certificates, list) else []
    if artifact_type == "helm_repository" or source_method == "repository":
        if source_method != "repository":
            raise HTTPException(422, detail="Helm repositories must use a repository URL")
        catalog = _discover_helm_repository(source_reference, certificates)
        safe_reference = catalog["repository_url"]
        parsed = urllib.parse.urlsplit(safe_reference)
        repository = ServiceArtifact(
            service_id=service.id, artifact_type="helm_repository",
            artifact_name=f"repository:{uuid.uuid4().hex[:12]}",
            source_reference=safe_reference, source_type="repository",
            source_metadata={}, last_refreshed_at=utcnow(),
        )
        db.add(repository); db.flush()
        charts = _reconcile_repository_catalog(db, auth, service, repository, catalog)
        record_audit(db, auth, "artifact.repository_added", "service_artifact", repository.id,
                     service_id=service.id, repository_url=safe_reference, chart_count=len(charts))
        db.commit()
        return RedirectResponse(f"/services/{service_key}?artifacts=true&artifact_added=repository", status_code=303)

    if source_method == "oci":
        try:
            reference = normalize_chart_reference(source_reference)
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc)) from exc
        if not reference.startswith("oci://"):
            raise HTTPException(422, detail="Choose an OCI registry chart reference")
        archives = _download_public_chart(reference, certificates)
    else:
        if not files:
            raise HTTPException(422, detail="Choose a packaged Helm chart archive")
        archives = [(uploaded.file, uploaded.filename or "chart.tgz") for uploaded in files]
    source, chart_count = _retained_helm_sources(archives)
    chart_name, chart_version = _chart_identity(source)
    safe_reference = ((files[0].filename or "chart.tgz")[:240] if source_method == "upload"
                      else _safe_artifact_source_reference(source_reference, source_method))
    label = {"oci": "OCI Helm chart", "upload": "Uploaded Helm chart"}[source_method]
    _persist_uploaded_artifact(
        db, auth, service, "helm_chart", source, source_reference=safe_reference,
        artifact_name=f"chart:{uuid.uuid4().hex[:12]}", source_type=source_method,
        chart_name=chart_name, chart_version=chart_version,
        source_metadata={"source_type": source_method, "source": safe_reference,
                         "chart_name": chart_name, "chart_version": chart_version},
    )
    record_audit(
        db, auth, "artifact.helm_acquired", "service", service.id,
        service_id=service.id, source_method=source_method,
        chart_count=chart_count, chart_name=chart_name, chart_version=chart_version,
        archive_count=len(archives), file_count=len(source),
    )
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true&artifact_added=helm", status_code=303)


@app.post("/services/{service_key}/artifacts/repositories/{repository_id}/refresh")
def refresh_helm_repository(service_key: str, repository_id: int, csrf_token: str = Form(),
                            db: Session = Depends(get_db),
                            auth: AuthContext = Depends(require_permission("service.edit", scoped=True))):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    repository = db.scalar(select(ServiceArtifact).where(
        ServiceArtifact.id == repository_id, ServiceArtifact.service_id == service.id if service else False,
        ServiceArtifact.artifact_type == "helm_repository", ServiceArtifact.lifecycle_status == "active",
    )) if service else None
    if not repository:
        raise HTTPException(404, detail="Helm repository was not found")
    certificates = parse_json(get_global_configuration(db).get("trusted_ca_certificates"), [])
    catalog = _discover_helm_repository(repository.source_reference or "", certificates if isinstance(certificates, list) else [])
    _reconcile_repository_catalog(db, auth, service, repository, catalog)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true&repository_refreshed=1", status_code=303)


@app.post("/services/{service_key}/artifacts/repositories/{repository_id}/remove")
def remove_helm_repository(service_key: str, repository_id: int, csrf_token: str = Form(),
                           db: Session = Depends(get_db),
                           auth: AuthContext = Depends(require_permission("service.edit", scoped=True))):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    repository = db.scalar(select(ServiceArtifact).where(
        ServiceArtifact.id == repository_id, ServiceArtifact.service_id == service.id if service else False,
        ServiceArtifact.artifact_type == "helm_repository",
    )) if service else None
    if not repository:
        raise HTTPException(404, detail="Helm repository was not found")
    repository.lifecycle_status = "removed"
    repository.updated_at = utcnow()
    record_audit(db, auth, "artifact.repository_removed", "service_artifact", repository.id,
                 service_id=service.id, repository_url=repository.source_reference)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)


@app.post("/services/{service_key}/artifacts/charts/{chart_id}/materialize")
def materialize_helm_chart(service_key: str, chart_id: int, version: str = Form(default=""), csrf_token: str = Form(),
                           db: Session = Depends(get_db),
                           auth: AuthContext = Depends(require_permission("service.edit", scoped=True))):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    chart = db.scalar(select(ServiceArtifact).where(
        ServiceArtifact.id == chart_id, ServiceArtifact.service_id == service.id if service else False,
        ServiceArtifact.artifact_type == "helm_chart", ServiceArtifact.lifecycle_status == "active",
    ).options(selectinload(ServiceArtifact.revisions))) if service else None
    if not chart:
        raise HTTPException(404, detail="Helm chart was not found")
    certificates = parse_json(get_global_configuration(db).get("trusted_ca_certificates"), [])
    _materialize_repository_chart(db, auth, chart, certificates if isinstance(certificates, list) else [], version)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true&chart_materialized={chart.id}", status_code=303)


@app.post("/services/{service_key}/artifacts/repositories/{repository_id}/scan")
def materialize_helm_repository(service_key: str, repository_id: int, csrf_token: str = Form(),
                                db: Session = Depends(get_db),
                                auth: AuthContext = Depends(require_permission("service.edit", scoped=True))):
    """Materialize every currently discovered chart for the existing full-repository scan path."""
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    repository = db.scalar(select(ServiceArtifact).where(
        ServiceArtifact.id == repository_id, ServiceArtifact.service_id == service.id if service else False,
        ServiceArtifact.artifact_type == "helm_repository", ServiceArtifact.lifecycle_status == "active",
    )) if service else None
    if not repository:
        raise HTTPException(404, detail="Helm repository was not found")
    charts = db.scalars(select(ServiceArtifact).where(
        ServiceArtifact.parent_repository_id == repository.id,
        ServiceArtifact.artifact_type == "helm_chart", ServiceArtifact.lifecycle_status == "active",
    ).options(selectinload(ServiceArtifact.revisions))).all()
    certificates = parse_json(get_global_configuration(db).get("trusted_ca_certificates"), [])
    for chart in charts:
        _materialize_repository_chart(db, auth, chart, certificates if isinstance(certificates, list) else [])
    record_audit(db, auth, "artifact.repository_scanned", "service_artifact", repository.id,
                 service_id=service.id, chart_count=len(charts))
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true&repository_materialized={len(charts)}", status_code=303)


@app.post("/services/{service_key}/artifacts/{artifact_id}/files")
def edit_artifact_file(
    service_key: str, artifact_id: int, path: str = Form(), content: str = Form(), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    artifact = db.scalar(select(ServiceArtifact).where(ServiceArtifact.id == artifact_id, ServiceArtifact.service_id == service.id if service else False).options(selectinload(ServiceArtifact.revisions))) if service else None
    if not artifact:
        raise HTTPException(404, detail="Artifact was not found")
    normalized = _artifact_file_path(path)
    latest = max(artifact.revisions, key=lambda item: item.revision_number, default=None)
    files = dict(latest.files if latest else {})
    files[normalized] = _artifact_text(content)
    revision_number = (latest.revision_number if latest else 0) + 1
    db.add(_artifact_revision(files, artifact_id=artifact.id, number=revision_number, label="WORKING", user_id=auth.user.id))
    artifact.updated_at = utcnow()
    record_audit(db, auth, "artifact.file_edited", "service_artifact", artifact.id,
                 service_id=service.id, path=normalized, revision=revision_number)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)


@app.post("/services/{service_key}/artifacts/images")
def add_artifact_image(
    service_key: str, image_reference: str = Form(min_length=1), image_digest: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    image = _ensure_service_image(db, service, _validate_image_reference(image_reference), _validate_image_digest(image_digest))
    if not image:
        raise HTTPException(422, detail="Image reference is required")
    record_audit(db, auth, "artifact.image_added", "service_image", image.id,
                 service_id=service.id, image=image.image_reference, digest=image.image_digest)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)


def _validate_image_reference(value: str) -> str:
    """Accept a bounded OCI reference without ever treating it as a command."""
    reference = str(value or "").strip()
    if not reference or len(reference) > 512 or any(char.isspace() for char in reference) or "\x00" in reference:
        raise HTTPException(422, detail="Enter a valid OCI image reference")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]*", reference):
        raise HTTPException(422, detail="Enter a valid OCI image reference")
    return reference


def _validate_image_digest(value: str) -> str | None:
    digest = str(value or "").strip()
    if not digest:
        return None
    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        raise HTTPException(422, detail="Image digest must be a sha256 digest")
    return digest.lower()


def _artifact_image_revision_event(db: Session, auth: AuthContext, service: Service, action: str, image: ServiceImage, **detail: Any) -> None:
    """Record direct workspace changes without rewriting immutable scan evidence."""
    record_audit(db, auth, action, "service_image", image.id,
                 service_id=service.id, image=image.image_reference,
                 digest=image.image_digest, artifact_revision="working", **detail)


@app.post("/services/{service_key}/artifacts/images/{image_id}/remove")
def remove_artifact_image(
    service_key: str, image_id: int, confirmation: str = Form(default=""), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    """Remove an image from the working inventory while retaining its lineage."""
    check_csrf(auth, csrf_token)
    service, image = _service_image_for_action(db, service_key, image_id)
    if image.lifecycle_status != "active":
        raise HTTPException(409, detail="Only an active image can be removed")
    if confirmation not in {"", image.image_reference, "remove"}:
        raise HTTPException(422, detail="Removal confirmation did not match")
    image.lifecycle_status = "removed"
    image.lifecycle_reason = "Removed from the working artifact revision"
    image.updated_at = utcnow()
    _artifact_image_revision_event(db, auth, service, "artifact.image_removed", image)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)


@app.post("/services/{service_key}/artifacts/images/{image_id}/replace")
def replace_artifact_image(
    service_key: str, image_id: int, replacement_reference: str = Form(min_length=1),
    replacement_digest: str = Form(default=""), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    """Create a replacement lineage row; the original image evidence is immutable."""
    check_csrf(auth, csrf_token)
    service, image = _service_image_for_action(db, service_key, image_id)
    if image.lifecycle_status != "active":
        raise HTTPException(409, detail="Only an active image can be replaced")
    reference = _validate_image_reference(replacement_reference)
    digest = _validate_image_digest(replacement_digest)
    if reference == image.image_reference and digest == image.image_digest:
        raise HTTPException(422, detail="Replacement image must be different from the current image")
    image.lifecycle_status = "replaced"
    image.lifecycle_reason = "Replaced in the working artifact revision"
    image.updated_at = utcnow()
    replacement = ServiceImage(
        service_id=service.id, image_reference=reference,
        image_digest=digest,
        lifecycle_status="active", replacement_of_id=image.id,
        lifecycle_reason="Working artifact replacement", requested_by_id=auth.user.id,
    )
    db.add(replacement)
    db.flush()
    _artifact_image_revision_event(db, auth, service, "artifact.image_replaced", image,
                                   replacement=reference, replacement_digest=replacement.image_digest,
                                   replacement_id=replacement.id)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true", status_code=303)


@app.post("/services/{service_key}/artifacts/images/{image_id}/scan")
def scan_artifact_image(
    service_key: str, image_id: int, csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    """Start the existing scanner for exactly one canonical image identity."""
    check_csrf(auth, csrf_token)
    service, image = _service_image_for_action(db, service_key, image_id)
    if image.lifecycle_status != "active":
        raise HTTPException(409, detail="Only an active image can be scanned")
    job_id = _start_public_scan(image.image_reference, ingest_service_id=service.service_key)
    image.scan_status = "queued"
    image.scan_job_id = job_id
    image.scan_error = None
    image.updated_at = utcnow()
    _artifact_image_revision_event(db, auth, service, "image_scan_started", image, scan_job_id=job_id)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true#container-images", status_code=303)


@app.post("/services/{service_key}/artifacts/images/scan-all")
def scan_all_artifact_images(
    service_key: str, csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    """Queue one existing scanner job per unique digest/reference identity."""
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.images)))
    if not service:
        raise HTTPException(404)
    seen: set[str] = set()
    queued = []
    for image in service.images:
        if image.lifecycle_status != "active":
            continue
        identity = (image.image_digest or image.image_reference).casefold()
        if identity in seen:
            continue
        seen.add(identity)
        job_id = _start_public_scan(image.image_reference, ingest_service_id=service.service_key)
        for duplicate in service.images:
            if duplicate.lifecycle_status == "active" and (duplicate.image_digest or duplicate.image_reference).casefold() == identity:
                duplicate.scan_status, duplicate.scan_job_id, duplicate.scan_error = "queued", job_id, None
                duplicate.updated_at = utcnow()
        queued.append({"image_id": image.id, "job_id": job_id})
        _artifact_image_revision_event(db, auth, service, "image_scan_started", image, scan_job_id=job_id, scan_all=True)
    db.commit()
    return RedirectResponse(f"/services/{service_key}?artifacts=true#container-images", status_code=303)


@app.get("/api/services/{service_key}/artifacts/images/status")
def artifact_image_status(service_key: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.view", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.images)))
    if not service:
        raise HTTPException(404)
    rows = []
    for image in service.images:
        status_value = image.scan_status or "never_scanned"
        job = PUBLIC_JOBS.get(image.scan_job_id or "") if image.scan_job_id else None
        if job:
            if job.get("status") in {"queued", "running"}:
                status_value = "queued" if job.get("status") == "queued" else "scanning"
            elif job.get("status") == "complete":
                status_value = "scanned"
                image.scan_status = status_value
                image.last_scanned_at = image.last_scanned_at or utcnow()
            elif job.get("status") in {"error", "incomplete", "cancelled"}:
                status_value = "failed"
                image.scan_status = status_value
                image.scan_error = str(job.get("error") or job.get("status"))[:500]
        elif status_value in {"queued", "scanning"} and image.updated_at and aware(image.updated_at) < utcnow() - timedelta(hours=2):
            # PUBLIC_JOBS is intentionally ephemeral.  Do not leave a durable
            # inventory row claiming work is active after a process restart.
            status_value = "failed"
            image.scan_status = status_value
            image.scan_error = "The scanner job state expired before completion. Re-scan to try again."
        rows.append({"id": image.id, "status": status_value, "job_id": image.scan_job_id,
                     "last_scanned_at": image.last_scanned_at.isoformat() if image.last_scanned_at else None,
                     "error": image.scan_error})
    db.commit()
    return {"images": rows}




def _focused_export_book(headers: list[str], rows: list[list]) -> Workbook:
    from .exchange import literal
    book = Workbook()
    sheet = book.active
    sheet.title = "CATS Export"
    sheet.append(headers)
    for row_number, row in enumerate(rows, 2):
        sheet.append([None] * len(headers))
        for index, value in enumerate(row, 1):
            literal(sheet.cell(row_number, index), value)
    format_sheet(sheet)
    return book


@app.get("/services/{service_key}/exports/mitigations.xlsx")
def export_service_mitigations(service_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    entries = db.execute(select(PoamEntry.id, PoamEntry.service_version, PoamEntry.item_type,
        PoamEntry.title, PoamEntry.remediation, PoamEntry.status, PoamEntry.due_date, PoamEntry.ticket)
        .where(PoamEntry.service_id == service.id, PoamEntry.remediation.is_not(None), PoamEntry.remediation != "")
        .order_by(PoamEntry.id).execution_options(yield_per=500))
    rows = ([item.id, item.service_version, item.item_type, item.title, item.remediation,
             item.status, item.due_date.isoformat() if item.due_date else "", item.ticket or ""] for item in entries)
    return workbook_response(_focused_export_book(
        ["Entry ID", "Service Version", "Type", "Title", "Mitigation", "Status", "Due Date", "Ticket"], rows),
        f"{service_key}-mitigations.xlsx")


@app.get("/services/{service_key}/exports/findings.xlsx")
def export_service_findings(service_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    latest_id = db.scalar(select(Execution.id).where(Execution.service_id == service.id)
        .order_by(Execution.scanned_at.desc(), Execution.id.desc()).limit(1))
    def export_rows():
        observations = db.execute(select(Finding.cve, Finding.severity, Finding.active,
            FindingObservation.image, FindingObservation.package, FindingObservation.installed_version,
            FindingObservation.fixed_version, Finding.first_seen, Finding.last_seen)
            .join(FindingObservation, FindingObservation.finding_id == Finding.id)
            .where(Finding.service_id == service.id, FindingObservation.execution_id == latest_id)
            .order_by(Finding.id, FindingObservation.id).execution_options(yield_per=500))
        for item in observations:
            yield ["Vulnerability", *item[:7], item.first_seen.isoformat(), item.last_seen.isoformat()]
        policies = db.execute(select(PolicyFinding.finding, PolicyFinding.severity, PolicyFinding.active,
            PolicyFinding.target, PolicyFinding.first_seen, PolicyFinding.last_seen)
            .where(PolicyFinding.service_id == service.id).order_by(PolicyFinding.id)
            .execution_options(yield_per=500))
        for item in policies:
            yield ["Configuration", item.finding, item.severity, item.active, item.target or "",
                   "", "", "", item.first_seen.isoformat(), item.last_seen.isoformat()]
    rows = export_rows()
    return workbook_response(_focused_export_book(
        ["Type", "Finding", "Severity", "Active", "Image or Target", "Package", "Installed Version",
         "Fixed Version", "First Seen", "Last Seen"], rows), f"{service_key}-findings.xlsx")


@app.get("/services/{service_key}/exports/diagrams.zip")
def export_service_diagrams(service_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    from .activity_queries import latest_evidence_execution
    latest = latest_evidence_execution(db, service.id, architecture=True)
    if latest is None:
        raise HTTPException(422, detail="No architecture evidence is available to diagram")
    graph = build_architecture_graph(latest.raw_payload or {})
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for view_name in ("all", "configuration", "containers", "flow", "network", "storage"):
            archive.writestr(f"architecture-{view_name}.svg", build_architecture_svg(graph, view_name))
        archive.writestr("helm-diagram.svg", build_helm_diagram(service, latest))
    output.seek(0)
    return StreamingResponse(output, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{service_key}-diagrams.zip"'})


@app.get("/services/{service_key}/exports/sbom.json")
def export_service_sbom_components(service_key: str, db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    from .activity_queries import latest_evidence_execution
    latest = latest_evidence_execution(db, service.id)
    if latest is None or not (latest.raw_payload or {}).get("sbom_components"):
        raise HTTPException(422, detail="No retained SBOM component evidence is available")
    return JSONResponse({"format": "cats-retained-sbom-components-v1", "service": service_key,
        "execution_id": latest.execution_key, "components": latest.raw_payload["sbom_components"]},
        headers={"Content-Disposition": f'attachment; filename="{service_key}-sbom-components.json"'})


@app.get("/services/{service_key}/exports/{kind}.xlsx")
def export_purpose_workbook(service_key: str, kind: str, db: Session = Depends(get_db),
                            auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    if kind not in PURPOSE_CATALOG:
        raise HTTPException(404)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if service is None:
        raise HTTPException(404)
    columns, _, _ = purpose_template_for_service(db, kind, service)
    return workbook_response(purpose_workbook_for(db, service, kind, columns),
                             f"{service.service_key}-{kind}.xlsx")


@app.get("/services/{service_key}/export.xlsx")
def export_service(service_key: str, include_diagrams: bool = False, version: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.export", scoped=True))):
    if version:
        raise HTTPException(422, detail="This workbook is current-state only. Use the version-selected spreadsheet exchange for historical exports")
    now = utcnow()
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(
        selectinload(Service.findings).selectinload(Finding.exceptions),
        selectinload(Service.policy_findings).selectinload(PolicyFinding.exceptions),
        selectinload(Service.findings).selectinload(Finding.observations),
        selectinload(Service.executions).defer(Execution.raw_payload), selectinload(Service.archive_events), selectinload(Service.groups),
        selectinload(Service.images),
        selectinload(Service.poam_entries).selectinload(PoamEntry.finding),
        selectinload(Service.poam_entries).selectinload(PoamEntry.policy_finding),
        selectinload(Service.poam_entries).selectinload(PoamEntry.created_by),
        selectinload(Service.poam_entries).selectinload(PoamEntry.approved_by),
    ))
    if not service:
        raise HTTPException(404)
    configuration = configuration_for_service(db, service)
    view = service_view(service, now, configuration)
    latest_execution = max(service.executions, key=lambda execution: aware(execution.scanned_at), default=None)
    from sqlalchemy import String, cast
    # Keep the Python predicate below for its service_id-or-service_key fallback
    # semantics while preventing unrelated audit rows and actors from loading.
    if db.get_bind().dialect.name == "postgresql":
        unusual_detail = or_(*(func.json_typeof(AuditEvent.detail[key]).in_(("boolean", "array", "object"))
                              for key in ("service_id", "service_key")))
    else:
        unusual_detail = or_(*(func.json_type(AuditEvent.detail, f"$.{key}").in_(("true", "false", "array", "object"))
                              for key in ("service_id", "service_key")))
    audit_events = db.scalars(select(AuditEvent).where(or_(
        and_(AuditEvent.target_type == "service", AuditEvent.target_id == str(service.id)),
        cast(AuditEvent.detail["service_id"].as_string(), String).in_((str(service.id), service.service_key)),
        cast(AuditEvent.detail["service_key"].as_string(), String).in_((str(service.id), service.service_key)),
        unusual_detail,
    )).options(selectinload(AuditEvent.actor)).order_by(AuditEvent.created_at)).all()
    service_audit = []
    for event in audit_events:
        detail = event.detail if isinstance(event.detail, dict) else {}
        if event.target_type == "service" and str(event.target_id) == str(service.id):
            service_audit.append(event)
        elif str(detail.get("service_id") or detail.get("service_key")) in {str(service.id), service.service_key}:
            service_audit.append(event)
    histories = db.scalars(
        select(PoamHistory).join(PoamEntry, PoamEntry.id == PoamHistory.poam_id)
        .where(PoamEntry.service_id == service.id)
        .options(selectinload(PoamHistory.actor))
        .order_by(PoamHistory.created_at)
    ).all()
    workbook = build_service_workbook(
        service, view, configuration, now, latest_execution,
        activity_events=service_audit, poam_histories=histories,
    )
    if not include_diagrams:
        return workbook_response(workbook, service_export_filename(service, now))
    archive = BytesIO()
    with ZipFile(archive, "w", ZIP_DEFLATED) as bundle:
        workbook_bytes = BytesIO()
        workbook.save(workbook_bytes)
        bundle.writestr("service-export.xlsx", workbook_bytes.getvalue())
        graph = build_architecture_graph(latest_execution.raw_payload if latest_execution else {})
        for view_name in ("all", "configuration", "containers", "flow", "network", "storage"):
            bundle.writestr(f"architecture-{view_name}.svg", build_architecture_svg(graph, view_name))
        bundle.writestr("legacy-helm-diagram.svg", build_helm_diagram(service, latest_execution))
    archive.seek(0)
    filename = service_export_filename(service, now).rsplit(".", 1)[0] + ".zip"
    return StreamingResponse(archive, media_type="application/zip", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.get("/services/{service_key}/helm-diagram.svg")
def export_service_helm_diagram(service_key: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.view", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    from .activity_queries import latest_evidence_execution
    latest_execution = latest_evidence_execution(db, service.id)
    return Response(build_helm_diagram(service, latest_execution), media_type="image/svg+xml")


@app.get("/services/{service_key}/watchlist/{match_id}", response_class=HTMLResponse)
def watchlist_match_detail(service_key: str, match_id: int, request: Request,
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.view", scoped=True))):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    match = db.scalar(select(DependencyWatchlistMatch).where(
        DependencyWatchlistMatch.id == match_id, DependencyWatchlistMatch.service_id == service.id))
    if not match:
        raise HTTPException(404)
    return templates.TemplateResponse(request, "watchlist_match.html", page_context(
        auth, service=service, match=match))


@app.get("/services/{service_key}/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(
    service_key: str, finding_id: int, request: Request,
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.view", scoped=True)),
):
    finding = db.scalar(select(Finding).where(Finding.id == finding_id).options(
        selectinload(Finding.service).selectinload(Service.executions),
        selectinload(Finding.service).selectinload(Service.groups),
        selectinload(Finding.observations),
        selectinload(Finding.exceptions),
    ))
    if not finding or finding.service.service_key != service_key:
        raise HTTPException(404)
    now = utcnow()
    configuration = configuration_for_service(db, finding.service)
    risk = service_view(finding.service, now, configuration)["risk_metadata"].get(finding.id, {})
    latest_execution = max(finding.service.executions, key=lambda execution: aware(execution.scanned_at), default=None)
    current_observations = [
        observation for observation in finding.observations
        if finding.active and latest_execution and observation.execution_id == latest_execution.id
    ]
    evidence_observation = current_observations[0] if current_observations else (
        max(finding.observations, key=lambda observation: observation.id, default=None)
    )
    evidence = evidence_observation.evidence if evidence_observation else {}
    history = sorted(finding.observations, key=lambda observation: observation.id, reverse=True)
    due_days = max(1, int(configuration.get("overdue_days", "90")))
    if configuration.get("compliance_mode") == "raw":
        try:
            raw_rules = json.loads(configuration.get("raw_due_rules", "[]"))
            raw_days = {
                str(rule.get("severity", "")).lower(): max(1, int(rule.get("days", due_days)))
                for rule in raw_rules
            }
            due_days = raw_days.get(finding.severity.lower(), due_days)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return templates.TemplateResponse(request, "finding.html", page_context(auth,
        remediation_enabled=remediation_enabled(db),
        finding=finding, service=finding.service, now=now,
        age=(now - aware(finding.episode_started)).days if finding.active else None,
        exception=active_exception(finding, now), evidence=evidence,
        current_observations=current_observations, history=history,
        risk=risk,
        remediation_classification={"classification": "REVIEW REQUIRED", "reason": "Image patching and its Helm source update require a candidate job."},
        due_date=(aware(finding.episode_started) + timedelta(days=due_days) if finding.active else None),
    ))


@app.post("/findings/{finding_id}/exceptions")
def request_exception(
    finding_id: int, justification: str = Form(min_length=3), expires_at: datetime = Form(),
    ticket: str = Form(default=""), bulk_scope: str = Form(default=""), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("exception.request", scoped=True)),
):
    check_csrf(auth, csrf_token)
    finding = db.scalar(select(Finding).where(Finding.id == finding_id).options(selectinload(Finding.service).selectinload(Service.groups)))
    if not finding:
        raise HTTPException(404)
    bulk_group = cybersecurity_group(finding.service) if bulk_scope == "group" else None
    if bulk_scope == "group" and not bulk_group:
        raise HTTPException(422, detail="This service does not have one unambiguous Cybersecurity group scope")
    expires_at = aware(expires_at)
    now = utcnow()
    if expires_at <= now:
        raise HTTPException(422, detail="Expiration must be in the future")
    maximum_exception = int(configuration_for_service(db, finding.service).get("exception_max_days", "365"))
    if maximum_exception and expires_at > now + timedelta(days=maximum_exception):
        raise HTTPException(422, detail=f"Exception expiration cannot exceed {maximum_exception} days")
    pending = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.request_type == "exception", WorkflowRequest.finding_id == finding.id,
        WorkflowRequest.status == "pending",
    ))
    if pending:
        raise HTTPException(409, detail="An exception request is already pending")
    workflow = WorkflowRequest(
        request_type="exception", service_id=finding.service_id, finding_id=finding.id,
        requested_by_id=auth.user.id, justification=justification,
        requested_expires_at=expires_at, ticket=ticket or None,
        bulk_group_id=bulk_group.id if bulk_group else None,
    )
    db.add(workflow)
    db.flush()
    record_audit(db, auth, "exception.requested", "workflow_request", workflow.id, service_id=finding.service_id)
    db.commit()
    return RedirectResponse(f"/services/{finding.service.service_key}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/policy-findings/{policy_finding_id}/exceptions")
def request_policy_exception(
    policy_finding_id: int, justification: str = Form(min_length=3), expires_at: datetime = Form(),
    ticket: str = Form(default=""), bulk_scope: str = Form(default=""), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    finding = db.scalar(select(PolicyFinding).where(PolicyFinding.id == policy_finding_id).options(
        selectinload(PolicyFinding.service).selectinload(Service.groups)
    ))
    if not finding:
        raise HTTPException(404)
    if not auth.has("exception.request", finding.service_id):
        raise HTTPException(403, detail="Permission denied")
    bulk_group = cybersecurity_group(finding.service) if bulk_scope == "group" else None
    if bulk_scope == "group" and not bulk_group:
        raise HTTPException(422, detail="This service does not have one unambiguous Cybersecurity group scope")
    expires_at = aware(expires_at)
    now = utcnow()
    if expires_at <= now:
        raise HTTPException(422, detail="Expiration must be in the future")
    maximum_exception = int(configuration_for_service(db, finding.service).get("exception_max_days", "365"))
    if maximum_exception and expires_at > now + timedelta(days=maximum_exception):
        raise HTTPException(422, detail=f"Exception expiration cannot exceed {maximum_exception} days")
    pending = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.request_type == "exception",
        WorkflowRequest.policy_finding_id == finding.id,
        WorkflowRequest.status == "pending",
    ))
    if pending:
        raise HTTPException(409, detail="An exception request is already pending")
    workflow = WorkflowRequest(
        request_type="exception", service_id=finding.service_id,
        policy_finding_id=finding.id, requested_by_id=auth.user.id,
        justification=justification, requested_expires_at=expires_at,
        ticket=ticket.strip() or None, bulk_group_id=bulk_group.id if bulk_group else None,
    )
    db.add(workflow)
    db.flush()
    record_audit(db, auth, "exception.requested", "workflow_request", workflow.id,
                 service_id=finding.service_id, finding_type="configuration")
    db.commit()
    return RedirectResponse(f"/services/{finding.service.service_key}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/findings/{finding_id}/poams")
def request_poam(
    finding_id: int, title: str = Form(min_length=3), remediation: str = Form(min_length=3),
    due_date: str = Form(default=""), ticket: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("poam.request", scoped=True)),
):
    """Create a pending vulnerability POA&M entry for Cybersecurity review."""
    check_csrf(auth, csrf_token)
    finding = db.scalar(select(Finding).where(Finding.id == finding_id).options(selectinload(Finding.service).selectinload(Service.groups)))
    if not finding:
        raise HTTPException(404)
    due_date = optional_form_datetime(due_date, "POA&M due date")
    if due_date is not None:
        if due_date <= utcnow():
            raise HTTPException(422, detail="POA&M due date must be in the future")
    pending = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.request_type == "poam", WorkflowRequest.finding_id == finding.id,
        WorkflowRequest.status == "pending",
    ))
    if pending:
        raise HTTPException(409, detail="A POA&M request is already pending")
    entry = PoamEntry(
        service_id=finding.service_id, finding_id=finding.id, item_type="vulnerability",
        title=title.strip(), description=f"Vulnerability finding {finding.cve}",
        remediation=remediation.strip(), due_date=due_date, ticket=ticket or None,
        created_by_id=auth.user.id,
    )
    db.add(entry)
    db.flush()
    workflow = WorkflowRequest(
        request_type="poam", service_id=finding.service_id, finding_id=finding.id,
        poam_id=entry.id, requested_by_id=auth.user.id,
        justification=f"{entry.title}\n{entry.description}\nRemediation: {entry.remediation}",
        requested_expires_at=due_date, ticket=ticket or None,
    )
    db.add(workflow)
    db.flush()
    db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id, action="requested", note="Submitted for Cybersecurity approval"))
    record_audit(db, auth, "poam.requested", "workflow_request", workflow.id, service_id=finding.service_id)
    db.commit()
    return RedirectResponse(f"/services/{finding.service.service_key}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/policy-findings/{policy_finding_id}/poams")
def request_policy_poam(
    policy_finding_id: int, title: str = Form(min_length=3), remediation: str = Form(min_length=3),
    due_date: str = Form(default=""), ticket: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    finding = db.scalar(select(PolicyFinding).where(PolicyFinding.id == policy_finding_id).options(
        selectinload(PolicyFinding.service).selectinload(Service.groups)
    ))
    if not finding:
        raise HTTPException(404)
    if not auth.has("poam.request", finding.service_id):
        raise HTTPException(403, detail="Permission denied")
    due_date = optional_form_datetime(due_date, "POA&M due date")
    if due_date is not None and due_date <= utcnow():
        raise HTTPException(422, detail="POA&M due date must be in the future")
    pending = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.request_type == "poam",
        WorkflowRequest.policy_finding_id == finding.id,
        WorkflowRequest.status == "pending",
    ))
    if pending:
        raise HTTPException(409, detail="A POA&M request is already pending")
    source_detail = finding.description or finding.title
    detail = f"Configuration finding {finding.finding}"
    if source_detail:
        detail = f"{detail}: {source_detail}"
    entry = PoamEntry(
        service_id=finding.service_id, policy_finding_id=finding.id,
        item_type="configuration", title=title.strip(), description=detail,
        remediation=remediation.strip(), due_date=due_date,
        ticket=ticket.strip() or None, created_by_id=auth.user.id,
    )
    db.add(entry)
    db.flush()
    workflow = WorkflowRequest(
        request_type="poam", service_id=finding.service_id,
        policy_finding_id=finding.id, poam_id=entry.id,
        requested_by_id=auth.user.id,
        justification=f"{entry.title}\n{entry.description}\nRemediation: {entry.remediation}",
        requested_expires_at=due_date, ticket=entry.ticket,
    )
    db.add(workflow)
    db.flush()
    db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id,
                       action="requested", note="Submitted for Cybersecurity approval"))
    record_audit(db, auth, "poam.requested", "workflow_request", workflow.id,
                 service_id=finding.service_id, finding_type="configuration")
    db.commit()
    return RedirectResponse(f"/services/{finding.service.service_key}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/poam", response_class=HTMLResponse)
def poam_page(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    allowed = auth.accessible_service_ids("service.view")
    service_query = select(Service).options(selectinload(Service.groups)).order_by(Service.name)
    if allowed is not None:
        service_query = service_query.where(Service.id.in_(allowed))
    visible_services = db.scalars(service_query).all()
    visible_ids = [service.id for service in visible_services]
    counts = {
        service_id: {"total": 0, "active": 0, "pending": 0, "overdue": 0}
        for service_id in visible_ids
    }
    if visible_ids:
        instant = utcnow()
        summaries = db.execute(select(PoamEntry.service_id, func.count().label("total"),
            func.sum(case((PoamEntry.status == "active", 1), else_=0)).label("active"),
            func.sum(case((PoamEntry.status == "pending_approval", 1), else_=0)).label("pending"),
            func.sum(case((and_(PoamEntry.status == "active", PoamEntry.due_date < instant), 1),
                          else_=0)).label("overdue"))
            .where(PoamEntry.service_id.in_(visible_ids)).group_by(PoamEntry.service_id)).mappings()
        for summary in summaries:
            counts[summary["service_id"]] = {key: int(summary[key] or 0)
                for key in ("total", "active", "pending", "overdue")}
    service_summaries = [{"service": service, **counts[service.id]} for service in visible_services]
    services = [service for service in visible_services if auth.has("poam.request", service.id)]
    return templates.TemplateResponse(request, "poam.html", page_context(
        auth, service_summaries=service_summaries, poam_services=services,
    ))


@app.get("/remediations", response_class=HTMLResponse)
def remediations_page(
    request: Request, tab: str = "poams", page: int = 1, page_size: int = 50,
    service: str = "", identifier: str = "", title: str = "", status_filter: str = "all",
    owner: str = "", severity: str = "", due_from: str = "", due_to: str = "",
    expiration_from: str = "", expiration_to: str = "", sort: str = "actionable", direction: str = "asc",
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    """Enterprise remediation oversight, scoped and paginated in the database."""
    if tab not in {"poams", "exceptions", "mitigations"}:
        raise HTTPException(422, detail="Unknown remediation tab")
    if page_size not in {25, 50, 100}:
        raise HTTPException(422, detail="Page size must be 25, 50, or 100")
    page = max(1, page)
    allowed = auth.accessible_service_ids("service.view")
    service_query = select(Service).order_by(Service.name)
    if allowed is not None:
        service_query = service_query.where(Service.id.in_(allowed))
    services = db.scalars(service_query).all()
    visible_ids = [item.id for item in services]
    service_filter_ids = set(visible_ids)
    service_term = service.strip()
    if service_term:
        lowered = service_term.casefold()
        service_filter_ids = {item.id for item in services if lowered in item.name.casefold() or lowered in item.service_key.casefold() or service_term == str(item.id)}
    now = utcnow()
    def parse_date(value: str):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(422, detail="Dates must use ISO format")
    parsed_due_from, parsed_due_to = parse_date(due_from), parse_date(due_to)
    parsed_exp_from, parsed_exp_to = parse_date(expiration_from), parse_date(expiration_to)
    identifier_term, title_term, owner_term = identifier.strip(), title.strip(), owner.strip()
    severity_term = severity.strip()
    status_values = {"all", "active", "pending_approval", "completed", "rejected", "overdue", "expired", "revoked"}
    if status_filter not in status_values:
        raise HTTPException(422, detail="Unknown remediation status")
    def apply_poam_filters(query, item_type=None):
        query = query.where(PoamEntry.service_id.in_(service_filter_ids or {-1}))
        if item_type:
            query = query.where(PoamEntry.item_type == item_type)
        else:
            query = query.where(PoamEntry.item_type != "mitigation")
        if status_filter not in {"all", "overdue"}:
            query = query.where(PoamEntry.status == status_filter)
        if status_filter == "overdue":
            query = query.where(PoamEntry.status == "active", PoamEntry.due_date.is_not(None), PoamEntry.due_date < now)
        if title_term:
            query = query.where(PoamEntry.title.ilike(f"%{title_term}%"))
        if owner_term:
            query = query.join(User, User.id == PoamEntry.created_by_id).where(User.display_name.ilike(f"%{owner_term}%"))
        if parsed_due_from:
            query = query.where(PoamEntry.due_date >= parsed_due_from)
        if parsed_due_to:
            query = query.where(PoamEntry.due_date <= parsed_due_to)
        if identifier_term or severity_term:
            query = query.outerjoin(Finding, Finding.id == PoamEntry.finding_id).outerjoin(PolicyFinding, PolicyFinding.id == PoamEntry.policy_finding_id)
            if identifier_term:
                query = query.where(or_(Finding.cve.ilike(f"%{identifier_term}%"), PolicyFinding.finding.ilike(f"%{identifier_term}%")))
            if severity_term:
                query = query.where(or_(Finding.severity == severity_term, PolicyFinding.severity == severity_term))
        return query
    def poam_order(query):
        descending = direction.lower() == "desc"
        if sort in {"due", "actionable"}:
            return query.order_by(PoamEntry.due_date.desc() if descending else PoamEntry.due_date.asc(), PoamEntry.created_at.desc())
        if sort == "status":
            return query.order_by(PoamEntry.status.desc() if descending else PoamEntry.status.asc(), PoamEntry.created_at.desc())
        return query.order_by(PoamEntry.created_at.asc() if not descending else PoamEntry.created_at.desc())
    poams, mitigations, exceptions = [], [], []
    total_items = 0
    if tab in {"poams", "mitigations"}:
        base = apply_poam_filters(select(PoamEntry).options(
            selectinload(PoamEntry.service), selectinload(PoamEntry.finding), selectinload(PoamEntry.policy_finding),
            selectinload(PoamEntry.created_by), selectinload(PoamEntry.approved_by),
        ), "mitigation" if tab == "mitigations" else None)
        total_items = db.scalar(select(func.count()).select_from(base.order_by(None).subquery())) or 0
        rows = db.scalars(poam_order(base).offset((page - 1) * page_size).limit(page_size)).all()
        if tab == "mitigations":
            mitigations = rows
        else:
            poams = rows
    else:
        def exception_state_clause(model):
            if status_filter == "active": return and_(model.revoked_at.is_(None), model.starts_at <= now, model.expires_at > now)
            if status_filter == "expired": return and_(model.revoked_at.is_(None), model.expires_at <= now)
            if status_filter == "revoked": return model.revoked_at.is_not(None)
            if status_filter == "pending_approval": return false()
            return true()
        vul_query = select(ExceptionRecord).join(Finding).where(Finding.service_id.in_(service_filter_ids or {-1}), exception_state_clause(ExceptionRecord)).options(selectinload(ExceptionRecord.finding).selectinload(Finding.service)).order_by(ExceptionRecord.created_at.desc())
        cfg_query = select(PolicyExceptionRecord).join(PolicyFinding).where(PolicyFinding.service_id.in_(service_filter_ids or {-1}), exception_state_clause(PolicyExceptionRecord)).options(selectinload(PolicyExceptionRecord.policy_finding).selectinload(PolicyFinding.service)).order_by(PolicyExceptionRecord.created_at.desc())
        if identifier_term:
            vul_query = vul_query.where(Finding.cve.ilike(f"%{identifier_term}%")); cfg_query = cfg_query.where(PolicyFinding.finding.ilike(f"%{identifier_term}%"))
        if severity_term:
            vul_query = vul_query.where(Finding.severity == severity_term); cfg_query = cfg_query.where(PolicyFinding.severity == severity_term)
        if owner_term:
            vul_query = vul_query.where(ExceptionRecord.approved_by.ilike(f"%{owner_term}%")); cfg_query = cfg_query.where(PolicyExceptionRecord.approved_by.ilike(f"%{owner_term}%"))
        if parsed_exp_from:
            vul_query = vul_query.where(ExceptionRecord.expires_at >= parsed_exp_from); cfg_query = cfg_query.where(PolicyExceptionRecord.expires_at >= parsed_exp_from)
        if parsed_exp_to:
            vul_query = vul_query.where(ExceptionRecord.expires_at <= parsed_exp_to); cfg_query = cfg_query.where(PolicyExceptionRecord.expires_at <= parsed_exp_to)
        from sqlalchemy import literal, union_all
        pending_query = select(WorkflowRequest).where(
            WorkflowRequest.service_id.in_(service_filter_ids or {-1}),
            WorkflowRequest.request_type == "exception", WorkflowRequest.status == "pending",
            or_(WorkflowRequest.finding_id.in_(select(Finding.id)),
                WorkflowRequest.policy_finding_id.in_(select(PolicyFinding.id))),
        ).options(selectinload(WorkflowRequest.service), selectinload(WorkflowRequest.finding),
                  selectinload(WorkflowRequest.policy_finding))
        if status_filter not in {"all", "pending_approval"}:
            pending_query = pending_query.where(false())
        if identifier_term:
            pending_query = pending_query.where(or_(WorkflowRequest.finding_id.in_(select(Finding.id).where(Finding.cve.ilike(f"%{identifier_term}%"))), WorkflowRequest.policy_finding_id.in_(select(PolicyFinding.id).where(PolicyFinding.finding.ilike(f"%{identifier_term}%")))))
        # Select one mixed page before hydrating any exception evidence graphs.
        def exception_ids(query, model, kind):
            return query.order_by(None).with_only_columns(
                model.id.label("record_id"), literal(kind).label("record_type"),
                model.created_at.label("created_at"), maintain_column_froms=True,
            )
        combined = union_all(exception_ids(vul_query, ExceptionRecord, "vulnerability"),
                             exception_ids(cfg_query, PolicyExceptionRecord, "configuration"),
                             exception_ids(pending_query, WorkflowRequest, "pending")).subquery()
        total_items = db.scalar(select(func.count()).select_from(combined)) or 0
        page = min(page, max(1, (total_items + page_size - 1) // page_size))
        selected = db.execute(select(combined.c.record_id, combined.c.record_type).order_by(
            combined.c.created_at.desc(), combined.c.record_type, combined.c.record_id,
        ).offset((page - 1) * page_size).limit(page_size)).all()
        ids_by_type = {kind: [row.record_id for row in selected if row.record_type == kind]
                       for kind in ("vulnerability", "configuration", "pending")}
        for record in db.scalars(vul_query.where(ExceptionRecord.id.in_(ids_by_type["vulnerability"]))).all():
            finding = record.finding; state = "Revoked" if record.revoked_at else ("Expired" if aware(record.expires_at) < now else "Active")
            exceptions.append({"kind":"Vulnerability", "item":finding.cve, "service":finding.service, "severity":finding.severity, "status":state, "expires_at":record.expires_at, "days_remaining":max(0,(aware(record.expires_at)-now).days) if state == "Active" else 0, "approved_by":record.approved_by, "created_at":record.created_at, "justification":record.justification, "record_id":record.id, "revoke_href":f"/exceptions/{record.id}/revoke", "href":f"/services/{finding.service.service_key}/findings/{finding.id}"})
        for record in db.scalars(cfg_query.where(PolicyExceptionRecord.id.in_(ids_by_type["configuration"]))).all():
            finding = record.policy_finding; state = "Revoked" if record.revoked_at else ("Expired" if aware(record.expires_at) < now else "Active")
            exceptions.append({"kind":"Configuration", "item":finding.finding, "service":finding.service, "severity":finding.severity, "status":state, "expires_at":record.expires_at, "days_remaining":max(0,(aware(record.expires_at)-now).days) if state == "Active" else 0, "approved_by":record.approved_by, "created_at":record.created_at, "justification":record.justification, "record_id":record.id, "revoke_href":f"/policy-exceptions/{record.id}/revoke", "href":f"/services/{finding.service.service_key}?finding_state=exceptions&finding_type=configuration"})
        for workflow in db.scalars(pending_query.where(WorkflowRequest.id.in_(ids_by_type["pending"]))).all():
            target = workflow.finding or workflow.policy_finding
            if not target:
                continue
            is_vulnerability = bool(workflow.finding)
            exceptions.append({"kind": "Vulnerability" if is_vulnerability else "Configuration", "item": target.cve if is_vulnerability else target.finding, "service": workflow.service, "severity": target.severity, "status": "Pending", "expires_at": workflow.requested_expires_at, "days_remaining": 0, "approved_by": "Pending review", "created_at": workflow.created_at, "justification": workflow.justification, "record_id": workflow.id, "href": f"/services/{workflow.service.service_key}/findings/{target.id}" if is_vulnerability else f"/services/{workflow.service.service_key}?finding_state=exceptions&finding_type=configuration"})
        positions = {(row.record_type, row.record_id): index for index, row in enumerate(selected)}
        exceptions.sort(key=lambda item: positions[(
            "pending" if item["status"] == "Pending" else
            "vulnerability" if item["kind"] == "Vulnerability" else "configuration",
            item["record_id"],
        )])
    active_poams = db.scalar(select(func.count(PoamEntry.id)).where(PoamEntry.service_id.in_(service_filter_ids or {-1}), PoamEntry.item_type != "mitigation", PoamEntry.status == "active")) or 0
    overdue_poams = db.scalar(select(func.count(PoamEntry.id)).where(PoamEntry.service_id.in_(service_filter_ids or {-1}), PoamEntry.item_type != "mitigation", PoamEntry.status == "active", PoamEntry.due_date < now)) or 0
    active_exceptions = db.scalar(select(func.count(ExceptionRecord.id)).join(Finding).where(Finding.service_id.in_(service_filter_ids or {-1}), ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now)) or 0
    active_exceptions += db.scalar(select(func.count(PolicyExceptionRecord.id)).join(PolicyFinding).where(PolicyFinding.service_id.in_(service_filter_ids or {-1}), PolicyExceptionRecord.revoked_at.is_(None), PolicyExceptionRecord.starts_at <= now, PolicyExceptionRecord.expires_at > now)) or 0
    expiring_exceptions = db.scalar(select(func.count(ExceptionRecord.id)).join(Finding).where(Finding.service_id.in_(service_filter_ids or {-1}), ExceptionRecord.revoked_at.is_(None), ExceptionRecord.starts_at <= now, ExceptionRecord.expires_at > now, ExceptionRecord.expires_at <= now + timedelta(days=30))) or 0
    expiring_exceptions += db.scalar(select(func.count(PolicyExceptionRecord.id)).join(PolicyFinding).where(PolicyFinding.service_id.in_(service_filter_ids or {-1}), PolicyExceptionRecord.revoked_at.is_(None), PolicyExceptionRecord.starts_at <= now, PolicyExceptionRecord.expires_at > now, PolicyExceptionRecord.expires_at <= now + timedelta(days=30))) or 0
    active_mitigations = db.scalar(select(func.count(PoamEntry.id)).where(PoamEntry.service_id.in_(service_filter_ids or {-1}), PoamEntry.item_type == "mitigation", PoamEntry.status == "active")) or 0
    page_count = max(1, (total_items + page_size - 1) // page_size)
    page = min(page, page_count)
    pagination_params = [("tab", tab), ("page_size", page_size), ("service", service), ("identifier", identifier), ("title", title), ("status_filter", status_filter), ("owner", owner), ("severity", severity), ("due_from", due_from), ("due_to", due_to), ("expiration_from", expiration_from), ("expiration_to", expiration_to), ("sort", sort), ("direction", direction)]
    pagination_base = "/remediations?" + urllib.parse.urlencode([(key, value) for key, value in pagination_params if value not in (None, "")])
    return templates.TemplateResponse(request, "remediations.html", page_context(auth,
        tab=tab, services=services, poams=poams, exceptions=exceptions, mitigations=mitigations, now=now,
        poam_services=[item for item in services if auth.has("poam.request", item.id)],
        summary={"poams": active_poams, "poams_overdue": overdue_poams, "exceptions": active_exceptions, "exceptions_soon": expiring_exceptions, "mitigations": active_mitigations},
        filters={"service": service, "identifier": identifier, "title": title, "status_filter": status_filter, "owner": owner, "severity": severity, "due_from": due_from, "due_to": due_to, "expiration_from": expiration_from, "expiration_to": expiration_to, "sort": sort, "direction": direction, "page_size": page_size},
        page=page, page_count=page_count, total_items=total_items,
        pagination_base=pagination_base,
    ))


@app.get("/poam/services/{service_key}", response_class=HTMLResponse)
def service_poam_page(
    service_key: str, request: Request, status_filter: str = "all", sort_by: str = "newest", db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_user), page: int = 1, page_size: int = 50,
):
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.groups)))
    if not service:
        raise HTTPException(404)
    if not auth.has("service.view", service.id):
        raise HTTPException(403, detail="Permission denied for this service")
    # Keep the legacy URL as a compatibility alias; the canonical experience
    # is the POA&M tab embedded in the service workspace.
    from .poam_query import pagination_base as poam_pagination_base
    return RedirectResponse(poam_pagination_base(service.service_key, status_filter, sort_by, page_size)
                            + "&page=" + str(page), status_code=303)


def poam_workbook(entries: list[PoamEntry]) -> Workbook:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "POA&M"
    sheet.append(["Service ID", "Service", "Type", "Title", "Description", "Finding", "Remediation",
                  "Due Date", "Status", "Ticket", "Created By", "Approved By", "Approved At"])
    for entry in entries:
        sheet.append([entry.service.service_key, entry.service.name, entry.item_type.replace("_", " ").title(),
                      entry.title, entry.description,
                      entry.finding.cve if entry.finding else (entry.policy_finding.finding if entry.policy_finding else None),
                      entry.remediation, excel_datetime(entry.due_date), entry.status.replace("_", " ").title(),
                      entry.ticket, entry.created_by.display_name,
                      entry.approved_by.display_name if entry.approved_by else None, excel_datetime(entry.approved_at)])
    for column in ("H", "M"):
        for cell in sheet[column][1:]:
            cell.number_format = "yyyy-mm-dd hh:mm"
    format_sheet(sheet)
    return workbook


def scoped_poam_export_entries(db: Session, auth: AuthContext, service_id: int | None = None, status_filter: str = "all", service_term: str = "", due_overdue: bool = False) -> list[PoamEntry]:
    allowed = auth.accessible_service_ids("service.export")
    if allowed == set():
        raise HTTPException(403, detail="Permission denied")
    query = select(PoamEntry).options(selectinload(PoamEntry.service), selectinload(PoamEntry.finding), selectinload(PoamEntry.policy_finding),
        selectinload(PoamEntry.created_by), selectinload(PoamEntry.approved_by)).order_by(PoamEntry.service_id, PoamEntry.created_at.desc())
    if allowed is not None:
        query = query.where(PoamEntry.service_id.in_(allowed))
    if service_id is not None:
        query = query.where(PoamEntry.service_id == service_id)
    if service_term:
        matching = db.scalars(select(Service.id).where(or_(Service.name.ilike(f"%{service_term}%"), Service.service_key.ilike(f"%{service_term}%")))).all()
        query = query.where(PoamEntry.service_id.in_(matching or [-1]))
    if status_filter != "all":
        query = query.where(PoamEntry.status == status_filter)
    if due_overdue:
        query = query.where(PoamEntry.status == "active", PoamEntry.due_date.is_not(None), PoamEntry.due_date < utcnow())
    return db.scalars(query).all()


@app.get("/poam/export.xlsx")
def export_all_poams(service: str = "", status_filter: str = "all", due_overdue: bool = False, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    return workbook_response(poam_workbook(scoped_poam_export_entries(db, auth, status_filter=status_filter, service_term=service, due_overdue=due_overdue)), f"cats-poam-{utcnow():%Y%m%d}.xlsx")


@app.get("/poam/services/{service_key}/export.xlsx")
def export_service_poams(service_key: str, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    if not auth.has("service.export", service.id):
        raise HTTPException(403, detail="Permission denied")
    return workbook_response(poam_workbook(scoped_poam_export_entries(db, auth, service.id)),
                             f"cats-{service.service_key}-poam-{utcnow():%Y%m%d}.xlsx")


@app.post("/poam")
def create_poam(
    service_id: int = Form(), item_type: str = Form(), title: str = Form(min_length=3),
    description: str = Form(min_length=3), remediation: str = Form(min_length=3),
    due_date: str = Form(default=""), ticket: str = Form(default=""),
    finding_id: str = Form(default=""), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.id == service_id).options(selectinload(Service.groups)))
    if not service or not auth.has("poam.request", service.id):
        raise HTTPException(403, detail="Permission denied for this service")
    if item_type not in {"vulnerability", "missing_evidence", "missing_requirement", "mitigation"}:
        raise HTTPException(422, detail="Unsupported POA&M item type")
    try:
        parsed_finding_id = int(finding_id) if finding_id.strip() else None
    except ValueError as exc:
        raise HTTPException(422, detail="Finding ID must be a whole number") from exc
    finding = db.get(Finding, parsed_finding_id) if parsed_finding_id else None
    if finding and finding.service_id != service.id:
        raise HTTPException(422, detail="Finding does not belong to the selected service")
    if item_type == "vulnerability" and not finding:
        raise HTTPException(422, detail="A vulnerability POA&M requires a finding ID")
    due_date = optional_form_datetime(due_date, "POA&M due date")
    if due_date is not None:
        if due_date <= utcnow():
            raise HTTPException(422, detail="POA&M due date must be in the future")
    entry = PoamEntry(
        service_id=service.id, finding_id=finding.id if finding else None, item_type=item_type,
        title=title.strip(), description=description.strip(), remediation=remediation.strip(),
        due_date=due_date, ticket=ticket.strip() or None, created_by_id=auth.user.id,
    )
    db.add(entry)
    db.flush()
    workflow = WorkflowRequest(
        request_type="poam", service_id=service.id, finding_id=entry.finding_id,
        poam_id=entry.id, requested_by_id=auth.user.id,
        justification=f"{entry.title}\n{entry.description}\nRemediation: {entry.remediation}",
        requested_expires_at=due_date, ticket=entry.ticket,
    )
    db.add(workflow)
    db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id, action="requested", note="Submitted for Cybersecurity approval"))
    db.flush()
    record_audit(db, auth, "poam.requested", "poam_entry", entry.id, service_id=service.id, item_type=item_type)
    db.commit()
    return RedirectResponse(f"/poam/services/{service.service_key}", status_code=303)


@app.post("/services/{service_key}/mitigations")
def create_mitigation(
    service_key: str, title: str = Form(min_length=3), description: str = Form(min_length=3),
    remediation: str = Form(min_length=3), due_date: str = Form(default=""), ticket: str = Form(default=""),
    finding_id: str = Form(default=""), policy_finding_id: str = Form(default=""), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("poam.request", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.groups)))
    if not service:
        raise HTTPException(404)
    def optional_id(raw: str, label: str):
        if not raw.strip():
            return None
        try:
            return int(raw)
        except ValueError as exc:
            raise HTTPException(422, detail=f"{label} must be a whole number") from exc
    parsed_finding_id = optional_id(finding_id, "Finding ID")
    parsed_policy_id = optional_id(policy_finding_id, "Configuration finding ID")
    if parsed_finding_id and (not (finding := db.get(Finding, parsed_finding_id)) or finding.service_id != service.id):
        raise HTTPException(422, detail="Finding does not belong to this service")
    if parsed_policy_id and (not (policy := db.get(PolicyFinding, parsed_policy_id)) or policy.service_id != service.id):
        raise HTTPException(422, detail="Configuration finding does not belong to this service")
    due = optional_form_datetime(due_date, "Mitigation due date")
    if due and due <= utcnow():
        raise HTTPException(422, detail="Mitigation due date must be in the future")
    entry = PoamEntry(service_id=service.id, finding_id=parsed_finding_id, policy_finding_id=parsed_policy_id,
                      item_type="mitigation", title=title.strip(), description=description.strip(),
                      remediation=remediation.strip(), due_date=due, ticket=ticket.strip() or None,
                      created_by_id=auth.user.id)
    db.add(entry); db.flush()
    workflow = WorkflowRequest(request_type="poam", service_id=service.id, finding_id=parsed_finding_id,
                               policy_finding_id=parsed_policy_id, poam_id=entry.id, requested_by_id=auth.user.id,
                               justification=f"{entry.title}\n{entry.description}\nRemediation: {entry.remediation}",
                               requested_expires_at=due, ticket=entry.ticket)
    db.add(workflow); db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id, action="requested",
                                         note="Mitigation submitted for Cybersecurity approval"))
    record_audit(db, auth, "mitigation.requested", "poam_entry", entry.id, service_id=service.id)
    db.commit()
    return RedirectResponse(f"/services/{service.service_key}", status_code=303)


def scoped_poam(db: Session, auth: AuthContext, poam_id: int, permission: str = "service.view") -> PoamEntry:
    entry = db.scalar(select(PoamEntry).where(PoamEntry.id == poam_id).options(
        selectinload(PoamEntry.service).selectinload(Service.groups), selectinload(PoamEntry.finding), selectinload(PoamEntry.policy_finding),
        selectinload(PoamEntry.created_by), selectinload(PoamEntry.approved_by),
    ))
    if not entry:
        raise HTTPException(404)
    if not auth.has(permission, entry.service_id):
        raise HTTPException(403, detail="Permission denied for this POA&M")
    return entry


@app.get("/poam/entries/{poam_id}", response_class=HTMLResponse)
def poam_entry_page(poam_id: int, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    entry = scoped_poam(db, auth, poam_id)
    history = db.scalars(select(PoamHistory).where(PoamHistory.poam_id == entry.id).options(
        selectinload(PoamHistory.actor)
    ).order_by(PoamHistory.created_at.desc())).all()
    pending_change = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.poam_id == entry.id, WorkflowRequest.status == "pending",
        WorkflowRequest.request_type.in_(["poam_update", "poam_complete", "poam_reopen"]),
    ))
    return templates.TemplateResponse(request, "poam_entry.html", page_context(
        auth, entry=entry, history=history, pending_change=pending_change,
        can_change=auth.has("poam.request", entry.service_id), now=utcnow(),
        is_overdue=bool(entry.status == "active" and entry.due_date and aware(entry.due_date) < utcnow()),
    ))


def create_poam_change(db: Session, auth: AuthContext, entry: PoamEntry, change_type: str, proposed: dict, justification: str):
    pending = db.scalar(select(WorkflowRequest.id).where(
        WorkflowRequest.poam_id == entry.id, WorkflowRequest.status == "pending",
        WorkflowRequest.request_type.in_(["poam_update", "poam_complete", "poam_reopen"]),
    ))
    if pending:
        raise HTTPException(409, detail="A POA&M change is already pending approval")
    workflow = WorkflowRequest(
        request_type=f"poam_{change_type}", service_id=entry.service_id, finding_id=entry.finding_id,
        policy_finding_id=entry.policy_finding_id,
        poam_id=entry.id, requested_by_id=auth.user.id, justification=justification,
    )
    db.add(workflow)
    db.flush()
    db.add(PoamChangeRequest(workflow_id=workflow.id, poam_id=entry.id, change_type=change_type, proposed=proposed))
    db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id, action=f"{change_type}_requested", note=justification, detail=proposed))
    record_audit(db, auth, f"poam.{change_type}_requested", "poam_entry", entry.id, service_id=entry.service_id)
    db.commit()


@app.post("/poam/entries/{poam_id}/update")
def request_poam_update(
    poam_id: int, title: str = Form(min_length=3), description: str = Form(min_length=3),
    remediation: str = Form(min_length=3), due_date: str = Form(default=""),
    ticket: str = Form(default=""), reason: str = Form(min_length=3), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    entry = scoped_poam(db, auth, poam_id, "poam.request")
    due_date = optional_form_datetime(due_date, "POA&M due date")
    proposed = {"title": title.strip(), "description": description.strip(), "remediation": remediation.strip(),
                "due_date": due_date.isoformat() if due_date else None, "ticket": ticket.strip() or None}
    create_poam_change(db, auth, entry, "update", proposed, reason.strip())
    return RedirectResponse(f"/poam/entries/{entry.id}", status_code=303)


@app.post("/poam/entries/{poam_id}/complete")
def request_poam_completion(
    poam_id: int, closure_note: str = Form(min_length=3), evidence_reference: str = Form(min_length=3),
    csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    entry = scoped_poam(db, auth, poam_id, "poam.request")
    if entry.status != "active":
        raise HTTPException(409, detail="Only active POA&M entries can be completed")
    proposed = {"closure_note": closure_note.strip(), "evidence_reference": evidence_reference.strip()}
    create_poam_change(db, auth, entry, "complete", proposed, closure_note.strip())
    return RedirectResponse(f"/poam/entries/{entry.id}", status_code=303)


@app.post("/poam/entries/{poam_id}/reopen")
def request_poam_reopen(
    poam_id: int, reason: str = Form(min_length=3), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    entry = scoped_poam(db, auth, poam_id, "poam.request")
    if entry.status != "completed":
        raise HTTPException(409, detail="Only completed POA&M entries can be reopened")
    create_poam_change(db, auth, entry, "reopen", {}, reason.strip())
    return RedirectResponse(f"/poam/entries/{entry.id}", status_code=303)


@app.post("/poam/entries/{poam_id}/comments")
def add_poam_comment(
    poam_id: int, comment: str = Form(min_length=3), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    entry = scoped_poam(db, auth, poam_id)
    db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id, action="comment", note=comment.strip()))
    record_audit(db, auth, "poam.comment_added", "poam_entry", entry.id, service_id=entry.service_id)
    db.commit()
    return RedirectResponse(f"/poam/entries/{entry.id}", status_code=303)


def _missing_evidence_key(row: dict) -> tuple[str, str, str]:
    return (str(row.get("type") or "Other").strip().lower(), str(row.get("item") or row.get("reference") or row.get("name") or row.get("image") or row.get("chart") or row.get("resource") or "").strip(), str(row.get("source_file") or row.get("source_path") or row.get("filepath") or row.get("file") or row.get("chart_path") or row.get("values_file") or row.get("template") or row.get("provenance") or row.get("source") or row.get("resource_path") or "").strip())


def _evidence_source_key(value: object, field: str, overview: dict) -> tuple[str, str, str] | None:
    """Use the same normalization as the displayed Missing Evidence table."""
    if field == "skipped_images":
        rows = normalize_overview({"images": overview.get("images") or overview.get("container_images") or []},
                                  skipped_images=[value])["missing_evidence"]
    elif field == "skipped_charts":
        rows = normalize_overview({}, skipped_charts=[value])["missing_evidence"]
    elif field == "dependencies":
        rows = normalize_overview({"dependencies": [value]})["missing_evidence"]
    else:
        rows = normalize_overview({"missing_evidence": [value]})["missing_evidence"]
    return _missing_evidence_key(rows[0]) if rows else None


def _current_removable_evidence_keys(payload: dict, complete: bool) -> set[tuple[str, str, str]]:
    overview = payload.get("service_overview") or {}
    if not isinstance(overview, dict):
        overview = {}
    keys = set()
    for container, field in ((overview, "missing_evidence"), (overview, "evidence"),
                             (payload, "skipped_images"), (payload, "skipped_charts")):
        values = container.get(field)
        if not isinstance(values, list):
            continue
        for value in values:
            key = _evidence_source_key(value, field, overview)
            if key:
                keys.add(key)
    if not complete and not keys:
        keys.add(("other", "Assessment", ""))
    for value in overview.get("dependencies") or []:
        key = _evidence_source_key(value, "dependencies", overview)
        if key:
            keys.add(key)
    return keys


@app.post("/services/{service_key}/missing-evidence/remove")
def remove_missing_evidence(
    request: Request,
    service_key: str, evidence_type: str = Form(), item: str = Form(), source_file: str = Form(default=""),
    csrf_token: str = Form(), execution_id: int | None = Form(default=None),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.executions)))
    if not service:
        raise HTTPException(404)
    if not auth.has("evidence.remove", service.id):
        raise HTTPException(403, detail="Permission denied")
    latest = max(service.executions, key=lambda execution: (aware(execution.scanned_at), execution.id), default=None)
    def stale():
        if _api_error_request(request):
            raise HTTPException(409, detail="That evidence observation is no longer current. The service evidence has changed since this page was loaded.")
        return RedirectResponse(f"/services/{service.service_key}?overview=true&evidence_notice=stale", status_code=303)
    if latest and execution_id is not None and latest.id != execution_id:
        return stale()
    if not latest or not isinstance(latest.raw_payload, dict):
        return stale()
    payload = dict(latest.raw_payload)
    overview = dict(payload.get("service_overview") or {})
    target = (str(evidence_type).strip().lower(), str(item).strip(), str(source_file).strip())
    displayed = normalize_overview(overview, skipped_images=payload.get("skipped_images") or [],
                                   skipped_charts=payload.get("skipped_charts") or [],
                                   incomplete=not latest.complete)["missing_evidence"]
    if target not in {_missing_evidence_key(row) for row in displayed}:
        return stale()
    removed = False
    # The assessment-level row is a derived observation used only when an
    # incomplete execution has no concrete evidence item.  It has no list
    # entry to delete, so removing it resolves the current execution's
    # incomplete state.  A future execution is authoritative and can recreate
    # the row if it is incomplete again.
    if target == ("other", "Assessment", "") and target in _current_removable_evidence_keys(payload, latest.complete):
        latest.complete = True
        payload["incomplete"] = False
        removed = True
    for container, field in ((overview, "missing_evidence"), (overview, "evidence"),
                             (overview, "dependencies"), (payload, "skipped_images"), (payload, "skipped_charts")):
        values = container.get(field)
        if not isinstance(values, list):
            continue
        kept = []
        for value in values:
            candidate = _evidence_source_key(value, field, overview)
            if candidate == target:
                removed = True
            else:
                kept.append(value)
        container[field] = kept
    if not removed:
        return stale()
    payload["service_overview"] = overview
    latest.raw_payload = payload
    record_audit(db, auth, "missing_evidence.removed", "service", service.id,
                 service_id=service.id, evidence_type=evidence_type, item=item, source_file=source_file)
    db.commit()
    return RedirectResponse(f"/services/{service.service_key}?overview=true", status_code=303)


def _safe_remediation_return(value: str, fallback: str) -> str:
    """Accept only local remediation/service paths supplied by our forms."""
    raw = (value or "").strip()
    if not raw or raw.startswith("//"):
        return fallback
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith(("/remediations", "/services/")):
        return fallback
    if parsed.path.startswith("/services/") and "remediations=true" not in parsed.query:
        return fallback
    return raw


@app.post("/poam/entries/{poam_id}/revoke")
def revoke_poam_entry(poam_id: int, return_to: str = Form(default=""), csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    check_csrf(auth, csrf_token)
    entry = scoped_poam(db, auth, poam_id, "poam.review")
    if entry.status not in {"active", "pending"}:
        raise HTTPException(409, detail="Only active or pending remediation entries can be revoked")
    entry.status = "revoked"
    db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id, action="revoked", note="Revoked by authorized reviewer"))
    record_audit(db, auth, "poam.revoked", "poam_entry", entry.id, service_id=entry.service_id)
    db.commit()
    fallback = f"/services/{entry.service.service_key}?remediations=true&tab={'mitigations' if entry.item_type == 'mitigation' else 'poams'}"
    return RedirectResponse(_safe_remediation_return(return_to, fallback), status_code=303)


@app.post("/poam/entries/{poam_id}/close")
def close_poam_entry(poam_id: int, return_to: str = Form(default=""), closure_note: str = Form(default="Closed by authorized reviewer"), csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    check_csrf(auth, csrf_token)
    entry = scoped_poam(db, auth, poam_id, "poam.review")
    if entry.status != "active":
        raise HTTPException(409, detail="Only active remediation entries can be closed")
    entry.status = "completed"
    db.add(PoamHistory(poam_id=entry.id, actor_user_id=auth.user.id, action="completed", note=closure_note.strip()[:2000] or "Closed by authorized reviewer"))
    record_audit(db, auth, "poam.completed", "poam_entry", entry.id, service_id=entry.service_id)
    db.commit()
    fallback = f"/services/{entry.service.service_key}?remediations=true&tab={'mitigations' if entry.item_type == 'mitigation' else 'poams'}"
    return RedirectResponse(_safe_remediation_return(return_to, fallback), status_code=303)


@app.post("/exceptions/{exception_id}/revoke")
def revoke_exception(
    exception_id: int, return_to: str = Form(default=""), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("exception.revoke", scoped=True)),
):
    check_csrf(auth, csrf_token)
    record = db.get(ExceptionRecord, exception_id)
    if not record:
        raise HTTPException(404)
    if record.revoked_at is not None:
        raise HTTPException(409, detail="Exception is already revoked")
    record.revoked_at = utcnow()
    record_audit(db, auth, "exception.revoked", "exception", record.id, service_id=record.finding.service_id)
    db.commit()
    fallback = f"/services/{record.finding.service.service_key}?remediations=true&tab=exceptions"
    return RedirectResponse(_safe_remediation_return(return_to, fallback), status_code=303)


@app.post("/policy-exceptions/{policy_exception_id}/revoke")
def revoke_policy_exception(
    policy_exception_id: int, return_to: str = Form(default=""), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    record = db.scalar(select(PolicyExceptionRecord).where(
        PolicyExceptionRecord.id == policy_exception_id
    ).options(selectinload(PolicyExceptionRecord.policy_finding).selectinload(PolicyFinding.service)))
    if not record:
        raise HTTPException(404)
    if not auth.has("exception.revoke", record.policy_finding.service_id):
        raise HTTPException(403, detail="Permission denied")
    if record.revoked_at is not None:
        raise HTTPException(409, detail="Exception is already revoked")
    record.revoked_at = utcnow()
    record_audit(db, auth, "exception.revoked", "policy_exception", record.id,
                 service_id=record.policy_finding.service_id, finding_type="configuration")
    db.commit()
    fallback = f"/services/{record.policy_finding.service.service_key}?remediations=true&tab=exceptions"
    return RedirectResponse(_safe_remediation_return(return_to, fallback), status_code=303)


@app.post("/services/{service_key}/archive")
def request_archive(
    service_key: str, reason: str = Form(min_length=3), ticket: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("archive.request", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.archive_events)))
    if not service:
        raise HTTPException(404)
    if archive_state(service):
        raise HTTPException(409, detail="Service is already archived")
    pending = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.request_type == "archive", WorkflowRequest.service_id == service.id,
        WorkflowRequest.status == "pending",
    ))
    if pending:
        raise HTTPException(409, detail="An archive request is already pending")
    workflow = WorkflowRequest(request_type="archive", service_id=service.id,
                               requested_by_id=auth.user.id, justification=reason, ticket=ticket or None)
    db.add(workflow)
    db.flush()
    record_audit(db, auth, "archive.requested", "workflow_request", workflow.id, service_id=service.id)
    db.commit()
    return RedirectResponse(f"/services/{service.service_key}", status_code=303)


def _service_image_for_action(db: Session, service_key: str, image_id: int) -> tuple[Service, ServiceImage]:
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.images)))
    image = db.scalar(select(ServiceImage).where(ServiceImage.id == image_id, ServiceImage.service_id == service.id if service else False)) if service else None
    if not service or not image:
        raise HTTPException(404, detail="Container image was not found")
    return service, image


@app.post("/services/{service_key}/images/{image_id}/remove")
def request_image_removal(
    service_key: str, image_id: int, reason: str = Form(min_length=3), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("archive.request", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service, image = _service_image_for_action(db, service_key, image_id)
    if image.lifecycle_status != "active":
        raise HTTPException(409, detail="Only an active image can be removed")
    pending = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.service_image_id == image.id,
        WorkflowRequest.request_type == "image_remove",
        WorkflowRequest.status == "pending",
    ))
    if pending:
        raise HTTPException(409, detail="An image-removal request is already pending")
    workflow = WorkflowRequest(
        request_type="image_remove", service_id=service.id, service_image_id=image.id,
        requested_by_id=auth.user.id, justification=reason.strip(),
    )
    db.add(workflow)
    db.flush()
    record_audit(db, auth, "image_removal.requested", "workflow_request", workflow.id,
                 service_id=service.id, image_id=image.id, image=image.image_reference, reason=reason.strip())
    db.commit()
    return RedirectResponse("/requests", status_code=303)


@app.post("/services/{service_key}/images/{image_id}/replace")
def request_image_replacement(
    service_key: str, image_id: int, replacement_reference: str = Form(min_length=1), reason: str = Form(min_length=3),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("archive.request", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service, image = _service_image_for_action(db, service_key, image_id)
    if image.lifecycle_status != "active":
        raise HTTPException(409, detail="Only an active image can be replaced")
    replacement_reference = replacement_reference.strip()
    if replacement_reference == image.image_reference:
        raise HTTPException(422, detail="Replacement image must be different from the current image")
    pending = db.scalar(select(WorkflowRequest).where(
        WorkflowRequest.service_image_id == image.id,
        WorkflowRequest.request_type == "image_replace",
        WorkflowRequest.status == "pending",
    ))
    if pending:
        raise HTTPException(409, detail="An image-replacement request is already pending")
    workflow = WorkflowRequest(
        request_type="image_replace", service_id=service.id, service_image_id=image.id,
        replacement_reference=replacement_reference, requested_by_id=auth.user.id,
        justification=reason.strip(),
    )
    db.add(workflow)
    db.flush()
    record_audit(db, auth, "image_replacement.requested", "workflow_request", workflow.id,
                 service_id=service.id, image_id=image.id, image=image.image_reference,
                 replacement=replacement_reference, reason=reason.strip())
    db.commit()
    return RedirectResponse("/requests", status_code=303)


@app.post("/services/{service_key}/restore")
def restore_service(
    service_key: str, reason: str = Form(min_length=3), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("service.restore", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(selectinload(Service.archive_events)))
    if not service:
        raise HTTPException(404)
    if not archive_state(service):
        raise HTTPException(409, detail="Service is not archived")
    db.add(ServiceArchiveEvent(service=service, action="restore", reason=reason, performed_by=auth.user.username))
    record_audit(db, auth, "service.restored", "service", service.id, service_id=service.id, reason=reason)
    db.commit()
    return RedirectResponse(f"/services/{service_key}", status_code=303)


@app.post("/services/{service_key}/delete")
def delete_service(
    service_key: str, confirmation: str = Form(), reason: str = Form(min_length=3),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.delete", scoped=True)),
):
    check_csrf(auth, csrf_token)
    if os.getenv("ALLOW_SERVICE_DELETE", "false").lower() != "true":
        raise HTTPException(403, detail="Permanent service deletion is disabled")
    service = db.scalar(select(Service).where(Service.service_key == service_key).options(
        selectinload(Service.archive_events)
    ))
    if not service:
        raise HTTPException(404)
    if not archive_state(service):
        raise HTTPException(409, detail="Archive the service before permanently deleting it")
    if confirmation != service.service_key:
        raise HTTPException(422, detail="Service ID confirmation did not match")
    finding_ids = list(db.scalars(select(Finding.id).where(Finding.service_id == service.id)))
    policy_finding_ids = list(db.scalars(select(PolicyFinding.id).where(PolicyFinding.service_id == service.id)))
    poam_ids = list(db.scalars(select(PoamEntry.id).where(PoamEntry.service_id == service.id)))
    if poam_ids:
        db.execute(delete(PoamChangeRequest).where(PoamChangeRequest.poam_id.in_(poam_ids)))
        db.execute(delete(PoamHistory).where(PoamHistory.poam_id.in_(poam_ids)))
    db.execute(delete(WorkflowRequest).where(WorkflowRequest.service_id == service.id))
    db.execute(delete(PoamEntry).where(PoamEntry.service_id == service.id))
    if finding_ids:
        db.execute(delete(FindingObservation).where(FindingObservation.finding_id.in_(finding_ids)))
        db.execute(delete(ExceptionRecord).where(ExceptionRecord.finding_id.in_(finding_ids)))
        db.execute(delete(Finding).where(Finding.id.in_(finding_ids)))
    if policy_finding_ids:
        db.execute(delete(PolicyExceptionRecord).where(PolicyExceptionRecord.policy_finding_id.in_(policy_finding_ids)))
        db.execute(delete(PolicyFinding).where(PolicyFinding.id.in_(policy_finding_ids)))
    db.execute(delete(UserRoleAssignment).where(UserRoleAssignment.service_id == service.id))
    db.execute(delete(RemediationExecution).where(RemediationExecution.service_id == service.id))
    db.execute(delete(PatchExecution).where(PatchExecution.service_id == service.id))
    db.execute(delete(DeploymentValidationRun).where(DeploymentValidationRun.service_id == service.id))
    artifact_ids = list(db.scalars(select(ServiceArtifact.id).where(ServiceArtifact.service_id == service.id)))
    if artifact_ids:
        db.execute(delete(ServiceArtifactRevision).where(ServiceArtifactRevision.artifact_id.in_(artifact_ids)))
        db.execute(delete(ServiceArtifact).where(ServiceArtifact.id.in_(artifact_ids)))
    from .models import DependencyProjection, DependencyProjectionRow, ExecutionSummary
    deleted_execution_ids = select(Execution.id).where(Execution.service_id == service.id)
    # SQLite deployments may disable foreign-key cascades; derived evidence
    # must still be removed alongside its authoritative executions.
    for derived_model in (DependencyProjectionRow, DependencyProjection, ExecutionSummary):
        db.execute(delete(derived_model).where(derived_model.execution_id.in_(deleted_execution_ids)))
    db.execute(delete(Execution).where(Execution.service_id == service.id))
    service.current_version_id = None
    db.flush()
    db.execute(delete(ServiceVersion).where(ServiceVersion.service_id == service.id))
    db.execute(delete(ServiceImage).where(ServiceImage.service_id == service.id))
    db.execute(delete(ServiceArchiveEvent).where(ServiceArchiveEvent.service_id == service.id))
    db.add(ServiceDeletionAudit(service_key=service.service_key, service_name=service.name,
                                reason=reason, deleted_by=auth.user.username))
    record_audit(db, auth, "service.deleted", "service", service.id, service_key=service.service_key, reason=reason)
    db.delete(service)
    db.commit()
    return RedirectResponse("/?archived=true", status_code=303)


@app.get("/requests", response_class=HTMLResponse)
def requests_page(request: Request, request_type: str = "all", db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    allowed = auth.accessible_service_ids("service.view")
    query = select(WorkflowRequest).options(
        selectinload(WorkflowRequest.service), selectinload(WorkflowRequest.finding),
        selectinload(WorkflowRequest.finding).selectinload(Finding.exceptions),
        selectinload(WorkflowRequest.policy_finding).selectinload(PolicyFinding.exceptions),
        selectinload(WorkflowRequest.requested_by), selectinload(WorkflowRequest.reviewed_by),
        selectinload(WorkflowRequest.service_image),
    ).order_by(WorkflowRequest.created_at.desc())
    if allowed is not None:
        query = query.where(WorkflowRequest.service_id.in_(allowed))
    if request_type == "poam":
        query = query.where(WorkflowRequest.request_type.like("poam%"))
    elif request_type in {"exception", "archive"}:
        query = query.where(WorkflowRequest.request_type == request_type)
    elif request_type != "all":
        raise HTTPException(422, detail="Unknown request filter")
    workflows = db.scalars(query).all()
    now = utcnow()
    workflow_statuses = {}
    for item in workflows:
        display_status = item.status
        exception_subject = item.finding or item.policy_finding
        if item.request_type == "exception" and item.status == "approved" and exception_subject:
            matching = [exception for exception in exception_subject.exceptions
                        if item.reviewed_at and aware(exception.created_at) >= aware(item.reviewed_at)]
            exception = max(matching, key=lambda value: aware(value.created_at), default=None)
            if exception and exception.revoked_at:
                display_status = "revoked"
            elif exception and aware(exception.expires_at) <= now:
                display_status = "expired"
        workflow_statuses[item.id] = display_status
    return templates.TemplateResponse(request, "requests.html", page_context(
        auth, workflows=workflows, workflow_statuses=workflow_statuses, request_type_filter=request_type,
    ))


@app.post("/requests/{workflow_id}/review")
def review_request(
    workflow_id: int, decision: str = Form(), review_reason: str = Form(default=""),
    apply_bulk: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_user),
):
    check_csrf(auth, csrf_token)
    workflow = db.get(WorkflowRequest, workflow_id)
    if not workflow:
        raise HTTPException(404)
    permission = "poam.review" if workflow.request_type.startswith("poam") else {
        "exception": "exception.review", "archive": "archive.review",
        "image_remove": "archive.review", "image_replace": "archive.review",
    }.get(workflow.request_type, "archive.review")
    if not auth.has(permission, workflow.service_id):
        raise HTTPException(403, detail="Permission denied")
    if workflow.status != "pending":
        raise HTTPException(409, detail="Request has already been reviewed")
    if workflow.requested_by_id == auth.user.id:
        raise HTTPException(409, detail="Requesters cannot approve or reject their own requests")
    if decision not in {"approved", "rejected"}:
        raise HTTPException(422, detail="Decision must be approved or rejected")
    if decision == "rejected" and len(review_reason.strip()) < 3:
        raise HTTPException(422, detail="A rejection reason is required")
    if decision == "approved" and workflow.bulk_group_id and apply_bulk != "yes":
        raise HTTPException(422, detail="Confirm the group-wide exception scope before approving")
    workflow.status = decision
    workflow.reviewed_by_id = auth.user.id
    workflow.review_reason = review_reason.strip() or None
    workflow.reviewed_at = utcnow()
    if workflow.request_type == "poam" and workflow.poam_id:
        poam = db.get(PoamEntry, workflow.poam_id)
        if not poam:
            raise HTTPException(409, detail="POA&M entry is missing")
        poam.status = "active" if decision == "approved" else "rejected"
        if decision == "approved":
            poam.approved_by_id = auth.user.id
            poam.approved_at = workflow.reviewed_at
        db.add(PoamHistory(poam_id=poam.id, actor_user_id=auth.user.id, action=decision,
                           note=workflow.review_reason, detail={"request_type": "creation"}))
    elif workflow.request_type in {"poam_update", "poam_complete", "poam_reopen"} and workflow.poam_id:
        poam = db.get(PoamEntry, workflow.poam_id)
        change = db.scalar(select(PoamChangeRequest).where(PoamChangeRequest.workflow_id == workflow.id))
        if not poam or not change:
            raise HTTPException(409, detail="POA&M change request is missing")
        if decision == "approved":
            if change.change_type == "update":
                for field in ("title", "description", "remediation", "ticket"):
                    setattr(poam, field, change.proposed.get(field))
                raw_due = change.proposed.get("due_date")
                poam.due_date = datetime.fromisoformat(raw_due) if raw_due else None
            elif change.change_type == "complete":
                poam.status = "completed"
            elif change.change_type == "reopen":
                poam.status = "active"
            poam.approved_by_id = auth.user.id
            poam.approved_at = workflow.reviewed_at
        db.add(PoamHistory(poam_id=poam.id, actor_user_id=auth.user.id,
                           action=f"{change.change_type}_{decision}", note=workflow.review_reason,
                           detail=change.proposed))
    if decision == "approved" and workflow.request_type == "exception":
        bulk_service_ids = None
        if workflow.bulk_group_id and apply_bulk == "yes":
            bulk_service_ids = db.scalars(select(ServiceGroup.service_id).where(
                ServiceGroup.group_id == workflow.bulk_group_id
            )).all()
        if workflow.policy_finding_id:
            source = db.get(PolicyFinding, workflow.policy_finding_id)
            query = select(PolicyFinding).options(selectinload(PolicyFinding.exceptions)).where(
                PolicyFinding.identity_key == source.identity_key,
                PolicyFinding.active.is_(True),
            )
            if bulk_service_ids is not None:
                query = query.where(PolicyFinding.service_id.in_(bulk_service_ids))
            for target in db.scalars(query).all():
                if not active_exception(target, utcnow()):
                    db.add(PolicyExceptionRecord(
                        policy_finding_id=target.id,
                        justification=workflow.justification, approved_by=auth.user.username,
                        expires_at=workflow.requested_expires_at, ticket=workflow.ticket,
                    ))
        else:
            source = db.get(Finding, workflow.finding_id)
            query = select(Finding).options(selectinload(Finding.exceptions)).where(
                Finding.cve == source.cve, Finding.active.is_(True),
            )
            if bulk_service_ids is not None:
                query = query.where(Finding.service_id.in_(bulk_service_ids))
            for target in db.scalars(query).all():
                if not active_exception(target, utcnow()):
                    db.add(ExceptionRecord(
                        finding_id=target.id, justification=workflow.justification,
                        approved_by=auth.user.username, expires_at=workflow.requested_expires_at,
                        ticket=workflow.ticket,
                    ))
    elif decision == "approved" and workflow.request_type == "archive":
        service = db.scalar(select(Service).where(Service.id == workflow.service_id).options(selectinload(Service.archive_events)))
        if archive_state(service):
            raise HTTPException(409, detail="Service is already archived")
        db.add(ServiceArchiveEvent(
            service_id=workflow.service_id, action="archive", reason=workflow.justification,
            performed_by=auth.user.username, ticket=workflow.ticket,
        ))
    elif decision == "approved" and workflow.request_type in {"image_remove", "image_replace"}:
        image = db.get(ServiceImage, workflow.service_image_id) if workflow.service_image_id else None
        if not image:
            raise HTTPException(409, detail="The requested service image no longer exists")
        image.lifecycle_status = "removed" if workflow.request_type == "image_remove" else "replaced"
        image.lifecycle_reason = workflow.justification
        image.approved_by_id = auth.user.id
        image.updated_at = utcnow()
        if workflow.request_type == "image_replace":
            replacement_reference = (workflow.replacement_reference or "").strip()
            if not replacement_reference:
                raise HTTPException(422, detail="Replacement image reference is missing")
            replacement = ServiceImage(
                service_id=workflow.service_id, image_reference=replacement_reference,
                lifecycle_status="active", replacement_of_id=image.id,
                lifecycle_reason=workflow.justification,
                requested_by_id=workflow.requested_by_id, approved_by_id=auth.user.id,
            )
            db.add(replacement)
            db.flush()
        _reconcile_image_scope(db, image.service, image.image_reference, set(), workflow.reviewed_at or utcnow())
        record_audit(db, auth,
                     "image_removed" if workflow.request_type == "image_remove" else "image_replaced",
                     "service_image", image.id, service_id=workflow.service_id,
                     image=image.image_reference, replacement=workflow.replacement_reference,
                     reason=workflow.justification)
    record_audit(db, auth, f"{workflow.request_type}.{decision}", "workflow_request", workflow.id,
                 service_id=workflow.service_id, review_reason=workflow.review_reason)
    db.commit()
    return RedirectResponse("/requests", status_code=303)


@app.get("/audit")
def audit_legacy_page(auth: AuthContext = Depends(require_permission("audit.view"))):
    return RedirectResponse("/admin/audit", status_code=303)


@app.get("/admin/audit", response_class=HTMLResponse)
def audit_page(request: Request, group_id: str = "", show: int = 10, page: int = 1, page_size: int = 10, action: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("audit.view"))):
    groups = manageable_groups(db, auth) if auth.has("config.manage") else []
    selected_group_id = requested_group_scope(group_id or (str(groups[0].id) if groups else None), db, auth) if groups else None
    configuration = get_configuration(db, selected_group_id)
    # Logging level is a runtime setting owned by the global Audit Policy.
    # Keep retention/integration group-aware, but always show the global level.
    configuration["log_level"] = get_global_configuration(db).get("log_level", configuration.get("log_level", "INFO"))
    try:
        retention_days = int(configuration.get("audit_retention_days", "365") or "365")
    except ValueError:
        retention_days = 365
    from .activity_queries import global_activity_page
    cutoff = utcnow() - timedelta(days=retention_days) if retention_days > 0 else None
    values = global_activity_page(db, cutoff=cutoff, action=action, page=page, page_size=(200 if request.query_params.get("full") == "true" else (show if "show" in request.query_params else page_size)))
    from urllib.parse import urlencode
    pagination_base = '/admin/audit?' + urlencode({'group_id': group_id, 'page_size': values['page_size'], 'action': action})
    return templates.TemplateResponse(request, "audit.html", page_context(
        auth, **values, groups=groups, selected_group_id=selected_group_id,
        configuration=configuration, saved=request.query_params.get("saved") == "1",
        pagination_base=pagination_base,
    ))

@app.get("/admin/general-policy", response_class=HTMLResponse)
def general_policy_page(request: Request, group_id: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_user)):
    if not auth.has("audit.view") and not auth.has("config.manage"):
        raise HTTPException(status_code=403, detail="Permission denied")
    groups = manageable_groups(db, auth) if auth.has("config.manage") else []
    selected_group_id = requested_group_scope(group_id or (str(groups[0].id) if groups else None), db, auth) if groups else None
    configuration = get_configuration(db, selected_group_id)
    configuration["log_level"] = get_global_configuration(db).get("log_level", configuration.get("log_level", "INFO"))
    try:
        retention_days = int(configuration.get("audit_retention_days", "365") or "365")
    except ValueError:
        retention_days = 365
    query = select(AuditEvent).options(selectinload(AuditEvent.actor)).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
    if retention_days > 0:
        query = query.where(AuditEvent.created_at >= utcnow() - timedelta(days=retention_days))
    retained_count = int(db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0)
    events = db.scalars(query.limit(10)).all()
    return templates.TemplateResponse(request, "general_policy.html", page_context(
        auth, events=events, groups=groups, selected_group_id=selected_group_id,
        selected_group=db.get(Group, selected_group_id) if selected_group_id is not None else None,
        export_templates=[{"kind": kind, "name": PURPOSE_NAMES[kind],
                           "source": purpose_template_policy(db, kind, selected_group_id)[1],
                           "mode": purpose_template_policy(db, kind, selected_group_id)[2],
                           "enabled_count": sum(c["enabled"] for c in purpose_template_policy(db, kind, selected_group_id)[0])}
                          for kind in PURPOSE_CATALOG],
        configuration=configuration, saved=request.query_params.get("saved") == "1",
        retained_count=retained_count, shown_count=len(events),
    ))


@app.post("/admin/audit-policy")
def save_audit_policy(
    audit_retention_days: str = Form(default="365"), audit_tool_integration: str = Form(default="planned"),
    log_level: str = Form(default="INFO"),
    group_id: str = Form(default=""), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_config_scope),
):
    check_csrf(auth, csrf_token)
    selected_group_id = requested_group_scope(group_id, db, auth)
    try:
        retention = int(audit_retention_days)
    except ValueError as exc:
        raise HTTPException(422, detail="Audit retention must be a number") from exc
    if retention < 0 or retention > 3650:
        raise HTTPException(422, detail="Audit retention must be between 0 and 3650 days")
    if audit_tool_integration not in {"planned"}:
        raise HTTPException(422, detail="Unsupported audit integration")
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise HTTPException(422, detail="Unsupported logging level")
    values = {"audit_retention_days": str(retention), "audit_tool_integration": audit_tool_integration, "log_level": log_level}
    for key, value in values.items():
        # Logging controls are runtime-wide even though retention/tool integration
        # may retain their existing group policy scope for backwards compatibility.
        target_group_id = None if key == "log_level" else selected_group_id
        storage_key = scoped_setting_key(key, target_group_id)
        setting = db.scalar(select(PortalSetting).where(PortalSetting.key == storage_key))
        if not setting:
            setting = PortalSetting(key=storage_key, group_id=target_group_id)
            db.add(setting)
        setting.value = value
        setting.updated_by_id = auth.user.id
        setting.updated_at = utcnow()
    record_audit(db, auth, "audit_policy.updated", "group" if selected_group_id else "portal", str(selected_group_id or "global"), changed=list(values))
    db.commit()
    suffix = f"&group_id={selected_group_id}" if selected_group_id else ""
    return RedirectResponse(f"/admin/general-policy?saved=1{suffix}", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("user.manage"))):
    users = db.scalars(select(User).options(
        selectinload(User.role_assignments).selectinload(UserRoleAssignment.role),
        selectinload(User.role_assignments).selectinload(UserRoleAssignment.service),
        selectinload(User.role_assignments).selectinload(UserRoleAssignment.group),
    ).order_by(User.username)).all()
    roles = db.scalars(select(Role).order_by(Role.system.desc(), Role.name)).all()
    services = db.scalars(select(Service).options(
        selectinload(Service.groups), selectinload(Service.archive_events),
    ).order_by(Service.name)).all()
    groups = db.scalars(select(Group).order_by(Group.name)).all()
    stage_groups = manageable_groups(db, auth)
    group_summaries = [
        {
            "group": group,
            "active_services": sum(1 for service in group.services if not archive_state(service)),
            "service_count": len(group.services),
        }
        for group in groups
    ]
    user_rows = []
    for user in users:
        assignments = []
        permissions = set()
        for assignment in user.role_assignments:
            permissions.update(assignment.role.permissions or [])
            assignments.append({
                "role": assignment.role.name,
                "group": assignment.group.name if assignment.group else "Global",
                "service": assignment.service.name if assignment.service else (
                    "All services in group" if assignment.group else "All services"
                ),
                "id": assignment.id,
            })
        user_rows.append({"user": user, "assignments": assignments, "permissions": sorted(permissions)})
    return templates.TemplateResponse(request, "admin.html", page_context(
        auth, users=users, user_rows=user_rows, roles=roles, services=services, groups=groups,
        group_summaries=group_summaries, permission_catalog=PERMISSIONS, stage_groups=stage_groups,
        saved=request.query_params.get("saved") == "1",
    ))


@app.get("/admin/staging", response_class=HTMLResponse)
def staging_page(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("user.manage"))):
    return templates.TemplateResponse(request, "staging.html", page_context(
        auth, stage_groups=manageable_groups(db, auth), saved=request.query_params.get("saved") == "1",
    ))


@app.post("/admin/services/stage")
def stage_service(
    service_id: str = Form(), group_id: str = Form(default=""), csrf_token: str = Form(),
    next_path: str = Form(default="/admin/staging"),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("user.manage")),
):
    check_csrf(auth, csrf_token)
    service_key = service_id.strip()
    if not service_key or len(service_key) > 120:
        raise HTTPException(422, detail="A valid service ID is required")
    if db.scalar(select(Service).where(Service.service_key == service_key)):
        raise HTTPException(409, detail="That service is already staged or registered")
    groups = manageable_groups(db, auth)
    if len(groups) == 1:
        selected_group = groups[0]
    else:
        try:
            selected_id = int(group_id)
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, detail="Select a group for this staged service") from exc
        selected_group = next((group for group in groups if group.id == selected_id), None)
        if not selected_group:
            raise HTTPException(403, detail="You cannot stage a service in that group")
    service = Service(
        service_key=service_key, name=f"Staged — {service_key}", lifecycle_status="staged",
        staging_original_name=service_key, staging_name_generated=True,
    )
    service.groups.append(selected_group)
    db.add(service)
    db.flush()
    record_audit(db, auth, "service.staged", "service", service.id,
                 service_key=service_key, group_id=selected_group.id,
                 previous_name=service_key, name=service.name)
    db.commit()
    # Return to the page that opened the staging modal. Only local paths are
    # accepted so this cannot become an open redirect.
    target = next_path.strip() or "/admin/staging"
    if not target.startswith("/") or target.startswith("//"):
        target = "/admin/staging"
    separator = "&" if "?" in target else "?"
    return RedirectResponse(f"{target}{separator}saved=1", status_code=303)


@app.post("/admin/services/{service_key}")
def edit_service(
    service_key: str, request: Request, name: str = Form(), description: str = Form(default=""), owner: str = Form(default=""), poc: str = Form(default=""),
    manual_version: str = Form(default=""), group_ids: list[int] = Form(default=[]), return_to: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("service.edit", scoped=True)),
):
    check_csrf(auth, csrf_token)
    service = db.scalar(select(Service).where(Service.service_key == service_key))
    if not service:
        raise HTTPException(404)
    if not name.strip():
        raise HTTPException(422, detail="Service name is required")
    previous = {
        "name": service.name, "description": service.description, "owner": service.owner,
        "poc": service.poc, "manual_version": service.manual_version,
        "group_ids": sorted(group.id for group in service.groups),
    }
    service.name = name.strip()[:240]
    service.description = description.strip()[:2000] or None
    service.owner = owner.strip()[:240] or None
    service.poc = poc.strip()[:240] or None
    service.manual_version = manual_version.strip()[:120] or None
    service.groups = list(db.scalars(select(Group).where(Group.id.in_(group_ids))).all()) if group_ids else []
    current = {
        "name": service.name, "description": service.description, "owner": service.owner,
        "poc": service.poc, "manual_version": service.manual_version,
        "group_ids": sorted(group.id for group in service.groups),
    }
    record_audit(db, auth, "service.metadata_updated", "service", service.id,
                 service_key=service.service_key, changed=[key for key in previous if previous[key] != current[key]])
    db.commit()
    # The service key is the stable route identity: editing the display name
    # must not change it. Preserve only local URLs within this service workspace.
    fallback_path = f"/services/{service.service_key}"
    # Older rendered pages do not carry return_to; the same-origin Referer is
    # a compatible fallback while newly rendered Findings pages post it explicitly.
    requested_destination = return_to.strip() or request.headers.get("referer", "")
    parsed_return = urllib.parse.urlsplit(requested_destination)
    allowed_prefix = fallback_path
    return_path = parsed_return.path
    if (
        not return_path.startswith("/") or return_path.startswith("//")
        or not (return_path == allowed_prefix or return_path.startswith(f"{allowed_prefix}/"))
    ):
        return_path = fallback_path
        return_query: list[tuple[str, str]] = []
    else:
        return_query = urllib.parse.parse_qsl(parsed_return.query, keep_blank_values=True)
    return_query = [(key, value) for key, value in return_query if key != "saved"]
    return_query.append(("saved", "1"))
    destination = urllib.parse.urlunsplit(("", "", return_path, urllib.parse.urlencode(return_query), ""))
    return RedirectResponse(destination, status_code=303)


@app.post("/admin/groups")
def create_group(
    name: str = Form(), description: str = Form(default=""), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("role.manage")),
):
    check_csrf(auth, csrf_token)
    name = name.strip()[:120]
    if not name or db.scalar(select(Group).where(Group.name == name)):
        raise HTTPException(409, detail="Group name is invalid or already exists")
    group = Group(name=name, description=description.strip())
    db.add(group)
    db.flush()
    record_audit(db, auth, "group.created", "group", group.id, name=name)
    db.commit()
    return RedirectResponse("/admin?saved=1", status_code=303)


@app.get("/admin/validators", response_class=HTMLResponse)
def managed_validators_page(request: Request, auth: AuthContext = Depends(require_permission('validator.view'))):
    return templates.TemplateResponse(request, 'validators.html', page_context(auth,
        can_manage_validators=True))


@app.get("/admin/configuration", response_class=HTMLResponse)
def configuration_page(request: Request, edit_os_id: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    configuration = get_global_configuration(db)
    certificates = parse_json(configuration.get("trusted_ca_certificates"), [])
    raw_repository_policies = parse_json(configuration.get("repository_policies"), {})
    repository_policies = (
        {str(key).lower(): normalize_policy(value) for key, value in raw_repository_policies.items()}
        if isinstance(raw_repository_policies, dict) else {}
    )
    custom_os = parse_json(configuration.get("os_definitions"), {})
    timezones = supported_display_timezones()
    oidc = configured_oidc(configuration)
    public_url = os.getenv("CATS_PUBLIC_URL", str(request.base_url).rstrip("/"))
    oidc["redirect_uri"] = oidc.get("redirect_uri") or f"{public_url}/auth/oidc/callback"
    oidc["post_logout_redirect_uri"] = oidc.get("post_logout_redirect_uri") or f"{public_url}/login"
    validator_raw = parse_json(configuration.get("validator_configuration"), {})
    validator_display = {"endpoint": validator_raw.get("endpoint") or "",
        "client_certificate_configured": bool(validator_raw.get("client_certificate")),
        "client_key_configured": secret_configured(validator_raw.get("client_key") or ""),
        "ca_configured": bool(validator_raw.get("ca_certificate"))}
    return templates.TemplateResponse(request, "configuration.html", page_context(
        auth,
        configuration=configuration,
        saved=request.query_params.get("saved") == "1",
        timezones=timezones,
        date_formats=[("%d %b %Y", "31 Jul 2026"), ("%Y-%m-%d", "2026-07-31"), ("%m/%d/%Y", "07/31/2026")],
        time_formats=[("%H:%M UTC", "24-hour time (UTC)"), ("%I:%M %p UTC", "12-hour time (UTC)")],
        certificates=certificates, repository_policies=repository_policies,
        custom_os=custom_os,
        oidc=oidc, public_url=public_url, registries=configured_registries(configuration),
        oidc_mappings=db.scalars(select(OidcClaimMapping).order_by(OidcClaimMapping.id)).all(),
        oidc_roles=db.scalars(select(Role).order_by(Role.name)).all(),
        oidc_groups=db.scalars(select(Group).order_by(Group.name)).all(),
        oidc_services=db.scalars(select(Service).order_by(Service.name)).all(),
        security_data_sources={row.key: row for row in db.scalars(select(SecurityDataSource))},
        intelligence_status=intelligence_status(),
        purpose_templates=[{"kind": kind, "name": PURPOSE_NAMES[kind],
                            "customized": purpose_template_for(db, kind)[1]} for kind in PURPOSE_CATALOG],
        validator=validator_display, validator_result=request.query_params.get("validator_result", ""),
        cyber_warning_policy=parse_json(configuration.get("cyber_warning_policy"), {}),
        signing=signing.public_metadata(configuration),
        os_definitions={**OS_DEFINITIONS, **custom_os}, package_managers=sorted(PACKAGE_MANAGERS),
        edit_os_id=edit_os_id.strip().lower(),
        repository_result=request.query_params.get("repository_result", ""),
        oidc_result=request.query_params.get("oidc_result", ""),
    ))


@app.post("/admin/general-policy/group-parent")
def update_group_parent(group_id: str, parent_id: str = Form(""), csrf_token: str = Form(),
                        db: Session = Depends(get_db), auth: AuthContext = Depends(require_config_scope)):
    check_csrf(auth, csrf_token)
    scope = requested_group_scope(group_id, db, auth)
    if scope is None:
        raise HTTPException(422, detail="Choose a group")
    group = db.get(Group, scope)
    if group is None:
        raise HTTPException(404)
    try:
        parent = db.get(Group, int(parent_id)) if parent_id else None
    except ValueError as exc:
        raise HTTPException(422, detail="Invalid parent group") from exc
    if parent_id and parent is None:
        raise HTTPException(422, detail="Parent group not found")
    if parent is not None and not auth.can_manage_group(parent.id):
        raise HTTPException(403, detail="Parent group is outside your configuration scope")
    ancestor = parent
    visited = {scope}
    while ancestor is not None:
        if ancestor.id in visited:
            raise HTTPException(422, detail="Group inheritance would create a cycle")
        visited.add(ancestor.id)
        ancestor = db.get(Group, ancestor.parent_id) if ancestor.parent_id else None
    group.parent_id = parent.id if parent else None
    record_audit(db, auth, "group.parent.updated", "group", scope, parent_id=group.parent_id)
    db.commit()
    return RedirectResponse(f"/admin/general-policy?group_id={scope}&saved=1", status_code=303)


@app.get("/admin/configuration/export-templates/{kind}", response_class=HTMLResponse)
@app.get("/admin/general-policy/export-templates/{kind}", response_class=HTMLResponse)
def purpose_template_page(kind: str, request: Request, group_id: str = "", db: Session = Depends(get_db),
                          auth: AuthContext = Depends(require_config_scope)):
    if kind not in PURPOSE_CATALOG:
        raise HTTPException(404)
    scope = requested_group_scope(group_id, db, auth)
    columns, source, mode = purpose_template_policy(db, kind, scope)
    labels = dict(PURPOSE_CATALOG[kind])
    defaults = dict(PURPOSE_CATALOG[kind])
    return templates.TemplateResponse(request, "purpose_export_template.html", page_context(
        auth, kind=kind, name=PURPOSE_NAMES[kind], columns=columns, labels=labels,
        defaults=defaults, source=source, mode=mode, group_id=scope,
        saved=request.query_params.get("saved") == "1"))


@app.post("/admin/configuration/export-templates/{kind}")
@app.post("/admin/general-policy/export-templates/{kind}")
def purpose_template_update(kind: str, field: list[str] = Form(), heading: list[str] = Form(),
                            enabled: list[str] | None = Form(None), csrf_token: str = Form(), group_id: str = "",
                            db: Session = Depends(get_db), auth: AuthContext = Depends(require_config_scope)):
    check_csrf(auth, csrf_token)
    if kind not in PURPOSE_CATALOG:
        raise HTTPException(404)
    scope = requested_group_scope(group_id, db, auth)
    if len(field) != len(heading):
        raise HTTPException(422, detail="Template fields and headings do not match")
    try:
        columns = validate_purpose_template(kind, [
            {"field": name, "heading": label, "enabled": name in (enabled or [])}
            for name, label in zip(field, heading)])
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from None
    key = purpose_policy_key(kind, scope) if scope is not None else purpose_setting_key(kind)
    setting = db.scalar(select(PortalSetting).where(PortalSetting.key == key))
    if setting is None:
        setting = PortalSetting(key=key, group_id=scope)
        db.add(setting)
    setting.value = json.dumps({"mode": "custom", "columns": columns} if scope is not None else columns, separators=(",", ":"))
    setting.updated_by_id = auth.user.id
    setting.updated_at = utcnow()
    record_audit(db, auth, "export_template.updated", "portal_setting", key,
                 template=kind, group_id=scope, enabled_fields=sum(c["enabled"] for c in columns))
    db.commit()
    return RedirectResponse(f"/admin/general-policy/export-templates/{kind}?group_id={scope or ''}&saved=1", status_code=303)


@app.post("/admin/configuration/export-templates/{kind}/reset")
@app.post("/admin/general-policy/export-templates/{kind}/reset")
def purpose_template_reset(kind: str, csrf_token: str = Form(), group_id: str = "", mode: str = Form("inherit"),
                           db: Session = Depends(get_db), auth: AuthContext = Depends(require_config_scope)):
    check_csrf(auth, csrf_token)
    if kind not in PURPOSE_CATALOG:
        raise HTTPException(404)
    scope = requested_group_scope(group_id, db, auth)
    if scope is not None and mode not in {"inherit", "default"}:
        raise HTTPException(422, detail="Invalid template policy")
    key = purpose_policy_key(kind, scope) if scope is not None else purpose_setting_key(kind)
    setting = db.scalar(select(PortalSetting).where(PortalSetting.key == key))
    if setting is not None and (scope is None or mode == "inherit"):
        db.delete(setting)
    elif scope is not None and mode == "default":
        if setting is None:
            setting = PortalSetting(key=key, group_id=scope)
            db.add(setting)
        setting.value = '{"mode":"default"}'
        setting.updated_by_id = auth.user.id
        setting.updated_at = utcnow()
    record_audit(db, auth, "export_template.policy" if scope is not None else "export_template.reset",
                 "portal_setting", key, template=kind, group_id=scope, mode=mode)
    db.commit()
    return RedirectResponse(f"/admin/general-policy/export-templates/{kind}?group_id={scope or ''}&saved=1", status_code=303)


@app.get("/admin/compliance", response_class=HTMLResponse)
def compliance_page(request: Request, group_id: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_config_scope)):
    groups = manageable_groups(db, auth)
    selected_group_id = requested_group_scope(group_id or (str(groups[0].id) if groups else None), db, auth)
    configuration = get_configuration(db, selected_group_id)
    try:
        epss_rules = json.loads(configuration.get("epss_rules", "[]"))
    except (TypeError, ValueError):
        epss_rules = []
    if not epss_rules:
        epss_rules = [{"severity": "Any", "threshold": configuration.get("epss_threshold", "0.90"), "noncompliant": True}]
    try:
        raw_due_rules = json.loads(configuration.get("raw_due_rules", "[]"))
    except (TypeError, ValueError):
        raw_due_rules = []
    return templates.TemplateResponse(request, "compliance.html", page_context(
        auth, configuration=configuration, epss_rules=epss_rules, raw_due_rules=raw_due_rules,
        saved=request.query_params.get("saved") == "1", groups=groups, selected_group_id=selected_group_id,
    ))


@app.get("/admin/compliance-frameworks", response_class=HTMLResponse)
def compliance_frameworks_page(request: Request, group_id: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_config_scope)):
    groups = manageable_groups(db, auth)
    selected_group_id = requested_group_scope(group_id or (str(groups[0].id) if groups else None), db, auth)
    return templates.TemplateResponse(request, "compliance_frameworks.html", page_context(
        auth, configuration=get_configuration(db, selected_group_id),
        saved=request.query_params.get("saved") == "1", groups=groups,
        selected_group_id=selected_group_id,
    ))


@app.get("/admin/evidence-policy", response_class=HTMLResponse)
def evidence_policy_page(request: Request, group_id: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_config_scope)):
    groups = manageable_groups(db, auth)
    selected_group_id = requested_group_scope(group_id or (str(groups[0].id) if groups else None), db, auth)
    return templates.TemplateResponse(request, "evidence_policy.html", page_context(
        auth, configuration=get_configuration(db, selected_group_id),
        saved=request.query_params.get("saved") == "1", groups=groups,
        selected_group_id=selected_group_id,
    ))


@app.get("/admin/workflow-policy", response_class=HTMLResponse)
def workflow_policy_page(request: Request, group_id: str = "", db: Session = Depends(get_db), auth: AuthContext = Depends(require_config_scope)):
    groups = manageable_groups(db, auth)
    selected_group_id = requested_group_scope(group_id or (str(groups[0].id) if groups else None), db, auth)
    return templates.TemplateResponse(request, "workflow_policy.html", page_context(
        auth, configuration=get_configuration(db, selected_group_id),
        saved=request.query_params.get("saved") == "1", groups=groups,
        selected_group_id=selected_group_id,
    ))


@app.get("/admin/dependency-watchlist", response_class=HTMLResponse)
def dependency_watchlist_page(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    entries = db.scalars(select(DependencyWatchlistEntry).order_by(DependencyWatchlistEntry.id)).all()
    return templates.TemplateResponse(request, "dependency_watchlist.html", page_context(
        auth, entries=entries, saved=request.query_params.get("saved") == "1"))


def _refresh_watchlist_matches(db: Session) -> None:
    # Re-evaluate persisted SBOM evidence when configuration changes. Old scan
    # payloads without a component inventory simply produce no matches.
    entries = db.scalars(select(DependencyWatchlistEntry).where(DependencyWatchlistEntry.enabled.is_(True))).all()
    cursor = 0
    while True:
        executions = db.scalars(select(Execution).where(
            Execution.id > cursor, Execution.raw_payload.is_not(None),
        ).order_by(Execution.id).limit(32)).all()
        if not executions:
            break
        for execution in executions:
            reconcile_watchlist_matches(db, execution, entries=entries)
        cursor = executions[-1].id
        # Keep rebuilt matches bounded while preserving the caller's transaction.
        db.flush()


@app.post("/admin/dependency-watchlist")
def save_dependency_watchlist(
    csrf_token: str = Form(), entry_id: int = Form(default=0), action: str = Form(default="save"),
    purl: str = Form(default=""), ecosystem: str = Form(default=""), name: str = Form(default=""),
    version_constraint: str = Form(default=""), enabled: bool = Form(default=False),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    entry = db.get(DependencyWatchlistEntry, entry_id) if entry_id else None
    if entry_id and not entry:
        raise HTTPException(404, detail="Watchlist entry not found")
    if action == "delete":
        if not entry:
            raise HTTPException(404, detail="Watchlist entry not found")
        db.execute(delete(DependencyWatchlistMatch).where(DependencyWatchlistMatch.entry_id == entry.id))
        db.delete(entry)
        record_audit(db, auth, "watchlist.deleted", "watchlist_entry", entry_id)
    elif action == "save":
        try:
            parsed = parse_watchlist_entries(yaml.safe_dump([{"purl": purl, "ecosystem": ecosystem,
                "name": name, "version_constraint": version_constraint}]), "yaml")[0]
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc)) from exc
        if not entry:
            entry = DependencyWatchlistEntry()
            db.add(entry)
        for key, value in parsed.items():
            setattr(entry, key, value)
        entry.enabled = enabled
        db.flush()
        record_audit(db, auth, "watchlist.saved", "watchlist_entry", entry.id,
                     purl=entry.purl, ecosystem=entry.ecosystem, name=entry.name,
                     version_constraint=entry.version_constraint, enabled=enabled)
    else:
        raise HTTPException(422, detail="Unknown watchlist action")
    db.flush()
    _refresh_watchlist_matches(db)
    db.commit()
    return RedirectResponse("/admin/dependency-watchlist?saved=1", status_code=303)


@app.post("/admin/dependency-watchlist/import")
async def import_dependency_watchlist(
    csrf_token: str = Form(), file: UploadFile = File(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    suffix = Path(file.filename or "").suffix.lower().lstrip(".")
    content = await file.read(1024 * 1024 + 1)
    try:
        entries = parse_watchlist_entries(content.decode("utf-8-sig"), suffix)
    except (ValueError, UnicodeError, yaml.YAMLError) as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    for item in entries:
        db.add(DependencyWatchlistEntry(**item, enabled=True))
    db.flush()
    _refresh_watchlist_matches(db)
    record_audit(db, auth, "watchlist.imported", "watchlist", "global", count=len(entries), format=suffix)
    db.commit()
    return RedirectResponse("/admin/dependency-watchlist?saved=1", status_code=303)


@app.post("/admin/configuration")
def save_configuration(
    display_timezone: str = Form(), date_format: str = Form(), time_format: str = Form(),
    identity_mode: str = Form(), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    if display_timezone not in set(supported_display_timezones()):
        raise HTTPException(422, detail="Unknown display timezone")
    if date_format not in {"%d %b %Y", "%Y-%m-%d", "%m/%d/%Y"}:
        raise HTTPException(422, detail="Unsupported date format")
    if time_format not in {"%H:%M UTC", "%I:%M %p UTC"}:
        raise HTTPException(422, detail="Unsupported time format")
    if identity_mode not in {"local", "oidc", "both"}:
        raise HTTPException(422, detail="Unsupported identity mode")
    values = {
        "display_timezone": display_timezone, "date_format": date_format,
        "time_format": time_format,
        "identity_mode": identity_mode,
    }
    for key, value in values.items():
        storage_key = scoped_setting_key(key, None)
        setting = db.scalar(select(PortalSetting).where(PortalSetting.key == storage_key))
        if not setting:
            setting = PortalSetting(key=storage_key, group_id=None)
            db.add(setting)
        setting.value = value
        setting.updated_by_id = auth.user.id
        setting.updated_at = utcnow()
    record_audit(db, auth, "configuration.updated", "portal", "global", changed=list(values))
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/remediation")
def save_remediation_configuration(csrf_token: str = Form(), enabled: bool = Form(False),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    check_csrf(auth, csrf_token)
    setting = db.scalar(select(PortalSetting).where(PortalSetting.key == "remediation_enabled"))
    if setting is None:
        setting = PortalSetting(key="remediation_enabled", group_id=None)
        db.add(setting)
    setting.value = "true" if enabled else "false"
    setting.updated_by_id = auth.user.id
    setting.updated_at = utcnow()
    record_audit(db, auth, "remediation.feature_toggled", "portal", "global", enabled=enabled)
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/oidc")
def save_oidc_configuration(
    request: Request, csrf_token: str = Form(), provider_name: str = Form(default=""), issuer: str = Form(default=""),
    client_id: str = Form(default=""), client_secret: str = Form(default=""), scopes: str = Form(default="openid profile email"),
    username_claim: str = Form(default="preferred_username"), email_claim: str = Form(default="email"),
    groups_claim: str = Form(default=""), roles_claim: str = Form(default=""),
    redirect_uri: str = Form(default=""), post_logout_redirect_uri: str = Form(default=""), browser_issuer: str = Form(default=""),
    action: str = Form(default="save"),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    issuer = issuer.strip().rstrip("/")
    browser_issuer = browser_issuer.strip().rstrip("/")
    parsed = urllib.parse.urlparse(issuer)
    if not issuer or parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise HTTPException(422, detail="OIDC issuer must be a valid HTTP(S) URL")
    # Remote HTTP issuers are rejected by default because OIDC discovery and
    # token exchange would otherwise expose credentials on the network.  A
    # local development Keycloak on a LAN address can be explicitly enabled
    # with CATS_OIDC_ALLOW_INSECURE_HTTP=true; production remains HTTPS-only.
    allow_insecure_http = os.getenv("CATS_OIDC_ALLOW_INSECURE_HTTP", "").strip().lower() in {"1", "true", "yes", "on"}
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"} and not allow_insecure_http:
        raise HTTPException(422, detail="OIDC issuer must use HTTPS outside local development")
    if browser_issuer:
        browser_parsed = urllib.parse.urlparse(browser_issuer)
        if browser_parsed.scheme not in {"https", "http"} or not browser_parsed.netloc:
            raise HTTPException(422, detail="Browser issuer must be a valid HTTP(S) URL")
    if not client_id.strip():
        raise HTTPException(422, detail="OIDC client ID is required")
    scopes = " ".join(scopes.split())
    if "openid" not in scopes.split():
        scopes = "openid " + scopes
    current = parse_json(get_global_configuration(db).get("oidc_configuration"), {})
    if not isinstance(current, dict): current = {}
    public_url = os.getenv("CATS_PUBLIC_URL", str(request.base_url).rstrip("/"))
    redirect_uri = redirect_uri.strip() or f"{public_url}/auth/oidc/callback"
    post_logout_redirect_uri = post_logout_redirect_uri.strip() or f"{public_url}/login"
    current.update({"provider_name": provider_name.strip()[:120], "issuer": issuer, "client_id": client_id.strip()[:240],
                    "scopes": scopes[:500], "username_claim": username_claim.strip()[:120] or "preferred_username",
                    "email_claim": email_claim.strip()[:120] or "email", "groups_claim": groups_claim.strip()[:120] or "groups",
                    "roles_claim": roles_claim.strip()[:180] or "realm_access.roles", "redirect_uri": redirect_uri.strip()[:500],
                    "post_logout_redirect_uri": post_logout_redirect_uri[:500], "browser_issuer": browser_issuer[:500]})
    if client_secret.strip():
        current["client_secret"] = encrypt_secret(client_secret.strip())
    _set_config_value(db, auth, "oidc_configuration", json.dumps(current), None)
    record_audit(db, auth, "configuration.oidc_updated", "portal", "global", provider=current.get("provider_name"), issuer=issuer)
    db.commit()
    if action == "test":
        # Test the values submitted in this form, after saving the non-secret
        # settings.  This keeps the form populated when discovery fails while
        # ensuring the client secret remains encrypted and is never echoed.
        try:
            from .auth import oidc_discovery
            oidc_discovery(current, configured_ca_bundle(get_global_configuration(db)))
            result = "OIDC discovery succeeded"
        except Exception as exc:
            result = f"OIDC discovery failed: {redact(exc)}"
        return RedirectResponse(f"/admin/configuration?saved=1&oidc_result={urllib.parse.quote(result)}", status_code=303)
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/oidc-mappings")
def save_oidc_claim_mapping(
    csrf_token: str = Form(), mapping_id: int = Form(default=0), action: str = Form(default="save"),
    claim_path: str = Form(default=""), expected_value: str = Form(default=""),
    role_id: int = Form(default=0), scope: str = Form(default=""), scope_id: int = Form(default=0),
    enabled: bool = Form(default=False), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    mapping = db.get(OidcClaimMapping, mapping_id) if mapping_id else None
    if mapping_id and mapping is None:
        raise HTTPException(404, detail="OIDC mapping not found")
    if action == "delete":
        if mapping is None:
            raise HTTPException(404, detail="OIDC mapping not found")
        db.delete(mapping)
        record_audit(db, auth, "oidc.mapping_deleted", "oidc_mapping", mapping_id)
    elif action == "save":
        claim_path = claim_path.strip()
        expected_value = expected_value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", claim_path) or len(claim_path) > 240:
            raise HTTPException(422, detail="Invalid claim path")
        if not expected_value or len(expected_value) > 300:
            raise HTTPException(422, detail="Expected claim value is required")
        if not db.get(Role, role_id):
            raise HTTPException(422, detail="Mapped CATS role does not exist")
        if scope == "global":
            service_id = group_id = None
        elif scope == "service" and db.get(Service, scope_id):
            service_id, group_id = scope_id, None
        elif scope == "group" and db.get(Group, scope_id):
            service_id, group_id = None, scope_id
        else:
            raise HTTPException(422, detail="A valid global, service, or group scope is required")
        if mapping is None:
            mapping = OidcClaimMapping()
            db.add(mapping)
        mapping.claim_path, mapping.expected_value, mapping.role_id = claim_path, expected_value, role_id
        mapping.global_scope, mapping.service_id, mapping.group_id = scope == "global", service_id, group_id
        mapping.enabled = enabled
        db.flush()
        record_audit(db, auth, "oidc.mapping_saved", "oidc_mapping", mapping.id,
            claim_path=claim_path, expected_value=expected_value, role_id=role_id,
            scope=scope, scope_id=scope_id if scope != "global" else None, enabled=enabled)
    else:
        raise HTTPException(422, detail="Unknown mapping action")
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/cyber-warning-policy")
def save_cyber_warning_policy(csrf_token: str = Form(), conditions: list[str] = Form(default=[]),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    check_csrf(auth, csrf_token)
    known = {"critical_high", "kev", "watchlist", "poam", "kind", "missing_evidence"}
    if set(conditions) - known:
        raise HTTPException(422, detail="Unknown warning condition")
    policy = {key: key in conditions for key in sorted(known)}
    _set_config_value(db, auth, "cyber_warning_policy", json.dumps(policy), None)
    record_audit(db, auth, "cyber_warning_policy.updated", "portal", "global", conditions=policy)
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/validator")
def save_validator_configuration(
    csrf_token: str = Form(), endpoint: str = Form(default=""), client_certificate: str = Form(default=""),
    client_key: str = Form(default=""), ca_certificate: str = Form(default=""), action: str = Form(default="save"),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    current = parse_json(get_global_configuration(db).get("validator_configuration"), {})
    if action == "save":
        endpoint = endpoint.strip().rstrip("/")
        parsed = urllib.parse.urlparse(endpoint)
        if endpoint and (parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password):
            raise HTTPException(422, detail="Validator endpoint must be credential-free HTTPS")
        current["endpoint"] = endpoint
        if client_certificate.strip():
            if len(client_certificate) > 65536 or "BEGIN CERTIFICATE" not in client_certificate:
                raise HTTPException(422, detail="Client certificate must be PEM")
            current["client_certificate"] = client_certificate.strip()
        if ca_certificate.strip():
            if len(ca_certificate) > 65536 or "BEGIN CERTIFICATE" not in ca_certificate:
                raise HTTPException(422, detail="Validator CA must be PEM")
            current["ca_certificate"] = ca_certificate.strip()
        if client_key.strip():
            if len(client_key) > 65536 or "PRIVATE KEY" not in client_key:
                raise HTTPException(422, detail="Client key must be PEM")
            current["client_key"] = encrypt_secret(client_key.strip())
        _set_config_value(db, auth, "validator_configuration", json.dumps(current), None)
        record_audit(db, auth, "validator.configuration_updated", "portal", "global",
                     endpoint=endpoint, client_certificate_changed=bool(client_certificate),
                     client_key_changed=bool(client_key), ca_changed=bool(ca_certificate))
        db.commit()
        return RedirectResponse("/admin/configuration?saved=1", status_code=303)
    if action != "test":
        raise HTTPException(422, detail="Unknown validator action")
    try:
        result = validator_health(current)
        if result.get("schema_version") != VALIDATION_PACKAGE_VERSION:
            raise ValueError("Validator schema version is incompatible")
        message = f"Connected; mTLS verified; ready={bool(result.get('ready'))}; active={result.get('active_jobs')}/{result.get('max_jobs')}; schema={result.get('schema_version')}"
    except Exception as exc:
        message = f"Connection failed: {type(exc).__name__}"
    record_audit(db, auth, "validator.connection_tested", "portal", "global", success=message.startswith("Connected"))
    db.commit()
    return RedirectResponse("/admin/configuration?validator_result=" + urllib.parse.quote(message), status_code=303)


@app.post("/admin/configuration/security-data/{source_key}")
async def manage_security_data_source(source_key: str, csrf_token: str = Form(), action: str = Form(),
    source: str = Form(default=""), file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    check_csrf(auth, csrf_token)
    if source_key not in SECURITY_DATA_KEYS or action not in {"save", "refresh", "upload"}:
        raise HTTPException(422, detail="Unknown security data action")
    record = db.get(SecurityDataSource, source_key)
    if record is None:
        record = SecurityDataSource(key=source_key)
        db.add(record)
    if action == "save":
        value = source.strip()
        if len(value) > 2000:
            raise HTTPException(422, detail="Source reference is too long")
        parsed = urllib.parse.urlparse(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise HTTPException(422, detail="Source references cannot contain credentials, query strings, or fragments")
        if source_key != "trivy" and value:
            if parsed.scheme not in {"https", "http"} or not parsed.netloc:
                raise HTTPException(422, detail="Source must be an HTTP(S) URL")
        if source_key == "trivy" and value and (value.startswith("-") or any(character.isspace() for character in value)):
            raise HTTPException(422, detail="Trivy source must be one OCI repository reference")
        record.source = value
        record.status = "CONFIGURED" if value else "UNCONFIGURED"
        record.failure_reason = None
        record_audit(db, auth, "security_data.source_changed", "security_data_source", source_key,
                     source=value)
    else:
        if action == "refresh" and not record.source:
            raise HTTPException(422, detail="Configure a source before refreshing")
        if action == "upload" and source_key == "trivy":
            raise HTTPException(422, detail="Trivy uses its configured OCI DB repository")
        if action == "upload" and file is None:
            raise HTTPException(422, detail="Upload a database or feed file")
        data = await file.read(MAX_SECURITY_DATA_UPLOAD + 1) if file else None
        record.last_attempt_at = utcnow()
        record_audit(db, auth, f"security_data.{action}_requested", "security_data_source", source_key)
        try:
            version = refresh_security_data(source_key, record.source or "", data,
                configured_ca_bundle(get_global_configuration(db)))
        except Exception as exc:
            record.status = "FAILED"
            record.failure_reason = f"{type(exc).__name__}: {redact(exc)}"[:1000]
            record_audit(db, auth, "security_data.update_failed", "security_data_source", source_key,
                         reason=record.failure_reason)
        else:
            record.installed_version = version
            record.installed_at = record.last_success_at = utcnow()
            record.status = "READY"
            record.failure_reason = None
            record_audit(db, auth, "security_data.updated", "security_data_source", source_key,
                         version=version)
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/oidc-test")
def test_oidc_configuration(csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    check_csrf(auth, csrf_token)
    config = parse_json(get_global_configuration(db).get("oidc_configuration"), {})
    try:
        from .auth import oidc_discovery
        oidc_discovery(config, configured_ca_bundle(get_global_configuration(db)))
        result = "OIDC discovery succeeded"
    except Exception as exc:
        result = f"OIDC discovery failed: {redact(exc)}"
    return RedirectResponse(f"/admin/configuration?saved=1&oidc_result={urllib.parse.quote(result)}", status_code=303)


@app.post("/admin/configuration/registries")
def save_registry_configuration(
    csrf_token: str = Form(), registry_id: str = Form(default=""), display_name: str = Form(default=""),
    endpoint: str = Form(default=""), namespace: str = Form(default=""), auth_mode: str = Form(default="none"),
    use_for_remediation: bool = Form(default=False),
    username: str = Form(default=""), password: str = Form(default=""), action: str = Form(default="save"),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    configuration = get_global_configuration(db)
    registries = parse_json(configuration.get("oci_registries"), [])
    if not isinstance(registries, list): registries = []
    registry_id = registry_id.strip() or uuid.uuid4().hex[:12]
    if action == "delete":
        registries = [item for item in registries if str(item.get("id")) != registry_id]
    else:
        endpoint = _validate_endpoint(endpoint)
        if auth_mode not in {"none", "credentials"}:
            raise HTTPException(422, detail="Unsupported registry authentication mode")
        existing = next((item for item in registries if str(item.get("id")) == registry_id), None)
        if existing is None:
            existing = {"id": registry_id}
            registries.append(existing)
        existing.update({"display_name": display_name.strip()[:120] or endpoint, "endpoint": endpoint,
                         "namespace": namespace.strip()[:240], "auth_mode": auth_mode, "username": username.strip()[:240],
                         "use_for_remediation": bool(use_for_remediation)})
        if use_for_remediation:
            for item in registries:
                if item is not existing:
                    item["use_for_remediation"] = False
        if password.strip(): existing["password"] = encrypt_secret(password.strip())
        existing.setdefault("password", "")
        existing.setdefault("status", "Not tested")
    _set_config_value(db, auth, "oci_registries", json.dumps(registries), None)
    record_audit(db, auth, "configuration.oci_registry_updated", "portal", "global", registry_id=registry_id, registry_action=action)
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/registry-test")
def test_registry_configuration(registry_id: str = Form(), csrf_token: str = Form(), db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    check_csrf(auth, csrf_token)
    configuration = get_global_configuration(db)
    registries = parse_json(configuration.get("oci_registries"), [])
    item = next((entry for entry in registries if str(entry.get("id")) == registry_id), None)
    if not item:
        raise HTTPException(404, detail="Registry was not found")
    status_text, detail = "Reachable", "Registry endpoint responded"
    try:
        request = urllib.request.Request(str(item.get("endpoint")) + "/v2/", method="GET")
        if item.get("auth_mode") == "credentials" and item.get("username") and item.get("password"):
            import base64
            token = base64.b64encode(f"{item['username']}:{decrypt_secret(item['password'])}".encode()).decode()
            request.add_header("Authorization", f"Basic {token}")
        ca_bundle = configured_ca_bundle(configuration)
        if ca_bundle:
            import ssl
            context = ssl.create_default_context()
            context.load_verify_locations(cadata=ca_bundle)
            with urllib.request.urlopen(request, timeout=10, context=context) as response:
                if response.status >= 400: raise RuntimeError(f"HTTP {response.status}")
        else:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status >= 400: raise RuntimeError(f"HTTP {response.status}")
    except Exception as exc:
        status_text, detail = "Unavailable", redact(exc)
    for entry in registries:
        if str(entry.get("id")) == registry_id:
            entry["status"], entry["status_detail"] = status_text, detail[:240]
    _set_config_value(db, auth, "oci_registries", json.dumps(registries), None)
    record_audit(db, auth, "configuration.oci_registry_tested", "portal", "global", registry_id=registry_id, status=status_text)
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


def _set_config_value(db: Session, auth: AuthContext, key: str, value: str, group_id: int | None) -> None:
    storage_key = scoped_setting_key(key, group_id)
    setting = db.scalar(select(PortalSetting).where(PortalSetting.key == storage_key))
    if not setting:
        setting = PortalSetting(key=storage_key, group_id=group_id); db.add(setting)
    setting.value = value; setting.updated_by_id = auth.user.id; setting.updated_at = utcnow()


@app.post("/admin/configuration/signing")
def save_signing_configuration(
    csrf_token: str = Form(), private_key: UploadFile | None = File(None),
    public_key: UploadFile | None = File(None), key_password: str = Form(""),
    enabled: bool = Form(False), action: str = Form("save"),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    try:
        current = {} if action == "remove" or (private_key and private_key.filename) else signing.configuration(get_global_configuration(db))
        if action == "remove":
            current = {}
        elif action == "save":
            if private_key and private_key.filename:
                private = private_key.file.read(signing.MAX_KEY_BYTES + 1)
                public = public_key.file.read(signing.MAX_KEY_BYTES + 1) if public_key and public_key.filename else b""
                current = signing.store_keys(private, public, key_password, enabled)
            elif (public_key and public_key.filename) or key_password:
                raise ValueError("Upload the private key again to change its public key or password.")
            else:
                current["enabled"] = enabled
                if enabled:
                    signing.job_material({signing.SETTING: json.dumps(current)}, "push")
                current["updated_at"] = utcnow().isoformat()
        else:
            raise ValueError("Unknown signing configuration action.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _set_config_value(db, auth, signing.SETTING, json.dumps(current), None)
    record_audit(db, auth, "configuration.signing_updated", "portal", "global",
                 enabled=current.get("enabled", False), key_fingerprint=current.get("fingerprint"), removed=action == "remove")
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.get("/admin/configuration/signing/public-key", response_class=PlainTextResponse)
def download_signing_public_key(db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope)):
    pem = signing.configuration(get_global_configuration(db)).get("public_key")
    if not pem:
        raise HTTPException(status_code=404, detail="No signing public key is configured")
    return PlainTextResponse(pem, headers={"Content-Disposition": 'attachment; filename="cosign.pub"'})


@app.post("/admin/configuration/trusted-certificates")
async def update_trusted_certificates(
    csrf_token: str = Form(), certificate: UploadFile | None = File(default=None),
    remove_fingerprint: str = Form(default=""), db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    configuration = get_global_configuration(db)
    certificates = parse_json(configuration.get("trusted_ca_certificates"), [])
    if certificate and certificate.filename:
        payload = await certificate.read()
        try:
            uploaded = certificate_bundle_metadata(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            raise HTTPException(422, detail=str(exc))
        merged = merge_certificate_metadata(certificates, uploaded)
        if len(merged) == len(certificates):
            raise HTTPException(409, detail="All certificates in that upload are already configured")
        certificates = merged
    if remove_fingerprint:
        certificates = [item for item in certificates if item.get("fingerprint") != remove_fingerprint]
    _set_config_value(db, auth, "trusted_ca_certificates", json.dumps(certificates), None)
    record_audit(db, auth, "configuration.trusted_ca_updated", "portal", "global", changed=["trusted_ca_certificates"])
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/repositories")
def update_repository_policies(
    csrf_token: str = Form(), policy_json: str = Form(default="{}"), definitions_json: str = Form(default="{}"),
    os_id: str = Form(default=""), edit_os_id: str = Form(default=""), action: str = Form(default="save"),
    mode: str = Form(default="default"), url: str = Form(default=""), display_name: str = Form(default=""),
    package_manager: str = Form(default=""), remove_os_id: str = Form(default=""),
    verify_tls: list[str] = Form(default=[]), verify_packages: list[str] = Form(default=[]),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    configuration = get_global_configuration(db)
    policies = parse_json(configuration.get("repository_policies"), {})
    definitions = parse_json(configuration.get("os_definitions"), {})
    if not isinstance(policies, dict): policies = {}
    if not isinstance(definitions, dict): definitions = {}
    key = (edit_os_id or os_id).strip().lower()
    if action == "delete" or remove_os_id:
        key = (remove_os_id or key).strip().lower()
        if key in OS_DEFINITIONS:
            raise HTTPException(422, detail="Built-in operating systems cannot be removed")
        definitions.pop(key, None); policies.pop(key, None)
    else:
        if not key: raise HTTPException(422, detail="Operating system is required")
        def posted_bool(values: list[str]) -> bool:
            if not values:
                return True
            decoded = [policy_bool(value, None) for value in values]
            if any(value is None for value in decoded):
                raise HTTPException(422, detail="Repository verification settings are invalid")
            return any(decoded)
        tls_verified = posted_bool(verify_tls)
        packages_verified = posted_bool(verify_packages)
        valid, message = validate_policy(key, mode, url, tls_verified, packages_verified)
        if not valid: raise HTTPException(422, detail=message)
        if key in OS_DEFINITIONS:
            # Built-in IDs and capabilities are immutable, but their mirror
            # policy can be changed independently.
            pass
        else:
            name = display_name.strip()[:120]
            manager = package_manager.strip().lower()
            valid, message = validate_os_definition(key, name, manager)
            if not valid: raise HTTPException(422, detail=message)
            definitions[key] = {"name": name, "package_manager": manager}
        policies[key] = {
            "mode": mode, "url": url.strip() if mode == "custom" else "",
            "verify_tls": tls_verified, "verify_packages": packages_verified,
        }
    _set_config_value(db, auth, "repository_policies", json.dumps(policies), None)
    _set_config_value(db, auth, "os_definitions", json.dumps(definitions), None)
    record_audit(
        db, auth, "configuration.repositories_updated", "portal", "global",
        changed=["repository_policies", "os_definitions"],
        os_id=key, verify_tls=policies.get(key, {}).get("verify_tls", True),
        verify_packages=policies.get(key, {}).get("verify_packages", True),
    )
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/os-definitions")
def update_os_definitions(
    csrf_token: str = Form(), group_id: str = Form(default=""), definitions_json: str = Form(default="{}"),
    os_id: str = Form(default=""), display_name: str = Form(default=""), package_manager: str = Form(default=""),
    remove_os_id: str = Form(default=""), db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    selected_group_id = None
    definitions = parse_json(definitions_json, {})
    if not isinstance(definitions, dict):
        definitions = {}
    if remove_os_id:
        key = remove_os_id.strip().lower()
        if key in OS_DEFINITIONS:
            raise HTTPException(422, detail="Built-in operating systems cannot be removed")
        definitions.pop(key, None)
    else:
        key = os_id.strip().lower()
        if key in OS_DEFINITIONS:
            raise HTTPException(422, detail="Built-in operating systems cannot be replaced")
        name = display_name.strip()[:120]
        valid, message = validate_os_definition(key, name, package_manager)
        if not valid:
            raise HTTPException(422, detail=message)
        definitions[key] = {"name": name, "package_manager": package_manager}
    _set_config_value(db, auth, "os_definitions", json.dumps(definitions), selected_group_id)
    record_audit(db, auth, "configuration.os_definition_updated", "portal", "global", changed=["os_definitions"])
    db.commit()
    return RedirectResponse("/admin/configuration?saved=1", status_code=303)


@app.post("/admin/configuration/repository-test")
def repository_test(
    csrf_token: str = Form(), url: str = Form(default=""), os_id: str = Form(default=""),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    if not url.strip():
        ok, message = True, "Image-defined repositories are supplied by the scanned image"
    else:
        ok, message = test_repository(url.strip())
    result = ("ok:" if ok else "error:") + message
    return RedirectResponse(f"/admin/configuration?edit_os_id={urllib.parse.quote(os_id.strip().lower())}&repository_result={urllib.parse.quote(result)}", status_code=303)


@app.post("/admin/evidence-policy")
def save_evidence_policy(
    skipped_images_incomplete: str = Form(default="true"), incomplete_noncompliant: str = Form(default="true"),
    group_id: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_config_scope),
):
    check_csrf(auth, csrf_token)
    selected_group_id = requested_group_scope(group_id, db, auth)
    if skipped_images_incomplete not in {"true", "false"}:
        raise HTTPException(422, detail="Unsupported skipped-image policy")
    if incomplete_noncompliant not in {"true", "false"}:
        raise HTTPException(422, detail="Unsupported incomplete-evidence policy")
    values = {
        "skipped_images_incomplete": skipped_images_incomplete,
        "incomplete_noncompliant": incomplete_noncompliant,
    }
    for key, value in values.items():
        storage_key = scoped_setting_key(key, selected_group_id)
        setting = db.scalar(select(PortalSetting).where(PortalSetting.key == storage_key))
        if not setting:
            setting = PortalSetting(key=storage_key, group_id=selected_group_id)
            db.add(setting)
        setting.value = value
        setting.updated_by_id = auth.user.id
        setting.updated_at = utcnow()
    record_audit(db, auth, "evidence_policy.updated", "group" if selected_group_id else "portal", str(selected_group_id or "global"), changed=list(values))
    db.commit()
    return RedirectResponse("/admin/general-policy?saved=1" + (f"&group_id={selected_group_id}" if selected_group_id else ""), status_code=303)


@app.post("/admin/workflow-policy")
def save_workflow_policy(
    warning_days: str = Form(default="14"), exception_max_days: str = Form(default="365"),
    group_id: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_config_scope),
):
    check_csrf(auth, csrf_token)
    selected_group_id = requested_group_scope(group_id, db, auth)
    try:
        warning_window = int(warning_days)
        maximum_exception = int(exception_max_days)
    except ValueError as exc:
        raise HTTPException(422, detail="Workflow policy values must be numbers") from exc
    if warning_window < 1 or warning_window > 3650:
        raise HTTPException(422, detail="Warning window must be between 1 and 3650 days")
    if maximum_exception < 0 or maximum_exception > 3650:
        raise HTTPException(422, detail="Maximum exception duration must be between 0 and 3650 days")
    values = {"warning_days": str(warning_window), "exception_max_days": str(maximum_exception)}
    for key, value in values.items():
        storage_key = scoped_setting_key(key, selected_group_id)
        setting = db.scalar(select(PortalSetting).where(PortalSetting.key == storage_key))
        if not setting:
            setting = PortalSetting(key=storage_key, group_id=selected_group_id)
            db.add(setting)
        setting.value = value
        setting.updated_by_id = auth.user.id
        setting.updated_at = utcnow()
    record_audit(db, auth, "workflow_policy.updated", "group" if selected_group_id else "portal", str(selected_group_id or "global"), changed=list(values))
    db.commit()
    return RedirectResponse("/admin/general-policy?saved=1" + (f"&group_id={selected_group_id}" if selected_group_id else ""), status_code=303)


@app.post("/admin/compliance")
def save_compliance(
    compliance_mode: str = Form(default="risk_based"), overdue_days: str = Form(),
    kev_enabled: str = Form(default="true"),
    kev_noncompliant: str = Form(default="true"), epss_enabled: str = Form(default="true"),
    epss_threshold: str = Form(default="0.90"), epss_severity: list[str] = Form(default=[]),
    epss_rule_threshold: list[str] = Form(default=[]), epss_rule_noncompliant: list[str] = Form(default=[]),
    minimum_severity: str = Form(default="None"),
    raw_due_severity: list[str] = Form(default=[]), raw_due_days: list[str] = Form(default=[]),
    group_id: str = Form(default=""), csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_config_scope),
):
    check_csrf(auth, csrf_token)
    selected_group_id = requested_group_scope(group_id, db, auth)
    try:
        overdue = int(overdue_days)
    except ValueError as exc:
        raise HTTPException(422, detail="Compliance thresholds must be numbers") from exc
    if overdue < 1 or overdue > 3650:
        raise HTTPException(422, detail="CVE aging threshold must be between 1 and 3650 days")
    if compliance_mode not in {"raw", "risk_based"}:
        raise HTTPException(422, detail="Unsupported compliance mode")
    if any(value not in {"true", "false"} for value in (kev_enabled, kev_noncompliant, epss_enabled)):
        raise HTTPException(422, detail="Risk policy switches must be true or false")
    if minimum_severity not in {"None", "Low", "Medium", "High", "Critical"}:
        raise HTTPException(422, detail="Unsupported minimum severity")
    try:
        epss_value = float(epss_threshold)
    except ValueError as exc:
        raise HTTPException(422, detail="EPSS threshold must be a number") from exc
    if epss_value < 0 or epss_value > 1:
        raise HTTPException(422, detail="EPSS threshold must be between 0 and 1")
    rules = []
    for index, severity in enumerate(epss_severity):
        severity = severity.strip()
        if not severity:
            continue
        threshold_text = epss_rule_threshold[index] if index < len(epss_rule_threshold) else ""
        try:
            threshold = float(threshold_text)
        except ValueError as exc:
            raise HTTPException(422, detail="Each EPSS rule threshold must be a number") from exc
        if threshold < 0 or threshold > 1:
            raise HTTPException(422, detail="Each EPSS rule threshold must be between 0 and 1")
        noncompliant = index < len(epss_rule_noncompliant) and epss_rule_noncompliant[index] == "true"
        rules.append({"severity": severity, "threshold": threshold, "noncompliant": noncompliant})
    if not rules:
        rules = [{"severity": "Any", "threshold": epss_value, "noncompliant": True}]
    raw_rules = []
    for index, severity in enumerate(raw_due_severity):
        severity = severity.strip()
        if not severity:
            continue
        days_text = raw_due_days[index] if index < len(raw_due_days) else ""
        try:
            days = int(days_text)
        except ValueError as exc:
            raise HTTPException(422, detail="Each raw due-date rule must be a whole number") from exc
        if days < 1 or days > 3650:
            raise HTTPException(422, detail="Raw due-date rules must be between 1 and 3650 days")
        raw_rules.append({"severity": severity, "days": days})
    if not raw_rules:
        raw_rules = [{"severity": "Critical", "days": 30}, {"severity": "High", "days": 60}, {"severity": "Medium", "days": 90}, {"severity": "Low", "days": 120}]
    values = {
        "compliance_mode": compliance_mode, "overdue_days": str(overdue),
        "kev_enabled": kev_enabled,
        "kev_noncompliant": kev_noncompliant, "epss_enabled": epss_enabled,
        "epss_threshold": str(epss_value), "epss_rules": json.dumps(rules, separators=(",", ":")),
        "minimum_severity": minimum_severity,
        "raw_due_rules": json.dumps(raw_rules, separators=(",", ":")),
    }
    for key, value in values.items():
        storage_key = scoped_setting_key(key, selected_group_id)
        setting = db.scalar(select(PortalSetting).where(PortalSetting.key == storage_key))
        if not setting:
            setting = PortalSetting(key=storage_key, group_id=selected_group_id)
            db.add(setting)
        setting.value = value
        setting.updated_by_id = auth.user.id
        setting.updated_at = utcnow()
    record_audit(db, auth, "vulnerability_policy.updated", "group" if selected_group_id else "portal", str(selected_group_id or "global"), changed=list(values))
    db.commit()
    return RedirectResponse("/admin/compliance?saved=1" + (f"&group_id={selected_group_id}" if selected_group_id else ""), status_code=303)


@app.post("/admin/compliance-frameworks")
def save_hardening_policy(
    hardening_overdue_days: str = Form(default="90"),
    hardening_noncompliant: str = Form(default="true"),
    group_id: str = Form(default=""), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_global_config_scope),
):
    check_csrf(auth, csrf_token)
    selected_group_id = requested_group_scope(group_id, db, auth)
    try:
        threshold = int(hardening_overdue_days)
    except ValueError as exc:
        raise HTTPException(422, detail="Hardening threshold must be a whole number") from exc
    if threshold < 1 or threshold > 3650:
        raise HTTPException(422, detail="Hardening threshold must be between 1 and 3650 days")
    if hardening_noncompliant not in {"true", "false"}:
        raise HTTPException(422, detail="Hardening treatment must be true or false")
    values = {"hardening_overdue_days": str(threshold), "hardening_noncompliant": hardening_noncompliant}
    for key, value in values.items():
        storage_key = scoped_setting_key(key, selected_group_id)
        setting = db.scalar(select(PortalSetting).where(PortalSetting.key == storage_key))
        if not setting:
            setting = PortalSetting(key=storage_key, group_id=selected_group_id)
            db.add(setting)
        setting.value = value
        setting.updated_by_id = auth.user.id
        setting.updated_at = utcnow()
    record_audit(db, auth, "hardening_policy.updated", "group" if selected_group_id else "portal", str(selected_group_id or "global"), changed=list(values))
    db.commit()
    return RedirectResponse("/admin/compliance-frameworks?saved=1" + (f"&group_id={selected_group_id}" if selected_group_id else ""), status_code=303)


@app.post("/admin/users")
def create_user(
    username: str = Form(), display_name: str = Form(), password: str = Form(),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("user.manage")),
):
    check_csrf(auth, csrf_token)
    username = username.strip().lower()
    if not username or db.scalar(select(User).where(User.username == username)):
        raise HTTPException(409, detail="Username is invalid or already exists")
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    user = User(username=username, display_name=display_name.strip() or username,
                password_hash=password_hash, must_change_password=True)
    db.add(user)
    db.flush()
    record_audit(db, auth, "user.created", "user", user.id, username=username)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/roles")
def create_role(
    name: str = Form(), description: str = Form(default=""), permissions: list[str] = Form(default=[]),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("role.manage")),
):
    check_csrf(auth, csrf_token)
    selected = sorted(set(permissions))
    if not name.strip() or db.scalar(select(Role).where(Role.name == name.strip())):
        raise HTTPException(409, detail="Role name is invalid or already exists")
    if any(item not in PERMISSIONS for item in selected):
        raise HTTPException(422, detail="Unknown permission")
    role = Role(name=name.strip(), description=description.strip(), permissions=selected, system=False)
    db.add(role)
    db.flush()
    record_audit(db, auth, "role.created", "role", role.id, name=role.name, permissions=selected)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/assignments")
def assign_role(
    user_id: int = Form(), role_id: int = Form(), service_ids: list[int] = Form(default=[]),
    service_id: str = Form(default=""), group_id: str = Form(default=""),
    csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("role.manage")),
):
    check_csrf(auth, csrf_token)
    user, role = db.get(User, user_id), db.get(Role, role_id)
    if not user or not role:
        raise HTTPException(404)
    selected_service_ids = list(dict.fromkeys(service_ids))
    if not selected_service_ids and service_id:
        selected_service_ids = [int(service_id)]
    group_scope = int(group_id) if group_id else None
    if selected_service_ids and group_scope is not None:
        if role.name != "Service Manager":
            raise HTTPException(422, detail="Only Service Manager assignments may combine group and service scope")
        group = db.get(Group, group_scope)
        if not group or any(not db.get(Service, selected_id) or not any(item.id == selected_id for item in group.services) for selected_id in selected_service_ids):
            raise HTTPException(422, detail="Every selected service must belong to the selected group")
    if (selected_service_ids or group_scope is not None) and any(p in role.permissions for p in {"user.manage", "role.manage", "service.delete"}):
        raise HTTPException(422, detail="Administrative permissions must be assigned globally")
    scopes = selected_service_ids or [None]
    try:
        for scope in scopes:
            exists = db.scalar(select(UserRoleAssignment).where(
                UserRoleAssignment.user_id == user_id, UserRoleAssignment.role_id == role_id,
                UserRoleAssignment.service_id == scope,
                UserRoleAssignment.group_id == group_scope,
            ))
            if not exists:
                assignment = UserRoleAssignment(user_id=user_id, role_id=role_id, service_id=scope, group_id=group_scope)
                db.add(assignment)
                db.flush()
                record_audit(db, auth, "role.assigned", "user_role_assignment", assignment.id,
                             user_id=user_id, role_id=role_id, service_id=scope, group_id=group_scope)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, detail="One or more selected assignments already exist or conflict with an existing assignment") from exc
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/assignments/{assignment_id}/delete")
def remove_assignment(
    assignment_id: int, csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("role.manage")),
):
    check_csrf(auth, csrf_token)
    assignment = db.get(UserRoleAssignment, assignment_id)
    if not assignment:
        raise HTTPException(404)
    if assignment.user_id == auth.user.id and assignment.role.name == "Administrator":
        raise HTTPException(409, detail="You cannot remove your own Administrator role")
    record_audit(db, auth, "role.unassigned", "user_role_assignment", assignment.id,
                 user_id=assignment.user_id, role_id=assignment.role_id, service_id=assignment.service_id)
    db.delete(assignment)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/toggle")
def toggle_user(
    user_id: int, csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("user.manage")),
):
    check_csrf(auth, csrf_token)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404)
    if user.id == auth.user.id:
        raise HTTPException(409, detail="You cannot disable your own account")
    user.enabled = not user.enabled
    if not user.enabled:
        db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    record_audit(db, auth, "user.enabled" if user.enabled else "user.disabled", "user", user.id)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/reset-password")
def reset_user_password(
    user_id: int, temporary_password: str = Form(), csrf_token: str = Form(),
    db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("user.manage")),
):
    check_csrf(auth, csrf_token)
    user = db.get(User, user_id)
    if not user or user.auth_source != "local":
        raise HTTPException(404)
    try:
        user.password_hash = hash_password(temporary_password)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    user.must_change_password = True
    user.failed_login_count = 0
    user.locked_until = None
    db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    record_audit(db, auth, "user.password_reset", "user", user.id)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/users/{user_id}/delete")
def delete_user_account(
    user_id: int, csrf_token: str = Form(), db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("user.manage")),
):
    check_csrf(auth, csrf_token)
    if user_id == auth.user.id:
        raise HTTPException(409, detail="You cannot delete your own account")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, detail="User account not found")
    # Never remove the last global Administrator/break-glass account.
    administrator = db.scalar(select(Role).where(Role.name == "Administrator"))
    if administrator:
        remaining = db.scalar(select(func.count(UserRoleAssignment.id)).where(
            UserRoleAssignment.user_id == user.id,
            UserRoleAssignment.role_id == administrator.id,
            UserRoleAssignment.service_id.is_(None), UserRoleAssignment.group_id.is_(None),
        )) or 0
        if remaining and (db.scalar(select(func.count(UserRoleAssignment.id)).where(
            UserRoleAssignment.role_id == administrator.id,
            UserRoleAssignment.service_id.is_(None), UserRoleAssignment.group_id.is_(None),
            UserRoleAssignment.user_id != user.id,
        )) or 0) == 0:
            raise HTTPException(409, detail="The last global Administrator account cannot be deleted")
    username, display_name = user.username, user.display_name
    for event in db.scalars(select(AuditEvent).where(AuditEvent.actor_user_id == user.id)):
        detail = dict(event.detail or {})
        detail.setdefault("actor_username", username)
        detail.setdefault("actor_display_name", display_name)
        event.detail = detail
        event.actor_user_id = None
    for history in db.scalars(select(PoamHistory).where(PoamHistory.actor_user_id == user.id)):
        history.actor_user_id = None
    # Re-point non-null historical foreign keys to the administrator performing
    # the deletion; audit snapshots above preserve the original actor.
    for workflow in db.scalars(select(WorkflowRequest).where(WorkflowRequest.requested_by_id == user.id)):
        workflow.requested_by_id = auth.user.id
    for workflow in db.scalars(select(WorkflowRequest).where(WorkflowRequest.reviewed_by_id == user.id)):
        workflow.reviewed_by_id = auth.user.id
    for entry in db.scalars(select(PoamEntry).where(PoamEntry.created_by_id == user.id)):
        entry.created_by_id = auth.user.id
    for entry in db.scalars(select(PoamEntry).where(PoamEntry.approved_by_id == user.id)):
        entry.approved_by_id = auth.user.id
    for patch_job in db.scalars(select(PatchExecution).where(PatchExecution.requested_by_id == user.id)):
        patch_job.requested_by_id = auth.user.id
    for validation_run in db.scalars(select(DeploymentValidationRun).where(DeploymentValidationRun.requested_by_id == user.id)):
        validation_run.requested_by_id = None
    for setting in db.scalars(select(PortalSetting).where(PortalSetting.updated_by_id == user.id)):
        setting.updated_by_id = auth.user.id
    for image in db.scalars(select(ServiceImage).where(or_(ServiceImage.requested_by_id == user.id, ServiceImage.approved_by_id == user.id))):
        if image.requested_by_id == user.id:
            image.requested_by_id = None
        if image.approved_by_id == user.id:
            image.approved_by_id = None
    db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    db.execute(delete(UserRoleAssignment).where(UserRoleAssignment.user_id == user.id))
    record_audit(db, auth, "user.deleted", "user", user.id, username=username, display_name=display_name)
    db.delete(user)
    db.commit()
    return RedirectResponse("/admin", status_code=303)
