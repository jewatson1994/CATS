"""HQ-owned validator registry and bounded bootstrap operations.

Only per-validator encrypted mTLS material is persisted; SSH credentials stay
in a worker closure and are cleared on every exit. No host tool installation.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import threading
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update

from .auth import require_user, record_audit
from .database import get_db, SessionLocal
from .models import ManagedValidator, ManagedValidatorOperation, PortalSetting
from .managed_validator_bootstrap import SSHBootstrap, BootstrapError, validate_target, preflight_failure
from .managed_validator_pki import create_identity
from .managed_validator_release import load_release, selftest_request, assert_selftest, SelfTestError
from . import validator_client

router = APIRouter()
WORKERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="managed-validator")
WORKER_SLOTS = threading.BoundedSemaphore(2)
READINESS_LOCK = threading.Lock()
READINESS_CACHE = {"expires": 0.0, "value": None}


def admin(auth=Depends(require_user)):
    if not auth.can_manage_group(None):
        raise HTTPException(403, "Only global administrators may manage validators")
    return auth


def public_record(db, row):
    # Explicit allowlist: no configuration, encrypted keys, credentials or raw exceptions.
    history = db.scalars(select(ManagedValidatorOperation).where(
        ManagedValidatorOperation.validator_id == row.id).order_by(
        ManagedValidatorOperation.started_at.desc()).limit(30)).all()
    return {key: getattr(row, key) for key in (
        "id", "name", "host", "ssh_port", "ssh_username", "api_port", "status",
        "fingerprint", "fingerprint_confirmed", "preflight", "certificate",
        "last_health", "last_self_test", "image", "active_operation_id")} | {
        "created_at": row.created_at.isoformat(), "updated_at": row.updated_at.isoformat(),
        "last_contact_at": row.last_contact_at.isoformat() if row.last_contact_at else None,
        "history": [{key: (getattr(op, key).isoformat() if isinstance(getattr(op, key), datetime)
            else getattr(op, key)) for key in ("id", "action", "status", "phase", "error",
            "cancel_requested", "started_at", "finished_at")} for op in history]}


def readiness():
    # UI polling must not repeatedly read multi-gigabyte Docker archives.
    # Provisioning always independently revalidates all bytes in load_release().
    with READINESS_LOCK:
        if time.monotonic() < READINESS_CACHE["expires"]:
            return dict(READINESS_CACHE["value"])
        try:
            release = load_release(verify_assets=False)
            value = {"ready": True, "image_reference": release["cats_image"]["reference"],
                     "image_id": release["cats_image"]["image_id"]}
        except (ValueError, OSError):
            value = {"ready": False, "reason": "Configure a verified local Docker-host release before provisioning."}
        READINESS_CACHE.update(expires=time.monotonic() + 30, value=value)
        return dict(value)


def clear_selection(db, validator_id):
    selected = db.scalar(select(PortalSetting).where(PortalSetting.key == "validator_configuration"))
    if selected and json.loads(selected.value or "{}").get("managed_validator_id") == validator_id:
        selected.value = "{}"


def recover_operations():
    # Running work cannot survive an HQ process restart. Do not invent remote cleanup.
    with SessionLocal() as db:
        for op in db.scalars(select(ManagedValidatorOperation).where(
                ManagedValidatorOperation.status == "RUNNING")):
            op.status = "FAILED"
            op.phase = "INTERRUPTED"
            op.error = "HQ restarted; remote state must be reconciled by Retry or Remove."
            op.finished_at = datetime.now(timezone.utc)
            row = db.get(ManagedValidator, op.validator_id)
            if row and row.active_operation_id == op.id:
                row.active_operation_id = None
                row.status = "DEGRADED" if row.configuration else "FAILED"
                clear_selection(db, row.id)
        db.commit()


def claim_operation(db, row, action):
    op = ManagedValidatorOperation(id=uuid.uuid4().hex, validator_id=row.id, action=action)
    changed = db.execute(update(ManagedValidator).where(ManagedValidator.id == row.id,
        ManagedValidator.active_operation_id.is_(None)).values(active_operation_id=op.id))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Another operation is already active for this validator")
    db.add(op)
    db.commit()
    db.refresh(row)
    return op


def phase(db, op, value):
    db.refresh(op)
    if op.cancel_requested:
        raise BootstrapError("Operation cancelled; inspect remote state before retrying")
    op.phase = value
    db.commit()


def health_checked(configuration, validator_id):
    result = validator_client.health(configuration)
    if result.get("validator_id") != validator_id or not result.get("ready"):
        raise BootstrapError("Validator health or managed identity verification failed")
    if "cats.validation/v2" not in result.get("request_schema_versions", result.get("protocol_versions", [])):
        raise BootstrapError("Validator does not support the required v2 validation contract")
    # Keep health bounded and allowlisted. A remote body is never a browser DTO.
    return {key: result[key] for key in ("ready", "validator_id", "version", "versions",
        "checked_at", "container_runtime_ready", "disk_free_bytes", "active_jobs", "max_jobs", "validation_types", "protocol_versions", "request_schema_versions") if key in result}


def run_operation(validator_id, operation_id, credentials, acknowledgments):
    with SessionLocal() as db:
        row, op = db.get(ManagedValidator, validator_id), db.get(ManagedValidatorOperation, operation_id)
        identity = None
        try:
            target = validate_target(row.host, row.ssh_port, row.ssh_username, row.api_port)
            action = op.action
            if action in ("preflight", "provision", "rotate", "remove"):
                phase(db, op, "CONNECTING")
                with SSHBootstrap(target, credentials, expected_fingerprint=row.fingerprint) as ssh:
                    if action == "remove":
                        phase(db, op, "REMOVING")
                        ssh.remove(row.id)
                        row.configuration, row.identity, row.certificate = {}, {}, {}
                        row.status = "REMOVED"
                        selected = db.scalar(select(PortalSetting).where(PortalSetting.key == "validator_configuration"))
                        if selected and json.loads(selected.value or "{}").get("managed_validator_id") == row.id:
                            selected.value = "{}"
                    else:
                        phase(db, op, "PREFLIGHT")
                        row.preflight = ssh.preflight(owner_id=row.id)
                        db.commit()
                        if row.preflight.get("status") not in ("supported", "supported_with_warnings"):
                            raise preflight_failure(row.preflight)
                        if action == "preflight":
                            if row.status != "HEALTHY":
                                row.status = "PREFLIGHT_OK"
                        else:
                            if row.preflight.get("warnings") and not acknowledgments["resource_warnings"]:
                                raise BootstrapError("Acknowledge host preflight warnings before provisioning")
                            if row.configuration:
                                try:
                                    current_health = health_checked(row.configuration, row.id)
                                except Exception:
                                    current_health = {}  # SSH deploy still rejects unfinished strict runtime resources.
                                if current_health.get("active_jobs", 0):
                                    raise BootstrapError("Wait for active validation jobs before replacing the validator")
                            phase(db, op, "VERIFYING_RELEASE")
                            release = load_release()
                            endpoint_host = f"[{row.host}]" if ":" in row.host else row.host
                            identity = create_identity(row.id, row.host, f"https://{endpoint_host}:{row.api_port}")
                            row.configuration = identity["configuration"]
                            row.identity, row.certificate = identity["persistence"], identity["public"]
                            row.image = {"reference": release["cats_image"]["reference"], "image_id": release["cats_image"]["image_id"]}
                            selected = db.scalar(select(PortalSetting).where(PortalSetting.key == "validator_configuration"))
                            if selected and json.loads(selected.value or "{}").get("managed_validator_id") == row.id:
                                selected.value = "{}"
                            row.status = "PROVISIONING"
                            db.commit()
                            phase(db, op, "DEPLOYING")
                            ssh.deploy(row.id, release, identity["deployment"])
                            identity["deployment"].clear()
                            phase(db, op, "HEALTH")
                            deadline = time.monotonic() + 90
                            while True:
                                try:
                                    row.last_health = health_checked(row.configuration, row.id)
                                    row.last_contact_at = datetime.now(timezone.utc)
                                    break
                                except Exception:
                                    if time.monotonic() >= deadline:
                                        raise BootstrapError("Managed mTLS health did not become ready") from None
                                    phase(db, op, "HEALTH")
                                    time.sleep(2)
                            row.status = "DEGRADED"
                            db.commit()
                            phase(db, op, "SELF_TEST")
                            run_selftest(db, row, op, release)
            elif action == "test":
                phase(db, op, "HEALTH")
                row.last_health = health_checked(row.configuration, row.id)
                row.last_contact_at = datetime.now(timezone.utc)
                # Health alone cannot promote an unverified validator.
                if row.status != "HEALTHY":
                    row.status = "DEGRADED"
            elif action == "self-test":
                phase(db, op, "SELF_TEST")
                row.last_health = health_checked(row.configuration, row.id)
                row.last_contact_at = datetime.now(timezone.utc)
                run_selftest(db, row, op, load_release())
            phase(db, op, "COMPLETE")
            op.status = "SUCCEEDED"
        except Exception as exc:
            db.rollback()
            row, op = db.get(ManagedValidator, validator_id), db.get(ManagedValidatorOperation, operation_id)
            if isinstance(exc, BootstrapError) and getattr(exc, 'preflight', None) is not None:
                row.preflight = exc.preflight
            row.status = "DEGRADED" if row.configuration else "FAILED"
            op.status = "CANCELLED" if op.cancel_requested else "FAILED"
            # Only bootstrap errors are authored safe messages; no stderr/SSH exception disclosure.
            op.error = str(exc)[:1000] if isinstance(exc, (BootstrapError, SelfTestError)) else "Operation failed; verify host, release and mTLS configuration."
        finally:
            if identity is not None:
                identity["deployment"].clear()
            credentials.clear()
            row.active_operation_id = None
            if row.status != "HEALTHY":
                selected = db.scalar(select(PortalSetting).where(PortalSetting.key == "validator_configuration"))
                if selected and json.loads(selected.value or "{}").get("managed_validator_id") == row.id:
                    selected.value = "{}"
            row.updated_at = datetime.now(timezone.utc)
            op.finished_at = datetime.now(timezone.utc)
            db.commit()


def run_selftest(db, row, op, release):
    declaration, artifact = selftest_request(release)
    def progress(_result):
        op.phase = "SELF_TEST"
        db.commit()
    def cancelled():
        db.refresh(op)
        return op.cancel_requested
    try:
        result = validator_client.validate(row.configuration, declaration,
            progress_callback=progress, artifact_path=artifact, cancel_requested=cancelled)
    except TimeoutError:
        raise SelfTestError("Self-test timed out waiting for a terminal result; verify sandbox cleanup before retrying.") from None
    except Exception:
        raise SelfTestError("Self-test API exchange failed before a usable result was received; check validator connectivity and protocol compatibility.") from None
    row.last_self_test = {key: result.get(key) for key in (
        "status", "request_id", "reason_category", "cleanup_status", "helm_result", "resource_summary", "completed_at")}
    db.commit()
    assert_selftest(result)
    row.status = "HEALTHY"


async def form(request, auth):
    from .main import check_csrf
    value = await request.form()
    check_csrf(auth, str(value.get("csrf_token", "")))
    if any(not isinstance(item, str) or len(item) > 32768 for item in value.values()):
        raise HTTPException(422, "Invalid validator form")
    return dict(value)


@router.get("/admin/validators")
def page(request: Request, auth=Depends(admin), db=Depends(get_db)):
    from .main import templates, page_context
    rows = db.scalars(select(ManagedValidator).order_by(ManagedValidator.name)).all()
    return templates.TemplateResponse(request, "validators.html", page_context(auth,
        validators=[public_record(db, row) for row in rows], image_readiness=readiness(),
        validator_management_allowed=True))


@router.get("/api/frontend/settings/validators")
def list_validators(auth=Depends(admin), db=Depends(get_db)):
    return {"validators": [public_record(db, row) for row in db.scalars(
        select(ManagedValidator).order_by(ManagedValidator.name))], "image_readiness": readiness()}


@router.post("/api/frontend/settings/validators")
async def add(request: Request, auth=Depends(admin), db=Depends(get_db)):
    values = await form(request, auth)
    try:
        target = validate_target(values.get("host", ""), values.get("ssh_port", "22"),
            values.get("ssh_username", "ubuntu"), values.get("api_port", "8443"))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    name = values.get("name", "").strip()
    if not name or len(name) > 120:
        raise HTTPException(422, "Validator name must be 1Ã¢â‚¬â€œ120 characters")
    row = ManagedValidator(id=uuid.uuid4().hex, name=name, host=target["host"],
        ssh_port=target["ssh_port"], ssh_username=target["username"], api_port=target["api_port"])
    db.add(row)
    record_audit(db, auth, "validator.created", "managed_validator", row.id)
    db.commit()
    return {"validator": public_record(db, row)}


@router.get("/api/frontend/settings/validators/{validator_id}")
def details(validator_id: str, auth=Depends(admin), db=Depends(get_db)):
    row = db.get(ManagedValidator, validator_id)
    if not row:
        raise HTTPException(404, "Validator not found")
    return {"validator": public_record(db, row)}


@router.post("/api/frontend/settings/validators/{validator_id}/{action}")
async def operate(validator_id: str, action: str, request: Request, auth=Depends(admin), db=Depends(get_db)):
    values = await form(request, auth)
    row = db.get(ManagedValidator, validator_id)
    if not row:
        raise HTTPException(404, "Validator not found")
    if action not in {"discover", "confirm", "preflight", "provision", "rotate", "test", "self-test", "cancel", "remove", "select"}:
        raise HTTPException(404, "Unknown validator action")
    if action == "cancel":
        op = db.get(ManagedValidatorOperation, row.active_operation_id) if row.active_operation_id else None
        if not op or values.get("operation_id", op.id) != op.id:
            raise HTTPException(409, "No matching active operation")
        op.cancel_requested = True
    elif row.active_operation_id:
        raise HTTPException(409, "Another operation is active")
    elif action == "discover":
        target = validate_target(row.host, row.ssh_port, row.ssh_username, row.api_port)
        bootstrap = SSHBootstrap(target, {})
        try:
            discovered = bootstrap.discover_fingerprint()
        except BootstrapError as exc:
            raise HTTPException(422, str(exc)) from None
        if discovered != row.fingerprint:
            row.fingerprint_confirmed = False
        row.fingerprint = discovered
    elif action == "confirm":
        if not row.fingerprint or values.get("fingerprint") != row.fingerprint:
            raise HTTPException(422, "Confirm the discovered SSH fingerprint exactly")
        row.fingerprint_confirmed = True
    elif action == "select":
        if row.status != "HEALTHY":
            raise HTTPException(409, "Only a runtime-verified HEALTHY validator can be selected")
        try:
            health_checked(row.configuration, row.id)
        except Exception:
            raise HTTPException(409, "Selected validator is not currently healthy") from None
        from .main import _set_config_value
        _set_config_value(db, auth, "validator_configuration", json.dumps(
            row.configuration | {"managed_validator_id": row.id}), None)
    else:
        if not row.fingerprint_confirmed:
            raise HTTPException(409, "Confirm the host SSH fingerprint first")
        if action in ("test", "self-test") and not row.configuration:
            raise HTTPException(409, "Provision the validator first")
        acknowledgments = {key: values.get(key) in ("true", "on", "1") for key in ("dedicated_host", "resource_warnings")}
        if action in ("provision", "rotate") and not acknowledgments["dedicated_host"]:
            raise HTTPException(422, "Acknowledge dedicated-host root-equivalent Docker socket access")
        credentials = {key: values.get(key, "") for key in (
            "auth_method", "password", "private_key", "passphrase", "sudo_password")}
        if action in ("provision", "rotate"):
            if not readiness()["ready"]:
                raise HTTPException(409, "Verified local release is unavailable")
        if not WORKER_SLOTS.acquire(blocking=False):
            credentials.clear()
            raise HTTPException(503, "HQ already has two active validator operations; retry shortly")
        try:
            op = claim_operation(db, row, action)
        except Exception:
            credentials.clear()
            WORKER_SLOTS.release()
            raise
        queued_validator_id, queued_operation_id = row.id, op.id
        def execute():
            try:
                run_operation(queued_validator_id, queued_operation_id, credentials, acknowledgments)
            finally:
                WORKER_SLOTS.release()
        try:
            WORKERS.submit(execute)
        except Exception:
            WORKER_SLOTS.release()
            credentials.clear()
            row.active_operation_id = None
            op.status, op.error = "FAILED", "HQ operation queue is unavailable"
            op.finished_at = datetime.now(timezone.utc)
            db.commit()
            raise HTTPException(503, "HQ operation queue is unavailable") from None
    record_audit(db, auth, "validator." + action, "managed_validator", row.id)
    db.commit()
    return {"validator": public_record(db, row)}


def select_configuration(db, manual_configuration, validation_type):
    """Dispatch only to a healthy managed runner with a verified self-test."""
    now = datetime.now(timezone.utc)
    candidates = []
    for row in db.scalars(select(ManagedValidator).where(ManagedValidator.enabled.is_(True), ManagedValidator.status == "HEALTHY")):
        if row.active_operation_id or not row.configuration or row.last_self_test.get("status") != "VERIFIED":
            continue
        try:
            expiry = datetime.fromisoformat(row.certificate["expires_at"]).replace(tzinfo=timezone.utc)
            contact = row.last_contact_at.replace(tzinfo=timezone.utc) if row.last_contact_at else None
            health = row.last_health or {}
            if expiry <= now or contact is None or (now - contact).total_seconds() > 120:
                continue
            supported_types = health.get("validation_types")
            # Existing v2 runners predate capability advertisement. Respect an
            # explicit list, including an empty one, when the runner supplies it.
            if "validation_types" not in health:
                protocols = health.get("request_schema_versions", health.get("protocol_versions", []))
                supported_types = ["helm-chart", "oci"] if "cats.validation/v2" in protocols else []
            if not health.get("ready") or validation_type not in (supported_types or []):
                continue
            load, capacity = int(health.get("active_jobs", 0)), int(health.get("max_jobs", 1))
            if load >= capacity:
                continue
            candidates.append((load, row.id, row))
        except (KeyError, ValueError, TypeError):
            continue
    if candidates:
        row = min(candidates, key=lambda item: item[:2])[2]
        return dict(row.configuration, managed_validator_id=row.id)
    return {}


def maintenance():
    with SessionLocal() as db:
        for row in db.scalars(select(ManagedValidator).where(ManagedValidator.status.in_(["HEALTHY", "DEGRADED"]))):
            if row.active_operation_id or not row.configuration:
                continue
            try:
                row.last_health = health_checked(row.configuration, row.id)
                row.last_contact_at = datetime.now(timezone.utc)
                expiry = datetime.fromisoformat(row.certificate["expires_at"]).replace(tzinfo=timezone.utc)
                row.status = "HEALTHY" if expiry > datetime.now(timezone.utc) and row.last_self_test.get("status") == "VERIFIED" else "DEGRADED"
            except Exception:
                row.status = "DEGRADED"
                clear_selection(db, row.id)
        db.commit()
