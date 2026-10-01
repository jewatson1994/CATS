"""Isolated validation worker API. Launch only through validator_server.py (mTLS)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import re
import logging
import asyncio

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .deployment_validation import (CommandResult, KindDeploymentValidator,
    ValidationArtifact, ValidationConfig, cleanup_stale_clusters, validation_names)
from .validator_protocol import SCHEMA_VERSION, validate_package, strict_json_loads
from .validator_settings import fingerprints, execution_settings


app = FastAPI(title="CATS Deployment Validation Sandbox", version="1.0")
STATE_DIR = Path(os.getenv("CATS_VALIDATOR_STATE_DIR", str(Path(tempfile.gettempdir()) / "cats-validator")))
if STATE_DIR.is_symlink():
    raise RuntimeError("Validator state directory cannot be a symlink")
STATE_DIR.mkdir(parents=True, exist_ok=True)
if os.name != "nt":
    if STATE_DIR.stat().st_uid != os.geteuid():
        raise RuntimeError("Validator state directory must belong to the worker")
    os.chmod(STATE_DIR, 0o700)
MAX_JOBS = max(1, min(int(os.getenv("CATS_VALIDATOR_MAX_JOBS", "1")), 16))
MAX_REQUEST_BYTES = int(os.getenv("CATS_VALIDATOR_MAX_REQUEST_BYTES", str(16 * 1024 * 1024)))
MAX_OUTPUT_BYTES = int(os.getenv("CATS_VALIDATOR_MAX_OUTPUT_BYTES", str(1024 * 1024)))
MAX_TIMEOUT = int(os.getenv("CATS_VALIDATOR_MAX_TIMEOUT", "600"))
MAX_RECORDS = int(os.getenv("CATS_VALIDATOR_MAX_RECORDS", "1000"))
if not (1024 <= MAX_REQUEST_BYTES <= 100 * 1024 * 1024 and
        4096 <= MAX_OUTPUT_BYTES <= 8 * 1024 * 1024 and 30 <= MAX_TIMEOUT <= 3600 and
        1 <= MAX_RECORDS <= 10000):
    raise RuntimeError("Validator resource limits are outside supported bounds")
UPLOAD_SLOTS = asyncio.Semaphore(MAX_JOBS)
logger = logging.getLogger("cats.validator.audit")
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_JOBS, thread_name_prefix="cats-validator")
LOCK = threading.Lock()
JOBS: dict[str, dict] = {}
RUNNING: set[str] = set()
STATE_LOCK = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _persist(record: dict) -> None:
    path = STATE_DIR / f"{record['validation_id']}.json"
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=STATE_DIR, delete=False) as stream:
        os.chmod(stream.name, 0o600)
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
        staged = Path(stream.name)
    os.replace(staged, path)


def _update(job_id: str, **values) -> None:
    with LOCK:
        record = JOBS[job_id]
        record.update(values)
        _persist(record)
        logger.info("validation job=%s client=%s status=%s phase=%s", job_id,
                    record.get("client_identity", "unknown"), record.get("status"), record.get("phase"))


def _safe_result(result: dict) -> dict:
    # The engine may collect Helm output or Kubernetes event messages. Keep
    # those out of this API until they have a dedicated secret-redaction path.
    allowed = ("status", "phase", "reason_category", "helm_result", "resource_summary",
               "cleanup_status", "duration_seconds", "cluster_name", "namespace")
    safe = {key: result.get(key) for key in allowed}
    if safe.get("status") == "PARTIALLY_VERIFIED":
        environmental = {"UNSUPPORTED_LOAD_BALANCER", "UNSUPPORTED_INGRESS", "MISSING_STORAGE_CLASS", "EXTERNAL_DEPENDENCY"}
        safe["status"] = "ERROR" if safe.get("reason_category") in environmental else "FAILED"
    elif safe.get("status") == "COULD_NOT_VALIDATE":
        safe["status"] = "ERROR"
    helm = safe.get("helm_result") or {}
    safe["helm_result"] = {key: helm.get(key) for key in ("template", "install", "release_status", "rendered_resource_count", "execution_mode", "helm_release_verified")}
    safe["reason"] = "Validation outcome: " + str(result.get("reason_category") or result.get("status") or "unknown")
    category = result.get("reason_category")
    safe["outcome"] = ("POLICY_REJECTED" if category == "SECURITY_POLICY_VIOLATION" else
        "TIMEOUT" if category == "WORKLOAD_TIMEOUT" else
        "SUCCESS" if safe.get("status") == "VERIFIED" else
        "DEPLOYMENT_FAILED" if safe.get("status") == "FAILED" else "INFRASTRUCTURE_ERROR")
    # Retain actionable field/rule evidence, never submitted values or logs.
    safe["policy_violations"] = [{key: str(row[key])[:160] for key in
        ("rule_id", "rule_name", "kind", "field_path") if key in row}
        for row in (result.get("security_policy_violations") or [])[:100] if isinstance(row, dict)]
    return safe


def _runner(job_id: str, current_phase: list[str]):
    def run(command, *, timeout, env=None):
        command_env = dict(env or {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ})
        ca_file = STATE_DIR / "ca-bundle.pem"
        trust = str(ca_file) if ca_file.is_file() and not ca_file.is_symlink() else os.getenv("SSL_CERT_FILE", "")
        if trust:
            command_env.update(SSL_CERT_FILE=trust, REQUESTS_CA_BUNDLE=trust, CURL_CA_BUNDLE=trust)
        process = subprocess.Popen(list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=command_env,
            start_new_session=os.name != "nt")
        buffers = [bytearray(), bytearray()]
        output_lock = threading.Lock()
        overflow = threading.Event()
        def read_output(stream, index):
            try:
                while chunk := stream.read(4096):
                    with output_lock:
                        remaining = MAX_OUTPUT_BYTES - sum(map(len, buffers))
                        buffers[index].extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            overflow.set()
            finally:
                stream.close()
        readers = [threading.Thread(target=read_output, args=(stream, index), daemon=True)
                   for index, stream in enumerate((process.stdout, process.stderr))]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        cancelled = timed_out = False
        while process.poll() is None:
            with LOCK:
                cancelled = JOBS[job_id].get("cancel_requested", False) and current_phase[0] != "CLEANING_UP"
            timed_out = time.monotonic() > deadline
            if overflow.is_set() or cancelled or timed_out:
                try:
                    if os.name != "nt":
                        import signal
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                break
            time.sleep(0.05)
        for reader in readers:
            reader.join(timeout=1)
        # A child can retain the pipes after its parent exits. Do not let it
        # survive the bounded command or accumulate background drain threads.
        if any(reader.is_alive() for reader in readers) and os.name != "nt":
            import signal
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for reader in readers:
                reader.join(timeout=1)
            overflow.set()
        return CommandResult(125 if overflow.is_set() else 130 if cancelled else 124 if timed_out else process.returncode or 0,
            *(buffer.decode("utf-8", "replace") for buffer in buffers))
    return run


def _execute(job_id: str, package: dict) -> None:
    with LOCK:
        if JOBS[job_id].get("cancel_requested"):
            JOBS[job_id].update(status="CANCELLED", phase="COMPLETE", completed_at=_now(),
                result={"status": "CANCELLED", "outcome": "CANCELLED", "reason_category": "CANCELLED", "cleanup_status": "NOT_REQUIRED"})
            _persist(JOBS[job_id]); return
        RUNNING.add(job_id)
    _update(job_id, status="RUNNING", phase="PREFLIGHT", started_at=_now())
    current_phase = ["PREFLIGHT"]
    try:
        artifact = package["artifact"]
        config = ValidationConfig.from_env()
        settings = execution_settings()
        config.strict_sandbox_policy = settings["execution_mode"] == "strict"
        config.permissive_workloads = not config.strict_sandbox_policy
        config.allow_network_egress = False if config.strict_sandbox_policy else settings["allow_network_egress"]
        if settings["node_image"]:
            config.kind_node_image = settings["node_image"]
        config.workspace_root = str(STATE_DIR / "workspaces")
        config.total_timeout_seconds = min(MAX_TIMEOUT, package["manifest"]["timeout_seconds"])
        config.require_local_images = True if config.strict_sandbox_policy else settings["require_local_images"]
        def progress(phase: str) -> None:
            current_phase[0] = phase
            _update(job_id, phase=phase)
        result = KindDeploymentValidator(config, runner=_runner(job_id, current_phase)).validate_artifact(
            ValidationArtifact(source_files=artifact["source_files"], values_files=artifact.get("values_files") or [],
                declared_resources=artifact.get("declared_resources") or [], job_id=job_id,
                artifact_type=artifact.get("artifact_type") or "ORIGINAL",
                reference=artifact.get("reference")), progress_callback=progress)
        with LOCK:
            cancelled = JOBS[job_id].get("cancel_requested", False)
        safe = _safe_result(result)
        if cancelled:
            safe["status"] = "CANCELLED"
            safe["outcome"] = "CANCELLED"
        _update(job_id, status=safe["status"], phase="COMPLETE", completed_at=_now(), result=safe)
    except Exception:
        _update(job_id, status="ERROR", phase="COMPLETE", completed_at=_now(),
            result={"status": "ERROR", "reason_category": "VALIDATOR_ERROR", "cleanup_status": "FAILED"})
    finally:
        with LOCK:
            RUNNING.discard(job_id)


@app.middleware("http")
async def require_tls(request: Request, call_next):
    identity = request.scope.get("validator_peer_sha256")
    allowed = {item.strip().lower().replace(":", "") for item in
               fingerprints().split(",") if item.strip()}
    if request.url.scheme != "https" or not identity or identity not in allowed:
        return JSONResponse({"detail": "mTLS is required"}, status_code=403)
    request.state.client_identity = identity
    return await call_next(request)


@app.on_event("startup")
def recover():
    global STATE_LOCK
    if os.name == "posix" and STATE_LOCK is None:
        import fcntl
        lock_path = STATE_DIR / ".worker.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(descriptor)
            raise RuntimeError("Only one worker may own the validator state directory")
        STATE_LOCK = descriptor
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    workspace = STATE_DIR / "workspaces"
    if workspace.is_symlink():
        raise RuntimeError("Validator workspace directory cannot be a symlink")
    workspace.mkdir(mode=0o700, exist_ok=True)
    for path in STATE_DIR.glob("*.json"):
        try:
            if path.is_symlink() or not re.fullmatch(r"[0-9a-f]{32}\.json", path.name) or path.stat().st_size > MAX_OUTPUT_BYTES:
                continue
            if len(JOBS) >= MAX_RECORDS:
                raise RuntimeError("Validator state capacity exceeded; archive completed records")
            record = strict_json_loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict) or record.get("validation_id") != path.stem:
                continue
            if record.get("status") in {"QUEUED", "RUNNING"}:
                config = ValidationConfig.from_env()
                config.strict_sandbox_policy = True
                cluster, _ = validation_names(config, record["validation_id"])
                cleanup = cleanup_stale_clusters([cluster], config=config)
                workspace_failed = False
                for candidate in workspace.glob(f"cats-deployment-{path.stem}-*"):
                    if candidate.is_symlink() or candidate.resolve().parent != workspace.resolve():
                        workspace_failed = True
                        continue
                    try:
                        shutil.rmtree(candidate)
                    except OSError:
                        workspace_failed = True
                record.update(status="ERROR", phase="COMPLETE", completed_at=_now(),
                    result={"status": "ERROR", "reason_category": "WORKER_RESTARTED",
                            "cleanup_status": "FAILED" if cleanup.get("failed") or workspace_failed else "COMPLETE"})
                _persist(record)
            JOBS[record["validation_id"]] = record
        except (OSError, ValueError, KeyError):
            continue


@app.on_event("shutdown")
def release_state_lock():
    global STATE_LOCK
    if STATE_LOCK is not None:
        os.close(STATE_LOCK)
        STATE_LOCK = None


@app.get("/health")
def health():
    required = {name: bool(shutil.which(name)) for name in ("docker", "kind", "helm", "kubectl")}
    versions = {}
    for name, arguments in (("kind", ["version"]), ("helm", ["version", "--short"]),
                            ("kubectl", ["version", "--client"])):
        if required[name]:
            try:
                completed = subprocess.run([name, *arguments], capture_output=True, text=True, timeout=3)
                versions[name] = completed.stdout.strip()[:160] if completed.returncode == 0 else "unavailable"
            except (OSError, subprocess.TimeoutExpired):
                versions[name] = "unavailable"
    try:
        runtime = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=3) if required["docker"] else None
        runtime_ready = bool(runtime and runtime.returncode == 0 and
                             int(runtime.stdout.strip().split(".")[0]) >= (28 if execution_settings()["execution_mode"] == "strict" else 1))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        runtime_ready = False
    free_bytes = shutil.disk_usage(STATE_DIR).free
    try:
        minimum_disk = max(0, int(os.getenv("CATS_VALIDATOR_MIN_DISK_BYTES", str(5 * 1024 ** 3))))
    except ValueError:
        minimum_disk = 5 * 1024 ** 3
    return {"schema_version": SCHEMA_VERSION, "version": "1.0",
            "ready": all(required.values()) and runtime_ready and free_bytes >= minimum_disk,
            "capabilities": required, "versions": versions, "container_runtime_ready": runtime_ready,
            "disk_free_bytes": free_bytes, "active_jobs": len(RUNNING), "max_jobs": MAX_JOBS, "checked_at": _now()}


@app.post("/api/v1/validations", status_code=202)
async def submit(request: Request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, detail="Expected application/json")
    try:
        length = int(request.headers.get("content-length", "0"))
    except ValueError:
        raise HTTPException(400, detail="Invalid Content-Length")
    if length < 0 or length > MAX_REQUEST_BYTES:
        raise HTTPException(413, detail="Validation package is too large")
    if UPLOAD_SLOTS.locked():
        raise HTTPException(429, detail="Validator upload capacity is full")
    async with UPLOAD_SLOTS:
        body = bytearray()
        try:
            async with asyncio.timeout(30):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > MAX_REQUEST_BYTES:
                        raise HTTPException(413, detail="Validation package is too large")
                    body.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, detail="Validation upload timed out")
    try:
        package = validate_package(strict_json_loads(body), max_bytes=MAX_REQUEST_BYTES)
    except (ValueError, TypeError, RecursionError) as exc:
        raise HTTPException(422, detail="Invalid validation package") from exc
    unsupported = set(package["manifest"].get("required_capabilities") or []) - {"kind", "helm", "kubectl", "docker"}
    if unsupported:
        raise HTTPException(422, detail="Validation package requires unsupported capabilities")
    with LOCK:
        active = sum(row.get("status") in {"QUEUED", "RUNNING"} for row in JOBS.values())
        if active >= MAX_JOBS * 2 or len(JOBS) >= MAX_RECORDS:
            raise HTTPException(429, detail="Validator capacity is full")
        job_id = uuid.uuid4().hex
        record = {"validation_id": job_id, "schema_version": SCHEMA_VERSION, "status": "QUEUED",
                  "phase": "QUEUED", "created_at": _now(), "cancel_requested": False,
                  "client_identity": request.state.client_identity}
        JOBS[job_id] = record
        _persist(record)
    EXECUTOR.submit(_execute, job_id, package)
    return {"validation_id": job_id, "status": "QUEUED", "schema_version": SCHEMA_VERSION}


@app.get("/api/v1/validations/{job_id}")
def result(job_id: str, request: Request):
    with LOCK:
        record = JOBS.get(job_id)
        if not re.fullmatch(r"[0-9a-f]{32}", job_id) or not record or record.get("client_identity") != request.state.client_identity:
            raise HTTPException(404)
        return dict(record)


@app.post("/api/v1/validations/{job_id}/cancel")
def cancel(job_id: str, request: Request):
    with LOCK:
        record = JOBS.get(job_id)
        if not re.fullmatch(r"[0-9a-f]{32}", job_id) or not record or record.get("client_identity") != request.state.client_identity:
            raise HTTPException(404)
        if record["status"] in {"QUEUED", "RUNNING"}:
            record["cancel_requested"] = True
            _persist(record)
        return {"validation_id": job_id, "status": record["status"], "cancel_requested": record["cancel_requested"]}
