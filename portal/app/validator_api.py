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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .deployment_validation import (CommandResult, KindDeploymentValidator,
    ValidationArtifact, ValidationConfig, cleanup_stale_clusters, validation_names)
from .validator_protocol import SCHEMA_VERSION, validate_package


app = FastAPI(title="CATS Deployment Validation Sandbox", version="1.0")
STATE_DIR = Path(os.getenv("CATS_VALIDATOR_STATE_DIR", str(Path(tempfile.gettempdir()) / "cats-validator")))
STATE_DIR.mkdir(parents=True, exist_ok=True)
if os.name != "nt":
    os.chmod(STATE_DIR, 0o700)
MAX_JOBS = max(1, min(int(os.getenv("CATS_VALIDATOR_MAX_JOBS", "2")), 16))
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_JOBS, thread_name_prefix="cats-validator")
LOCK = threading.Lock()
JOBS: dict[str, dict] = {}
RUNNING: set[str] = set()


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
    safe["helm_result"] = {key: helm.get(key) for key in ("template", "install", "release_status", "rendered_resource_count")}
    safe["reason"] = "Validation outcome: " + str(result.get("reason_category") or result.get("status") or "unknown")
    return safe


def _runner(job_id: str, current_phase: list[str]):
    def run(command, *, timeout, env=None):
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(list(command), stdout=stdout, stderr=stderr,
                env=dict(env or os.environ), start_new_session=os.name != "nt")
            deadline = time.monotonic() + timeout
            cancelled = False
            while process.poll() is None:
                with LOCK:
                    cancelled = JOBS[job_id].get("cancel_requested", False)
                if (cancelled and current_phase[0] != "CLEANING_UP") or time.monotonic() > deadline:
                    try:
                        if os.name != "nt":
                            import signal
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                    except OSError:
                        process.kill()
                    process.wait()
                    break
                time.sleep(0.25)
            stdout.seek(0); stderr.seek(0)
            return CommandResult(130 if cancelled and current_phase[0] != "CLEANING_UP" else 124 if time.monotonic() > deadline else process.returncode or 0,
                stdout.read(1024 * 1024).decode("utf-8", "replace"), stderr.read(1024 * 1024).decode("utf-8", "replace"))
    return run


def _execute(job_id: str, package: dict) -> None:
    with LOCK:
        if JOBS[job_id].get("cancel_requested"):
            JOBS[job_id].update(status="CANCELLED", phase="COMPLETE", completed_at=_now())
            _persist(JOBS[job_id]); return
        RUNNING.add(job_id)
    _update(job_id, status="RUNNING", phase="PREFLIGHT", started_at=_now())
    current_phase = ["PREFLIGHT"]
    try:
        artifact = package["artifact"]
        config = ValidationConfig.from_env()
        config.total_timeout_seconds = package["manifest"]["timeout_seconds"]
        if config.require_local_images:
            for image in package["manifest"].get("referenced_images") or []:
                check = subprocess.run([config.docker_binary, "image", "inspect", "--", image],
                    capture_output=True, timeout=10)
                if check.returncode:
                    _update(job_id, status="ERROR", phase="COMPLETE", completed_at=_now(),
                        result={"status": "ERROR", "reason_category": "IMAGE_PREFLIGHT_UNAVAILABLE",
                                "cleanup_status": "NOT_REQUIRED"})
                    return
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
        _update(job_id, status=safe["status"], phase="COMPLETE", completed_at=_now(), result=safe)
    except Exception:
        _update(job_id, status="ERROR", phase="COMPLETE", completed_at=_now(),
            result={"status": "ERROR", "reason_category": "VALIDATOR_ERROR", "cleanup_status": "UNKNOWN"})
    finally:
        with LOCK:
            RUNNING.discard(job_id)


@app.middleware("http")
async def require_tls(request: Request, call_next):
    if request.url.scheme != "https":
        return JSONResponse({"detail": "mTLS is required"}, status_code=403)
    return await call_next(request)


@app.on_event("startup")
def recover():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    for path in STATE_DIR.glob("*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("status") in {"QUEUED", "RUNNING"}:
                cluster, _ = validation_names(ValidationConfig.from_env(), record["validation_id"])
                cleanup = cleanup_stale_clusters([cluster])
                record.update(status="ERROR", phase="COMPLETE", completed_at=_now(),
                    result={"status": "ERROR", "reason_category": "WORKER_RESTARTED",
                            "cleanup_status": "FAILED" if cleanup.get("failed") else "COMPLETE"})
                _persist(record)
            JOBS[record["validation_id"]] = record
        except (OSError, ValueError, KeyError):
            continue


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
        runtime_ready = required["docker"] and subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, timeout=3).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
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
    if int(request.headers.get("content-length", "0")) > 110 * 1024 * 1024:
        raise HTTPException(413, detail="Validation package is too large")
    body = await request.body()
    if len(body) > 110 * 1024 * 1024:
        raise HTTPException(413, detail="Validation package is too large")
    try:
        package = validate_package(json.loads(body))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    unsupported = set(package["manifest"].get("required_capabilities") or []) - {"kind", "helm", "kubectl", "docker"}
    if unsupported:
        raise HTTPException(422, detail="Validation package requires unsupported capabilities")
    with LOCK:
        active = sum(row.get("status") in {"QUEUED", "RUNNING"} for row in JOBS.values())
        if active >= MAX_JOBS * 2:
            raise HTTPException(429, detail="Validator capacity is full")
        job_id = uuid.uuid4().hex
        record = {"validation_id": job_id, "schema_version": SCHEMA_VERSION, "status": "QUEUED",
                  "phase": "QUEUED", "created_at": _now(), "cancel_requested": False}
        JOBS[job_id] = record
        _persist(record)
    EXECUTOR.submit(_execute, job_id, package)
    return {"validation_id": job_id, "status": "QUEUED", "schema_version": SCHEMA_VERSION}


@app.get("/api/v1/validations/{job_id}")
def result(job_id: str):
    with LOCK:
        record = JOBS.get(job_id)
        if not record:
            raise HTTPException(404)
        return dict(record)


@app.post("/api/v1/validations/{job_id}/cancel")
def cancel(job_id: str):
    with LOCK:
        record = JOBS.get(job_id)
        if not record:
            raise HTTPException(404)
        if record["status"] in {"QUEUED", "RUNNING"}:
            record["cancel_requested"] = True
            _persist(record)
        return {"validation_id": job_id, "status": record["status"], "cancel_requested": record["cancel_requested"]}
