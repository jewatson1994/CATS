from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import threading
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException

from .patch_ownership import ExecutionAlreadyOwned, execution_lock
from .patching import advance_patch_stages, initial_patch_stages, redact, safe_job_config


app = FastAPI(title="CATS Patch Worker", docs_url=None, redoc_url=None)
JOB_ROOT = Path(os.getenv("CATS_PATCH_JOB_ROOT", str(Path(tempfile.gettempdir()) / "cats-patch-jobs")))
JOB_ROOT.mkdir(parents=True, exist_ok=True)
TOKEN = os.getenv("CATS_PATCH_WORKER_TOKEN", "")
PROCESSES: dict[str, subprocess.Popen] = {}
LOCK = threading.Lock()


def _authorize(value: str | None) -> None:
    if TOKEN and value != TOKEN:
        raise HTTPException(status_code=403, detail="Worker authentication failed")


def _job_paths(job_id: str) -> tuple[Path, Path, Path]:
    if not job_id.isalnum() or len(job_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid job identifier")
    root = JOB_ROOT / job_id
    return root, root / "output" / "patch-state.json", root / "output" / "patch-result.json"


def _watch(job_id: str, process: subprocess.Popen, secrets: list[str]) -> None:
    try:
        process.wait()
    finally:
        for index in range(len(secrets)):
            secrets[index] = ""
        with LOCK:
            # A stale watcher must never clean up a newer execution.
            if PROCESSES.get(job_id) is not process:
                return
            root, state_path, _ = _job_paths(job_id)
            try:
                _record_interrupted(state_path)
            finally:
                # Persistence failures must not retain sensitive inputs or a
                # dead process registration. Keep the original error visible.
                shutil.rmtree(root / "input", ignore_errors=True)
                try:
                    (root / "job-config.json").unlink(missing_ok=True)
                finally:
                    PROCESSES.pop(job_id, None)


def _record_interrupted(state_path: Path) -> None:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    if state.get("status") in {"complete", "completed", "failed", "cancelled"}:
        return
    state.update(status="failed", error="Patch worker stopped before producing a result; retry with a new job")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = state_path.with_suffix(".recovery.tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    temporary.replace(state_path)


@app.post("/internal/patch-bindings/prepare")
def prepare_patch_binding(payload: dict, x_cats_worker_token: str | None = Header(None)):
    # Identity must cross an authenticated worker boundary, even on deployments
    # which intentionally permit legacy job endpoints without a shared token.
    if not TOKEN:
        raise HTTPException(status_code=503, detail="Worker binding authentication is not configured")
    _authorize(x_cats_worker_token)
    from .patch_inputs import prepare_binding, default_binding_root
    config = safe_job_config(dict(payload.get("config") or {}))
    if "execution_binding" in config:
        raise HTTPException(status_code=400, detail="Preparation cannot accept an execution binding")
    try:
        prepared = prepare_binding(config, default_binding_root())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(status_code=409, detail="Immutable execution preparation failed") from exc
    return {"prepared": prepared}


@app.delete("/internal/patch-bindings/{binding_id}")
def release_patch_binding(binding_id: str, x_cats_worker_token: str | None = Header(None)):
    if not TOKEN:
        raise HTTPException(status_code=503, detail="Worker binding authentication is not configured")
    _authorize(x_cats_worker_token)
    from .patch_inputs import release_binding, default_binding_root
    try:
        release_binding(binding_id, default_binding_root())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(status_code=409, detail="Execution binding cannot be released") from exc
    return {"released": True}


@app.post("/internal/patch-jobs/{job_id}")
def start_patch_job(job_id: str, payload: dict, x_cats_worker_token: str | None = Header(None)):
    _authorize(x_cats_worker_token)
    root, state_path, _ = _job_paths(job_id)
    output = root / "output"
    output.mkdir(parents=True, exist_ok=True)
    config = safe_job_config(dict(payload.get("config") or {}))
    if config.get("job_id") != job_id:
        raise HTTPException(status_code=400, detail="Job identifier does not match configuration")
    config_path = root / "job-config.json"
    initial_state = {"status": "running", "phase": "queued", "stages": initial_patch_stages(config.get("output_mode", "download"))}

    credentials = dict(payload.get("credentials") or {})
    allowed = {
        "CATS_SIGNING_PRIVATE_KEY", "CATS_SIGNING_PASSWORD",
        "CATS_PATCH_SOURCE_USERNAME", "CATS_PATCH_SOURCE_PASSWORD",
        "CATS_PATCH_DEST_USERNAME", "CATS_PATCH_DEST_PASSWORD",
    }
    credentials = {key: str(value or "") for key, value in credentials.items() if key in allowed}
    secrets = [credentials.get("CATS_PATCH_SOURCE_PASSWORD", ""), credentials.get("CATS_PATCH_DEST_PASSWORD", "")]
    with LOCK:
        if job_id in PROCESSES:
            raise HTTPException(status_code=409, detail="Patch job already has an execution")
        # Reusing an execution directory can pair a stale result with new inputs.
        if state_path.exists():
            raise HTTPException(status_code=409, detail="Patch job already exists; retry with a new job identifier")
        # Exclusive creation coordinates independent API processes and survives
        # restarts. Retain the claim even if initialization or spawning fails:
        # an uncertain execution must never be overwritten by a duplicate POST.
        try:
            with (root / "execution.claim").open("x", encoding="utf-8") as claim:
                claim.write(job_id)
                claim.flush()
                os.fsync(claim.fileno())
        except FileExistsError:
            raise HTTPException(status_code=409, detail="Patch execution is already reserved; inspect the existing job before retrying") from None
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        state_path.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")
        env = dict(os.environ)
        env.update(credentials)
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "app.patch_worker", str(config_path), str(output)],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception:
            try:
                _record_interrupted(state_path)
            finally:
                try:
                    config_path.unlink(missing_ok=True)
                finally:
                    for index in range(len(secrets)):
                        secrets[index] = ""
            raise HTTPException(status_code=503, detail="Patch worker failed to start") from None
        finally:
            credentials.clear()
            env.clear()
        PROCESSES[job_id] = process
    threading.Thread(target=_watch, args=(job_id, process, secrets), daemon=True).start()
    return {"job_id": job_id, **initial_state, "state_available": state_path.exists()}


def _recover_orphan(job_id: str, root: Path, state_path: Path) -> None:
    # Absence from this supervisor's map is not proof of death. Only the
    # worker's process-lifetime lock can fence a restarted supervisor against
    # a surviving worker. No lock file means admission may still be spawning.
    lock_path = state_path.parent / "execution.lock"
    if not lock_path.exists():
        return
    with LOCK:
        if job_id in PROCESSES:
            return
        try:
            with execution_lock(lock_path):
                # Re-read under ownership; completion may have raced this GET.
                _record_interrupted(state_path)
                shutil.rmtree(root / "input", ignore_errors=True)
                (root / "job-config.json").unlink(missing_ok=True)
        except ExecutionAlreadyOwned:
            return


@app.get("/internal/patch-jobs/{job_id}")
def patch_job_status(job_id: str, x_cats_worker_token: str | None = Header(None)):
    _authorize(x_cats_worker_token)
    root, state_path, result_path = _job_paths(job_id)
    _recover_orphan(job_id, root, state_path)
    config = {}
    config_path = JOB_ROOT / job_id / "job-config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            config = {}
    state = {"job_id": job_id, "status": "queued", "phase": "queued", "stages": initial_patch_stages(config.get("output_mode", "download"))}
    if state_path.exists():
        try:
            state.update(json.loads(state_path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    if result_path.exists():
        try:
            state["result"] = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    with LOCK:
        process = PROCESSES.get(job_id)
        if process and process.poll() is not None and state.get("status") not in {"complete", "completed", "failed", "cancelled"}:
            failed_phase = state.get("phase") if state.get("phase") in state.get("stages", {}) else "queued"
            state.update(
                status="failed", phase=failed_phase, failed_stage=failed_phase,
                stages=advance_patch_stages(state.get("stages"), failed_phase, "failed", config.get("output_mode", "download")),
                error="Patch worker stopped before producing a result",
            )
    return state


@app.post("/internal/patch-jobs/{job_id}/cancel")
def cancel_patch_job(job_id: str, x_cats_worker_token: str | None = Header(None)):
    _authorize(x_cats_worker_token)
    _, state_path, _ = _job_paths(job_id)
    with LOCK:
        if not state_path.exists():
            raise HTTPException(status_code=404, detail="Patch job not found")

        def read_state():
            try:
                return json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise HTTPException(status_code=503, detail="Patch state is unavailable") from None

        existing = read_state()
        if existing.get("status") in {"complete", "completed", "failed", "cancelled"}:
            return {"job_id": job_id, **existing}
        process = PROCESSES.get(job_id)
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (AttributeError, ProcessLookupError, PermissionError):
                try:
                    process.terminate()
                except ProcessLookupError:
                    # Exit can race both termination attempts; wait and inspect
                    # retained evidence before deciding the terminal status.
                    pass
                except PermissionError:
                    raise HTTPException(status_code=409, detail="Patch could not be stopped; check its status before retrying") from None
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Do not report cancellation while the worker can still publish.
                raise HTTPException(status_code=409, detail="Patch is still stopping; check its status before retrying") from None
            existing = read_state()
            if existing.get("status") in {"complete", "completed", "failed", "cancelled"}:
                return {"job_id": job_id, **existing}
        elif process is None:
            # After a supervisor restart, absence from this process map does not
            # prove an old execution stopped. Never claim cancellation here.
            (state_path.parent / "cancel.requested").touch(exist_ok=True)
            return {"job_id": job_id, **existing, "cancellation_requested": True,
                    "message": "Cancellation requested; waiting for the patch worker to acknowledge."}
        else:
            # A process which already exited was not cancelled by this request.
            # Preserve a completed result or record the interrupted execution.
            _record_interrupted(state_path)
            return {"job_id": job_id, **read_state()}
        existing.update(status="cancelled")
        temporary = state_path.with_suffix(".cancel.tmp")
        temporary.write_text(json.dumps(existing), encoding="utf-8")
        temporary.replace(state_path)
        return {"job_id": job_id, **existing}


# Configuration verification belongs to the remediation worker, separate from
# runtime SchrÃ¶dinger validation. Each request has a fresh immutable attempt ID.
CANDIDATE_SLOTS = threading.BoundedSemaphore(max(1, int(os.getenv("CATS_CANDIDATE_VERIFICATION_CONCURRENCY", "2"))))
CANDIDATE_PROCESSES: dict[str, subprocess.Popen] = {}


def _candidate_paths(attempt_id: str) -> tuple[Path, Path, Path]:
    if len(attempt_id) != 32 or any(char not in "0123456789abcdef" for char in attempt_id):
        raise HTTPException(status_code=400, detail="Invalid verification attempt")
    root = JOB_ROOT / "candidate-verifications" / attempt_id
    return root, root / "request.json", root / "result.json"


def _candidate_authorize(token: str | None) -> None:
    import hmac
    if not TOKEN or not token or not hmac.compare_digest(token.encode("utf-8"), TOKEN.encode("utf-8")):
        raise HTTPException(status_code=403, detail="Worker authentication failed")


def _watch_candidate(attempt_id: str, process: subprocess.Popen, config: Path) -> None:
    try:
        try:
            process.wait(timeout=max(1, int(os.getenv("CATS_REMEDIATION_VERIFICATION_TIMEOUT", "3600"))))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (AttributeError, ProcessLookupError, PermissionError):
                process.kill()
            process.wait()
    finally:
        config.unlink(missing_ok=True)
        with LOCK:
            CANDIDATE_PROCESSES.pop(attempt_id, None)
        CANDIDATE_SLOTS.release()


@app.post("/internal/candidate-verifications/{attempt_id}")
def start_candidate_verification(attempt_id: str, payload: dict, x_cats_worker_token: str | None = Header(None)):
    from .candidate_worker import validate_request
    _candidate_authorize(x_cats_worker_token)
    root, config, result = _candidate_paths(attempt_id)
    if payload.get("attempt_id") != attempt_id or not isinstance(payload.get("remediation_job_id"), str):
        raise HTTPException(status_code=400, detail="Verification identity mismatch")
    try:
        validate_request(payload)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid verification source") from None
    with LOCK:
        retention_root = JOB_ROOT / "candidate-verifications"
        retained = list(retention_root.iterdir()) if retention_root.exists() else []
        oldest = time.time() - max(60, int(os.getenv("CATS_CANDIDATE_VERIFICATION_RETENTION_SECONDS", "3600")))
        for directory in retained:
            if directory.name not in CANDIDATE_PROCESSES and directory.stat().st_mtime < oldest:
                shutil.rmtree(directory, ignore_errors=True)
        if sum(directory.exists() for directory in retained) >= max(1, int(os.getenv("CATS_CANDIDATE_VERIFICATION_MAX_RETAINED", "128"))):
            raise HTTPException(status_code=503, detail="Verification retention capacity reached")
        if root.exists():
            raise HTTPException(status_code=409, detail="Verification attempt already exists")
        if not CANDIDATE_SLOTS.acquire(blocking=False):
            raise HTTPException(status_code=503, detail="Verification worker is busy")
        try:
            root.mkdir(parents=True, mode=0o700)
            config.write_text(json.dumps(payload), encoding="utf-8")
            process = subprocess.Popen([sys.executable, "-m", "app.candidate_worker", str(config), str(result)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            CANDIDATE_PROCESSES[attempt_id] = process
        except Exception:
            CANDIDATE_SLOTS.release()
            shutil.rmtree(root, ignore_errors=True)
            raise HTTPException(status_code=503, detail="Verification worker failed to start") from None
    threading.Thread(target=_watch_candidate, args=(attempt_id, process, config), daemon=True).start()
    return {"status": "running", "attempt_id": attempt_id}


@app.get("/internal/candidate-verifications/{attempt_id}")
def candidate_verification_status(attempt_id: str, x_cats_worker_token: str | None = Header(None)):
    _candidate_authorize(x_cats_worker_token)
    root, _, result = _candidate_paths(attempt_id)
    if not root.is_dir():
        raise HTTPException(status_code=404, detail="Verification attempt is unavailable")
    if result.is_file():
        try:
            return json.loads(result.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"status": "failed", "attempt_id": attempt_id, "error": "Invalid verification evidence"}
    with LOCK:
        process = CANDIDATE_PROCESSES.get(attempt_id)
        running = process is not None and process.poll() is None
    return {"status": "running" if running else "failed", "attempt_id": attempt_id,
            "error": "" if running else "Verification worker stopped before producing evidence"}


@app.delete("/internal/candidate-verifications/{attempt_id}")
def cleanup_candidate_verification(attempt_id: str, x_cats_worker_token: str | None = Header(None)):
    _candidate_authorize(x_cats_worker_token)
    root, _, _ = _candidate_paths(attempt_id)
    with LOCK:
        process = CANDIDATE_PROCESSES.get(attempt_id)
    if process is not None and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (AttributeError, ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=10)
    shutil.rmtree(root, ignore_errors=True)
    return {"attempt_id": attempt_id, "status": "removed"}
