from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException

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
        root = JOB_ROOT / job_id
        shutil.rmtree(root / "input", ignore_errors=True)
        (root / "job-config.json").unlink(missing_ok=True)
        with LOCK:
            PROCESSES.pop(job_id, None)


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
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    initial_state = {"status": "running", "phase": "queued", "stages": initial_patch_stages(config.get("output_mode", "download"))}
    state_path.write_text(json.dumps(initial_state, indent=2), encoding="utf-8")

    credentials = dict(payload.get("credentials") or {})
    allowed = {
        "CATS_SIGNING_PRIVATE_KEY", "CATS_SIGNING_PASSWORD",
        "CATS_PATCH_SOURCE_USERNAME", "CATS_PATCH_SOURCE_PASSWORD",
        "CATS_PATCH_DEST_USERNAME", "CATS_PATCH_DEST_PASSWORD",
    }
    credentials = {key: str(value or "") for key, value in credentials.items() if key in allowed}
    secrets = [credentials.get("CATS_PATCH_SOURCE_PASSWORD", ""), credentials.get("CATS_PATCH_DEST_PASSWORD", "")]
    with LOCK:
        running = PROCESSES.get(job_id)
        if running and running.poll() is None:
            raise HTTPException(status_code=409, detail="Patch job is already running")
        env = dict(os.environ)
        env.update(credentials)
        process = subprocess.Popen(
            [sys.executable, "-m", "app.patch_worker", str(config_path), str(output)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        credentials.clear()
        PROCESSES[job_id] = process
    threading.Thread(target=_watch, args=(job_id, process, secrets), daemon=True).start()
    return {"job_id": job_id, **initial_state, "state_available": state_path.exists()}


@app.get("/internal/patch-jobs/{job_id}")
def patch_job_status(job_id: str, x_cats_worker_token: str | None = Header(None)):
    _authorize(x_cats_worker_token)
    _, state_path, result_path = _job_paths(job_id)
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
        if process and process.poll() is not None and state.get("status") not in {"complete", "failed", "cancelled"}:
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
    root, _, _ = _job_paths(job_id)
    with LOCK:
        process = PROCESSES.get(job_id)
    if process and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()
    output = root / "output"
    output.mkdir(parents=True, exist_ok=True)
    state_path = output / "patch-state.json"
    existing = {}
    if state_path.exists():
        try:
            existing = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
    state_path.write_text(json.dumps({
        "status": "cancelled", "phase": existing.get("phase", "cancelled"),
        "stages": existing.get("stages") or initial_patch_stages("download"),
    }, indent=2), encoding="utf-8")
    return {"job_id": job_id, "status": "cancelled", "phase": "cancelled"}
