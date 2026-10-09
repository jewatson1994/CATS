from datetime import datetime, timedelta, timezone
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main as portal_main
from app.main import app
from app.patching import initial_patch_stages
from app.frontend import PAGE_MEDIA_TYPE


ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def isolated_scan_history(tmp_path, monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import scan_coordination
    engine = create_engine(f"sqlite:///{(tmp_path / 'elapsed.db').as_posix()}")
    scan_coordination.ScanJob.__table__.create(engine)
    scan_coordination.ScanAttempt.__table__.create(engine)
    from app.models import ServiceImage
    ServiceImage.__table__.create(engine)
    monkeypatch.setattr(scan_coordination, "SessionLocal", sessionmaker(bind=engine, expire_on_commit=False))
    monkeypatch.setattr(portal_main, "PUBLIC_JOBS", scan_coordination.DurableJobs())
    yield
    engine.dispose()


@pytest.fixture
def owner_client(monkeypatch):
    from app.auth import AuthContext
    from app.models import User, UserSession
    owner = AuthContext(User(id=7, username="elapsed-owner", role_assignments=[]),
                        UserSession(id=7, csrf_token="elapsed-csrf"))
    monkeypatch.setitem(app.dependency_overrides, portal_main.optional_user, lambda: owner)
    return TestClient(app)


def _clock(monkeypatch, *values):
    moments = iter(values)
    monkeypatch.setattr(portal_main, "utcnow", lambda: next(moments))


def test_react_job_elapsed_time_contract():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable for the React job lifecycle test")
    frontend = ROOT / "frontend"
    runner = frontend / "node_modules/vitest/vitest.mjs"
    if not runner.exists():
        pytest.skip("Install the pinned frontend dependencies to run React lifecycle tests")
    result = subprocess.run(
        [node, str(runner), "run", "src/hooks/useJob.test.tsx", "--configLoader", "runner"],
        cwd=frontend, capture_output=True, text=True, timeout=45, check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "passed" in result.stdout


def test_scan_timestamps_continue_across_stages_and_freeze(monkeypatch):
    start = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
    _clock(monkeypatch, start, start + timedelta(seconds=10), start + timedelta(seconds=41), start + timedelta(seconds=50))
    job_id = "scan-elapsed-test"
    portal_main.PUBLIC_JOBS[job_id] = {"job_id": job_id, "job_kind": "scan", "status": "queued", "phase": "queued"}
    portal_main._public_job_update(job_id, status="running", phase="prepare_inputs")
    started_at = portal_main.PUBLIC_JOBS[job_id]["started_at"]
    portal_main._public_job_update(job_id, status="running", phase="generate_sboms")
    assert portal_main.PUBLIC_JOBS[job_id]["started_at"] == started_at
    portal_main._public_job_update(job_id, status="complete", phase="report_results")
    finished_at = portal_main.PUBLIC_JOBS[job_id]["finished_at"]
    portal_main._public_job_update(job_id, summary={"results": 1})
    assert portal_main.PUBLIC_JOBS[job_id]["finished_at"] == finished_at

def test_standalone_sbom_and_scan_cancellation_expose_terminal_timestamps(monkeypatch, owner_client):
    start = datetime(2026, 9, 15, 13, 0, tzinfo=timezone.utc)
    _clock(monkeypatch, start, start + timedelta(seconds=9), start + timedelta(seconds=20), start + timedelta(seconds=27))
    sbom_id = "b" * 32
    scan_id = "c" * 32
    portal_main.PUBLIC_JOBS[sbom_id] = {"job_id": sbom_id, "owner_user_id": 7, "job_kind": "sbom", "status": "queued", "phase": "queued"}
    portal_main.PUBLIC_JOBS[scan_id] = {"job_id": scan_id, "owner_user_id": 7, "job_kind": "scan", "status": "queued", "phase": "queued"}
    portal_main._public_job_update(sbom_id, status="running", phase="prepare_inputs")
    portal_main._public_job_update(sbom_id, status="error", phase="worker")
    portal_main._public_job_update(scan_id, status="running", phase="scan_sboms")
    response = owner_client.post(f"/api/public/jobs/{scan_id}/cancel")
    assert response.status_code == 200
    for job_id in (sbom_id, scan_id):
        state = owner_client.get(f"/api/public/jobs/{job_id}").json()
        assert state["started_at"]
        assert state["finished_at"]


def test_patch_timestamps_survive_refresh_and_phase_changes(monkeypatch, tmp_path):
    monkeypatch.setattr(portal_main, "PATCH_JOB_ROOT", tmp_path)
    start = datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)
    _clock(monkeypatch, start, start + timedelta(seconds=11), start + timedelta(seconds=52))
    job_id = "patch-elapsed-test"
    portal_main.PATCH_JOBS[job_id] = {
        "job_id": job_id, "status": "queued", "phase": "queued",
        "output_mode": "download", "stages": initial_patch_stages("download"),
    }
    try:
        portal_main._patch_job_update(job_id, status="running", phase="acquiring_image")
        started_at = portal_main.PATCH_JOBS[job_id]["started_at"]
        portal_main._patch_job_update(job_id, status="running", phase="patching_image")
        assert portal_main.PATCH_JOBS[job_id]["started_at"] == started_at
        portal_main._patch_job_update(job_id, status="failed", phase="scanning_patched")
        finished_at = portal_main.PATCH_JOBS[job_id]["finished_at"]
        portal_main.PATCH_JOBS.pop(job_id)
        restored = portal_main._load_patch_job(job_id)
        assert restored["started_at"] == started_at
        assert restored["finished_at"] == finished_at
    finally:
        portal_main.PATCH_JOBS.pop(job_id, None)


def test_timer_page_exposes_job_scope_and_timestamp_contract(monkeypatch, owner_client):
    job_id = "d" * 32
    portal_main.PUBLIC_JOBS[job_id] = {
        "job_id": job_id, "owner_user_id": 7, "job_kind": "scan", "status": "running", "phase": "generate_sboms",
        "started_at": "2026-09-15T12:00:00+00:00",
    }
    scan = owner_client.get(f"/scan?job_id={job_id}", headers={"Accept": PAGE_MEDIA_TYPE})
    assert scan.status_code == 200
    data = scan.json()["data"]
    assert data["job_id"] == job_id
    assert data["job"]["started_at"] == "2026-09-15T12:00:00+00:00"
    assert data["job"]["status"] == "running"
    assert data["job"]["phase"] == "generate_sboms"
