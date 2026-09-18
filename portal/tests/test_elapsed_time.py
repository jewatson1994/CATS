from datetime import datetime, timedelta, timezone
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main as portal_main
from app.main import app
from app.patching import initial_patch_stages


ROOT = Path(__file__).parents[1]


def _clock(monkeypatch, *values):
    moments = iter(values)
    monkeypatch.setattr(portal_main, "utcnow", lambda: next(moments))


def test_shared_elapsed_time_javascript_contract():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable for the dependency-free browser utility test")
    result = subprocess.run(
        [node, str(ROOT / "tests" / "elapsed_time.test.js")],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "elapsed-time tests passed" in result.stdout


def test_scan_timestamps_continue_across_stages_and_freeze(monkeypatch):
    start = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
    _clock(monkeypatch, start, start + timedelta(seconds=10), start + timedelta(seconds=41), start + timedelta(seconds=50))
    job_id = "scan-elapsed-test"
    portal_main.PUBLIC_JOBS[job_id] = {"job_id": job_id, "job_kind": "scan", "status": "queued", "phase": "queued"}
    try:
        portal_main._public_job_update(job_id, status="running", phase="prepare_inputs")
        started_at = portal_main.PUBLIC_JOBS[job_id]["started_at"]
        portal_main._public_job_update(job_id, status="running", phase="generate_sboms")
        assert portal_main.PUBLIC_JOBS[job_id]["started_at"] == started_at
        portal_main._public_job_update(job_id, status="complete", phase="report_results")
        finished_at = portal_main.PUBLIC_JOBS[job_id]["finished_at"]
        portal_main._public_job_update(job_id, summary={"results": 1})
        assert portal_main.PUBLIC_JOBS[job_id]["finished_at"] == finished_at
    finally:
        portal_main.PUBLIC_JOBS.pop(job_id, None)


def test_standalone_sbom_and_scan_cancellation_expose_terminal_timestamps(monkeypatch):
    start = datetime(2026, 9, 15, 13, 0, tzinfo=timezone.utc)
    _clock(monkeypatch, start, start + timedelta(seconds=9), start + timedelta(seconds=20), start + timedelta(seconds=27))
    sbom_id = "sbom-elapsed-test"
    scan_id = "cancel-elapsed-test"
    portal_main.PUBLIC_JOBS[sbom_id] = {"job_id": sbom_id, "job_kind": "sbom", "status": "queued", "phase": "queued"}
    portal_main.PUBLIC_JOBS[scan_id] = {"job_id": scan_id, "job_kind": "scan", "status": "queued", "phase": "queued"}
    try:
        portal_main._public_job_update(sbom_id, status="running", phase="prepare_inputs")
        portal_main._public_job_update(sbom_id, status="error", phase="worker")
        portal_main._public_job_update(scan_id, status="running", phase="scan_sboms")
        response = TestClient(app).post(f"/api/public/jobs/{scan_id}/cancel")
        assert response.status_code == 200
        for job_id in (sbom_id, scan_id):
            state = TestClient(app).get(f"/api/public/jobs/{job_id}").json()
            assert state["started_at"]
            assert state["finished_at"]
    finally:
        portal_main.PUBLIC_JOBS.pop(sbom_id, None)
        portal_main.PUBLIC_JOBS.pop(scan_id, None)


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


def test_timer_ui_is_shared_and_polling_cadence_is_unchanged(monkeypatch):
    job_id = "timer-markup-test"
    portal_main.PUBLIC_JOBS[job_id] = {
        "job_id": job_id, "job_kind": "scan", "status": "running", "phase": "generate_sboms",
        "started_at": "2026-09-15T12:00:00+00:00",
    }
    try:
        scan = TestClient(app).get(f"/scan?job_id={job_id}")
        assert scan.status_code == 200
        assert scan.text.count("data-job-elapsed data-elapsed-time") == 1
        assert "data-started-at=\"2026-09-15T12:00:00+00:00\"" in scan.text
        assert "window.setTimeout(poll, 1500)" in scan.text
        assert "window.setTimeout(poll, 3000)" in scan.text
    finally:
        portal_main.PUBLIC_JOBS.pop(job_id, None)

    patch_template = (ROOT / "app" / "templates" / "patch.html").read_text(encoding="utf-8")
    sbom_template = (ROOT / "app" / "templates" / "self_service.html").read_text(encoding="utf-8")
    public_results_template = (ROOT / "app" / "templates" / "public_results.html").read_text(encoding="utf-8")
    patch_results_template = (ROOT / "app" / "templates" / "patch_results.html").read_text(encoding="utf-8")
    remediation_template = (ROOT / "app" / "templates" / "remediation_report.html").read_text(encoding="utf-8")
    remediation_list_template = (ROOT / "app" / "templates" / "service_remediations.html").read_text(encoding="utf-8")
    assert patch_template.count("data-patch-elapsed") == 2  # selector plus the single element
    assert "setTimeout(poll,1000)" in patch_template
    assert "setTimeout(poll,2500)" in patch_template
    assert sbom_template.count("data-job-elapsed data-elapsed-time") == 1
    assert "CatsElapsedTime.attach" in patch_template and "CatsElapsedTime.attach" in sbom_template
    assert all("data-elapsed-time" in template for template in (
        public_results_template, patch_results_template, remediation_template, remediation_list_template,
    ))
