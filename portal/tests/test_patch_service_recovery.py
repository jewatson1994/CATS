import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from app import patch_service as worker


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(worker, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(worker, "TOKEN", "")
    monkeypatch.setattr(worker, "PROCESSES", {})
    monkeypatch.setattr(worker.threading, "Thread", lambda **kw: SimpleNamespace(start=lambda: None))
    return tmp_path


def test_duplicate_does_not_overwrite_inputs(isolated, monkeypatch):
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **kw: SimpleNamespace(poll=lambda: None))
    worker.start_patch_job("same", {"config": {"job_id": "same", "source_image": "original"}})
    path = isolated / "same" / "job-config.json"
    original = path.read_bytes()
    with pytest.raises(HTTPException) as exc:
        worker.start_patch_job("same", {"config": {"job_id": "same", "source_image": "changed"}})
    assert exc.value.status_code == 409
    assert path.read_bytes() == original


def test_crash_is_persisted_after_watcher_cleanup(isolated):
    root = isolated / "crash"
    (root / "output").mkdir(parents=True)
    state = root / "output" / "patch-state.json"
    state.write_text(json.dumps({"status": "running", "phase": "patch"}))
    process = SimpleNamespace(wait=lambda: 1)
    worker.PROCESSES["crash"] = process
    worker._watch("crash", process, [])
    assert worker.patch_job_status("crash")["status"] == "failed"
    assert json.loads(state.read_text())["status"] == "failed"
    with pytest.raises(HTTPException):
        worker.start_patch_job("crash", {"config": {"job_id": "crash"}})


def test_stale_watcher_cannot_remove_new_execution(isolated):
    root = isolated / "stale"
    root.mkdir()
    config = root / "job-config.json"
    config.write_text("new inputs")
    current = object()
    worker.PROCESSES["stale"] = current
    worker._watch("stale", SimpleNamespace(wait=lambda: 1), [])
    assert worker.PROCESSES["stale"] is current
    assert config.read_text() == "new inputs"


def test_spawn_failure_is_terminal_and_clears_config(isolated, monkeypatch):
    def fail(*a, **kw):
        raise OSError("sensitive detail")
    monkeypatch.setattr(worker.subprocess, "Popen", fail)
    with pytest.raises(HTTPException) as exc:
        worker.start_patch_job("spawn", {"config": {"job_id": "spawn"}})
    assert exc.value.status_code == 503
    assert "sensitive" not in exc.value.detail
    assert worker.patch_job_status("spawn")["status"] == "failed"
    assert not (isolated / "spawn" / "job-config.json").exists()


@pytest.mark.parametrize("status", ["complete", "cancelled", "failed"])
def test_watcher_preserves_terminal_evidence(isolated, status):
    root = isolated / "terminal" / "output"
    root.mkdir(parents=True)
    path = root / "patch-state.json"
    original = json.dumps({"status": status, "evidence": "retained"})
    path.write_text(original)
    process = SimpleNamespace(wait=lambda: 0)
    worker.PROCESSES["terminal"] = process
    worker._watch("terminal", process, [])
    assert path.read_text() == original


@pytest.mark.parametrize("status", ["complete", "failed", "cancelled"])
def test_cancel_preserves_terminal_evidence(isolated, status):
    root = isolated / "terminal" / "output"
    root.mkdir(parents=True)
    path = root / "patch-state.json"
    original = json.dumps({"status": status, "evidence": "retained"})
    path.write_text(original)
    assert worker.cancel_patch_job("terminal")["status"] == status
    assert path.read_text() == original


def test_cancel_does_not_claim_success_for_unowned_execution(isolated):
    root = isolated / "orphan" / "output"
    root.mkdir(parents=True)
    path = root / "patch-state.json"
    original = json.dumps({"status": "running"})
    path.write_text(original)
    with pytest.raises(HTTPException) as exc:
        worker.cancel_patch_job("orphan")
    assert exc.value.status_code == 409
    assert path.read_text() == original


def test_completion_during_cancel_preserves_result(isolated, monkeypatch):
    root = isolated / "race" / "output"
    root.mkdir(parents=True)
    path = root / "patch-state.json"
    path.write_text(json.dumps({"status": "running"}))
    def finish(timeout):
        path.write_text(json.dumps({"status": "complete", "evidence": "retained"}))
    worker.PROCESSES["race"] = SimpleNamespace(pid=123, poll=lambda: None, wait=finish)
    monkeypatch.setattr(worker.os, "killpg", lambda *args: None, raising=False)
    assert worker.cancel_patch_job("race")["status"] == "complete"
    assert json.loads(path.read_text())["evidence"] == "retained"


def test_cancel_records_already_exited_worker_as_failed(isolated):
    root = isolated / "exited" / "output"
    root.mkdir(parents=True)
    path = root / "patch-state.json"
    path.write_text(json.dumps({"status": "running"}))
    worker.PROCESSES["exited"] = SimpleNamespace(poll=lambda: 1)
    assert worker.cancel_patch_job("exited")["status"] == "failed"
    assert json.loads(path.read_text())["status"] == "failed"


def test_exit_during_termination_preserves_completed_evidence(isolated, monkeypatch):
    root = isolated / "exitRace" / "output"
    root.mkdir(parents=True)
    path = root / "patch-state.json"
    path.write_text(json.dumps({"status": "running"}))
    def gone(*args):
        raise ProcessLookupError()
    def finish(timeout):
        path.write_text(json.dumps({"status": "complete", "evidence": "retained"}))
    worker.PROCESSES["exitRace"] = SimpleNamespace(pid=123, poll=lambda: None, terminate=gone, wait=finish)
    monkeypatch.setattr(worker.os, "killpg", gone, raising=False)
    assert worker.cancel_patch_job("exitRace")["status"] == "complete"
    assert json.loads(path.read_text())["evidence"] == "retained"


def test_recovery_write_failure_still_cleans_execution(isolated, monkeypatch):
    root = isolated / "diskfailure"
    (root / "input").mkdir(parents=True)
    (root / "input" / "credentials").write_text("sensitive")
    config = root / "job-config.json"
    config.write_text("inputs")
    process = SimpleNamespace(wait=lambda: 1)
    worker.PROCESSES["diskfailure"] = process
    secrets = ["password"]
    def fail(path):
        raise OSError("disk full")
    monkeypatch.setattr(worker, "_record_interrupted", fail)
    with pytest.raises(OSError, match="disk full"):
        worker._watch("diskfailure", process, secrets)
    assert secrets == [""]
    assert "diskfailure" not in worker.PROCESSES
    assert not config.exists()
    assert not (root / "input").exists()
