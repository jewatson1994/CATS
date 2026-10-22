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
    result = worker.cancel_patch_job("orphan")
    assert result["status"] == "running"
    assert result["cancellation_requested"] is True
    assert (root / "cancel.requested").is_file()
    assert worker.cancel_patch_job("orphan")["cancellation_requested"] is True
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


def test_interrupted_admission_cannot_overwrite_inputs(isolated, monkeypatch):
    root = isolated / "reserved"
    root.mkdir()
    (root / "execution.claim").write_text("reserved")
    config = root / "job-config.json"
    config.write_text("original inputs")
    def unexpected_spawn(*args, **kwargs):
        pytest.fail("reserved execution must not start another process")
    monkeypatch.setattr(worker.subprocess, "Popen", unexpected_spawn)
    with pytest.raises(HTTPException) as exc:
        worker.start_patch_job("reserved", {"config": {"job_id": "reserved"}})
    assert exc.value.status_code == 409
    assert config.read_text() == "original inputs"
    assert not (root / "output" / "patch-state.json").exists()


def test_independent_processes_admit_only_one_execution(tmp_path):
    import os
    import subprocess
    import sys

    script = """
import os
import time
from pathlib import Path
from types import SimpleNamespace
from fastapi import HTTPException
from app import patch_service as worker
worker.JOB_ROOT = Path(os.environ["ADMISSION_ROOT"])
worker.TOKEN = ""
worker.threading.Thread = lambda **kw: SimpleNamespace(start=lambda: None)
def spawn(*args, **kwargs):
    with (worker.JOB_ROOT / "spawns").open("a") as log:
        log.write("spawn\\n")
    return SimpleNamespace(poll=lambda: None)
worker.subprocess.Popen = spawn
while not (worker.JOB_ROOT / "go").exists():
    time.sleep(0.01)
try:
    worker.start_patch_job("shared", {"config": {"job_id": "shared"}})
    print("admitted")
except HTTPException as exc:
    print(exc.status_code)
"""
    env = dict(os.environ, ADMISSION_ROOT=str(tmp_path))
    processes = [subprocess.Popen([sys.executable, "-c", script], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(4)]
    try:
        (tmp_path / "go").touch()
        results = [process.communicate(timeout=30) for process in processes]
        assert all(process.returncode == 0 for process in processes), results
        assert sorted(stdout.strip() for stdout, _ in results) == ["409", "409", "409", "admitted"]
        assert (tmp_path / "spawns").read_text().count("spawn") == 1
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


def test_execution_lock_excludes_duplicate_and_releases_on_process_termination(tmp_path):
    import os
    import subprocess
    import sys
    import time
    from app.patch_ownership import execution_lock, ExecutionAlreadyOwned
    lock = tmp_path / "execution.lock"
    ready = tmp_path / "ready"
    script = "from pathlib import Path; import sys,time; from app.patch_ownership import execution_lock; lock=execution_lock(Path(sys.argv[1])); lock.__enter__(); Path(sys.argv[2]).touch(); time.sleep(60)"
    # Use the interpreter directly: Windows venv launchers spawn another process.
    interpreter = getattr(sys, "_base_executable", sys.executable)
    worker = subprocess.Popen([interpreter, "-c", script, str(lock), str(ready)], env=dict(os.environ))
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < deadline:
            assert worker.poll() is None
            time.sleep(0.02)
        assert ready.exists()
        with pytest.raises(ExecutionAlreadyOwned):
            with execution_lock(lock):
                pytest.fail("duplicate ownership")
    finally:
        worker.kill()
        worker.wait(timeout=10)
    with execution_lock(lock):
        assert lock.exists()


@pytest.mark.parametrize("status,code", [("complete", 0), ("completed", 0), ("failed", 2), ("cancelled", 2)])
def test_worker_terminal_attempt_is_not_reexecuted(tmp_path, monkeypatch, status, code):
    from app import patch_worker
    import json
    import sys
    state = tmp_path / "patch-state.json"
    state.write_text(json.dumps({"status": status}))
    monkeypatch.setattr(sys, "argv", ["patch_worker", str(tmp_path / "missing-config"), str(tmp_path)])
    monkeypatch.setattr(patch_worker, "execute", lambda: pytest.fail("terminal attempt replayed"))
    assert patch_worker.main() == code
    assert json.loads(state.read_text()) == {"status": status}


def test_manifest_metadata_preserves_cancellation():
    from app.patch_worker import retained_manifest_metadata, PatchCancelled
    def cancelled(command):
        raise PatchCancelled()
    with pytest.raises(PatchCancelled):
        retained_manifest_metadata(cancelled, "registry/image@sha256:" + "a" * 64)


def test_real_patch_worker_kill_and_supervisor_restart(tmp_path):
    """Run production patch_worker; only its external Docker command is controlled."""
    import os
    import signal
    import subprocess
    import sys
    import time
    from pathlib import Path

    root = tmp_path / "jobs" / "realworker"
    output = root / "output"
    output.mkdir(parents=True)
    config = root / "job-config.json"
    config.write_text(json.dumps({"job_id": "realworker", "source_image": "test/image:latest", "source_mode": "oci"}))
    state = output / "patch-state.json"
    state.write_text(json.dumps({"status": "running", "phase": "queued"}))
    (root / "execution.claim").write_text("realworker")
    commands = tmp_path / "commands"
    commands.mkdir()
    if os.name == "nt":
        compiler = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        if not compiler.exists():
            pytest.skip("Windows controlled command fixture requires .NET Framework compiler")
        source = commands / "Docker.cs"
        source.write_text("class Docker { static void Main() { System.Threading.Thread.Sleep(60000); } }")
        subprocess.run([str(compiler), "/nologo", "/out:" + str(commands / "docker.exe"), str(source)],
                       check=True, capture_output=True)
    else:
        docker = commands / "docker"
        docker.write_text("#!/bin/sh\nsleep 60\n")
        docker.chmod(0o755)
    env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"],
               PYTHONPATH=os.pathsep.join(sys.path), CATS_PATCH_JOB_ROOT=str(root.parent),
               CATS_PATCH_CLEAN_IMAGES="false", CATS_PATCH_WORKER_TOKEN="")
    interpreter = getattr(sys, "_base_executable", sys.executable)
    process = subprocess.Popen([interpreter, "-m", "app.patch_worker", str(config), str(output)], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    def restarted_status():
        result = subprocess.run([interpreter, "-c", "import json; from app.patch_service import patch_job_status; print(json.dumps(patch_job_status('realworker')))"],
                                env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, process.communicate()
            if json.loads(state.read_text()).get("phase") == "acquiring_image":
                break
            time.sleep(0.02)
        else:
            pytest.fail("Production worker did not reach image acquisition")
        assert restarted_status()["status"] == "running"
        # Kill the production worker and its controlled command, without its
        # supervisor watcher, exactly the orphan condition being recovered.
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=True)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        recovered = restarted_status()
        assert recovered["status"] == "failed"
        assert "stopped" in recovered["error"]
        assert not config.exists()
        before = state.read_bytes()
        replay = subprocess.run([interpreter, "-m", "app.patch_worker", str(config), str(output)],
                                env=env, capture_output=True, timeout=30)
        assert replay.returncode == 2
        assert state.read_bytes() == before
        assert not (output / "patch-result.json").exists()
    finally:
        if process.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)



@pytest.mark.parametrize("status", ["complete", "completed", "failed", "cancelled"])
def test_restarted_get_preserves_terminal_state(isolated, status):
    root = isolated / "retained" / "output"
    root.mkdir(parents=True)
    state = root / "patch-state.json"
    original = json.dumps({"status": status, "evidence": "immutable"})
    state.write_text(original)
    (root / "execution.lock").touch()
    assert worker.patch_job_status("retained")["status"] == status
    assert state.read_text() == original


def test_restarted_get_does_not_guess_before_worker_has_lock(isolated):
    root = isolated / "admitting" / "output"
    root.mkdir(parents=True)
    state = root / "patch-state.json"
    original = json.dumps({"status": "running", "phase": "queued"})
    state.write_text(original)
    assert worker.patch_job_status("admitting")["status"] == "running"
    assert state.read_text() == original
