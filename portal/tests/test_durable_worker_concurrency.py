"""Bound execution claims and reserve lease capacity under concurrent work."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import signal
import threading
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool
import yaml

from app import durable_jobs
from app.remediation_worker_config import configure


def start_worker(monkeypatch, *, maximum=1, maintenance=None):
    signals, errors = {}, []
    monkeypatch.setattr(durable_jobs.signal, "signal", lambda number, handler: signals.setdefault(number, handler))

    def run():
        try:
            durable_jobs.run_worker(("test",), lambda *_: {}, max_workers=maximum, maintenance=maintenance)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, name="test-dispatcher")
    thread.start()
    return thread, signals, errors


@pytest.mark.parametrize("maximum", [1, 5])
def test_claims_only_free_slots_and_drains_active_jobs_on_shutdown(monkeypatch, maximum):
    claimed, finished, executing_threads = [], [], []
    gate, ready = threading.Event(), threading.Event()
    lock = threading.Lock()

    def claim(*_):
        claimed.append(len(claimed) + 1)
        return claimed[-1]

    def execute(job, _handler):
        with lock:
            executing_threads.append(threading.current_thread().name)
            if len(executing_threads) == maximum:
                ready.set()
        assert gate.wait(10)
        finished.append(job)

    monkeypatch.setattr(durable_jobs, "claim", claim)
    monkeypatch.setattr(durable_jobs, "execute", execute)
    thread, signals, errors = start_worker(monkeypatch, maximum=maximum)
    try:
        assert ready.wait(5), "configured slots did not execute together"
        assert claimed == list(range(1, maximum + 1))
        signals[signal.SIGTERM]()
        assert thread.is_alive(), "shutdown must wait for active jobs"
    finally:
        gate.set()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert sorted(finished) == list(range(1, maximum + 1))
    assert claimed == list(range(1, maximum + 1)), "shutdown claimed additional jobs"
    if maximum == 1:
        assert executing_threads == ["test-dispatcher"], "serial workers must retain existing DB routing"


def test_completed_slot_admits_one_next_job_despite_maintenance_failure(monkeypatch):
    claimed, active, completed, maintenance_calls = [], set(), [], []
    gates = {job: threading.Event() for job in range(1, 8)}
    five_running, sixth_running = threading.Event(), threading.Event()
    lock = threading.Lock()
    peak = 0

    def claim(*_):
        claimed.append(len(claimed) + 1)
        return claimed[-1]

    def execute(job, _handler):
        nonlocal peak
        with lock:
            active.add(job)
            peak = max(peak, len(active))
            if len(active) == 5:
                five_running.set()
            if job == 6:
                sixth_running.set()
        assert gates[job].wait(10)
        with lock:
            active.remove(job)
            completed.append(job)

    def maintenance():
        maintenance_calls.append(True)
        raise RuntimeError("reconciliation unavailable")

    monkeypatch.setattr(durable_jobs, "claim", claim)
    monkeypatch.setattr(durable_jobs, "execute", execute)
    thread, signals, errors = start_worker(monkeypatch, maximum=5, maintenance=maintenance)
    try:
        assert five_running.wait(5)
        assert claimed == [1, 2, 3, 4, 5]
        gates[1].set()
        assert sixth_running.wait(5)
        assert claimed == [1, 2, 3, 4, 5, 6]
        assert peak == 5
        assert len(maintenance_calls) == 1
    finally:
        signals[signal.SIGTERM]()
        for gate in gates.values():
            gate.set()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert sorted(completed) == [1, 2, 3, 4, 5, 6]
    assert claimed == [1, 2, 3, 4, 5, 6]


@pytest.mark.parametrize("value", [0, -1, 33, "5", True])
def test_runner_rejects_unbounded_or_invalid_capacity(value):
    with pytest.raises(ValueError, match="max_workers"):
        durable_jobs.run_worker(("test",), None, max_workers=value)


@pytest.mark.parametrize("workers, expected", [(1, 2), (5, 12), (32, 66)])
def test_worker_pool_is_bounded_and_sized_before_database_import(workers, expected):
    env = {"CATS_REMEDIATION_WORKERS": str(workers)}
    assert configure(env) == workers
    assert env["CATS_DB_BACKGROUND_POOL_SIZE"] == str(expected)
    assert env["CATS_DB_BACKGROUND_MAX_OVERFLOW"] == "0"


def test_serial_default_and_explicit_pool_override():
    env = {}
    assert configure(env) == 1
    assert env["CATS_DB_BACKGROUND_POOL_SIZE"] == "2"
    env = {"CATS_REMEDIATION_WORKERS": "5", "CATS_DB_BACKGROUND_POOL_SIZE": "2",
           "CATS_REMEDIATION_DB_POOL_SIZE": "14"}
    assert configure(env) == 5
    assert env["CATS_DB_BACKGROUND_POOL_SIZE"] == "14"


@pytest.mark.parametrize("env", [
    {"CATS_REMEDIATION_WORKERS": "0"}, {"CATS_REMEDIATION_WORKERS": "33"},
    {"CATS_REMEDIATION_WORKERS": "five"},
    {"CATS_REMEDIATION_WORKERS": "5", "CATS_REMEDIATION_DB_POOL_SIZE": "11"},
    {"CATS_REMEDIATION_WORKERS": "5", "CATS_DB_BACKGROUND_POOL_SIZE": "2"},
    {"CATS_REMEDIATION_DB_POOL_SIZE": "513"}, {"CATS_REMEDIATION_DB_POOL_SIZE": "bad"},
])
def test_invalid_or_undersized_worker_settings_fail_startup(env):
    with pytest.raises(ValueError, match="CATS_REMEDIATION"):
        configure(env)


def test_five_active_jobs_can_renew_leases_while_retaining_sessions(monkeypatch):
    env = {"CATS_REMEDIATION_WORKERS": "5"}
    configure(env)
    engine = create_engine("sqlite://", poolclass=QueuePool, pool_size=int(env["CATS_DB_BACKGROUND_POOL_SIZE"]),
                           max_overflow=0, pool_timeout=0.5, connect_args={"check_same_thread": False})
    holding, release = threading.Barrier(6), threading.Event()
    renewed = {job: threading.Event() for job in range(5)}
    finished = []

    class Context:
        def __init__(self, job, session_factory):
            self.job, self.lost = job, threading.Event()

        def check(self):
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))

        def heartbeat(self):
            self.check()
            renewed[self.job.id].set()

        def finish(self, result=None, **kwargs):
            self.check()
            assert not self.lost.is_set()
            assert not kwargs
            finished.append(self.job.id)

    def handler(_ctx, _payload):
        # Model each handler retaining its domain session and an overlapping
        # nested operation. Heartbeats still need their own connection.
        with engine.connect(), engine.connect():
            holding.wait(timeout=5)
            assert release.wait(10)
        return {"done": True}

    monkeypatch.setattr(durable_jobs, "JobContext", Context)
    monkeypatch.setenv("CATS_JOB_LEASE_SECONDS", "3")
    try:
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(durable_jobs.execute, SimpleNamespace(id=job, payload={}, kind="test", correlation_id=str(job)), handler)
                       for job in range(5)]
            try:
                holding.wait(timeout=5)
                assert engine.pool.checkedout() >= 10
                assert all(event.wait(4) for event in renewed.values()), "a running job lost heartbeat capacity"
            finally:
                release.set()
            for future in futures:
                future.result(timeout=5)
        assert sorted(finished) == list(range(5))
    finally:
        engine.dispose()


@pytest.mark.parametrize("relative", ["compose.yaml", "templates/compose.main.yaml"])
def test_deployment_wires_capacity_without_raising_container_limits(relative):
    root = Path(__file__).resolve().parents[2]
    services = yaml.safe_load((root / relative).read_text(encoding="utf-8"))["services"]
    worker = services["remediation-worker"]
    assert worker["environment"]["CATS_REMEDIATION_WORKERS"] == "${CATS_REMEDIATION_WORKERS:-1}"
    assert worker["environment"]["CATS_DB_BACKGROUND_POOL_SIZE"] == "${CATS_REMEDIATION_DB_POOL_SIZE:-}"
    assert worker["cpus"] == "${CATS_REMEDIATION_CPUS:-1.0}"
    assert worker["mem_limit"] == "${CATS_REMEDIATION_MEMORY:-2g}"
    assert worker["pids_limit"] == 256
    assert services["patch-worker"]["environment"]["CATS_CANDIDATE_VERIFICATION_CONCURRENCY"] == (
        "${CATS_CANDIDATE_VERIFICATION_CONCURRENCY:-${CATS_REMEDIATION_WORKERS:-2}}")
    assert services["portal"]["environment"]["CATS_PUBLIC_WORKERS"] == "${CATS_PUBLIC_WORKERS:-2}"
    for name in ("risk-worker", "export-worker", "provisioning-worker"):
        assert services[name]["environment"]["CATS_DB_BACKGROUND_POOL_SIZE"] == 2
        assert "CATS_REMEDIATION_WORKERS" not in services[name]["environment"]
