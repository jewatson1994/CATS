"""Durability, lease fencing and untrusted worker artifact boundary checks."""
import hashlib
import os
import uuid
import asyncio
import io
import json
import sys
import tarfile
import types
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app import scan_artifacts as artifacts
from app import scan_coordination as coordination


@pytest.fixture
def database(tmp_path, monkeypatch):
    test_url = os.getenv("TEST_DATABASE_URL")
    admin_engine = None
    schema = None
    if test_url:
        assert test_url.startswith("postgresql"), "TEST_DATABASE_URL must select PostgreSQL"
        schema = "scan_test_" + uuid.uuid4().hex
        admin_engine = create_engine(test_url)
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_engine(test_url, connect_args={"options": f"-csearch_path={schema}"})
    else:
        engine = create_engine(f"sqlite:///{(tmp_path / 'coordination.db').as_posix()}",
                               connect_args={"check_same_thread": False, "timeout": 20})
    from app import models
    coordination.Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    with sessions() as db:
        db.add(models.Service(id=1, service_key="service", name="Coordination test service"))
        db.commit()
    monkeypatch.setattr(coordination, "SessionLocal", sessions)
    monkeypatch.setenv("CATS_SCAN_MAX_ATTEMPTS", "2")
    try:
        yield sessions
    finally:
        engine.dispose()
        if admin_engine:
            with admin_engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin_engine.dispose()


def enqueue(key="job"):
    coordination.DurableJobs()[key] = {"status": "queued", "ingest_service_id": "service",
        "ingest_service_version": "v1", "input_digest": "a" * 64}


def expire(sessions, key="job", ready=False):
    with sessions() as db:
        job = db.get(coordination.ScanJob, key)
        job.lease_until = coordination.now() - timedelta(seconds=1)
        if ready:
            job.available_at = coordination.now() - timedelta(seconds=1)
        db.commit()


def pulse(claim, token=None):
    return coordination.heartbeat(claim["job_id"], claim["attempt_id"],
                                  token or claim["attempt_token"], "scan")


def test_mapping_survives_recreation_and_returns_detached_values(database):
    enqueue()
    first = coordination.DurableJobs()
    value = first["job"]
    value["status"] = "error"
    second = coordination.DurableJobs()
    assert second["job"]["status"] == "queued"
    assert list(second) == ["job"] and len(second) == 1
    second.update_job("job", {"status": "cancelled"})
    assert first["job"]["status"] == "cancelled"
    with pytest.raises(KeyError):
        second["missing"]


def test_competing_claims_have_one_owner(database):
    enqueue()
    barrier = Barrier(6)
    def compete(index):
        barrier.wait()
        return coordination.claim(f"worker-{index}")
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(compete, range(6)))
    assert len([result for result in results if result]) == 1
    with database() as db:
        assert db.get(coordination.ScanJob, "job").attempts == 1
        assert len(list(db.scalars(select(coordination.ScanAttempt)))) == 1


def test_heartbeat_renews_and_cancel_fences(database):
    enqueue()
    claim = coordination.claim("worker")
    with database() as db:
        job = db.get(coordination.ScanJob, "job")
        job.lease_until = coordination.now() + timedelta(seconds=2)
        db.commit()
    response = pulse(claim)
    assert response["cancelled"] is False and response["lease_until"]
    with database() as db:
        lease = db.get(coordination.ScanJob, "job").lease_until
        reference = coordination.now() if lease.tzinfo else coordination.now().replace(tzinfo=None)
        assert lease > reference + timedelta(seconds=10)
    coordination.DurableJobs().update_job("job", {"status": "cancelled"})
    with pytest.raises(HTTPException) as error:
        pulse(claim)
    assert error.value.status_code == 409


def test_expiry_retries_and_exhaustion_fence_old_attempt(database):
    enqueue()
    first = coordination.claim("worker-one")
    expire(database)
    with pytest.raises(HTTPException) as error:
        pulse(first)
    assert error.value.status_code == 409
    assert coordination.claim("worker-two") is None
    assert coordination.DurableJobs()["job"]["status"] == "queued"
    with database() as db:
        job = db.get(coordination.ScanJob, "job")
        job.available_at = coordination.now() - timedelta(seconds=1)
        db.commit()
    second = coordination.claim("worker-two")
    assert second["attempt_id"] != first["attempt_id"]
    with pytest.raises(HTTPException) as error:
        pulse(first)
    assert error.value.status_code == 409
    expire(database)
    assert coordination.claim("worker-three") is None
    assert coordination.DurableJobs()["job"]["status"] == "error"
    with database() as db:
        assert db.get(coordination.ScanAttempt, second["attempt_id"]).state == "expired"


def test_credentials_and_cross_job_fencing(database):
    enqueue("one")
    enqueue("two")
    one, two = coordination.claim("one"), coordination.claim("two")
    with pytest.raises(HTTPException) as error:
        pulse(one, two["attempt_token"])
    assert error.value.status_code == 403
    with database() as db, pytest.raises(HTTPException) as error:
        coordination.fenced(db, one["job_id"], two["attempt_id"], two["attempt_token"])
    assert error.value.status_code == 409


IDENTITY = {"job_id": "job", "attempt_id": "attempt", "input_digest": "a" * 64,
            "service_key": "service", "service_version": "v1"}


def envelope(path, members, declared=None, identity=None):
    data = b"result"
    manifest = {"schema": 1, **(identity or IDENTITY), "files": declared if declared is not None else
        {"report.txt": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}
    with tarfile.open(path, "w:gz") as archive:
        encoded = json.dumps(manifest).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(encoded)
        archive.addfile(info, io.BytesIO(encoded))
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = "../../outside"
            info.size = len(content) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(content) if info.isfile() else None)


def test_artifact_roundtrip(tmp_path):
    root = tmp_path / "source"
    (root / "nested").mkdir(parents=True)
    (root / "nested" / "report.txt").write_text("findings")
    archive = tmp_path / "result.tar.gz"
    expected = artifacts.pack(root, archive, IDENTITY)
    destination = tmp_path / "received"
    assert artifacts.unpack(archive, destination, IDENTITY) == expected
    assert (destination / "nested" / "report.txt").read_text() == "findings"


@pytest.mark.parametrize("name", ["../outside", "/absolute", "a/../outside", "a\\outside", "C:outside", "a//b", "./report"])
def test_artifact_paths_reject_traversal(name):
    with pytest.raises(ValueError):
        artifacts.safe_name(name)


@pytest.mark.parametrize("members", [
    [("report.txt", b"result", tarfile.SYMTYPE)],
    [("report.txt", b"result", tarfile.LNKTYPE)],
    [("report.txt", b"result", tarfile.REGTYPE)] * 2,
    [("report.txt", b"wrong!", tarfile.REGTYPE)],
    [("report.txt", b"short", tarfile.REGTYPE)],
    [("undeclared.txt", b"result", tarfile.REGTYPE)],
    [("../outside", b"result", tarfile.REGTYPE)],
    [],
])
def test_malicious_or_inconsistent_envelopes_rejected(tmp_path, members):
    source = tmp_path / "bad.tar.gz"
    envelope(source, members)
    with pytest.raises(ValueError):
        artifacts.unpack(source, tmp_path / "received", IDENTITY)
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("key", list(IDENTITY))
def test_artifact_identity_rejected(tmp_path, key):
    source = tmp_path / "bad.tar.gz"
    envelope(source, [("report.txt", b"result", tarfile.REGTYPE)], identity={**IDENTITY, key: "stale"})
    with pytest.raises(ValueError, match="identity"):
        artifacts.unpack(source, tmp_path / "received", IDENTITY)


def test_artifact_budget(tmp_path, monkeypatch):
    source = tmp_path / "bad.tar.gz"
    envelope(source, [("report.txt", b"result", tarfile.REGTYPE)])
    monkeypatch.setenv("CATS_SCAN_DISK_BYTES", "5")
    with pytest.raises(ValueError, match="budget"):
        artifacts.unpack(source, tmp_path / "received2", IDENTITY)


def test_traversal_in_manifest_rejected_before_writes(tmp_path):
    source = tmp_path / "bad.tar.gz"
    envelope(source, [], declared={"../outside": {"size": 0, "sha256": hashlib.sha256(b"").hexdigest()}})
    with pytest.raises(ValueError, match="path"):
        artifacts.unpack(source, tmp_path / "received", IDENTITY)
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("configured,authorization", [
    (None, ""), ("", "Bearer "), ("short", "Bearer short"),
    ("x" * 32, ""), ("x" * 32, "Bearer " + "y" * 32),
    ("x" * 32, "bearer " + "x" * 32),
])
def test_worker_authentication_fails_closed(monkeypatch, configured, authorization):
    from app.scan_protocol import authenticated
    if configured is None:
        monkeypatch.delenv("CATS_SCAN_WORKER_TOKEN", raising=False)
    else:
        monkeypatch.setenv("CATS_SCAN_WORKER_TOKEN", configured)
    with pytest.raises(HTTPException) as error:
        authenticated(authorization)
    assert error.value.status_code == 401


def test_worker_authentication_accepts_matching_strong_token(monkeypatch):
    from app.scan_protocol import authenticated
    monkeypatch.setenv("CATS_SCAN_WORKER_TOKEN", "x" * 32)
    authenticated("Bearer " + "x" * 32)


@pytest.fixture
def protocol(database, tmp_path, monkeypatch):
    from app import scan_protocol
    import app
    main = types.ModuleType("app.main")
    main.PUBLIC_JOB_ROOT = tmp_path / "jobs"
    main.PUBLIC_JOB_ROOT.mkdir()
    monkeypatch.setitem(sys.modules, "app.main", main)
    monkeypatch.setattr(app, "main", main, raising=False)
    monkeypatch.setattr(scan_protocol, "SessionLocal", database)
    return scan_protocol, main


class StreamRequest:
    def __init__(self, content):
        self.content = content
        self.read = False

    async def stream(self):
        self.read = True
        for offset in range(0, len(self.content), 113):
            yield self.content[offset:offset + 113]


def submit_result(protocol, claim, content):
    return asyncio.run(protocol.results(claim["job_id"], claim["attempt_id"],
                                        StreamRequest(content), claim["attempt_token"]))


def result_content(tmp_path, claim, extra=None, returncode=0):
    root = tmp_path / "result-source"
    (root / "output").mkdir(parents=True, exist_ok=True)
    (root / "output" / "scan-summary.json").write_text('{"images": []}', encoding="utf-8")
    if extra:
        (root / extra).write_text("extra", encoding="utf-8")
    identity = {key: claim[key] for key in IDENTITY}
    if returncode is not None:
        identity["returncode"] = returncode
    archive = tmp_path / "result.tar.gz"
    artifacts.pack(root, archive, identity)
    return archive.read_bytes()


def test_result_acceptance_survives_restart_and_identical_replay(database, protocol, tmp_path):
    worker_protocol, main = protocol
    enqueue()
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = coordination.claim("worker")
    content = result_content(tmp_path, claim)
    assert submit_result(worker_protocol, claim, content) == {"accepted": True}
    with database() as db:
        job = db.get(coordination.ScanJob, "job")
        attempt = db.get(coordination.ScanAttempt, claim["attempt_id"])
        assert job.status == "evidence_ready" and job.lease_until is None
        assert attempt.state == "received"
        assert attempt.manifest_digest == hashlib.sha256(content).hexdigest()
    assert coordination.DurableJobs()["job"]["phase"] == "ingest"
    assert (main.PUBLIC_JOB_ROOT / "job" / "attempts" / claim["attempt_id"] /
            "output" / "scan-summary.json").is_file()
    # An independently recreated mapping sees the same ready state after worker exit.
    assert coordination.DurableJobs()["job"]["returncode"] == 0
    assert coordination.claim("replacement-worker") is None
    assert submit_result(worker_protocol, claim, content) == {"accepted": True, "duplicate": True}
    changed = result_content(tmp_path, claim, extra="output/new.txt")
    with pytest.raises(HTTPException) as error:
        submit_result(worker_protocol, claim, changed)
    assert error.value.status_code == 409


@pytest.mark.parametrize("extra,returncode", [("input.tar.gz", 0), (None, None)])
def test_protocol_rejects_unauthorized_artifact_or_missing_exit_status(database, protocol, tmp_path, extra, returncode):
    worker_protocol, main = protocol
    enqueue()
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = coordination.claim("worker")
    content = result_content(tmp_path, claim, extra=extra, returncode=returncode)
    with pytest.raises(HTTPException) as error:
        submit_result(worker_protocol, claim, content)
    assert error.value.status_code == 422
    with database() as db:
        assert db.get(coordination.ScanAttempt, claim["attempt_id"]).state == "running"
        assert db.get(coordination.ScanJob, "job").status == "claimed"


def test_protocol_fences_expired_attempt_before_reading_body(database, protocol):
    worker_protocol, _ = protocol
    enqueue()
    claim = coordination.claim("worker")
    expire(database)
    request = StreamRequest(b"untrusted data")
    with pytest.raises(HTTPException) as error:
        asyncio.run(worker_protocol.results(claim["job_id"], claim["attempt_id"], request,
                                            claim["attempt_token"]))
    assert error.value.status_code == 409
    assert not request.read


@pytest.mark.parametrize("returncode,expected", [(0, "complete"), (2, "incomplete")])
def test_restart_ingests_ready_evidence_once(database, protocol, tmp_path, returncode, expected):
    from app.models import ServiceImage
    worker_protocol, main = protocol
    ServiceImage.__table__.create(database.kw["bind"], checkfirst=True)
    enqueue()
    coordination.DurableJobs().update_job("job", {"job_kind": "scan"})
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = coordination.claim("worker")
    submit_result(worker_protocol, claim, result_content(tmp_path, claim, returncode=returncode))
    ingestions = []
    main.ingest_public_scan = lambda *, job_id, service_id, request, db, auth: ingestions.append((job_id, service_id, auth.has("scan.ingest", 1)))
    worker_protocol.ingest_one()
    assert coordination.DurableJobs()["job"]["status"] == expected
    assert coordination.DurableJobs()["job"]["summary"] == {"images": []}
    assert ingestions == [("job", "service", True)]
    assert (main.PUBLIC_JOB_ROOT / "job" / "output" / "scan-summary.json").is_file()
    worker_protocol.ingest_one()
    assert len(ingestions) == 1


def test_ingest_failure_retains_attempt_evidence(database, protocol, tmp_path):
    from app.models import ServiceImage
    worker_protocol, main = protocol
    ServiceImage.__table__.create(database.kw["bind"], checkfirst=True)
    enqueue()
    coordination.DurableJobs().update_job("job", {"job_kind": "scan"})
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = coordination.claim("worker")
    submit_result(worker_protocol, claim, result_content(tmp_path, claim))
    def fail(*args, **kwargs):
        raise ValueError("ingest failed")
    main.ingest_public_scan = fail
    worker_protocol.ingest_one()
    assert coordination.DurableJobs()["job"]["status"] == "error"
    # Atomic publication retains the verified evidence at its final location.
    assert (main.PUBLIC_JOB_ROOT / "job" / "output" / "scan-summary.json").is_file()


@pytest.fixture
def worker_harness(tmp_path, monkeypatch):
    from app import scan_worker
    monkeypatch.setenv("CATS_SCAN_WORKER_TOKEN", "worker-credential-" + "x" * 32)
    monkeypatch.setenv("CATS_PORTAL_API_TOKEN", "portal-credential")
    monkeypatch.setenv("CATS_CONFIG_ENCRYPTION_KEY", "encryption-credential")
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret.example.invalid")
    monkeypatch.setenv("PIPELINE_API_TOKEN", "pipeline-credential")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "oidc-credential")
    monkeypatch.setenv("BOOTSTRAP_PASSWORD", "bootstrap-credential")
    monkeypatch.setenv("CATS_SCAN_LEASE_SECONDS", "3")
    monkeypatch.setenv("CATS_SCAN_JOB_TIMEOUT", "10")
    monkeypatch.setattr(scan_worker, "STOP", threading.Event())
    monkeypatch.setattr(scan_worker.shutil, "which", lambda _: None)
    root = tmp_path / "worker"
    root.mkdir()
    monkeypatch.setattr(scan_worker, "ROOT", root)
    source = tmp_path / "worker-input-source"
    (source / "charts").mkdir(parents=True)
    (source / "charts" / "values.yaml").write_text("enabled: true", encoding="utf-8")
    (source / ".cats-trust").mkdir()
    (source / ".cats-trust" / "ca-bundle.pem").write_text("test trust", encoding="utf-8")
    archive = tmp_path / "worker-input.tar.gz"
    artifacts.pack(source, archive, {"job_id": "job"})
    job = {**IDENTITY, "input_digest": artifacts.digest(archive), "attempt_token": "attempt-token",
           "job": {"job_kind": "sbom", "sbom_formats": ["syft-json", "cyclonedx-json"],
                   "cyclonedx_spec_version": "1.6"}}
    worker = scan_worker.Worker()
    calls, uploaded, processes = [], [], []
    started = threading.Event()
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def json(self): return {"cancelled": False}
        def iter_content(self, size):
            yield archive.read_bytes()
    def request(method, suffix, **kwargs):
        calls.append((method, suffix, kwargs))
        if method == "GET": return Response()
        if method == "PUT": uploaded.append(kwargs["data"].read())
        return Response()
    monkeypatch.setattr(worker, "request", request)
    script = tmp_path / "fake-scanner.py"
    script.write_text(
        "import json, os, sys, time\nfrom pathlib import Path\n"
        "output = Path(sys.argv[2])\n"
        "(output / 'phase-generate_sboms.json').write_text('{\"status\": \"running\"}')\n"
        "(output / 'scan-summary.json').write_text(json.dumps({'mode': os.getenv('CATS_JOB_MODE'), "
        "'formats': os.getenv('SBOM_FORMATS'), 'spec': os.getenv('SBOM_CYCLONEDX_SPEC_VERSION'), "
        "'environment_keys': list(os.environ), 'trust': Path(os.environ['SSL_CERT_FILE']).read_text()}))\n"
        "print('scanner ran', flush=True)\n"
        "print('token: fake-sensitive-value', flush=True)\n"
        "time.sleep(float(sys.argv[3]))\nsys.exit(int(sys.argv[4]))\n", encoding="utf-8")
    real_popen = subprocess.Popen
    def popen(arguments, **kwargs):
        process = real_popen([sys.executable, str(script), *arguments[1:], "1.5", "2"], **kwargs)
        processes.append(process)
        started.set()
        return process
    monkeypatch.setattr(scan_worker.subprocess, "Popen", popen)
    yield scan_worker, worker, job, root, calls, uploaded, processes, started, request
    worker.session.close()
    for process in processes:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_worker_executes_real_subprocess_with_isolated_environment(worker_harness, tmp_path):
    scan_worker, worker, job, root, calls, uploaded, processes, _, _ = worker_harness
    worker.execute(job)
    assert processes[0].returncode == 2
    assert (root / "readiness").exists()
    assert len(uploaded) == 1
    archive = tmp_path / "worker-results.tar.gz"
    archive.write_bytes(uploaded[0])
    output = tmp_path / "worker-evidence"
    manifest = artifacts.unpack(archive, output, {key: job[key] for key in IDENTITY})
    assert manifest["returncode"] == 2 and manifest["worker_id"] == worker.worker_id
    summary = json.loads((output / "output" / "scan-summary.json").read_text(encoding="utf-8"))
    assert summary["mode"] == "sbom" and summary["formats"] == "syft-json,cyclonedx-json"
    assert summary["spec"] == "1.6" and summary["trust"] == "test trust"
    assert not any(key.startswith(("CATS_SCAN_", "CATS_PORTAL_")) or key in
                   {"DATABASE_URL", "CATS_CONFIG_ENCRYPTION_KEY", "PIPELINE_API_TOKEN", "OIDC_CLIENT_SECRET", "BOOTSTRAP_PASSWORD"} for key in summary["environment_keys"])
    worker_log = (output / "output" / "worker.log").read_text(encoding="utf-8")
    assert "scanner ran" in worker_log
    assert "fake-sensitive-value" not in worker_log and "[redacted]" in worker_log
    assert not (output / "sources").exists()  # Uploaded charts stay immutable at the Portal.
    progress = [kwargs["json"] for method, suffix, kwargs in calls if suffix.endswith("/heartbeat")]
    assert any(item["phase"] == "generate_sboms" for item in progress)
    assert any("[redacted]" in item["log_tail"] for item in progress)
    assert not [path for path in root.iterdir() if path.name != "readiness"]


def test_worker_rejects_input_checksum_before_scanner(worker_harness):
    _, worker, job, root, _, uploaded, processes, _, _ = worker_harness
    job["input_digest"] = "0" * 64
    with pytest.raises(ValueError, match="identity verification"):
        worker.execute(job)
    assert not processes and not uploaded
    assert not [path for path in root.iterdir() if path.name != "readiness"]


@pytest.mark.parametrize("reason", ["stop", "lease"])
def test_worker_interrupt_kills_subprocess_and_cleans_attempt(worker_harness, monkeypatch, reason):
    scan_worker, worker, job, root, _, uploaded, processes, started, request = worker_harness
    def interrupt_request(method, suffix, **kwargs):
        if suffix.endswith("/heartbeat") and started.is_set():
            if reason == "lease":
                raise scan_worker.requests.HTTPError("fenced lease", response=type("Fence", (), {"status_code": 409})())
            scan_worker.STOP.set()
        return request(method, suffix, **kwargs)
    monkeypatch.setattr(worker, "request", interrupt_request)
    with pytest.raises(RuntimeError, match="interrupted|authorized"):
        worker.execute(job)
    assert processes and processes[0].poll() is not None
    assert not uploaded
    assert not [path for path in root.iterdir() if path.name != "readiness"]


def test_cancelled_job_updates_image_and_rejects_late_completion(database):
    from app.models import ServiceImage
    enqueue()
    with database() as db:
        image = ServiceImage(service_id=1, image_reference="example/app:1", scan_job_id="job", scan_status="scanning")
        db.add(image)
        db.commit()
        image_id = image.id
    jobs = coordination.DurableJobs()
    jobs.update_job("job", {"status": "cancelled"})
    jobs.update_job("job", {"status": "complete"})
    assert jobs["job"]["status"] == "cancelled"
    with database() as db:
        assert db.get(ServiceImage, image_id).scan_status == "failed"


def test_zero_exit_with_incomplete_summary_remains_incomplete(database, protocol, tmp_path):
    worker_protocol, main = protocol
    enqueue()
    coordination.DurableJobs().update_job("job", {"job_kind": "scan"})
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = coordination.claim("worker")
    result_content(tmp_path, claim)
    source = tmp_path / "result-source"
    (source / "output" / "scan-summary.json").write_text('{"images": [], "status": "incomplete"}', encoding="utf-8")
    archive = tmp_path / "incomplete.tar.gz"
    artifacts.pack(source, archive, {**{key: claim[key] for key in IDENTITY}, "returncode": 0})
    submit_result(worker_protocol, claim, archive.read_bytes())
    main.ingest_public_scan = lambda *args, **kwargs: None
    worker_protocol.ingest_one()
    assert coordination.DurableJobs()["job"]["status"] == "incomplete"


@pytest.mark.parametrize("status", ["cancelled", "error"])
def test_terminal_definition_without_evidence_notifies_once(database, protocol, monkeypatch, status):
    from app import definition_routes
    worker_protocol, _ = protocol
    enqueue()
    context = {"artifact_id": 7, "run_id": "run", "index": 0, "user_id": 1}
    coordination.DurableJobs().update_job("job", {"definition_context": context, "status": status})
    notifications = []
    monkeypatch.setattr(definition_routes, "complete_scan", lambda job_id, job: notifications.append((job_id, job)))
    worker_protocol.ingest_one()
    worker_protocol.ingest_one()
    assert len(notifications) == 1
    assert notifications[0][0] == "job"
    assert notifications[0][1]["status"] == status
    assert notifications[0][1]["definition_context"] == context
    assert coordination.DurableJobs()["job"]["definition_notified"] is True


@pytest.mark.parametrize("actual", ["sha256:" + "b" * 64, "", None])
def test_pinned_image_rejects_mismatched_or_missing_digest(tmp_path, actual):
    from app.scan_protocol import verify_image_identity
    reference = "example/app@sha256:" + "a" * 64
    (tmp_path / "portal-result.json").write_text(json.dumps({"findings": [
        {"image": reference, "image_digest": actual}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="digest differs"):
        verify_image_identity({"image_list": reference}, tmp_path)


@pytest.mark.parametrize("actual", ["sha256:" + "a" * 64, "example/app@sha256:" + "a" * 64])
def test_pinned_image_accepts_exact_digest(tmp_path, actual):
    from app.scan_protocol import verify_image_identity
    reference = "example/app@sha256:" + "a" * 64
    (tmp_path / "portal-result.json").write_text(json.dumps({"findings": [
        {"image": reference, "image_digest": actual}]}), encoding="utf-8")
    verify_image_identity({"image_list": reference}, tmp_path)


def test_evidence_rejects_self_conflicting_digest_identity(tmp_path):
    from app.scan_protocol import verify_image_identity
    (tmp_path / "portal-result.json").write_text(json.dumps({"findings": [{
        "image": "example/app@sha256:" + "a" * 64,
        "image_digest": "sha256:" + "b" * 64}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="conflicting"):
        verify_image_identity({}, tmp_path)


def test_completed_definition_evidence_notifies_once(database, protocol, tmp_path, monkeypatch):
    from app import definition_routes
    worker_protocol, main = protocol
    enqueue()
    context = {"artifact_id": 7, "run_id": "run", "index": 0, "user_id": 1}
    coordination.DurableJobs().update_job("job", {"job_kind": "scan", "definition_context": context})
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = coordination.claim("worker")
    submit_result(worker_protocol, claim, result_content(tmp_path, claim))
    main.ingest_public_scan = lambda *args, **kwargs: None
    notifications = []
    monkeypatch.setattr(definition_routes, "complete_scan", lambda job_id, job: notifications.append((job_id, job)))
    worker_protocol.ingest_one()
    worker_protocol.ingest_one()
    assert len(notifications) == 1
    assert notifications[0][1]["status"] == "complete"
    assert coordination.DurableJobs()["job"]["definition_notified"] is True


def test_worker_tolerates_transient_heartbeat_outage(worker_harness, monkeypatch):
    scan_worker, worker, job, root, calls, uploaded, processes, started, request = worker_harness
    failed = []
    def transient_request(method, suffix, **kwargs):
        if suffix.endswith("/heartbeat") and not failed:
            failed.append(True)
            raise scan_worker.requests.ConnectionError("temporary Portal restart")
        return request(method, suffix, **kwargs)
    monkeypatch.setattr(worker, "request", transient_request)
    worker.execute(job)
    assert failed and len(uploaded) == 1 and processes[0].returncode == 2
    assert not [path for path in root.iterdir() if path.name != "readiness"]

def test_worker_reports_deterministic_failure_immediately(worker_harness):
    _, worker, job, root, calls, uploaded, processes, _, _ = worker_harness
    job["input_digest"] = "0" * 64
    with pytest.raises(ValueError, match="identity verification"):
        worker.execute(job)
    failures = [kwargs["json"] for method, suffix, kwargs in calls if suffix.endswith("/failure")]
    assert len(failures) == 1 and failures[0]["category"] == "invalid_output"
    assert "identity verification" in failures[0]["reason"]
    assert not processes and not uploaded and not [path for path in root.iterdir() if path.name != "readiness"]


@pytest.mark.parametrize("body", [[], {"lease_until": "invalid-date"}])
def test_worker_malformed_renewal_fences_before_scanner(worker_harness, monkeypatch, body):
    _, worker, job, root, _, uploaded, processes, _, request = worker_harness
    renewed = threading.Event()
    class Malformed:
        def json(self):
            renewed.set()
            return body
    def malformed_request(method, suffix, **kwargs):
        if suffix.endswith("/heartbeat"): return Malformed()
        if suffix.endswith("/input"):
            assert renewed.wait(2)
        return request(method, suffix, **kwargs)
    monkeypatch.setattr(worker, "request", malformed_request)
    with pytest.raises(RuntimeError, match="interrupted|authorized"):
        worker.execute(job)
    assert not processes and not uploaded
    assert not [path for path in root.iterdir() if path.name != "readiness"]


def test_scanner_environment_removes_control_secrets_but_keeps_trust_paths():
    from app import scan_runtime
    env = scan_runtime.sanitized_environment({"PATH": "tools", "HOME": "broker-home", "PIPELINE_API_TOKEN": "token", "OIDC_CLIENT_SECRET": "secret", "BOOTSTRAP_PASSWORD": "password", "SSH_PRIVATE_KEY": "private", "CATS_SCAN_WORKER_TOKEN": "control", "SSL_CERT_FILE": "trusted.pem"})
    assert env == {"PATH": "tools", "HOME": "broker-home", "SSL_CERT_FILE": "trusted.pem"}
