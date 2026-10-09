"""Failure fencing, credential identity, queue fairness and additive upgrades."""
import json
from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, inspect, text
from app import scan_coordination as jobs
from app.scan_protocol import authenticated
from test_scan_worker_coordination import database, protocol, enqueue


@pytest.mark.parametrize("category,retry", [("registry_authorization", False), ("scanner_timeout", True), ("evidence_integrity", False)])
def test_explicit_failure_policy_and_fencing(database, category, retry):
    enqueue()
    claim = jobs.claim("worker")
    result = jobs.report_failure("job", claim["attempt_id"], claim["attempt_token"], category,
                                 "registry password=secret Bearer abcdef", worker_id="worker")
    assert result["retry"] is retry
    payload = jobs.DurableJobs()["job"]
    assert "secret" not in payload["error"] and "abcdef" not in payload["error"]
    assert payload["failure"]["category"] == category
    with database() as db:
        assert db.get(jobs.ScanAttempt, claim["attempt_id"]).state == "failed"
    with pytest.raises(HTTPException) as caught:
        jobs.heartbeat("job", claim["attempt_id"], claim["attempt_token"], "scan")
    assert caught.value.status_code == 409


def test_worker_cannot_report_other_identity_attempt(database):
    enqueue()
    claim = jobs.claim("first")
    with pytest.raises(HTTPException) as caught:
        jobs.report_failure("job", claim["attempt_id"], claim["attempt_token"], "scanner_execution", worker_id="second")
    assert caught.value.status_code == 403
    assert jobs.DurableJobs()["job"]["status"] == "running"


def test_heartbeat_reports_actual_lease(database):
    enqueue()
    claim = jobs.claim("worker")
    response = jobs.heartbeat("job", claim["attempt_id"], claim["attempt_token"], "scan")
    assert response["lease_until"] >= claim["lease_until"]


@pytest.mark.parametrize("token", ["é" * 40, "replace-with-a-long-random-scan-worker-token"])
def test_invalid_unicode_and_placeholder_credentials_fail_closed(monkeypatch, token):
    monkeypatch.delenv("CATS_SCAN_WORKER_CREDENTIALS", raising=False)
    monkeypatch.setenv("CATS_SCAN_WORKER_TOKEN", token)
    with pytest.raises(HTTPException) as caught:
        authenticated("Bearer " + token, "scan-worker")
    assert caught.value.status_code == 401


def test_per_worker_rotation_and_identity(monkeypatch):
    monkeypatch.setenv("CATS_SCAN_WORKER_CREDENTIALS", json.dumps({"first": {"current": "a" * 40, "previous": "b" * 40}, "second": {"current": "c" * 40}}))
    assert authenticated("Bearer " + "a" * 40, "first") == "first"
    assert authenticated("Bearer " + "b" * 40, "first") == "first"
    with pytest.raises(HTTPException):
        authenticated("Bearer " + "a" * 40, "second")
    with pytest.raises(HTTPException) as caught:
        authenticated("Bearer " + "é" * 40, "first")
    assert caught.value.status_code == 401


def test_anonymous_capacity_keeps_authenticated_admission_and_priority(database, monkeypatch):
    monkeypatch.setenv("CATS_SCAN_ANONYMOUS_QUEUE_CAPACITY", "1")
    jobs.DurableJobs()["anonymous"] = {"status": "queued"}
    with pytest.raises(HTTPException) as caught:
        jobs.DurableJobs()["anonymous-second"] = {"status": "queued"}
    assert caught.value.status_code == 429
    jobs.DurableJobs()["authenticated"] = {"status": "queued", "owner_user_id": "user"}
    assert jobs.claim("worker")["job_id"] == "authenticated"


def test_cancel_attempt_and_indexed_definition_callback(database):
    enqueue()
    jobs.DurableJobs().update_job("job", {"definition_context": {"run_id": "run"}})
    claim = jobs.claim("worker")
    jobs.DurableJobs().update_job("job", {"status": "cancelled"})
    with database() as db:
        row = db.get(jobs.ScanJob, "job")
        assert row.definition_pending is True and row.finished_at is not None
        assert db.get(jobs.ScanAttempt, claim["attempt_id"]).state == "cancelled"
    jobs.DurableJobs().update_job("job", {"definition_notified": True})
    with database() as db:
        assert db.get(jobs.ScanJob, "job").definition_pending is False


def test_additive_upgrade_backfills_once_and_is_repeatable(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE scan_jobs (id TEXT PRIMARY KEY, status TEXT, payload JSON, service_key TEXT)"))
        connection.execute(text("INSERT INTO scan_jobs VALUES ('old', 'cancelled', :payload, '')"), {"payload": json.dumps({"definition_context": {"run_id": "run"}})})
        jobs.upgrade_connection(connection)
        jobs.upgrade_connection(connection)
        row = connection.execute(text("SELECT definition_pending, finished_at FROM scan_jobs")).one()
        assert row[0] == 1 and row[1] is not None
        assert "ix_scan_jobs_definition_pending" in {index["name"] for index in inspect(connection).get_indexes("scan_jobs")}


def test_retention_preserves_active_and_recent_evidence(database, protocol, monkeypatch):
    worker_protocol, main = protocol
    old_id, active_id, recent_id = "a" * 32, "b" * 32, "c" * 32
    for job_id in (old_id, active_id, recent_id):
        jobs.DurableJobs()[job_id] = {"status": "queued", "owner_user_id": "user"}
        (main.PUBLIC_JOB_ROOT / job_id / "output").mkdir(parents=True)
        (main.PUBLIC_JOB_ROOT / job_id / "output" / "retained.txt").write_text("evidence")
    for job_id in (old_id, recent_id):
        jobs.DurableJobs().update_job(job_id, {"status": "complete"})
    with database() as db:
        db.get(jobs.ScanJob, old_id).finished_at = jobs.now() - timedelta(days=31)
        db.commit()
    worker_protocol.retention_once()
    assert not (main.PUBLIC_JOB_ROOT / old_id).exists()
    assert (main.PUBLIC_JOB_ROOT / recent_id / "output" / "retained.txt").exists()
    assert (main.PUBLIC_JOB_ROOT / active_id / "output" / "retained.txt").exists()


def test_preparation_expiry_releases_admission(database, monkeypatch):
    jobs.DurableJobs().reserve("preparing", {"owner_user_id": 1})
    with database() as db:
        db.get(jobs.ScanJob, "preparing").created_at = jobs.now() - timedelta(minutes=16)
        db.commit()
    assert jobs.claim("worker") is None
    assert jobs.DurableJobs()["preparing"]["status"] == "error"


def test_small_queue_keeps_authenticated_slot(database, monkeypatch):
    monkeypatch.setenv("CATS_SCAN_QUEUE_CAPACITY", "2")
    jobs.DurableJobs()["anon-one"] = {"status": "queued"}
    with pytest.raises(HTTPException) as caught:
        jobs.DurableJobs()["anon-two"] = {"status": "queued"}
    assert caught.value.status_code == 429
    jobs.DurableJobs()["owner"] = {"status": "queued", "owner_user_id": 1}


def test_postgresql_additive_upgrade(database):
    engine = database.kw["bind"]
    if engine.dialect.name != "postgresql":
        pytest.skip("Set TEST_DATABASE_URL to run PostgreSQL additive migration")
    with engine.begin() as connection:
        jobs.ScanJob.__table__.drop(connection)
        connection.execute(text("CREATE TABLE scan_jobs (id TEXT PRIMARY KEY, status TEXT, payload JSON, service_key TEXT)"))
        connection.execute(text("INSERT INTO scan_jobs VALUES ('old', 'cancelled', :payload, '')"),
                           {"payload": json.dumps({"definition_context": {"run_id": "run"}})})
        jobs.upgrade_connection(connection)
        jobs.upgrade_connection(connection)
        row = connection.execute(text("SELECT definition_pending, finished_at, anonymous FROM scan_jobs")).one()
        assert row[0] is True and row[1] is not None and row[2] is False
        assert "ix_scan_jobs_definition_pending" in {index["name"] for index in inspect(connection).get_indexes("scan_jobs")}


@pytest.mark.parametrize("reference", ["service", "execution", "image", "definition", "ingested"])
def test_retention_preserves_referenced_history(database, protocol, reference):
    from app.models import Execution, ServiceImage
    worker_protocol, main = protocol
    job_id = "d" * 32
    payload = {"status": "queued", "owner_user_id": 1}
    if reference == "service":
        payload["ingest_service_id"] = "service"
    if reference == "definition":
        payload.update(definition_context={"run_id": "run"}, definition_notified=True)
    if reference == "ingested":
        payload["ingested"] = True
    jobs.DurableJobs()[job_id] = payload
    jobs.DurableJobs().update_job(job_id, {"status": "complete"})
    output = main.PUBLIC_JOB_ROOT / job_id / "output"
    output.mkdir(parents=True)
    (output / "evidence.txt").write_text("retained")
    with database() as db:
        db.get(jobs.ScanJob, job_id).finished_at = jobs.now() - timedelta(days=31)
        if reference == "execution":
            db.add(Execution(execution_key="public:" + job_id, service_id=1,
                             scanned_at=jobs.now(), complete=True, raw_payload={}))
        if reference == "image":
            db.add(ServiceImage(service_id=1, image_reference="example:1", scan_job_id=job_id))
        db.commit()
    worker_protocol.retention_once()
    assert output.is_dir() and jobs.DurableJobs()[job_id]["status"] == "complete"


def test_orphan_cleanup_preserves_unknown_output_and_execution(database, protocol):
    import os
    import time
    from app.models import Execution
    worker_protocol, main = protocol
    ids = ["e" * 32, "f" * 32, "1" * 32]
    for job_id in ids:
        target = main.PUBLIC_JOB_ROOT / job_id
        target.mkdir()
        if job_id == ids[0]:
            (target / "output").mkdir()
        os.utime(target, (time.time() - 90000, time.time() - 90000))
    with database() as db:
        db.add(Execution(execution_key="public:" + ids[1], service_id=1,
                         scanned_at=jobs.now(), complete=True, raw_payload={}))
        db.commit()
    worker_protocol.retention_once()
    assert (main.PUBLIC_JOB_ROOT / ids[0]).is_dir()
    assert (main.PUBLIC_JOB_ROOT / ids[1]).is_dir()
    assert not (main.PUBLIC_JOB_ROOT / ids[2]).exists()


def test_fatal_worker_evidence_retained_without_ingestion(database, protocol, tmp_path):
    from test_scan_worker_coordination import result_content, submit_result, IDENTITY
    from app import scan_artifacts
    worker_protocol, main = protocol
    enqueue()
    jobs.DurableJobs().update_job("job", {"job_kind": "scan"})
    (main.PUBLIC_JOB_ROOT / "job").mkdir()
    claim = jobs.claim("worker")
    result_content(tmp_path, claim)
    source = tmp_path / "result-source"
    (source / "output" / "scan-failure.json").write_text('{"phase":"configuration_scan","exit_code":47}')
    archive = tmp_path / "fatal.tar.gz"
    scan_artifacts.pack(source, archive, {**{key: claim[key] for key in IDENTITY}, "returncode": 47})
    submit_result(worker_protocol, claim, archive.read_bytes())
    main.ingest_public_scan = lambda **kwargs: pytest.fail("Fatal worker evidence attempted ingestion")
    worker_protocol.ingest_one()
    state = jobs.DurableJobs()["job"]
    assert state["status"] == "error"
    assert "configuration_scan" in state["error"] and "47" in state["error"]
    assert (main.PUBLIC_JOB_ROOT / "job" / "output" / "scan-failure.json").is_file()


def test_orphan_cleanup_rotates_beyond_retained_directories(database, protocol, monkeypatch):
    import os
    import time
    worker_protocol, main = protocol
    monkeypatch.setenv("CATS_SCAN_CLEANUP_BATCH_SIZE", "2")
    paths = []
    for index in range(12):
        job_id = f"{index:032x}"
        jobs.DurableJobs()[job_id] = {"status": "queued", "owner_user_id": 1}
        target = main.PUBLIC_JOB_ROOT / job_id
        target.mkdir()
        paths.append(target)
    orphan = main.PUBLIC_JOB_ROOT / ("f" * 32)
    orphan.mkdir()
    os.utime(orphan, (time.time() - 90000,) * 2)
    # Deterministic ordering proves that a complete retained prefix cannot starve
    # the orphan; scandir ordering itself is platform-dependent.
    original_scandir = os.scandir
    class OrderedEntries:
        def __init__(self, root):
            with original_scandir(root) as entries:
                self.entries = iter(sorted(entries, key=lambda entry: entry.name))
            self.closed = False
        def __iter__(self):
            return self
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.close()
        def __next__(self):
            return next(self.entries)
        def close(self):
            self.closed = True
    monkeypatch.setattr(worker_protocol.os, "scandir", OrderedEntries)
    worker_protocol.retention_once()
    assert orphan.exists()
    worker_protocol.retention_once()
    assert not orphan.exists()
    assert all(path.exists() for path in paths)
    assert worker_protocol._cleanup_entries is None


@pytest.mark.parametrize("protected", ["definition_context", "ingested"])
def test_retention_rotates_past_payload_protected_rows(database, protocol, monkeypatch, protected):
    worker_protocol, main = protocol
    monkeypatch.setenv("CATS_SCAN_CLEANUP_BATCH_SIZE", "2")
    old = jobs.now() - timedelta(days=31)
    for index in range(4):
        job_id = f"{index:032x}"
        payload = {"status": "queued", "owner_user_id": 1}
        if index < 3:
            payload[protected] = {"run_id": "retained"} if protected == "definition_context" else True
            payload["definition_notified"] = True
        jobs.DurableJobs()[job_id] = payload
        jobs.DurableJobs().update_job(job_id, {"status": "complete"})
        (main.PUBLIC_JOB_ROOT / job_id / "output").mkdir(parents=True)
        with database() as db:
            db.get(jobs.ScanJob, job_id).finished_at = old
            db.commit()
    worker_protocol.retention_once()
    eligible = main.PUBLIC_JOB_ROOT / f"{3:032x}"
    assert eligible.exists()
    worker_protocol.retention_once()
    assert not eligible.exists()
    assert all((main.PUBLIC_JOB_ROOT / f"{index:032x}" / "output").exists() for index in range(3))
