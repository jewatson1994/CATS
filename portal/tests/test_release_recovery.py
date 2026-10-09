"""Recovery keeps release receipts durable while respecting live worker ownership."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app import main
from app.database import Base
from app.delivery_execution import delivery_lock
from app.deployment_bundle import file_digest
from app.models import AuditEvent, RemediationExecution, Service, ServiceVersion, User
from app.remediation_delivery import DeliveryAttempt
from app.remediation_retention import RetentionPolicy, cleanup_remediation_artifacts


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    root = tmp_path / "candidates"
    root.mkdir()
    dispatched = []
    monkeypatch.setattr(main, "SessionLocal", sessions)
    monkeypatch.setattr(main, "REMEDIATION_JOB_ROOT", root)
    monkeypatch.setattr(main, "REMEDIATION_WORKERS", SimpleNamespace(
        submit=lambda callback, identity: dispatched.append((callback, identity))))
    with sessions() as db:
        service = Service(service_key="recovery-service", name="Recovery service")
        actor = User(username="recovery-user", display_name="Recovery user")
        db.add_all([service, actor])
        db.flush()
        version = ServiceVersion(service_id=service.id, version="1.0.0")
        db.add(version)
        db.flush()
        service_id, actor_id, version_id = service.id, actor.id, version.id
        db.commit()

    def create(status="running", *, key="R-RECOVERY", age=60):
        folder = root / key
        folder.mkdir()
        artifact = folder / "candidate.zip"
        artifact.write_bytes(b"retained candidate")
        partial = {"release_stage": "publishing_documentation", "artifacts": [
            {"reference": "registry.example/team/chart@sha256:" + "a" * 64}],
            "documentation": {"storage_key": "b" * 64 + "/" + "c" * 64,
                "publications": [{"subject": "registry.example/team/chart@sha256:" + "a" * 64,
                                  "status": "published", "digest": "sha256:" + "d" * 64}]}}
        with sessions() as db:
            record = RemediationExecution(job_key=key, service_id=service_id,
                requested_by_id=actor_id, source_version_id=version_id,
                status="completed", remediation_status="complete", delivery_status=status,
                artifact_path=str(artifact), artifact_digest=file_digest(artifact),
                completed_at=datetime.now(timezone.utc) - timedelta(days=age))
            db.add(record)
            db.flush()
            attempt = DeliveryAttempt(remediation_id=record.id, actor_id=actor_id,
                content_digest=record.artifact_digest, status=status, result=partial,
                destination={"id": "registry", "endpoint": "registry.example", "namespace": "team"})
            db.add(attempt)
            db.commit()
            return record.id, attempt.id, partial

    yield SimpleNamespace(root=root, sessions=sessions, create=create,
                          dispatched=dispatched, actor_id=actor_id)
    engine.dispose()


@pytest.mark.parametrize("status", ["running", "staged", "publishing"])
def test_interrupted_delivery_preserves_receipts_and_allows_explicit_retry(recovery, monkeypatch, status):
    record_id, attempt_id, partial = recovery.create(status)
    main._recover_release_deliveries()
    with recovery.sessions() as db:
        attempt = db.get(DeliveryAttempt, attempt_id)
        record = db.get(RemediationExecution, record_id)
        assert attempt.status == record.delivery_status == "failed"
        assert attempt.completed_at is not None
        assert attempt.result["interrupted"] is True
        assert "retry" in attempt.result["error"].lower()
        assert {key: attempt.result[key] for key in partial} == partial
        assert Path(record.artifact_path).exists()
        audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "remediation.delivery_interrupted"))
        assert audit.detail["attempt_id"] == attempt_id
    assert recovery.dispatched == []

    # Re-running startup recovery must not rewrite terminal history or audit it twice.
    main._recover_release_deliveries()
    monkeypatch.setattr(main, "_delivery_actor", lambda *args: SimpleNamespace())
    monkeypatch.setattr(main, "_check_delivery_policy", lambda *args: None)
    monkeypatch.setattr(main, "_portal_signing_material", lambda *args: ({}, {}))
    monkeypatch.setattr(main.service_oci, "resolve_destination", lambda *args: {
        "id": "registry", "endpoint": "registry.example", "namespace": "team"})
    with recovery.sessions() as db:
        retry = main._queue_delivery(db, db.get(RemediationExecution, record_id),
            recovery.actor_id, "oci", "registry", authorize_documentation=True)
        assert retry.id != attempt_id and retry.status == "queued"
        assert db.get(DeliveryAttempt, attempt_id).result["documentation"] == partial["documentation"]
        assert len(db.scalars(select(AuditEvent).where(
            AuditEvent.action == "remediation.delivery_interrupted")).all()) == 1
    assert recovery.dispatched == [(main._run_delivery_attempt, retry.id)]


def test_queued_recovery_dispatches_only_after_releasing_ownership(recovery, monkeypatch):
    record_id, attempt_id, partial = recovery.create("queued")
    executed = []

    def execute(identity):
        # The wrapper acquired ownership, proving the startup lock is already released.
        with delivery_lock(recovery.root, identity) as owned:
            assert owned is False
        executed.append(identity)

    monkeypatch.setattr(main, "_execute_delivery_attempt", execute)
    monkeypatch.setattr(main, "REMEDIATION_WORKERS", SimpleNamespace(
        submit=lambda callback, identity: callback(identity)))
    main._recover_release_deliveries()
    assert executed == [attempt_id]
    with recovery.sessions() as db:
        attempt = db.get(DeliveryAttempt, attempt_id)
        assert attempt.status == db.get(RemediationExecution, record_id).delivery_status == "queued"
        assert attempt.result == partial and attempt.completed_at is None


@pytest.mark.parametrize("status", ["queued", "running", "staged", "publishing"])
def test_recovery_does_not_interrupt_owned_delivery(recovery, status):
    record_id, attempt_id, partial = recovery.create(status)
    with delivery_lock(recovery.root, attempt_id) as owned:
        assert owned
        main._recover_release_deliveries()
    with recovery.sessions() as db:
        attempt = db.get(DeliveryAttempt, attempt_id)
        assert attempt.status == db.get(RemediationExecution, record_id).delivery_status == status
        assert attempt.result == partial and attempt.completed_at is None
        assert db.scalar(select(AuditEvent.id)) is None
    assert recovery.dispatched == []


def test_worker_wrapper_excludes_duplicate_execution_and_releases_on_error(recovery, monkeypatch):
    _, attempt_id, _ = recovery.create("queued")
    executed = []

    def execute(identity):
        executed.append(identity)
        raise RuntimeError("worker interrupted")

    monkeypatch.setattr(main, "_execute_delivery_attempt", execute)
    with delivery_lock(recovery.root, attempt_id) as owned:
        assert owned
        main._run_delivery_attempt(attempt_id)
    assert executed == []
    with pytest.raises(RuntimeError, match="worker interrupted"):
        main._run_delivery_attempt(attempt_id)
    assert executed == [attempt_id]
    with delivery_lock(recovery.root, attempt_id) as owned:
        assert owned


@pytest.mark.parametrize("exit_mode", ["normal", "abrupt"])
def test_cross_process_ownership_is_released_on_exit(tmp_path, exit_mode):
    root = tmp_path / "locks"
    ready = tmp_path / "child-ready"
    script = """
import os
from pathlib import Path
import sys
from app.delivery_execution import delivery_lock
with delivery_lock(sys.argv[1], 37) as owned:
    assert owned
    Path(sys.argv[2]).write_text('ready')
    sys.stdin.readline()
    if sys.argv[3] == 'abrupt':
        os._exit(0)
"""
    process = subprocess.Popen([sys.executable, "-c", script, str(root), str(ready), exit_mode],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.025)
        assert ready.exists(), "Child did not acquire delivery ownership"
        with delivery_lock(root, 37) as owned:
            assert owned is False
        _, error = process.communicate("release\n", timeout=15)
        assert process.returncode == 0, error
        with delivery_lock(root, 37) as owned:
            assert owned is True
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=15)


@pytest.mark.parametrize("status", ["published", "failed", "download_ready"])
def test_release_history_survives_expiry_and_quota_cleanup(recovery, status):
    record_id, _, _ = recovery.create(status, key="R-DURABLE")
    expired_id, _, _ = recovery.create("failed", key="R-EXPIRED")
    history = recovery.root / "R-DURABLE" / "release-documentation" / ("a" * 64) / ("b" * 64)
    history.mkdir(parents=True)
    files = {"documentation.zip": b"retained documentation", "release-manifest.json": b"{}",
             "release-manifest.sig": b"retained signature", "signing-public-key.pem": b"retained public key"}
    for name, content in files.items():
        (history / name).write_bytes(content)
    with recovery.sessions() as db:
        record = db.get(RemediationExecution, record_id)
        original_path, original_digest = record.artifact_path, record.artifact_digest
        result = cleanup_remediation_artifacts(db, recovery.root, policy=RetentionPolicy(30, 7, 1))
        db.commit()
        assert result["removed"] == ["R-EXPIRED"]
        assert db.get(RemediationExecution, expired_id).artifact_path is None
        assert record.artifact_path == original_path and record.artifact_digest == original_digest
        assert file_digest(original_path) == original_digest
        assert result["over_quota"] is True
        assert result["retained_bytes"] == len(Path(original_path).read_bytes()) + sum(map(len, files.values()))
    assert {name: (history / name).read_bytes() for name in files} == files
