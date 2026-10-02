"""Regression checks for candidate provenance and retained artifact integrity."""
from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy import select

from test_portal import setup_function, new_client, csrf, payload, pipeline_headers
from app import main
from app.database import SessionLocal
from app.models import Execution, RemediationExecution, Service, User


def test_retry_keeps_original_execution_after_new_release(monkeypatch):
    client = new_client()
    client.post("/admin/configuration/remediation", data={"csrf_token": csrf(client), "enabled": "true"})
    monkeypatch.setattr(main.REMEDIATION_WORKERS, "submit", lambda *args: None)
    now = datetime.now(timezone.utc)
    first = payload("original-remediation-scan", now, [])
    assert client.post("/api/v1/pipeline-results", json=first, headers=pipeline_headers).status_code == 201
    queued = client.post("/services/payments-service/remediate", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert queued.status_code == 303
    with SessionLocal() as db:
        original = db.scalar(select(RemediationExecution))
        original.status = "failed"
        source_id, version_id = original.source_execution_id, original.source_version_id
        db.commit()
    newer = payload("newer-remediation-scan", now + timedelta(minutes=1), [])
    newer["service"]["version"] = "3.0.0"
    assert client.post("/api/v1/pipeline-results", json=newer, headers=pipeline_headers).status_code == 201
    retried = client.post(queued.headers["location"] + "/retry", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert retried.status_code == 303
    with SessionLocal() as db:
        retry = db.scalar(select(RemediationExecution).where(RemediationExecution.retry_of_id.is_not(None)))
        assert retry.source_execution_id == source_id
        assert retry.source_version_id == version_id
        assert retry.original_revision == "2.4.1"
        assert retry.revision_number == 2


def test_candidate_download_rejects_changed_retained_artifact(tmp_path, monkeypatch):
    client = new_client()
    monkeypatch.setattr(main, "REMEDIATION_JOB_ROOT", tmp_path)
    body = payload("integrity-source", datetime.now(timezone.utc), [])
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    job_key = "R-INTEGRITY"
    output = tmp_path / job_key
    output.mkdir()
    artifact = output / "remediation-candidate.zip"
    artifact.write_bytes(b"original candidate")
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        source = db.scalar(select(Execution))
        db.add(RemediationExecution(job_key=job_key, service_id=service.id, requested_by_id=db.scalar(select(User.id)), status="bundle_ready",
                                   source_execution_id=source.id, artifact_path=str(artifact), artifact_digest=digest))
        db.commit()
    url = f"/services/payments-service/remediations/{job_key}/candidate.zip"
    assert client.get(url).status_code == 200
    artifact.write_bytes(b"changed candidate")
    response = client.get(url)
    assert response.status_code == 409
    assert response.content != b"changed candidate"
