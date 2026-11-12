"""Attach retained temporary scan results after choosing a destination in the UI."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import main
from app.auth import AuthContext
from app.models import Execution, Finding, Service
from test_portal import setup_function, new_client, payload, pipeline_headers, SessionLocal


@pytest.fixture
def completed_scan(monkeypatch, tmp_path):
    client = new_client()
    monkeypatch.setattr(AuthContext, "accessible_service_ids", lambda self, permission: {1})
    monkeypatch.setattr(AuthContext, "has", lambda self, permission, service_id=None: True)
    now = datetime.now(timezone.utc)
    baseline = payload("before-manual-ingest", now - timedelta(days=1), ["CVE-OLD"])
    baseline["service"]["version"] = "1.0"
    assert client.post("/api/v1/pipeline-results", json=baseline, headers=pipeline_headers).status_code == 201
    job_id = "completed-temporary-scan"
    output = tmp_path / job_id / "output"
    output.mkdir(parents=True)
    (output / "portal-result.json").write_text(json.dumps(payload("temporary", now, ["CVE-NEW"])), encoding="utf-8")
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path)
    main.PUBLIC_JOBS[job_id] = {"job_id": job_id, "status": "complete", "owner_user_id": 1,
                               "image_list": "registry/payments:2", "ingest_scope": "auto"}
    yield client, f"/api/public/jobs/{job_id}/ingest"
    client.close()


def test_completed_scan_uses_selected_version_and_scope_and_retries_without_duplicates(completed_scan):
    client, url = completed_scan
    params = {"service_id": "payments-service", "service_version": " 2.0 ", "scan_scope": "service"}
    response = client.post(url, params=params)
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] and not response.json()["duplicate"]
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        assert service.current_version.version == "2.0"
        execution = db.scalar(select(Execution).where(Execution.execution_key == "public:completed-temporary-scan"))
        assert execution.service_id == service.id
        assert execution.service_version.version == "2.0" and execution.scan_scope == "service"
        assert {row.cve: row.active for row in db.scalars(select(Finding))} == {"CVE-OLD": False, "CVE-NEW": True}
    repeated = client.post(url, params=params)
    assert repeated.status_code == 200 and repeated.json()["duplicate"]
    changed = client.post(url, params={**params, "service_version": "3.0"})
    assert changed.status_code == 409
    with SessionLocal() as db:
        assert len(list(db.scalars(select(Execution)))) == 2
        assert db.scalar(select(Service)).current_version.version == "2.0"


@pytest.mark.parametrize("version", ["", "   ", "x" * 121, "2.0\ninvalid"])
def test_invalid_selected_version_does_not_change_service(completed_scan, version):
    client, url = completed_scan
    response = client.post(url, params={"service_id": "payments-service", "service_version": version})
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(Service)).current_version.version == "1.0"
        assert len(list(db.scalars(select(Execution)))) == 1
