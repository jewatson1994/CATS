"""Fresh current evidence and explicitly historical provenance remain distinct."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import Execution, Finding, Service, ServiceVersion, ServiceTransferProvenance
from test_portal import (setup_function, new_client, payload, pipeline_headers,
                         SessionLocal, page_data)


@pytest.mark.parametrize("preexisting", [False, True])
def test_newer_service_scan_promotes_new_or_previously_known_version(preexisting):
    client = new_client()
    now = datetime.now(timezone.utc)
    first = payload("august-evidence", now - timedelta(days=60), ["CVE-OLD"])
    first["service"]["version"] = "1.0"
    assert client.post("/api/v1/pipeline-results", json=first, headers=pipeline_headers).status_code == 201
    if preexisting:
        with SessionLocal() as db:
            service = db.scalar(select(Service))
            db.add(ServiceVersion(service_id=service.id, version="1.5"))
            db.commit()
    latest = payload("october-evidence", now, ["CVE-NEW"])
    latest["service"]["version"] = "1.5"
    assert client.post("/api/v1/pipeline-results", json=latest, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        assert service.current_version.version == "1.5"
        assert {row.cve: row.active for row in db.scalars(select(Finding))} == {"CVE-OLD": False, "CVE-NEW": True}
        assert len(list(db.scalars(select(Execution)))) == 2
    current = page_data(client.get("/services/payments-service?overview=true"))
    assert current["view"]["version"] == "1.5"
    history = page_data(client.get("/services/payments-service/history?version=1.0"))
    assert [row["key"] for row in history["snapshots"]] == ["august-evidence"]
    trend = client.get("/api/dashboard/cybersecurity/services/payments-service/history").json()
    assert [row["version"] for row in trend["trend"]] == ["1.0", "1.5"]
    assert [row["total"] for row in trend["trend"]] == [1, 1]


def test_fresh_rescan_can_make_retained_version_current_but_image_scan_cannot():
    client = new_client()
    now = datetime.now(timezone.utc)
    for index, version in enumerate(("1.5", "1.0")):
        body = payload(f"initial-{version}", now + timedelta(minutes=index), [f"CVE-{version}"])
        body["service"]["version"] = version
        assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    body = payload("image-only", now + timedelta(minutes=2), ["CVE-IMAGE"])
    body["service"]["version"] = "1.5"
    body.update(scan_scope="image", scope_image="registry/payments:image-only")
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        assert db.scalar(select(Service)).current_version.version == "1.0"
    body = payload("fresh-service", now + timedelta(minutes=3), ["CVE-FRESH"])
    body["service"]["version"] = "1.5"
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        assert db.scalar(select(Service)).current_version.version == "1.5"
        assert [row.cve for row in db.scalars(select(Finding).where(Finding.active.is_(True)))] == ["CVE-FRESH"]


def test_imported_provenance_does_not_promote_newer_historical_version():
    client = new_client()
    now = datetime.now(timezone.utc)
    body = payload("local-current", now, ["CVE-CURRENT"])
    body["service"]["version"] = "1.0"
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    imported = payload("retained-only", now + timedelta(days=1), ["CVE-IMPORTED"])
    imported["service"]["version"] = "1.5"
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        db.add(ServiceTransferProvenance(service_id=service.id,
            detail={"historical_executions": [imported], "assessment_role": "informational_only"}))
        db.commit()
    history = page_data(client.get("/services/payments-service/history?version=1.5"))
    assert [row["key"] for row in history["imported_snapshots"]] == ["retained-only"]
    with SessionLocal() as db:
        assert db.scalar(select(Service)).current_version.version == "1.0"
        assert [row.cve for row in db.scalars(select(Finding))] == ["CVE-CURRENT"]


@pytest.mark.parametrize("input_images,chart,expected_scope,selected_scope", [
    ("registry/payments:1.5", True, "service", "auto"),
    ("registry/payments:1.5", False, "image", "auto"),
    ("registry/payments:1.5", False, "service", "service"),
    ("registry/payments:1.5", False, "service", "api-service"),
    ("registry/payments:1.5\nregistry/sidecar:1", False, "service", "auto"),
])
def test_public_ingest_scope_uses_job_inputs_not_vulnerable_image_count(monkeypatch, tmp_path, input_images, chart, expected_scope, selected_scope):
    import json
    from app import main
    from app.auth import AuthContext
    client = new_client()
    monkeypatch.setattr(AuthContext, "accessible_service_ids", lambda self, permission: {1})
    monkeypatch.setattr(AuthContext, "has", lambda self, permission, service_id=None: True)
    now = datetime.now(timezone.utc)
    baseline = payload("public-baseline", now - timedelta(days=1), ["CVE-OLD"])
    baseline["service"]["version"] = "1.0"
    assert client.post("/api/v1/pipeline-results", json=baseline, headers=pipeline_headers).status_code == 201
    job_id = "scope-regression"
    output = tmp_path / job_id / "output"
    output.mkdir(parents=True)
    body = payload("ignored", now, ["CVE-NEW"])
    body["scan_scope"] = "service"
    (output / "portal-result.json").write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setattr(main, "PUBLIC_JOB_ROOT", tmp_path)
    main.PUBLIC_JOBS[job_id] = {"job_id": job_id, "status": "complete", "owner_user_id": 1,
        "image_list": input_images, "chart_url": "https://charts.invalid/chart.tgz" if chart else "",
        "ingest_service_version": "1.5", "ingest_scope": "service" if selected_scope == "service" else "auto"}
    scope_query = "&scan_scope=service" if selected_scope == "api-service" else ""
    response = client.post(f"/api/public/jobs/{job_id}/ingest?service_id=payments-service{scope_query}")
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == f"public:{job_id}"))
        assert execution.scan_scope == expected_scope
        assert db.scalar(select(Service)).current_version.version == ("1.0" if expected_scope == "image" else "1.5")


def test_scan_form_retains_explicit_full_service_choice(monkeypatch):
    from app import main
    from app.auth import AuthContext
    client = new_client()
    monkeypatch.setattr(AuthContext, 'accessible_service_ids', lambda self, permission: {1})
    monkeypatch.setattr(AuthContext, 'has', lambda self, permission, service_id=None: True)
    baseline = payload('scope-form-baseline', datetime.now(timezone.utc), ['CVE-OLD'])
    assert client.post('/api/v1/pipeline-results', json=baseline, headers=pipeline_headers).status_code == 201
    captured = {}
    async def prepare(*args, **kwargs):
        captured.update(kwargs)
        main.PUBLIC_JOBS['scope-form-job'] = {'job_id': 'scope-form-job', 'owner_user_id': 1,
            'status': 'queued', 'ingest_service_id': 'payments-service',
            'ingest_service_version': kwargs['ingest_service_version'], 'ingest_scope': kwargs['ingest_scope']}
        return 'scope-form-job'
    monkeypatch.setattr(main, '_prepare_public_scan', prepare)
    response = client.post('/scan', data={'image_list': 'registry/payments:1.5',
        'ingest_service_id': 'payments-service', 'ingest_service_version': '1.5', 'ingest_scope': 'service'})
    assert response.status_code == 200, response.text
    assert captured['ingest_scope'] == 'service'
    result = page_data(response)
    assert result['ingest_scope'] == 'service'
    assert result['ingest_service_version'] == '1.5'
