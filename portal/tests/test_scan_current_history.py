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
    retained = history["imported_snapshots"][0]
    view = "/services/payments-service/history?version=1.5&scan=" + retained["scan_id"]
    compact = page_data(client.get(view + "&tab=overview"))["imported_snapshots"][0]
    assert compact["summary"] == retained["summary"]
    assert "findings" not in compact["data"]
    details = page_data(client.get(view + "&tab=findings"))["imported_snapshots"][0]
    assert [row["cve"] for row in details["data"]["findings"]] == ["CVE-IMPORTED"]
    assert "sbom_components" not in details["data"]
    with SessionLocal() as db:
        assert db.scalar(select(Service)).current_version.version == "1.0"
        assert [row.cve for row in db.scalars(select(Finding))] == ["CVE-CURRENT"]


def test_history_cards_and_severity_match_only_the_selected_scan_and_original_validation():
    from app.models import DeploymentValidationRun
    client = new_client()
    now = datetime.now(timezone.utc)
    for key, version, findings in [("selected", "1.0", ["CVE-DEMO", "CVE-DEMO", "CVE-SECOND"]),
                                   ("other", "1.0", []), ("current", "2.0", ["CVE-NEW"])]:
        body = payload(key, now + timedelta(seconds={"selected": 0, "other": 1, "current": 2}[key]), findings)
        body["service"]["version"] = version
        if key == "selected":
            body["service_overview"] = {"images": [{"image": "alpine:3"}, {"image": "busybox:1"}]}
            body["sbom_images"] = ["docker.io/library/alpine:3"]
            body["sbom_components"] = [{"name": "lib", "version": "2", "image": "alpine:3"}]
            body["skipped_images"] = ["redis:7 :: pull failed"]
            for finding, severity in zip(body["findings"], ("low", "HIGH", "Undefined")):
                finding.update(image="busybox:1", severity=severity, kev=severity == "HIGH")
            body["policy_findings"] = [{"finding": "POL-1", "severity": "Critical"}]
        response = client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers)
        assert response.status_code == 201, response.text
    with SessionLocal() as db:
        old = db.scalar(select(Execution).where(Execution.execution_key == "selected"))
        current = db.scalar(select(Execution).where(Execution.execution_key == "current"))
        scan_id = old.id
        for key, scan, artifact, status in [("original", old, "ORIGINAL", "FAILED"),
                ("passing", old, "ORIGINAL", "VERIFIED"), ("patched", old, "REMEDIATED", "FAILED"),
                ("different", current, "ORIGINAL", "FAILED")]:
            db.add(DeploymentValidationRun(run_key=key, service_id=scan.service_id, execution_id=scan.id,
                                          artifact_type=artifact, status=status))
        db.commit()
    url = f"/services/payments-service/history?version=1.0&scan=scan-{scan_id}"
    snapshot = page_data(client.get(url))["snapshots"][0]
    stats = snapshot["summary"]
    assert {name: stats[name] for name in ("artifacts", "sbom_components", "vulnerability_findings", "policy_findings")} == {
        "artifacts": 3, "sbom_components": 1, "vulnerability_findings": 3, "policy_findings": 1}
    assert stats["severity"] == {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Unknown": 1}
    assert (stats["kev"], stats["sbom_covered_images"], stats["total_images"], stats["validation_failures"]) == (1, 1, 3, 1)
    assert all(stats[field] is None for field in ("posture", "posture_captured_at", "watchlist", "open_poams", "overdue_poams"))
    assert [item["cve"] for item in snapshot["data"]["findings"]] == ["CVE-DEMO", "CVE-DEMO", "CVE-SECOND"]
    for tab_url, headers in ((url + "&tab=overview", {}), (url, {"Accept": "text/html"})):
        overview = page_data(client.get(tab_url, headers=headers))["snapshots"][0]
        assert overview["summary"] == stats
        assert len(overview["data"]["service_overview"]["artifacts"]) == stats["artifacts"]
        assert not {"findings", "policy_findings", "sbom_components"}.intersection(overview["data"])
    dependencies = page_data(client.get(url + "&tab=dependencies"))["snapshots"][0]
    assert dependencies["scan_id"] == snapshot["scan_id"] and "summary" not in dependencies
    assert [row["name"] for row in dependencies["data"]["sbom_components"]] == ["lib"]
    assert "findings" not in dependencies["data"] and "policy_findings" not in dependencies["data"]
    findings = page_data(client.get(url + "&tab=findings"))["snapshots"][0]
    assert findings["scan_id"] == snapshot["scan_id"] and "summary" not in findings
    assert len(findings["data"]["findings"]) == stats["vulnerability_findings"]
    assert [row["finding"] for row in findings["data"]["policy_findings"]] == ["POL-1"]
    assert "sbom_components" not in findings["data"] and "service_overview" not in findings["data"]


def test_history_preserves_absent_vs_empty_evidence_for_legacy_imported_scans():
    client = new_client()
    now = datetime.now(timezone.utc)
    current = payload("native-current", now, ["CVE-NEW"])
    assert client.post("/api/v1/pipeline-results", json=current, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        empty = {"findings": [], "policy_findings": [], "sbom_components": [], "sbom_images": [],
                 "service_overview": {"images": []}}
        scans = [{"execution_id": key, "scanned_at": now.isoformat(),
                  "service": {"id": "payments-service", "name": "Earlier service", "version": key}, **fields}
                 for key, fields in (("missing", {}), ("empty", empty))]
        db.add(ServiceTransferProvenance(service_id=service.id, detail={"historical_executions": scans}))
        db.commit()
    for version, value in (("missing", None), ("empty", 0)):
        stats = page_data(client.get(f"/services/payments-service/history?version={version}"))["imported_snapshots"][0]["summary"]
        assert all(stats[name] == value for name in ("kev", "artifacts", "total_images", "sbom_covered_images",
                                                    "sbom_components", "vulnerability_findings", "policy_findings"))
        assert stats["severity"] == (None if value is None else dict.fromkeys(("Critical", "High", "Medium", "Low", "Unknown"), 0))
        assert stats["validation_failures"] is None


@pytest.mark.parametrize("input_images,chart,expected_scope,selected_scope", [
    ("registry/payments:1.5", True, "service", "auto"),
    ("registry/payments:1.5", False, "image", "auto"),
    ("registry/payments:1.5", False, "service", "service"),
    ("registry/payments:1.5", False, "service", "api-service"),
    ("registry/payments:1.5\nregistry/sidecar:1", False, "service", "auto"),
    ("registry/payments:1.5\nregistry/sidecar:1", False, "evidence", "scheduled"),
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
        "ingest_service_version": "1.5", "ingest_scope": "service" if selected_scope == "service" else "auto",
        "schedule_context": {"revision": "scheduled-inventory"} if selected_scope == "scheduled" else None,
        "ingest_service_id": "payments-service" if selected_scope == "scheduled" else ""}
    if selected_scope == "scheduled":
        wrong_service = client.post(f"/api/public/jobs/{job_id}/ingest?service_id=other-service")
        assert wrong_service.status_code == 409
    scope_query = "&scan_scope=service" if selected_scope == "api-service" else ""
    response = client.post(f"/api/public/jobs/{job_id}/ingest?service_id=payments-service{scope_query}")
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == f"public:{job_id}"))
        assert execution.scan_scope == expected_scope
        assert db.scalar(select(Service)).current_version.version == ("1.5" if expected_scope == "service" else "1.0")
        if selected_scope == "scheduled":
            assert not execution.complete
            assert db.scalar(select(Finding.active).where(Finding.cve == "CVE-OLD"))


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
