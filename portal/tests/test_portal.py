from io import BytesIO
import os
import re
import json
import urllib.parse
import urllib.error
import ssl
import tarfile
from zipfile import ZipFile
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["PIPELINE_API_TOKEN"] = "test-token"
os.environ["CATS_BOOTSTRAP_USERNAME"] = "admin"
os.environ["CATS_BOOTSTRAP_PASSWORD"] = "test-password-long"
os.environ["SESSION_COOKIE_SECURE"] = "false"
os.environ["CATS_DEPLOYMENT_VALIDATION_ENABLED"] = "false"

from fastapi.testclient import TestClient
from openpyxl import load_workbook
from sqlalchemy import event, select

from app.auth import AuthContext, hash_password, seed_auth, token_hash
from app.database import Base, SessionLocal, engine
from app.main import app, configuration_for_service
from app.models import AuditEvent, DeploymentValidationRun, ExceptionRecord, Execution, Finding, Group, PoamEntry, PolicyExceptionRecord, PolicyFinding, PortalSetting, RemediationExecution, Role, Service, ServiceVersion, ServiceArchiveEvent, ServiceArtifact, ServiceArtifactRevision, ServiceImage, User, UserRoleAssignment, UserSession, WorkflowRequest

pipeline_headers = {"Authorization": "Bearer test-token"}


def setup_function():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    seed_auth()


def new_client(username="admin", password="test-password-long"):
    client = TestClient(app)
    response = client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert response.status_code == 303
    return client


def csrf(client):
    raw = client.cookies.get("cats_session")
    with SessionLocal() as db:
        return db.scalar(select(UserSession.csrf_token).where(UserSession.token_hash == token_hash(raw)))


def payload(execution_id, scanned_at, cves, service_id="payments-service", complete=True, skipped_images=None):
    return {
        "schema_version": "1.0", "execution_id": execution_id,
        "scanned_at": scanned_at.isoformat(), "complete": complete, "skipped_images": skipped_images or [], "fixable_only": True,
        "service": {"id": service_id, "name": service_id.replace("-", " ").title(), "version": "2.4.1", "poc": "cats-test-poc@example.invalid"},
        "findings": [{"cve": cve, "severity": "High", "image": f"registry/payments:{execution_id}",
                      "package": "openssl", "fixed_version": "9.9", "evidence": {"description": "Test vulnerability"}}
                     for cve in cves],
    }


def ingest(client, execution="run-1", cves=None, service_id="payments-service", complete=True, when=None, skipped_images=None):
    when = when or datetime.now(timezone.utc)
    return client.post("/api/v1/pipeline-results", json=payload(execution, when, cves or [], service_id, complete, skipped_images), headers=pipeline_headers)


def test_service_versions_reuse_identity_and_link_executions():
    client = new_client()
    for execution_key, version in (("release-a-1", "release-A"), ("release-a-2", " release-A "), ("release-b-1", "release-B")):
        body = payload(execution_key, datetime.now(timezone.utc), [])
        body["service"]["version"] = version
        assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        versions = db.scalars(select(ServiceVersion).where(ServiceVersion.service_id == service.id)).all()
        assert {row.version for row in versions} == {"release-A", "release-B"}
        assert service.current_version.version == "release-B"
        linked = db.scalars(select(Execution).where(Execution.service_id == service.id).order_by(Execution.id)).all()
        assert [row.service_version.version for row in linked] == ["release-A", "release-A", "release-B"]


def test_cybersecurity_chart_history_and_totals_respect_service_access():
    client = new_client()
    now = datetime.now(timezone.utc)
    for identifier, version, cves, complete in (("chart-1", "1.0", ["CVE-ONE", "CVE-TWO"], True),
                                               ("chart-2", "2.0", ["CVE-ONE"], False)):
        body = payload(identifier, now + timedelta(minutes=1 if identifier == "chart-2" else 0), cves, complete=complete)
        body["service"]["version"] = version
        assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    assert ingest(client, execution="private-chart", service_id="private-service", cves=["CVE-PRIVATE"]).status_code == 201
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id).where(Service.service_key == "payments-service"))
    add_user("chart-viewer", "Assessor", service_id=service_id)
    viewer = new_client("chart-viewer")
    data = page_data(viewer.get("/cybersecurity?component=not-present"))
    assert not data["rows"]
    assert data["metrics"]["services"] == 1
    assert data["metrics"]["high"] == data["metrics"]["vulnerabilities"]
    assert "history" not in data
    assert [item["service_key"] for item in data["services"]] == ["payments-service"]
    assert viewer.get("/api/dashboard/cybersecurity/services/private-service/history").status_code == 404
    latest, previous = viewer.get("/api/dashboard/cybersecurity/services/payments-service/history").json()["versions"]
    assert (latest["version"], latest["total"], latest["complete"]) == ("2.0", 1, False)
    assert (previous["version"], previous["total"]) == ("1.0", 2)


def test_incomplete_scan_does_not_promote_service_version():
    client = new_client()
    first = payload("current-release", datetime.now(timezone.utc), [])
    first["service"]["version"] = "release-A"
    assert client.post("/api/v1/pipeline-results", json=first, headers=pipeline_headers).status_code == 201
    second = payload("incomplete-release", datetime.now(timezone.utc), [], complete=False)
    second["service"]["version"] = "release-B"
    assert client.post("/api/v1/pipeline-results", json=second, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        assert service.current_version.version == "release-A"
        assert db.scalar(select(Execution).where(Execution.execution_key == "incomplete-release")).service_version.version == "release-B"


def test_delayed_historical_version_does_not_replace_current_posture():
    client = new_client()
    now = datetime.now(timezone.utc)
    current = payload("current-release", now, ["CVE-CURRENT"], service_id="delayed-release")
    current["service"]["version"] = "release-2"
    assert client.post("/api/v1/pipeline-results", json=current, headers=pipeline_headers).status_code == 201
    historical = payload("delayed-old-release", now - timedelta(days=10), ["CVE-OLD"], service_id="delayed-release")
    historical["service"]["version"] = "release-1"
    assert client.post("/api/v1/pipeline-results", json=historical, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "delayed-release"))
        assert service.current_version.version == "release-2"
        findings = {finding.cve: finding.active for finding in db.scalars(select(Finding).where(Finding.service_id == service.id))}
        assert findings == {"CVE-CURRENT": True, "CVE-OLD": False}
        assert len(service.versions) == 2
    page = client.get("/services/delayed-release?overview=true")
    assert page.status_code == 200
    assert "release-2" in page.text


def test_delayed_scan_of_current_version_does_not_replace_current_posture():
    client = new_client()
    now = datetime.now(timezone.utc)
    current = payload("current-scan", now, ["CVE-CURRENT"], service_id="same-release")
    current["service"]["version"] = "release-2"
    assert client.post("/api/v1/pipeline-results", json=current, headers=pipeline_headers).status_code == 201
    delayed = payload("delayed-scan", now - timedelta(days=1), ["CVE-OLD"], service_id="same-release")
    delayed["service"]["version"] = "release-2"
    assert client.post("/api/v1/pipeline-results", json=delayed, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "same-release"))
        findings = {finding.cve: finding.active for finding in db.scalars(select(Finding).where(Finding.service_id == service.id))}
        assert findings == {"CVE-CURRENT": True, "CVE-OLD": False}
        assert len(service.executions) == 2


def helm_payload(execution="helm-validation", service_id="payments-service"):
    body = payload(execution, datetime.now(timezone.utc), [], service_id)
    body.update({"artifact_type": "helm", "helm_source_files": {"Chart.yaml": "apiVersion: v2\nname: demo\nversion: 1.0.0\n"}})
    body["service_overview"] = {"rendered_resources": [{"apiVersion": "v1", "kind": "Service", "metadata": {"name": "demo"}}]}
    return body


def add_user(username, role_name, service_id=None):
    with SessionLocal() as db:
        role = db.scalar(select(Role).where(Role.name == role_name))
        user = User(username=username, display_name=username.title(), password_hash=hash_password("test-password-long"), must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, service_id=service_id)); db.commit()


def test_watchlist_warning_dashboard_and_authorization(monkeypatch):
    from app import dependency_queries
    monkeypatch.setattr(dependency_queries, "schedule_projection", lambda *args: None)
    client = new_client()
    saved = client.post("/admin/dependency-watchlist", data={"csrf_token": csrf(client), "action": "save",
        "name": "requests", "ecosystem": "python", "version_constraint": ">=2.30", "enabled": "true"}, follow_redirects=False)
    assert saved.status_code == 303
    body = payload("watchlist-run", datetime.now(timezone.utc), [])
    body["sbom_components"] = [{"name": "requests", "version": "2.31.0", "ecosystem": "python",
        "purl": "pkg:pypi/requests@2.31.0", "image": "registry.internal/app:1"},
        {"name": "request-helper", "version": "2.31.0", "ecosystem": "python", "image": "registry.internal/app:1"}]
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    dependencies = client.get("/services/payments-service?dependencies=true&dependency_filter=watchlisted")
    assert dependencies.status_code == 200, dependencies.text
    assert page_envelope(dependencies)["page"] == "service_dependencies"
    assert page_data(dependencies)["dependency_rows"] == []
    assert page_data(dependencies)["dependency_projection_status"] == "pending"
    assert page_data(dependencies)["dependency_total"] is None
    from app.models import DependencyProjection
    from app.policy_data import risk_metadata
    with SessionLocal() as db:
        projection = db.scalar(select(DependencyProjection))
        execution_id, token, binding = projection.execution_id, projection.build_token, db.get_bind()
    assert dependency_queries.build_projection(binding, execution_id, token, risk_metadata)
    dependencies = client.get("/services/payments-service?dependencies=true&dependency_filter=watchlisted")
    assert page_data(dependencies)["dependency_rows"][0]["watchlisted"]
    assert "requests" in dependencies.text
    warnings = client.get("/services/payments-service?finding_state=warnings")
    assert warnings.status_code == 200 and page_data(warnings)["warning_items"]
    dashboard = client.get("/cybersecurity")
    assert dashboard.status_code == 200 and page_envelope(dashboard)["page"] == "cybersecurity"
    assert page_data(client.get("/cybersecurity?attention=watchlist&component=requests"))["rows"][0]["service"]["name"] == "Payments Service"
    assert not page_data(client.get("/cybersecurity?component=not-present"))["rows"]
    with SessionLocal() as db:
        from app.models import DependencyWatchlistMatch
        matches = db.scalars(select(DependencyWatchlistMatch)).all()
        assert len(matches) == 1 and matches[0].component_name == "requests"
        assert not db.scalars(select(Finding)).all()
        detail_url = f"/services/payments-service/watchlist/{matches[0].id}"
    assert "pkg:pypi/requests@2.31.0" in client.get(detail_url).text
    add_user("assessor", "Assessor")
    viewer = new_client("assessor")
    assert viewer.post("/admin/dependency-watchlist", data={"csrf_token": csrf(viewer), "name": "secret"}).status_code == 403


def test_oidc_claim_mapping_preserves_scope_and_local_roles():
    from app.auth import provision_oidc_user
    from app.models import OidcClaimMapping
    with SessionLocal() as db:
        service = Service(service_key="claim-service", name="Claim Service")
        other = Service(service_key="other-service", name="Other Service")
        db.add_all([service, other]); db.flush()
        role = db.scalar(select(Role).where(Role.name == "Service Manager"))
        db.add(OidcClaimMapping(claim_path="custom.nested.roles", expected_value="owners",
            role_id=role.id, service_id=service.id, enabled=True))
        db.flush()
        user = provision_oidc_user(db, {"sub": "subject-1", "preferred_username": "claim-user",
            "custom": {"nested": {"roles": ["owners", "other"]}}})
        db.commit()
        db.refresh(user)
        auth = AuthContext(user, UserSession(token_hash="dummy", csrf_token="dummy", user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
        assert auth.has("service.edit", service.id)
        assert not auth.has("service.edit", other.id)
        assert not auth.has("config.manage")
        import pytest
        with pytest.raises(ValueError):
            provision_oidc_user(db, {"sub": "subject-2", "preferred_username": "unmapped-user",
                "custom": {"nested": {"roles": "none"}}})


def test_security_data_upload_is_authorized_and_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("CATS_POLICY_DATA_DIR", str(tmp_path))
    client = new_client()
    response = client.post("/admin/configuration/security-data/kev", data={"csrf_token": csrf(client), "action": "upload"},
        files={"file": ("kev.json", b'{"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}', "application/json")},
        follow_redirects=False)
    assert response.status_code == 303
    assert "CVE-2026-0001" in (tmp_path / "kev.json").read_text()
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "security_data.updated"))
    add_user("security-viewer", "Assessor")
    viewer = new_client("security-viewer")
    denied = viewer.post("/admin/configuration/security-data/kev", data={"csrf_token": csrf(viewer), "action": "refresh"})
    assert denied.status_code == 403


def page_envelope(response):
    """Inspect the initial React page, including POST validation errors."""
    match = re.search(r'<script\b[^>]*\bid="cats-bootstrap"[^>]*>(.*?)</script>', response.text, re.S)
    assert match, "Expected the initial React page envelope"
    envelope = json.loads(match.group(1))
    assert envelope["schemaVersion"] == 1
    return envelope


def page_data(response):
    data = page_envelope(response)["data"]
    if data.get("dashboard_url"):
        return TestClient(app).get(data["dashboard_url"], headers={"cookie": response.request.headers.get("cookie", "")}).json()
    return data


def test_login_and_http_cookie_mode():
    client = new_client()
    assert client.get("/").status_code == 200
    assert client.cookies.get("cats_session")
    public = TestClient(app).get("/", follow_redirects=False)
    assert public.status_code == 200
    assert page_envelope(public)["page"] == "home"
    assert page_data(public)["current_user"] is None


def test_public_home_scan_and_patch_workspaces():
    client = TestClient(app)
    home = client.get("/")
    assert home.status_code == 200
    assert page_envelope(home)["page"] == "home"
    assert page_data(home)["current_user"] is None
    assert "Understand what is deployed" not in home.text
    assert "SECURITY LIFECYCLE" not in home.text
    assert "Discover" not in home.text and "Monitor" not in home.text
    assert "Authenticated service operations" not in home.text
    assert client.get("/scan").status_code == 200
    patch = client.get("/patch")
    assert patch.status_code == 200
    assert page_envelope(patch)["page"] == "patch"
    assert "configured_registries" in page_data(patch)
    invalid = client.post("/patch", data={"source_mode": "oci", "output_mode": "download"})
    assert invalid.status_code == 200
    assert "Image URI is required" in invalid.text


def test_scan_and_sbom_are_separate_workspaces_with_multi_format_generation(monkeypatch, tmp_path):
    from app import main as portal_main

    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    submitted = []
    monkeypatch.setattr(portal_main.PUBLIC_WORKERS, "submit", lambda function, *args: submitted.append((function, args)))
    client = TestClient(app)

    scan = client.get("/scan")
    assert scan.status_code == 200
    assert page_envelope(scan)["page"] == "self_service"
    assert page_data(scan)["mode"] == "scan"

    sbom = client.get("/sbom")
    assert sbom.status_code == 200
    assert page_data(sbom)["mode"] == "sbom"
    for value in ("syft-json", "cyclonedx-json", "cyclonedx-xml", "spdx-json"):
        assert value in page_data(sbom)["sbom_output_formats"]
    assert "selected_sbom_formats" in page_data(sbom)
    assert "cyclonedx_spec_version" in page_data(sbom)

    response = client.post("/sbom", data={
        "image_list": "docker.io/library/alpine:3.19",
        "sbom_formats": ["cyclonedx-json", "cyclonedx-xml", "spdx-json"],
        "cyclonedx_spec_version": "1.6",
    }, follow_redirects=False)
    assert response.status_code == 303
    job_id = response.headers["location"].split("job_id=", 1)[1]
    assert submitted and submitted[0][1][0] == job_id
    job = portal_main.PUBLIC_JOBS[job_id]
    assert job["job_kind"] == "sbom"
    assert job["sbom_formats"] == ["cyclonedx-json", "cyclonedx-xml", "spdx-json"]
    assert job["cyclonedx_spec_version"] == "1.6"

    missing_format = client.post("/sbom", data={
        "image_list": "docker.io/library/alpine:3.19",
        "cyclonedx_spec_version": "1.5",
    })
    assert missing_format.status_code == 200
    assert "Select at least one SBOM format" in missing_format.text


def test_sbom_job_passes_one_inventory_configuration_to_runner(monkeypatch, tmp_path):
    from app import main as portal_main

    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setenv("CATS_SCANNER_RUNNER", "test-cats-scan")
    captured = {}

    class CompletedProcess:
        returncode = 0

        def __init__(self, arguments, **kwargs):
            captured["arguments"] = arguments
            captured["environment"] = kwargs["env"]
            output = Path(arguments[2])
            output.mkdir(parents=True, exist_ok=True)
            (output / "scan-summary.json").write_text(json.dumps({
                "status": "complete", "sboms": 1, "reports": 3,
                "formats": ["cyclonedx-json", "cyclonedx-xml", "spdx-json"],
            }), encoding="utf-8")

        def poll(self):
            return 0

    monkeypatch.setattr(portal_main.subprocess, "Popen", CompletedProcess)
    job_id = "sbom-runner-test"
    portal_main.PUBLIC_JOBS[job_id] = {
        "job_id": job_id, "job_kind": "sbom", "status": "queued", "phase": "queued",
        "sbom_formats": ["cyclonedx-json", "cyclonedx-xml", "spdx-json"],
        "cyclonedx_spec_version": "1.6",
    }
    portal_main._run_public_scan(job_id, "docker.io/library/alpine:3.19\n")

    assert captured["environment"]["CATS_JOB_MODE"] == "sbom"
    assert captured["environment"]["SBOM_FORMATS"] == "cyclonedx-json,cyclonedx-xml,spdx-json"
    assert captured["environment"]["SBOM_CYCLONEDX_SPEC_VERSION"] == "1.6"
    assert portal_main.PUBLIC_JOBS[job_id]["status"] == "complete"
    assert portal_main.PUBLIC_JOBS[job_id]["phase"] == "generate_sboms"


def test_sbom_download_contains_only_manifest_reports(monkeypatch, tmp_path):
    from app import main as portal_main

    job_id = "sbom-download-test"
    output = tmp_path / job_id / "output"
    formats_dir = output / "sboms" / "formats"
    formats_dir.mkdir(parents=True)
    raw = output / "sboms" / "alpine.json"
    cyclonedx = formats_dir / "alpine.cyclonedx.xml"
    raw.write_text('{"artifacts": []}', encoding="utf-8")
    cyclonedx.write_text("<bom/>", encoding="utf-8")
    (output / "worker.log").write_text("not part of the SBOM bundle", encoding="utf-8")
    (formats_dir / "manifest.json").write_text(json.dumps({"reports": [
        {"format": "syft-json", "path": "sboms/alpine.json"},
        {"format": "cyclonedx-xml", "path": "sboms/formats/alpine.cyclonedx.xml"},
    ]}), encoding="utf-8")
    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    portal_main.PUBLIC_JOBS[job_id] = {"job_id": job_id, "job_kind": "sbom", "status": "complete"}

    response = TestClient(app).get(f"/api/public/jobs/{job_id}/sboms")
    assert response.status_code == 200
    with ZipFile(BytesIO(response.content)) as bundle:
        assert set(bundle.namelist()) == {
            "manifest.json", "sboms/alpine.json", "sboms/formats/alpine.cyclonedx.xml",
        }


def test_public_results_view_handles_recursive_partial_result(monkeypatch, tmp_path):
    from app import main as portal_main

    job_id = "recursive-partial"
    output = tmp_path / job_id / "output"
    output.mkdir(parents=True)
    (output / "portal-result.json").write_text(json.dumps({
        "service": {"name": "torture-test"},
        "findings": [{"cve": "CVE-2026-0001", "image": "registry.example/api:1", "evidence": None}],
        "policy_findings": ["malformed-policy-row"],
        "skipped_charts": [{"item": "backend", "reason": "helm template failed at templates/deployment.yaml: rendered error"}],
    }), encoding="utf-8")
    (output / "results-export.tar.gz").write_bytes(b"test archive")
    trivy_result = output / "trivy-results" / "nginx.json"
    trivy_result.parent.mkdir()
    trivy_result.write_text('{"Results": []}', encoding="utf-8")
    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setitem(portal_main.PUBLIC_JOBS, job_id, {"job_id": job_id, "status": "complete", "chart_names": []})
    response = TestClient(app).get(f"/api/public/jobs/{job_id}/results/view")
    assert response.status_code == 200
    assert "torture-test" in response.text
    assert "backend" in response.text
    html_overview = TestClient(app).get(f"/api/public/jobs/{job_id}/overview.html")
    assert html_overview.status_code == 200
    assert "INTERACTIVE SCAN OVERVIEW" in html_overview.text
    assert "data-type-filter=\"Vulnerability\"" in html_overview.text
    assert "CVE-2026-0001" in html_overview.text
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" in html_overview.text
    assert 'id="search"' in html_overview.text and 'id="detail"' in html_overview.text
    assert "Open this file after extracting the ZIP" in html_overview.text
    assert 'href="portal-result.json"' in html_overview.text
    assert 'href="trivy-results/nginx.json"' in html_overview.text
    assert 'href="#artifacts"' in html_overview.text
    artifacts = TestClient(app).get(f"/api/public/jobs/{job_id}/artifacts")
    assert artifacts.status_code == 200
    with ZipFile(BytesIO(artifacts.content)) as bundle:
        assert "scan-overview.html" in bundle.namelist()
        exported_html = bundle.read("scan-overview.html").decode()
        assert "CVE-2026-0001" in exported_html and "const findings=" in exported_html
        assert 'href="scan-results.xlsx"' in exported_html
        assert 'href="results-export.tar.gz"' in exported_html
    archive = TestClient(app).get(f"/api/public/jobs/{job_id}/results-export")
    assert archive.status_code == 200
    assert archive.headers["content-type"] == "application/gzip"


def test_public_ingest_retains_large_helm_source_set_and_is_idempotent(monkeypatch, tmp_path):
    from app import main as portal_main

    client = new_client()
    monkeypatch.setattr(AuthContext, "accessible_service_ids", lambda self, permission: {1})
    monkeypatch.setattr(AuthContext, "has", lambda self, permission, service_id=None: True)
    assert ingest(client, execution="large-source-baseline").status_code == 201
    job_id = "large-source-ingest"
    output = tmp_path / job_id / "output"
    charts = tmp_path / job_id / "input" / "charts"
    output.mkdir(parents=True); charts.mkdir(parents=True)
    body = payload("replaced-by-public-route", datetime.now(timezone.utc), ["CVE-2026-1111"] * 20)
    body["policy_findings"] = [{"finding": f"KSV-{index}", "target": f"Deployment/item-{index}"} for index in range(25)]
    body["service_overview"] = {"rendered_resources": [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "large"}}]}
    (output / "portal-result.json").write_text(json.dumps(body), encoding="utf-8")
    for index in range(734):
        directory = charts / f"chart-{index:04d}"
        directory.mkdir()
        (directory / "values.yaml").write_text(f"index: {index}\n", encoding="utf-8")
    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setitem(portal_main.PUBLIC_JOBS, job_id, {"job_id": job_id, "status": "complete", "image_list": ""})

    first = client.post(f"/api/public/jobs/{job_id}/ingest?service_id=payments-service")
    assert first.status_code == 200
    assert first.json()["accepted"] is True and first.json()["duplicate"] is False
    assert set(first.json()["ingest_timings_ms"]) >= {"read_result", "validate_payload", "database_ingest", "total"}
    with SessionLocal() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == f"public:{job_id}"))
        assert len(execution.raw_payload["helm_source_files"]) == 734
        assert len(execution.raw_payload["findings"]) == 20
        assert len(execution.raw_payload["policy_findings"]) == 25

    second = client.post(f"/api/public/jobs/{job_id}/ingest?service_id=payments-service")
    assert second.status_code == 200 and second.json()["duplicate"] is True
    with SessionLocal() as db:
        assert len(db.scalars(select(Execution).where(Execution.execution_key == f"public:{job_id}")).all()) == 1


def test_duplicate_execution_ignores_mutable_service_presentation_but_not_evidence():
    client = new_client()
    body = payload("stable-evidence-id", datetime.now(timezone.utc), ["CVE-2026-1010"])
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    presentation_change = json.loads(json.dumps(body))
    presentation_change["service"].update({"name": "Renamed Service", "owner": "New Owner", "groups": ["Updated"]})
    duplicate = client.post("/api/v1/pipeline-results", json=presentation_change, headers=pipeline_headers)
    assert duplicate.status_code == 201 and duplicate.json()["duplicate"] is True
    changed_evidence = json.loads(json.dumps(presentation_change))
    changed_evidence["findings"][0]["fixed_version"] = "10.0"
    conflict = client.post("/api/v1/pipeline-results", json=changed_evidence, headers=pipeline_headers)
    assert conflict.status_code == 409


def test_public_ingest_validation_error_is_safe_structured_and_atomic(monkeypatch, tmp_path):
    from app import main as portal_main

    client = new_client()
    monkeypatch.setattr(AuthContext, "accessible_service_ids", lambda self, permission: {1})
    monkeypatch.setattr(AuthContext, "has", lambda self, permission, service_id=None: True)
    assert ingest(client, execution="atomic-baseline").status_code == 201
    job_id = "invalid-public-ingest"
    output = tmp_path / job_id / "output"; output.mkdir(parents=True)
    body = payload("ignored", datetime.now(timezone.utc), [])
    body["policy_findings"] = [{"finding": ""}]
    (output / "portal-result.json").write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setitem(portal_main.PUBLIC_JOBS, job_id, {"job_id": job_id, "status": "complete", "image_list": ""})
    before_name = "Payments Service"
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        service.name = before_name; db.commit()

    response = client.post(f"/api/public/jobs/{job_id}/ingest?service_id=payments-service")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["code"] == "PUBLIC_INGEST_VALIDATION_ERROR"
    assert detail["stage"] == "validate_payload" and detail["record"].startswith("policy_findings.0.finding")
    assert "input" not in json.dumps(detail).lower()
    with SessionLocal() as db:
        assert db.scalar(select(Execution).where(Execution.execution_key == f"public:{job_id}")) is None
        assert db.scalar(select(Service).where(Service.service_key == "payments-service")).name == before_name


def test_public_ingest_database_failure_rolls_back_all_partial_state(monkeypatch, tmp_path):
    from app import main as portal_main

    client = new_client()
    monkeypatch.setattr(AuthContext, "accessible_service_ids", lambda self, permission: {1})
    monkeypatch.setattr(AuthContext, "has", lambda self, permission, service_id=None: True)
    assert ingest(client, execution="rollback-baseline").status_code == 201
    job_id = "database-failure-ingest"
    output = tmp_path / job_id / "output"; output.mkdir(parents=True)
    body = payload("ignored", datetime.now(timezone.utc), ["CVE-2026-9898"])
    body["service"]["name"] = "Should Roll Back"
    body["policy_findings"] = [{"finding": "KSV-rollback"}]
    (output / "portal-result.json").write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setitem(portal_main.PUBLIC_JOBS, job_id, {"job_id": job_id, "status": "complete", "image_list": ""})
    monkeypatch.setattr(portal_main, "sync_policy_findings", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("forced transaction failure")))

    failing_client = TestClient(app, raise_server_exceptions=False)
    failing_client.cookies.update(client.cookies)
    response = failing_client.post(f"/api/public/jobs/{job_id}/ingest?service_id=payments-service")
    assert response.status_code == 500
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        assert service.name == "Payments Service"
        assert db.scalar(select(Execution).where(Execution.execution_key == f"public:{job_id}")) is None
        assert db.scalar(select(Finding).where(Finding.service_id == service.id, Finding.cve == "CVE-2026-9898")) is None


def test_service_remediation_creates_auditable_review_candidate(monkeypatch):
    from app import main as portal_main

    client = new_client()
    assert client.post("/admin/configuration/remediation", data={"csrf_token": csrf(client), "enabled": "true"}, follow_redirects=False).status_code == 303
    data = payload("remediation-source", datetime.now(timezone.utc), [])
    data["policy_findings"] = [{
        "finding": "KSV-allowPrivilegeEscalation", "severity": "High", "target": "Deployment/payments",
        "title": "Container allows privilege escalation", "description": "allowPrivilegeEscalation should be false",
    }]
    data["service_overview"] = {"rendered_resources": [{
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "payments"},
        "_cats_source_file": "templates/deployment.yaml",
        "spec": {"template": {"spec": {"containers": [{"name": "payments", "image": "registry/payments:1"}]}}},
    }]}
    assert client.post("/api/v1/pipeline-results", json=data, headers=pipeline_headers).status_code == 201
    monkeypatch.setattr(portal_main.REMEDIATION_WORKERS, "submit", lambda function, *args: function(*args))
    response = client.post("/services/payments-service/remediate", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        job = db.scalar(select(RemediationExecution))
        assert job.status == "review_required"
        assert job.rollback_reference == "remediation-source"
        assert job.configuration_changes[0]["classification"] == "REVIEW REQUIRED"
        assert Path(job.artifact_path).is_file()
        location = f"/services/payments-service/remediations/{job.job_key}"
    report = client.get(location)
    assert report.status_code == 200
    assert page_data(report)["job"]["status"] == "review_required"
    assert all(key in page_data(report)["job"] for key in ("before_snapshot", "after_snapshot", "deployment_status"))
    retry = client.post(location + "/retry", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert retry.status_code == 303
    with SessionLocal() as db:
        newer = db.scalar(select(RemediationExecution).where(RemediationExecution.retry_of_id == job.id))
        assert newer and newer.job_key != job.job_key and newer.output_mode == job.output_mode


def test_remediation_feature_defaults_off_and_blocks_backend_without_hiding_history():
    client = new_client()
    with SessionLocal() as db:
        db.add(Service(service_key="payments-service", name="Payments Service"))
        db.commit()
    assert page_data(client.get("/admin/configuration"))["configuration"]["remediation_enabled"] == "false"
    page = client.get("/services/payments-service?remediations=true&tab=pipeline")
    assert page.status_code == 200 and not page_data(page)["remediation_enabled"]
    denied = client.post("/services/payments-service/remediate", data={"csrf_token": csrf(client)})
    assert denied.status_code == 403
    with SessionLocal() as db:
        assert db.scalar(select(RemediationExecution)) is None
    enabled = client.post("/admin/configuration/remediation", data={"csrf_token": csrf(client), "enabled": "true"}, follow_redirects=False)
    assert enabled.status_code == 303
    assert page_data(client.get("/services/payments-service?remediations=true&tab=pipeline"))["can_remediate"]
    add_user("remediation-viewer", "Assessor")
    viewer = new_client("remediation-viewer")
    assert viewer.post("/services/payments-service/remediate", data={"csrf_token": csrf(viewer)}).status_code == 403
    with SessionLocal() as db:
        other = Service(service_key="other-service", name="Other Service")
        db.add(other); db.commit(); other_id = other.id
    add_user("other-manager", "Service Manager", service_id=other_id)
    manager = new_client("other-manager")
    assert manager.post("/services/payments-service/remediate", data={"csrf_token": csrf(manager)}).status_code == 403
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        admin = db.scalar(select(User).where(User.username == "admin"))
        db.add(RemediationExecution(job_key="R-CONCURRENT", service_id=service.id, requested_by_id=admin.id,
                                    output_mode="publish", status="running", phase="patch_images"))
        db.commit()
    assert client.post("/services/payments-service/remediate", data={"csrf_token": csrf(client)}).status_code == 409
    assert client.post("/admin/configuration/remediation", data={"csrf_token": csrf(client)}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        assert db.scalar(select(RemediationExecution).where(RemediationExecution.job_key == "R-CONCURRENT")).status == "running"
    assert "R-CONCURRENT" in client.get("/services/payments-service?remediations=true&tab=pipeline").text
    assert client.post("/services/payments-service/remediate", data={"csrf_token": csrf(client)}).status_code == 403
    with SessionLocal() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "remediation.feature_toggled"))


def test_remediation_submits_exact_candidate_images_to_remote_validator(monkeypatch):
    from app import main as portal_main
    from app.models import PortalSetting
    from app import validator_client

    client = new_client()
    client.post("/admin/configuration/remediation", data={"csrf_token": csrf(client), "enabled": "true"})
    data = payload("remediation-remote", datetime.now(timezone.utc), [])
    data["helm_source_files"] = {
        "Chart.yaml": "apiVersion: v2\nname: payments\nversion: 1.0.0\n",
        "values.yaml": "image: registry.internal/payments:1\n",
        "templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\nspec:\n  template:\n    spec:\n      containers:\n      - name: payments\n        image: {{ .Values.image }}\n",
        "overrides/service.yaml": "replicas: 3\n",
    }
    data["helm_values_files"] = ["values.yaml", "overrides/service.yaml"]
    data["service_overview"] = {"rendered_resources": [{
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "payments"},
        "_cats_source_mappings": [{"field_path": "spec.template.spec.containers[0].image",
                                  "values_file": "values.yaml", "values_key": ".Values.image", "ambiguous": False}],
        "spec": {"template": {"spec": {"containers": [{"name": "payments", "image": "registry.internal/payments:1"}]}}},
    }]}
    assert client.post("/api/v1/pipeline-results", json=data, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        db.add(PortalSetting(key="validator_configuration", value='{"endpoint":"https://validator.internal"}'))
        db.commit()

    candidate = "registry.internal/remediated/payments@sha256:" + "a" * 64
    from subprocess import CompletedProcess
    original_which, original_run = portal_main.shutil.which, portal_main.subprocess.run
    helm_lookups = []
    def fake_which(binary):
        if binary != "helm":
            return original_which(binary)
        helm_lookups.append(binary)
        # Each execution renders its baseline before optional chart packaging.
        return "fixture-baseline-helm" if len(helm_lookups) % 2 else None
    def fake_baseline_run(command, **kwargs):
        if command[0] != "fixture-baseline-helm":
            return original_run(command, **kwargs)
        assert command[1] in {"lint", "template"}
        assert any(Path(argument).name == "baseline" for argument in command)
        baseline = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\nspec:\n  template:\n    spec:\n      containers:\n      - name: payments\n        image: registry.internal/payments:1\n"
        return CompletedProcess(command, 0, baseline if command[1] == "template" else "Lint passed", "")
    monkeypatch.setattr(portal_main.shutil, "which", fake_which)
    monkeypatch.setattr(portal_main.subprocess, "run", fake_baseline_run)
    def fake_patch(_db, _record, _service, plan):
        for image in plan["images"]:
            image.update(candidate=candidate, patch_status="PATCHED", classification="AUTO-REMEDIABLE",
                         remediation_evidence={"sbom": "complete", "trivy": "complete", "dockle": "complete"})
    def fake_static(candidate_dir, _payload, _plan, validation):
        (candidate_dir / ".cats-rendered.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\nspec:\n  template:\n    spec:\n      containers:\n      - name: payments\n        image: " + candidate + "\n", encoding="utf-8")
        validation["status"] = "PASS"
        validation["checks"]["trivy_config_rescan"] = {"status": "PASS"}
        validation["checks"]["vulnerability_rescan"] = {"status": "PASS"}
        return validation
    submitted = []
    def fake_validate(_config, package, *, artifact_path, **kwargs):
        from app.deployment_bundle import file_digest, validate_bundle
        assert package["artifact"]["digest"] == file_digest(artifact_path)
        manifest = validate_bundle(artifact_path, expected_digest=package["artifact"]["digest"])
        with ZipFile(artifact_path) as archive:
            assert candidate in archive.read("candidate/values.yaml").decode()
            assert "1.0.0-cats." in archive.read("candidate/Chart.yaml").decode()
        submitted.append((package, manifest, artifact_path))
        return {"status": "VERIFIED", "request_id": package["request_id"],
                "validation_type": package["validation_type"], "service": package["service"],
                "artifact_digest": package["artifact"]["digest"], "cleanup_status": "COMPLETE",
                "helm_result": {"install": "PASS", "execution_mode": "HELM", "release_status": "DEPLOYED", "helm_release_verified": True}}
    monkeypatch.setattr(portal_main, "_run_remediation_image_patches", fake_patch)
    monkeypatch.setattr(portal_main, "_validate_materialized_candidate", fake_static)
    monkeypatch.setattr(validator_client, "validate", fake_validate)
    monkeypatch.setattr(portal_main.validator_management, "select_configuration",
                        lambda _db, _manual, _kind: {"endpoint": "https://validator.internal"})
    monkeypatch.setattr(portal_main.REMEDIATION_WORKERS, "submit", lambda function, *args: function(*args))
    response = client.post("/services/payments-service/remediate", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    assert submitted[0][0]["schema_version"] == "cats.validation/v2"
    assert submitted[0][1]["requiredImages"] == [candidate]
    assert submitted[0][1]["deployment"]["valuesFiles"] == ["candidate/" + name for name in data["helm_values_files"]]
    def failed_validate(config, package, **kwargs):
        return {**fake_validate(config, package, **kwargs), "status": "FAILED"}
    monkeypatch.setattr(validator_client, "validate", failed_validate)
    retry = client.post(response.headers["location"] + "/validate", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert retry.status_code == 303
    with SessionLocal() as db:
        rerun = db.scalar(select(RemediationExecution))
        assert rerun.validation_results["deployment"]["status"] == "FAILED"
        assert Path(rerun.artifact_path).is_file()
        assert len(db.scalars(select(RemediationExecution)).all()) == 1


def test_remediation_bundle_contains_manifest_archive_and_fresh_scan_evidence(monkeypatch):
    from app import main as portal_main
    client = new_client()
    client.post("/admin/configuration/remediation", data={"csrf_token": csrf(client), "enabled": "true"})
    data = payload("remediation-bundle", datetime.now(timezone.utc), [])
    data["helm_source_files"] = {"Chart.yaml": "apiVersion: v2\nname: payments\nversion: 1.0.0\n",
                                 "values.yaml": "image: registry.internal/payments:1\n",
                                 "templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\nspec:\n  template:\n    spec:\n      containers:\n      - name: payments\n        image: {{ .Values.image }}\n"}
    data["helm_values_files"] = ["values.yaml"]
    data["service_overview"] = {"rendered_resources": [{"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "payments"},
        "_cats_source_mappings": [{"field_path": "spec.template.spec.containers[0].image",
                                  "values_file": "values.yaml", "values_key": ".Values.image", "ambiguous": False}],
        "spec": {"template": {"spec": {"containers": [{"name": "payments", "image": "registry.internal/payments:1"}]}}}}]}
    assert client.post("/api/v1/pipeline-results", json=data, headers=pipeline_headers).status_code == 201
    patch_key = "a" * 32
    candidate = "registry.internal/remediated/payments:1"
    from subprocess import CompletedProcess
    original_which, original_run = portal_main.shutil.which, portal_main.subprocess.run
    helm_lookups = []
    def fake_which(binary):
        if binary != "helm":
            return original_which(binary)
        helm_lookups.append(binary)
        return "fixture-baseline-helm" if len(helm_lookups) % 2 else None
    def fake_baseline_run(command, **kwargs):
        if command[0] != "fixture-baseline-helm":
            return original_run(command, **kwargs)
        assert command[1] in {"lint", "template"}
        assert any(Path(argument).name == "baseline" for argument in command)
        baseline = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\nspec:\n  template:\n    spec:\n      containers:\n      - name: payments\n        image: registry.internal/payments:1\n"
        return CompletedProcess(command, 0, baseline if command[1] == "template" else "Lint passed", "")
    monkeypatch.setattr(portal_main.shutil, "which", fake_which)
    monkeypatch.setattr(portal_main.subprocess, "run", fake_baseline_run)
    output = portal_main.PATCH_JOB_ROOT / patch_key / "output"
    output.mkdir(parents=True, exist_ok=True)
    from test_deployment_bundle import docker_archive
    docker_archive(output / "patched-image.tar", candidate)
    (output / "grype-after.json").write_text('{"matches":[]}', encoding="utf-8")
    (output / "remediated-sbom.json").write_text('{"artifacts":[]}', encoding="utf-8")
    def fake_patch(_db, _record, _service, plan):
        for image in plan["images"]:
            image.update(candidate=candidate, digest="b" * 64, patch_job_id=patch_key,
                         patch_status="PATCHED", classification="AUTO-REMEDIABLE",
                         remediation_evidence={"sbom": "complete", "trivy": "complete", "dockle": "complete"})
    def fake_static(candidate_dir, _payload, _plan, validation):
        (candidate_dir / ".cats-rendered.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments\nspec:\n  template:\n    spec:\n      containers:\n      - name: payments\n        image: " + candidate + "\n", encoding="utf-8")
        validation["status"] = "PASS"
        validation["checks"]["trivy_config_rescan"] = {"status": "PASS"}
        validation["checks"]["vulnerability_rescan"] = {"status": "PASS"}
        return validation
    monkeypatch.setattr(portal_main, "_run_remediation_image_patches", fake_patch)
    monkeypatch.setattr(portal_main, "_validate_materialized_candidate", fake_static)
    monkeypatch.setattr(portal_main.REMEDIATION_WORKERS, "submit", lambda function, *args: function(*args))
    response = client.post("/services/payments-service/remediate", data={"csrf_token": csrf(client),
        "output_mode": "bundle"}, follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        job = db.scalar(select(RemediationExecution))
        assert job.output_mode == "bundle"
        assert job.status in {"bundle_ready", "bundle_partial"}
        with ZipFile(job.artifact_path) as bundle:
            names = set(bundle.namelist())
            assert {"manifest.json", f"images/{patch_key}.tar", f"scans/{patch_key}-grype-after.json",
                    f"sbom/{patch_key}.json"} <= names
            manifest = json.loads(bundle.read("manifest.json"))
            assert manifest["values_files"] == ["values.yaml"]
            assert manifest["images"][0]["remediated"] == candidate
            assert "remediation-plan.yaml" in names


def test_administrator_can_save_oci_registry():
    client = new_client()
    response = client.post("/admin/configuration/registries", data={
        "csrf_token": csrf(client), "display_name": "Production Harbor",
        "endpoint": "https://harbor.example.invalid/", "namespace": "/cyber-approved/",
        "auth_mode": "none", "username": "", "password": "", "action": "save",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/configuration?saved=1"


def test_internal_login_navigation_stays_in_current_tab():
    """Internal authentication links must not open a second browser tab."""
    source_root = Path(__file__).parents[1] / "frontend" / "src"
    template_paths = sorted(source_root.rglob("*.tsx"))
    assert template_paths

    for path in template_paths:
        text = path.read_text(encoding="utf-8")
        for tag in re.findall(r"<a\b[^>]*>", text, flags=re.IGNORECASE | re.DOTALL):
            href_match = re.search(r"\bhref\s*=\s*['\"]([^'\"]+)['\"]", tag, flags=re.IGNORECASE)
            if not href_match:
                continue
            href = href_match.group(1)
            if href.startswith("/login") or href.startswith("/auth/oidc/login"):
                assert not re.search(r"\btarget\s*=\s*['\"]_blank['\"]", tag, flags=re.IGNORECASE), (
                    f"internal login link opens a new tab in {path.name}: {tag}"
                )

    for path in [*source_root.rglob("*.ts"), *template_paths]:
        assert "window.open(" not in path.read_text(encoding="utf-8"), f"new-window behavior found in {path.name}"


def test_authenticated_primary_navigation_and_gear_cleanup():
    client = new_client()
    page = client.get("/")
    assert page.status_code == 200
    assert page_data(page)["current_user"]["display_name"]
    assert page_data(page)["permissions"]["config.manage"]
    assert "Remediations workspace" not in page.text
    assert "Service staging" not in page.text.split("admin-menu", 1)[-1].split("user-menu", 1)[0]
    assert "Audit Policy" not in page.text.split("admin-menu", 1)[-1].split("user-menu", 1)[0]
    remediations = client.get("/remediations")
    assert remediations.status_code == 200 and page_data(remediations)["request_path"] == "/remediations"
    assert page_envelope(remediations)["page"] == "remediations"


def test_active_services_are_alphabetical_without_compliance_explainer():
    client = new_client()
    ingest(client, execution="zeta", service_id="zeta-service")
    ingest(client, execution="alpha", service_id="alpha-service")
    page = client.get("/")
    assert page.status_code == 200
    assert [row["service"]["name"] for row in page_data(page)["views"]] == ["Alpha Service", "Zeta Service"]
    assert "Non-compliant means at least one unexcepted fixable CVE is older than 90 days." not in page.text


def test_services_overview_query_count_is_constant_as_services_grow():
    client = new_client()
    for index in range(20):
        assert ingest(client, execution=f"overview-scale-{index}", service_id=f"overview-service-{index}").status_code == 201
    calls = []
    listener = lambda *args: calls.append(args[2])
    event.listen(engine, "before_cursor_execute", listener)
    try:
        response = client.get("/")
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert response.status_code == 200
    assert len(calls) <= 20


def test_configuration_policy_findings_render_as_generic_active_findings():
    client = new_client()
    policy_payload = payload("policy-run", datetime.now(timezone.utc), [], service_id="payments-service")
    policy_payload["policy_findings"] = [{
        "type": "Configuration", "finding": "KSV014", "severity": "High",
        "scanner": "Trivy", "framework": "CIS Kubernetes",
        "target": "Deployment/payments-api", "title": "Privilege escalation enabled",
        "remediation": "Set allowPrivilegeEscalation to false",
    }]
    response = client.post("/api/v1/pipeline-results", json=policy_payload, headers=pipeline_headers)
    assert response.status_code == 201
    page = client.get("/services/payments-service?finding_state=active")
    assert page.status_code == 200
    assert page_data(page)["finding_state"] == "active"
    assert page_data(page)["policy_findings"][0]["finding"] == "KSV014"
    assert "CIS Kubernetes" in page.text and "Deployment/payments-api" in page.text
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["finding_counts"]["active"] == 1
    dashboard = client.get("/")
    assert page_data(dashboard)["views"][0]["active_count"] == 1
    assert "Active CVEs" not in dashboard.text and "Over 90d" not in dashboard.text


def test_overview_navigation_never_runs_digest_resolution(monkeypatch):
    """Overview rendering must use persisted scan data, not Docker/registry I/O."""
    client = new_client()
    response = ingest(client, execution="overview-fast", cves=["CVE-2025-0001"])
    assert response.status_code == 201

    def fail_if_called(*args, **kwargs):
        raise AssertionError("digest resolution must not run while rendering an overview")

    monkeypatch.setattr("app.main._resolve_manifest_digest", fail_if_called)
    overview = client.get("/services/payments-service?overview=true")
    assert overview.status_code == 200
    assert page_envelope(overview)["page"] == "service_overview"


def test_service_findings_can_be_filtered_by_type():
    client = new_client()
    policy_payload = payload("filter-run", datetime.now(timezone.utc), ["CVE-2026-0001"])
    policy_payload["policy_findings"] = [{
        "type": "Configuration", "finding": "KSV014", "severity": "High",
        "framework": "CIS Kubernetes", "target": "Deployment/payments-api",
    }]
    response = client.post("/api/v1/pipeline-results", json=policy_payload, headers=pipeline_headers)
    assert response.status_code == 201
    configuration_page = client.get("/services/payments-service?finding_type=configuration")
    assert configuration_page.status_code == 200
    assert "KSV014" in configuration_page.text
    assert "CVE-2026-0001" not in configuration_page.text
    assert not page_data(configuration_page)["findings"]
    vulnerability_page = client.get("/services/payments-service?finding_type=vulnerability")
    assert vulnerability_page.status_code == 200
    assert "CVE-2026-0001" in vulnerability_page.text
    assert "KSV014" not in vulnerability_page.text
    assert page_data(vulnerability_page)["finding_type"] == "vulnerability"
    assert not page_data(vulnerability_page)["policy_findings"]


def test_warning_filter_renders_warning_records_instead_of_active_findings():
    client = new_client()
    ingest(client, execution="warning-seed")
    when = datetime.now(timezone.utc)
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        finding = Finding(service_id=service.id, cve="CVE-2026-WARN", severity="High", first_seen=when - timedelta(days=80),
                          episode_started=when - timedelta(days=80), last_seen=when, active=True)
        db.add(finding)
        db.commit()
    with SessionLocal() as db:
        setting = PortalSetting(key="raw_due_rules", value='[{"severity":"High","days":90}]')
        db.add(setting); db.commit()
    response = client.get("/services/payments-service?finding_state=warnings")
    assert response.status_code == 200
    assert page_data(response)["finding_state"] == "warnings"
    assert any(row["item"] == "CVE-2026-WARN" for row in page_data(response)["warning_items"])
    assert "No warnings for this service" not in response.text


def test_remediations_workspace_uses_existing_records_and_tabs():
    client = new_client()
    ingest(client, cves=["CVE-2026-REMEDIATE"])
    page = client.get("/remediations?tab=poams")
    assert page.status_code == 200
    assert page_data(page)["tab"] == "poams"
    assert all(key in page_data(page) for key in ("poams", "exceptions", "mitigations"))
    assert client.get("/remediations?tab=exceptions").status_code == 200
    assert client.get("/remediations?tab=mitigations").status_code == 200


def test_service_remediations_replaces_service_poam_tab_without_breaking_legacy_url():
    client = new_client()
    ingest(client, cves=["CVE-2026-SERVICE-REMEDIATION"])
    page = client.get("/services/payments-service?remediations=true&tab=poams")
    assert page.status_code == 200
    assert page_data(page)["service"]["name"] == "Payments Service"
    assert page_data(page)["tab"] == "poams"
    assert all(key in page_data(page) for key in ("poams", "exceptions", "mitigations"))
    assert page_data(page)["return_to"] == "/services/payments-service?remediations=true&tab=poams"
    assert client.get("/services/payments-service?remediations=true&tab=exceptions").status_code == 200
    assert client.get("/services/payments-service?remediations=true&tab=mitigations").status_code == 200
    legacy = client.get("/services/payments-service?poam=true")
    assert legacy.status_code == 200
    assert page_envelope(legacy)["page"] == "poam_service"
    assert page_data(legacy)["service"]["name"] == "Payments Service"


def test_account_last_login_delete_protection_and_audit_snapshot():
    client = new_client()
    assert client.post("/admin/users", data={"csrf_token": csrf(client), "username": "remove-me", "display_name": "Remove Me", "password": "temporary-password"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "remove-me"))
        user_id = user.id
        assert user.last_login_at is None
        service = Service(service_key="deleted-requester-service", name="Deleted requester service")
        db.add(service); db.flush()
        execution = Execution(execution_key="deleted-requester-execution", service_id=service.id, scanned_at=datetime.now(timezone.utc), complete=True, raw_payload={})
        db.add(execution); db.flush()
        validation_run = DeploymentValidationRun(run_key="DV-DELETED-REQUESTER", service_id=service.id, execution_id=execution.id, requested_by_id=user.id)
        db.add(validation_run); db.commit(); validation_run_id = validation_run.id
    failed_login = TestClient(app).post("/login", data={"username": "remove-me", "password": "wrong-password"})
    assert failed_login.status_code == 401
    with SessionLocal() as db:
        assert db.get(User, user_id).last_login_at is None
    new_client("remove-me", "temporary-password")
    with SessionLocal() as db:
        assert db.get(User, user_id).last_login_at is not None
    assert client.post("/admin/users/{}/delete".format(user_id), data={"csrf_token": csrf(client)}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        assert db.get(User, user_id) is None
        assert db.get(DeploymentValidationRun, validation_run_id).requested_by_id is None
        deleted = db.scalar(select(AuditEvent).where(AuditEvent.action == "user.deleted", AuditEvent.detail["username"].as_string() == "remove-me"))
        assert deleted is not None
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
    assert client.post(f"/admin/users/{admin.id}/delete", data={"csrf_token": csrf(client)}).status_code == 409


def test_configuration_finding_exception_and_poam_use_first_class_workflows():
    admin = new_client()
    policy_payload = payload("policy-workflow", datetime.now(timezone.utc), [])
    policy_payload["policy_findings"] = [{
        "type": "Hardening", "finding": "KSV014", "severity": "High",
        "scanner": "Trivy", "framework": "CIS Kubernetes",
        "target": "Deployment/payments-api", "title": "Privilege escalation enabled",
        "description": "The workload permits privilege escalation.",
        "remediation": "Set allowPrivilegeEscalation to false", "fingerprint": "ksv014-payments",
    }]
    assert admin.post("/api/v1/pipeline-results", json=policy_payload, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        finding = db.scalar(select(PolicyFinding).where(PolicyFinding.service_id == service.id))
        service_id, policy_finding_id = service.id, finding.id
        assert finding.finding == "KSV014" and finding.type == "Configuration"
    other_payload = payload("other-policy-workflow", datetime.now(timezone.utc), [], service_id="other-service")
    other_payload["policy_findings"] = [{"finding": "KSV999", "fingerprint": "other-config"}]
    assert admin.post("/api/v1/pipeline-results", json=other_payload, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        other_policy_finding_id = db.scalar(select(PolicyFinding.id).join(Service).where(Service.service_key == "other-service"))
    add_user("policy-manager", "Service Manager", service_id)
    manager = new_client("policy-manager")
    page = manager.get("/services/payments-service?finding_type=configuration")
    assert page.status_code == 200
    assert page_data(page)["policy_findings"][0]["id"] == policy_finding_id
    assert page_data(page)["policy_findings"][0]["finding"] == "KSV014"
    assert page_data(page)["can"]["exception.request"][str(service_id)]
    assert page_data(page)["can"]["poam.request"][str(service_id)]
    expiry = datetime.now(timezone.utc) + timedelta(days=30)
    assert manager.post(f"/policy-findings/{other_policy_finding_id}/exceptions", data={
        "csrf_token": csrf(manager), "justification": "Out of scope request",
        "expires_at": expiry.isoformat(),
    }).status_code == 403
    assert manager.post(f"/policy-findings/{other_policy_finding_id}/poams", data={
        "csrf_token": csrf(manager), "title": "Out of scope configuration",
        "remediation": "Must not be accepted",
    }).status_code == 403
    exception_response = manager.post(f"/policy-findings/{policy_finding_id}/exceptions", data={
        "csrf_token": csrf(manager), "justification": "Compensating admission policy is active",
        "expires_at": expiry.isoformat(), "ticket": "RISK-CONFIG-14",
    }, follow_redirects=False)
    assert exception_response.status_code == 303
    poam_response = manager.post(f"/policy-findings/{policy_finding_id}/poams", data={
        "csrf_token": csrf(manager), "title": "Harden payments deployment",
        "remediation": "Disable privilege escalation and redeploy", "ticket": "POAM-CONFIG-14",
    }, follow_redirects=False)
    assert poam_response.status_code == 303
    with SessionLocal() as db:
        exception_workflow = db.scalar(select(WorkflowRequest).where(
            WorkflowRequest.request_type == "exception", WorkflowRequest.policy_finding_id == policy_finding_id
        ))
        poam_workflow = db.scalar(select(WorkflowRequest).where(
            WorkflowRequest.request_type == "poam", WorkflowRequest.policy_finding_id == policy_finding_id
        ))
        poam_id = poam_workflow.poam_id
    add_user("policy-cyber", "Cybersecurity")
    cyber = new_client("policy-cyber")
    assert "KSV014" in cyber.get("/requests").text
    assert cyber.post(f"/requests/{exception_workflow.id}/review", data={
        "csrf_token": csrf(cyber), "decision": "approved",
    }, follow_redirects=False).status_code == 303
    assert cyber.post(f"/requests/{poam_workflow.id}/review", data={
        "csrf_token": csrf(cyber), "decision": "approved",
    }, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        policy_exception = db.scalar(select(PolicyExceptionRecord).where(
            PolicyExceptionRecord.policy_finding_id == policy_finding_id
        ))
        entry = db.get(PoamEntry, poam_id)
        assert policy_exception is not None
        assert entry.policy_finding_id == policy_finding_id and entry.status == "active"
        policy_exception_id = policy_exception.id
    finding_export = load_workbook(BytesIO(cyber.get("/services/payments-service/export.xlsx").content))
    assert "Configuration Findings" in finding_export.sheetnames
    assert "KSV014" in [cell.value for cell in finding_export["Configuration Findings"]["A"]]
    poam_export = load_workbook(BytesIO(cyber.get("/poam/services/payments-service/export.xlsx").content))["POA&M"]
    assert "KSV014" in [cell.value for cell in poam_export["F"]]
    poam_service_page = cyber.get("/poam/services/payments-service")
    assert "KSV014" in json.dumps(page_data(poam_service_page))
    poam_detail_page = cyber.get(f"/poam/entries/{poam_id}")
    assert "KSV014" in json.dumps(page_data(poam_detail_page))
    exceptions_page = cyber.get("/services/payments-service?finding_state=exceptions&finding_type=configuration")
    assert "KSV014" in exceptions_page.text
    assert page_data(exceptions_page)["policy_findings"][0]["exception"]["id"] == policy_exception_id
    assert cyber.post(f"/policy-exceptions/{policy_exception_id}/revoke", data={
        "csrf_token": csrf(cyber),
    }, follow_redirects=False).status_code == 303


def test_configuration_findings_age_resolve_and_recur_by_stable_identity():
    client = new_client()
    old = datetime.now(timezone.utc) - timedelta(days=100)
    first = payload("policy-old", old, [])
    first["policy_findings"] = [{
        "type": "Compliance", "finding": "AVD-KSV-0014", "severity": "High",
        "scanner": "Trivy", "target": "Deployment/api", "fingerprint": "stable-config-14",
    }]
    assert client.post("/api/v1/pipeline-results", json=first, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        overdue_policy_finding_id = db.scalar(select(PolicyFinding.id))
    overdue = client.get("/services/payments-service?finding_state=noncompliant&finding_type=configuration")
    assert page_data(overdue)["noncompliance_items"][0]["item"] == "AVD-KSV-0014"
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["finding_counts"]["noncompliant"] == 1
    assert page_data(overdue)["noncompliance_items"][0]["policy_finding_id"] == overdue_policy_finding_id
    service_id = str(page_data(overdue)["view"]["service"]["id"])
    assert page_data(overdue)["can"]["exception.request"][service_id]
    assert page_data(overdue)["can"]["poam.request"][service_id]
    second = payload("policy-clear", datetime.now(timezone.utc) - timedelta(days=1), [])
    second["policy_findings"] = []
    assert client.post("/api/v1/pipeline-results", json=second, headers=pipeline_headers).status_code == 201
    assert "AVD-KSV-0014" in client.get("/services/payments-service?finding_state=resolved&finding_type=configuration").text
    third = payload("policy-return", datetime.now(timezone.utc), [])
    third["policy_findings"] = first["policy_findings"]
    assert client.post("/api/v1/pipeline-results", json=third, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        finding = db.scalar(select(PolicyFinding))
        assert finding.active and finding.recurrence_count == 1


def test_group_scoped_manager_can_act_when_service_has_multiple_groups():
    admin = new_client()
    policy_payload = payload("group-policy", datetime.now(timezone.utc), [])
    policy_payload["policy_findings"] = [{"finding": "KSV-GROUP", "fingerprint": "group-config"}]
    assert admin.post("/api/v1/pipeline-results", json=policy_payload, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        first_group = Group(name="First Group")
        assigned_group = Group(name="Assigned Group")
        service.groups.extend([first_group, assigned_group])
        db.flush()
        role = db.scalar(select(Role).where(Role.name == "Service Manager"))
        user = User(username="group-manager", display_name="Group Manager",
                    password_hash=hash_password("test-password-long"), must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, group_id=assigned_group.id))
        policy_finding_id = db.scalar(select(PolicyFinding.id).where(PolicyFinding.service_id == service.id))
        db.commit()
    manager = new_client("group-manager")
    assert "Payments Service" in [view["service"]["name"] for view in page_data(manager.get("/"))["views"]]
    response = manager.post(f"/policy-findings/{policy_finding_id}/poams", data={
        "csrf_token": csrf(manager), "title": "Group-scoped remediation",
        "remediation": "Apply hardened configuration",
    }, follow_redirects=False)
    assert response.status_code == 303


def test_complete_scan_resolves_finding():
    client = new_client()
    now = datetime.now(timezone.utc)
    assert ingest(client, cves=["CVE-2026-0001"], when=now).status_code == 201
    ingest(client, "run-2", [], complete=True, when=now + timedelta(days=1))
    assert "CVE-2026-0001" in client.get("/services/payments-service?finding_state=resolved").text


def test_group_scoped_access_is_not_global():
    client = new_client()
    assert ingest(client, execution="group-seed", cves=[]).status_code == 201
    with SessionLocal() as db:
        group = Group(name="Payments Group")
        db.add(group)
        db.flush()
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        if not service:
            service = Service(service_key="payments-service", name="Payments", owner="Platform")
            db.add(service)
            db.flush()
        service.groups.append(group)
        role = db.scalar(select(Role).where(Role.name == "Service Manager"))
        user = User(username="scoped", display_name="Scoped", password_hash=hash_password("test-password-long"), must_change_password=False)
        db.add(user)
        db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, group_id=group.id))
        db.commit()
    scoped = new_client("scoped")
    assert scoped.get("/services/payments-service").status_code == 200
    assert scoped.get("/services/unknown-service").status_code == 403


def test_skipped_images_are_visible_on_service():
    client = new_client()
    ingest(client, skipped_images=["registry/legacy-centos:1.0", "registry/vendor:2.0"], complete=False)
    page = page_data(client.get("/services/payments-service"))
    assert page["view"]["skipped_images"] == ["registry/legacy-centos:1.0", "registry/vendor:2.0"]
    assert page_data(client.get("/"))["views"][0]["evidence_state"] == "Incomplete · 2 skipped"


def test_incomplete_execution_without_skipped_images_is_noncompliant():
    client = new_client()
    ingest(client, complete=False, skipped_images=[])
    page = client.get("/services/payments-service?finding_state=noncompliant")
    assert page.status_code == 200
    assert "Latest assessment did not provide complete evidence" in page.text
    assert "No image details reported" not in page.text
    assert page_data(page)["noncompliance_items"]
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["finding_counts"]["noncompliant"] == 1


def test_service_manager_can_add_incomplete_evidence_to_poam():
    admin = new_client()
    ingest(admin, skipped_images=["registry/unavailable:demo"], complete=False)
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        service_id = service.id
    add_user("evidence-manager", "Service Manager", service_id)
    manager = new_client("evidence-manager")
    page = manager.get("/services/payments-service?finding_state=noncompliant")
    assert page.status_code == 200
    assert page_data(page)["can"]["poam.request"][str(service_id)]
    assert "registry/unavailable:demo" in page.text
    assert any("registry/unavailable:demo" in json.dumps(row) for row in page_data(page)["noncompliance_items"])
    created = manager.post("/poam", data={
        "csrf_token": csrf(manager), "service_id": service_id, "item_type": "missing_evidence",
        "finding_id": "", "title": "Missing evidence for registry/unavailable:demo",
        "description": "Unavailable for assessment: registry/unavailable:demo",
        "remediation": "Restore scanner access and submit a complete report",
    }, follow_redirects=False)
    assert created.status_code == 303
    with SessionLocal() as db:
        entry = db.scalar(select(PoamEntry))
        assert entry.item_type == "missing_evidence" and entry.status == "pending_approval"


def test_service_findings_are_paginated_and_gzip_compressed():
    client = new_client()
    ingest(client)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        for number in range(60):
            db.add(Finding(
                service_id=service.id, cve=f"CVE-PAGE-{number:04d}", severity="High",
                first_seen=now, episode_started=now, last_seen=now, active=True,
            ))
        db.commit()
    first = client.get("/services/payments-service?page_size=50")
    assert first.status_code == 200
    assert first.headers.get("content-encoding") == "gzip"
    assert len(page_data(first)["findings"]) == 50
    assert (page_data(first)["page"], page_data(first)["total_pages"], page_data(first)["total_items"]) == (1, 2, 60)
    second = client.get("/services/payments-service?page=2&page_size=50")
    assert len(page_data(second)["findings"]) == 10
    assert (page_data(second)["page"], page_data(second)["total_pages"]) == (2, 2)


def test_service_finding_filters_combine_and_reset_pagination():
    client = new_client()
    ingest(client)
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        db.add_all([
            Finding(service_id=service.id, cve="CVE-FILTER-CRITICAL", severity="Critical", first_seen=now, episode_started=now, last_seen=now, active=True),
            Finding(service_id=service.id, cve="CVE-FILTER-HIGH", severity="High", first_seen=now, episode_started=now, last_seen=now, active=True),
            Finding(service_id=service.id, cve="CVE-FILTER-LOW", severity="Low", first_seen=now, episode_started=now, last_seen=now, active=True),
            *[Finding(service_id=service.id, cve=f"CVE-BULK-CRIT-{number:03d}", severity="Critical", first_seen=now, episode_started=now, last_seen=now, active=True) for number in range(55)],
        ])
        db.commit()
    response = client.get("/services/payments-service?page=4&page_size=50&severity=Critical&severity=High&q=FILTER")
    assert response.status_code == 200
    assert "CVE-FILTER-CRITICAL" in response.text and "CVE-FILTER-HIGH" in response.text
    assert "CVE-FILTER-LOW" not in response.text
    assert (page_data(response)["page"], page_data(response)["total_items"], page_data(response)["total_pages"]) == (1, 2, 1)
    assert page_data(response)["query"] == "FILTER"
    assert page_data(response)["severity"] == ["Critical", "High"]
    response = client.get("/services/payments-service?page_size=50&severity=Critical")
    assert response.status_code == 200
    assert page_data(response)["total_pages"] == 2
    assert page_data(response)["pagination_base"] == "/services/payments-service?overview=false&finding_state=active&finding_type=all&page_size=50&severity=Critical"


def test_risk_overlay_filters_active_findings_before_age_drives_noncompliance():
    client = new_client()
    ingest(client, cves=["CVE-KEV-MATCH", "CVE-EPSS-MATCH", "CVE-NO-MATCH"])
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        group = Group(name="Risk Overlay Group")
        service.groups.append(group)
        db.add(group)
        db.flush()
        findings = {finding.cve: finding for finding in service.findings}
        kev_observation = findings["CVE-KEV-MATCH"].observations[-1]
        epss_observation = findings["CVE-EPSS-MATCH"].observations[-1]
        kev_observation.evidence = {**kev_observation.evidence, "kev": True}
        epss_observation.evidence = {**epss_observation.evidence, "epss": 0.95}
        for key, value in {
            "compliance_mode": "risk_based",
            "overdue_days": "90",
            "minimum_severity": "None",
            "kev_enabled": "true",
            "kev_noncompliant": "true",
            "epss_enabled": "true",
            "epss_rules": '[{"severity":"Any","threshold":0.9,"noncompliant":true}]',
        }.items():
            db.add(PortalSetting(key=f"group:{group.id}:{key}", group_id=group.id, value=value))
        db.commit()

    active = client.get("/services/payments-service?finding_state=active")
    assert "CVE-KEV-MATCH" in active.text
    assert "CVE-EPSS-MATCH" in active.text
    assert "CVE-NO-MATCH" not in active.text
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["finding_counts"]["active"] == 2
    assert page_data(overview)["finding_counts"]["noncompliant"] == 0

    with SessionLocal() as db:
        for finding in db.scalars(select(Finding)).all():
            finding.episode_started = now - timedelta(days=100)
        db.commit()
    noncompliant = client.get("/services/payments-service?finding_state=noncompliant")
    assert "CVE-KEV-MATCH" in noncompliant.text
    assert "CVE-EPSS-MATCH" in noncompliant.text
    assert "CVE-NO-MATCH" not in noncompliant.text
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["finding_counts"]["active"] == 0
    assert page_data(overview)["finding_counts"]["noncompliant"] == 2
    service_row = page_data(client.get("/"))["views"][0]
    assert service_row["noncompliant_count"] == 2


def test_administrator_can_edit_service_metadata():
    client = new_client(); ingest(client)
    detail = page_data(client.get("/services/payments-service"))
    service_id = str(detail["view"]["service"]["id"])
    assert detail["can"]["service.edit"][service_id]
    assert detail["can"]["archive.request"][service_id]
    overview = page_data(client.get("/services/payments-service?overview=true"))
    assert overview["can"]["service.edit"][service_id]
    assert overview["can"]["archive.request"][service_id]
    response = client.post("/admin/services/payments-service", data={
        "csrf_token": csrf(client), "name": "Payments Platform", "owner": "Cyber Team",
        "description": "Payments service metadata", "poc": "owner@example.invalid", "manual_version": "3.0",
    }, follow_redirects=False)
    assert response.status_code == 303
    page = client.get("/services/payments-service").text
    assert "Payments Platform" in page and "3.0" in page and "Payments service metadata" in page


def test_edit_service_preserves_service_tab_query_rename_and_confirmation():
    client = new_client(); ingest(client)
    destinations = [
        "/services/payments-service?overview=true",
        "/services/payments-service?architecture=true",
        "/services/payments-service?artifacts=true",
        "/services/payments-service?validation=true&validation_run=run-7",
        "/services/payments-service?findings=true&findings_view=raw&q=openssl&severity=HIGH&page=3&page_size=25",
        "/services/payments-service?remediations=true&tab=pipeline",
        "/services/payments-service?activity=true",
    ]
    for index, destination in enumerate(destinations):
        response = client.post("/admin/services/payments-service", data={
            "csrf_token": csrf(client),
            "name": f"Payments Platform {index}",
            "return_to": destination,
        }, follow_redirects=False)
        assert response.status_code == 303
        location = response.headers["location"]
        parsed = urllib.parse.urlsplit(location)
        assert parsed.path == "/services/payments-service"
        expected_query = urllib.parse.parse_qsl(urllib.parse.urlsplit(destination).query, keep_blank_values=True)
        assert urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) == expected_query + [("saved", "1")]

    # The display-name rename does not alter the stable service route, and the
    # shared service shell renders confirmation on the preserved destination.
    page = client.get(response.headers["location"])
    assert page.status_code == 200
    assert "Payments Platform 6" in page.text
    assert page_data(page)["saved"]


def test_findings_filter_controls_and_view_selector_keep_expected_contract():
    client = new_client(); ingest(client)
    raw = client.get(
        "/services/payments-service?findings=true&findings_view=raw&q=CVE&severity=Critical&resource=registry&page=1&page_size=50"
    )
    assert raw.status_code == 200
    data = page_data(raw)
    assert data["query"] == "CVE"
    assert data["severity"] == ["Critical"]
    assert data["resource"] == "registry"
    assert data["selected_findings_view"] == "raw"
    assert data["page_size"] == 50

    simplified = client.get("/services/payments-service?findings=true&findings_view=simplified&page_size=50")
    assert simplified.status_code == 200
    assert page_envelope(simplified)["page"] == "service_simplified"
    assert page_data(simplified)["selected_findings_view"] == "simplified"

    css = (Path(__file__).parents[1] / "app" / "static" / "app.css").read_text(encoding="utf-8")
    assert "--finding-filter-height:42px" in css
    assert ".finding-view-selector{display:inline-flex" in css
    assert "margin:0 0 .75rem" in css


def test_simplified_findings_offer_per_cve_actions_without_view_raw():
    client = new_client()
    assert ingest(client, cves=["CVE-2099-0002", "CVE-2099-0001"]).status_code == 201
    page = client.get("/services/payments-service?findings_view=simplified")
    assert page.status_code == 200
    data = page_data(page)
    assert page_envelope(page)["page"] == "service_simplified"
    service_id = str(data["view"]["service"]["id"])
    assert data["can"]["exception.request"][service_id]
    assert data["can"]["poam.request"][service_id]
    with SessionLocal() as db:
        findings = {finding.cve: finding.id for finding in db.scalars(select(Finding)).all()}
    for cve, finding_id in findings.items():
        members = []
        for row in data["simplified_findings"]:
            assert 'finding_ids' not in row and 'cves' not in row
            response = client.get(f"/api/v1/services/payments-service/findings/simplified/{row['group_id']}/members")
            assert response.status_code == 200
            members.extend(response.json()['items'])
        assert any(item['id'] == finding_id and item['cve'] == cve for item in members)



def _helm_chart_archive(name: str, extra_name: str = "templates/deployment.yaml", extra_content: str = "apiVersion: apps/v1\nkind: Deployment\n") -> bytes:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        for path, content in {
            f"{name}/Chart.yaml": f"apiVersion: v2\nname: {name}\nversion: 1.0.0\n",
            f"{name}/{extra_name}": extra_content,
        }.items():
            data = content.encode()
            member = tarfile.TarInfo(path)
            member.size = len(data)
            bundle.addfile(member, BytesIO(data))
    return output.getvalue()


def test_artifacts_page_exposes_first_class_helm_and_kubernetes_workflow():
    client = new_client(); ingest(client)
    page = client.get("/services/payments-service?artifacts=true")
    assert page.status_code == 200
    assert page_envelope(page)["page"] == "service_artifacts"
    assert page_data(page)["can_edit"]
    assert page_data(page)["csrf_token"] == csrf(client)
    assert page_data(page)["manifest_count"] == 0
    assert page_data(page)["artifact_rows"] == []


def test_artifacts_page_lists_helm_charts_from_retained_scan_without_persisting_copies():
    client = new_client()
    body = helm_payload()
    body.update({"artifact_type": "helm", "helm_source_files": {
        "demo/Chart.yaml": "apiVersion: v2\nname: demo\nversion: 1.0.0\n",
        "demo/values.yaml": "password: must-not-expose",
    }})
    response = client.post("/api/v1/pipeline-results", headers=pipeline_headers, json=body)
    assert response.status_code == 201
    page = client.get("/services/payments-service?artifacts=true")
    assert page.status_code == 200
    data = page_data(page)
    assert data["chart_count"] == data["scan_chart_count"] == 1
    row = data["artifact_rows"][0]
    assert row["artifact"]["chart_name"] == "demo"
    assert row["artifact"]["chart_version"] == "1.0.0"
    assert row["retained_scan"] and row["file_count"] == 2
    assert "must-not-expose" not in str(data)
    with SessionLocal() as db:
        assert db.scalar(select(ServiceArtifact)) is None


def test_service_artifact_acquisition_reuses_multi_chart_repository_pipeline(monkeypatch):
    from app import main as portal_main
    client = new_client(); ingest(client)
    catalog = {"repository_url": "https://charts.example.invalid/helm-charts", "index_url": "https://charts.example.invalid/helm-charts/index.yaml", "api_version": "v1", "generated": "now", "charts": [
        {"name": "alpha", "latest": {"version": "1.0.0", "url": "https://charts.example.invalid/alpha.tgz"}, "versions": [{"version": "1.0.0", "url": "https://charts.example.invalid/alpha.tgz"}]},
        {"name": "beta", "latest": {"version": "2.0.0", "url": "https://charts.example.invalid/beta.tgz"}, "versions": [{"version": "2.0.0", "url": "https://charts.example.invalid/beta.tgz"}]},
    ]}
    monkeypatch.setattr(portal_main, "_discover_helm_repository", lambda reference, certificates: catalog)
    response = client.post("/services/payments-service/artifacts/acquire", data={
        "csrf_token": csrf(client), "artifact_type": "helm_repository", "source_method": "repository",
        "source_reference": "https://charts.example.invalid/helm-charts",
    }, follow_redirects=False)
    assert response.status_code == 303 and "artifact_added=repository" in response.headers["location"]
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        repository = db.scalar(select(ServiceArtifact).where(ServiceArtifact.service_id == service.id, ServiceArtifact.artifact_type == "helm_repository"))
        charts = db.scalars(select(ServiceArtifact).where(ServiceArtifact.parent_repository_id == repository.id).order_by(ServiceArtifact.chart_name)).all()
        assert repository.source_reference == catalog["repository_url"] and repository.source_metadata["chart_count"] == 2
        assert [(chart.chart_name, chart.chart_version) for chart in charts] == [("alpha", "1.0.0"), ("beta", "2.0.0")]
        assert all(not chart.revisions for chart in charts)
        alpha_id = charts[0].id
    page = client.get("/services/payments-service?artifacts=true")
    data = page_data(page)
    assert data["repository_count"] == 1 and data["chart_count"] == 2
    charts = [row for row in data["artifact_rows"] if row["artifact"]["artifact_type"] == "helm_chart"]
    assert {row["artifact"]["chart_name"] for row in charts} == {"alpha", "beta"}
    assert all(row["revision"] is None for row in charts)
    assert any(row["artifact"]["source_reference"] == catalog["repository_url"] for row in data["artifact_rows"])
    monkeypatch.setattr(portal_main, "_download_public_chart", lambda reference, certificates: [(_helm_chart_archive("alpha"), "alpha-1.0.0.tgz")])
    materialized = client.post(f"/services/payments-service/artifacts/charts/{alpha_id}/materialize", data={"csrf_token": csrf(client), "version": "1.0.0"}, follow_redirects=False)
    assert materialized.status_code == 303
    with SessionLocal() as db:
        revisions = db.scalars(select(ServiceArtifactRevision).where(ServiceArtifactRevision.artifact_id == alpha_id)).all()
        assert len(revisions) == 1 and revisions[0].source_metadata["repository_id"] == repository.id
        assert revisions[0].source_metadata["chart_version"] == "1.0.0"


def test_packaged_helm_and_existing_kubernetes_uploads_are_retained_and_rbac_enforced():
    client = new_client(); ingest(client)
    response = client.post("/services/payments-service/artifacts/acquire", data={
        "csrf_token": csrf(client), "artifact_type": "helm", "source_method": "upload",
    }, files={"files": ("application-1.0.0.tgz", _helm_chart_archive("application"), "application/gzip")}, follow_redirects=False)
    assert response.status_code == 303
    manifests = client.post("/services/payments-service/artifacts/upload", data={
        "csrf_token": csrf(client), "artifact_type": "kubernetes",
    }, files={"files": ("deployment.yaml", b"apiVersion: apps/v1\nkind: Deployment\n", "text/yaml")}, follow_redirects=False)
    assert manifests.status_code == 303
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id).where(Service.service_key == "payments-service"))
        artifacts = db.scalars(select(ServiceArtifact).where(ServiceArtifact.service_id == service_id)).all()
        assert {artifact.artifact_type for artifact in artifacts} == {"helm_chart", "kubernetes"}
    add_user("artifact-viewer", "Assessor", service_id=service_id)
    viewer = new_client("artifact-viewer")
    denied = viewer.post("/services/payments-service/artifacts/acquire", data={
        "csrf_token": csrf(viewer), "artifact_type": "helm", "source_method": "upload",
    }, files={"files": ("blocked.tgz", _helm_chart_archive("blocked"), "application/gzip")})
    assert denied.status_code == 403


def test_helm_archive_traversal_and_links_are_rejected():
    client = new_client(); ingest(client)
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        member = tarfile.TarInfo("../../outside/Chart.yaml")
        data = b"name: unsafe\nversion: 1\n"
        member.size = len(data)
        bundle.addfile(member, BytesIO(data))
    response = client.post("/services/payments-service/artifacts/acquire", data={
        "csrf_token": csrf(client), "artifact_type": "helm", "source_method": "upload",
    }, files={"files": ("unsafe.tgz", output.getvalue(), "application/gzip")},
        headers={"accept": "application/json"})
    assert response.status_code == 400
    assert "unsafe path" in response.json()["detail"]

    linked = BytesIO()
    with tarfile.open(fileobj=linked, mode="w:gz") as bundle:
        chart = tarfile.TarInfo("unsafe/Chart.yaml")
        chart_data = b"name: unsafe\nversion: 1\n"
        chart.size = len(chart_data)
        bundle.addfile(chart, BytesIO(chart_data))
        symlink = tarfile.TarInfo("unsafe/templates/escape.yaml")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../outside.yaml"
        bundle.addfile(symlink)
    response = client.post("/services/payments-service/artifacts/acquire", data={
        "csrf_token": csrf(client), "artifact_type": "helm", "source_method": "upload",
    }, files={"files": ("linked.tgz", linked.getvalue(), "application/gzip")},
        headers={"accept": "application/json"})
    assert response.status_code == 400
    assert "unsafe link" in response.json()["detail"]


def test_helm_repository_and_tls_failures_are_specific_and_secure(monkeypatch):
    from app import main as portal_main
    client = new_client(); ingest(client)
    real_fetch = portal_main._fetch_public_url
    monkeypatch.setattr(portal_main, "_fetch_public_url", lambda url, certificates=None: (b"not a helm index", url))
    invalid = client.post("/services/payments-service/artifacts/acquire", data={
        "csrf_token": csrf(client), "artifact_type": "helm", "source_method": "repository",
        "source_reference": "https://charts.example.invalid",
    }, headers={"accept": "application/json"})
    assert invalid.status_code == 400
    assert "valid index.yaml" in invalid.json()["detail"]
    browser_invalid = client.post("/services/payments-service/artifacts/acquire", data={
        "csrf_token": csrf(client), "artifact_type": "helm", "source_method": "repository",
        "source_reference": "https://charts.example.invalid",
    }, headers={"accept": "text/html"})
    assert browser_invalid.status_code == 400
    assert "valid index.yaml" in browser_invalid.text
    assert "You've been boozled." not in browser_invalid.text

    monkeypatch.setattr(portal_main, "_fetch_public_url", real_fetch)
    def tls_failure(*_args, **_kwargs):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("untrusted issuer"))
    monkeypatch.setattr(portal_main.urllib.request, "urlopen", tls_failure)
    with __import__("pytest").raises(__import__("fastapi").HTTPException) as raised:
        portal_main._fetch_public_url("https://private.example.invalid/chart.tgz", [])
    assert "TLS certificate verification failed" in raised.value.detail
    source = Path(portal_main.__file__).read_text(encoding="utf-8")
    assert "--insecure-skip-tls-verify" not in source


def test_uploaded_helm_revision_is_directly_available_to_deployment_validation(monkeypatch):
    from app import main as portal_main
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    submitted = []
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda run_id: submitted.append(run_id))
    client = new_client()
    with SessionLocal() as db:
        db.add(Service(service_key="artifact-only", name="Artifact Only"))
        db.commit()
    added = client.post("/services/artifact-only/artifacts/acquire", data={
        "csrf_token": csrf(client), "artifact_type": "helm", "source_method": "upload",
    }, files={"files": ("application.tgz", _helm_chart_archive("application"), "application/gzip")}, follow_redirects=False)
    assert added.status_code == 303
    with SessionLocal() as db:
        artifact = db.scalar(select(ServiceArtifact).join(Service).where(Service.service_key == "artifact-only"))
        revision = db.scalar(select(ServiceArtifactRevision).where(ServiceArtifactRevision.artifact_id == artifact.id))
        artifact_id, revision_id = artifact.id, revision.id
    validation = client.post("/services/artifact-only/deployment-validations", data={
        "csrf_token": csrf(client), "artifact_id": str(artifact_id),
    }, follow_redirects=False)
    assert validation.status_code == 303
    with SessionLocal() as db:
        run = db.scalar(select(DeploymentValidationRun).where(DeploymentValidationRun.service_id == select(Service.id).where(Service.service_key == "artifact-only").scalar_subquery()))
        assert run.artifact_revision_id == revision_id and run.execution_id is None
        assert run.status == "QUEUED" and submitted == [run.id]


def test_artifact_validation_badge_is_exact_revision_safe(monkeypatch):
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    client = new_client()
    with SessionLocal() as db:
        service = Service(service_key="revision-safe", name="Revision Safe")
        db.add(service); db.flush()
        artifact = ServiceArtifact(service_id=service.id, artifact_type="helm_chart", artifact_name="application",
                                   chart_name="application", chart_version="1.2.0", source_type="upload")
        db.add(artifact); db.flush()
        original = ServiceArtifactRevision(artifact_id=artifact.id, revision_number=1, revision_label="ORIGINAL",
            files={"application/Chart.yaml": "name: application\nversion: 1.2.0\n"}, checksum="a" * 64)
        db.add(original); db.flush()
        db.add(DeploymentValidationRun(run_key="validated-original", service_id=service.id,
            artifact_revision_id=original.id, artifact_type="WORKING", artifact_reference=f"artifact:{artifact.id}:r1",
            status="VERIFIED", phase="COMPLETE", cleanup_status="COMPLETE"))
        db.commit(); artifact_id = artifact.id
    page = client.get("/services/revision-safe?artifacts=true")
    assert page_data(page)["artifact_rows"][0]["validation"]["label"] == "Validated"
    assert page_data(page)["can_validate"]
    with SessionLocal() as db:
        db.add(ServiceArtifactRevision(artifact_id=artifact_id, revision_number=2, revision_label="WORKING",
            files={"application/Chart.yaml": "name: application\nversion: 1.2.0\n", "application/values.yaml": "replicas: 2\n"}, checksum="b" * 64))
        db.commit()
    page = client.get("/services/revision-safe?artifacts=true")
    row = page_data(page)["artifact_rows"][0]
    assert row["validation"]["label"] == "Not Validated"
    assert (row["revision"]["revision_label"], row["revision"]["revision_number"]) == ("WORKING", 2)
    assert "validated-original" not in page.text


def test_service_snapshot_separates_staged_services_from_active_and_archived():
    client = new_client()
    with SessionLocal() as db:
        group = Group(name="Staged Services")
        db.add(group)
        db.commit()
        group_id = group.id
    response = client.post("/admin/services/stage", data={
        "csrf_token": csrf(client), "service_id": "helm-test", "group_id": str(group_id), "next_path": "/",
    }, follow_redirects=False)
    assert response.status_code == 303
    default = client.get("/")
    assert "helm-test" not in [view["service"]["service_key"] for view in page_data(default)["views"]]
    assert page_data(default)["lifecycle_counts"]["staged"] == 1
    staged = client.get("/?lifecycle=staged&q=helm-test&sort=name")
    assert staged.status_code == 200
    assert "helm-test" in [view["service"]["service_key"] for view in page_data(staged)["views"]]
    assert page_data(staged)["lifecycle_counts"]["staged"] == 1
    assert page_data(staged)["lifecycle"] == "staged"
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "helm-test"))
        assert service.lifecycle_status == "staged"
    ingested = ingest(client, execution="helm-test-run", service_id="helm-test")
    assert ingested.status_code == 201
    assert "helm-test" in [view["service"]["service_key"] for view in page_data(client.get("/"))["views"]]
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "helm-test"))
        assert service.lifecycle_status == "active"


def test_staged_service_promotes_on_any_ingested_finding_or_evidence():
    client = new_client()
    with SessionLocal() as db:
        group = Group(name="Ingest Promotion")
        db.add(group)
        db.commit()
        group_id = group.id

    response = client.post("/admin/services/stage", data={
        "csrf_token": csrf(client), "service_id": "staged-evidence", "group_id": str(group_id), "next_path": "/",
    }, follow_redirects=False)
    assert response.status_code == 303

    data = payload("staged-evidence-run", datetime.now(timezone.utc), ["CVE-2026-9999"], service_id="staged-evidence")
    data["policy_findings"] = [{
        "finding": "KSV-999", "severity": "High", "target": "Deployment/staged-evidence",
    }]
    data["service_overview"] = {
        "images": [{"image": "registry.example/staged-evidence:1", "digest": "sha256:" + "a" * 64}],
        "artifacts": [{"type": "chart", "name": "staged-evidence", "version": "1.0.0"}],
    }
    ingested = client.post("/api/v1/pipeline-results", json=data, headers=pipeline_headers)
    assert ingested.status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "staged-evidence"))
        assert service.lifecycle_status == "active"
        promotion = db.scalar(select(AuditEvent).where(
            AuditEvent.action == "service.promoted", AuditEvent.target_id == str(service.id),
        ))
        assert promotion is not None
        assert promotion.detail["reason"] == "ingested_evidence"


def test_generated_staged_name_is_restored_idempotently_without_changing_identity_or_evidence():
    client = new_client()
    with SessionLocal() as db:
        group = Group(name="Lifecycle Identity")
        db.add(group); db.commit()
        group_id = group.id
    staged = client.post("/admin/services/stage", data={
        "csrf_token": csrf(client), "service_id": "torture-test", "group_id": str(group_id), "next_path": "/",
    }, follow_redirects=False)
    assert staged.status_code == 303
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "torture-test"))
        service_id = service.id
        assert service.name == "Staged — torture-test"
        assert service.staging_name_generated is True and service.staging_original_name == "torture-test"

    body = helm_payload("torture-lifecycle-run", "torture-test")
    # Reproduce the reported client behavior: the submitted display name still
    # contains CATS' generated staging label.
    body["service"]["name"] = "Staged — torture-test"
    body["findings"] = [{"cve": "CVE-2026-4242", "severity": "High", "image": "registry/torture:1"}]
    response = client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers)
    assert response.status_code == 201

    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "torture-test"))
        execution = db.scalar(select(Execution).where(Execution.service_id == service.id))
        finding = db.scalar(select(Finding).where(Finding.service_id == service.id))
        assert service.id == service_id and service.lifecycle_status == "active"
        assert service.name == "torture-test"
        assert service.staging_name_generated is False and service.staging_original_name is None
        assert execution.service_id == service_id and finding.service_id == service_id
        db.add(DeploymentValidationRun(
            run_key="DV-LIFECYCLE-VERIFIED", service_id=service.id, execution_id=execution.id,
            artifact_type="ORIGINAL", artifact_reference=execution.execution_key,
            status="VERIFIED", phase="COMPLETE", engine="kind", completed_at=datetime.now(timezone.utc),
            diagnostics={"classification_summary": {"expected_resources": 1, "observed_expected": 1,
                                                       "expected_only": 0, "failed": 0}},
        ))
        db.commit()

    evidence = client.get("/api/v1/services/torture-test/architecture-evidence")
    assert evidence.status_code == 200 and evidence.json()["architecture"]["state"] == "VERIFIED"
    for url in (
        "/services/torture-test?overview=true", "/services/torture-test?architecture=true",
        "/services/torture-test?artifacts=true", "/services/torture-test?validation=true",
        "/services/torture-test?remediations=true",
    ):
        page = client.get(url)
        assert page.status_code == 200 and "Staged — torture-test" not in page.text
    activity = client.get("/services/torture-test?activity=true")
    assert activity.status_code == 200 and "torture-test" in activity.text
    assert "Staged — torture-test" in activity.text  # immutable name-at-event audit context

    # A retry is idempotent and cannot modify the restored name.
    duplicate = client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers)
    assert duplicate.status_code == 201 and duplicate.json()["duplicate"] is True
    with SessionLocal() as db:
        service = db.get(Service, service_id)
        assert service.name == "torture-test" and service.lifecycle_status == "active"


def test_user_owned_staged_prefix_is_never_stripped_without_generation_metadata():
    client = new_client()
    with SessionLocal() as db:
        service = Service(service_key="production-app", name="Staged — Production Application",
                          lifecycle_status="staged", staging_name_generated=False)
        db.add(service); db.commit(); service_id = service.id
    body = payload("production-app-run", datetime.now(timezone.utc), [], service_id="production-app")
    body["service"]["name"] = "Staged — Production Application"
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.get(Service, service_id)
        assert service.lifecycle_status == "active"
        assert service.name == "Staged — Production Application"


def test_startup_reconciles_preexisting_staged_evidence():
    from app import main as portal_main

    with SessionLocal() as db:
        service = Service(service_key="legacy-staged", name="Staged — legacy-staged", lifecycle_status="staged")
        db.add(service)
        db.flush()
        db.add(Execution(
            execution_key="legacy-staged-run", service_id=service.id,
            scanned_at=datetime.now(timezone.utc), complete=True,
            raw_payload={"service": {"id": "legacy-staged"}, "findings": [], "service_overview": {"artifacts": [{"type": "chart"}]}},
        ))
        db.commit()

    assert portal_main.promote_staged_services_with_evidence() == 1
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "legacy-staged"))
        assert service.lifecycle_status == "active"
        promotion = db.scalar(select(AuditEvent).where(
            AuditEvent.action == "service.promoted", AuditEvent.target_id == str(service.id),
        ))
        assert promotion is not None
        assert promotion.detail["reason"] == "existing_ingested_evidence"


def test_service_manager_scope_and_exception_approval_separation():
    admin = new_client()
    ingest(admin, cves=["CVE-2026-0001"])
    ingest(admin, "run-other", [], service_id="other-service")
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        finding = db.scalar(select(Finding).where(Finding.service_id == service.id))
        service_id, finding_id = service.id, finding.id
    add_user("manager", "Service Manager", service_id)
    manager = new_client("manager")
    names = [view["service"]["name"] for view in page_data(manager.get("/"))["views"]]
    assert "Payments Service" in names and "Other Service" not in names
    expiry = datetime.now(timezone.utc) + timedelta(days=30)
    requested = manager.post(f"/findings/{finding_id}/exceptions", data={
        "csrf_token": csrf(manager), "justification": "Vendor remediation scheduled",
        "expires_at": expiry.isoformat(), "ticket": "RISK-42",
    }, follow_redirects=False)
    assert requested.status_code == 303
    with SessionLocal() as db:
        workflow_id = db.scalar(select(WorkflowRequest.id))
    assert manager.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(manager), "decision": "approved"}).status_code == 403
    add_user("cyber", "Cybersecurity")
    cyber = new_client("cyber")
    assert cyber.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(cyber), "decision": "approved"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        exception_id = db.scalar(select(ExceptionRecord.id))
    assert cyber.post(f"/exceptions/{exception_id}/revoke", data={"csrf_token": csrf(cyber)}, follow_redirects=False).status_code == 303
    assert any(row["status"] == "revoked" for row in page_data(cyber.get("/requests"))["workflows"])


def test_service_workspace_exposes_embedded_poam_and_activity_tabs():
    client = new_client()
    ingest(client, cves=["CVE-2026-0099"])
    poam = client.get("/services/payments-service?poam=true")
    assert poam.status_code == 200
    assert page_data(poam)["service"]["name"] == "Payments Service"
    assert page_data(poam)["embedded"]
    activity = client.get("/services/payments-service?activity=true")
    assert activity.status_code == 200
    assert page_envelope(activity)["page"] == "service_activity"
    assert any(row["action"] == "scan.ingested" for row in page_data(activity)["events"])


def test_poam_is_scoped_and_requires_cybersecurity_approval():
    admin = new_client()
    ingest(admin, cves=["CVE-2026-0002"])
    ingest(admin, "other-run", [], service_id="other-service")
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        other = db.scalar(select(Service).where(Service.service_key == "other-service"))
        finding = db.scalar(select(Finding).where(Finding.service_id == service.id))
        finding.episode_started = datetime.now(timezone.utc) - timedelta(days=100)
        service_id, other_id, finding_id = service.id, other.id, finding.id
        db.commit()
    add_user("poam-manager", "Service Manager", service_id)
    manager = new_client("poam-manager")
    poam_index = manager.get("/poam").text
    assert page_data(manager.get("/poam/services/payments-service"))["can_create_poam"]
    assert "Payments Service" in poam_index and "Other Service" not in poam_index
    assert manager.get("/poam/services/other-service").status_code == 403
    service_poam = manager.get("/poam/services/payments-service")
    assert service_poam.status_code == 200
    assert page_data(service_poam)["service"]["name"] == "Payments Service"
    noncompliant_page = page_data(manager.get("/services/payments-service?finding_state=noncompliant"))
    assert noncompliant_page["can"]["poam.request"][str(service_id)]
    assert any(row["finding_id"] == finding_id for row in noncompliant_page["noncompliance_items"])
    created = manager.post("/poam", data={
        "csrf_token": csrf(manager), "service_id": service_id, "item_type": "missing_evidence",
        "title": "Missing authorization evidence", "description": "Authorization package is absent",
        "remediation": "Upload signed authorization package", "ticket": "POAM-7", "finding_id": "",
    }, follow_redirects=False)
    assert created.status_code == 303
    forbidden = manager.post("/poam", data={
        "csrf_token": csrf(manager), "service_id": other_id, "item_type": "missing_requirement",
        "title": "Out of scope", "description": "Should not be accepted", "remediation": "None",
    })
    assert forbidden.status_code == 403
    vulnerability = manager.post(f"/findings/{finding_id}/poams", data={
        "csrf_token": csrf(manager), "title": "Patch vulnerability", "remediation": "Deploy fixed image",
    }, follow_redirects=False)
    assert vulnerability.status_code == 303
    with SessionLocal() as db:
        entries = db.scalars(select(PoamEntry).order_by(PoamEntry.id)).all()
        assert [entry.status for entry in entries] == ["pending_approval", "pending_approval"]
        workflow_id = db.scalar(select(WorkflowRequest.id).where(WorkflowRequest.poam_id == entries[0].id))
    assert manager.post(f"/requests/{workflow_id}/review", data={
        "csrf_token": csrf(manager), "decision": "approved",
    }).status_code == 403
    add_user("poam-cyber", "Cybersecurity")
    cyber = new_client("poam-cyber")
    assert cyber.post(f"/requests/{workflow_id}/review", data={
        "csrf_token": csrf(cyber), "decision": "approved",
    }, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        entry = db.get(PoamEntry, entries[0].id)
        assert entry.status == "active" and entry.approved_by_id is not None
    detail = page_data(cyber.get("/poam/services/payments-service"))
    assert any(row["title"] == "Missing authorization evidence" and row["status"] == "active" for row in detail["entries"])
    updated = manager.post(f"/poam/entries/{entries[0].id}/update", data={
        "csrf_token": csrf(manager), "title": "Updated authorization evidence",
        "description": "The authorization package remains incomplete",
        "remediation": "Upload and validate the signed authorization package", "due_date": "",
        "ticket": "POAM-8", "reason": "Milestones changed",
    }, follow_redirects=False)
    assert updated.status_code == 303
    with SessionLocal() as db:
        update_workflow = db.scalar(select(WorkflowRequest).where(WorkflowRequest.request_type == "poam_update"))
    assert cyber.post(f"/requests/{update_workflow.id}/review", data={
        "csrf_token": csrf(cyber), "decision": "approved", "review_reason": "Update validated",
    }, follow_redirects=False).status_code == 303
    assert "Updated authorization evidence" in cyber.get(f"/poam/entries/{entries[0].id}").text
    completed = manager.post(f"/poam/entries/{entries[0].id}/complete", data={
        "csrf_token": csrf(manager), "closure_note": "Authorization package supplied and validated",
        "evidence_reference": "EVIDENCE-2026-42",
    }, follow_redirects=False)
    assert completed.status_code == 303
    with SessionLocal() as db:
        complete_workflow = db.scalar(select(WorkflowRequest).where(WorkflowRequest.request_type == "poam_complete"))
    assert cyber.post(f"/requests/{complete_workflow.id}/review", data={
        "csrf_token": csrf(cyber), "decision": "approved", "review_reason": "Evidence verified",
    }, follow_redirects=False).status_code == 303
    completed_page = page_data(cyber.get(f"/poam/entries/{entries[0].id}"))
    assert completed_page["entry"]["status"] == "completed"
    assert "EVIDENCE-2026-42" in json.dumps(completed_page["history"])
    assert manager.post(f"/poam/entries/{entries[0].id}/reopen", data={
        "csrf_token": csrf(manager), "reason": "New evidence gap was identified",
    }, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        reopen_workflow = db.scalar(select(WorkflowRequest).where(WorkflowRequest.request_type == "poam_reopen"))
    assert cyber.post(f"/requests/{reopen_workflow.id}/review", data={
        "csrf_token": csrf(cyber), "decision": "approved", "review_reason": "Reopen approved",
    }, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        assert db.get(PoamEntry, entries[0].id).status == "active"
    export = cyber.get("/poam/services/payments-service/export.xlsx")
    assert export.status_code == 200
    export_sheet = load_workbook(BytesIO(export.content))["POA&M"]
    assert "Updated authorization evidence" in [cell.value for cell in export_sheet["D"]]
    add_user("poam-assessor", "Assessor")
    assessor = new_client("poam-assessor")
    assessor_index = assessor.get("/poam").text
    assert "Payments Service" in assessor_index and "Other Service" in assessor_index
    assert not page_data(assessor.get("/poam/services/payments-service"))["can_create_poam"]


def test_audit_logs_default_to_ten_and_expand_within_retention():
    client = new_client()
    with SessionLocal() as db:
        for number in range(250):
            db.add(AuditEvent(action=f"test.event.{number}", target_type="test", target_id=str(number)))
        db.commit()
    default_page = client.get("/admin/audit")
    assert default_page.status_code == 200
    assert page_data(default_page)["shown_count"] == 10
    assert sum(row["action"].startswith("test.event.") for row in page_data(default_page)["events"]) == 10
    expanded = client.get("/admin/audit?show=60")
    assert sum(row["action"].startswith("test.event.") for row in page_data(expanded)["events"]) == 60
    assert page_data(expanded)["shown_count"] > 10


    full = page_data(client.get("/admin/audit?full=true"))
    assert full["shown_count"] == 200
    assert full["page_size"] == 200
    assert full["page_count"] == 2
    older = page_data(client.get("/admin/audit?page=2&page_size=200"))
    assert not ({row["id"] for row in full["events"]} & {row["id"] for row in older["events"]})



def test_archive_requires_request_and_separate_approval():
    admin = new_client(); ingest(admin)
    requested = admin.post("/services/payments-service/archive", data={"csrf_token": csrf(admin), "reason": "Retired"}, follow_redirects=False)
    assert requested.status_code == 303
    with SessionLocal() as db:
        workflow_id = db.scalar(select(WorkflowRequest.id))
    assert admin.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(admin), "decision": "approved"}).status_code == 409
    add_user("cyber", "Cybersecurity")
    cyber = new_client("cyber")
    assert cyber.post(f"/requests/{workflow_id}/review", data={"csrf_token": csrf(cyber), "decision": "approved"}, follow_redirects=False).status_code == 303
    assert "Payments Service" in [view["service"]["name"] for view in page_data(cyber.get("/?archived=true"))["views"]]


def test_admin_can_create_account_custom_role_and_assignment():
    client = new_client(); ingest(client)
    assert client.post("/admin/users", data={"csrf_token": csrf(client), "username": "assessor1", "display_name": "Assessor One", "password": "temporary-password"}, follow_redirects=False).status_code == 303
    assert client.post("/admin/roles", data={"csrf_token": csrf(client), "name": "Evidence Exporter", "description": "Exports evidence", "permissions": ["service.view", "service.export"]}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "assessor1")); role = db.scalar(select(Role).where(Role.name == "Evidence Exporter"))
    assert client.post("/admin/assignments", data={"csrf_token": csrf(client), "user_id": user.id, "role_id": role.id, "service_id": ""}, follow_redirects=False).status_code == 303


def test_reset_password_dialog_is_not_constrained_as_a_table_action():
    css = (Path(__file__).parents[1] / "app" / "static" / "app.css").read_text(encoding="utf-8")
    assert ".account-actions > form,.account-actions > button" in css
    assert ".account-actions form,.account-actions > button" not in css
    assert ".account-actions form button" not in css


def test_excel_export_remains_valid():
    client = new_client(); ingest(client, cves=["CVE-2026-0001"])
    service_page = page_data(client.get("/services/payments-service"))
    assert service_page["can"]["service.export"][str(service_page["view"]["service"]["id"])]
    overview_page = page_data(client.get("/services/payments-service?overview=true"))
    assert overview_page["can"]["service.export"][str(overview_page["view"]["service"]["id"])]
    assert overview_page["view"]["service"]["service_key"] == "payments-service"
    diagram = client.get("/services/payments-service/helm-diagram.svg")
    assert diagram.status_code == 200
    assert diagram.headers["content-type"].startswith("image/svg+xml")
    assert "Helm rendering" in diagram.text
    assert "Ports / protocols" in diagram.text
    assert service_page["view"]["last_execution"] is not None
    assert service_page["findings"][0]["cve"] == "CVE-2026-0001"
    response = client.get("/services/payments-service/export.xlsx")
    assert response.status_code == 200
    assert load_workbook(BytesIO(response.content))["Findings"]["A2"].value == "CVE-2026-0001"
    package = client.get("/services/payments-service/export.xlsx?include_diagrams=true")
    assert package.status_code == 200
    assert package.headers["content-type"].startswith("application/zip")
    with ZipFile(BytesIO(package.content)) as archive:
        names = set(archive.namelist())
        assert {"service-export.xlsx", "legacy-helm-diagram.svg"} <= names
        assert {f"architecture-{view}.svg" for view in ("all", "configuration", "containers", "flow", "network", "storage")} <= names


def test_architecture_reflow_endpoint_and_canonical_legacy_export():
    from test_architecture_packing import flows

    client = new_client()
    body = payload("responsive", datetime.now(timezone.utc), [])
    body["service_overview"] = flows(8)
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    url = "/services/payments-service?architecture=true"
    narrow = client.get(url + "&layout_width=1000")
    wide = client.get(url + "&layout_width=1920")
    assert narrow.status_code == wide.status_code == 200
    assert len(wide.json()["flow"]["components"]) == 8
    assert narrow.json()["flow"]["bounds"]["height"] > wide.json()["flow"]["bounds"]["height"]
    assert client.get(url + "&layout_width=0").status_code == 422
    assert client.get(url + "&layout_width=10001").status_code == 422
    assert TestClient(app).get(url + "&layout_width=1000", follow_redirects=False).status_code in {303, 401, 403}
    diagram = client.get("/services/payments-service/helm-diagram.svg")
    assert "CATS Architecture" in diagram.text
    assert "application-7" in diagram.text


def test_architecture_and_overview_use_exact_persisted_validation_evidence():
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=helm_payload("architecture-verified"), headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        run = db.scalar(select(DeploymentValidationRun))
        run.status = "VERIFIED"; run.phase = "COMPLETE"; run.cleanup_status = "COMPLETE"
        run.completed_at = datetime.now(timezone.utc)
        run.comparison = {"matched": ["Service/validation/demo"], "declared_only": [], "defaulted": [], "observed_only": [],
                          "expected_evidence": [{"apiVersion": "v1", "kind": "Service", "namespace": "validation", "name": "demo", "matched": True}], "observed_evidence": []}
        run.diagnostics = {"classification_summary": {"expected_resources": 1, "observed_expected": 1, "expected_only": 0, "runtime_generated": 0, "observed_only": 0, "failed": 0}}
        db.commit()
    architecture = client.get("/services/payments-service?architecture=true")
    overview = client.get("/services/payments-service?overview=true")
    evidence = client.get("/api/v1/services/payments-service/architecture-evidence").json()
    assert page_data(architecture)["architecture_verification"]["state"] == "VERIFIED"
    assert page_data(overview)["architecture_verification"]["state"] == "VERIFIED"
    assert evidence["architecture"]["state"] == "VERIFIED"
    assert evidence["graph"]["summary"]["runtime_verified"] == 1


def test_new_working_revision_is_declared_until_that_exact_revision_is_verified():
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=helm_payload("architecture-revision"), headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        execution = db.scalar(select(Execution).where(Execution.service_id == service.id))
        original = db.scalar(select(DeploymentValidationRun).where(DeploymentValidationRun.execution_id == execution.id))
        original.status = "VERIFIED"; original.phase = "COMPLETE"; original.completed_at = datetime.now(timezone.utc)
        original.diagnostics = {"classification_summary": {"expected_resources": 1, "observed_expected": 1,
                                                               "expected_only": 0, "failed": 0}}
        db.commit(); execution_id = execution.id; service_id = service.id
    assert client.get("/api/v1/services/payments-service/architecture-evidence").json()["architecture"]["state"] == "VERIFIED"

    assert client.post("/services/payments-service/artifacts/from-original", data={
        "csrf_token": csrf(client), "execution_id": str(execution_id),
    }, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        artifact = db.scalar(select(ServiceArtifact).where(ServiceArtifact.service_id == service_id))
        artifact_id = artifact.id
    assert client.post(f"/services/payments-service/artifacts/{artifact_id}/files", data={
        "csrf_token": csrf(client), "path": "values.yaml", "content": "replicaCount: 2\n",
    }, follow_redirects=False).status_code == 303

    unvalidated = client.get("/api/v1/services/payments-service/architecture-evidence").json()
    assert unvalidated["architecture"]["state"] == "DECLARED"
    assert unvalidated["graph"]["nodes"]  # declared/static graph remains available
    with SessionLocal() as db:
        revision = db.scalar(select(ServiceArtifactRevision).where(
            ServiceArtifactRevision.artifact_id == artifact_id,
            ServiceArtifactRevision.revision_label == "WORKING",
        ))
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        db.add(DeploymentValidationRun(
            run_key="DV-EXACT-WORKING", service_id=service.id, execution_id=execution_id,
            artifact_revision_id=revision.id, artifact_type="WORKING",
            artifact_reference=f"artifact:{artifact_id}:r{revision.revision_number}", engine="kind",
            status="VERIFIED", phase="COMPLETE", completed_at=datetime.now(timezone.utc),
            diagnostics={"classification_summary": {"expected_resources": 1, "observed_expected": 1,
                                                       "expected_only": 0, "failed": 0}},
        ))
        db.commit()
    verified = client.get("/api/v1/services/payments-service/architecture-evidence").json()
    assert verified["architecture"]["state"] == "VERIFIED"


def test_service_export_contains_authoritative_overview_sheets_and_provenance():
    client = new_client()
    body = payload("export-complete", datetime.now(timezone.utc), ["CVE-2026-0100"], service_id="export-service")
    body["service_overview"] = {
        "images": [{"image": "registry.example/team/api:2.0", "source_file": "charts/api/templates/deployment.yaml", "discovered_from": "Deployment/api"}],
        "helm_components": [{"chart": "api", "path": "charts/api", "declared_by": "charts/root/values.yaml", "enabled": False}],
        "missing_evidence": [{"type": "Chart", "item": "worker", "reason": "chart not found", "source_file": "charts/root/values.yaml"}],
    }
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    response = client.get("/services/export-service/export.xlsx")
    assert response.status_code == 200
    workbook = load_workbook(BytesIO(response.content), read_only=True)
    required = {"Summary", "Containers", "Helm Charts", "Artifacts", "Missing Evidence", "Ports & Protocols", "Accounts", "Dependencies", "Render Warnings", "Raw Findings", "Vulnerabilities", "Simplified Findings", "Configuration Findings", "POA&Ms", "Exceptions", "Mitigations", "Activity"}
    assert required.issubset(set(workbook.sheetnames))
    containers = list(workbook["Containers"].values)
    assert any("charts/api/templates/deployment.yaml" in str(row) for row in containers)
    missing = list(workbook["Missing Evidence"].values)
    assert any("charts/root/values.yaml" in str(row) for row in missing)


def test_service_export_accepts_singleton_recursive_helm_evidence():
    client = new_client()
    body = payload("export-singletons", datetime.now(timezone.utc), [], service_id="singleton-export")
    body["service_overview"] = {
        "images": {"image": "registry.example/team/api:2.0", "source_file": "charts/api/templates/deployment.yaml"},
        "helm_components": {"chart": "api", "path": "charts/api", "declared_by": "values.yml"},
        "ports": {"port": 8080, "protocol": "TCP", "service": "api"},
        "accounts": {"name": "api", "kind": "ServiceAccount", "namespace": "default"},
        "rendered_resources": {"items": [{
            "apiVersion": "v1", "kind": "Service", "metadata": {"name": "api"},
            "spec": {"ports": [{"port": 8080}]},
        }]},
    }
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    response = client.get("/services/singleton-export/export.xlsx?include_diagrams=true")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/zip")


def test_service_poc_is_displayed_and_exported():
    client = new_client(); ingest(client)
    page = client.get("/services/payments-service")
    assert page_data(page)["view"]["service"]["poc"] == "cats-test-poc@example.invalid"
    workbook = load_workbook(BytesIO(client.get("/exports/services.xlsx").content))
    assert "POC" in [cell.value for cell in workbook["Service Snapshot"][1]]


def test_administrator_can_save_configuration():
    client = new_client()
    page = client.get("/admin/configuration")
    assert page.status_code == 200
    response = client.post("/admin/configuration", data={
        "csrf_token": csrf(client), "display_timezone": "America/New_York",
        "date_format": "%Y-%m-%d", "time_format": "%H:%M UTC",
        "log_level": "WARNING", "audit_retention_days": "730", "identity_mode": "local",
    }, follow_redirects=False)
    assert response.status_code == 303
    policy = client.post("/admin/compliance", data={
        "csrf_token": csrf(client), "overdue_days": "120", "exception_max_days": "180", "skipped_images_incomplete": "true",
        "minimum_severity": "Critical", "epss_severity": ["Critical", "High"],
        "epss_rule_threshold": ["0.90", "0.80"], "epss_rule_noncompliant": ["true", "true"],
    }, follow_redirects=False)
    assert policy.status_code == 303
    assert page_envelope(client.get("/"))["page"] == "dashboard"
    with SessionLocal() as db:
        assert db.scalar(select(PortalSetting.value).where(PortalSetting.key == "overdue_days")) == "120"


def test_configuration_is_global_and_migrates_legacy_group_preference():
    client = new_client()
    with SessionLocal() as db:
        legacy_group = Group(name="Legacy configuration group")
        db.add(legacy_group)
        db.flush()
        db.add(PortalSetting(
            key=f"group:{legacy_group.id}:display_timezone",
            group_id=legacy_group.id,
            value="America/Los_Angeles",
        ))
        db.add(PortalSetting(
            key=f"group:{legacy_group.id}:log_level",
            group_id=legacy_group.id,
            value="DEBUG",
        ))
        db.commit()

    page = client.get("/admin/configuration")
    assert page.status_code == 200
    assert page_envelope(page)["page"] == "configuration"
    assert page_data(page)["configuration"]["display_timezone"] == "America/Los_Angeles"
    assert "group_id" not in page_data(page)["configuration"]
    with SessionLocal() as db:
        global_setting = db.scalar(select(PortalSetting).where(
            PortalSetting.key == "display_timezone", PortalSetting.group_id.is_(None)
        ))
        assert global_setting is not None
        assert global_setting.value == "America/Los_Angeles"
        global_log_level = db.scalar(select(PortalSetting).where(
            PortalSetting.key == "log_level", PortalSetting.group_id.is_(None)
        ))
        assert global_log_level is not None
        assert global_log_level.value == "DEBUG"


def test_service_configuration_does_not_reapply_legacy_global_group_settings():
    with SessionLocal() as db:
        group = Group(name="Scoped group")
        service = Service(service_key="global-config-service", name="Global config service", manual_version="1")
        db.add_all([group, service]); db.flush()
        service.groups.append(group)
        db.add(PortalSetting(key="display_timezone", group_id=None, value="UTC"))
        db.add(PortalSetting(key=f"group:{group.id}:display_timezone", group_id=group.id, value="America/New_York"))
        db.commit(); db.refresh(service)
        assert configuration_for_service(db, service)["display_timezone"] == "UTC"


def test_configuration_lists_all_builtin_os_repositories_and_image_defined_default():
    client = new_client()
    page = client.get("/admin/configuration")
    assert page.status_code == 200
    for os_id in ("ubuntu", "debian", "rhel", "rocky", "almalinux", "centos", "fedora", "alpine"):
        assert os_id in page.text
    assert page_data(page)["os_definitions"]
    assert all("package_manager" in row for row in page_data(page)["os_definitions"].values())


def test_custom_os_repository_can_be_added_and_builtins_are_protected():
    client = new_client()
    response = client.post("/admin/configuration/repositories", data={
        "csrf_token": csrf(client), "action": "add", "os_id": "test-linux",
        "display_name": "Test Linux", "package_manager": "dnf",
        "mode": "custom", "url": "https://mirror.example.invalid/test-linux",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert "test-linux" in client.get("/admin/configuration").text
    assert "https://mirror.example.invalid/test-linux" in client.get("/admin/configuration").text
    protected = client.post("/admin/configuration/repositories", data={
        "csrf_token": csrf(client), "action": "delete", "remove_os_id": "ubuntu",
    })
    assert protected.status_code == 422


def test_audit_logging_level_is_saved_globally():
    client = new_client()
    response = client.post("/admin/audit-policy", data={
        "csrf_token": csrf(client), "audit_retention_days": "365",
        "audit_tool_integration": "planned", "log_level": "DEBUG", "group_id": "",
    }, follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        setting = db.scalar(select(PortalSetting).where(
            PortalSetting.key == "log_level", PortalSetting.group_id.is_(None)
        ))
        assert setting is not None and setting.value == "DEBUG"


def test_account_can_save_personal_theme():
    client = new_client()
    assert client.get("/account/appearance").status_code == 200
    response = client.post("/account/appearance", data={
        "csrf_token": csrf(client), "theme": "blue",
    }, follow_redirects=False)
    assert response.status_code == 303
    assert page_data(client.get("/"))["current_user"]["theme"] == "blue"
    assert page_data(client.get("/account/appearance?saved=1"))["saved"]


def test_image_scoped_ingest_only_reconciles_the_scanned_image():
    client = new_client()
    first = payload("multi-image-1", datetime.now(timezone.utc), ["CVE-A"], service_id="multi-image")
    first["findings"].append({"cve": "CVE-B", "severity": "High", "image": "registry.example/image-b:2.3", "package": "openssl", "fixed_version": "9.9", "evidence": {}})
    first["findings"][0]["image"] = "registry.example/image-a:2.3"
    assert client.post("/api/v1/pipeline-results", json=first, headers=pipeline_headers).status_code == 201
    second = payload("image-only-2", datetime.now(timezone.utc), [], service_id="multi-image")
    second["scan_scope"] = "image"
    second["scope_image"] = "registry.example/image-a:2.3"
    second["findings"] = []
    assert client.post("/api/v1/pipeline-results", json=second, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "multi-image"))
        findings = {finding.cve: finding.active for finding in db.scalars(select(Finding).where(Finding.service_id == service.id)).all()}
        images = {image.image_reference: image.lifecycle_status for image in db.scalars(select(ServiceImage).where(ServiceImage.service_id == service.id)).all()}
    assert findings == {"CVE-A": False, "CVE-B": True}
    assert images["registry.example/image-a:2.3"] == "active"
    assert images["registry.example/image-b:2.3"] == "active"


def test_missing_evidence_source_file_is_preserved_in_service_overview():
    client = new_client()
    body = payload("provenance-1", datetime.now(timezone.utc), [], service_id="provenance-service")
    body["service_overview"] = {"missing_evidence": [{"type": "Image", "item": "registry.example/missing:1", "reason": "repository unavailable", "source_file": "charts/app/values.yaml"}]}
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    page = client.get("/services/provenance-service?overview=true")
    assert page.status_code == 200
    assert "charts/app/values.yaml" in page.text


def test_remove_missing_evidence_matches_displayed_sources_and_rejects_stale_page():
    client = new_client()
    body = payload("evidence-1", datetime.now(timezone.utc), [], service_id="evidence-service", complete=False,
                   skipped_images=["registry.example/missing:1 :: unavailable"])
    body["service_overview"] = {
        "images": [{"image": "registry.example/missing:1", "source_file": "charts/app/values.yaml"}],
        "missing_evidence": [{"type": "Chart", "item": "worker", "reason": "unavailable"}],
        "dependencies": [{"name": "library", "resolved": False, "reason": "unavailable"}],
    }
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    page = client.get("/services/evidence-service?overview=true")
    assert page.status_code == 200
    with SessionLocal() as db:
        execution_id = db.scalar(select(Execution.id).where(Execution.execution_key == "evidence-1"))
    assert page_data(page)["latest_execution"]["id"] == execution_id

    def remove(kind, item, source="", run=execution_id):
        return client.post("/services/evidence-service/missing-evidence/remove", data={
            "csrf_token": csrf(client), "execution_id": run,
            "evidence_type": kind, "item": item, "source_file": source,
        }, follow_redirects=False)

    assert remove("Image", "registry.example/missing:1", "charts/app/values.yaml").status_code == 303
    assert remove("Dependency", "library").status_code == 303
    assert remove("Chart", "worker").status_code == 303
    with SessionLocal() as db:
        execution = db.get(Execution, execution_id)
        assert execution.raw_payload["skipped_images"] == []
        assert execution.raw_payload["service_overview"]["dependencies"] == []
        assert execution.raw_payload["service_overview"]["missing_evidence"] == []
        assert db.scalars(select(AuditEvent).where(AuditEvent.action == "missing_evidence.removed")).all()
    assert remove("Chart", "worker").headers["location"].endswith("evidence_notice=stale")
    stale_page = client.get("/services/evidence-service?overview=true&evidence_notice=stale")
    assert page_data(stale_page)["evidence_notice"] == "stale"
    assert page_envelope(stale_page)["page"] == "service_overview"
    stale_api = client.post("/services/evidence-service/missing-evidence/remove", data={
        "csrf_token": csrf(client), "execution_id": execution_id,
        "evidence_type": "Chart", "item": "worker",
    }, headers={"accept": "application/json"})
    assert stale_api.status_code == 409
    assert "no longer current" in stale_api.json()["detail"]
    newer = payload("evidence-2", datetime.now(timezone.utc) + timedelta(seconds=1), [],
                    service_id="evidence-service")
    newer["service_overview"] = {"missing_evidence": [{"type": "Chart", "item": "new-worker"}]}
    assert client.post("/api/v1/pipeline-results", json=newer, headers=pipeline_headers).status_code == 201
    assert remove("Chart", "new-worker").headers["location"].endswith("evidence_notice=stale")
    current_page = client.get("/services/evidence-service?overview=true")
    assert [row["item"] for row in page_data(current_page)["overview_data"]["missing_evidence"]] == ["new-worker"]
    with SessionLocal() as db:
        current = db.scalar(select(Execution).where(Execution.execution_key == "evidence-2"))
        assert current.raw_payload["service_overview"]["missing_evidence"]


def test_browser_errors_are_pages_and_api_errors_remain_json(caplog):
    from starlette.routing import Route

    def crash(request):
        raise RuntimeError("private failure detail")

    browser_route = Route("/__test_browser_crash", crash)
    api_route = Route("/api/__test_api_crash", crash)
    app.router.routes.extend((browser_route, api_route))
    try:
        client = TestClient(app, raise_server_exceptions=False)
        browser = client.get("/__test_browser_crash", headers={"accept": "text/html"})
        assert browser.status_code == 500
        assert page_envelope(browser)["page"] == "boozled"
        assert page_data(browser)["detail"] is None  # Static safe copy belongs to the native error component.
        assert page_data(browser)["home_url"] == "http://testserver/"
        assert "private failure detail" not in browser.text
        assert "private failure detail" in caplog.text
        for internal in ("RuntimeError", "Traceback", "DATABASE_URL", "PIPELINE_API_TOKEN", "sqlite://", "C:\\Users\\"):
            assert internal not in browser.text
        api = client.get("/api/__test_api_crash", headers={"accept": "application/json"})
        assert api.status_code == 500
        assert api.json() == {"detail": "Something went wrong while processing your request."}
        assert "private failure detail" not in api.text
        missing = client.get("/not-a-page", headers={"accept": "text/html"})
        assert missing.status_code == 404 and page_envelope(missing)["page"] == "request_error"
        assert page_data(missing)["detail"] == "The requested page or item was not found."
        assert "application/json" not in missing.headers["content-type"]
        missing_api = client.get("/api/not-a-page", headers={"accept": "application/json"})
        assert missing_api.status_code == 404 and missing_api.json()["detail"] == "Not Found"
        login = client.post("/login", data={"username": "admin", "password": "test-password-long"}, follow_redirects=False)
        assert login.status_code == 303
        invalid = client.post("/services/example/missing-evidence/remove", data={}, headers={"accept": "text/html"})
        assert invalid.status_code == 422 and page_envelope(invalid)["page"] == "request_error"
        assert page_data(invalid)["detail"]
    finally:
        app.router.routes.remove(browser_route)
        app.router.routes.remove(api_route)


def test_missing_evidence_remove_requires_permission_and_csrf():
    admin = new_client()
    body = payload("permission-evidence", datetime.now(timezone.utc), [], service_id="permission-service")
    body["service_overview"] = {"missing_evidence": [{"type": "Chart", "item": "worker"}]}
    assert admin.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    add_user("evidence-assessor", "Assessor")
    assessor = new_client("evidence-assessor")
    denied = assessor.post("/services/permission-service/missing-evidence/remove", data={
        "csrf_token": csrf(assessor), "evidence_type": "Chart", "item": "worker",
    }, headers={"accept": "text/html"})
    assert denied.status_code == 403 and page_envelope(denied)["page"] == "request_error"
    assert page_data(denied)["detail"]
    bad_csrf = admin.post("/services/permission-service/missing-evidence/remove", data={
        "csrf_token": "wrong", "evidence_type": "Chart", "item": "worker",
    }, headers={"accept": "text/html"})
    assert bad_csrf.status_code == 403
    with SessionLocal() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == "permission-evidence"))
        assert execution.raw_payload["service_overview"]["missing_evidence"]


def test_all_sixty_missing_evidence_entries_reach_noncompliance():
    client = new_client()
    body = payload("sixty-evidence", datetime.now(timezone.utc), [], complete=False,
                   skipped_images=[f"registry.example/missing:{i}" for i in range(9)])
    body["service_overview"] = {
        "missing_evidence": [{"type": "Chart", "item": f"missing-chart-{i}",
                              "reason": "Remote chart unavailable", "source_file": f"charts/{i}/values.yaml"}
                             for i in range(50)],
        "dependencies": [{"name": "unresolved-dependency", "resolved": False}],
    }
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["finding_counts"]["noncompliant"] == 60
    page = client.get("/services/payments-service?findings_view=raw&finding_state=noncompliant&page_size=100")
    assert page.status_code == 200
    assert "missing-chart-49" in page.text and "unresolved-dependency" in page.text
    assert "charts/49/values.yaml" in page.text
    assert page_data(page)["total_items"] == 60
    assert len(page_data(page)["noncompliance_items"]) == 60
    filtered = client.get("/services/payments-service?findings_view=raw&finding_state=noncompliant&q=missing-chart-49")
    assert page_data(filtered)["total_items"] == 1 and "charts/49/values.yaml" in filtered.text
    second_page = client.get("/services/payments-service?findings_view=raw&finding_state=noncompliant&page_size=50&page=2")
    assert page_data(second_page)["page"] == 2
    assert page_data(second_page)["total_items"] == 60
    assert len(page_data(second_page)["noncompliance_items"]) == 10


def test_raw_findings_do_not_hide_non_risk_eligible_cves():
    client = new_client()
    assert ingest(client, cves=["CVE-2099-11111"]).status_code == 201
    with SessionLocal() as db:
        db.add(PortalSetting(key="compliance_mode", value="risk_based"))
        db.commit()
    assert "CVE-2099-11111" not in client.get("/services/payments-service?findings_view=simplified").text
    page = client.get("/services/payments-service?findings_view=raw")
    assert "CVE-2099-11111" in page.text


def test_public_ingest_preserves_scan_companion_overview(monkeypatch, tmp_path):
    from app import main as portal_main
    client = new_client(); ingest(client)
    monkeypatch.setattr(AuthContext, "accessible_service_ids", lambda self, permission: {1})
    monkeypatch.setattr(AuthContext, "has", lambda self, permission, service_id=None: True)
    job_id = "companion-evidence"
    output = tmp_path / job_id / "output"
    output.mkdir(parents=True)
    body = payload("companion", datetime.now(timezone.utc), ["CVE-2099-12345"] * 3, complete=False)
    body["service_overview"] = {"rendered_resources": [{"kind": "Service", "metadata": {"name": "kept"}}]}
    (output / "portal-result.json").write_text(json.dumps(body), encoding="utf-8")
    (output / "service-overview.json").write_text(json.dumps({"missing_evidence": [
        {"type": "Chart", "item": "companion-chart", "reason": "Unavailable"}]}), encoding="utf-8")
    monkeypatch.setattr(portal_main, "PUBLIC_JOB_ROOT", tmp_path)
    monkeypatch.setitem(portal_main.PUBLIC_JOBS, job_id, {"job_id": job_id, "status": "complete"})
    assert client.post(f"/api/public/jobs/{job_id}/ingest?service_id=payments-service").status_code == 200
    with SessionLocal() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == f"public:{job_id}"))
        assert len(execution.raw_payload["findings"]) == 3
        assert execution.raw_payload["service_overview"]["rendered_resources"][0]["metadata"]["name"] == "kept"
        assert execution.raw_payload["service_overview"]["missing_evidence"][0]["item"] == "companion-chart"
    assert "companion-chart" in client.get("/services/payments-service?findings_view=raw&finding_state=noncompliant").text


def test_helm_ingest_queues_deployment_validation_without_changing_static_result(monkeypatch):
    from app import main as portal_main
    submitted = []
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda run_id: submitted.append(run_id))
    response = new_client().post("/api/v1/pipeline-results", json=helm_payload(), headers=pipeline_headers)
    assert response.status_code == 201 and response.json()["accepted"] is True
    with SessionLocal() as db:
        run = db.scalar(select(DeploymentValidationRun))
        assert run.status == "QUEUED" and submitted == [run.id]


def test_validation_persistence_failure_cannot_roll_back_static_ingest(monkeypatch):
    from app import main as portal_main
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_new_validation_run", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("optional store unavailable")))
    response = new_client().post("/api/v1/pipeline-results", json=helm_payload("static-survives-validation-store"), headers=pipeline_headers)
    assert response.status_code == 201
    assert response.json()["deployment_validation_run_id"] is None
    with SessionLocal() as db:
        execution = db.scalar(select(Execution).where(Execution.execution_key == "static-survives-validation-store"))
        assert execution is not None and execution.complete is True
        assert db.scalar(select(DeploymentValidationRun)) is None


def test_helm_source_limits_reject_before_persistence(monkeypatch):
    monkeypatch.setenv("CATS_INGEST_MAX_SOURCE_BYTES", "32")
    body = helm_payload("oversized-source")
    body["helm_source_files"] = {"Chart.yaml": "x" * 64}
    response = new_client().post("/api/v1/pipeline-results", json=body, headers=pipeline_headers)
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(Execution)) is None


def test_pipeline_content_length_limit_rejects_early():
    from app import main as portal_main
    response = new_client().post("/api/v1/pipeline-results", content=b"{}", headers={**pipeline_headers, "content-length": str(portal_main.PIPELINE_MAX_REQUEST_BYTES + 1)})
    assert response.status_code == 413


def test_pipeline_size_limit_counts_actual_body_when_header_is_misleading(monkeypatch):
    from app import main as portal_main
    monkeypatch.setattr(portal_main, "PIPELINE_MAX_REQUEST_BYTES", 64)
    body = json.dumps({"padding": "x" * 200}).encode()
    response = new_client().post("/api/v1/pipeline-results", content=body, headers={**pipeline_headers, "content-type": "application/json", "content-length": "1"})
    assert response.status_code == 413


def test_disabled_deployment_validation_is_not_attempted_and_static_scan_remains_visible(monkeypatch):
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=helm_payload("disabled-validation"), headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        assert db.scalar(select(DeploymentValidationRun)).status == "NOT_ATTEMPTED"
    overview = client.get("/services/payments-service?overview=true")
    details = client.get("/services/payments-service?validation=true")
    assert overview.status_code == details.status_code == 200
    assert page_data(overview)["deployment_validation"]["status"] == "NOT_ATTEMPTED"
    assert page_data(overview)["deployment_validation"]["static_scan_complete"] is True
    assert page_data(details)["validation"]["status"] == "NOT_ATTEMPTED"
    assert page_data(details)["validation"]["static_scan_complete"] is True


def test_helm_ingest_without_retained_sources_records_not_attempted(monkeypatch):
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    body = helm_payload("missing-validation-sources")
    body["helm_source_files"] = {}
    response = new_client().post("/api/v1/pipeline-results", json=body, headers=pipeline_headers)
    assert response.status_code == 201
    with SessionLocal() as db:
        run = db.scalar(select(DeploymentValidationRun))
        assert run.status == "NOT_ATTEMPTED"
        assert "did not retain Helm source files" in run.reason


def test_validation_ui_preserves_helm_provenance_after_a_later_non_helm_scan(monkeypatch):
    from app import main as portal_main
    submitted = []
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda run_id: submitted.append(run_id))
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=helm_payload("helm-provenance"), headers=pipeline_headers).status_code == 201
    later = payload("image-evidence-later", datetime.now(timezone.utc), [], service_id="payments-service")
    later["artifact_type"] = "image"
    assert client.post("/api/v1/pipeline-results", json=later, headers=pipeline_headers).status_code == 201
    response = client.post("/services/payments-service/deployment-validations", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        runs = db.scalars(select(DeploymentValidationRun).order_by(DeploymentValidationRun.id)).all()
        assert len(runs) == 2
        assert all(run.execution.execution_key == "helm-provenance" for run in runs)
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["deployment_validation"]["execution_key"] == "helm-provenance"


def test_validation_ui_reports_incomplete_linked_static_scan_and_hides_disabled_rerun(monkeypatch):
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")
    body = helm_payload("incomplete-static")
    body["complete"] = False
    client = new_client()
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    details = client.get("/services/payments-service?validation=true")
    assert page_data(details)["validation"]["static_scan_complete"] is False
    assert page_data(details)["validation_unavailable_reason"] == "Deployment Validation is disabled by configuration."
    assert not page_data(details)["can_validate"]


def test_validation_history_links_open_the_selected_immutable_run(monkeypatch):
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("history-selection"), headers=pipeline_headers)
    with SessionLocal() as db:
        first = db.scalar(select(DeploymentValidationRun))
        first.reason = "Older run explanation"
        second = DeploymentValidationRun(run_key="DV-NEWER-HISTORY", service_id=first.service_id, execution_id=first.execution_id,
                                         status="COULD_NOT_VALIDATE", phase="COMPLETE", reason="Newer run explanation", artifact_reference="history-selection")
        db.add(second); db.commit(); first_key = first.run_key
    latest = client.get("/services/payments-service?validation=true")
    selected = client.get(f"/services/payments-service?validation=true&validation_run={first_key}")
    assert page_data(latest)["validation"]["reason"] == "Newer run explanation"
    assert page_data(latest)["validation"]["run_key"] == "DV-NEWER-HISTORY"
    assert page_data(selected)["validation"]["reason"] == "Older run explanation"
    assert page_data(selected)["validation"]["run_key"] == first_key
    assert first_key in {run["run_key"] for run in page_data(selected)["validation_runs"]}


def test_overview_collapses_worker_phase_to_in_progress(monkeypatch):
    from app import main as portal_main
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda _run_id: None)
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("queued-overview"), headers=pipeline_headers)
    overview = client.get("/services/payments-service?overview=true")
    assert page_data(overview)["deployment_validation"]["status"] == "QUEUED"


def test_stale_never_started_validation_recovers_as_not_attempted(monkeypatch):
    from app import main as portal_main
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("stale-queued"), headers=pipeline_headers)
    with SessionLocal() as db:
        run = db.scalar(select(DeploymentValidationRun))
        run.status = "QUEUED"; run.started_at = None; run.cluster_name = None
        run.created_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit(); run_id = run.id
    portal_main.recover_stale_validation_runs()
    with SessionLocal() as db:
        recovered = db.get(DeploymentValidationRun, run_id)
        assert recovered.status == "NOT_ATTEMPTED"
        assert recovered.cleanup_status == "NOT_REQUIRED"


def test_validation_setup_exception_finishes_queued_run(monkeypatch):
    from app import main as portal_main
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda _: None)
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("setup-error"), headers=pipeline_headers)
    with SessionLocal() as db:
        run_id = db.scalar(select(DeploymentValidationRun)).id
    def fail_setup(_):
        raise ValueError("setup failed")
    monkeypatch.setattr(portal_main, "_execute_deployment_validation", fail_setup)
    portal_main._run_deployment_validation(run_id)
    with SessionLocal() as db:
        run = db.get(DeploymentValidationRun, run_id)
        assert run.status == "NOT_ATTEMPTED"
        assert run.phase == "COMPLETE"
        assert run.cleanup_status == "NOT_REQUIRED"
        assert run.reason_category == "INTERNAL_VALIDATION_ERROR"
        assert "ValueError" in run.reason
        assert run.completed_at is not None


def test_validation_without_available_remote_validator_finishes_without_execution(monkeypatch):
    from app import main as portal_main
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda _: None)
    monkeypatch.setattr(portal_main.validator_management, "select_configuration", lambda *args: {})
    def unexpected_execution(*args, **kwargs):
        raise AssertionError("No validation should execute without an available validator")
    monkeypatch.setattr(portal_main, "validate_remote_artifact", unexpected_execution)
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("no-validator"), headers=pipeline_headers)
    with SessionLocal() as db:
        run_id = db.scalar(select(DeploymentValidationRun)).id
    portal_main._run_deployment_validation(run_id)
    with SessionLocal() as db:
        run = db.get(DeploymentValidationRun, run_id)
        assert run.status == "NOT_ATTEMPTED"
        assert run.phase == "COMPLETE"
        assert run.reason_category == "VALIDATOR_UNAVAILABLE"
        assert run.started_at is None
        assert run.cluster_name is None
        assert run.completed_at is not None


def test_validation_worker_sends_valid_v2_request(monkeypatch):
    from app import main as portal_main, deployment_bundle
    from app.validator_protocol import validate_request
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda _: None)
    monkeypatch.setattr(portal_main.validator_management, "select_configuration", lambda *args: {"endpoint": "https://validator:8443"})
    monkeypatch.setattr(deployment_bundle, "build_helm_archive", lambda path, *args, **kwargs: path.write_bytes(b"prepared chart"))
    requests = []
    def remote(configuration, declaration, **kwargs):
        validate_request(declaration)
        assert kwargs["artifact_path"].read_bytes() == b"prepared chart"
        requests.append(declaration)
        return {"status": "VERIFIED", "phase": "COMPLETE", "cleanup": {"status": "COMPLETE"}}
    monkeypatch.setattr(portal_main, "validate_remote_artifact", remote)
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("valid-request"), headers=pipeline_headers)
    with SessionLocal() as db:
        run_id = db.scalar(select(DeploymentValidationRun)).id
    portal_main._run_deployment_validation(run_id)
    assert len(requests) == 1
    with SessionLocal() as db:
        assert db.get(DeploymentValidationRun, run_id).status == "VERIFIED"


def test_failed_terminal_cleanup_is_retried_by_stale_recovery(monkeypatch):
    from app import main as portal_main
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("cleanup-retry"), headers=pipeline_headers)
    with SessionLocal() as db:
        run = db.scalar(select(DeploymentValidationRun))
        run.status = "COULD_NOT_VALIDATE"; run.cleanup_status = "FAILED"; run.cluster_name = "cats-validation-cleanup-retry"
        run.created_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit(); run_id = run.id
    monkeypatch.setattr(portal_main, "cleanup_stale_clusters", lambda names, config: {"deleted": list(names), "failed": []})
    portal_main.recover_stale_validation_runs()
    with SessionLocal() as db:
        recovered = db.get(DeploymentValidationRun, run_id)
        assert recovered.status == "COULD_NOT_VALIDATE"
        assert recovered.cleanup_status == "COMPLETE"


def test_rerun_creates_historical_validation_row_and_schedules_it(monkeypatch):
    from app import main as portal_main
    submitted = []
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda run_id: submitted.append(run_id))
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("rerun-original"), headers=pipeline_headers)
    response = client.post("/services/payments-service/deployment-validations", data={"csrf_token": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303 and "validation=true&validation_run=DV-" in response.headers["location"]
    with SessionLocal() as db:
        runs = db.scalars(select(DeploymentValidationRun).order_by(DeploymentValidationRun.id)).all()
        assert len(runs) == 2 and [run.id for run in runs] == submitted


def test_deployment_validation_json_history_and_detail_apis(monkeypatch):
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("api-validation"), headers=pipeline_headers)
    with SessionLocal() as db:
        stored = db.scalar(select(DeploymentValidationRun))
        stored.status = "PARTIALLY_VERIFIED"
        stored.reason_category = "EXPECTED_RESOURCE_NOT_OBSERVED"
        stored.classification_reasons = [{
            "code": "EXPECTED_RESOURCE_NOT_OBSERVED", "resource": {"kind": "CronJob", "namespace": "demo", "name": "maintenance"},
            "expected_state": "Observed", "observed_state": "Missing", "explanation": "Expected object was not observed.",
        }]
        stored.capability_preflight = [{"capability": "Configuration dependencies", "required": True, "status": "AVAILABLE"}]
        stored.diagnostics = {"classification_summary": {"expected_resources": 2, "observed_expected": 1, "expected_only": 1, "runtime_generated": 1, "observed_only": 0, "failed": 0}}
        db.commit()
    history = client.get("/api/v1/services/payments-service/deployment-validations")
    assert history.status_code == 200 and len(history.json()["runs"]) == 1
    run = history.json()["runs"][0]
    result = client.get(f"/api/v1/services/payments-service/deployment-validations/{run['run_key']}")
    assert result.status_code == 200 and result.json()["status"] == "PARTIALLY_VERIFIED"
    # The detail endpoint exposes persisted reasons and grouped capability data.
    assert result.json()["classification_reasons"][0]["code"] == "EXPECTED_RESOURCE_NOT_OBSERVED"
    assert result.json()["classification_summary"]["expected_only"] == 1
    assert result.json()["capability_assessment"][0]["capability"] == "Configuration dependencies"
    assert result.json()["checks"]["helm_template"] == "NOT_ATTEMPTED"
    assert result.json()["terminal"] is True and result.json()["cleanup_terminal"] is True


def test_rerun_json_response_returns_authoritative_new_run(monkeypatch):
    from app import main as portal_main
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "true")
    monkeypatch.setattr(portal_main, "_submit_validation_run", lambda _run_id: None)
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("json-rerun"), headers=pipeline_headers)
    response = client.post("/services/payments-service/deployment-validations", data={"csrf_token": csrf(client)}, headers={"Accept": "application/json"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["run_id"].startswith("DV-")
    assert payload["run"]["run_key"] == payload["run_id"]
    assert payload["run"]["status"] == "QUEUED"
    assert payload["run"]["terminal"] is False


def test_deployment_validation_requires_permission_and_csrf(monkeypatch):
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")
    admin = new_client()
    admin.post("/api/v1/pipeline-results", json=helm_payload("permission-validation"), headers=pipeline_headers)
    assert admin.post("/services/payments-service/deployment-validations", data={}, follow_redirects=False).status_code == 422
    with SessionLocal() as db:
        service_id = db.scalar(select(Service.id).where(Service.service_key == "payments-service"))
    add_user("validation-viewer", "Assessor", service_id=service_id)
    viewer = new_client("validation-viewer")
    assert viewer.get("/api/v1/services/payments-service/deployment-validations").status_code == 200
    assert viewer.post("/services/payments-service/deployment-validations", data={"csrf_token": csrf(viewer)}, follow_redirects=False).status_code == 403


def test_service_deletion_removes_deployment_validation_rows(monkeypatch):
    from types import SimpleNamespace
    from app.dependency_queries import ensure_projection
    from app.models import DependencyProjection, DependencyProjectionRow, ExecutionSummary
    monkeypatch.setenv("CATS_DEPLOYMENT_VALIDATION_ENABLED", "false")
    client = new_client()
    client.post("/api/v1/pipeline-results", json=helm_payload("delete-validation"), headers=pipeline_headers)
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "payments-service"))
        execution = db.scalar(select(Execution).where(Execution.service_id == service.id))
        ensure_projection(db, SimpleNamespace(id=execution.id, payload_digest=None,
            raw_payload={"sbom_components": [{"name": "cached-package"}]}), [], [],
            lambda cve: (False, None))
        assert db.scalar(select(DependencyProjectionRow)) is not None
        assert db.scalar(select(ExecutionSummary)) is not None
        db.add(ServiceArchiveEvent(service_id=service.id, action="archive", reason="test", performed_by="admin"))
        db.commit()
    monkeypatch.setenv("ALLOW_SERVICE_DELETE", "true")
    response = client.post("/services/payments-service/delete", data={"confirmation": "payments-service", "reason": "Remove test service", "csrf_token": csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    with SessionLocal() as db:
        assert db.scalar(select(DeploymentValidationRun)) is None
        assert db.scalar(select(DependencyProjection)) is None
        assert db.scalar(select(DependencyProjectionRow)) is None
        assert db.scalar(select(ExecutionSummary)) is None


def test_focused_findings_export_projects_current_observations_without_evidence():
    client = new_client()
    now = datetime.now(timezone.utc)
    assert ingest(client, execution='older', cves=['CVE-OLDER'], when=now-timedelta(days=1)).status_code == 201
    assert ingest(client, execution='latest', cves=['CVE-LATEST'], when=now).status_code == 201
    statements = []
    def capture(conn, cursor, sql, params, context, many):
        statements.append(sql)
    event.listen(engine, 'before_cursor_execute', capture)
    try:
        response = client.get('/services/payments-service/exports/findings.xlsx')
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    assert response.status_code == 200
    sheet = load_workbook(BytesIO(response.content)).active
    assert sheet.max_row == 2
    assert sheet.cell(2, 2).value == 'CVE-LATEST'
    assert not any('raw_payload' in sql or 'finding_observations.evidence' in sql for sql in statements)
