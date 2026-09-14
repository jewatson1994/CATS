from io import BytesIO
import os
import re
import json
from zipfile import ZipFile
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["PIPELINE_API_TOKEN"] = "test-token"
os.environ["CATS_BOOTSTRAP_USERNAME"] = "admin"
os.environ["CATS_BOOTSTRAP_PASSWORD"] = "test-password-long"
os.environ["SESSION_COOKIE_SECURE"] = "false"

from fastapi.testclient import TestClient
from openpyxl import load_workbook
from sqlalchemy import event, select

from app.auth import AuthContext, hash_password, seed_auth, token_hash
from app.database import Base, SessionLocal, engine
from app.main import app, configuration_for_service
from app.models import AuditEvent, ExceptionRecord, Execution, Finding, Group, PoamEntry, PolicyExceptionRecord, PolicyFinding, PortalSetting, RemediationExecution, Role, Service, ServiceImage, User, UserRoleAssignment, UserSession, WorkflowRequest

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


def add_user(username, role_name, service_id=None):
    with SessionLocal() as db:
        role = db.scalar(select(Role).where(Role.name == role_name))
        user = User(username=username, display_name=username.title(), password_hash=hash_password("test-password-long"), must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, service_id=service_id)); db.commit()


def test_login_and_http_cookie_mode():
    client = new_client()
    assert client.get("/").status_code == 200
    assert client.cookies.get("cats_session")
    public = TestClient(app).get("/", follow_redirects=False)
    assert public.status_code == 200
    assert "Start Scan" in public.text and "Generate SBOM" in public.text and "Sign In" in public.text


def test_public_home_scan_and_patch_workspaces():
    client = TestClient(app)
    home = client.get("/")
    assert home.status_code == 200
    assert all(label in home.text for label in ("CATS", "Production Services", "Scan Images &amp; Charts", "Generate SBOM", "Patch Images", "Sign In"))
    assert "Understand what is deployed" not in home.text
    assert "SECURITY LIFECYCLE" not in home.text
    assert "Discover" not in home.text and "Monitor" not in home.text
    assert "Authenticated service operations" not in home.text
    assert client.get("/scan").status_code == 200
    patch = client.get("/patch")
    assert patch.status_code == 200
    assert "OCI Registry" in patch.text and "Upload Image" in patch.text
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
    assert "<h1>Scan</h1>" in scan.text
    assert 'href="/scan">Scan</a>' in scan.text
    assert 'href="/sbom">SBOM</a>' in scan.text

    sbom = client.get("/sbom")
    assert sbom.status_code == 200
    assert "<h1>SBOM</h1>" in sbom.text and "SBOM generator" in sbom.text
    assert sbom.text.index('href="/scan"') < sbom.text.index('href="/sbom"') < sbom.text.index('href="/patch"')
    for value in ("syft-json", "cyclonedx-json", "cyclonedx-xml", "spdx-json"):
        assert f'value="{value}"' in sbom.text
    assert 'name="sbom_formats"' in sbom.text
    assert 'name="cyclonedx_spec_version"' in sbom.text

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


def test_service_remediation_creates_auditable_review_candidate(monkeypatch):
    from app import main as portal_main

    client = new_client()
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
    assert "Before / After" in report.text and "Deployment validation" in report.text and "Review Required" in report.text


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
    template_root = Path(__file__).parents[1] / "app" / "templates"
    static_root = Path(__file__).parents[1] / "app" / "static"
    template_paths = sorted(template_root.glob("*.html"))
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

    for path in static_root.rglob("*.js"):
        assert "window.open(" not in path.read_text(encoding="utf-8"), f"new-window behavior found in {path.name}"


def test_authenticated_primary_navigation_and_gear_cleanup():
    client = new_client()
    page = client.get("/")
    assert page.status_code == 200
    assert page.text.index('href="/patch"') < page.text.index('href="/remediations"')
    assert "Remediations workspace" not in page.text
    assert "Service staging" not in page.text.split("admin-menu", 1)[-1].split("user-menu", 1)[0]
    assert "Audit Policy" not in page.text.split("admin-menu", 1)[-1].split("user-menu", 1)[0]
    remediations = client.get("/remediations")
    assert remediations.status_code == 200 and 'href="/remediations"' in remediations.text
    assert "class=\"active\"" in remediations.text


def test_active_services_are_alphabetical_without_compliance_explainer():
    client = new_client()
    ingest(client, execution="zeta", service_id="zeta-service")
    ingest(client, execution="alpha", service_id="alpha-service")
    page = client.get("/")
    assert page.status_code == 200
    assert page.text.index("Alpha Service") < page.text.index("Zeta Service")
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
    assert "Active Fixable Findings" in page.text
    assert "KSV014" in page.text and "Configuration" in page.text
    assert "CIS Kubernetes" in page.text and "Deployment/payments-api" in page.text
    overview = client.get("/services/payments-service?overview=true")
    assert "Active Fixable</span><strong>1</strong>" in overview.text
    dashboard = client.get("/")
    assert "Active Findings" in dashboard.text and "Overdue Findings" in dashboard.text
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
    assert "Overview" in overview.text


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
    assert "&ndash;" in configuration_page.text
    vulnerability_page = client.get("/services/payments-service?finding_type=vulnerability")
    assert vulnerability_page.status_code == 200
    assert "CVE-2026-0001" in vulnerability_page.text
    assert "KSV014" not in vulnerability_page.text
    assert ">Configuration</option>" in vulnerability_page.text


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
    assert "Warnings" in response.text and "CVE-2026-WARN" in response.text
    assert "No warnings for this service" not in response.text


def test_remediations_workspace_uses_existing_records_and_tabs():
    client = new_client()
    ingest(client, cves=["CVE-2026-REMEDIATE"])
    page = client.get("/remediations?tab=poams")
    assert page.status_code == 200
    assert all(label in page.text for label in ("POA&amp;Ms", "Exceptions", "Mitigations"))
    assert client.get("/remediations?tab=exceptions").status_code == 200
    assert client.get("/remediations?tab=mitigations").status_code == 200


def test_service_remediations_replaces_service_poam_tab_without_breaking_legacy_url():
    client = new_client()
    ingest(client, cves=["CVE-2026-SERVICE-REMEDIATION"])
    page = client.get("/services/payments-service?remediations=true&tab=poams")
    assert page.status_code == 200
    assert "Payments Service Remediations" in page.text
    assert all(label in page.text for label in ("POA&amp;Ms", "Exceptions", "Mitigations"))
    assert 'href="/services/payments-service?remediations=true&amp;tab=poams"' in page.text
    assert client.get("/services/payments-service?remediations=true&tab=exceptions").status_code == 200
    assert client.get("/services/payments-service?remediations=true&tab=mitigations").status_code == 200
    legacy = client.get("/services/payments-service?poam=true")
    assert legacy.status_code == 200 and "Payments Service POA&amp;M" in legacy.text


def test_account_last_login_delete_protection_and_audit_snapshot():
    client = new_client()
    assert client.post("/admin/users", data={"csrf_token": csrf(client), "username": "remove-me", "display_name": "Remove Me", "password": "temporary-password"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "remove-me"))
        user_id = user.id
        assert user.last_login_at is None
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
    assert f'data-exception-url="/policy-findings/{policy_finding_id}/exceptions"' in page.text
    assert f'data-poam-url="/policy-findings/{policy_finding_id}/poams"' in page.text
    assert 'data-label="KSV014"' in page.text
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
    assert "<code>KSV014</code>" in poam_service_page.text
    poam_detail_page = cyber.get(f"/poam/entries/{poam_id}")
    assert "<dt>Finding</dt><dd>KSV014</dd>" in poam_detail_page.text
    exceptions_page = cyber.get("/services/payments-service?finding_state=exceptions&finding_type=configuration")
    assert "KSV014" in exceptions_page.text
    assert f'action="/policy-exceptions/{policy_exception_id}/revoke"' in exceptions_page.text
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
    assert "AVD-KSV-0014" in overdue.text and "Configuration" in overdue.text
    overview = client.get("/services/payments-service?overview=true")
    assert "Active Non-Compliance</span><strong>1</strong>" in overview.text
    assert f'data-exception-url="/policy-findings/{overdue_policy_finding_id}/exceptions"' in overdue.text
    assert f'data-poam-url="/policy-findings/{overdue_policy_finding_id}/poams"' in overdue.text
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
    assert "Payments Service" in manager.get("/").text
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
    page = client.get("/services/payments-service").text
    assert "Skipped images (2)" in page
    assert "registry/legacy-centos:1.0" in page
    assert "Incomplete · 2 skipped" in client.get("/").text


def test_incomplete_execution_without_skipped_images_is_noncompliant():
    client = new_client()
    ingest(client, complete=False, skipped_images=[])
    page = client.get("/services/payments-service?finding_state=noncompliant")
    assert page.status_code == 200
    assert "Latest assessment reported incomplete evidence" in page.text
    assert "No image details reported" not in page.text
    assert "<th>Details</th>" in page.text
    overview = client.get("/services/payments-service?overview=true")
    assert "Active Non-Compliance</span><strong>1</strong>" in overview.text
    assert "overdue-card" in overview.text


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
    assert "Add missing evidence to POA&amp;M" in page.text
    assert "registry/unavailable:demo" in page.text
    assert 'class="secondary-button evidence-poam-action"' in page.text
    assert 'data-image="registry/unavailable:demo"' in page.text
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
    assert first.text.count("<strong>CVE-PAGE-") == 50
    assert "Page 1 of 2" in first.text and "Showing 1" in first.text and "of 60" in first.text
    second = client.get("/services/payments-service?page=2&page_size=50")
    assert second.text.count("<strong>CVE-PAGE-") == 10
    assert "Page 2 of 2" in second.text


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
    assert "Active Fixable</span><strong>2</strong>" in overview.text
    assert "Active Non-Compliance</span><strong>0</strong>" in overview.text

    with SessionLocal() as db:
        for finding in db.scalars(select(Finding)).all():
            finding.episode_started = now - timedelta(days=100)
        db.commit()
    noncompliant = client.get("/services/payments-service?finding_state=noncompliant")
    assert "CVE-KEV-MATCH" in noncompliant.text
    assert "CVE-EPSS-MATCH" in noncompliant.text
    assert "CVE-NO-MATCH" not in noncompliant.text
    overview = client.get("/services/payments-service?overview=true")
    assert "Active Fixable</span><strong>0</strong>" in overview.text
    assert "Active Non-Compliance</span><strong>2</strong>" in overview.text
    dashboard = client.get("/").text
    service_row = dashboard[dashboard.index("Payments Service"):dashboard.index("</tr>", dashboard.index("Payments Service"))]
    assert ">2</td>" in service_row
    assert ">3</td>" not in service_row


def test_administrator_can_edit_service_metadata():
    client = new_client(); ingest(client)
    detail = client.get("/services/payments-service").text
    assert "Edit service information" in detail
    assert "Actions" in detail and ">Edit</button>" in detail and ">Archive</button>" in detail
    overview = client.get("/services/payments-service?overview=true").text
    assert "Edit service information" in overview
    assert '<details class="actions-menu">' in overview
    assert ">Edit</button>" in overview and ">Archive</button>" in overview
    response = client.post("/admin/services/payments-service", data={
        "csrf_token": csrf(client), "name": "Payments Platform", "owner": "Cyber Team",
        "description": "Payments service metadata", "poc": "owner@example.invalid", "manual_version": "3.0",
    }, follow_redirects=False)
    assert response.status_code == 303
    page = client.get("/services/payments-service").text
    assert "Payments Platform" in page and "Version 3.0" in page and "Payments service metadata" in page


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
    assert "helm-test" not in default.text
    assert "View Staged (1)" in default.text
    staged = client.get("/?lifecycle=staged&q=helm-test&sort=name")
    assert staged.status_code == 200
    assert "helm-test" in staged.text
    assert "View Staged (1)" in staged.text
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "helm-test"))
        assert service.lifecycle_status == "staged"
    ingested = ingest(client, execution="helm-test-run", service_id="helm-test")
    assert ingested.status_code == 201
    assert "helm-test" in client.get("/").text
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
    page = manager.get("/").text
    assert "Payments Service" in page and "Other Service" not in page
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
    assert "Revoked" in cyber.get("/requests").text


def test_service_workspace_exposes_embedded_poam_and_activity_tabs():
    client = new_client()
    ingest(client, cves=["CVE-2026-0099"])
    poam = client.get("/services/payments-service?poam=true")
    assert poam.status_code == 200
    assert "Payments Service POA&amp;M" in poam.text
    assert 'href="/services/payments-service?activity=true"' in poam.text
    activity = client.get("/services/payments-service?activity=true")
    assert activity.status_code == 200
    assert "Service activity" in activity.text
    assert "Scan" in activity.text


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
    assert "Create POA&amp;M entry" in poam_index
    assert "Payments Service" in poam_index and "Other Service" not in poam_index
    assert manager.get("/poam/services/other-service").status_code == 403
    service_poam = manager.get("/poam/services/payments-service")
    assert service_poam.status_code == 200
    assert "Payments Service POA&amp;M" in service_poam.text
    noncompliant_page = manager.get("/services/payments-service?finding_state=noncompliant").text
    assert 'class="secondary-button poam-action"' in noncompliant_page
    assert 'data-title="Remediate CVE-2026-0002"' in noncompliant_page
    assert 'id="shared-poam-dialog"' in noncompliant_page
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
    detail = cyber.get("/poam/services/payments-service").text
    assert "Missing authorization evidence" in detail and "Active" in detail
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
    completed_page = cyber.get(f"/poam/entries/{entries[0].id}").text
    assert "Completed" in completed_page and "EVIDENCE-2026-42" in completed_page
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
    assert "Create POA&amp;M entry" not in assessor_index


def test_audit_logs_default_to_ten_and_expand_within_retention():
    client = new_client()
    with SessionLocal() as db:
        for number in range(15):
            db.add(AuditEvent(action=f"test.event.{number}", target_type="test", target_id=str(number)))
        db.commit()
    default_page = client.get("/admin/audit")
    assert default_page.status_code == 200
    assert "Showing 10 of" in default_page.text
    assert default_page.text.count("test.event.") == 10
    expanded = client.get("/admin/audit?show=60")
    assert expanded.text.count("test.event.") == 15
    assert "Collapse to latest 10" in expanded.text


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
    assert "Payments Service" in cyber.get("/?archived=true").text


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
    service_page = client.get("/services/payments-service").text
    assert "Export to Excel" in service_page
    overview_page = client.get("/services/payments-service?overview=true").text
    assert '>Export</a>' in overview_page
    assert 'class="secondary-button" href="/services/payments-service?architecture=true">Architecture</a>' not in overview_page
    assert 'class="secondary-button" href="/services/payments-service/helm-diagram.svg">Helm Diagram</a>' not in overview_page
    diagram = client.get("/services/payments-service/helm-diagram.svg")
    assert diagram.status_code == 200
    assert diagram.headers["content-type"].startswith("image/svg+xml")
    assert "Helm rendering" in diagram.text
    assert "Ports / protocols" in diagram.text
    assert "Latest Evidence:" in service_page and "None received" not in service_page
    assert "metric-card selected" in service_page
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
    assert "POC: cats-test-poc@example.invalid" in page.text
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
    assert "Overdue Findings" in client.get("/").text


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
    assert "Global runtime preferences" in page.text
    assert "Group Scope" not in page.text
    assert "America/Los_Angeles" in page.text
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
    assert "Operating system" in page.text
    assert "OS ID" in page.text
    assert "Package manager" in page.text
    assert "Image-defined" in page.text


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
    assert 'data-theme="blue"' in client.get("/").text
    assert "Saved successfully." in client.get("/account/appearance?saved=1").text


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
