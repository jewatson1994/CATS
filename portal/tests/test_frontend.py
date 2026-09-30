import json
from types import SimpleNamespace
from datetime import datetime, timezone

import pytest
from starlette.requests import Request

from app.frontend import PAGE_MEDIA_TYPE, MIGRATED_PAGES, ReactTemplates, page_data


def request(accept="text/html"):
    return Request({"type": "http", "method": "GET", "scheme": "https", "path": "/",
                    "query_string": b"page=2", "headers": [(b"accept", accept.encode())],
                    "server": ("cats.test", 443)})


@pytest.fixture
def templates(tmp_path):
    for name in ("login.html", "dashboard.html", "legacy.html"):
        (tmp_path / name).write_text("legacy {{ error }}", encoding="utf-8")
    return ReactTemplates(directory=tmp_path, frontend_index=tmp_path / "index.html")


def test_vendor_dto_omits_secrets_and_counts_findings(templates):
    user = SimpleNamespace(display_name="Jane", theme="cats", role="admin", password_hash="secret", token="secret")
    service = SimpleNamespace(id=1, service_key="a", name="A", owner="Jane", poc="Jane", token="secret")
    context = {"current_user": user, "csrf_token": "csrf", "session": "secret", "can": lambda _: True,
               "views": [{"service": service, "active": [{"token": "secret"}], "policy_findings": [1],
                          "noncompliant": [], "excepted": [], "compliant": False}],
               "stage_groups": [SimpleNamespace(id=4, name="Group", secret="secret")]}
    response = templates.TemplateResponse(request(PAGE_MEDIA_TYPE), "dashboard.html", context)
    payload = json.loads(response.body)
    assert payload["schemaVersion"] == 1 and payload["page"] == "dashboard"
    assert payload["data"]["csrf_token"] == "csrf"
    assert payload["data"]["current_user"] == {"display_name": "Jane", "theme": "cats"}
    assert payload["data"]["views"][0]["active_count"] == 2
    assert "secret" not in response.body.decode() and "password_hash" not in response.body.decode()
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["vary"] == "Accept"


def test_html_bootstrap_escapes_script_and_preserves_post_error(templates):
    templates.frontend_index.write_text("<html><head></head><body>React</body></html>", encoding="utf-8")
    error = '</script><script>alert("x")</script>&\u2028\u2029'
    response = templates.TemplateResponse(request(), "login.html", {"error": error}, status_code=401)
    body = response.body.decode()
    assert response.status_code == 401
    assert error not in body and "\\u003c/script\\u003e" in body
    serialized = body.split('id="cats-bootstrap">', 1)[1].split("</script>", 1)[0]
    assert json.loads(serialized)["data"]["error"] == error


def test_legacy_fallback_and_nonmigrated_pages(templates):
    response = templates.TemplateResponse(request(), "login.html", {"error": "failure"})
    assert response.body == b"legacy failure"
    response = templates.TemplateResponse(request(PAGE_MEDIA_TYPE), "legacy.html", {"error": "unchanged"})
    assert response.body == b"legacy unchanged"


def test_old_signature_and_quality_zero(templates):
    response = templates.TemplateResponse("login.html", {"request": request(PAGE_MEDIA_TYPE), "error": "bad"}, 403)
    assert response.status_code == 403 and json.loads(response.body)["page"] == "login"
    response = templates.TemplateResponse(request(PAGE_MEDIA_TYPE + ";q=0, text/html"), "login.html", {"error": "bad"})
    assert response.body == b"legacy bad"


def test_keyword_signature_and_vary_preservation(templates):
    response = templates.TemplateResponse(request=request(PAGE_MEDIA_TYPE), name="login.html", context={},
                                          headers={"Vary": "Cookie"})
    assert response.headers["vary"] == "Cookie, Accept"


def test_self_service_job_and_ingestion_projection(templates):
    context = {"mode": "scan", "archive_names": ["chart.tgz"], "authenticated_ingest": True,
               "authenticated_services": [SimpleNamespace(service_key="test", name="Test", token="secret")],
               "service_version_options": {"test": ["1.0"]}, "job_id": "public-id",
               "job": {"status": "running", "phase": "scan_sboms", "oidc_access_token": "secret",
                       "summary": {"reports": 2, "formats": ["json"], "password": "secret"}}}
    response = templates.TemplateResponse(request(PAGE_MEDIA_TYPE), "self_service.html", context)
    data = json.loads(response.body)["data"]
    assert data["archive_names"] == ["chart.tgz"]
    assert data["authenticated_services"] == [{"service_key": "test", "name": "Test"}]
    assert data["job"]["summary"]["reports"] == 2
    assert "secret" not in response.body.decode()


def test_errors_preserve_status_and_safe_home_link(templates):
    response = templates.TemplateResponse(request(PAGE_MEDIA_TYPE), "request_error.html",
                                          {"detail": "No access", "home_url": "/"}, status_code=403)
    payload = json.loads(response.body)
    assert response.status_code == 403 and payload["page"] == "request_error"
    assert payload["data"]["detail"] == "No access"


def test_patch_registry_and_signing_metadata_omit_credentials(templates):
    context = {"signing": {"enabled": True, "private_key": "secret"},
               "configured_registries": [{"id": "r", "display_name": "Registry", "endpoint": "registry.test",
                                            "namespace": "app", "password": "secret"}],
               "job": {"status": "queued", "credentials": "secret"}, "patch_phases": ["queued", "patching_image"],
               "can": lambda permission: permission == "user.manage"}
    response = templates.TemplateResponse(request(PAGE_MEDIA_TYPE), "patch.html", context)
    data = json.loads(response.body)["data"]
    assert data["signing"] == {"enabled": True}
    assert data["patch_phases"] == ["queued", "patching_image"]
    assert data["can"]["user.manage"] == {"*": True}
    assert "secret" not in response.body.decode()


def test_service_projection_scopes_permissions_and_formats_dates():
    calls = []
    def can(permission, service_id=None):
        calls.append((permission, service_id))
        return service_id == 9
    now = datetime(2026, 9, 30, tzinfo=timezone.utc)
    service = SimpleNamespace(id=9, service_key="test", name="Test", groups=[SimpleNamespace(id=2, name="Group", token="secret")], token="secret")
    finding = SimpleNamespace(id=3, cve="CVE-2026-1", severity="High", active=True,
                              episode_started=datetime(2026, 9, 25), last_seen=now, raw_payload={"password": "secret"})
    context = {"can": can, "view": {"service": service, "version": "1.0", "last_execution": now,
               "due_dates": {3: now}, "risk_metadata": {3: {"kev": True, "epss": .42, "secret": "secret"}}},
               "findings": [finding], "now": now, "affected_images": {3: ["image:1"]},
               "active_exception": lambda item, at: SimpleNamespace(id=7, expires_at=now, justification="secret")}
    payload = page_data(request(), "service.html", context, formatters={"cats_date": lambda _: "09/30/2026", "cats_datetime": lambda _: "09/30/2026 12:00"})
    data = payload["data"]
    row = data["findings"][0]
    assert row["episode_days"] == 5 and row["due"] == "09/30/2026"
    assert row["exception"] == {"id": 7, "expires_at": "09/30/2026"}
    assert data["can"]["exception.request"] == {"9": True}
    assert ("exception.request", 9) in calls
    assert data["view"]["last_execution"] == "09/30/2026 12:00"
    assert "secret" not in json.dumps(payload)
    assert "service.html" not in MIGRATED_PAGES and "service_simplified.html" not in MIGRATED_PAGES


def test_service_policy_and_simplified_projection():
    context = {"view": {"service": SimpleNamespace(id=9, service_key="test", groups=[]),
                        "policy_due_dates": {4: datetime(2026, 9, 30)}},
               "policy_findings": [SimpleNamespace(id=4, finding="CFG", title="Config", description="Details", secret="secret")],
               "remediation_classes": {4: {"classification": "REMEDIABLE", "reason": "Fix", "credentials": "secret"}},
               "simplified_findings": [{"package": "pkg", "fixed_version": "2", "images": ["image"],
                                        "cves": ["CVE"], "finding_ids": [3], "due": datetime(2026, 9, 30), "secret": "secret"}]}
    payload = page_data(request(), "service_simplified.html", context)
    assert payload["data"]["policy_findings"][0]["remediation_classification"] == "REMEDIABLE"
    assert payload["data"]["simplified_findings"][0]["due"] == "2026-09-30T00:00:00"
    assert "secret" not in json.dumps(payload)
