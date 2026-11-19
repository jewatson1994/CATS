"""Bounded real-session HTTP acceptance against the isolated GUI fixture portal.

Credentials are read from CATS_BOOTSTRAP_PASSWORD, never written to evidence.
Uses GETs after ordinary /login form submissions; no dependency overrides,
fixture permission changes, service mutations, or diagnostic insertion.
"""
import argparse
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor, HTTPRedirectHandler, Request
import uuid


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cookies = CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookies), NoRedirect())

    def request(self, path, form=None, accept="application/json"):
        correlation = uuid.uuid4().hex
        headers = {"Accept": accept, "X-Correlation-ID": correlation}
        data = None
        if form is not None:
            data = urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            response = self.opener.open(Request(self.base + path, data=data, headers=headers), timeout=20)
        except HTTPError as error:
            response = error
        with response:
            status, response_headers, raw = response.status, response.headers, response.read().decode()
        body = json.loads(raw) if "json" in response_headers.get("content-type", "") else raw
        assert response_headers.get("x-correlation-id") == correlation, "Correlation header mismatch"
        if path.startswith(("/admin/diagnostics", "/api/diagnostics")) or status >= 400:
            assert "no-store" in response_headers.get("cache-control", ""), "Missing no-store"
        return status, response_headers, body

    def login(self, username, password):
        status, headers, _ = self.request("/login", {"username": username, "password": password, "next": "/admin/diagnostics"})
        assert status == 303 and headers.get("location") == "/admin/diagnostics", "Fixture login failed or requires password/access setup"
        assert any(cookie.name == "cats_session" and cookie.value for cookie in self.cookies), "Login did not issue a session"


def run(base):
    password = os.environ.get("CATS_BOOTSTRAP_PASSWORD")
    if not password:
        raise RuntimeError("CATS_BOOTSTRAP_PASSWORD is required")
    checks = []
    admin = Client(base)
    admin.login("diagnostics-admin", password)
    checks.append({"check": "admin_real_login", "passed": True})
    status, _, page = admin.request("/admin/diagnostics", accept="application/vnd.cats.page+json")
    assert status == 200 and page["data"]["may_view_diagnostics"] is True
    checks.append({"check": "admin_center", "status": status})

    def history(params):
        status, _, body = admin.request("/api/diagnostics?" + urlencode(params))
        assert status == 200 and isinstance(body["items"], list)
        return body

    owned = history({"correlation_id": "diagnostics-gui-ownerless"})
    assert owned["total"] >= 1, "Run gui_seed.py --url first"
    event = owned["items"][0]
    assert event["code"] == "CAT-SVC-OWNERSHIP-001" and event["status"] == 409
    assert event["cause"] == "Service has no owning group"
    assert "exactly one" in " ".join(event["resolution"])
    error_id = event["error_id"]
    status, _, detail = admin.request("/api/diagnostics/" + error_id)
    assert status == 200 and detail["error_id"] == error_id
    exceptions = detail["technical"]["exceptions"]
    assert any(frame.get("file") == "service_ownership.py" for exception in exceptions for frame in exception.get("frames", []))
    checks.append({"check": "retained_ownerless_ingestion", "status": status, "error_id": error_id,
                   "correlation_id": event["correlation_id"], "original_status": 409, "source_frame_preserved": True})

    worker = history({"component": "remediation worker"})
    assert worker["total"] >= 3
    item = worker["items"][0]
    resource = item["resource"]
    stamp = datetime.fromisoformat(item["timestamp"])
    filters = {"component": item["component"], "service_id": resource["service_id"], "job_id": resource["job_id"],
               "severity": item["severity"], "correlation_id": item["correlation_id"], "q": item["code"],
               "since": (stamp - timedelta(seconds=1)).isoformat(), "until": (stamp + timedelta(seconds=1)).isoformat()}
    matched = history(filters)
    assert matched["total"] == 1 and matched["items"][0]["error_id"] == item["error_id"]
    assert history({"q": "no-such-diagnostic-fixture-94827"})["total"] == 0
    first = history({"component": "remediation worker", "limit": 1, "offset": 0})
    second = history({"component": "remediation worker", "limit": 1, "offset": 1})
    assert first["total"] == second["total"] and first["items"][0]["error_id"] != second["items"][0]["error_id"]
    checks.append({"check": "all_query_filters_and_pagination", "passed": True, "worker_records": worker["total"]})
    status, _, summary = admin.request("/api/diagnostics/summary")
    assert status == 200 and any(row["component"] == "remediation worker" and row["count"] >= 3 for row in summary["items"])
    checks.append({"check": "admin_recurrence", "status": status})

    serialized = json.dumps(worker)
    assert "GUI_FAKE_SECRET_MUST_NOT_APPEAR" not in serialized
    assert item["technical"]["api_key"].lower() == "[redacted]"
    assert item["technical"]["exceptions"], "Authorized exception evidence missing"
    status, _, job = admin.request("/api/v1/jobs/" + resource["jobs_view_id"])
    assert status == 200 and "technical" not in job["diagnostic"]
    checks.append({"check": "admin_exception_redaction_and_public_job_projection", "status": status, "passed": True})

    routes = ["/admin/diagnostics", "/api/diagnostics", "/api/diagnostics/summary", "/api/diagnostics/" + error_id]
    viewer = Client(base)
    viewer.login("diagnostics-viewer", os.environ.get("GUI_DIAGNOSTIC_VIEWER_PASSWORD") or password)
    checks.append({"check": "viewer_real_login", "passed": True})
    for role, client in (("anonymous", Client(base)), ("viewer", viewer)):
        for route in routes:
            status, headers, body = client.request(route)
            assert status in ({303, 401, 403} if role == "anonymous" else {403}), "Protected route was accessible"
            if isinstance(body, dict) and "diagnostic" in body:
                diagnostic = body["diagnostic"]
                assert "technical" not in diagnostic and diagnostic["resource"] == {}
                assert diagnostic["correlation_id"] == headers["x-correlation-id"]
            elif status == 303:
                assert headers.get("location", "").startswith("/login")
            else:
                raise AssertionError("Expected projected denial diagnostic")
            checks.append({"check": role + "_denied", "route": route, "status": status})
    # Independent real login verifies a new session sees the persisted event.
    refreshed = Client(base)
    refreshed.login("diagnostics-admin", password)
    status, _, again = refreshed.request("/api/diagnostics/" + error_id)
    assert status == 200 and again["error_id"] == error_id
    checks.append({"check": "persisted_across_new_session", "passed": True})
    return {"passed": True, "base_url": base, "checked_at": datetime.now(timezone.utc).isoformat(),
            "scope": "Real HTTP sessions; GET-only acceptance after login; synthetic isolated fixtures", "checks": checks}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18089")
    parser.add_argument("--output", default=".test-temp/diagnostics-gui-20261116/live-http.json")
    args = parser.parse_args()
    result = run(args.url)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "checks": len(result["checks"]), "evidence": str(output)}))
