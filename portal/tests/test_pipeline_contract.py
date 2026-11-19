"""Keep the published CI contract and the executable integration example in sync."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import main
from app.database import SessionLocal
from app.models import Finding, PolicyFinding
from test_portal import pipeline_headers, setup_function


PIPELINE = "/api/v1/pipeline-results"
AMENDMENT = "/api/v1/amendment-assessments/{proposal_id}"


def documented_execution():
    guide = Path(__file__).resolve().parents[2] / "docs" / "api-integration.md"
    example = guide.read_text(encoding="utf-8").split("```json\n", 1)[1].split("\n```", 1)[0]
    return json.loads(example)


def test_pipeline_schema_matches_registered_operations():
    client = TestClient(main.app)
    contract = client.get("/api/v1/pipeline/openapi.json").json()
    full = client.get("/openapi.json").json()
    assert set(contract["paths"]) == {PIPELINE, AMENDMENT}
    assert contract["components"]["securitySchemes"]["PipelineBearer"]["scheme"] == "bearer"
    for path, receipt in ((PIPELINE, "PipelineReceipt"), (AMENDMENT, "AmendmentReceipt")):
        operation = contract["paths"][path]["post"]
        assert operation == full["paths"][path]["post"]
        assert operation["security"] == [{"PipelineBearer": []}]
        assert operation["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith("/ExecutionPayload")
        assert operation["responses"]["201"]["content"]["application/json"]["schema"]["$ref"].endswith("/" + receipt)
        assert operation["responses"]["422"]["content"]["application/json"]["schema"]["$ref"].endswith("/PipelineError")


def test_full_schema_has_one_handler_per_operation():
    operations = [(method, route.path) for route in main.app.routes
                  if isinstance(route, APIRoute) and route.include_in_schema for method in route.methods]
    assert len(operations) == len(set(operations))
    operation = main.app.openapi()["paths"]["/admin/validators"]["get"]
    assert "text/html" in operation["responses"]["200"]["content"]


def test_documented_execution_round_trip_and_conflict():
    client = TestClient(main.app)
    body = documented_execution()
    first = client.post(PIPELINE, json=body, headers=pipeline_headers)
    assert first.status_code == 201, first.text
    first_result = first.json()
    assert first_result == {"accepted": True, "duplicate": False,
                            "execution_id": first_result["execution_id"], "deployment_validation_run_id": None}
    assert isinstance(first_result["execution_id"], int)
    second = client.post(PIPELINE, json=body, headers=pipeline_headers)
    assert second.status_code == 201
    assert second.json() == {"accepted": True, "duplicate": True, "execution_id": first_result["execution_id"]}
    conflicting = client.post(PIPELINE, json={**body, "complete": True}, headers=pipeline_headers)
    assert conflicting.status_code == 409
    assert conflicting.json()["diagnostic"]["correlation_id"] == conflicting.headers["X-Correlation-ID"]


def test_partial_scopes_only_resolve_findings_in_their_coverage():
    client = TestClient(main.app)
    example = documented_execution()
    image = example["scope_image"]
    started = datetime.now(timezone.utc) - timedelta(hours=1)
    def submit(index, scope, **evidence):
        response = client.post(PIPELINE, headers=pipeline_headers, json={
            **example, "scan_scope": scope, "execution_id": f"coverage-run-{index}", "complete": True,
            "scanned_at": (started + timedelta(minutes=index)).isoformat(), **evidence,
        })
        assert response.status_code == 201, response.text

    def active():
        with SessionLocal() as db:
            return (set(db.scalars(select(Finding.cve).where(Finding.active.is_(True)))),
                    set(db.scalars(select(PolicyFinding.finding).where(PolicyFinding.active.is_(True)))))

    submit(1, "service", findings=[{"cve": "CVE-2026-0001", "image": image},
                                   {"cve": "CVE-2026-0002", "image": "other:1.0"}],
           policy_findings=[{"finding": "policy-01"}])
    submit(2, "evidence")
    assert active() == ({"CVE-2026-0001", "CVE-2026-0002"}, {"policy-01"})
    submit(3, "image")
    assert active() == ({"CVE-2026-0002"}, {"policy-01"})
    submit(4, "service")
    assert active() == (set(), set())


@pytest.mark.parametrize("path", [PIPELINE, AMENDMENT.format(proposal_id=1)])
def test_pipeline_requires_configured_bearer(monkeypatch, path):
    client = TestClient(main.app)
    body = documented_execution()
    for header in ("", "test-token", "Basic test-token", "Bearer wrong"):
        denied = client.post(path, json=body, headers={"Authorization": header})
        assert denied.status_code == 401
        assert denied.headers["WWW-Authenticate"] == "Bearer"
    monkeypatch.delenv("PIPELINE_API_TOKEN")
    assert client.post(path, json=body, headers=pipeline_headers).status_code == 503
    monkeypatch.setenv("PIPELINE_API_TOKEN", "")
    assert client.post(path, json=body).status_code == 503


@pytest.mark.parametrize("url", [PIPELINE, AMENDMENT.format(proposal_id=1)])
def test_pipeline_limits_declared_and_streamed_lengths(monkeypatch, url):
    client = TestClient(main.app)
    monkeypatch.setattr(main, "PIPELINE_MAX_REQUEST_BYTES", 64)
    for length, expected in (("65", 413), ("1", 413), ("-1", 400), ("invalid", 400)):
        response = client.post(url, json=documented_execution(), headers={"Content-Length": length})
        assert response.status_code == expected
    for endpoint in (url, url + "/"):
        response = client.post(endpoint, content=iter([b"x" * 32, b"y" * 33]), follow_redirects=False)
        assert response.status_code == 413
