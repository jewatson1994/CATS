"""Contracts for persisted, authorized diagnostics and the original ingestion failure."""
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.orm import sessionmaker
from starlette.responses import JSONResponse, StreamingResponse

from app import main
from app.auth import hash_password
from app.database import SessionLocal
from app.diagnostic_http import DiagnosticMiddleware
from app.diagnostic_migrations import upgrade_connection
from app.diagnostic_routes import administrator
from app.diagnostic_store import DiagnosticEvent, cleanup, record_diagnostic
from app.diagnostics import build_diagnostic
from app.models import Role, Service, User, UserRoleAssignment
from test_portal import new_client, payload, pipeline_headers, setup_function


def test_original_existing_service_without_owner_409_survives_refresh():
    client = new_client()
    with SessionLocal() as db:
        db.add(Service(service_key="ownerless", name="Ownerless", manual_version="1"))
        db.commit()
    body = payload("ownerless-scan", datetime.now(timezone.utc), [], service_id="ownerless")
    response = client.post("/api/v1/pipeline-results", json=body,
        headers={**pipeline_headers, "X-Correlation-ID": "ingestion-regression-001"})
    assert response.status_code == 409, response.text
    item = response.json()["diagnostic"]
    assert item["code"] == "CAT-SVC-OWNERSHIP-001"
    assert item["cause"] == "Service has no owning group"
    assert "exactly one" in " ".join(item["resolution"])
    assert "technical" not in item
    assert item["correlation_id"] == response.headers["x-correlation-id"] == "ingestion-regression-001"
    # A new request/client loads the same persisted record, not a browser notice cache.
    refreshed = new_client().get("/api/diagnostics/" + item["error_id"])
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["error_id"] == item["error_id"]
    assert "service_ownership.py" in json.dumps(refreshed.json()["technical"])
    assert "no-store" in refreshed.headers["cache-control"]
    history = client.get("/api/diagnostics", params={"correlation_id": item["correlation_id"]}).json()
    assert history["total"] == 1
    assert history["items"][0]["code"] == item["code"]
    page = client.get("/admin/diagnostics", headers={"Accept": "application/json"})
    assert page.status_code == 200


@pytest.mark.parametrize("permissions", [["audit.view"], ["config.manage"], ["service.view"]])
def test_history_requires_both_global_administrator_capabilities(permissions):
    with SessionLocal() as db:
        role = Role(name="Limited diagnostics user", permissions=permissions)
        user = User(username="limited", display_name="Limited", password_hash=hash_password("test-password-long"), must_change_password=False)
        db.add_all([role, user]); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id)); db.commit()
    client = new_client("limited")
    for route in ("/api/diagnostics", "/api/diagnostics/summary", "/api/diagnostics/unknown", "/admin/diagnostics"):
        response = client.get(route, headers={"Accept": "application/json"})
        assert response.status_code == 403, response.text
        assert "technical" not in response.json()["diagnostic"]


def test_scope_only_permissions_do_not_grant_diagnostic_history():
    with pytest.raises(HTTPException) as error:
        administrator(SimpleNamespace(has=lambda permission: False))
    assert error.value.status_code == 403
    response = TestClient(main.app).get("/api/diagnostics", follow_redirects=False)
    assert response.status_code in (303, 401, 403)


def test_history_search_filter_recurrence_and_retention(monkeypatch):
    client = new_client()
    for job, component in (("a", "Scan worker"), ("b", "Scan worker"), ("c", "Patch worker")):
        assert record_diagnostic(build_diagnostic(TimeoutError("scan timed out"), component=component,
            operation="scan", resource={"job_id": job, "service_id": 42}))
    result = client.get("/api/diagnostics", params={"component": "Scan worker", "service_id": 42, "job_id": "b", "severity": "error", "q": "TIMEOUT", "limit": 1}).json()
    assert result["total"] == 1 and result["items"][0]["resource"]["job_id"] == "b"
    summary = client.get("/api/diagnostics/summary").json()
    assert any(row["component"] == "Scan worker" and row["count"] == 2 for row in summary["items"])
    assert client.get("/api/diagnostics", params={"q": "%"}).json()["total"] == 0
    assert client.get("/api/diagnostics", params={"limit": 201}).status_code == 422
    with SessionLocal() as db:
        row = db.scalar(select(DiagnosticEvent).where(DiagnosticEvent.job_id == "a"))
        old_id = row.error_id
        row.timestamp = datetime.now(timezone.utc) - timedelta(days=40)
        db.commit()
    assert client.get("/api/diagnostics/" + old_id).status_code == 404
    with SessionLocal() as db:
        cleanup(db); db.commit()
        assert db.get(DiagnosticEvent, old_id) is None


def test_bounded_retention_idempotent_migration_and_separate_transaction(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///" + str(tmp_path / "diagnostics.db"))
    factory = sessionmaker(bind=engine)
    with engine.begin() as connection:
        upgrade_connection(connection); upgrade_connection(connection)
    assert len(inspect(engine).get_indexes("diagnostic_events")) >= 7
    monkeypatch.setenv("CATS_DIAGNOSTIC_MAX_EVENTS", "100")
    for index in range(104):
        item = build_diagnostic("failure", component="test", operation=str(index))
        assert record_diagnostic(item, factory)
    assert record_diagnostic(item, factory)  # idempotent retry
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(DiagnosticEvent)) == 100
    assert record_diagnostic(item, lambda: (_ for _ in ()).throw(RuntimeError("storage down"))) is False
    engine.dispose()


def test_early_middleware_errors_streams_and_storage_failure(monkeypatch):
    from app import diagnostic_http
    collected = []
    monkeypatch.setattr(diagnostic_http, "enqueue_diagnostic", lambda item: collected.append(item) or False)
    app = FastAPI()
    @app.get("/raw")
    def raw():
        return JSONResponse({"detail": "Missing scan-worker credentials password=hidden-value"}, status_code=409)
    @app.get("/crash")
    def crash():
        raise RuntimeError("vendor error E567 token=hidden-value")
    @app.get("/stream")
    def stream():
        return StreamingResponse(iter([b"one", b"two"]), media_type="text/plain")
    app.add_middleware(DiagnosticMiddleware)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/raw")
    assert response.status_code == 409
    assert response.json()["diagnostic"]["code"] == "CAT-SCAN-CREDENTIALS-001"
    assert "hidden-value" not in response.text
    crash = client.get("/crash")
    assert crash.status_code == 500 and crash.json()["diagnostic"]["cause"] is None
    assert "E567" in json.dumps(collected[-1]["technical"])
    assert "hidden-value" not in json.dumps(collected)
    assert client.get("/stream").content == b"onetwo"


def test_optional_validation_failure_is_terminal_and_keeps_diagnostic(monkeypatch):
    from app.models import DeploymentValidationRun
    with SessionLocal() as db:
        service = Service(service_key="validation-failure", name="Validation", manual_version="1")
        db.add(service); db.flush()
        run = DeploymentValidationRun(run_key="DV-DIAGNOSTIC", service_id=service.id, status="QUEUED", phase="QUEUED", artifact_type="ORIGINAL", engine="kind")
        db.add(run); db.commit(); run_id = run.id
    def fail(_):
        raise RuntimeError("validator connection refused token=hidden-value")
    monkeypatch.setattr(main, "_execute_deployment_validation", fail)
    main._run_deployment_validation(run_id)
    with SessionLocal() as db:
        run = db.get(DeploymentValidationRun, run_id)
        assert run.phase == "COMPLETE" and run.completed_at
        assert run.diagnostics["diagnostic"]["code"] == "CAT-VALIDATOR-CONNECTION-001"
        assert "hidden-value" not in json.dumps(run.diagnostics)
        run.diagnostics = {**run.diagnostics, "diagnostic": build_diagnostic(
            RuntimeError("internal validator evidence"), component="Validator", operation="validate")}
        rendered = main.deployment_validation_view(run)
        assert "technical" not in rendered["diagnostics"]["diagnostic"]
        assert "technical" in run.diagnostics["diagnostic"]
