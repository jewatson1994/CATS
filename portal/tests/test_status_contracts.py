"""Lightweight polling contracts: small, revisioned, and authorized like detail."""
from datetime import datetime, timezone
import json

from sqlalchemy import select

from app.database import SessionLocal
from app.models import DeploymentValidationRun, Execution, RemediationExecution, Role, Service, User, UserRoleAssignment
from app.auth import hash_password
from test_portal import new_client, payload, pipeline_headers, setup_function  # noqa: F401

BIG = ["evidence line " * 40 for _ in range(400)]


def _service_and_execution(client, key="payments-service"):
    assert client.post("/api/v1/pipeline-results", json=payload("status-run", datetime.now(timezone.utc), ["CVE-1"], service_id=key),
                       headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == key))
        execution = db.scalar(select(Execution).where(Execution.service_id == service.id))
        return service.id, execution.id


def _outsider():
    with SessionLocal() as db:
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        other = Service(service_key="other-service", name="Other", lifecycle_status="active")
        db.add(other); db.flush()
        user = User(username="outsider", display_name="Outsider", password_hash=hash_password("test-password-long"),
                    must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, service_id=other.id)); db.commit()
    return new_client("outsider")


def test_validation_status_is_small_revisioned_and_matches_detail_terminal():
    client = new_client()
    service_id, execution_id = _service_and_execution(client)
    with SessionLocal() as db:
        db.add(DeploymentValidationRun(run_key="DV-STATUS", service_id=service_id, execution_id=execution_id,
            status="RUNNING", phase="INSTALLING", cleanup_status="PENDING", events=[{"message": m} for m in BIG],
            diagnostics={"logs": BIG}, observed_topology={"resources": BIG}))
        db.commit()
    root = "/api/v1/services/payments-service/deployment-validations/DV-STATUS"
    detail = client.get(root)
    status = client.get(root + "/status")
    assert status.status_code == 200 and status.headers["cache-control"] == "no-store"
    body = status.json()
    assert len(status.content) < 10_000 < len(detail.content)
    assert body["status"] == "RUNNING" and body["terminal"] is False and body["terminal"] == detail.json()["terminal"]
    assert "events" not in body and "diagnostics" not in body and "observed_topology" not in body
    assert client.get(root + "/status").json()["revision"] == body["revision"]
    with SessionLocal() as db:
        run = db.scalar(select(DeploymentValidationRun).where(DeploymentValidationRun.run_key == "DV-STATUS"))
        run.status, run.phase, run.cleanup_status = "VERIFIED", "COMPLETE", "COMPLETE"
        run.completed_at = run.updated_at = datetime.now(timezone.utc)
        db.commit()
    final = client.get(root + "/status").json()
    assert final["revision"] != body["revision"]
    assert final["terminal"] is True and final["terminal"] == client.get(root).json()["terminal"]


def test_remediation_status_excludes_evidence_and_tracks_stage_changes():
    client = new_client()
    service_id, execution_id = _service_and_execution(client)
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        db.add(RemediationExecution(job_key="R-STATUS", service_id=service_id, requested_by_id=admin.id,
            status="running", phase="patch_images", source_execution_id=execution_id,
            stages={"snapshot": {"status": "success", "detail": "x" * 5000}, "patch_images": {"status": "running"}},
            validation_results={"checks": {str(n): {"detail": line} for n, line in enumerate(BIG)}},
            configuration_changes=[{"detail": line} for line in BIG], logs=BIG))
        db.commit()
    root = "/api/v1/services/payments-service/remediations/R-STATUS"
    status = client.get(root + "/status")
    body = status.json()
    assert status.status_code == 200 and len(status.content) < 10_000
    assert body["active"] is True and body["terminal"] is False
    assert body["stages"]["patch_images"]["status"] == "running"
    assert len(body["stages"]["snapshot"]["detail"]) <= 240
    assert not {"validation", "validation_results", "configuration_changes", "logs"} & set(body)
    assert len(client.get(root).content) > 100_000  # the existing full API is unchanged
    with SessionLocal() as db:
        record = db.scalar(select(RemediationExecution).where(RemediationExecution.job_key == "R-STATUS"))
        record.stages = {**record.stages, "patch_images": {"status": "success"}}
        record.phase = "rewrite_artifacts"
        db.commit()
    changed = client.get(root + "/status").json()
    assert changed["revision"] != body["revision"] and changed["phase"] == "rewrite_artifacts"
    assert client.get(root + "/status").json()["revision"] == changed["revision"]


def test_status_contracts_enforce_service_scope():
    client = new_client()
    service_id, execution_id = _service_and_execution(client)
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        db.add(DeploymentValidationRun(run_key="DV-SCOPE", service_id=service_id, execution_id=execution_id))
        db.add(RemediationExecution(job_key="R-SCOPE", service_id=service_id, requested_by_id=admin.id,
                                    status="running", source_execution_id=execution_id))
        db.commit()
    outsider = _outsider()
    for url in ("/api/v1/services/payments-service/deployment-validations/DV-SCOPE/status",
                "/api/v1/services/payments-service/remediations/R-SCOPE/status",
                f"/api/v1/services/payments-service/dependencies/status?execution_id={execution_id}"):
        assert outsider.get(url).status_code in {403, 404}, url
    # A run belonging to another service is never resolved through this service.
    assert outsider.get("/api/v1/services/other-service/deployment-validations/DV-SCOPE/status").status_code == 404
    assert outsider.get(f"/api/v1/services/other-service/dependencies/status?execution_id={execution_id}").status_code == 404


def test_dependency_status_reports_preparation_and_schedules_pending_work(monkeypatch):
    from app import dependency_queries
    scheduled = []
    monkeypatch.setattr(dependency_queries, "schedule_projection", lambda *args: scheduled.append(args[1]))
    client = new_client()
    _service_id, execution_id = _service_and_execution(client)
    url = f"/api/v1/services/payments-service/dependencies/status?execution_id={execution_id}"
    first = client.get(url)
    assert first.status_code == 200 and len(first.content) < 1000
    body = first.json()
    assert body["status"] in {"pending", "building", "ready"} and body["execution_id"] == execution_id
    if body["status"] == "pending":
        assert scheduled == [execution_id]
    assert json.dumps(body).count("build_token") == 0
    assert client.get(f"/api/v1/services/payments-service/dependencies/status?execution_id=999999").status_code == 404


def test_status_contracts_never_select_evidence_columns():
    """The status queries themselves must not read heavy evidence columns,
    not only omit them from the response."""
    from sqlalchemy import event
    from app.database import engine
    client = new_client()
    service_id, execution_id = _service_and_execution(client)
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        db.add(RemediationExecution(job_key="R-COLS", service_id=service_id, requested_by_id=admin.id, status="running",
                                    phase="patch_images", source_execution_id=execution_id, logs=BIG,
                                    validation_results={"checks": {"a": {"detail": "x"}}}))
        db.add(DeploymentValidationRun(run_key="DV-COLS", service_id=service_id, execution_id=execution_id, status="RUNNING",
                                       phase="INSTALLING", cleanup_status="PENDING", events=[{"m": line} for line in BIG],
                                       diagnostics={"logs": BIG}))
        db.commit()
    heavy = {
        "remediation_executions": ("validation_results", "before_snapshot", "after_snapshot", "logs", "patched_images",
                                   "configuration_changes", "changed_artifacts"),
        "deployment_validation_runs": ("events", "observed_topology", "comparison", "diagnostics"),
        "executions": ("raw_payload",),
    }
    for url in ("/api/v1/services/payments-service/remediations/R-COLS/status",
                "/api/v1/services/payments-service/deployment-validations/DV-COLS/status",
                f"/api/v1/services/payments-service/dependencies/status?execution_id={execution_id}"):
        statements = []
        listener = lambda conn, cursor, sql, params, context, many: statements.append(" ".join(sql.split()))
        event.listen(engine, "before_cursor_execute", listener)
        try:
            assert client.get(url).status_code == 200, url
        finally:
            event.remove(engine, "before_cursor_execute", listener)
        selects = [sql for sql in statements if sql.upper().startswith("SELECT")]
        for table, columns in heavy.items():
            for column in columns:
                assert not any(f"{table}.{column}" in sql for sql in selects), (url, f"{table}.{column}")
    # The check is meaningful: the full detail routes do read those columns.
    for url, column in (("/api/v1/services/payments-service/remediations/R-COLS", "remediation_executions.validation_results"),
                        ("/api/v1/services/payments-service/deployment-validations/DV-COLS", "deployment_validation_runs.events")):
        statements = []
        listener = lambda conn, cursor, sql, params, context, many: statements.append(" ".join(sql.split()))
        event.listen(engine, "before_cursor_execute", listener)
        try:
            assert client.get(url).status_code == 200, url
        finally:
            event.remove(engine, "before_cursor_execute", listener)
        assert any(column in sql for sql in statements), (url, column)
