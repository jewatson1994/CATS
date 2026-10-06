from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app import main
from app.models import DeploymentValidationRun, Execution, Service
from test_portal import setup_function, new_client, helm_payload, pipeline_headers, SessionLocal, add_user


def seed(client):
    now = datetime.now(timezone.utc)
    for index, label in enumerate(("old", "current")):
        body = helm_payload("architecture-" + label)
        body["service"]["version"] = label
        body["scanned_at"] = (now + timedelta(days=index)).isoformat()
        body["service_overview"]["rendered_resources"][0]["metadata"]["name"] = label
        assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        service = db.scalar(select(Service))
        db.execute(delete(DeploymentValidationRun))
        executions = db.scalars(select(Execution).order_by(Execution.id)).all()
        for index, execution in enumerate(executions):
            db.add(DeploymentValidationRun(service_id=service.id, execution_id=execution.id,
                run_key="run-" + execution.raw_payload["service"]["version"],
                status="RUNNING", created_at=now + timedelta(days=index)))
        db.add(DeploymentValidationRun(service_id=service.id, run_key="unattached-current",
            status="RUNNING", created_at=now + timedelta(days=3)))
        db.commit()
        return service.id


def _complete_runs():
    with SessionLocal() as db:
        for run in db.scalars(select(DeploymentValidationRun).where(DeploymentValidationRun.execution_id.is_not(None))):
            run.status, run.phase, run.artifact_type = "VERIFIED", "COMPLETE", "ORIGINAL"
            run.completed_at = run.created_at
        db.commit()


def test_selected_release_filters_graph_runs_and_mutable_revision(monkeypatch):
    from app import evidence_reads
    client = new_client()
    seed(client)
    _complete_runs()
    observed = {}
    def verify(**kwargs):
        observed.update(kwargs)
        return {}
    monkeypatch.setattr(main, "architecture_verification", verify)
    def no_working_revision(*args):
        raise AssertionError("Historical polling must not read the mutable workspace")
    monkeypatch.setattr(evidence_reads, "latest_working_revision_id", no_working_revision)
    monkeypatch.setattr(main, "latest_architecture_working_revision", no_working_revision)
    for label in ("old", "current"):
        response = client.get("/api/v1/services/payments-service/architecture-evidence", params={"view_version": label})
        assert response.status_code == 200
        assert label in str(response.json()["graph"])
        # Only the selected release's applicable run is read and evaluated.
        assert [run.run_key for run in observed["runs"]] == ["run-" + label]
        assert observed["artifact_revision_id"] is None
        assert observed["execution_id"] is not None
    assert client.get("/api/v1/services/payments-service/architecture-evidence?view_version=missing").status_code == 404


def test_unselected_polling_keeps_current_behavior(monkeypatch):
    from app import evidence_reads
    client = new_client()
    seed(client)
    observed = {}
    monkeypatch.setattr(evidence_reads, "latest_working_revision_id", lambda *args: None)
    def verify(**kwargs):
        observed.update(kwargs)
        return {}
    monkeypatch.setattr(main, "architecture_verification", verify)
    response = client.get("/api/v1/services/payments-service/architecture-evidence")
    assert response.status_code == 200
    # RUNNING runs never verify architecture; the newest run still drives polling.
    assert observed["runs"] == []
    assert response.json()["active_validation"]["run_id"] == "unattached-current"
    _complete_runs()
    response = client.get("/api/v1/services/payments-service/architecture-evidence")
    assert [run.run_key for run in observed["runs"]] == ["run-current"]
    assert response.json()["active_validation"]["run_id"] == "unattached-current"
    summary = client.get("/api/v1/services/payments-service/architecture-evidence?summary=true").json()
    assert set(summary["graph"]) == {"summary"}
    assert summary["graph"]["summary"] == response.json()["graph"]["summary"]


def test_historical_polling_retains_service_scoped_permission():
    client = new_client()
    service_id = seed(client)
    with SessionLocal() as db:
        other = Service(service_key="other-service", name="Other")
        db.add(other)
        db.commit()
    add_user("scoped-reader", "Service Manager", service_id)
    reader = new_client("scoped-reader")
    assert reader.get("/api/v1/services/payments-service/architecture-evidence?view_version=old").status_code == 200
    assert reader.get("/api/v1/services/other-service/architecture-evidence?view_version=old").status_code == 403
