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


def test_selected_release_filters_graph_runs_and_mutable_revision(monkeypatch):
    client = new_client()
    seed(client)
    observed = {}
    def verify(**kwargs):
        observed.update(kwargs)
        return {}
    monkeypatch.setattr(main, "architecture_verification", verify)
    def no_working_revision(*args):
        raise AssertionError("Historical polling must not read the mutable workspace")
    monkeypatch.setattr(main, "latest_architecture_working_revision", no_working_revision)
    for label in ("old", "current"):
        response = client.get("/api/v1/services/payments-service/architecture-evidence", params={"view_version": label})
        assert response.status_code == 200
        assert label in str(response.json()["graph"])
        assert [run.run_key for run in observed["runs"]] == ["run-" + label]
        assert observed["artifact_revision_id"] is None
        assert observed["execution_id"] is not None
    assert client.get("/api/v1/services/payments-service/architecture-evidence?view_version=missing").status_code == 404


def test_unselected_polling_keeps_current_behavior(monkeypatch):
    client = new_client()
    seed(client)
    observed = {}
    monkeypatch.setattr(main, "latest_architecture_working_revision", lambda *args: None)
    def verify(**kwargs):
        observed.update(kwargs)
        return {}
    monkeypatch.setattr(main, "architecture_verification", verify)
    assert client.get("/api/v1/services/payments-service/architecture-evidence").status_code == 200
    assert len(observed["runs"]) == 3


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
