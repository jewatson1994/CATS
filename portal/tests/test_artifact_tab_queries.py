from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import main
from app.database import Base
from app.models import (Service, ServiceArtifact, ServiceArtifactRevision, DeploymentValidationRun,
                        Execution, ServiceImage, utcnow)


def test_artifacts_route_loads_latest_revision_and_validation_only(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    monkeypatch.setattr(main, "configuration_for_service", lambda *args: main.CONFIG_DEFAULTS)
    monkeypatch.setattr(main, "page_context", lambda auth, **context: context)
    monkeypatch.setattr(main.templates, "TemplateResponse", lambda request, name, context: context)
    with Session(engine) as db:
        service = Service(service_key="artifacts", name="Artifacts"); db.add(service); db.flush()
        artifact = ServiceArtifact(service_id=service.id, artifact_type="helm", artifact_name="Chart")
        db.add(artifact); db.flush()
        for number in range(100):
            revision = ServiceArtifactRevision(artifact_id=artifact.id, revision_number=number,
                files={"Chart.yaml": str(number)}, checksum=str(number))
            db.add(revision); db.flush()
            for attempt in range(3):
                db.add(DeploymentValidationRun(service_id=service.id, artifact_revision_id=revision.id,
                    run_key=f"{number}-{attempt}", status="VERIFIED" if attempt == 2 else "ERROR",
                    created_at=now+timedelta(seconds=attempt)))
            db.add(Execution(service_id=service.id, execution_key=f"scan-{number}",
                scanned_at=now+timedelta(minutes=number), complete=True, scan_scope="service",
                raw_payload={"artifact_type":"helm", "helm_source_files":{"Chart.yaml":str(number)}}))
        db.add_all([
            Execution(service_id=service.id, execution_key="empty-newer", scanned_at=now+timedelta(days=1),
                complete=True, scan_scope="service", raw_payload={"artifact_type":"helm", "helm_source_files":{}}),
            Execution(service_id=service.id, execution_key="image-newer", scanned_at=now+timedelta(days=2),
                complete=True, scan_scope="image", raw_payload={"artifact_type":"helm", "helm_source_files":{"Chart.yaml":"excluded"}}),
        ])
        db.add(ServiceImage(service_id=service.id, image_reference="image:tag", image_digest="digest"))
        db.commit(); db.expunge_all()
        statements = []
        event.listen(engine, "before_cursor_execute", lambda *args: statements.append(args[2]))
        request = Request({"type":"http", "method":"GET", "path":"/", "query_string":b"", "headers":[]})
        result = main.service_detail("artifacts", request, artifacts=True, db=db,
            auth=SimpleNamespace(has=lambda *args: True))
        assert result["original_files"] == {"Chart.yaml":"99"}
        assert len(result["artifact_rows"]) == 1
        row = result["artifact_rows"][0]
        assert row["revision"].revision_number == 99
        assert row["validation"]["run_key"] == "99-2"
        assert row["validation"]["key"] == "validated"
        assert len(result["image_inventory"]) == 1
        assert sum(isinstance(item, ServiceArtifactRevision) for item in db.identity_map.values()) == 1
        assert not any(isinstance(item, DeploymentValidationRun) for item in db.identity_map.values())
        assert sum(isinstance(item, Execution) for item in db.identity_map.values()) <= 2
        assert "revisions" not in row["artifact"].__dict__
        assert len(statements) < 20
