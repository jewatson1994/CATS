"""Definition preview, retention, and per-component processing regressions."""
import re
from unittest.mock import patch

from sqlalchemy import select

from app import main
from app.definition_routes import process_definition
from app.models import Service, ServiceArtifact, ServiceArtifactRevision
from test_portal import setup_function, new_client, csrf, SessionLocal


SOURCE = """services:
  web:
    sourceType: helm
    enabled: false
    helmRepo:
      url: https://charts.example.invalid
      chartName: demo
      version: 1.2.3
  cache:
    sourceType: oci
    ociRepo:
      url: oci://registry.example.invalid/charts
      repoName: cache
      tag: 2.0.0
  unknown:
    sourceType: git
"""


def _service():
    with SessionLocal() as db:
        db.add(Service(service_key="definition-test", name="Definition Test"))
        db.commit()


def _preview(client, source=SOURCE):
    return client.post("/services/definition-test/definitions/preview",
        data={"csrf_token": csrf(client), "adapter": "singularity"},
        files={"upload": ("catalog.yaml", source)})


def test_preview_is_non_mutating_and_confirm_retains_all_components():
    _service()
    client = new_client()
    assert client.get("/services/definition-test/definitions").status_code == 200
    response = _preview(client)
    assert response.status_code == 200, response.text
    assert "web" in response.text and "cache" in response.text and "unknown" in response.text
    assert "Declared: 3" in response.text
    with SessionLocal() as db:
        assert list(db.scalars(select(ServiceArtifact))) == []
    token = re.search(r"/definitions/confirm/([a-f0-9]+)", response.text).group(1)
    with patch.object(main.PUBLIC_WORKERS, "submit") as submit:
        confirmed = client.post(f"/services/definition-test/definitions/confirm/{token}",
            data={"csrf_token": csrf(client)}, follow_redirects=False)
        assert confirmed.status_code == 303
        submit.assert_called_once()
    assert client.post(f"/services/definition-test/definitions/confirm/{token}",
        data={"csrf_token": csrf(client)}).status_code == 409
    with SessionLocal() as db:
        service = db.scalar(select(Service).where(Service.service_key == "definition-test"))
        artifact = db.scalar(select(ServiceArtifact).where(ServiceArtifact.service_id == service.id))
        assert service.assessment_status == "assessment_pending"
        assert artifact.source_metadata["counts"] == {"declared": 3, "normalized": 2, "unsupported": 1, "unresolved": 0}
        assert [c["status"] for c in artifact.source_metadata["components"]] == ["normalized", "normalized", "unsupported"]
        assert db.scalar(select(ServiceArtifactRevision).where(ServiceArtifactRevision.artifact_id == artifact.id)).files == {"catalog.yaml": SOURCE}


def test_definition_processing_isolates_failed_sibling_and_preserves_terminal_scan_status():
    _service()
    client = new_client()
    response = _preview(client)
    token = re.search(r"/definitions/confirm/([a-f0-9]+)", response.text).group(1)
    with patch.object(main.PUBLIC_WORKERS, "submit"):
        assert client.post(f"/services/definition-test/definitions/confirm/{token}",
            data={"csrf_token": csrf(client)}).status_code == 200
    with SessionLocal() as db:
        definition = db.scalar(select(ServiceArtifact).where(ServiceArtifact.artifact_type == "service_definition"))
        artifact_id = definition.id
        user_id = definition.revisions[0].created_by_id

    def catalog(url, certificates):
        return {"charts": [{"name": "demo", "versions": [{"version": "1.2.3", "url": "https://charts.example.invalid/demo-1.2.3.tgz"}]}]}

    def download(url, certificates):
        if str(url).startswith("oci://"):
            raise ValueError("registry unavailable")
        return [(b"chart", "demo.tgz")]

    def start(*args, **kwargs):
        from app.definition_routes import complete_scan
        complete_scan("instant-job", {"definition_context": kwargs["definition_context"], "status": "complete"})
        return "instant-job"

    with patch.object(main, "_discover_helm_repository", side_effect=catalog), \
         patch.object(main, "_download_public_chart", side_effect=download), \
         patch.object(main, "_retained_helm_sources", return_value=({"Chart.yaml": "name: demo\nversion: 1.2.3\n"}, 1)), \
         patch.object(main, "_chart_identity", return_value=("demo", "1.2.3")), \
         patch.object(main, "_start_public_scan", side_effect=start):
        process_definition(artifact_id, user_id)
    with SessionLocal() as db:
        definition = db.get(ServiceArtifact, artifact_id)
        statuses = [c["status"] for c in definition.source_metadata["components"]]
        assert statuses == ["complete", "acquisition_failed", "unsupported"]
        assert definition.source_metadata["components"][0]["scan_job_id"] == "instant-job"
        assert len(list(db.scalars(select(ServiceArtifact).where(ServiceArtifact.artifact_type == "helm_chart")))) == 1


def test_invalid_definition_and_csrf_do_not_write_artifacts():
    _service()
    client = new_client()
    assert client.post("/services/definition-test/definitions/preview",
        data={"csrf_token": "wrong", "adapter": "singularity"},
        files={"upload": ("catalog.yaml", SOURCE)}).status_code == 403
    assert _preview(client, "services: [not-a-catalog]\n").status_code == 422
    with SessionLocal() as db:
        assert list(db.scalars(select(ServiceArtifact))) == []
