"""Definition preview, retention, and per-component processing regressions."""
from unittest.mock import patch

from sqlalchemy import select

from app import main
from app.definition_routes import process_definition
from app.oci_diagnostics import OciPullFailure
from app.models import Service, ServiceArtifact, ServiceArtifactRevision
from test_portal import setup_function, new_client, csrf, SessionLocal, page_data


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
    assert page_data(response)["preview"]["counts"]["declared"] == 3
    with SessionLocal() as db:
        assert list(db.scalars(select(ServiceArtifact))) == []
    token = page_data(response)["preview_token"]
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
    token = page_data(response)["preview_token"]
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


def test_latest_reprocess_keeps_each_resolved_version_and_chart_artifact():
    _service()
    client = new_client()
    response = _preview(client, SOURCE.replace("1.2.3", "latest"))
    assert page_data(response)["preview"]["components"][0]["version"] == "latest"
    token = page_data(response)["preview_token"]
    with patch.object(main.PUBLIC_WORKERS, "submit"):
        assert client.post(f"/services/definition-test/definitions/confirm/{token}",
                           data={"csrf_token": csrf(client)}).status_code == 200
    with SessionLocal() as db:
        definition = db.scalar(select(ServiceArtifact).where(ServiceArtifact.artifact_type == "service_definition"))
        artifact_id = definition.id
        user_id = definition.revisions[0].created_by_id

    current = {"version": "1.2.3"}

    def catalog(*_):
        version = current["version"]
        return {"charts": [{"name": "demo", "latest": {"version": version,
                 "url": f"https://charts.example.invalid/demo-{version}.tgz"}}]}

    def download(url, _):
        if url.startswith("oci://"):
            raise ValueError("registry unavailable")
        return [(b"chart", "demo.tgz")]

    def retained(*_, **__):
        return {"demo/Chart.yaml": f"name: demo\nversion: {current['version']}\n"}, 1

    def scan(*args, **kwargs):
        from app.definition_routes import complete_scan
        complete_scan("completed-job", {"definition_context": kwargs["definition_context"], "status": "complete"})
        return "completed-job"

    with patch.object(main, "_discover_helm_repository", side_effect=catalog), \
         patch.object(main, "_download_public_chart", side_effect=download), \
         patch.object(main, "_retained_helm_sources", side_effect=retained), \
         patch.object(main, "_chart_identity", side_effect=lambda files: ("demo", current["version"])), \
         patch.object(main, "_start_public_scan", side_effect=scan):
        process_definition(artifact_id, user_id)
        with SessionLocal() as db:
            first = db.get(ServiceArtifact, artifact_id).source_metadata
            assert first["components"][0]["version"] == "latest"
            assert first["components"][0]["resolved_version"] == "1.2.3"
        current["version"] = "2.0.0"
        with patch.object(main.PUBLIC_WORKERS, "submit"):
            assert client.post(f"/services/definition-test/definitions/{artifact_id}/reprocess",
                               data={"csrf_token": csrf(client)}, follow_redirects=False).status_code == 303
        process_definition(artifact_id, user_id)

    with SessionLocal() as db:
        definition = db.get(ServiceArtifact, artifact_id)
        meta = definition.source_metadata
        assert meta["components"][0]["version"] == "latest"
        assert meta["components"][0]["resolved_version"] == "2.0.0"
        assert meta["run_history"][0]["components"][0]["resolved_version"] == "1.2.3"
        charts = list(db.scalars(select(ServiceArtifact).where(ServiceArtifact.artifact_type == "helm_chart")))
        assert {chart.chart_version for chart in charts} == {"1.2.3", "2.0.0"}
        assert {chart.source_metadata["declared_version"] for chart in charts} == {"latest"}


def test_oci_failure_reaches_retained_evidence_and_ui_without_stopping_sibling():
    _service()
    client = new_client()
    source = SOURCE.replace("services:\n", "services:\n  cache-two:\n    sourceType: oci\n    ociRepo: {url: 'oci://registry.example.invalid/charts', repoName: cache, tag: 2.0.0}\n")
    response = _preview(client, source)
    token = page_data(response)["preview_token"]
    with patch.object(main.PUBLIC_WORKERS, "submit"):
        client.post(f"/services/definition-test/definitions/confirm/{token}",
                    data={"csrf_token": csrf(client)})
    with SessionLocal() as db:
        definition = db.scalar(select(ServiceArtifact).where(ServiceArtifact.artifact_type == "service_definition"))
        artifact_id, user_id = definition.id, definition.revisions[0].created_by_id

    def download(reference, _):
        if reference.startswith("oci://"):
            raise OciPullFailure(reference, exit_code=1, stderr="unauthorized; password=secret-value")
        return [(b"chart", "demo.tgz")]

    with patch.object(main, "_discover_helm_repository", return_value={"charts": [{"name": "demo", "versions": [{"version": "1.2.3", "url": "https://charts.example.invalid/demo.tgz"}]}]}), \
         patch.object(main, "_download_public_chart", side_effect=download), \
         patch.object(main, "_retained_helm_sources", return_value=({"demo/Chart.yaml": "name: demo\nversion: 1.2.3\nappVersion: 9.8.7\n", "demo/values.yaml": "image:\n  tag: latest\n"}, 1)), \
         patch.object(main, "_chart_identity", return_value=("demo", "1.2.3")), \
         patch.object(main, "_start_public_scan", return_value="evidence-job"):
        process_definition(artifact_id, user_id)
    with SessionLocal() as db:
        definition = db.get(ServiceArtifact, artifact_id)
        components = definition.source_metadata["components"]
        assert [c["status"] for c in components] == ["acquisition_failed", "scanning", "acquisition_failed", "unsupported"]
        assert components[0]["acquisition_diagnostic"]["failure_category"] == "authentication_denied"
        assert components[0]["acquisition_diagnostic"]["helm_exit_code"] == 1
        assert components[1]["chart_app_version"] == "9.8.7"
        chart = db.scalar(select(ServiceArtifact).where(ServiceArtifact.artifact_type == "helm_chart"))
        assert chart.chart_version == "1.2.3"
        assert chart.revisions[0].files["demo/values.yaml"] == "image:\n  tag: latest\n"
        assert "secret-value" not in str(definition.source_metadata)
    page = client.get("/services/definition-test/definitions")
    assert page.status_code == 200
    assert "OCI registry authentication required or denied" in page.text
    assert page_data(page)["definitions"][0]["source_metadata"]["components"][1]["chart_app_version"] == "9.8.7"
    assert "secret-value" not in page.text
