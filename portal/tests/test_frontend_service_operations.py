from datetime import datetime, timezone
from types import SimpleNamespace

from app.frontend_service_operations import project_service_operations


def test_artifact_projection_excludes_retained_source_and_model_internals():
    artifact = SimpleNamespace(id=7, artifact_type="helm_chart", chart_name="chart", source_metadata={"chart_count": 2, "credentials": "do not expose", "versions": [{"version": "1.0", "secret": "hidden"}]}, secret="hidden")
    context = {"artifact_rows": [{"artifact": artifact, "semantic_type": "helm_chart", "source_label": "Upload", "revision": SimpleNamespace(checksum="safe", source_content="hidden"), "files": {"values.yaml": "credential: secret"}}], "original_files": {"source.yaml": "private"}, "image_inventory": [{"image": SimpleNamespace(id=9, image_reference="registry/image", secret="hidden"), "references": ["Pod/test"], "count": 1}]}
    data = project_service_operations("service_artifacts.html", context)
    assert data["artifact_rows"][0]["file_count"] == 1
    assert data["original_file_count"] == 1
    assert data["artifact_rows"][0]["artifact"]["source_metadata"] == {"chart_count": 2, "versions": [{"version": "1.0"}]}
    assert "secret" not in data["artifact_rows"][0]["artifact"]
    assert "source_content" not in data["artifact_rows"][0]["revision"]
    assert "files" not in data["artifact_rows"][0]
    assert "secret" not in data["image_inventory"][0]["image"]


def test_dependencies_projection_keeps_evidence_but_not_execution_payload():
    execution = SimpleNamespace(id=1, execution_key="scan", scanned_at=datetime(2026, 9, 30, tzinfo=timezone.utc), raw_payload={"secret": "hidden"})
    data = project_service_operations("service_dependencies.html", {"dependency_executions": [execution], "dependency_selected_execution": execution, "dependency_rows": [{"name": "package", "hashes": {"SHA256": "abc"}, "secret": "hidden"}]})
    assert data["dependency_executions"][0]["scanned_at"] == "2026-09-30T00:00:00+00:00"
    assert "raw_payload" not in data["dependency_selected_execution"]
    assert data["dependency_rows"][0]["hashes"] == {"SHA256": "abc"}
    assert "secret" not in data["dependency_rows"][0]


def test_validation_evidence_is_json_safe_and_unrelated_context_is_omitted():
    data = project_service_operations("service_validation.html", {"validation": {"status": "VERIFIED", "started_at": datetime(2026, 9, 30), "conditions": {"ready": True}}, "validation_runs": [], "auth": SimpleNamespace(token="private")})
    assert data["validation"]["conditions"] == {"ready": True}
    assert data["validation"]["started_at"] == "2026-09-30T00:00:00"
    assert "auth" not in data


def test_validation_nested_credentials_and_signed_artifact_urls_are_excluded():
    context = {"validation": {"status": "VERIFIED", "artifact_reference": "https://user:secret@example.test/chart?token=secret", "diagnostics": {"raw_payload": {"secret": "private"}, "load_balancer_provider": {"status": "AVAILABLE", "credentials": "private"}}, "capability_preflight": [{"capability": "Storage", "evidence": {"provider": {"status": "READY", "password": "private"}}}]}, "validation_runs": []}
    data = project_service_operations("service_validation.html", context)
    assert "private" not in str(data) and "secret" not in str(data)
    assert data["validation"]["artifact_reference"] == "https://example.test/chart"
    assert data["validation"]["capability_preflight"][0]["evidence"]["provider"]["status"] == "READY"
