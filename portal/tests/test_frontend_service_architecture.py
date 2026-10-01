from app.frontend_service_architecture import project_service_architecture


def test_architecture_projection_uses_normalized_graph_and_omits_execution():
    result = project_service_architecture({"architecture_graph": {"nodes": [{"id": "safe"}], "raw_payload": {"credential": "secret"}}, "latest_execution": {"raw_payload": "secret"}, "architecture_verification": {"state": "DECLARED", "run": {"secret": "hidden"}}})
    assert result["architecture_graph"]["nodes"][0]["id"] == "safe"
    assert "raw_payload" not in result["architecture_graph"]
    assert "latest_execution" not in result
    assert "run" not in result["architecture_verification"]


def test_graph_nested_source_and_layout_extensions_are_not_exposed():
    data = project_service_architecture({"architecture_graph": {"nodes": [{"id": "pod", "source_mappings": [{"credentials": "secret"}], "chart_provenance": {"chart_name": "safe", "credentials": "secret"}, "evidence": [{"detail": "safe", "access_token": "secret"}]}], "layouts": {"all": {"positions": {"pod": {"x": 1, "y": 2, "credential": "secret"}}, "credentials": "secret"}}}})
    assert "secret" not in str(data)
    assert data["architecture_graph"]["layouts"]["all"]["positions"]["pod"]["x"] == 1
