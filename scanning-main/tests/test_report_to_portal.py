from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "report-to-portal.sh"


def test_helm_status_filter_uses_jq_boolean_predicate_not_undefined_in_arity():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'IN("render failed";' not in source
    assert 'as $status | ($status == "render failed"' in source


def test_large_helm_evidence_is_file_backed_not_passed_as_jq_arguments():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "--argjson helm_warnings" not in source
    assert "--argjson helm_discovery" not in source
    assert "--argjson helm_chart_graph" not in source
    assert '--slurpfile helm_warnings_input "$HELM_RENDER_WARNINGS_FILE"' in source
    assert '--slurpfile helm_discovery_input "$HELM_DISCOVERY_FILE"' in source
    assert '--slurpfile helm_chart_graph_input "$HELM_CHART_GRAPH_FILE"' in source
