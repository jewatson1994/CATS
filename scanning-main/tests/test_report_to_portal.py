from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "report-to-portal.sh"


def test_helm_status_filter_uses_jq_boolean_predicate_not_undefined_in_arity():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'IN("render failed";' not in source
    assert 'as $status | ($status == "render failed"' in source
