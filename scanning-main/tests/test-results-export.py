import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "assemble-results.py"
SPEC = importlib.util.spec_from_file_location("assemble_results", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_results_are_grouped_by_native_scanner_format(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    (results / "api-results.json").write_text(json.dumps({"matches": []}), encoding="utf-8")
    raw = tmp_path / "trivy-results" / "raw"
    raw.mkdir(parents=True)
    (raw / "001-helm.json").write_text(json.dumps({"Results": []}), encoding="utf-8")
    (raw / "image-api-dockle.json").write_text(json.dumps({"details": []}), encoding="utf-8")
    (tmp_path / "portal-policy-findings.json").write_text("[]\n", encoding="utf-8")

    assert MODULE.main.__name__ == "main"
    import sys
    old = sys.argv
    try:
        sys.argv = [str(SCRIPT), "--root", str(tmp_path), "--output", str(results)]
        assert MODULE.main() == 0
    finally:
        sys.argv = old

    manifest = json.loads((results / "manifest.json").read_text(encoding="utf-8"))
    assert (results / "grype" / "api-results.json").is_file()
    assert (results / "trivy" / "001-helm.json").is_file()
    assert (results / "dockle" / "image-api-dockle.json").is_file()
    assert (results / "cats" / "cats-findings.json").is_file()
    assert json.loads((results / "cats" / "cats-findings.json").read_text(encoding="utf-8"))["findings"] == []
    assert (tmp_path / "results-export.tar.gz").is_file()
    assert {item["scan_type"] for item in manifest["reports"]} == {
        "Anchore Grype", "Trivy", "Dockle Report", "Generic Findings Import"
    }
