"""Evidence identity survives ingestion; identity hints never establish equivalence."""
import json
from pathlib import Path
import subprocess
import sys

import pytest
from app.schemas import ExecutionPayload


def test_scanner_identity_survives_payload_validation(tmp_path):
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    raw = {"distro": {"id": "sles", "versionID": "15.6", "variantID": "server"},
        "artifacts": [{"name": "libexample", "version": "1-2", "type": "rpm", "purl": "pkg:rpm/suse/libexample@1-2?arch=x86_64",
            "metadata": {"architecture": "x86_64", "sourceRpm": "example-1-2.src.rpm", "vendor": "SUSE",
                         "epoch": 0, "release": "2", "modularityLabel": "example-stream"}}]}
    (sboms / "one.json").write_text(json.dumps(raw), encoding="utf-8")
    (sboms / "one.image").write_text("example:1", encoding="utf-8")
    output = tmp_path / "components.json"
    script = Path(__file__).parents[2] / "scanning-main/scripts/extract-sbom-components.py"
    subprocess.run([sys.executable, str(script), str(sboms), str(output)], check=True)
    rows = json.loads(output.read_text(encoding="utf-8"))["components"]
    assert ExecutionPayload.validate_sbom_components(rows) == rows
    assert rows[0]["source_rpm"] == "example-1-2.src.rpm"
    assert rows[0]["package_epoch"] == "0"
    assert rows[0]["distro_id"] == "sles" and rows[0]["distro_variant"] == "server"
    assert "csaf_product_context" not in rows[0]
    with pytest.raises(ValueError):
        ExecutionPayload.validate_sbom_components([{**rows[0], "source_rpm": "x" * 701}])
    with pytest.raises(ValueError):
        ExecutionPayload.validate_sbom_components([{**rows[0], "csaf_product_context": "guessed-product"}])
