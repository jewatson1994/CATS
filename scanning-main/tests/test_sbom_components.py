import json
from pathlib import Path
import subprocess
import sys


SCRIPT = Path(__file__).parents[1] / "scripts" / "extract-sbom-components.py"


def test_extracts_components_with_image_provenance_and_skips_unpaired_json(tmp_path):
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    (sboms / "one.json").write_text(json.dumps({"artifacts": [
        {"name": "openssl", "version": "3.0.1", "type": "apk",
         "purl": "pkg:apk/alpine/openssl@3.0.1"},
    ]}), encoding="utf-8")
    (sboms / "one.image").write_text("registry.internal/app:1\n", encoding="utf-8")
    (sboms / "other.json").write_text(json.dumps({"artifacts": [
        {"name": "unrelated", "version": "1"},
    ]}), encoding="utf-8")
    output = tmp_path / "components.json"

    subprocess.run([sys.executable, str(SCRIPT), str(sboms), str(output)], check=True)

    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["images"] == ["registry.internal/app:1"]
    assert result["components"] == [{
        "name": "openssl", "version": "3.0.1", "ecosystem": "apk",
        "purl": "pkg:apk/alpine/openssl@3.0.1", "image": "registry.internal/app:1",
    }]
