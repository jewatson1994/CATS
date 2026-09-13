import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).parents[1] / "scripts" / "generate-sbom-formats.py"


def test_sbom_formats_serialize_one_inventory_with_metadata(tmp_path):
    source = tmp_path / "image.json"
    source.write_text(json.dumps({
        "schema": {"version": "16.0.0"},
        "descriptor": {"name": "syft", "version": "1.2.3"},
        "source": {"name": "demo:1.0"},
        "artifacts": [{
            "name": "openssl", "version": "3.0.1", "type": "apk",
            "purl": "pkg:apk/alpine/openssl@3.0.1", "licenses": [{"spdxExpression": "Apache-2.0"}],
        }],
    }), encoding="utf-8")
    output = tmp_path / "formats"
    subprocess.run([
        sys.executable, str(SCRIPT), "--input", str(source), "--output-dir", str(output),
        "--image", "demo:1.0", "--digest", "sha256:" + "a" * 64,
        "--formats", "syft-json,cyclonedx-json,cyclonedx-xml,spdx-json",
        "--cyclonedx-spec-version", "1.5",
    ], check=True)

    cdx = json.loads((output / "image.cyclonedx.json").read_text(encoding="utf-8"))
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert cdx["metadata"]["properties"][0]["value"] == "demo:1.0"
    assert cdx["components"][0]["purl"] == "pkg:apk/alpine/openssl@3.0.1"
    ET.parse(output / "image.cyclonedx.xml")
    spdx = json.loads((output / "image.spdx.json").read_text(encoding="utf-8"))
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["packages"][0]["name"] == "openssl"
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert {item["format"] for item in manifest["reports"]} == {"syft-json", "cyclonedx-json", "cyclonedx-xml", "spdx-json"}
    assert all(item["generator"] == "syft" for item in manifest["reports"])
