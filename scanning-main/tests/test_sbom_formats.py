import hashlib
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
    source_digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
    assert all(item["source_sbom_digest"] == source_digest for item in manifest["reports"])
    assert all(item["sha256"] == hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest()
               for item in manifest["reports"])


def test_source_and_distribution_identity_survive_format_round_trips(tmp_path):
    raw = {"distro": {"id": "ubuntu", "versionID": "22.04", "versionCodename": "jammy"},
        "source": {"type": "directory", "name": "/materialized/rootfs"},
        "artifacts": [{"id": "syft-component-id", "name": "libssl3", "version": "3.0.2-0ubuntu1",
            "type": "deb", "purl": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1?arch=amd64&distro=ubuntu-22.04",
            "metadata": {"architecture": "amd64", "source": "openssl", "sourceVersion": "3.0.2-0ubuntu1"}}]}
    source = tmp_path / "image.json"
    source.write_text(json.dumps(raw), encoding="utf-8")
    source.with_suffix(".provenance").write_text(json.dumps({"imageID": "sha256:abc", "architecture": "amd64", "os": "linux"}), encoding="utf-8")
    output = tmp_path / "formats"
    subprocess.run([sys.executable, str(SCRIPT), "--input", str(source), "--output-dir", str(output),
        "--formats", "cyclonedx-json,spdx-json", "--image", "example:1"], check=True)
    extractor = SCRIPT.parent / "extract-sbom-components.py"
    for name in ("image.cyclonedx", "image.spdx"):
        (output / (name + ".image")).write_text("example:1", encoding="utf-8")
    extracted = tmp_path / "normalized.json"
    subprocess.run([sys.executable, str(extractor), str(output), str(extracted)], check=True)
    rows = json.loads(extracted.read_text(encoding="utf-8"))["components"]
    assert len(rows) == 2
    for row in rows:
        assert row["purl"] == raw["artifacts"][0]["purl"]
        assert row["ecosystem"] == "deb"
        assert row["architecture"] == "amd64"
        assert row["source_package"] == "openssl" and row["name"] == "libssl3"
        assert row["source_version"] == "3.0.2-0ubuntu1"
        assert row["distro_id"] == "ubuntu" and row["distro_version"] == "22.04"
        assert row["distro_codename"] == "jammy"
        assert row["component_id"] == "syft-component-id"
        assert row["image_id"] == "sha256:abc"
        assert row["image_architecture"] == "amd64"
        assert row["scanner_source_type"] == "directory"


def test_real_installed_package_provenance_survives_cyclonedx_and_spdx(tmp_path):
    fixtures = json.loads((Path(__file__).parent / "fixtures" / "identity" /
                           "retained-installed-packages.json").read_text(encoding="utf-8"))["records"]
    extractor = SCRIPT.parent / "extract-sbom-components.py"
    for index, record in enumerate(fixtures):
        root = tmp_path / str(index)
        root.mkdir()
        raw = {key: record[key] for key in ("descriptor", "schema", "distro", "source")}
        raw["artifacts"] = [record["artifact"]]
        source = root / "image.json"
        source.write_text(json.dumps(raw), encoding="utf-8")
        output = root / "formats"
        subprocess.run([sys.executable, str(SCRIPT), "--input", str(source), "--output-dir", str(output),
            "--formats", "cyclonedx-json,cyclonedx-xml,spdx-json", "--image", record["capture"],
            "--digest", record["image_digest"]], check=True)
        for name in ("image.cyclonedx", "image.spdx"):
            (output / (name + ".image")).write_text(record["capture"], encoding="utf-8")
        extracted = root / "normalized.json"
        subprocess.run([sys.executable, str(extractor), str(output), str(extracted)], check=True)
        rows = json.loads(extracted.read_text(encoding="utf-8"))["components"]
        assert len(rows) == 2
        artifact = record["artifact"]
        for row in rows:
            assert row["purl"] == artifact["purl"]
            assert row["version"] == artifact["version"]
            assert row["name"] == artifact["name"]
            assert json.loads(row["package_metadata"]) == artifact["metadata"]
            assert row["package_db_name"] == artifact["name"]
            assert row["package_db_version"] == artifact["metadata"]["version"]
            assert row["package_found_by"] == artifact["foundBy"]
            assert row["package_metadata_type"] == artifact["metadataType"]
            assert row["package_db_path"] == artifact["locations"][0]["path"]
            assert row["scanner_name"] == "syft"
            assert row["scanner_version"] == "1.31.0"
            assert row["scanner_schema_version"] == "16.0.37"
            assert "scanner_timestamp" not in row
            assert row["distro_id"] == record["distro"]["id"]
            if artifact["type"] == "rpm":
                assert row["source_rpm"] == artifact["metadata"]["sourceRpm"]
                assert row["package_nevra"].endswith("." + artifact["metadata"]["architecture"])
        # XML carries the same original metadata, including explicit empty/null values.
        xml = ET.parse(output / "image.cyclonedx.xml")
        values = [node.text for node in xml.iter() if node.attrib.get("name") == "cats:identity:package_metadata"]
        assert len(values) == 1 and json.loads(values[0]) == artifact["metadata"]
