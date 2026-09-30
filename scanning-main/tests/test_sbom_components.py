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
        "sbom": "one.json",
    }]


def test_preserves_license_identity_and_digest_without_inventing_missing_fields(tmp_path):
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    (sboms / "one.json").write_text(json.dumps({"components": [{
        "name": "library", "version": "1.0", "type": "library",
        "purl": "pkg:maven/example/library@1.0",
        "licenses": [{"expression": "MIT OR Apache-2.0"}],
        "supplier": {"name": "Example"}, "hashes": [{"alg": "SHA-256", "content": "abc"}],
    }]}), encoding="utf-8")
    (sboms / "one.image").write_text("registry.example/app:1", encoding="utf-8")
    (sboms / "one.digest").write_text("sha256:123", encoding="utf-8")
    output = tmp_path / "components.json"
    subprocess.run([sys.executable, str(SCRIPT), str(sboms), str(output)], check=True)
    component = json.loads(output.read_text(encoding="utf-8"))["components"][0]
    assert component["license_declared"] == "MIT OR Apache-2.0"
    assert component["license_source"] == "CycloneDX"
    assert component["supplier"] == "Example"
    assert component["hashes"] == "SHA-256:abc"
    assert component["image_digest"] == "sha256:123"
    assert "location" not in component


def test_retains_supplied_cyclonedx_dependency_links(tmp_path):
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    (sboms / "one.json").write_text(json.dumps({
        "components": [{"name": "app", "bom-ref": "pkg:app"},
                       {"name": "library", "bom-ref": "pkg:library"}],
        "dependencies": [{"ref": "pkg:app", "dependsOn": ["pkg:library"]}],
    }), encoding="utf-8")
    (sboms / "one.image").write_text("example/app:1", encoding="utf-8")
    output = tmp_path / "components.json"
    subprocess.run([sys.executable, str(SCRIPT), str(sboms), str(output)], check=True)
    app, library = json.loads(output.read_text(encoding="utf-8"))["components"]
    assert app["dependency_children"] == "pkg:library"
    assert library["dependency_parents"] == "pkg:app"
