import hashlib
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
        "sbom": "one.json", "sbom_format": "syft-json",
        "sbom_digest": "sha256:" + hashlib.sha256((sboms / "one.json").read_bytes()).hexdigest(),
        "sbom_artifact": json.dumps({"name": "openssl", "version": "3.0.1", "type": "apk",
            "purl": "pkg:apk/alpine/openssl@3.0.1"}, sort_keys=True, separators=(",", ":")),
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


def test_spdx_external_purl_and_ecosystem_architecture_are_preserved(tmp_path):
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    purl = "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1?arch=amd64&distro=ubuntu-22.04"
    (sboms / "one.json").write_text(json.dumps({"packages": [{"name": "libssl3", "versionInfo": "3.0.2-0ubuntu1",
        "SPDXID": "SPDXRef-1", "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]}]}), encoding="utf-8")
    (sboms / "one.image").write_text("example:1", encoding="utf-8")
    output = tmp_path / "components.json"
    subprocess.run([sys.executable, str(SCRIPT), str(sboms), str(output)], check=True)
    row = json.loads(output.read_text(encoding="utf-8"))["components"][0]
    assert row["purl"] == purl
    assert row["ecosystem"] == "deb"
    assert row["architecture"] == "amd64"
    assert row["component_id"] == "SPDXRef-1"
    assert "source_package" not in row


def test_ambiguous_and_oversized_purls_are_not_rewritten(tmp_path):
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    (sboms / "one.json").write_text(json.dumps({"packages": [
        {"name": "ambiguous", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/ubuntu/x@1"},
            {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/x@1"}]},
        {"name": "oversized", "purl": "pkg:npm/x@1?qualifier=" + "x" * 1500},
        {"name": "missing", "versionInfo": "1"}]}), encoding="utf-8")
    (sboms / "one.image").write_text("example:1", encoding="utf-8")
    output = tmp_path / "components.json"
    subprocess.run([sys.executable, str(SCRIPT), str(sboms), str(output)], check=True)
    rows = json.loads(output.read_text(encoding="utf-8"))["components"]
    assert len(rows) == 3 and all("purl" not in row for row in rows)


def test_extractor_retains_malformed_purl_for_downstream_rejection(tmp_path):
    root = tmp_path / "sboms"
    root.mkdir()
    malformed = " pkg:deb/ubuntu/libexample@1.0?arch=amd64 "
    (root / "one.image").write_text("example:1", encoding="utf-8")
    (root / "one.digest").write_text("sha256:" + "a" * 181, encoding="utf-8")
    (root / "one.json").write_text(json.dumps({"artifacts": [{"name": "libexample", "purl": malformed}]}), encoding="utf-8")
    output = tmp_path / "components.json"
    subprocess.run([sys.executable, str(SCRIPT), str(root), str(output)], check=True)
    row = json.loads(output.read_text(encoding="utf-8"))["components"][0]
    assert row["purl"] == malformed
    assert "image_digest" not in row
