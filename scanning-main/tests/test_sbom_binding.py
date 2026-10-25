import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


SCRIPTS = Path(__file__).parents[1] / "scripts"
spec = importlib.util.spec_from_file_location("binding_identity", SCRIPTS / "sbom_identity.py")
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


def native():
    config = json.dumps({"os": "linux", "architecture": "arm64", "variant": "v8"}).encode()
    manifest = json.dumps({"mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": identity._digest(config), "size": len(config)}}).encode()
    digest = identity._digest(manifest)
    artifact = {"id": "syft-original-id", "name": "libexample", "version": "1", "type": "deb",
                "purl": "pkg:deb/ubuntu/libexample@1?arch=arm64", "metadataType": "dpkg-db-entry",
                "metadata": {"package": "libexample", "version": "1", "source": "source", "sourceVersion": None},
                "locations": [{"path": "/var/lib/dpkg/status", "annotations": {"evidence": "primary"}}]}
    return {"artifacts": [artifact], "distro": {"id": "ubuntu", "versionID": "22.04"},
        "descriptor": {"name": "syft", "version": "1.31.0"},
        "source": {"type": "image", "metadata": {"manifest": base64.b64encode(manifest).decode(),
            "config": base64.b64encode(config).decode(), "manifestDigest": digest,
            "mediaType": "application/vnd.oci.image.manifest.v1+json", "imageID": identity._digest(config),
            "os": "linux", "architecture": "arm64"}}}, digest


def test_document_binding_hashes_original_bytes_and_verified_platform():
    document, digest = native()
    raw = json.dumps(document, indent=2).encode()
    result = identity.document_binding(raw, document, "example:tag")
    assert result["sbom_digest"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert result["sbom_format"] == "syft-json"
    assert result["image_digest"] == result["image_manifest_digest"] == digest
    assert result["image_platform"] == "linux/arm64/v8"
    assert json.loads(result["sbom_distro"]) == document["distro"]
    assert json.loads(result["sbom_descriptor"]) == document["descriptor"]
    source = json.loads(result["sbom_source"])
    assert source["metadata"]["manifestDigest"] == digest
    assert "manifest" not in source["metadata"] and "config" not in source["metadata"]
    assert identity.document_binding(raw + b"\n", document, "example:tag")["sbom_digest"] != result["sbom_digest"]
    for image, contradictory in (("example@sha256:" + "f" * 64, document), ("example:tag", deepcopy(document))):
        if image == "example:tag":
            contradictory["source"]["metadata"]["architecture"] = "amd64"
        rejected = identity.document_binding(json.dumps(contradictory).encode(), contradictory, image)
        assert not {"image_digest", "image_manifest_digest", "image_platform"} & rejected.keys()


def test_artifact_projection_keeps_original_presence_and_rejects_overflow():
    document, _ = native()
    artifact = document["artifacts"][0]
    projection = json.loads(identity.artifact_projection(artifact))
    assert projection == artifact
    del artifact["metadata"]["sourceVersion"]
    assert "sourceVersion" not in json.loads(identity.artifact_projection(artifact))["metadata"]
    artifact["metadata"]["sourceVersion"] = ""
    assert json.loads(identity.artifact_projection(artifact))["metadata"]["sourceVersion"] == ""
    artifact["locations"][0]["path"] = "x" * 65536
    assert identity.artifact_projection(artifact) == ""
    artifact = {"id": "x", "metadata": None}
    assert json.loads(identity.artifact_projection(artifact)) == artifact


def test_extractor_and_report_binding_share_exact_inventory_identity(tmp_path):
    document, digest = native()
    document["artifacts"].append({**document["artifacts"][0], "id": "second-occurrence"})
    sboms = tmp_path / "sboms"
    sboms.mkdir()
    path = sboms / "one.json"
    raw = json.dumps(document, indent=2).encode()
    path.write_bytes(raw)
    (sboms / "one.image").write_text("example:tag")
    (sboms / "one.digest").write_text("example@sha256:" + "f" * 64)
    output = tmp_path / "components.json"
    subprocess.run([sys.executable, str(SCRIPTS / "extract-sbom-components.py"), str(sboms), str(output)], check=True)
    rows = json.loads(output.read_text())["components"]
    binding = json.loads(subprocess.check_output([sys.executable, str(SCRIPTS / "sbom_identity.py"), str(path), "example:tag"], text=True))
    assert len(rows) == 2 and rows[0]["purl"] == rows[1]["purl"]
    assert {row["component_id"] for row in rows} == {"syft-original-id", "second-occurrence"}
    for row in rows:
        for key in ("sbom_digest", "sbom_format", "image_manifest_digest", "image_digest", "image_platform",
                    "sbom_descriptor", "sbom_source", "sbom_distro"):
            assert row[key] == binding[key]
        assert row["image_digest"] == digest
        assert json.loads(row["sbom_artifact"])["id"] == row["component_id"]


def test_unverified_format_identity_does_not_invent_image_platform():
    for field, format_name in (("components", "cyclonedx-json"), ("packages", "spdx-json")):
        document = {field: [{"name": "libexample", "purl": "pkg:deb/ubuntu/libexample@1?arch=arm64"}]}
        binding = identity.document_binding(json.dumps(document).encode(), document, "example@sha256:" + "f" * 64)
        assert binding["sbom_format"] == format_name
        assert not {"image_digest", "image_manifest_digest", "image_platform"} & binding.keys()


def test_scanner_snapshot_binds_consumed_bytes_and_rejects_replacement(tmp_path, monkeypatch):
    sys.path.insert(0, str(SCRIPTS))
    scanner_spec = importlib.util.spec_from_file_location("scan_sbom", SCRIPTS / "scan-sbom.py")
    scanner = importlib.util.module_from_spec(scanner_spec)
    scanner_spec.loader.exec_module(scanner)
    document, digest = native()
    raw = json.dumps(document).encode()
    sbom, report = tmp_path / "image.json", tmp_path / "result.json"
    sbom.write_bytes(raw)
    sbom.with_suffix(".image").write_text("example:tag")
    def run(command, stdout):
        snapshot = Path(command[1].removeprefix("sbom:"))
        assert snapshot.read_bytes() == raw
        assert snapshot != sbom
        sbom.write_bytes(raw + b"\n")
        stdout.write(b'{"matches": []}')
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(scanner.subprocess, "run", run)
    assert scanner.scan(sbom, report) == 0
    binding_path = report.with_suffix(".binding")
    recorded = json.loads(binding_path.read_text())
    assert recorded["sbom_digest"] == identity._digest(raw)
    assert recorded["scanner_report_digest"] == identity._digest(report.read_bytes())
    assert identity.binding_from_files(sbom, "example:tag", None, binding_path, report) == {}
    sbom.write_bytes(raw)
    assert identity.binding_from_files(sbom, "example:tag", None, binding_path, report)["image_digest"] == digest
    assert identity.binding_from_files(sbom, "another:tag", None, binding_path, report) == {}
    report.write_text('{"matches": [{"artifact": {"id": "replacement"}}]}')
    assert identity.binding_from_files(sbom, "example:tag", None, binding_path, report) == {}
    assert identity.binding_from_files(sbom, "example:tag", None, tmp_path / "missing.binding", report) == {}


def test_failed_scanner_discards_previous_binding(tmp_path, monkeypatch):
    sys.path.insert(0, str(SCRIPTS))
    scanner_spec = importlib.util.spec_from_file_location("failed_scan_sbom", SCRIPTS / "scan-sbom.py")
    scanner = importlib.util.module_from_spec(scanner_spec)
    scanner_spec.loader.exec_module(scanner)
    sbom, report = tmp_path / "image.json", tmp_path / "result.json"
    sbom.write_text('{"artifacts": []}')
    report.with_suffix(".binding").write_text('{"stale": true}')
    def run(command, stdout):
        stdout.write(b'{"partial": true}')
        return subprocess.CompletedProcess(command, 2)
    monkeypatch.setattr(scanner.subprocess, "run", run)
    assert scanner.scan(sbom, report) == 2
    assert not report.exists() and not report.with_suffix(".binding").exists()
