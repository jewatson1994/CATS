import importlib.util
import json
from pathlib import Path


spec = importlib.util.spec_from_file_location("scanner_sbom_identity", Path(__file__).parents[1] / "scripts" / "sbom_identity.py")
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


def test_original_metadata_distinguishes_absence_empty_null_and_zero_epoch():
    raw = {"metadataType": "rpm-db-entry", "metadata": {"name": "binary", "version": "1.2",
           "release": "3", "architecture": "x86_64", "epoch": None, "sourceRpm": "source-1.2-3.src.rpm"}}
    normalized = identity.package_identity(raw)
    assert json.loads(normalized["package_metadata"]) == raw["metadata"]
    assert "package_epoch" not in normalized
    assert normalized["package_nevra"] == "binary-1.2-3.x86_64"
    raw["metadata"]["epoch"] = 0
    normalized = identity.package_identity(raw)
    assert normalized["package_epoch"] == "0"
    assert normalized["package_nevra"] == "binary-0:1.2-3.x86_64"
    assert "source_version" not in normalized
    raw = {"metadata": {"package": "binary", "source": "", "sourceVersion": "", "version": "1:2.3"}}
    assert json.loads(identity.package_identity(raw)["package_metadata"]) == raw["metadata"]
    del raw["metadata"]["sourceVersion"]
    assert "sourceVersion" not in json.loads(identity.package_identity(raw)["package_metadata"])


def test_ambiguous_database_paths_and_oversized_metadata_are_not_shortened():
    raw = {"locations": [{"path": "/var/lib/dpkg/status", "annotations": {"evidence": "primary"}},
                         {"path": "/different/status", "annotations": {"evidence": "primary"}}],
           "metadata": {"source": "x" * 9000}}
    result = identity.package_identity(raw)
    assert "package_db_path" not in result
    assert "package_metadata" not in result
    assert "source_package" not in result


def test_scanner_timestamp_is_only_copied_from_original_descriptor():
    assert "scanner_timestamp" not in identity.document_identity({"descriptor": {"name": "syft", "version": "1.31.0"}})
    assert identity.document_identity({"descriptor": {"name": "grype", "version": "0.98.0", "timestamp": "2026-10-20T05:00:51Z"}})["scanner_timestamp"] == "2026-10-20T05:00:51Z"
