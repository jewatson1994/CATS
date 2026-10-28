"""Original report bytes, complete SBOM formats, scope and bounded ingestion."""
import base64
from datetime import datetime, timezone
import gzip
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile

from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Execution, Service, ServiceVersion
from app.retained_documents import EvidenceDocument, SBOM_FORMATS, decode_document
from app.schemas import ExecutionPayload
from app.service_exports import _service_raw_scanner_bytes, _service_sboms_bytes


SCRIPT = Path(__file__).parents[2] / "scanning-main/scripts/retain-export-evidence.py"


def document(raw=b'{"matches":[]}\r\n', **overrides):
    return {"category": "scanner", "format": "grype-json", "name": "image-results.json", "image": "",
            "encoding": "gzip+base64", "content": base64.b64encode(gzip.compress(raw, mtime=0)).decode(),
            "bytes": len(raw), "sha256": sha256(raw).hexdigest(), **overrides}


def pipeline_payload(**extra):
    return {"execution_id": "retained-scan", "scanned_at": "2026-10-25T00:00:00Z", "complete": True,
            "fixable_only": True, "service": {"id": "export-test", "name": "Test", "version": "1"}, **extra}


@pytest.fixture
def collected(tmp_path):
    for folder in ("results", "trivy-results/raw", "sboms"):
        (tmp_path / folder).mkdir(parents=True)
    grype = b'{ "matches" : [], "descriptor": {"name":"grype"} }\r\n'
    trivy = b'{\n  "SchemaVersion": 2, "Results": []\n}\n'
    syft = b'{"schema":{"version":"16"},"descriptor":{"name":"syft","version":"1"},"artifacts":[{"name":"openssl","version":"3.0","type":"deb"}]}\n'
    (tmp_path / "results/image-results.json").write_bytes(grype)
    (tmp_path / "trivy-results/raw/chart.json").write_bytes(trivy)
    (tmp_path / "trivy-results/raw/image-example-dockle.json").write_text('{"details": []}')
    (tmp_path / "sboms/image.json").write_bytes(syft)
    (tmp_path / "sboms/image.image").write_text("example:1")
    target = tmp_path / "retained.json"
    subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), str(target)], check=True)
    retained = json.loads(target.read_text())
    subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), str(target)], check=True)
    assert json.loads(target.read_text()) == retained  # Retry preserves ingestion idempotency.
    return retained, grype, trivy, syft


@pytest.fixture
def db_source():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="export-test", name="Test")
        db.add(service)
        db.flush()
        version = ServiceVersion(service_id=service.id, version="1")
        db.add(version)
        db.flush()
        service.current_version_id = version.id
        execution = Execution(service_id=service.id, service_version_id=version.id,
                              execution_key="retained-scan", scanned_at=datetime.now(timezone.utc),
                              complete=True, raw_payload={})
        db.add(execution)
        db.flush()
        yield db, service, execution
    engine.dispose()


def test_original_bytes_and_all_four_formats_survive_ingestion_and_export(collected, db_source):
    retained, grype, trivy, syft = collected
    db, service, execution = db_source
    validated = ExecutionPayload.model_validate(pipeline_payload(**retained)).model_dump(mode="json")
    execution.raw_payload = validated
    db.flush()
    with ZipFile(BytesIO(_service_raw_scanner_bytes(service.service_key, db))) as archive:
        assert archive.read("grype-json/image-results.json") == grype
        assert archive.read("trivy-json/chart.json") == trivy
        assert len(archive.namelist()) == 3  # Neither normalized findings nor Dockle masquerades as raw.
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["execution_id"] == execution.execution_key
        assert manifest["missing_formats"] == []
        assert all(entry["provenance"] == "original" for entry in manifest["entries"])
    with ZipFile(BytesIO(_service_sboms_bytes(service.service_key, db))) as archive:
        assert archive.read("syft-json/image.json") == syft
        assert len(archive.namelist()) == 5
        manifest = json.loads(archive.read("manifest.json"))
        assert {entry["format"] for entry in manifest["entries"]} == set(SBOM_FORMATS)
        assert manifest["missing_formats"] == []
        for retained_document in validated["evidence_documents"]:
            if retained_document["category"] == "sbom":
                original = EvidenceDocument.model_validate(retained_document)
                assert archive.read(f"{original.format}/{original.name}") == decode_document(original)
        derived = [entry for entry in manifest["entries"] if entry["format"] != "syft-json"]
        assert all(entry["derived_from_sha256"] == sha256(syft).hexdigest() for entry in derived)
        assert all(entry["conversion_timestamp_source"] == "source-file-mtime" for entry in derived)
        assert json.loads(archive.read("cyclonedx-json/image.cyclonedx.json"))["bomFormat"] == "CycloneDX"
        assert b"<bom " in archive.read("cyclonedx-xml/image.cyclonedx.xml")
        assert json.loads(archive.read("spdx-json/image.spdx.json"))["spdxVersion"] == "SPDX-2.3"


def test_historical_or_normalized_evidence_is_never_mislabeled_as_raw(db_source):
    db, service, execution = db_source
    execution.raw_payload = {"evidence_documents": [document()]}
    db.flush()
    next_version = ServiceVersion(service_id=service.id, version="2")
    db.add(next_version)
    db.flush()
    service.current_version_id = next_version.id
    db.add(Execution(service_id=service.id, service_version_id=next_version.id, execution_key="new",
                     scanned_at=datetime.now(timezone.utc), complete=True,
                     raw_payload={"sbom_components": [{"name": "normalized"}], "findings": [{"cve": "CVE-1"}]}))
    db.flush()
    for builder in (_service_raw_scanner_bytes, _service_sboms_bytes):
        with pytest.raises(HTTPException) as exc:
            builder(service.service_key, db)
        assert exc.value.status_code == 422


@pytest.mark.parametrize("changes", [
    {"name": "../escape.json"}, {"name": "C:\\escape.json"}, {"name": "bad:name.json"},
    {"format": "spdx-json"}, {"derived_from_sha256": "a" * 64}, {"sha256": "a" * 64},
    {"bytes": 1}, {"content": "not base64"},
])
def test_schema_rejects_unsafe_or_corrupt_documents(changes):
    with pytest.raises(ValueError):
        ExecutionPayload.model_validate(pipeline_payload(evidence_documents=[document(**changes)]))


def test_schema_rejects_duplicate_casefold_names_and_aggregate_limits(monkeypatch):
    value = document()
    with pytest.raises(ValueError, match="Duplicate"):
        ExecutionPayload.model_validate(pipeline_payload(evidence_documents=[value, {**value, "name": value["name"].upper()}]))
    monkeypatch.setenv("CATS_INGEST_MAX_EVIDENCE_BYTES", str(value["bytes"] * 2 - 1))
    with pytest.raises(ValueError, match="byte limit"):
        ExecutionPayload.model_validate(pipeline_payload(evidence_documents=[value, {**value, "name": "other.json"}]))


def test_decompression_cannot_expand_past_declared_size(monkeypatch):
    monkeypatch.setenv("CATS_INGEST_MAX_EVIDENCE_BYTES", "1000")
    bomb = EvidenceDocument.model_validate(document(b"x" * 200000, bytes=1))
    with pytest.raises(ValueError, match="size or checksum"):
        decode_document(bomb)


def test_retained_corruption_fails_export_without_a_fake_unavailable_file(db_source):
    db, service, execution = db_source
    execution.raw_payload = {"evidence_documents": [document(sha256="0" * 64)]}
    db.flush()
    with pytest.raises(HTTPException) as exc:
        _service_raw_scanner_bytes(service.service_key, db)
    assert exc.value.status_code == 409


def test_evidence_zip_enforces_export_size_limit(db_source, monkeypatch):
    db, service, execution = db_source
    execution.raw_payload = {"evidence_documents": [document()]}
    db.flush()
    monkeypatch.setenv("CATS_EXPORT_MAX_BYTES", "40")
    with pytest.raises(ValueError, match="byte limit"):
        _service_raw_scanner_bytes(service.service_key, db)


def test_collection_records_limits_and_conversion_failure(tmp_path, monkeypatch):
    (tmp_path / "sboms").mkdir()
    (tmp_path / "sboms/broken.json").write_bytes(b"not-json\r\n")
    target = tmp_path / "retained.json"
    subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), str(target)], check=True)
    result = json.loads(target.read_text())
    assert len(result["evidence_documents"]) == 1  # Exact original remains available.
    assert {item["format"] for item in result["evidence_unavailable"]} == set(SBOM_FORMATS) - {"syft-json"}
    ExecutionPayload.model_validate(pipeline_payload(**result))
    monkeypatch.setenv("CATS_INGEST_MAX_EVIDENCE_BYTES", "1")
    subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), str(target)], check=True)
    result = json.loads(target.read_text())
    assert not result["evidence_documents"]
    assert {item["format"] for item in result["evidence_unavailable"]} == set(SBOM_FORMATS)
    ExecutionPayload.model_validate(pipeline_payload(**result))


def test_legacy_summary_bundle_omits_original_free_form_reports():
    from app.service_bundle import portable_payload
    value = portable_payload(pipeline_payload(evidence_documents=[document()]))
    assert value["evidence_documents"] == []
