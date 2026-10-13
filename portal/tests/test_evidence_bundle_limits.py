"""Manifest size and resource bounds for portable evidence archives."""
from io import BytesIO
from types import SimpleNamespace
from zipfile import ZipFile, ZIP_DEFLATED

import pytest

from app.service_bundle import export_bundle, parse_bundle


def executions():
    # Distinct long version labels produce a valid manifest over 64 KiB.
    return [SimpleNamespace(raw_payload={
        "execution_id": f"scan-{index}",
        "scanned_at": "2025-01-02T00:00:00Z",
        "complete": True, "fixable_only": True,
        "service": {"id": "example", "name": "Example", "version": f"{index}-{'v' * 116}"},
    }) for index in range(600)]


def test_large_evidence_manifest_roundtrips():
    source = executions()
    data = export_bundle(source)
    with ZipFile(BytesIO(data)) as archive:
        assert archive.getinfo("manifest.json").file_size > 65536
    manifest, payloads = parse_bundle(data)
    assert len(manifest["versions"]) == len(payloads) == len(source)
    assert {p.service.version for p in payloads} == {e.raw_payload["service"]["version"] for e in source}


def test_evidence_manifest_counts_toward_aggregate_limit(monkeypatch):
    source = executions()
    data = export_bundle(source)
    with ZipFile(BytesIO(data)) as archive:
        sizes = [entry.file_size for entry in archive.infolist()]
    limit = sum(sizes) - 1
    assert limit > max(sizes)
    assert len(data) < limit
    monkeypatch.setenv("CATS_BUNDLE_MAX_BYTES", str(limit))
    with pytest.raises(ValueError, match="expanded"):
        parse_bundle(data)
    with pytest.raises(ValueError, match="expanded"):
        export_bundle(source)


def test_large_evidence_manifest_rejects_duplicate_keys_and_complexity(monkeypatch):
    data = export_bundle(executions())
    with ZipFile(BytesIO(data)) as archive:
        manifest = archive.read("manifest.json")
        body = archive.read("evidence.json")
    malformed = BytesIO()
    with ZipFile(malformed, "w", ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", b'{"format":"duplicate",' + manifest[1:])
        archive.writestr("evidence.json", body)
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        parse_bundle(malformed.getvalue())
    monkeypatch.setenv("CATS_BUNDLE_MAX_JSON_NODES", "10")
    with pytest.raises(ValueError, match="complexity"):
        parse_bundle(data)
