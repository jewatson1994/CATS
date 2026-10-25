"""Exercise retained lookup evidence through the real pipeline ingestion boundary."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

from sqlalchemy import delete, func, select

from app.container_intelligence import observation_identities
from app.database import SessionLocal
from app.models import Execution, FindingObservation, SbomComponent
from test_portal import new_client, payload, pipeline_headers, setup_function


def retained_payload():
    body = payload("sbom-bound-run", datetime.now(timezone.utc), ["CVE-2026-12345"])
    digest = "sha256:" + "a" * 64
    document = "sha256:" + "b" * 64
    finding = body["findings"][0]
    finding.update(installed_version="1.0", image_digest=digest,
        evidence={"scanner_component_id": "artifact-one", "sbom_digest": document,
                  "image_platform": "linux/amd64"})
    body["sbom_components"] = [{"component_id": "artifact-one", "name": "openssl",
        "version": "1.0", "purl": "pkg:apk/wolfi/openssl@1.0?arch=x86_64",
        "image": finding["image"], "image_digest": digest, "image_manifest_digest": digest,
        "image_platform": "linux/amd64", "sbom_digest": document, "sbom_format": "syft-json"}]
    return body


def test_ingest_retains_exact_inventory_once_and_preserves_original_evidence():
    client = new_client()
    body = retained_payload()
    response = client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers)
    assert response.status_code == 201, response.text
    duplicate = client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers)
    assert duplicate.status_code == 201 and duplicate.json()["duplicate"] is True, duplicate.text
    with SessionLocal() as db:
        execution = db.scalar(select(Execution))
        component = db.scalar(select(SbomComponent))
        observation = db.scalar(select(FindingObservation))
        assert db.scalar(select(func.count()).select_from(SbomComponent)) == 1
        assert component.execution_id == execution.id
        assert component.data == body["sbom_components"][0]
        assert execution.raw_payload["sbom_components"] == body["sbom_components"]
        original = deepcopy(observation.evidence)
        identity = observation_identities(db, [observation])[0]
        assert identity["sbom_binding"]["status"] == "matched"
        assert identity["context"]["purl"] == component.data["purl"]
        assert identity["scanner_identity"]["raw_purl"] is None
        assert observation.evidence == original
    changed = deepcopy(body)
    changed["sbom_components"][0]["version"] = "2.0"
    assert client.post("/api/v1/pipeline-results", json=changed,
                       headers=pipeline_headers).status_code == 409
    with SessionLocal() as db:
        assert db.scalar(select(SbomComponent)).data == body["sbom_components"][0]


def test_explicit_backfill_reuses_retained_rows_without_changing_scan(monkeypatch, capsys):
    client = new_client()
    body = retained_payload()
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    with SessionLocal() as db:
        original = deepcopy(db.scalar(select(Execution)).raw_payload)
        db.execute(delete(SbomComponent))
        db.commit()
    path = Path(__file__).parents[2] / "scripts/index-retained-sbom-components.py"
    spec = importlib.util.spec_from_file_location("index_retained_sbom", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SessionLocal", SessionLocal)
    monkeypatch.setattr(sys, "argv", [str(path), "--limit", "1"])
    module.main()
    assert "Indexed 1 component rows from 1 executions" in capsys.readouterr().out
    module.main()
    assert "Indexed 0 component rows from 0 executions" in capsys.readouterr().out
    with SessionLocal() as db:
        assert db.scalar(select(Execution)).raw_payload == original
        assert db.scalar(select(func.count()).select_from(SbomComponent)) == 1
        assert db.scalar(select(SbomComponent)).data == original["sbom_components"][0]
