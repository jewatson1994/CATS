"""Exact retained inventory recovery and bounded queries; no publisher coverage claims."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select, update, delete
from app.models import Execution, Finding, FindingObservation, SbomComponent, Service
from app.sbom_components import retain_components, recover_identities, key, MAX_MATCHES
from app.container_intelligence import observation_identities
from app.native_vex_models import VexDispositionService
from test_native_vex import db, setup

DIGEST = "sha256:" + "a" * 64
DOCUMENT = "sha256:" + "b" * 64
PURL = "pkg:apk/wolfi/libtest@1.0?arch=x86_64"


def inventory(db, **changes):
    service, finding, observations, _ = setup(db)
    observation = observations[0]
    observation.image_digest = DIGEST
    observation.evidence = {"scanner_component_id": "component-one", "image_platform": "linux/amd64", "sbom_digest": DOCUMENT}
    component = {"component_id": "component-one", "name": "libtest", "version": "1.0",
        "purl": PURL, "image": "one", "image_digest": DIGEST, "image_manifest_digest": DIGEST, "image_platform": "linux/amd64",
        "sbom_digest": DOCUMENT, "sbom_format": "syft-json"}
    component.update(changes)
    retain_components(db, observation.execution_id, [component])
    db.commit()
    return service, finding, observation, component


def test_exact_recovery_preserves_scanner_evidence(db):
    _, _, observation, component = inventory(db)
    original = deepcopy(observation.evidence)
    identity = observation_identities(db, [observation])[0]
    assert identity["context"]["purl"] == PURL
    assert identity["raw_purl"] is None
    assert identity["scanner_identity"]["context"] == {}
    assert identity["sbom_binding"]["provenance"]["sbom_digest"] == DOCUMENT
    assert observation.evidence == original


@pytest.mark.parametrize("change,reason", [
    ({"image_manifest_digest": "sha256:" + "c" * 64}, "sbom_image_digest_conflict"),
    ({"image_manifest_digest": ""}, "sbom_image_digest_missing"),
    ({"image_platform": "linux/arm64"}, "sbom_platform_conflict"),
    ({"image_platform": ""}, "sbom_platform_binding_missing"),
    ({"version": "2.0"}, "sbom_observed_identity_conflict"),
    ({"sbom_digest": ""}, "sbom_document_digest_missing"),
    ({"sbom_artifact": "not json"}, "sbom_structured_evidence_invalid"),
    ({"sbom_artifact": json.dumps({"name": "different"})}, "sbom_component_identity_conflict"),
])
def test_conflicting_and_incomplete_records_fail_closed(db, change, reason):
    _, _, observation, _ = inventory(db, **change)
    result = observation_identities(db, [observation])[0]
    assert not result["context"]
    assert reason in result["sbom_binding"]["reasons"]


@pytest.mark.parametrize("change,reason", [
    ({"sbom_digest": None}, "sbom_observation_document_digest_missing"),
    ({"sbom_digest": "sha256:" + "c" * 64}, "sbom_document_digest_conflict"),
    ({"image_platform": None}, "sbom_platform_binding_missing"),
    ({"image_platform": "linux/arm64"}, "sbom_platform_conflict"),
    ({"scanner_source": {"metadata": {"manifestDigest": "sha256:" + "c" * 64}}},
        "sbom_scanner_artifact_digest_conflict"),
    ({"scanner_source": {"target": {"manifestDigest": "sha256:" + "c" * 64}}},
        "sbom_scanner_artifact_digest_conflict"),
    ({"component_id": "another-component"}, "sbom_scanner_component_id_conflict"),
])
def test_observation_requires_matching_document_platform_and_component(db, change, reason):
    _, _, observation, _ = inventory(db)
    observation.evidence = {**observation.evidence, **change}
    identity = observation_identities(db, [observation])[0]
    assert not identity["context"]
    assert identity["sbom_binding"]["reasons"] == [reason]


def test_same_name_versions_images_and_dependency_edges_never_match(db):
    _, _, observation, component = inventory(db, component_id="unrelated", dependency_children="component-one")
    retain_components(db, observation.execution_id, [{**component, "component_id": "component-one", "image": "other"}])
    db.flush()
    assert recover_identities(db, [observation])[0]["status"] == "missing"
    observation.evidence = {}
    assert recover_identities(db, [observation])[0]["reasons"] == ["sbom_exact_identifier_missing"]


def test_distinct_instances_and_versions_are_not_collapsed(db):
    _, _, observation, component = inventory(db)
    retain_components(db, observation.execution_id, [{**component, "location": "/different/location"}])
    db.flush()
    assert recover_identities(db, [observation])[0]["status"] == "ambiguous"


def test_wrong_execution_and_cross_service_never_match(db):
    service, finding, observation, component = inventory(db)
    other = Execution(service_id=service.id, execution_key="different", complete=True,
                      scanned_at=observation.finding.last_seen, raw_payload={})
    db.add(other); db.flush()
    original_execution = observation.execution_id
    observation.execution_id = other.id; db.flush()
    assert recover_identities(db, [observation])[0]["status"] == "missing"
    outsider = Service(service_key="outsider", name="Other"); db.add(outsider); db.flush()
    db.execute(update(Execution).where(Execution.id == original_execution).values(service_id=outsider.id))
    observation.execution_id = original_execution; db.flush()
    assert recover_identities(db, [observation])[0]["reasons"] == ["sbom_execution_service_conflict"]


def test_complete_scanner_identity_does_not_query_inventory(db):
    _, _, observation, _ = inventory(db)
    observation.evidence = {"purl": PURL}
    db.flush()
    db.refresh(observation)
    statements = []
    def record(conn, cursor, statement, parameters, context, many):
        statements.append(statement)
    event.listen(db.bind, "before_cursor_execute", record)
    try:
        identity = observation_identities(db, [observation])[0]
    finally:
        event.remove(db.bind, "before_cursor_execute", record)
    assert identity["context"]["purl"] == PURL
    assert not statements


def test_batched_duplicate_requests_and_candidate_cap(db):
    _, _, observation, component = inventory(db)
    retain_components(db, observation.execution_id, [{**component, "location": str(i)} for i in range(MAX_MATCHES + 3)])
    db.flush()
    statements = []
    def record(conn, cursor, statement, parameters, context, many):
        statements.append(statement)
    event.listen(db.bind, "before_cursor_execute", record)
    try:
        results = recover_identities(db, [observation] * 250)
    finally:
        event.remove(db.bind, "before_cursor_execute", record)
    assert len(statements) == 3  # ownership + one bounded probe, not 250 full inventories
    assert all(result["reasons"] == ["sbom_candidate_limit"] for result in results)
    assert "LIMIT" in statements[-1]


@pytest.mark.parametrize("mutation", ["insert", "update", "delete", "move"])
def test_component_mutations_invalidate_service_generation(db, mutation):
    service, _, observation, component = inventory(db)
    before = db.scalar(select(VexDispositionService.generation).where(VexDispositionService.service_id == service.id))
    if mutation == "insert":
        retain_components(db, observation.execution_id, [component])
    elif mutation == "update":
        db.execute(update(SbomComponent).values(data={**component, "version": "2.0"}))
    elif mutation == "delete":
        db.execute(delete(SbomComponent))
    else:
        other = Service(service_key="moved", name="Other"); db.add(other); db.flush()
        execution = Execution(service_id=other.id, execution_key="moved", complete=True,
                              scanned_at=observation.finding.last_seen, raw_payload={})
        db.add(execution); db.flush()
        other_before = db.scalar(select(VexDispositionService.generation).where(VexDispositionService.service_id == other.id))
        db.execute(update(SbomComponent).values(execution_id=execution.id))
        assert db.scalar(select(VexDispositionService.generation).where(VexDispositionService.service_id == other.id)) > other_before
    assert db.scalar(select(VexDispositionService.generation).where(VexDispositionService.service_id == service.id)) > before


def test_original_metadata_conflict_cannot_be_overwritten(db):
    _, _, observation, _ = inventory(db, sbom_artifact=json.dumps({"id": "component-one", "name": "libtest",
        "version": "1.0", "purl": PURL, "metadata": {"architecture": "x86_64"}}))
    observation.evidence = {**observation.evidence, "scanner_artifact": {"id": "component-one",
        "metadata": {"architecture": "aarch64"}}}
    assert recover_identities(db, [observation])[0]["reasons"] == ["sbom_scanner_metadata_conflict"]


def test_replaced_execution_payload_cannot_reuse_old_projection(db):
    _, _, observation, _ = inventory(db)
    db.execute(update(Execution).where(Execution.id == observation.execution_id).values(
        raw_payload={"sbom_components": []}))
    db.flush()
    assert db.scalar(select(SbomComponent.id).limit(1)) is None
    assert recover_identities(db, [observation])[0]["status"] == "missing"


@pytest.mark.parametrize("enabled", [False, True])
def test_mixed_recovered_and_unresolved_observations_remain_actionable(db, enabled):
    from app import native_vex as nv
    from app.findings_sql import get_raw_finding_page
    from app.remediation_jobs import filter_native_vex_images
    from test_native_vex import enable, excluded, NOW
    from test_vex_repository import PID
    service, finding, observation, component = inventory(db, purl=PID)
    db.add(FindingObservation(finding_id=finding.id, execution_id=observation.execution_id,
        image="two", image_digest=DIGEST, package="libtest", installed_version="2.0",
        fixed_version="3.0", evidence={"scanner_component_id": "missing",
            "image_platform": "linux/amd64", "sbom_digest": DOCUMENT}))
    db.commit()
    if enabled:
        enable(db)
    evaluation = nv.evaluate_service(db, service.id, now=NOW)
    db.commit()
    assert evaluation.summary["excluded_observations"] == 1
    assert not excluded(db, finding)
    assert get_raw_finding_page(db, service.id, {}, NOW)["total_items"] == 1
    plan = {"images": [{"original": "one"}, {"original": "two"}]}
    filter_native_vex_images(db, service.id, observation.execution_id, plan, NOW)
    assert [item["original"] for item in plan["images"]] == (["two"] if enabled else ["one", "two"])
    assert finding.active and finding.resolved_at is None
    db.execute(delete(SbomComponent))
    db.commit()
    nv.evaluate_service(db, service.id, now=NOW)
    db.commit()
    plan = {"images": [{"original": "one"}, {"original": "two"}]}
    filter_native_vex_images(db, service.id, observation.execution_id, plan, NOW)
    assert len(plan["images"]) == 2
