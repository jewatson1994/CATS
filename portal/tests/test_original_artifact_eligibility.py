"""Synthetic unit fixtures; these are not real lifecycle acceptance evidence."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import pytest
from test_artifact_catalog import db, artifact
from app import artifact_catalog as catalog, release_validity
from app.cyber_approvals import CyberApproval, digest
from app.execution_summaries import payload_digest
from app.models import Service, Execution, DeploymentValidationRun


@pytest.fixture
def original(db):
    service = Service(service_key="original", name="Original")
    db.add(service); db.flush()
    target = artifact(db)
    source = "source/original@" + target.digest
    reference = "published/original@" + target.digest
    execution = Execution(execution_key="scan", service_id=service.id, scanned_at=datetime.now(timezone.utc), complete=True, raw_payload={"scan": "unit fixture"})
    db.add(execution); db.flush()
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    snapshot = {"service_id": service.id, "source_execution_id": execution.id,
        "source_payload_digest": payload_digest(execution.raw_payload), "signing_fingerprint": "key",
        "approval_validity": release_validity.new_validity(now),
        "artifacts": [{"kind": "image", "reference": source, "digest": target.digest}]}
    approval = CyberApproval(service_id=service.id, source_execution_id=execution.id,
        variant="current_service", status="approved", publish_status="published", decided_by_id=1,
        decided_at=now, decision_rationale="Unit fixture", snapshot=snapshot, snapshot_digest=digest(snapshot))
    db.add(approval); db.flush()
    item = {"kind": "image", "digest": target.digest, "source_digest": target.digest,
        "source_reference": source, "reference": reference, "scan_identity_retained": True,
        "verification_status": "verified", "signature": {"signature_status": "verified",
        "signature": {"image": reference, "generator": "cosign", "key_fingerprint": "key", "verified_at": now.isoformat()}}}
    approval.publication = {"status": "published", "verification_status": "verified", "signature_status": "verified",
        "approval_id": approval.id, "release_key": approval.release_key, "signing_fingerprint": "key", "artifacts": [item],
        "manifest": {"approval_id": approval.id, "snapshot_digest": approval.snapshot_digest, "artifacts": [item]}}
    validation = DeploymentValidationRun(run_key="validation", service_id=service.id, artifact_reference=reference, status="VERIFIED")
    db.add(validation); db.flush()
    return service, target, approval, execution, validation


def test_original_requires_explicit_exact_service(db, original):
    service, target, approval, execution, validation = original
    assert catalog.artifact_eligibility(db, target.id, service.id) == {"eligible": True, "reasons": [], "approval_id": approval.id, "validation_run_id": validation.id}
    assert not catalog.artifact_eligibility(db, target.id)["eligible"]
    assert not catalog.artifact_eligibility(db, target.id, service.id + 1)["eligible"]


@pytest.mark.parametrize("failure", ["revoked", "pending", "expired", "snapshot", "publication", "manifest", "source_digest", "signature_image", "signature_key", "retained_identity", "scan", "incomplete", "validation", "newer_failed_validation"])
def test_original_fails_closed(db, original, failure):
    service, target, approval, execution, validation = original
    publication = deepcopy(approval.publication)
    if failure == "revoked": approval.revoked_at = datetime.now(timezone.utc)
    elif failure == "pending": approval.status = "pending"
    elif failure == "expired":
        approval.decided_at = datetime.now(timezone.utc) - timedelta(days=100)
        approval.snapshot = {**approval.snapshot, "approval_validity": release_validity.new_validity(approval.decided_at)}
        approval.snapshot_digest = digest(approval.snapshot)
    elif failure == "snapshot": approval.snapshot_digest = "tampered"
    elif failure == "publication": publication["status"] = "publishing"
    elif failure == "manifest": publication["manifest"]["snapshot_digest"] = "other"
    elif failure == "source_digest": publication["artifacts"][0]["source_digest"] = "sha256:" + "b"*64
    elif failure == "signature_image": publication["artifacts"][0]["signature"]["signature"]["image"] = "other"
    elif failure == "signature_key": publication["artifacts"][0]["signature"]["signature"]["key_fingerprint"] = "other"
    elif failure == "retained_identity": publication["artifacts"][0]["scan_identity_retained"] = False
    elif failure == "scan": execution.raw_payload = {"changed": True}
    elif failure == "incomplete": execution.complete = False
    elif failure == "validation": validation.artifact_reference = "other"
    elif failure == "newer_failed_validation": db.add(DeploymentValidationRun(run_key="newer", service_id=service.id, artifact_reference=validation.artifact_reference, status="FAILED"))
    approval.publication = publication
    db.flush()
    assert not catalog.artifact_eligibility(db, target.id, service.id)["eligible"]


def test_newer_original_decision_supersedes_previous_publication(db, original):
    service, target, approval, execution, validation = original
    db.add(CyberApproval(service_id=service.id, source_execution_id=execution.id,
        variant="current_service", status="denied", snapshot=deepcopy(approval.snapshot),
        snapshot_digest=approval.snapshot_digest, decision_rationale="New review denied"))
    db.flush()
    assert not catalog.artifact_eligibility(db, target.id, service.id)["eligible"]
