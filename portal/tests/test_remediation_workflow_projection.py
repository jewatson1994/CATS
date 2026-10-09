from types import SimpleNamespace as N

import pytest

from app.remediation_workflow import artifact_capabilities, delivery_policy, validation_required, workflow_projection
from app.frontend_remediations import project_remediations


def candidate(**overrides):
    values = dict(service_id=7, service=N(service_key="payments"), original_revision="v1",
        status="complete", verification_status="not_verified", delivery_status="not_delivered",
        artifact_digest="sha256:abc", artifact_path="private/candidate.zip",
        workflow_inputs={"workflow_version": 2, "service": {"id": "payments", "version": "v1"},
            "artifact_capabilities": {"download": True, "oci": True, "standard-bundle": True, "offline-bundle": False}},
        validation_results={"deployment": {"status": "NOT RUN"}})
    return N(**(values | overrides))


def verified():
    return candidate(verification_status="verified", validation_results={"deployment": {
        "status": "VERIFIED", "artifact_digest": "sha256:abc", "service": {"id": "payments", "version": "v1"}}})


def test_new_pending_validation_is_unresolved_even_when_optional():
    for required in (True, False):
        assert delivery_policy(candidate(), validation_required=required)["resolved"] is False
        assert delivery_policy(candidate(), validation_required=required)["publish_allowed"] is False


@pytest.mark.parametrize("status", ["FAILED", "PARTIALLY_VERIFIED", "BLOCKED"])
def test_failed_validation_resolves_stage_but_never_allows_publication(status):
    record = candidate(verification_status="failed", validation_results={"deployment": {"status": status}})
    for required in (True, False):
        assert delivery_policy(record, validation_required=required) == {
            "resolved": True, "publish_allowed": False, "reason": "Candidate validation failed; OCI publication is blocked."}
        workflow = workflow_projection(record, validation_required=required)
        assert workflow["stage"] == "deliver" and workflow["validation_outcome"] == "failed"


@pytest.mark.parametrize("status", ["unavailable", "skipped"])
def test_unavailable_or_skipped_validation_permits_only_optional_publication(status):
    record = candidate(verification_status=status, validation_results={"deployment": {"status": status.upper()}})
    assert delivery_policy(record, validation_required=False)["publish_allowed"] is True
    assert delivery_policy(record, validation_required=True)["publish_allowed"] is False


@pytest.mark.parametrize("change", ["digest", "service", "version", "missing"])
def test_required_verification_is_bound_to_candidate_service_and_version(change):
    record = verified()
    assert delivery_policy(record, validation_required=True)["publish_allowed"] is True
    evidence = record.validation_results["deployment"]
    if change == "digest":
        evidence["artifact_digest"] = "sha256:other"
    elif change == "service":
        evidence["service"]["id"] = "other"
    elif change == "version":
        evidence["service"]["version"] = "v2"
    else:
        record.validation_results = {}
    assert delivery_policy(record, validation_required=True)["publish_allowed"] is False


def test_legacy_terminal_not_verified_is_resolved_without_bypassing_required_policy():
    record = candidate(workflow_inputs={})
    assert delivery_policy(record, validation_required=False)["publish_allowed"] is True
    assert delivery_policy(record, validation_required=True)["resolved"] is True
    assert delivery_policy(record, validation_required=True)["publish_allowed"] is False


def test_validation_retry_keeps_delivery_unresolved():
    record = verified()
    record.verification_status = "queued"
    assert delivery_policy(record, validation_required=False)["resolved"] is False
    assert workflow_projection(record)["stage"] == "validate"


@pytest.mark.parametrize("cleanup", ["UNKNOWN", "FAILED", "PENDING", "RUNNING"])
@pytest.mark.parametrize("required", [True, False])
def test_unresolved_cleanup_blocks_publication_even_when_validation_is_optional(cleanup, required):
    record = candidate(verification_status="unavailable", validation_results={"deployment": {
        "status": "UNAVAILABLE", "cleanup_status": cleanup}})
    policy = delivery_policy(record, validation_required=required)
    assert policy["resolved"] is True
    assert policy["publish_allowed"] is False
    assert "cleanup" in policy["reason"]
    record = verified()
    record.validation_results["deployment"]["cleanup_status"] = cleanup
    assert delivery_policy(record, validation_required=required)["publish_allowed"] is False


def test_candidate_download_is_available_for_troubleshooting_with_export_permission():
    result = workflow_projection(candidate(), can=lambda permission, sid: permission == "service.export", service_id=7)
    options = {row["mode"]: row for row in result["delivery_options"]}
    assert options["bundle"]["available"] is True
    assert options["oci"]["available"] is False
    assert options["standard-bundle"]["available"] is False
    assert options["offline-bundle"]["available"] is False


def test_oci_publication_and_signing_have_explicit_scoped_permissions():
    record = verified()
    for permissions, allowed in [({"service.export", "remediation.execute"}, False),
        ({"artifact.publish"}, False), ({"artifact.publish", "artifact.sign"}, True)]:
        result = workflow_projection(record, can=lambda key, sid: key in permissions and sid == 7,
                                     service_id=7, signing_required=True)
        assert next(row for row in result["delivery_options"] if row["mode"] == "oci")["available"] is allowed


def test_skip_requires_optional_policy_and_remediation_permission():
    assert workflow_projection(candidate(), validation_required=False, can=lambda *_: True)["can_skip_validation"] is True
    assert workflow_projection(candidate(), validation_required=False, can=lambda *_: False)["can_skip_validation"] is False
    assert workflow_projection(candidate(), validation_required=True, can=lambda *_: True)["can_skip_validation"] is False


def test_permissions_are_added_to_only_publish_roles():
    from app.auth import PERMISSIONS, SYSTEM_ROLES
    assert "artifact.publish" in PERMISSIONS
    assert "artifact.publish" in SYSTEM_ROLES["Administrator"]
    assert "artifact.publish" in SYSTEM_ROLES["Cybersecurity"]
    assert "artifact.publish" not in SYSTEM_ROLES["Service Manager"]


def test_policy_default_is_required(monkeypatch):
    monkeypatch.delenv("CATS_REMEDIATION_REQUIRE_VALIDATION", raising=False)
    assert validation_required() is True
    monkeypatch.setenv("CATS_REMEDIATION_REQUIRE_VALIDATION", "false")
    assert validation_required() is False


def test_projection_whitelists_plan_evidence_and_explicit_permissions():
    import json
    record = verified()
    record.workflow_inputs["approved_plan"] = {"images": [{"original": "safe", "credentials": "SECRET"}], "credentials": "SECRET"}
    record.validation_results["deployment"].update(validated_at="2026-10-09T12:00:00Z", phase="COMPLETE", request={"token": "SECRET"})
    data = {"can": {}, "next_path": "/remediations"}
    project_remediations(data, "remediation_report.html", {"job": record, "service": N(id=7)}, lambda *_: True, {})
    assert "SECRET" not in json.dumps(data)
    assert "private/candidate.zip" not in json.dumps(data)
    assert data["job"]["workflow"]["approved_plan"]["images"][0]["original"] == "safe"
    assert data["job"]["candidate_validation"]["phase"] == "COMPLETE"
    assert data["job"]["candidate_validation"]["validated_at"] == "2026-10-09T12:00:00Z"
    assert data["can"]["artifact.publish"]["7"] is True
    assert data["can"]["artifact.sign"]["7"] is True


def test_legacy_capabilities_never_invent_deliverable_artifacts():
    record = candidate(workflow_inputs={})
    assert artifact_capabilities(record) == {"download": True, "oci": False, "standard-bundle": False, "offline-bundle": False}
    record.validation_results["candidate_manifest"] = {"images": [{"archive_path": "images/a.tar"}],
        "deployment_manifest": {"deployment": {"chartPath": "candidate/chart"}, "validationType": "standard-bundle"}}
    assert artifact_capabilities(record) == {"download": True, "oci": True, "standard-bundle": True, "offline-bundle": False}


def test_polling_projection_omits_details_that_need_permissions_or_evidence():
    result = workflow_projection(candidate(), include_details=False)
    assert result == {"stage": "validate", "state": "ready", "validation_outcome": "not_verified", "validation_resolved": False, "validation_required": True}
    assert not {"approved_plan", "delivery_options", "publish_allowed", "can_skip_validation"} & result.keys()


def test_status_reads_workflow_version_scalar_and_tracks_skip_without_evidence():
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import Session
    from app.database import Base
    from app.models import RemediationExecution, Service, User
    from app.remediation_delivery import DeliveryAttempt
    from app.status_contracts import remediation_status
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="workflow-status", name="Status")
        user = User(username="workflow-status", display_name="Status", password_hash="unused")
        db.add_all([service, user]); db.flush()
        record = RemediationExecution(job_key="R-WORKFLOW-STATUS", service_id=service.id, requested_by_id=user.id,
            status="complete", verification_status="not_verified", workflow_inputs={"workflow_version": 2, "approved_plan": {"secret": "not selected"}},
            validation_results={"large": "x" * 100_000})
        db.add(record); db.commit()
        statements = []
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, params, context, many: statements.append(sql))
        result = remediation_status(db, "workflow-status", "R-WORKFLOW-STATUS", DeliveryAttempt)
        assert result["workflow"]["stage"] == "validate"
        assert result["workflow"]["validation_resolved"] is False
        assert len(statements) == 2
        assert "JSON_EXTRACT" in statements[0]
        assert not any("validation_results" in sql or "before_snapshot" in sql or "approved_plan" in sql for sql in statements)
        record.verification_status = "skipped"
        db.commit()
        updated = remediation_status(db, "workflow-status", "R-WORKFLOW-STATUS", DeliveryAttempt)
        assert updated["workflow"]["stage"] == "deliver"
        assert updated["workflow"]["validation_resolved"] is True
        assert updated["revision"] != result["revision"]
    engine.dispose()
