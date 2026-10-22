from test_artifact_catalog import db, setup_lineage
from app.artifact_evidence_summary import vulnerability_evidence

def test_only_verified_digest_bound_counters_are_exposed(db):
    _, source, target, patch, _ = setup_lineage(db)
    assert vulnerability_evidence(db, patch_id=patch.id) is None
    receipt = {"status": "complete", "patch_status": "PATCHED", "delivery_status": "delivered",
        "source_image": patch.source_image, "immutable_destination": patch.destination_image,
        "signature_status": "verified", "signature": {"image": patch.destination_image,
        "generator": "cosign", "key_fingerprint": "key", "verified_at": "now"},
        "artifact_validation": "docker-load", "validated_source": "flattened-rootfs",
        "vulnerabilities_before": 2, "vulnerabilities_after": 7}
    patch.summary = {"artifact_receipt": receipt}
    assert vulnerability_evidence(db, source_id=source.id, target_id=target.id) == {
        "before": 2, "after": 7, "source_digest": source.digest, "target_digest": target.digest,
        "scope": "retained_image_patch"}
    for change in ({"source_image": "tag"}, {"vulnerabilities_after": None}, {"signature_status": "unverified"}):
        patch.summary = {"artifact_receipt": {**receipt, **change}}
        assert vulnerability_evidence(db, patch_id=patch.id) is None


def test_readiness_route_preserves_scope_and_request_permissions(db, monkeypatch):
    import pytest
    from fastapi import HTTPException
    from test_artifact_catalog import ScopedAuth
    from app.artifact_catalog_routes import proposal_readiness
    from app import release_revisions
    service, _, _, _, _ = setup_lineage(db)
    calls = []
    def readiness(db, auth, proposal_id, service_id):
        calls.append((proposal_id, service_id))
        return {"ready_for_cyber_review": False, "blockers": [{"code": "proposed_assessment_required"}]}
    monkeypatch.setattr(release_revisions, "amendment_readiness", readiness)
    for auth, code in [(ScopedAuth([]), 404), (ScopedAuth([service.id]), 403)]:
        with pytest.raises(HTTPException) as error:
            proposal_readiness("one", 12, db=db, auth=auth)
        assert error.value.status_code == code
    assert not calls
    result = proposal_readiness("one", 12, db=db, auth=ScopedAuth([service.id], True))
    assert result["ready_for_cyber_review"] is False
    assert calls == [(12, service.id)]
