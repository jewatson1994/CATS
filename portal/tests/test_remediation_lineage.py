from types import SimpleNamespace
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, ServiceVersion, Execution, RemediationExecution, User
from app.remediation_lineage import (ArtifactProvenance, ingested_artifacts,
    remediation_artifacts, record_reingestion_provenance)

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def output(**kwargs):
    return SimpleNamespace(output_mode="publish", patched_images=[{"candidate": "r/api:tag", "digest": DIGEST}],
        validation_results={}, **kwargs)


def test_mutable_tags_and_malformed_digests_never_match():
    assert ingested_artifacts({"service_overview": {"images": ["r/api:tag", {"image": "r/api:tag", "digest": "sha256:bad"}]}}) == {}


def test_digests_match_regardless_of_tag_and_case():
    assert ("image", DIGEST, "oci_manifest") in ingested_artifacts({"service_overview": {
        "images": [{"reference": "new/api:release", "digest": DIGEST.upper()}]}})


def test_download_tar_checksum_is_not_image_manifest_identity():
    row = output()
    row.output_mode = "bundle"
    assert remediation_artifacts(row) == {}


def test_helm_package_and_oci_manifest_have_distinct_identity_domains():
    row = output()
    row.validation_results = {"charts": [{"name": "api", "sha256": "a" * 64,
        "digest": OTHER, "package_status": "PACKAGED", "publish_status": "PUBLISHED"}]}
    artifacts = remediation_artifacts(row)
    assert ("helm", DIGEST, "package_sha256") in artifacts
    assert ("helm", OTHER, "oci_manifest") in artifacts


def test_explicit_artifact_verification_overrides_legacy_inventory():
    row = output()
    snapshot = {"status": "not_verified", "artifact_digest": OTHER}
    row.validation_results = {"artifact_identities": [{"kind": "image", "digest": DIGEST,
        "reference": "registry/api@" + DIGEST, "verification": snapshot}]}
    assert remediation_artifacts(row)[("image", DIGEST, "oci_manifest")]["verification"] == snapshot


def test_artifact_provenance_is_scoped_idempotent_and_not_release_promotion():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(service_key="a", name="A")
        other_service = Service(service_key="b", name="B")
        user = User(username="manager", display_name="Manager", password_hash="unused")
        db.add_all([service, other_service, user]); db.flush()
        old = ServiceVersion(service_id=service.id, version="1.5")
        new = ServiceVersion(service_id=service.id, version="1.6")
        db.add_all([old, new]); db.flush()
        service.current_version_id = new.id
        source = Execution(service_id=service.id, service_version_id=old.id, execution_key="source",
            scanned_at=old.created_at, complete=True, raw_payload={})
        target = Execution(service_id=service.id, service_version_id=new.id, execution_key="target",
            scanned_at=new.created_at, complete=True, raw_payload={})
        db.add_all([source, target]); db.flush()
        candidate = RemediationExecution(service_id=service.id, requested_by_id=user.id, job_key="r1",
            source_execution_id=source.id, source_version_id=old.id, revision_number=1,
            output_mode="publish", patched_images=output().patched_images,
            validation_results={"status": "PASS"}, remediation_status="partial",
            verification_status="not_verified", signing_status="failed")
        foreign = RemediationExecution(service_id=other_service.id, requested_by_id=user.id, job_key="foreign",
            output_mode="publish", patched_images=output().patched_images)
        db.add_all([candidate, foreign]); db.flush()
        payload = {"service_overview": {"images": [{"image": "app@" + DIGEST}, {"image": "other@" + OTHER}]}}
        rows = record_reingestion_provenance(db, target, payload)
        assert len(rows) == 1
        assert rows[0]["source_version"] == "1.5"
        assert rows[0]["revision_number"] == 1
        assert rows[0]["post_remediation_scan"] == "PASS"
        assert rows[0]["runtime_verification"] == "not_verified"
        assert rows[0]["signature"] == "failed"
        assert rows[0]["release_lineage"] is False
        assert rows[0]["remediation_status"] == "partial"
        candidate.verification_status = "verified"
        assert record_reingestion_provenance(db, target, payload) == rows
        assert len(db.scalars(select(ArtifactProvenance)).all()) == 1
        assert service.current_version_id == new.id
        assert source.service_version_id == old.id
