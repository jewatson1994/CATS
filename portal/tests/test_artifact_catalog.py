import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from app.database import Base
from app import release_revisions  # Register amendment models before fixture schema creation.
from app.models import PatchExecution, Service
from app.artifact_catalog import (GlobalArtifact, ArtifactLocation, ArtifactPatchLineage,
    ArtifactRecommendation, register_artifact, assign_artifact, record_patch_lineage,
    recommend_artifact, artifact_eligibility)


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def artifact(db, char="a", **kwargs):
    kwargs.setdefault("platform", "linux/amd64")
    return register_artifact(db, digest="sha256:" + char * 64,
        media_type="application/vnd.oci.image.manifest.v1+json", **kwargs)


def setup_lineage(db):
    service = Service(service_key="one", name="One")
    db.add(service)
    db.flush()
    source, target = artifact(db), artifact(db, "b")
    patch = PatchExecution(job_key="patch", service_id=service.id, requested_by_id=1,
        source_mode="registry", output_mode="publish", status="complete",
        source_image="repo/source@" + source.digest, destination_image="repo/target@" + target.digest)
    db.add(patch)
    db.flush()
    line = record_patch_lineage(db, patch_execution_id=patch.id, source_artifact_id=source.id, output_artifact_id=target.id)
    return service, source, target, patch, line


def test_global_identity_separates_locations_and_platform(db):
    first = artifact(db, reference="registry/one:tag", provenance={"origin": "scan"})
    same = artifact(db, reference="registry/two:tag")
    other = artifact(db, platform="linux/arm64")
    assert first.id == same.id != other.id
    assert db.scalar(select(func.count()).select_from(ArtifactLocation)) == 2
    assert db.scalar(select(func.count()).select_from(GlobalArtifact)) == 2


@pytest.mark.parametrize("digest", ["latest", "sha256:abc", "repo@sha256:" + "a" * 64, "sha256:" + "z" * 64])
def test_rejects_mutable_and_invalid_identity(db, digest):
    with pytest.raises(ValueError):
        register_artifact(db, digest=digest, media_type="image")
    assert db.scalar(select(func.count()).select_from(GlobalArtifact)) == 0


def test_rejects_conflicting_location_before_mutating(db):
    with pytest.raises(ValueError):
        artifact(db, reference="repo@sha256:" + "b" * 64)
    assert db.scalar(select(func.count()).select_from(GlobalArtifact)) == 0


def test_transaction_is_owned_by_caller(db):
    artifact(db)
    db.rollback()
    assert db.scalar(select(func.count()).select_from(GlobalArtifact)) == 0


def test_lineage_is_idempotent_immutable_and_not_signature_evidence(db):
    service, source, target, patch, line = setup_lineage(db)
    assert record_patch_lineage(db, patch_execution_id=patch.id, source_artifact_id=source.id, output_artifact_id=target.id).id == line.id
    patch.summary = {"signature_status": "verified", "verification_status": "verified"}
    db.flush()
    assert artifact_eligibility(db, target.id)["eligible"] is False
    db.commit()
    line.evidence = {"signature_status": "verified"}
    with pytest.raises(ValueError, match="immutable"):
        db.flush()
    db.rollback()


def test_recommendations_deduplicate_per_service(db):
    service, source, target, patch, line = setup_lineage(db)
    assign_artifact(db, service_id=service.id, artifact_id=source.id)
    first = recommend_artifact(db, service_id=service.id, source_artifact_id=source.id, target_artifact_id=target.id)
    assert recommend_artifact(db, service_id=service.id, source_artifact_id=source.id, target_artifact_id=target.id).id == first.id
    second = Service(service_key="two", name="Two")
    db.add(second)
    db.flush()
    assign_artifact(db, service_id=second.id, artifact_id=source.id)
    recommend_artifact(db, service_id=second.id, source_artifact_id=source.id, target_artifact_id=target.id)
    assert db.scalar(select(func.count()).select_from(ArtifactRecommendation)) == 2
    assert first.status == "pending_verification"


def test_lineage_rejects_tag_only_patch(db):
    service, source, target, patch, line = setup_lineage(db)
    patch.source_image = "repo:latest"
    db.flush()
    with pytest.raises(ValueError, match="digest-bound"):
        record_patch_lineage(db, patch_execution_id=patch.id, source_artifact_id=source.id, output_artifact_id=target.id)

def test_verified_worker_receipt_is_digest_bound_and_revocable(db):
    service, source, target, patch, line = setup_lineage(db)
    receipt = {"status": "complete", "patch_status": "PATCHED", "delivery_status": "delivered",
        "source_image": patch.source_image, "immutable_destination": patch.destination_image,
        "signature_status": "verified", "signature": {"image": patch.destination_image,
        "generator": "cosign", "key_fingerprint": "trusted-key", "verified_at": "2026-10-21T12:00:00Z"},
        "artifact_validation": "docker-load", "validated_source": "flattened-rootfs",
        "vulnerabilities_before": 4, "vulnerabilities_after": 1}
    patch.summary = {"artifact_receipt": receipt}
    db.flush()
    assert artifact_eligibility(db, target.id)["eligible"] is False
    from app.models import DeploymentValidationRun
    db.add(DeploymentValidationRun(run_key="verified", service_id=service.id,
        artifact_reference=patch.destination_image, status="VERIFIED"))
    db.flush()
    assert artifact_eligibility(db, target.id)["eligible"] is True
    assert artifact_eligibility(db, target.id, service_id=service.id + 1)["eligible"] is False
    patch.summary = {"artifact_receipt": {**receipt, "signature": {**receipt["signature"], "image": "other@" + source.digest}}}
    db.flush()
    assert artifact_eligibility(db, target.id)["eligible"] is False
    patch.summary = {"artifact_receipt": receipt}
    patch.status = "failed"
    db.flush()
    assert artifact_eligibility(db, target.id)["eligible"] is False


def test_receipt_import_uses_execution_service(db):
    from app.artifact_catalog import register_patch_artifacts, ServiceArtifactAssignment
    service, source, target, patch, line = setup_lineage(db)
    patch.summary = {"artifact_receipt": {"source_image": patch.source_image,
        "immutable_destination": patch.destination_image}}
    db.flush()
    imported = register_patch_artifacts(db, patch_execution_id=patch.id, media_type=source.media_type, platform=source.platform)
    assert [row.id for row in imported] == [source.id, target.id]
    assert db.scalar(select(func.count()).select_from(ServiceArtifactAssignment)) == 2
    assert artifact_eligibility(db, target.id)["eligible"] is False

class ScopedAuth:
    csrf_token = "token"
    def __init__(self, service_ids, edit=False):
        self.ids, self.edit = set(service_ids), edit
    def accessible_service_ids(self, permission):
        return self.ids
    def has(self, permission, service_id):
        return service_id in self.ids and (permission == "service.view" or self.edit)


def test_catalog_route_hides_other_service_and_provenance(db):
    from app.artifact_catalog_routes import catalog
    one, two = Service(service_key="one", name="One"), Service(service_key="two", name="Secret")
    db.add_all([one, two]); db.flush()
    shared, secret = artifact(db), artifact(db, "b")
    assign_artifact(db, service_id=one.id, artifact_id=shared.id)
    assign_artifact(db, service_id=two.id, artifact_id=shared.id)
    assign_artifact(db, service_id=two.id, artifact_id=secret.id)
    response = catalog(db=db, auth=ScopedAuth([one.id]), search="", page=1)
    assert response["total"] == 1
    assert response["items"][0]["services"] == [{"service_key": "one", "name": "One"}]
    assert "Secret" not in str(response)
    assert catalog(db=db, auth=ScopedAuth([one.id]), search="%", page=1)["total"] == 0


def test_proposal_route_enforces_csrf_and_permissions_without_activation(db, monkeypatch):
    import asyncio
    from starlette.requests import Request
    from fastapi import HTTPException
    from app import artifact_catalog_routes as routes
    service, source, target, patch, line = setup_lineage(db)
    from app.models import ServiceImage
    db.add(ServiceImage(service_id=service.id, image_reference=patch.source_image, image_digest=source.digest))
    db.flush()
    assign_artifact(db, service_id=service.id, artifact_id=source.id)
    rec = recommend_artifact(db, service_id=service.id, source_artifact_id=source.id, target_artifact_id=target.id)
    request = Request({"type": "http", "headers": [(b"x-csrf-token", b"token")]})
    audit = []
    monkeypatch.setattr(routes, "record_audit", lambda *args, **kwargs: audit.append(kwargs))
    def call(auth, req=request):
        return asyncio.run(routes.propose_selection(service.service_key, rec.id, req, db=db, auth=auth))
    with pytest.raises(HTTPException) as error:
        call(ScopedAuth([service.id]))
    assert error.value.status_code == 403
    with pytest.raises(HTTPException) as error:
        call(ScopedAuth([service.id], True), Request({"type": "http", "headers": []}))
    assert error.value.status_code == 403
    result = call(ScopedAuth([service.id], True))
    assert result["status"] == "proposed" and result["active_release_changed"] is False
    assert len(audit) == 1
    call(ScopedAuth([service.id], True))
    assert len(audit) == 1


def test_verified_shared_patch_recommends_to_24_services_without_release_changes(db):
    from app.artifact_catalog import generate_shared_recommendations
    from app.models import DeploymentValidationRun, ServiceImage
    from app.release_revisions import ReleaseRevision, ServiceActiveRelease
    producer, source, target, patch, line = setup_lineage(db)
    services = [producer] + [Service(service_key=f'shared-{i}', name=f'Shared {i}') for i in range(24)]
    db.add_all(services); db.flush()
    for service in services:
        db.add(ServiceImage(service_id=service.id, image_reference="registry/shared:latest", image_digest=source.digest))
    db.flush()
    patch.summary = {'artifact_receipt': {'status': 'complete', 'patch_status': 'PATCHED',
        'delivery_status': 'delivered', 'source_image': patch.source_image,
        'immutable_destination': patch.destination_image, 'signature_status': 'verified',
        'signature': {'image': patch.destination_image, 'generator': 'cosign', 'key_fingerprint': 'trusted', 'verified_at': '2026-10-21T12:00:00Z'},
        'artifact_validation': 'docker-load', 'validated_source': 'flattened-rootfs',
        'vulnerabilities_before': 10, 'vulnerabilities_after': 2}}
    validation = DeploymentValidationRun(run_key='shared-validation', service_id=producer.id,
        artifact_reference=patch.destination_image, status='PARTIALLY_VERIFIED')
    db.add(validation); db.flush()
    assert generate_shared_recommendations(db, validation_run_id=validation.id) == []
    validation.status = 'VERIFIED'; db.flush()
    first = generate_shared_recommendations(db, validation_run_id=validation.id)
    assert len(first) == 24
    first[0].status = 'dismissed'; db.flush()
    assert {row.id for row in generate_shared_recommendations(db, validation_run_id=validation.id)} == {row.id for row in first}
    assert first[0].status == 'dismissed'
    assert {row.service_id for row in first} == {service.id for service in services[1:]}
    assert not artifact_eligibility(db, target.id, service_id=services[1].id)['eligible']
    assert db.scalar(select(func.count()).select_from(ArtifactRecommendation)) == 24
    assert db.scalar(select(func.count()).select_from(ReleaseRevision)) == 0
    assert db.scalar(select(func.count()).select_from(ServiceActiveRelease)) == 0
    retired = db.scalar(select(ServiceImage).where(ServiceImage.service_id == services[-1].id))
    retired.lifecycle_status = 'retired'; db.flush()
    assert len(generate_shared_recommendations(db, validation_run_id=validation.id)) == 23
    assert db.scalar(select(func.count()).select_from(ArtifactRecommendation)) == 24  # Preserve history.
    newer = DeploymentValidationRun(run_key='newer-failed', service_id=producer.id,
        artifact_reference=patch.destination_image, status='COULD_NOT_VALIDATE')
    db.add(newer); db.flush()
    assert generate_shared_recommendations(db, validation_run_id=validation.id) == []


def test_known_source_association_rejects_conflicts(db):
    from app.artifact_catalog import associate_known_source_images
    from app.models import ServiceImage
    service = Service(service_key='association', name='Association')
    db.add(service); db.flush()
    source = artifact(db)
    image = ServiceImage(service_id=service.id, image_reference='repo@sha256:' + 'b'*64, image_digest=source.digest)
    db.add(image); db.flush()
    assert associate_known_source_images(db, artifact_id=source.id) == []
    image.image_reference = 'repo:tag'; db.flush()
    assert len(associate_known_source_images(db, artifact_id=source.id)) == 1
    register_artifact(db, digest=source.digest, media_type=source.media_type, platform='linux/arm64')
    assert associate_known_source_images(db, artifact_id=source.id) == []



@pytest.mark.parametrize('model_name', ['GlobalArtifact', 'ArtifactLocation', 'ArtifactPatchLineage', 'ServiceArtifactAssignment', 'ArtifactRecommendation'])
def test_unique_race_savepoint_preserves_caller_transaction(db, monkeypatch, model_name):
    from app import artifact_catalog as catalog
    service, source, target, patch, lineage = setup_lineage(db)
    assignment = assign_artifact(db, service_id=service.id, artifact_id=source.id)
    recommendation = recommend_artifact(db, service_id=service.id, source_artifact_id=source.id, target_artifact_id=target.id)
    artifact(db, reference='repo:stable', provenance={'original': True})
    model = getattr(catalog, model_name)
    existing = db.scalar(select(model))
    keys = {
        'GlobalArtifact': ('digest', 'media_type', 'platform'),
        'ArtifactLocation': ('artifact_id', 'reference'),
        'ArtifactPatchLineage': ('patch_execution_id', 'source_artifact_id', 'output_artifact_id'),
        'ServiceArtifactAssignment': ('service_id', 'artifact_id', 'role'),
        'ArtifactRecommendation': ('service_id', 'source_artifact_id', 'target_artifact_id'),
    }[model_name]
    values = {key: getattr(existing, key) for key in keys}
    db.commit()
    service.name = 'Caller pending edit'
    original_scalar = db.scalar
    reads = 0
    def miss_then_read(statement, *args, **kwargs):
        nonlocal reads
        reads += 1
        if reads == 1:
            return None  # A concurrent winner appears between SELECT and INSERT.
        return original_scalar(statement, *args, **kwargs)
    monkeypatch.setattr(db, 'scalar', miss_then_read)
    assert catalog._get_or_add(db, model, **values).id == existing.id
    assert db.is_active
    assert service.name == 'Caller pending edit'
    db.rollback()
    assert service.name == 'One'


def test_nonduplicate_integrity_failure_does_not_poison_caller(db):
    from app.artifact_catalog import _get_or_add
    from sqlalchemy.exc import IntegrityError
    service = Service(service_key='preserved', name='Preserved')
    db.add(service); db.commit()
    service.name = 'Pending'
    with pytest.raises(IntegrityError):
        _get_or_add(db, GlobalArtifact, digest=None, media_type='oci', platform='linux/amd64')
    assert db.is_active and service.name == 'Pending'
    db.rollback()
    assert service.name == 'Preserved'


def test_recommendation_enqueue_is_atomic_deduplicated_and_verified_only(db):
    from app.artifact_catalog import enqueue_recommendation_reconciliation
    from app.models import DeploymentValidationRun
    from app.durable_jobs import DurableJob
    service = Service(service_key='queue', name='Queue')
    db.add(service); db.flush()
    run = DeploymentValidationRun(run_key='queue-run', service_id=service.id, status='PARTIALLY_VERIFIED')
    db.add(run); db.flush()
    assert enqueue_recommendation_reconciliation(db, validation_run_id=run.id) is None
    run.status = 'VERIFIED'; db.commit()
    job = enqueue_recommendation_reconciliation(db, validation_run_id=run.id)
    assert enqueue_recommendation_reconciliation(db, validation_run_id=run.id).id == job.id
    assert job.max_attempts == 5 and job.service_id == service.id
    db.rollback()
    assert db.scalar(select(func.count()).select_from(DurableJob)) == 0


def test_reconciliation_handler_replays_and_checks_service_binding(db, monkeypatch):
    from types import SimpleNamespace
    from app import artifact_catalog as catalog, database
    from app.models import DeploymentValidationRun
    from app.durable_jobs import JobError
    service = Service(service_key='worker', name='Worker')
    db.add(service); db.flush()
    run = DeploymentValidationRun(run_key='worker-validation', service_id=service.id, status='VERIFIED')
    db.add(run); db.commit()
    monkeypatch.setattr(database, 'SessionLocal', lambda: Session(db.get_bind()))
    calls = []
    monkeypatch.setattr(catalog, 'generate_shared_recommendations', lambda session, validation_run_id: calls.append(validation_run_id) or [])
    ctx = SimpleNamespace(check=lambda: None, job=SimpleNamespace(service_id=service.id))
    for _ in range(2):
        assert catalog.handle_recommendation_reconciliation(ctx, {'validation_run_id': run.id})['recommendation_count'] == 0
    assert calls == [run.id, run.id]
    ctx.job.service_id = service.id + 1
    with pytest.raises(JobError): catalog.handle_recommendation_reconciliation(ctx, {'validation_run_id': run.id})
    assert len(calls) == 2


def test_internal_reconciliation_outbox_survives_saturated_queue(db, monkeypatch):
    from app.artifact_catalog import enqueue_recommendation_reconciliation
    from app.models import DeploymentValidationRun
    from app.durable_jobs import DurableJob, submit
    from fastapi import HTTPException
    monkeypatch.setenv('CATS_JOB_QUEUE_CAPACITY', '1')
    service = Service(service_key='saturation', name='Saturation')
    db.add(service); db.flush()
    submit(db, kind='export', payload={}, commit=False)
    run = DeploymentValidationRun(run_key='saturation-validation', service_id=service.id, status='VERIFIED')
    db.add(run); db.flush()
    with pytest.raises(HTTPException) as error: submit(db, kind='export', payload={}, commit=False)
    assert error.value.status_code == 429
    job = enqueue_recommendation_reconciliation(db, validation_run_id=run.id)
    assert enqueue_recommendation_reconciliation(db, validation_run_id=run.id).id == job.id
    db.commit()
    assert db.get(DeploymentValidationRun, run.id).status == 'VERIFIED'
    assert db.get(DurableJob, job.id).status == 'queued'
    assert db.scalar(select(func.count()).select_from(DurableJob)) == 2


def test_current_source_inventory_rejects_retired_or_conflicting_image(db):
    from app.artifact_catalog import has_current_source_image
    from app.models import ServiceImage
    service, source, target, patch, lineage = setup_lineage(db)
    assign_artifact(db, service_id=service.id, artifact_id=source.id)
    assert not has_current_source_image(db, service_id=service.id, artifact_id=source.id)
    image = ServiceImage(service_id=service.id, image_reference='repo:tag', image_digest=source.digest)
    db.add(image); db.flush()
    assert has_current_source_image(db, service_id=service.id, artifact_id=source.id)
    image.lifecycle_status = 'retired'; db.flush()
    assert not has_current_source_image(db, service_id=service.id, artifact_id=source.id)
    image.lifecycle_status = 'active'; image.image_reference = 'repo@' + target.digest; db.flush()
    assert not has_current_source_image(db, service_id=service.id, artifact_id=source.id)


def test_retired_source_blocks_adoption_and_notification(db, monkeypatch):
    import asyncio
    from starlette.requests import Request
    from fastapi import HTTPException
    from app import artifact_catalog_routes as routes
    from app.models import ServiceImage
    service, source, target, patch, line = setup_lineage(db)
    image = ServiceImage(service_id=service.id, image_reference=patch.source_image, image_digest=source.digest)
    db.add(image); db.flush()
    assign_artifact(db, service_id=service.id, artifact_id=source.id)
    rec = recommend_artifact(db, service_id=service.id, source_artifact_id=source.id, target_artifact_id=target.id)
    auth = ScopedAuth([service.id], True)
    monkeypatch.setattr(routes, 'artifact_eligibility', lambda *args, **kwargs: {'eligible': True, 'reasons': []})
    assert len(routes.replacement_notifications(db, auth)) == 1
    assert routes.recommendations(service.service_key, db, auth)['items'][0]['can_adopt']
    image.lifecycle_status = 'retired'; db.commit()
    assert routes.replacement_notifications(db, auth) == []
    assert not routes.recommendations(service.service_key, db, auth)['items'][0]['can_adopt']
    request = Request({'type': 'http', 'headers': [(b'x-csrf-token', b'token')]})
    with pytest.raises(HTTPException) as error:
        asyncio.run(routes.propose_selection(service.service_key, rec.id, request, db=db, auth=auth))
    assert error.value.status_code == 409
    assert rec.status == 'pending_verification'
