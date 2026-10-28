import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Service, ServiceImage, PatchExecution, AuditEvent
from app.artifact_catalog import GlobalArtifact, ArtifactPatchLineage
from app import durable_jobs, main, patch_campaigns

@pytest.mark.parametrize('mode', ['valid', 'missing', 'invalid'])
@pytest.mark.parametrize('campaign_cancel_requested', [None, False, True])
def test_completed_worker_catalog_import_preserves_execution(monkeypatch, tmp_path, mode, campaign_cancel_requested):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, 'SessionLocal', lambda: Session(engine))
    monkeypatch.setattr(main, 'PATCH_JOB_ROOT', tmp_path)
    monkeypatch.setattr(main, 'PATCH_JOBS', {})
    with Session(engine) as db:
        service = Service(service_key='receipt', name='Receipt')
        db.add(service); db.flush()
        patch = PatchExecution(job_key='receipt-job', service_id=service.id, requested_by_id=1, source_mode='oci', output_mode='push', source_image='repo/source:tag')
        db.add(patch); db.flush(); patch_id = patch.id
        if campaign_cancel_requested is not None:
            original = ServiceImage(service_id=service.id, image_reference='repo/source:tag',
                image_digest='sha256:' + 'a'*64)
            campaign = patch_campaigns.PatchCampaign(service_id=service.id, requested_by_id=1,
                destination_registry_id='destination', destination_prefix='')
            job = durable_jobs.DurableJob(id='campaign-job', kind=patch_campaigns.KIND,
                service_id=service.id, requested_by_id=1, status='running',
                cancel_requested=campaign_cancel_requested)
            db.add_all([original, campaign, job]); db.flush()
            db.add(patch_campaigns.PatchCampaignItem(campaign_id=campaign.id, image_id=original.id,
                image_reference='repo/source@sha256:' + 'a'*64, job_id=job.id, patch_execution_id=patch.id))
            original_id = original.id
        db.commit()
    receipt = {'status': 'complete', 'source_image': 'repo/source@sha256:' + 'a'*64,
        'immutable_destination': 'repo/output@sha256:' + 'b'*64, 'patch_status': 'PATCHED',
        'delivery_status': 'delivered', 'output_mode': 'push',
        'media_type': 'application/vnd.oci.image.manifest.v1+json', 'platform': 'linux/amd64',
        'source_media_type': 'application/vnd.docker.distribution.manifest.v2+json', 'source_platform': 'linux/amd64',
        'untrusted_extra': 'not-retained'}
    if mode == 'missing': receipt.pop('source_platform')
    if mode == 'invalid': receipt['immutable_destination'] = 'repo/output@bad'
    main.PATCH_JOBS['receipt-job'] = {'patch_execution_id': patch_id, 'output_mode': 'push'}
    for _ in range(2):
        main._patch_job_update('receipt-job', status='complete', phase='completed', result=receipt)
    with Session(engine) as db:
        retained = db.get(PatchExecution, patch_id)
        assert retained.status == 'complete'
        assert retained.completed_at
        assert 'untrusted_extra' not in retained.summary['artifact_receipt']
        assert db.scalar(select(func.count()).select_from(GlobalArtifact)) == (2 if mode == 'valid' else 0)
        assert db.scalar(select(func.count()).select_from(ArtifactPatchLineage)) == (1 if mode == 'valid' else 0)
        assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == 'artifact.catalog.import_skipped')) == (0 if mode == 'valid' else 1)
        if campaign_cancel_requested is not None:
            # Even a repeated successful worker callback retains only evidence.
            # Inventory mutation belongs to the durable completion transaction.
            assert db.scalar(select(func.count()).select_from(ServiceImage)) == 1
            assert db.get(ServiceImage, original_id).lifecycle_status == 'active'
            job = db.get(durable_jobs.DurableJob, 'campaign-job')
            assert job.status == 'running' and job.cancel_requested is campaign_cancel_requested
            assert job.result.get('inventory_updated') is not True
    engine.dispose()


def test_reconciliation_dispatch_uses_registered_handler(monkeypatch):
    from types import SimpleNamespace
    from app import artifact_catalog, remediation_worker
    calls = []
    monkeypatch.setattr(artifact_catalog, 'handle_recommendation_reconciliation', lambda ctx, payload: calls.append(payload) or {'ok': True})
    ctx = SimpleNamespace(job=SimpleNamespace(kind='artifact_recommendations'))
    assert remediation_worker.handle(ctx, {'validation_run_id': 42}) == {'ok': True}
    assert calls == [{'validation_run_id': 42}]
