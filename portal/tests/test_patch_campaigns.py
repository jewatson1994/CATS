import pytest
from types import SimpleNamespace
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.database import Base
from app.models import Service, ServiceImage
from app import patch_campaigns as c

@pytest.fixture
def setup(monkeypatch):
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    monkeypatch.setattr(c, 'record_audit', lambda *a, **k: None)
    with Session(engine) as db:
        service = Service(service_key='one', name='One')
        db.add(service); db.flush()
        image = ServiceImage(service_id=service.id, image_reference='registry:5000/team/app:latest', image_digest='sha256:' + 'a'*64)
        db.add(image); db.commit()
        auth = SimpleNamespace(user=SimpleNamespace(id=1), has=lambda permission, service_id: service_id == service.id)
        yield db, service, image, auth
    engine.dispose()

def submit(setup, **changes):
    db, service, image, auth = setup
    data = dict(image_ids=[image.id], destination_registry_id='destination', destination_prefix='patched')
    data.update(changes)
    return c.submit_campaign(db, auth, service, data, {'destination': {'password': 'never-retain'}})

def test_submission_pins_source_and_is_atomic(setup):
    db, _, image, _ = setup
    campaign = submit(setup)
    item = db.scalar(select(c.PatchCampaignItem))
    job = db.get(c.durable_jobs.DurableJob, item.job_id)
    assert item.image_reference == 'registry:5000/team/app@' + image.image_digest
    assert job.max_attempts == 1
    assert job.payload == {'campaign_id': campaign.id, 'image_id': image.id}
    db.rollback()
    assert db.scalar(select(func.count()).select_from(c.PatchCampaign)) == 0
    assert db.scalar(select(func.count()).select_from(c.durable_jobs.DurableJob)) == 0

@pytest.mark.parametrize('change', [{'image_ids': []}, {'image_ids': [1, 1]}, {'image_ids': list(range(21))}, {'destination_registry_id': 'unknown'}, {'destination_prefix': '../escape'}, {'image_ids': [999]}])
def test_rejects_invalid_campaign_without_work(setup, change):
    with pytest.raises(HTTPException) as failure: submit(setup, **change)
    assert failure.value.status_code == 422
    assert setup[0].scalar(select(func.count()).select_from(c.PatchCampaign)) == 0

def test_missing_digest_and_permissions(setup):
    setup[2].image_digest = None
    with pytest.raises(HTTPException): submit(setup)
    setup[3].has = lambda *a: False
    with pytest.raises(HTTPException) as failure: submit(setup)
    assert failure.value.status_code == 403

def test_detail_scope_and_partial_results(setup):
    db, service, image, auth = setup
    second = ServiceImage(service_id=service.id, image_reference='repo/two', image_digest='sha256:' + 'c'*64)
    db.add(second); db.flush()
    campaign = submit(setup, image_ids=[image.id, second.id])
    with pytest.raises(HTTPException) as failure: c.detail(campaign.id, db, SimpleNamespace(has=lambda *a: False))
    assert failure.value.status_code == 404
    jobs = list(db.scalars(select(c.durable_jobs.DurableJob)))
    jobs[0].status = 'completed'; jobs[0].result = {'patch_status': 'PATCHED', 'secret': 'hidden'}
    jobs[1].status = 'failed'; jobs[1].error = 'Retained failure'
    db.flush()
    result = c.campaign_data(db, campaign)
    assert result['status'] == 'partial'
    assert result['items'][0]['result']['patch_status'] == 'PATCHED'
    assert 'secret' not in result['items'][0]['result']
    assert result['items'][1]['error'] == 'Retained failure'


def test_worker_metadata_requires_exact_single_manifest():
    import json
    from app.patch_worker import retained_manifest_metadata
    reference = 'registry/repo@sha256:' + 'a'*64
    descriptor = {'digest': 'sha256:' + 'a'*64, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'platform': {'os': 'linux', 'architecture': 'arm64', 'variant': 'v8'}}
    def run(command):
        assert command == ['docker', 'manifest', 'inspect', '--verbose', reference]
        return SimpleNamespace(stdout=json.dumps({'Descriptor': descriptor}))
    assert retained_manifest_metadata(run, reference) == {'media_type': descriptor['mediaType'], 'platform': 'linux/arm64/v8'}
    descriptor['digest'] = 'sha256:' + 'b'*64
    assert retained_manifest_metadata(run, reference) == {}
    assert retained_manifest_metadata(run, 'registry/repo:latest') == {}
    assert retained_manifest_metadata(lambda command: SimpleNamespace(stdout='[]'), reference) == {}
    descriptor['digest'] = 'sha256:' + 'a'*64
    descriptor['platform'] = {}
    assert retained_manifest_metadata(run, reference) == {}


def test_handler_reuses_engine_and_never_replays_dispatch(setup, monkeypatch, tmp_path):
    import app
    import threading
    from datetime import datetime, timezone
    from app.models import User
    db, service, image, auth = setup
    user = User(id=1, username='worker-owner', display_name='Owner')
    db.add(user)
    campaign = submit(setup)
    item = db.scalar(select(c.PatchCampaignItem))
    job = db.get(c.durable_jobs.DurableJob, item.job_id)
    db.commit()
    calls = []
    fake = SimpleNamespace(SessionLocal=lambda: Session(db.get_bind()), PATCH_JOB_ROOT=tmp_path,
        PATCH_JOB_LOCK=threading.Lock(), PATCH_JOBS={}, _validate_image_reference=lambda ref: None,
        _portal_signing_material=lambda *a: ({}, {}), configuration_for_service=lambda *a: {},
        parse_json=lambda value, default: default, decrypt_secret=lambda value: 'decrypted',
        _configured_registry_for_image=lambda *a: None, safe_job_config=lambda value: value,
        initial_patch_stages=lambda mode: {}, utcnow=lambda: datetime.now(timezone.utc),
        _audit_signing_request=lambda *a: None,
        _run_patch_job=lambda key, env: calls.append((key, dict(env))),
        _load_patch_job=lambda key: {'status': 'complete', 'result': {'delivery_status': 'delivered', 'patch_status': 'PATCHED', 'signature_status': 'verified'}})
    monkeypatch.setattr(app, 'main', fake, raising=False)
    monkeypatch.setattr(c, 'AuthContext', lambda *a: auth)
    monkeypatch.setattr(c, '_registries', lambda db: {'destination': {'endpoint': 'https://registry.example', 'username': 'robot', 'password': 'encrypted'}})
    ctx = SimpleNamespace(job=job, check=lambda: None, stage=lambda *a: None)
    result = c.handle(ctx, job.payload)
    assert result['patch_status'] == 'PATCHED'
    assert len(calls) == 1
    assert calls[0][1]['CATS_PATCH_DEST_PASSWORD'] == 'decrypted'
    configuration = next(tmp_path.glob('*/job-config.json')).read_text()
    assert 'decrypted' not in configuration and 'encrypted' not in configuration
    with pytest.raises(c.durable_jobs.JobError, match='already dispatched'):
        c.handle(ctx, job.payload)
    assert len(calls) == 1


def test_controls_bound_retry_and_forbid_republication(setup, monkeypatch):
    db, service, image, auth = setup
    monkeypatch.setattr(c, '_csrf', lambda *args: None)
    campaign = submit(setup)
    item = db.scalar(select(c.PatchCampaignItem))
    original = item.job_id
    for attempt in range(3):
        result = c.item_action(campaign.id, item.id, 'cancel', None, db, auth)
        assert result['items'][0]['status'] == 'cancelled'
        if attempt < 2:
            result = c.item_action(campaign.id, item.id, 'retry', None, db, auth)
            assert result['items'][0]['status'] == 'queued'
    with pytest.raises(HTTPException) as error:
        c.item_action(campaign.id, item.id, 'retry', None, db, auth)
    assert error.value.status_code == 409
    assert db.get(c.durable_jobs.DurableJob, original).status == 'cancelled'
    assert db.scalar(select(func.count()).select_from(c.durable_jobs.DurableJob)) == 3
    item.patch_execution_id = 999
    job = db.get(c.durable_jobs.DurableJob, item.job_id)
    job.payload = {}; job.status = 'failed'
    assert not c.item_controls(item, job, True)['can_retry']


def test_controls_require_csrf_owner_scope_and_running_cancel_is_request(setup, monkeypatch):
    db, service, image, auth = setup
    campaign = submit(setup)
    item = db.scalar(select(c.PatchCampaignItem))
    job = db.get(c.durable_jobs.DurableJob, item.job_id)
    def reject(*args): raise HTTPException(403, 'CSRF')
    monkeypatch.setattr(c, '_csrf', reject)
    with pytest.raises(HTTPException): c.item_action(campaign.id, item.id, 'cancel', None, db, auth)
    assert job.status == 'queued'
    monkeypatch.setattr(c, '_csrf', lambda *args: None)
    outsider = SimpleNamespace(user=SimpleNamespace(id=2), has=auth.has)
    with pytest.raises(HTTPException) as error: c.item_action(campaign.id, item.id, 'cancel', None, db, outsider)
    assert error.value.status_code == 403
    denied = SimpleNamespace(user=auth.user, has=lambda *args: False)
    with pytest.raises(HTTPException) as error: c.item_action(campaign.id, item.id, 'cancel', None, db, denied)
    assert error.value.status_code == 404
    job.status = 'running'
    result = c.item_action(campaign.id, item.id, 'cancel', None, db, auth)
    assert result['items'][0]['status'] == 'running'
    assert result['items'][0]['cancel_requested']
    assert not result['items'][0]['can_retry']


@pytest.mark.parametrize("prior_state", ["verified", "running", "running_complete", "different_signer"])
def test_handler_reuses_verified_recipe_without_second_engine_run(setup, monkeypatch, tmp_path, prior_state):
    import app
    import threading
    from datetime import datetime, timezone
    from app.models import User, PatchExecution
    from app.artifact_catalog import register_artifact, record_patch_lineage
    from app.patch_recipes import PatchRecipeClaim
    db, service, image, auth = setup
    db.add(User(id=1, username='reuse-owner', display_name='Owner'))
    campaign = submit(setup)
    item = db.scalar(select(c.PatchCampaignItem))
    job = db.get(c.durable_jobs.DurableJob, item.job_id)
    source = register_artifact(db, digest=image.image_digest,
        media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
    output = register_artifact(db, digest='sha256:' + 'b'*64,
        media_type=source.media_type, platform=source.platform)
    reference = 'registry.example/patched/image-99@' + output.digest
    receipt = {'status': 'complete', 'patch_status': 'PATCHED', 'delivery_status': 'delivered',
        'source_image': item.image_reference, 'immutable_destination': reference,
        'signature_status': 'verified', 'signature': {'image': reference, 'generator': 'cosign',
            'key_fingerprint': 'current-key', 'verified_at': '2026-10-21T00:00:00Z'},
        'artifact_validation': 'docker-load', 'validated_source': 'flattened-rootfs',
        'vulnerabilities_before': 5, 'vulnerabilities_after': 1}
    patch = PatchExecution(job_key='prior', service_id=service.id, requested_by_id=1,
        source_mode='oci', output_mode='push', status='complete', source_image=item.image_reference,
        destination_image=reference, summary={'artifact_receipt': receipt})
    db.add(patch); db.flush()
    record_patch_lineage(db, patch_execution_id=patch.id, source_artifact_id=source.id,
                        output_artifact_id=output.id)
    prior_job = c.durable_jobs.submit(db, kind=c.KIND, payload={}, service_id=service.id,
                                     requested_by_id=1, commit=False)
    config = {'job_id': 'ignored', 'source_mode': 'oci', 'source_image': item.image_reference,
        'output_mode': 'push', 'destination_image': 'ignored', 'reuse_source_credentials': False,
        'remediation_evidence': True, 'signing_fingerprint': 'current-key',
        'destination_scope': {'registry': 'destination', 'host': 'registry.example', 'namespace': '', 'prefix': 'patched'},
        'trusted_ca_certificates': [], 'repository_policies': {}, 'os_definitions': {}}
    identity = {'schema': 'cats-patch-inputs-v1', 'engine_digest': 'sha256:' + 'c'*64,
        'repository_snapshot_digest': 'sha256:' + 'd'*64, 'scanner_database_digest': 'sha256:' + 'e'*64}
    receipt = dict(receipt)
    consumed_config = {**config, 'job_id': patch.job_key}
    receipt['consumed_inputs'] = {
        'schema': 'cats-patch-consumed-inputs-v1', 'job_id': patch.job_key,
        'source_image': patch.source_image, 'immutable_destination': reference,
        'identity': identity, 'config': consumed_config,
        'destination_scope': {'registry': 'destination', 'host': 'registry.example',
                              'namespace': '', 'prefix': 'patched'}}
    patch.summary = {'artifact_receipt': dict(receipt)}
    fingerprint = c.recipe_fingerprint(source=source, config=config, identity=identity,
        destination_scope={'registry': 'destination', 'host': 'registry.example', 'namespace': '', 'prefix': 'patched'})
    db.add(PatchRecipeClaim(fingerprint=fingerprint, owner_job_id=prior_job.id, patch_execution_id=patch.id))
    if prior_state in ("running", "running_complete"):
        patch.status = "running"
        if prior_state == "running_complete":
            from datetime import timedelta
            from app import patch_recipes
            prior_job.status = "running"
            prior_job.lease_until = c.durable_jobs.now() + timedelta(seconds=120)
            def complete_original(_seconds):
                with Session(db.get_bind()) as publisher:
                    publisher.get(PatchExecution, patch.id).status = "complete"
                    publisher.commit()
            monkeypatch.setattr(patch_recipes.time, "sleep", complete_original)
    elif prior_state == "different_signer":
        patch.summary = {"artifact_receipt": {**receipt, "signature": {**receipt["signature"], "key_fingerprint": "another-key"}}}
    db.commit()
    calls = []
    fake = SimpleNamespace(SessionLocal=lambda: Session(db.get_bind()), PATCH_JOB_ROOT=tmp_path,
        PATCH_JOB_LOCK=threading.Lock(), PATCH_JOBS={}, _validate_image_reference=lambda ref: None,
        _portal_signing_material=lambda *a: ({'signing_fingerprint': 'current-key'}, {}),
        configuration_for_service=lambda *a: {}, parse_json=lambda value, default: default,
        patch_recipe_identity=lambda config: identity,
        _run_patch_job=lambda *args: calls.append(args))
    monkeypatch.setattr(app, 'main', fake, raising=False)
    monkeypatch.setattr(c, 'AuthContext', lambda *a: auth)
    monkeypatch.setattr(c, '_registries', lambda db: {'destination': {'endpoint': 'https://registry.example'}})
    ctx = SimpleNamespace(job=job, check=lambda: None, stage=lambda *a: None)
    if prior_state not in ("verified", "running_complete"):
        with pytest.raises(c.durable_jobs.JobError, match="Equivalent patch"):
            c.handle(ctx, job.payload)
        assert calls == []
        db.expire_all()
        assert db.get(c.PatchCampaignItem, item.id).patch_execution_id is None
        return
    result = c.handle(ctx, job.payload)
    assert result['reused'] is True
    assert result['immutable_destination'] == reference
    assert calls == []
    assert list(tmp_path.iterdir()) == []
    db.expire_all()
    assert db.get(c.PatchCampaignItem, item.id).patch_execution_id == patch.id
    assert c.campaign_data(db, campaign)['items'][0]['job_id'] == 'prior'
