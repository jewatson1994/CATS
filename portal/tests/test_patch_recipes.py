from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from app import durable_jobs
from app.database import Base
from app.patch_recipes import PatchRecipeClaim, recipe_fingerprint, claim_recipe, reusable_patch


def inputs():
    return dict(source=SimpleNamespace(digest='sha256:' + 'a'*64,
        media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64'),
        config={'job_id': 'one', 'source_image': 'one@sha256:' + 'a'*64,
            'destination_image': 'output:one', 'repository_policies': {'a': 1, 'b': 2},
            'signing_fingerprint': 'key-one'},
        identity={'schema': 'cats-patch-inputs-v1', 'engine_digest': 'sha256:' + 'b'*64,
            'repository_snapshot_digest': 'sha256:' + 'c'*64,
            'scanner_database_digest': 'sha256:' + 'd'*64},
        destination_scope={'host': 'registry', 'namespace': 'team'})


def test_equivalent_recipes_ignore_locations_and_attempt_ids():
    args = inputs()
    expected = recipe_fingerprint(**args)
    assert len(expected) == 64
    args['config'].update(job_id='two', source_image='mirror@sha256:' + 'a'*64,
                          destination_image='output:two', repository_policies={'b': 2, 'a': 1})
    assert recipe_fingerprint(**args) == expected


@pytest.mark.parametrize('field', ['engine_digest', 'repository_snapshot_digest', 'scanner_database_digest'])
def test_each_immutable_input_changes_identity_and_is_required(field):
    args = inputs()
    original = recipe_fingerprint(**args)
    args['identity'][field] = 'sha256:' + 'e'*64
    assert recipe_fingerprint(**args) != original
    del args['identity'][field]
    assert recipe_fingerprint(**args) is None


@pytest.mark.parametrize('part', ['source', 'policy', 'signing', 'destination'])
def test_equivalence_includes_source_policy_signer_and_destination(part):
    args = inputs()
    original = recipe_fingerprint(**args)
    if part == 'source': args['source'].platform = 'linux/arm64'
    elif part == 'policy': args['config']['repository_policies'] = {'a': 2}
    elif part == 'signing': args['config']['signing_fingerprint'] = 'key-two'
    else: args['destination_scope']['namespace'] = 'another'
    assert recipe_fingerprint(**args) != original


def test_unknown_engine_or_source_disables_reuse():
    args = inputs()
    args['identity'] = None
    assert recipe_fingerprint(**args) is None
    args = inputs()
    args['source'].platform = 'unknown'
    assert recipe_fingerprint(**args) is None
    args['source'] = None
    assert recipe_fingerprint(**args) is None


def test_concurrent_claim_has_one_owner_and_cannot_be_taken_over(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'claims.db'),
                           connect_args={'timeout': 20})
    Base.metadata.create_all(engine)
    def claim(job):
        with Session(engine) as db:
            row = claim_recipe(db, 'a'*64, job)
            owner = row.owner_job_id
            db.commit()
            return owner
    with ThreadPoolExecutor(max_workers=2) as pool:
        owners = list(pool.map(claim, ['one', 'two']))
    assert owners[0] == owners[1]
    assert claim('later') == owners[0]
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(PatchRecipeClaim)) == 1
        assert reusable_patch(db, db.get(PatchRecipeClaim, 'a'*64), inputs()['source']) is None
    engine.dispose()


def test_claim_rolls_back_with_undispatched_caller(tmp_path):
    engine = create_engine('sqlite:///' + str(tmp_path / 'rollback.db'))
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        claim_recipe(db, 'b'*64, 'one')
        db.rollback()
        assert db.get(PatchRecipeClaim, 'b'*64) is None
    engine.dispose()


def test_reuse_requires_exact_lineage_and_verified_retained_receipt():
    from app.models import PatchExecution
    from app.artifact_catalog import register_artifact, record_patch_lineage
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        source = register_artifact(db, digest='sha256:' + 'a'*64,
            media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
        output = register_artifact(db, digest='sha256:' + 'b'*64,
            media_type=source.media_type, platform=source.platform)
        reference = 'registry/output@' + output.digest
        receipt = {'status': 'complete', 'patch_status': 'PATCHED',
            'delivery_status': 'delivered', 'source_image': 'registry/source@' + source.digest,
            'immutable_destination': reference, 'signature_status': 'verified',
            'signature': {'image': reference, 'generator': 'cosign', 'key_fingerprint': 'key',
                          'verified_at': '2026-10-21T00:00:00Z'},
            'artifact_validation': 'docker-load', 'validated_source': 'flattened-rootfs',
            'vulnerabilities_before': 5, 'vulnerabilities_after': 1}
        patch = PatchExecution(job_key='recipe', service_id=1, requested_by_id=1,
            source_mode='oci', output_mode='push', status='complete',
            source_image=receipt['source_image'], destination_image=reference,
            summary={'artifact_receipt': receipt})
        db.add(patch); db.flush()
        record_patch_lineage(db, patch_execution_id=patch.id, source_artifact_id=source.id,
                             output_artifact_id=output.id)
        args = inputs()
        args['source'] = source
        args['config'].update(job_id=patch.job_key, source_image=patch.source_image,
                              signing_fingerprint='key')
        receipt['consumed_inputs'] = {
            'schema': 'cats-patch-consumed-inputs-v1', 'job_id': patch.job_key,
            'source_image': patch.source_image, 'immutable_destination': reference,
            'identity': args['identity'], 'config': args['config'],
            'destination_scope': args['destination_scope']}
        patch.summary = {'artifact_receipt': dict(receipt)}
        claim = claim_recipe(db, recipe_fingerprint(**args), 'owner')
        claim.patch_execution_id = patch.id
        assert reusable_patch(db, claim, source, signing_fingerprint="key") is patch
        assert reusable_patch(db, claim, source, destination_scope={"host": "registry"}) is patch
        assert reusable_patch(db, claim, source, destination_scope={"host": "other-registry"}) is None
        assert reusable_patch(db, claim, source, destination_scope={"host": "reg"}) is None
        assert reusable_patch(db, claim, source, destination_scope={"host": "registry", "prefix": "another"}) is None
        assert reusable_patch(db, claim, source, signing_fingerprint="different") is None
        from copy import deepcopy
        valid_consumed = deepcopy(receipt['consumed_inputs'])
        invalid = [None, {}, {**valid_consumed, 'job_id': 'another-attempt'},
            {**valid_consumed, 'schema': 'unknown'},
            {**valid_consumed, 'source_image': 'wrong@' + source.digest},
            {**valid_consumed, 'immutable_destination': 'wrong@' + output.digest},
            {**valid_consumed, 'identity': None},
            {**valid_consumed, 'extra_input': 'unbound'},
            {**valid_consumed, 'config': {**valid_consumed['config'], 'job_id': 'wrong'}},
            {**valid_consumed, 'config': {**valid_consumed['config'], 'signing_fingerprint': 'wrong'}},
            {**valid_consumed, 'destination_scope': {'host': 'wrong'}}]
        for field in ('engine_digest', 'repository_snapshot_digest', 'scanner_database_digest'):
            invalid.append({**valid_consumed, 'identity': {
                **valid_consumed['identity'], field: 'sha256:' + 'f' * 64}})
        for consumed in invalid:
            patch.summary = {'artifact_receipt': {**receipt, 'consumed_inputs': consumed}}
            assert reusable_patch(db, claim, source) is None
        patch.summary = {'artifact_receipt': {key: value for key, value in receipt.items()
                                             if key != 'consumed_inputs'}}
        assert reusable_patch(db, claim, source) is None
        patch.summary = {'artifact_receipt': dict(receipt)}
        assert reusable_patch(db, claim, source) is patch
        receipt['signature_status'] = 'failed'
        patch.summary = {'artifact_receipt': dict(receipt)}
        assert reusable_patch(db, claim, source) is None
        receipt['signature_status'] = 'verified'
        receipt['source_image'] = 'registry/source@sha256:' + 'c'*64
        patch.summary = {'artifact_receipt': dict(receipt)}
        assert reusable_patch(db, claim, source) is None
    engine.dispose()


def test_unsigned_recipe_does_not_reserve_unreusable_claim():
    args = inputs()
    del args['config']['signing_fingerprint']
    assert recipe_fingerprint(**args) is None


@pytest.mark.parametrize("outcome", ["complete", "cancel", "expired", "timeout"])
def test_waiter_tracks_original_publisher_without_taking_over(monkeypatch, outcome):
    from datetime import timedelta
    from app import patch_recipes as recipes
    from app.models import PatchExecution
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        owner = durable_jobs.submit(db, kind='patch_campaign_item', payload={},
            service_id=1, requested_by_id=1, commit=False)
        owner.status = 'running'
        owner.lease_until = durable_jobs.now() + timedelta(seconds=120)
        patch = PatchExecution(job_key='waiting', service_id=1, requested_by_id=1,
            source_mode='oci', output_mode='push', status='running')
        db.add(patch); db.flush()
        claim = claim_recipe(db, 'f'*64, owner.id)
        claim.patch_execution_id = patch.id
        owner_id, patch_id = owner.id, patch.id
        if outcome == 'expired':
            owner.lease_until = durable_jobs.now() - timedelta(seconds=1)
        db.commit()
    sleeps = []
    def finish(_seconds):
        sleeps.append(_seconds)
        with Session(engine) as db:
            db.get(PatchExecution, patch_id).status = 'complete'
            db.commit()
    def check():
        if outcome == 'cancel':
            raise durable_jobs.JobCancelled()
    monkeypatch.setattr(recipes.time, 'sleep', finish)
    ctx = SimpleNamespace(check=check, stage=lambda *args: None)
    if outcome == 'complete':
        recipes.wait_for_recipe(lambda: Session(engine), 'f'*64, ctx)
        assert len(sleeps) == 1
    elif outcome == 'cancel':
        with pytest.raises(durable_jobs.JobCancelled):
            recipes.wait_for_recipe(lambda: Session(engine), 'f'*64, ctx)
    else:
        with pytest.raises(durable_jobs.JobError):
            recipes.wait_for_recipe(lambda: Session(engine), 'f'*64, ctx,
                                    timeout=0 if outcome == 'timeout' else 300)
    with Session(engine) as db:
        assert db.get(PatchRecipeClaim, 'f'*64).owner_job_id == owner_id
        assert db.get(durable_jobs.DurableJob, owner_id).status == 'running'
    engine.dispose()


@pytest.mark.parametrize('failure', ['failed', 'cancelled', 'missing', 'no_lease', 'cancel_requested'])
def test_restart_preserves_uncertain_claim_and_refuses_republication(tmp_path, monkeypatch, failure):
    from datetime import timedelta
    from app import patch_recipes as recipes
    from app.models import PatchExecution

    url = 'sqlite:///' + str(tmp_path / 'restart.db')
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        owner = durable_jobs.submit(db, kind='patch_campaign_item', payload={},
            service_id=1, requested_by_id=1, commit=False)
        owner.status = 'running'
        owner.lease_until = durable_jobs.now() + timedelta(seconds=120)
        patch = PatchExecution(job_key='interrupted-publication', service_id=1,
            requested_by_id=1, source_mode='oci', output_mode='push', status='running')
        db.add(patch)
        db.flush()
        claim = claim_recipe(db, 'e'*64, owner.id)
        claim.patch_execution_id = patch.id
        owner_id, patch_id = owner.id, patch.id
        if failure in {'failed', 'cancelled'}:
            owner.status = failure
        elif failure == 'no_lease':
            owner.lease_until = None
        elif failure == 'cancel_requested':
            owner.cancel_requested = True
        elif failure == 'missing':
            db.delete(owner)
        db.commit()
    engine.dispose()

    # Reopening the file-backed database simulates losing every in-memory job
    # and session after a registry operation with an uncertain outcome.
    engine = create_engine(url)
    monkeypatch.setattr(recipes.time, 'sleep', lambda _: pytest.fail('inactive owner must not be polled'))
    ctx = SimpleNamespace(check=lambda: None, stage=lambda *args: None)
    with pytest.raises(durable_jobs.JobError, match='no active publisher'):
        recipes.wait_for_recipe(lambda: Session(engine), 'e'*64, ctx)
    with Session(engine) as db:
        claim = claim_recipe(db, 'e'*64, 'replacement-job')
        assert claim.owner_job_id == owner_id
        assert claim.patch_execution_id == patch_id
        from app.artifact_catalog import register_artifact
        source = register_artifact(db, digest='sha256:' + 'a'*64,
            media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
        assert reusable_patch(db, claim, source) is None
        assert db.scalar(select(func.count()).select_from(PatchRecipeClaim)) == 1
        assert db.get(PatchExecution, patch_id).status == 'running'
    engine.dispose()


@pytest.mark.parametrize("reference", [None, 42, "mutable:latest", "other@sha256:" + "f"*64])
def test_recipe_requires_execution_source_matches_identity(reference):
    args = inputs()
    args["config"]["source_image"] = reference
    assert recipe_fingerprint(**args) is None


@pytest.mark.parametrize("field", ["package_versions", "mirror_digest", "runtime_digest"])
def test_unknown_manifest_inputs_disable_reuse(field):
    args = inputs()
    args["identity"][field] = "sha256:" + "f" * 64
    assert recipe_fingerprint(**args) is None


def test_opaque_execution_handles_do_not_change_canonical_recipe():
    args = inputs()
    expected = recipe_fingerprint(**args)
    args['config']['execution_binding'] = 'a' * 32
    assert recipe_fingerprint(**args) == expected
    args['config']['execution_binding'] = 'b' * 32
    assert recipe_fingerprint(**args) == expected
