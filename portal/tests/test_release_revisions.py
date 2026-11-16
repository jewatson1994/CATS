from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import main, artifact_catalog, release_revisions as revisions
from app.database import Base


@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def retained(db):
    row = revisions.ReleaseRevision(approval_id=123, service_id=456,
        manifest={'purpose': revisions.PURPOSE}, manifest_digest='sha256:' + 'a' * 64)
    db.add(row)
    db.flush()
    state = revisions.ReleaseRevisionState(revision_id=row.id)
    db.add(state)
    db.commit()
    return row, state


def test_canonical_manifest_is_stable_and_rejects_nan():
    assert revisions.canonical({'b': 2, 'a': 1}) == b'{"a":1,"b":2}'
    with pytest.raises(ValueError):
        revisions.canonical({'a': float('nan')})


@pytest.mark.parametrize('operation', ['update', 'delete'])
def test_revision_is_immutable(db, operation):
    row, _ = retained(db)
    if operation == 'update':
        row.manifest_digest = 'changed'
    else:
        db.delete(row)
    with pytest.raises(ValueError, match='immutable'):
        db.flush()


def test_state_optimistic_concurrency(db):
    _, state = retained(db)
    revisions._change_state(db, state, 0, suspended=True)
    db.flush()
    with pytest.raises(ValueError, match='reload'):
        revisions._change_state(db, state, 0, revoked=True)
    assert state.suspended
    assert not state.revoked


def test_scope_required_even_with_decision_permission():
    auth = SimpleNamespace(has=lambda action, service: action == 'approval.decide')
    with pytest.raises(PermissionError):
        revisions._permission(auth, 1, 'approval.decide')


def test_missing_approval_fails_closed(db):
    with pytest.raises(ValueError, match='unavailable'):
        revisions._approval(db, 998)


def test_proposal_cannot_activate(db):
    row, state = retained(db)
    auth = SimpleNamespace(has=lambda *args: True)
    with pytest.raises(ValueError, match='active-eligible'):
        revisions.activate(db, auth, row.id, 0)


def test_restriction_preserves_approval_and_immutable_manifest(db):
    row, state = retained(db)
    auth = SimpleNamespace(has=lambda *args: True)
    manifest = dict(row.manifest)
    revisions.restrict(db, auth, row.id, 0, 'suspend', 'Investigation')
    db.flush()
    assert state.suspended
    assert state.decision == 'proposed'
    assert not state.revoked
    assert row.manifest == manifest


@pytest.fixture
def approved_revision(db):
    from datetime import datetime, timezone
    from app.artifact_catalog import register_artifact, assign_artifact
    from app.cyber_approvals import CyberApproval, digest
    from app.models import Service
    from app.release_validity import new_validity
    now = datetime.now(timezone.utc)
    service = Service(service_key='rev-test', name='Revision')
    db.add(service)
    db.flush()
    artifact = register_artifact(db, digest='sha256:' + 'b' * 64,
        media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
    assign_artifact(db, service_id=service.id, artifact_id=artifact.id)
    snapshot = dict(release_revision=dict(artifact_ids=[artifact.id], base_revision_id=None),
        artifacts=[dict(digest=artifact.digest)], approval_validity=new_validity(now),
        signing_fingerprint='sha256:' + 'c' * 64)
    approval = CyberApproval(service_id=service.id, source_execution_id=1, variant='current_service',
        status='approved', snapshot=snapshot, snapshot_digest=digest(snapshot),
        decided_at=now, decided_by_id=1)
    db.add(approval)
    db.flush()
    auth = SimpleNamespace(has=lambda *args: True)
    revision = revisions.propose(db, auth, approval.id)
    revisions.decide(db, auth, revision.id, 0)
    db.flush()
    return revision, auth


def test_activation_requires_retained_signature(db, approved_revision, monkeypatch, tmp_path):
    revision, auth = approved_revision
    monkeypatch.setattr(revisions, 'manifest_directory', lambda row: tmp_path)
    with pytest.raises(ValueError, match='Signed revision manifest unavailable'):
        revisions.activate(db, auth, revision.id, 0)
    assert db.get(revisions.ServiceActiveRelease, revision.service_id).revision_id is None


def test_cyber_approval_activates_despite_failed_eligibility_and_can_be_suspended(
        db, approved_revision, monkeypatch, tmp_path):
    import hashlib
    from app import artifact_catalog
    revision, auth = approved_revision
    monkeypatch.setattr(artifact_catalog, 'artifact_eligibility', lambda *a, **kw:
        {'eligible': False, 'reasons': ['validation_failed']})
    monkeypatch.setattr(revisions, 'manifest_directory', lambda row: tmp_path)
    content = revisions.canonical(revision.manifest)
    (tmp_path / 'release-manifest.json').write_bytes(content)
    monkeypatch.setattr(revisions.release_signing, 'verify_release_manifest', lambda *a, **kw:
        {'status': 'verified', 'manifest_sha256': hashlib.sha256(content).hexdigest()})
    revisions.activate(db, auth, revision.id, 0)
    assert revisions.active_revision(db, revision.service_id).id == revision.id
    revisions.restrict(db, auth, revision.id, 1, 'suspend', 'Review evidence')
    assert revisions.active_revision(db, revision.service_id) is None


def test_signed_digest_mismatch_cannot_activate(db, approved_revision, monkeypatch, tmp_path):
    from app import artifact_catalog
    revision, auth = approved_revision
    monkeypatch.setattr(artifact_catalog, 'artifact_eligibility', lambda *a, **kw: {'eligible': True})
    monkeypatch.setattr(revisions, 'manifest_directory', lambda row: tmp_path)
    (tmp_path / 'release-manifest.json').write_bytes(revisions.canonical(revision.manifest))
    monkeypatch.setattr(revisions.release_signing, 'verify_release_manifest', lambda *a, **kw:
        {'status': 'verified', 'manifest_sha256': '0' * 64})
    with pytest.raises(ValueError, match='signature not verified'):
        revisions.activate(db, auth, revision.id, 0)


@pytest.fixture
def active_signed_revision(db, approved_revision, monkeypatch, tmp_path):
    import hashlib
    revision, auth = approved_revision
    monkeypatch.setattr(artifact_catalog, 'artifact_eligibility', lambda *a, **kw:
        {'eligible': False, 'reasons': ['validation_failed']})
    monkeypatch.setattr(revisions, 'manifest_directory', lambda row: tmp_path)
    content = revisions.canonical(revision.manifest)
    (tmp_path / 'release-manifest.json').write_bytes(content)
    monkeypatch.setattr(revisions.release_signing, 'verify_release_manifest', lambda *a, **kw:
        {'status': 'verified', 'manifest_sha256': hashlib.sha256(content).hexdigest()})
    revisions.activate(db, auth, revision.id, 0)
    db.commit()
    return revision


def test_active_revision_does_not_reassess_catalog_eligibility(db, active_signed_revision, monkeypatch):
    revision = active_signed_revision
    monkeypatch.setattr(artifact_catalog, 'artifact_eligibility', lambda *a, **kw:
        {'eligible': False, 'reasons': ['validation_failed', 'newer_scan_requires_approval']})
    assert revisions.active_revision(db, revision.service_id).id == revision.id
    revisions.validate_activation(db, revision)


def test_active_revision_uses_frozen_inventory_after_assignment_changes(db, active_signed_revision):
    from sqlalchemy import delete
    revision = active_signed_revision
    db.execute(delete(artifact_catalog.ServiceArtifactAssignment).where(
        artifact_catalog.ServiceArtifactAssignment.service_id == revision.service_id))
    db.commit()
    assert revisions.active_revision(db, revision.service_id).id == revision.id
    with pytest.raises(ValueError, match='Artifact unavailable'):
        revisions.validate_activation(db, revision)


@pytest.mark.parametrize('change', ['revoked', 'expired', 'denied', 'missing_decider',
    'snapshot_tampered', 'snapshot_rehashed', 'manifest_bytes', 'signature', 'suspended', 'revision_revoked',
    'malformed_snapshot', 'malformed_manifest', 'malformed_manifest_artifact'])
def test_active_revision_retains_authority_and_integrity_checks(
        db, active_signed_revision, monkeypatch, tmp_path, change):
    from datetime import timedelta
    from app.cyber_approvals import CyberApproval, digest
    revision = active_signed_revision
    approval = db.get(CyberApproval, revision.approval_id)
    now = approval.decided_at
    if change == 'revoked':
        approval.revoked_at = now
    elif change == 'expired':
        now += timedelta(days=90)
    elif change == 'denied':
        approval.status = 'denied'
    elif change == 'missing_decider':
        approval.decided_by_id = None
    elif change in {'snapshot_tampered', 'snapshot_rehashed'}:
        approval.snapshot = dict(approval.snapshot, artifacts=[dict(digest='sha256:' + '0' * 64)])
        if change == 'snapshot_rehashed':
            approval.snapshot_digest = digest(approval.snapshot)
    elif change == 'manifest_bytes':
        (tmp_path / 'release-manifest.json').write_bytes(b'{}')
    elif change == 'signature':
        monkeypatch.setattr(revisions.release_signing, 'verify_release_manifest',
            lambda *a, **kw: {'status': 'verification_failed'})
    elif change == 'malformed_snapshot':
        approval.snapshot = ['malformed']
        approval.snapshot_digest = digest(approval.snapshot)
    elif change in {'malformed_manifest', 'malformed_manifest_artifact'}:
        from sqlalchemy import update
        manifest = ['malformed'] if change == 'malformed_manifest' else dict(revision.manifest, artifacts=[None])
        # Simulate corrupt retained database content without the ORM immutability hook.
        db.execute(update(revisions.ReleaseRevision).where(revisions.ReleaseRevision.id == revision.id)
            .values(manifest=manifest, manifest_digest=digest(manifest)))
    else:
        state = db.get(revisions.ReleaseRevisionState, revision.id)
        setattr(state, 'suspended' if change == 'suspended' else 'revoked', True)
    db.commit()
    assert revisions.active_revision(db, revision.service_id, now) is None




def test_distribution_binding_uses_retained_location_and_scoped_mapping(db, approved_revision):
    from app.oci_models import OCIRepository, OCIUpstream
    from app.cyber_approvals import CyberApproval
    revision, _ = approved_revision
    approval = db.get(CyberApproval, revision.approval_id)
    upstream = OCIUpstream(name='binding', endpoint='https://registry.example')
    db.add(upstream)
    db.flush()
    mapping = OCIRepository(public_repository='service/app', service_id=revision.service_id,
        upstream_id=upstream.id, upstream_repository='team/app')
    db.add(mapping)
    db.flush()
    artifact = revision.manifest['artifacts'][0]
    requested = [dict(repository_id=mapping.id, tag='stable', artifact_id=artifact['id'])]
    with pytest.raises(ValueError, match='retained artifact evidence'):
        revisions._distribution_bindings(db, approval, [artifact], requested)
    approval.snapshot = dict(approval.snapshot, artifacts=[dict(digest=artifact['digest'],
        reference='registry.example/team/app@' + artifact['digest'])])
    binding = revisions._distribution_bindings(db, approval, [artifact], requested)[0]
    assert binding['digest'] == artifact['digest']
    assert binding['endpoint'] == upstream.endpoint
    assert binding['upstream_repository'] == mapping.upstream_repository
    with pytest.raises(ValueError, match='Duplicate'):
        revisions._distribution_bindings(db, approval, [artifact], requested * 2)
    with pytest.raises(ValueError, match='reserved'):
        revisions._distribution_bindings(db, approval, [artifact],
            [dict(requested[0], tag='sha256-' + 'a' * 64 + '.sig')])
    mapping.service_id += 10
    with pytest.raises(ValueError, match='this service'):
        revisions._distribution_bindings(db, approval, [artifact], requested)


def test_project_signed_tag_pins_concrete_route_and_upstream_bytes(db, approved_revision, monkeypatch):
    from app.cyber_approvals import CyberApproval
    from app.oci_authorization import project_tag_allowed
    from app.oci_models import OCIRepository, OCIUpstream
    revision, _ = approved_revision
    approval = db.get(CyberApproval, revision.approval_id)
    upstream = OCIUpstream(name='project', endpoint='https://harbor.example')
    db.add(upstream)
    db.flush()
    project = OCIRepository(public_repository='public/*', upstream_id=upstream.id, upstream_repository='team/*')
    db.add(project)
    db.flush()
    artifact = revision.manifest['artifacts'][0]
    digest = artifact['digest']
    requested = [dict(repository_id=project.id, tag='stable', artifact_id=artifact['id'])]
    retained = dict(kind='image', digest=digest, reference='harbor.example/team/nested/app@' + digest)
    approval.snapshot = dict(approval.snapshot, artifacts=[retained])
    binding = revisions._distribution_bindings(db, approval, [artifact], requested)[0]
    assert binding['public_repository'] == 'public/nested/app'
    assert binding['upstream_repository'] == 'team/nested/app'
    effective = SimpleNamespace(id=project.id, service_id=revision.service_id, public_repository='public/nested/app',
        upstream_repository='team/nested/app', project=project, upstream=upstream, upstream_id=upstream.id,
        enabled=True, suspended=False)
    active = SimpleNamespace(id=revision.id, manifest=dict(artifacts=[artifact], distribution_bindings=[binding]))
    monkeypatch.setattr(revisions, 'active_revision', lambda *args: active)
    assert project_tag_allowed(db, effective, 'stable', digest)
    assert not project_tag_allowed(db, effective, 'stable', 'sha256:' + 'a' * 64)
    assert not project_tag_allowed(db, effective, 'unbound', digest)
    effective.public_repository = 'public/sibling'
    effective.upstream_repository = 'team/sibling'
    assert not project_tag_allowed(db, effective, 'stable', digest)
    assert revisions.distribution_location(effective, active, digest) == 'team/sibling'
    effective.public_repository = binding['public_repository']
    effective.upstream_repository = binding['upstream_repository']
    project.upstream_repository = 'another/*'
    assert not project_tag_allowed(db, effective, 'stable', digest)
    with pytest.raises(ValueError, match='retained artifact evidence'):
        revisions._distribution_bindings(db, approval, [artifact], requested)


def test_recommendation_amendment_retains_inventory_and_requires_current_base(db, approved_revision, monkeypatch):
    from app.artifact_catalog import register_artifact, assign_artifact, ArtifactRecommendation
    base, auth = approved_revision
    target = register_artifact(db, digest='sha256:' + 'd' * 64,
        media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
    unchanged = register_artifact(db, digest='sha256:' + 'e' * 64,
        media_type='application/vnd.oci.image.manifest.v1+json', platform='linux/amd64')
    # Shared recommendations can be proposed before receiving-service validation or assignment.
    pointer = db.get(revisions.ServiceActiveRelease, base.service_id)
    pointer.revision_id = base.id
    recommendation = ArtifactRecommendation(service_id=base.service_id,
        source_artifact_id=base.manifest['artifacts'][0]['id'], target_artifact_id=target.id)
    db.add(recommendation); db.flush()
    # The active manifest is immutable; use a read-only stand-in to exercise a larger inventory.
    active = SimpleNamespace(id=base.id, approval_id=base.approval_id,
        manifest=dict(base.manifest, artifacts=base.manifest['artifacts'] + [dict(id=unchanged.id)]))
    monkeypatch.setattr(revisions, 'active_revision', lambda *a: active)
    proposal = revisions.propose_recommendation(db, auth, recommendation)
    assert proposal.intent['release_revision']['artifact_ids'] == [target.id, unchanged.id]
    assert proposal.intent['previous_artifacts'] == db.get(revisions.CyberApproval, base.approval_id).snapshot['artifacts']
    assert proposal.intent['posture_status'] == 'requires_fresh_service_assessment'
    assert proposal.intent['assessment_readiness']['automatic_assessment_available'] is True
    readiness = revisions.amendment_readiness(db, auth, proposal.id, base.service_id)
    assert readiness['ready_for_cyber_review'] is False
    assert readiness['artifacts'][0]['assigned'] is False
    assert readiness['artifacts'][0]['eligible'] is False
    assert 'service_assignment_missing' in readiness['artifacts'][0]['reasons']
    assert revisions.propose_recommendation(db, auth, recommendation).id == proposal.id
    assert revisions.amendment_specification(db, auth, proposal.id, base.service_id) == proposal.intent['release_revision']
    assert pointer.revision_id == base.id
    assert db.get(revisions.CyberApproval, base.approval_id).status == 'approved'
    pointer.revision_id = None; db.flush()
    with pytest.raises(ValueError, match='changed'):
        revisions.amendment_specification(db, auth, proposal.id, base.service_id)
    with pytest.raises(ValueError, match='unavailable'):
        revisions.amendment_specification(db, auth, proposal.id, base.service_id + 1)


def test_signed_binding_retains_public_mapping_but_pins_cross_repository(db, approved_revision):
    from app.oci_models import OCIRepository, OCIUpstream
    from app.cyber_approvals import CyberApproval
    from types import SimpleNamespace
    revision, _ = approved_revision
    approval = db.get(CyberApproval, revision.approval_id)
    upstream = OCIUpstream(name='replacement', endpoint='https://registry.example')
    db.add(upstream); db.flush()
    mapping = OCIRepository(public_repository='service/stable', service_id=revision.service_id,
        upstream_id=upstream.id, upstream_repository='original/image')
    db.add(mapping); db.flush()
    artifact = revision.manifest['artifacts'][0]
    retained = dict(kind='image', digest=artifact['digest'], reference='registry.example/patched/image@' + artifact['digest'])
    approval.snapshot = dict(approval.snapshot, artifacts=[retained])
    requested = [dict(repository_id=mapping.id, tag='stable', artifact_id=artifact['id'])]
    binding = revisions._distribution_bindings(db, approval, [artifact], requested)[0]
    assert binding['public_repository'] == 'service/stable'
    assert binding['mapping_upstream_repository'] == 'original/image'
    assert binding['upstream_repository'] == 'patched/image'
    active = SimpleNamespace(manifest=dict(artifacts=[artifact], distribution_bindings=[binding]))
    assert revisions.distribution_location(mapping, active, artifact['digest']) == 'patched/image'
    assert mapping.upstream_repository == 'original/image'
    approval.snapshot = dict(approval.snapshot, artifacts=[dict(retained, reference='untrusted.example/patched/image@' + artifact['digest'])])
    with pytest.raises(ValueError, match='retained artifact evidence'):
        revisions._distribution_bindings(db, approval, [artifact], requested)
    approval.snapshot = dict(approval.snapshot, artifacts=[retained, dict(retained, reference='registry.example/another/image@' + artifact['digest'])])
    with pytest.raises(ValueError, match='retained artifact evidence'):
        revisions._distribution_bindings(db, approval, [artifact], requested)
    mapping.upstream_repository = 'edited/image'
    with pytest.raises(ValueError, match='location changed'):
        revisions.distribution_location(mapping, active, artifact['digest'])
