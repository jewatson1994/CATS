"""Production component identity comes from the current Cyber release on full and replica installations."""
import pytest
from sqlalchemy import select

from app import cyber_approvals, cyber_release_publication, release_revisions
from app.models import Execution
from app.replica_integrity import digest as sealed_digest, seal_record
from app.runtime_applications import RuntimeApplication, missing_components, production_decision
from app.runtime_models import RuntimeEnvironment, now
from app.runtime_policy import RuntimePolicyCache, evaluate_observation
from test_oci_authorization import NOW as legacy_time, context
from test_oci_compliance_imported import CHILD, NOW, OTHER, PIN, capture, imported
from test_runtime_policy import evaluate, observed, runtime
from test_runtime_release_review import case, decision, publication_environment, review, submit


def production(db, service_id, timestamp, component):
    cache = RuntimePolicyCache()
    scope = {'kind': 'kubernetes', 'service_ids': [service_id]}
    result = evaluate_observation(db, scope, component, timestamp, cache=cache)
    return production_decision(db, result, component, service_id, timestamp, cache)


def observed_component(ref, container='web', *, image_id=None):
    return {'state': 'running', 'image_ref': ref, 'image_id': image_id if image_id is not None else ref,
            'workload': 'api', 'workload_kind': 'Deployment', 'container_kind': 'container', 'container': container}


def prod_app(db, service_id, timestamp, components):
    env = RuntimeEnvironment(name='Production', kind='kubernetes', cluster_role='production',
                             service_ids=[service_id], discovery_observed_at=timestamp)
    db.add(env)
    db.flush()
    app = RuntimeApplication(environment_id=env.id, service_id=service_id, identity='app', namespace='live',
                             name='API', members=[], fingerprint='abc', last_observed_at=timestamp,
                             components=components, present=True)
    db.add(app)
    db.flush()
    return env, app


def inventory(*components):
    return {'applications': [{'components': list(components)}]}


def test_signed_local_release_matches_workload_and_detects_absence_or_corruption(case):
    approval_id = submit(case, review(case)['review_digest'])['id']
    decision(case, approval_id, 'approved')
    approval = case.db.get(cyber_approvals.CyberApproval, approval_id)
    revision = case.db.scalar(select(release_revisions.ReleaseRevision))
    receipt = cyber_release_publication.publish(case.db, approval, approval.destination, lambda _: None)
    assert receipt['revision_signature']['signature_status'] == 'verified'
    approval.publish_status, approval.publication = 'published', receipt
    case.db.flush()
    release_revisions.activate(case.db, case.cyber, revision.id, 0)
    timestamp = now()
    observed = observed_component(case.ref)
    service_id = case.service.id
    exact = production(case.db, service_id, timestamp, observed)
    assert (exact['status'], exact.get('approval_id')) == ('approved', approval.id), exact
    published_ref = next(asset['reference'] for asset in receipt['artifacts'] if asset['kind'] == 'image')
    published = production(case.db, service_id, timestamp, observed_component(published_ref))
    assert (published['status'], published.get('approval_id')) == ('approved', approval.id), published
    extra = production(case.db, service_id, timestamp, {**observed, 'container_kind': 'ephemeral'})
    assert (extra['status'], extra['reason']) == ('noncompliant', 'unexpected_component')
    env, app = prod_app(case.db, service_id, timestamp, [observed, observed])
    assert not list(missing_components(case.db, env, timestamp, RuntimePolicyCache()))
    app.present = False
    missing, = list(missing_components(case.db, env, timestamp, RuntimePolicyCache()))
    assert missing[0]['namespace'] == 'live' and missing[0]['container'] == 'web'
    assert missing[1] == {'status': 'noncompliant', 'reason': 'missing_approved_component',
                          'service_id': service_id, 'approval_id': approval.id}
    aggregate = case.db.get(Execution, approval.source_execution_id)
    original_key = aggregate.execution_key
    aggregate.execution_key = original_key + '-changed'
    case.db.commit()
    damaged = production(case.db, service_id, timestamp, observed)
    assert (damaged['status'], damaged['reason']) == ('unverified', 'approval_evidence_changed')
    aggregate.execution_key = original_key
    approval.snapshot = {**approval.snapshot, 'runtime_evidence': {}}
    case.db.commit()
    result = production_decision(case.db, exact, observed, service_id, timestamp, RuntimePolicyCache())
    assert (result['status'], result['reason']) == ('unverified', 'current_release_evidence_unavailable')
    issue, = list(missing_components(case.db, env, timestamp, RuntimePolicyCache()))
    assert issue[1]['status'] == 'unverified'


def test_pre_revision_approval_keeps_legacy_digest_policy(runtime):
    row = observed()
    base = evaluate(runtime, row)
    assert production_decision(runtime.db, base, row, runtime.mapping.service_id, legacy_time, RuntimePolicyCache()) == base


def installed_capture(case, evidence):
    capture(case, lambda state: state['extension']['approval_context'].update(
        evidence_scope='runtime-release-candidate', runtime_evidence=evidence))


@pytest.mark.parametrize('mode', ['full', 'replica'])
def test_imported_current_inventory_and_verified_child_bind_slots(imported, mode, monkeypatch):
    monkeypatch.setenv('CATS_MODE', mode)
    service_id = imported.service.id
    first = observed_component('docker.io/library/nginx@' + PIN)
    other = observed_component('docker.io/library/sidecar@' + OTHER, 'metrics')
    # Both images belong to this sealed release. Only their reviewed component may run each one.
    sidecar = {**imported.release.artifacts[0], 'digest': OTHER, 'manifests': [OTHER],
               'reference': 'registry.example/published/nginx@' + OTHER, 'source_digest': OTHER,
               'source_reference': 'docker.io/library/sidecar@' + OTHER}
    artifacts = [*imported.release.artifacts, sidecar]
    imported.release.artifacts = artifacts
    imported.release.manifest = {'artifacts': artifacts}
    imported.release.manifest_digest = sealed_digest(imported.release.manifest)
    seal_record(imported.release)
    installed_capture(imported, inventory(first, other))
    production_ref = 'registry.example/published/nginx@'
    seen = observed_component(production_ref + CHILD)
    exact = production(imported.db, service_id, NOW, seen)
    assert (exact['status'], exact['release_id']) == ('approved', imported.release.id)
    moved = production(imported.db, service_id, NOW, {**seen, 'container': 'debug'})
    assert (moved['status'], moved['reason']) == ('noncompliant', 'unexpected_component')
    for image_id in (production_ref + OTHER, OTHER):
        swapped = production(imported.db, service_id, NOW, observed_component(production_ref + OTHER, image_id=image_id))
        assert (swapped['status'], swapped['reason']) == ('noncompliant', 'component_digest_mismatch')
    env, _ = prod_app(imported.db, service_id, NOW, [seen])
    absent, = list(missing_components(imported.db, env, NOW, RuntimePolicyCache()))
    assert absent[0]['container'] == 'metrics' and absent[1]['release_id'] == imported.release.id
    # A modified local capture retains the original integrity seal and cannot supply different slots.
    capture(imported, lambda e: e['extension']['approval_context'].pop('runtime_evidence'), seal=False)
    rejected = production(imported.db, service_id, NOW, seen)
    assert (rejected['status'], rejected['reason']) == ('unverified', 'current_release_evidence_unavailable')


@pytest.mark.parametrize('bad', [None, {}, {'applications': []}, {'applications': [None]},
    inventory({'workload_kind': 'Deployment'}), inventory(observed_component('docker.io/library/nginx:latest'))])
def test_damaged_imported_component_structure_fails_closed(imported, bad):
    installed_capture(imported, bad)
    result = production(imported.db, imported.service.id, NOW, observed_component('registry.example/published/nginx@' + PIN))
    assert (result['status'], result['reason']) == ('unverified', 'current_release_evidence_unavailable')


def test_runtime_release_without_component_evidence_cannot_downgrade_to_legacy(imported):
    capture(imported, lambda state: state['extension']['approval_context'].update(evidence_scope='runtime-release-candidate'))
    result = production(imported.db, imported.service.id, NOW, observed_component('registry.example/published/nginx@' + PIN))
    assert (result['status'], result['reason']) == ('unverified', 'current_release_evidence_unavailable')


def test_intact_imported_legacy_release_preserves_approval(imported):
    result = production(imported.db, imported.service.id, NOW, observed_component('registry.example/published/nginx@' + PIN))
    assert result['status'] == 'approved' and result['release_id'] == imported.release.id
