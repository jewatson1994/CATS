"""Runtime status must prove observed bytes belong to a current scoped release."""
from copy import deepcopy
from datetime import timedelta
import hashlib
import json
from types import SimpleNamespace

import pytest

from app import oci_authorization, oci_group_policy, release_revisions
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.execution_summaries import payload_digest
from app.models import Execution, Service, Finding, FindingObservation
from app.oci_compliance import authorize_compliance
from app.local_cyber_overrides import create_override, revoke_override
from app.oci_models import OCIManifest, OCIObjectLink, OCIRepository, OCIUpstream
from app.replica_integrity import seal_record
from app.replica_models import ReplicaRelease
from app.runtime_policy import evaluate_observation, RuntimePolicyCache
from test_oci_authorization import context, DIGEST, NOW
from test_oci_compliance_imported import imported, PIN as IMPORT_PIN, CHILD as IMPORT_CHILD, NOW as IMPORT_NOW, capture
from test_replica_authorization import replica


@pytest.fixture
def runtime(context, monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.delenv('CATS_OCI_HOSTNAME', raising=False)
    db, scoped, approval, execution = context
    upstream = OCIUpstream(name='runtime-source', endpoint='https://registry.example')
    db.add(upstream)
    db.flush()
    mapping = OCIRepository(public_repository='approved/image', upstream_id=upstream.id,
                            upstream_repository='team/image', service_id=scoped.service_id)
    db.add(mapping)
    db.commit()
    return SimpleNamespace(db=db, mapping=mapping, approval=approval, execution=execution,
                           environment=SimpleNamespace(service_ids=[scoped.service_id]))


def observed(digest=DIGEST, repository='registry.example/team/image'):
    return dict(state='running', image_ref=repository + ':latest', image_id='docker-pullable://' + repository + '@' + digest)


def evaluate(runtime, observation=None, now=NOW):
    return evaluate_observation(runtime.db, runtime.environment, observation or observed(), now)


def test_exact_approved_image_without_machine_pull_grants(runtime):
    result = evaluate(runtime)
    assert result == dict(status='approved', reason='approved',
                         service_id=runtime.mapping.service_id, approval_id=runtime.approval.id)


@pytest.mark.parametrize('identity', ['', DIGEST, 'docker://' + DIGEST,
    'containerd://' + DIGEST, 'registry.example/team/image:latest',
    'registry.example/team/image@sha256:bad', 'https://registry.example/team/image@' + DIGEST])
def test_tag_or_config_id_never_proves_runtime_manifest(runtime, identity):
    result = evaluate(runtime, dict(state='running', image_ref='registry.example/team/image@' + DIGEST, image_id=identity))
    assert result['status'] == 'unverified'
    assert result['reason'] == 'immutable_runtime_identity_unavailable'


def test_requested_tag_does_not_override_actual_digest(runtime):
    result = evaluate(runtime, observed('sha256:' + 'f' * 64))
    assert result['status'] == 'unverified'
    assert result['reason'] == 'image_not_in_retained_release_evidence'


@pytest.mark.parametrize('repository', ['untrusted.example/team/image', 'registry.example/other/image'])
def test_repository_identity_cannot_be_replaced_by_digest_alone(runtime, repository):
    assert evaluate(runtime, observed(repository=repository)) == {
        'status': 'unverified', 'reason': 'no_approved_release_match'}


def test_agent_supplied_service_cannot_expand_environment_scope(runtime):
    runtime.environment.service_ids = [runtime.mapping.service_id + 100]
    value = observed() | {'service_id': runtime.mapping.service_id}
    assert evaluate(runtime, value)['status'] == 'unverified'
    runtime.environment.service_ids = []
    assert evaluate(runtime, value)['reason'] == 'environment_service_scope_unavailable'


@pytest.mark.parametrize('change,reason', [('revoked', 'release_revoked'),
    ('expired', 'release_expired')])
def test_current_denial_is_noncompliant(runtime, change, reason):
    timestamp = NOW
    if change == 'revoked':
        runtime.approval.revoked_at = NOW
    elif change == 'expired':
        timestamp += timedelta(days=90)
    runtime.db.commit()
    result = evaluate(runtime, now=timestamp)
    assert result['status'] == 'noncompliant'
    assert result['reason'] == reason


def test_corrupt_evidence_is_unverified(runtime):
    runtime.approval.snapshot_digest = 'sha256:' + '0' * 64
    runtime.db.commit()
    assert evaluate(runtime)['status'] == 'unverified'


def test_scanned_without_approved_release_is_unverified(runtime):
    runtime.db.delete(runtime.approval)
    runtime.db.commit()
    assert evaluate(runtime)['status'] == 'unverified'


def test_only_configured_public_host_can_relocate_repository(runtime, monkeypatch):
    value = observed(repository=f'cats.example:9443/approved/{runtime.mapping.service_id}/image')
    assert evaluate(runtime, value)['status'] == 'unverified'
    monkeypatch.setenv('CATS_OCI_HOSTNAME', 'cats.example:9443')
    assert evaluate(runtime, observed(repository='cats.example:9443/approved/image'))['reason'] == 'repository_mapping_unavailable'
    assert evaluate(runtime, value)['status'] == 'approved'
    assert evaluate(runtime, observed(repository='evil.example/approved/image'))['status'] == 'unverified'


def test_project_mapping_uses_only_admin_selected_service(runtime):
    runtime.mapping.public_repository = 'approved/*'
    runtime.mapping.upstream_repository = 'team/*'
    runtime.mapping.service_id = None
    runtime.db.commit()
    assert evaluate(runtime)['status'] == 'approved'
    runtime.environment.service_ids = [1000]
    assert evaluate(runtime)['status'] == 'unverified'


def test_disabled_exact_public_mapping_does_not_fall_back_to_project(runtime, monkeypatch):
    monkeypatch.setenv('CATS_OCI_HOSTNAME', 'cats.example')
    runtime.mapping.enabled = False
    runtime.db.add(OCIRepository(public_repository='approved/*',
        upstream_id=runtime.mapping.upstream_id, upstream_repository='team/*', service_id=None))
    runtime.db.commit()
    assert evaluate(runtime, observed(repository=f'cats.example/approved/{runtime.mapping.service_id}/image'))['status'] == 'unverified'


def test_verified_published_image_binding(runtime):
    source = 'sha256:' + 'b' * 64
    snapshot = deepcopy(runtime.approval.snapshot)
    snapshot['artifacts'] = [dict(kind='image', reference='source.example/original@' + source, digest=source)]
    runtime.approval.snapshot = snapshot
    runtime.approval.snapshot_digest = snapshot_digest(snapshot)
    artifact = dict(kind='image', reference='registry.example/team/image@' + DIGEST,
        digest=DIGEST, source_digest=source, scan_identity_retained=True,
        identity_resolution='retained-evidence', verification_status='verified')
    runtime.approval.publish_status = 'published'
    runtime.approval.publication = dict(status='published', verification_status='verified',
        signature_status='verified', artifacts=[artifact], manifest=dict(
            approval_id=runtime.approval.id, snapshot_digest=runtime.approval.snapshot_digest,
            artifacts=[artifact]))
    runtime.db.commit()
    assert evaluate(runtime)['status'] == 'approved'
    receipt = deepcopy(runtime.approval.publication)
    receipt['signature_status'] = 'unverified'
    runtime.approval.publication = receipt
    runtime.db.commit()
    assert evaluate(runtime)['status'] == 'unverified'


def test_chart_manifest_is_not_a_running_image(runtime):
    snapshot = deepcopy(runtime.approval.snapshot)
    snapshot['artifacts'][0]['kind'] = 'chart'
    runtime.approval.snapshot = snapshot
    runtime.approval.snapshot_digest = snapshot_digest(snapshot)
    runtime.db.commit()
    assert evaluate(runtime)['status'] == 'unverified'


@pytest.mark.parametrize('tamper', [None, 'root', 'child', 'size', 'config', 'attestation', 'empty-config'])
def test_multiarch_child_requires_verified_index_bytes(runtime, tamper):
    config_type = ('application/vnd.oci.empty.v1+json' if tamper == 'empty-config'
                   else 'application/vnd.oci.image.config.v1+json')
    child = json.dumps({'schemaVersion': 2, 'config': {'digest': DIGEST, 'size': 0, 'mediaType': config_type}, 'layers': []})
    child_digest = 'sha256:' + hashlib.sha256(child.encode()).hexdigest()
    document = {'schemaVersion': 2, 'manifests': [{'digest': child_digest, 'size': len(child.encode())}]}
    if tamper == 'size':
        document['manifests'][0]['size'] += 1
    if tamper == 'attestation':
        document['manifests'][0]['annotations'] = {'vnd.docker.reference.type': 'attestation-manifest'}
    if tamper == 'config':
        document = {'schemaVersion': 2, 'config': {'digest': child_digest, 'size': len(child.encode())}, 'layers': []}
    root = json.dumps(document)
    root_digest = 'sha256:' + hashlib.sha256(root.encode()).hexdigest()
    snapshot = deepcopy(runtime.approval.snapshot)
    snapshot['artifacts'] = [dict(kind='image', reference='registry.example/team/image@' + root_digest,
                                  digest=root_digest)]
    runtime.approval.snapshot = snapshot
    runtime.approval.snapshot_digest = snapshot_digest(snapshot)
    runtime.db.add_all([
        OCIManifest(repository_id=runtime.mapping.id, digest=root_digest,
                    media_type='application/vnd.oci.image.index.v1+json', content='{}' if tamper == 'root' else root),
        OCIManifest(repository_id=runtime.mapping.id, digest=child_digest,
                    media_type='application/vnd.oci.image.manifest.v1+json', content='{}' if tamper == 'child' else child),
        OCIObjectLink(repository_id=runtime.mapping.id, root_digest=root_digest,
                      object_digest=child_digest, kind='manifest'),
    ])
    runtime.db.commit()
    assert evaluate(runtime, observed(child_digest))['status'] == ('approved' if tamper is None else 'unverified')


def test_replica_current_superseded_and_exception_states(replica):
    environment = SimpleNamespace(service_ids=[replica.service_id])
    with replica.sessions() as db:
        mapping = db.get(OCIRepository, replica.mapping_id)
        host = mapping.upstream.endpoint.split('://', 1)[1]
        repository = host + '/' + mapping.upstream_repository
        assert evaluate_observation(db, environment, observed(replica.new, repository), replica.now)['status'] == 'approved'
        old = observed(replica.old, repository)
        assert evaluate_observation(db, environment, old, replica.now)['status'] == 'noncompliant'
        grant = create_override(db, replica.auth, replica.service_id, replica.data, replica.now)
        db.commit()
        result = evaluate_observation(db, environment, old, replica.now)
        assert result['status'] == 'excepted'
        assert result['override_id'] == grant.id
        revoke_override(db, replica.auth, replica.service_id, grant.id, 'Replaced workload')
        db.commit()
        assert evaluate_observation(db, environment, old, replica.now)['status'] == 'noncompliant'


def test_replica_manifest_children_require_sealed_membership(replica):
    environment = SimpleNamespace(service_ids=[replica.service_id])
    child = 'sha256:' + 'd' * 64
    with replica.sessions() as db:
        mapping = db.get(OCIRepository, replica.mapping_id)
        repository = mapping.upstream.endpoint.split('://', 1)[1] + '/' + mapping.upstream_repository
        release = db.get(ReplicaRelease, replica.new_id)
        artifacts = deepcopy(release.artifacts)
        artifacts[0]['manifests'].append(child)
        release.artifacts = artifacts
        seal_record(release)
        db.commit()
        assert evaluate_observation(db, environment, observed(child, repository), replica.now)['status'] == 'approved'
        release.integrity_seal = 'tampered'
        db.commit()
        assert evaluate_observation(db, environment, observed(child, repository), replica.now)['status'] == 'unverified'


def remove_mapping(runtime):
    runtime.db.delete(runtime.mapping)
    runtime.db.commit()


def another_approval(runtime, digest=DIGEST):
    db = runtime.db
    other = Service(service_key='another', name='Another')
    db.add(other)
    db.flush()
    scan = Execution(service_id=other.id, execution_key='other-scan', scanned_at=NOW,
                     complete=True, scan_scope='service', raw_payload={})
    db.add(scan)
    db.flush()
    snapshot = deepcopy(runtime.approval.snapshot)
    snapshot.update(service_id=other.id, source_execution_id=scan.id,
                    artifacts=[dict(kind='image', reference='registry.example/team/image@' + digest, digest=digest)])
    approval = CyberApproval(service_id=other.id, source_execution_id=scan.id, variant='current',
                             status='approved', snapshot=snapshot, snapshot_digest=snapshot_digest(snapshot),
                             decided_at=NOW)
    db.add(approval)
    db.commit()
    return approval


@pytest.mark.parametrize('state', ['terminated', 'waiting', 'unknown', 'paused', 'restarting', 'exited', None])
def test_only_running_containers_can_be_currently_approved(runtime, state):
    assert evaluate(runtime, observed() | {'state': state}) == {
        'status': 'unverified', 'reason': 'container_not_running'}


def test_full_immutable_qualified_identity_without_any_oci_routes(runtime):
    remove_mapping(runtime)
    assert evaluate(runtime)['status'] == 'approved'
    assert evaluate(runtime, observed(repository='REGISTRY.EXAMPLE/team/image:stable'))['status'] == 'approved'
    assert evaluate(runtime, observed(repository='registry.example/unrelated/image'))['reason'] == 'no_approved_release_match'
    assert evaluate(runtime, observed(repository='evil.example/team/image'))['reason'] == 'no_approved_release_match'
    assert evaluate(runtime, observed('sha256:' + 'e' * 64)) == dict(
        status='unverified', reason='no_approved_release_match', service_id=runtime.approval.service_id)
    assert evaluate(runtime, observed(repository='team/image'))['reason'] == 'immutable_runtime_identity_unavailable'
    assert evaluate(runtime, now=NOW + timedelta(days=90))['reason'] == 'release_expired'
    runtime.approval.revoked_at = NOW
    runtime.db.commit()
    assert evaluate(runtime)['reason'] == 'release_revoked'


def test_direct_reference_requires_explicit_retained_host(runtime):
    remove_mapping(runtime)
    snapshot = deepcopy(runtime.approval.snapshot)
    snapshot['artifacts'][0]['reference'] = 'nginx@' + DIGEST
    runtime.approval.snapshot = snapshot
    runtime.approval.snapshot_digest = snapshot_digest(snapshot)
    runtime.db.commit()
    assert evaluate(runtime, observed(repository='docker.io/library/nginx'))['status'] == 'unverified'


def test_dynamic_scope_and_service_scoped_proxy_disambiguate_shared_image(runtime, monkeypatch):
    second = another_approval(runtime)
    runtime.environment.service_scope = 'all'
    expect = {'status': 'unverified', 'reason': 'ambiguous_service_membership'}
    assert evaluate(runtime) == expect  # One service has a mapping; the other retains the same image directly.
    runtime.mapping.public_repository = 'approved/*'
    runtime.mapping.upstream_repository = 'team/*'
    runtime.mapping.service_id = None
    runtime.db.commit()
    assert evaluate(runtime) == expect
    monkeypatch.setenv('CATS_OCI_HOSTNAME', 'cats.example')
    second_ref = observed(repository=f'cats.example/approved/{second.service_id}/image')
    assert evaluate(runtime, second_ref)['approval_id'] == second.id
    first_id = runtime.approval.service_id
    first_ref = observed(repository=f'cats.example/approved/{first_id}/image')
    assert evaluate(runtime, first_ref)['approval_id'] == runtime.approval.id
    runtime.environment.service_scope = 'selected'
    runtime.environment.service_ids = [first_id]
    assert evaluate(runtime)['approval_id'] == runtime.approval.id
    assert evaluate(runtime, second_ref)['reason'] == 'service_outside_environment_scope'
    runtime.db.get(Service, first_id).lifecycle_status = 'staged'
    runtime.db.commit()
    assert evaluate(runtime, first_ref)['reason'] == 'service_inactive'
    runtime.environment.service_scope = 'all'
    assert evaluate(runtime)['approval_id'] == second.id


def test_current_scan_freshness_does_not_shorten_real_approval(runtime):
    runtime.mapping.policy = {'max_scan_age_days': 1}
    runtime.db.commit()
    assert evaluate(runtime, now=NOW + timedelta(days=2))['status'] == 'approved'


def test_passing_group_compliance_policy_never_resurrects_a_revoked_release(runtime, monkeypatch):
    now = NOW
    execution = runtime.execution
    execution.raw_payload = dict(complete=True, fixable_only=True, scan_scope='service', service={'id': 'oci'},
        scanned_at=now.isoformat(), findings=[],
        service_overview={'images': [{'image': 'registry.example/team/image@' + DIGEST, 'digest': DIGEST}]})
    execution.payload_digest = payload_digest(execution.raw_payload)
    snapshot = deepcopy(runtime.approval.snapshot)
    snapshot['source_payload_digest'] = execution.payload_digest
    runtime.approval.snapshot = snapshot
    runtime.approval.snapshot_digest = snapshot_digest(snapshot)
    runtime.approval.revoked_at = now
    runtime.db.commit()
    policy = dict(oci_group_policy.DEFAULT_POLICY, mode='compliance', group_id=None)
    monkeypatch.setattr(oci_group_policy, 'policy_for_service', lambda *_: policy)
    assert authorize_compliance(runtime.db, runtime.mapping, DIGEST, policy, now).allowed
    assert oci_authorization.authorize(runtime.db, runtime.mapping, DIGEST, now).allowed
    assert evaluate(runtime)['reason'] == 'release_revoked'


@pytest.mark.parametrize('deployment', ['full', 'replica'])
def test_imported_release_in_both_modes_requires_trusted_current_inventory(replica, monkeypatch, deployment):
    monkeypatch.setenv('CATS_MODE', deployment)
    env = dict(service_scope='all')
    with replica.sessions() as db:
        mapping = db.get(OCIRepository, replica.mapping_id)
        repository = 'registry.example/' + mapping.upstream_repository
        db.delete(mapping)
        db.commit()
        assert evaluate_observation(db, env, observed(replica.new, repository), replica.now)['status'] == 'approved'
        result = evaluate_observation(db, env, observed('sha256:' + 'f' * 64, repository), replica.now)
        assert result == dict(status='noncompliant', reason='image_outside_current_approved_release',
                              service_id=replica.service_id, release_id=replica.new_id)
        assert evaluate_observation(db, env, observed(replica.old, repository), replica.now)['reason'] == 'release_superseded'
        release = db.get(ReplicaRelease, replica.new_id)
        release.integrity_seal = 'broken'
        db.commit()
        assert evaluate_observation(db, env, observed(replica.new, repository), replica.now)['status'] == 'unverified'


@pytest.mark.parametrize('environment_kind,state,pin,expected', [
    ('kubernetes', 'running', DIGEST, 'approved'),
    ('kubernetes', 'running', 'sha256:' + 'f' * 64, 'unverified'),
    ('docker', 'running', DIGEST, 'unverified'),
    ('kubernetes', 'waiting', DIGEST, 'unverified'),
])
def test_bare_runtime_pin_requires_kubernetes_and_corroboration(runtime, environment_kind, state, pin, expected):
    runtime.environment.kind = environment_kind
    value = dict(state=state, image_ref='registry.example/team/image@' + pin, image_id=DIGEST)
    assert evaluate(runtime, value)['status'] == expected
    value.update(state='running', image_id='sha256:' + 'e' * 64, image_ref='registry.example/team/image@sha256:' + 'e' * 64)
    assert evaluate(runtime, value)['status'] == 'unverified'
    value.update(image_id=DIGEST, image_ref='registry.example/team/image:latest')
    assert evaluate(runtime, value)['status'] == 'unverified'


def test_requested_gateway_alias_names_service_but_cannot_launder_different_bytes(runtime, monkeypatch):
    other = another_approval(runtime)
    runtime.environment.service_scope = 'all'
    runtime.mapping.public_repository = 'approved/*'
    runtime.mapping.upstream_repository = 'team/*'
    runtime.mapping.service_id = None
    other.revoked_at = NOW
    runtime.db.commit()
    monkeypatch.setenv('CATS_OCI_HOSTNAME', 'cats.example')
    requested = f'cats.example/approved/{other.service_id}/image'
    value = observed() | dict(image_ref=requested + ':latest')
    assert evaluate(runtime, value) == dict(status='noncompliant', reason='release_revoked',
                                            service_id=other.service_id, approval_id=other.id)
    value['image_ref'] = requested + '@sha256:' + 'f' * 64
    assert evaluate(runtime, value)['reason'] == 'requested_digest_mismatch'
    value['image_ref'] = requested + ':latest'
    value['image_id'] = 'other.example/team/image@' + DIGEST
    assert evaluate(runtime, value)['reason'] == 'requested_service_repository_mismatch'
    value['image_id'] = 'registry.example/team/different@' + DIGEST
    assert evaluate(runtime, value)['reason'] == 'requested_service_repository_mismatch'


def test_revision_history_current_and_outside_repo_member(runtime, tmp_path, monkeypatch):
    from app.artifact_catalog import register_artifact, assign_artifact
    db = runtime.db
    first = runtime.approval
    auth = SimpleNamespace(has=lambda *args: True)
    monkeypatch.setattr(release_revisions, 'manifest_directory', lambda row: tmp_path / str(row.id))
    monkeypatch.setattr(release_revisions.release_signing, 'verify_release_manifest',
                        lambda path, *_args, **_kwargs: dict(status='verified',
                            manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))

    def activate(approval, pin, version, base=None):
        image = register_artifact(db, digest=pin, media_type='application/vnd.oci.image.manifest.v1+json',
                                  platform='linux/amd64')
        assign_artifact(db, service_id=first.service_id, artifact_id=image.id)
        snapshot = deepcopy(approval.snapshot)
        snapshot.update(release_revision=dict(artifact_ids=[image.id], base_revision_id=base),
                        signing_fingerprint='sha256:' + 'd' * 64,
                        artifacts=[dict(kind='image', reference='registry.example/team/image@' + pin, digest=pin)])
        approval.snapshot = snapshot
        approval.snapshot_digest = snapshot_digest(snapshot)
        approval.decided_by_id = 1
        db.flush()
        revision = release_revisions.propose(db, auth, approval.id)
        release_revisions.decide(db, auth, revision.id, 0)
        folder = release_revisions.manifest_directory(revision)
        folder.mkdir()
        (folder / 'release-manifest.json').write_bytes(release_revisions.canonical(revision.manifest))
        release_revisions.activate(db, auth, revision.id, version, NOW)
        db.commit()
        return revision

    old = activate(first, DIGEST, 0)
    assert evaluate(runtime)['status'] == 'approved'
    pin = 'sha256:' + 'b' * 64
    following = CyberApproval(service_id=first.service_id, source_execution_id=first.source_execution_id,
        variant='current', status='approved', snapshot=deepcopy(first.snapshot),
        snapshot_digest=first.snapshot_digest, decided_at=NOW)
    db.add(following)
    db.flush()
    latest = activate(following, pin, 1, base=old.id)
    assert evaluate(runtime, observed(pin))['approval_id'] == following.id
    assert evaluate(runtime)['reason'] == 'release_superseded'
    assert evaluate(runtime, observed('sha256:' + 'e' * 64))['reason'] == 'image_outside_current_approved_release'
    runtime.environment.kind = 'kubernetes'
    bare = 'sha256:' + 'e' * 64
    assert evaluate(runtime, dict(state='running', image_ref='registry.example/team/image@' + bare,
                                  image_id=bare))['status'] == 'unverified'
    release_revisions.restrict(db, auth, latest.id, 1, 'suspend', 'Cyber review')
    db.commit()
    assert evaluate(runtime, observed(pin))['reason'] == 'release_suspended'
    release_revisions.restrict(db, auth, latest.id, 2, 'revoke', 'Image replacement required')
    db.commit()
    assert evaluate(runtime, observed(pin))['reason'] == 'release_revoked'


def test_request_cache_shares_release_evidence_across_distinct_manifest_ids(runtime):
    from sqlalchemy import event
    remove_mapping(runtime)
    cache = RuntimePolicyCache()
    runtime.environment.service_scope = 'all'
    db = runtime.db
    engine = db.get_bind()
    queries = []
    def count(_connection, _cursor, sql, *_args):
        queries.append(sql)
    event.listen(engine, 'before_cursor_execute', count)
    try:
        def query_for(number):
            return evaluate_observation(db, runtime.environment, observed('sha256:' + format(number, '064x')),
                                        NOW, cache=cache)
        assert query_for(1)['status'] == 'unverified'
        warmup = len(queries)
        for number in range(2, 102):
            assert query_for(number)['status'] == 'unverified'
        assert len(queries) == warmup
        for number in range(100):
            row = observed(repository=f'other.example/project/container-{number}')
            assert evaluate_observation(db, runtime.environment, row, NOW, cache=cache)['status'] == 'unverified'
        assert len(queries) == warmup
    finally:
        event.remove(engine, 'before_cursor_execute', count)
    assert evaluate(runtime)['status'] == 'approved'
    runtime.approval.revoked_at = NOW
    db.commit()
    assert evaluate(runtime)['reason'] == 'release_revoked'


@pytest.mark.parametrize('restriction', ['expired', 'revoked'])
def test_imported_release_loses_runtime_approval_at_restriction(replica, restriction):
    with replica.sessions() as db:
        active = db.get(ReplicaRelease, replica.new_id)
        if restriction == 'expired':
            active.expires_at = replica.now
        else:
            active.revoked_at = replica.now
        seal_record(active)
        db.commit()
        row = observed(replica.new, 'registry.example/team/nginx')
        result = evaluate_observation(db, {'service_scope': 'all'}, row, replica.now)
        assert result == dict(status='noncompliant', reason='release_' + restriction,
                              service_id=replica.service_id, release_id=replica.new_id)


@pytest.mark.parametrize('case, expected', [
    ('exact', 'noncompliant'), ('clean', 'compliant'), ('excepted', 'compliant'),
    ('sibling', 'unverified'), ('tag_only', 'unverified'), ('missing_observation', 'unverified'),
    ('corrupt', None), ('incomplete', None), ('different_pin', None),
])
def test_independent_current_scan_does_not_change_valid_release(runtime, monkeypatch, case, expected):
    from app import main
    from app.models import ExceptionRecord
    monkeypatch.setattr(main, 'configuration_for_service',
        lambda *_: dict(main.CONFIG_DEFAULTS, compliance_mode='raw', overdue_days='1', raw_due_rules='[]'))
    db = runtime.db
    reference = 'registry.example/team/image'
    other = 'sha256:' + 'e' * 64
    scanned = NOW + timedelta(hours=1)
    started = NOW - timedelta(days=10)
    pin = other if case in {'sibling', 'different_pin'} else DIGEST
    evidence_pin = None if case == 'tag_only' else pin
    finding_reference = reference + (':latest' if evidence_pin is None else '@' + pin)
    cve = 'CVE-2026-12345'
    finding = dict(cve=cve, severity='High', image=finding_reference, image_digest=evidence_pin)
    raw = dict(complete=case != 'incomplete', scan_scope='service', fixable_only=True, findings=[] if case == 'clean' else [finding],
        service={'id': 'oci'}, scanned_at=scanned.isoformat(), service_overview={
            'images': [dict(image=reference + '@' + p, digest=p) for p in ({other} if case == 'different_pin' else {DIGEST, pin})]})
    execution = Execution(service_id=runtime.approval.service_id, execution_key='updated-scan',
        scanned_at=scanned, complete=raw['complete'], scan_scope='service', raw_payload=raw,
        payload_digest=payload_digest(raw) if case != 'corrupt' else 'sha256:' + '0' * 64)
    db.add(execution)
    db.flush()
    if case != 'clean':
        result = Finding(service_id=execution.service_id, cve=cve, severity='High', first_seen=started,
                         episode_started=started, last_seen=scanned, active=True)
        db.add(result)
        db.flush()
        if case != 'missing_observation':
            db.add(FindingObservation(finding_id=result.id, execution_id=execution.id, image=finding_reference,
                                      image_digest=evidence_pin, evidence={}))
        if case == 'excepted':
            db.add(ExceptionRecord(finding_id=result.id, starts_at=started, expires_at=scanned + timedelta(days=1),
                                   approved_by='Cyber', justification='Accepted'))
    db.commit()
    verdict = evaluate(runtime, now=scanned)
    assert verdict['status'] == 'approved' and verdict['approval_id'] == runtime.approval.id
    assessment = verdict.get('scan_assessment')
    assert (assessment and assessment['status']) == expected
    if expected:
        assert assessment['execution_id'] == execution.id
        assert assessment['scanned_at'] == scanned.isoformat() and assessment['source'] == 'local_scan'
    if expected == 'noncompliant':
        assert assessment['reason'] == 'scan_image_noncompliant'


@pytest.mark.parametrize('condition,expected', [('exact', 'noncompliant'), ('clean', 'compliant'),
    ('excepted', 'unverified'), ('observation_excluded', 'unverified'), ('unscanned_child', None), ('tampered', None)])
def test_runtime_scan_posture_uses_sealed_image_specific_publisher_decisions(imported, condition, expected):
    def change(evidence):
        source = 'docker.io/library/nginx@' + IMPORT_PIN
        raw = evidence['records']['executions'][0]['raw_payload']
        raw['findings'] = [dict(cve='CVE-X', severity='High', image=source, image_digest=IMPORT_PIN)]
        records = evidence['records']
        records.update(findings=[dict(id=1, service_id=41, cve='CVE-X', active=True)],
            finding_observations=[dict(id=2, finding_id=1, execution_id=42, image=source, image_digest=IMPORT_PIN)])
        extension = evidence['extension']
        extension['display']['services_row'].update(compliant=condition == 'clean', evidence_state='Complete')
        extension['finding_decisions'] = [dict(finding_id=1, noncompliant=condition != 'clean',
                                                  excepted=condition == 'excepted', vex_excluded=False)]
        extension['observation_decisions'] = [dict(observation_id=2, excluded=True)] if condition == 'observation_excluded' else []
    capture(imported, change, seal=condition != 'tampered')
    pin = IMPORT_CHILD if condition == 'unscanned_child' else IMPORT_PIN
    verdict = evaluate_observation(imported.db, {'service_scope': 'all'}, observed(pin, 'registry.example/published/nginx'), IMPORT_NOW)
    assert verdict['status'] == 'approved'
    assessment = verdict.get('scan_assessment')
    assert (assessment and assessment['status']) == expected
    assert not assessment or ('execution_id' not in assessment and assessment['source'] == 'publisher_capture'
                              and assessment['scanned_at'] == IMPORT_NOW.isoformat())


def test_local_scan_posture_reads_latest_scan_without_transferring_history(runtime):
    from sqlalchemy import event
    from app.runtime_scan_assessment import _latest_scan
    db = runtime.db
    for number in range(30):
        raw = dict(complete=True, service={'id': 'oci'}, scan_scope='service',
                   sbom_components=[{'image': 'registry.example/team/obsolete', 'digest': 'sha256:' + 'e' * 64}])
        db.add(Execution(service_id=runtime.approval.service_id, execution_key=f'older-{number}',
            scanned_at=NOW - timedelta(days=number + 1), complete=True, scan_scope='service',
            raw_payload=raw, payload_digest=payload_digest(raw)))
    db.commit()
    statements = []
    def record(_conn, _cursor, sql, *_args):
        if 'FROM executions' in sql:
            statements.append(sql)
    event.listen(db.get_bind(), 'before_cursor_execute', record)
    try:
        assert _latest_scan(db, runtime.approval.service_id) is None  # The newest execution has no verifiable scan.
    finally:
        event.remove(db.get_bind(), 'before_cursor_execute', record)
    assert len(statements) == 1 and 'LIMIT' in statements[0]
