"""Copyable commands use the same service-bound live authority as real pulls."""
from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import HTTPException, Response
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app import main, oci_proxy, oci_pull_instructions as instructions, release_revisions
from app.auth import AuthContext
from app.cyber_approvals import CyberApproval, digest as snapshot_digest
from app.database import Base
from app.execution_summaries import payload_digest
from app.models import Execution, Role, Service, ServiceImage, User, UserRoleAssignment
from app.oci_models import OCIRepository, OCIServicePullAccess, OCIUpstream, parse_service_repository
from app.release_validity import new_validity
from test_replica_authorization import replica

DIGEST = 'sha256:' + 'a' * 64


def viewer(db, service_id):
    user = User(username='pull-viewer', display_name='Service viewer')
    role = Role(name='Pull reader', permissions=['service.view'])
    assignment = UserRoleAssignment(user=user, role=role, service_id=service_id)
    db.add_all([user, role, assignment])
    db.commit()
    return AuthContext(user, SimpleNamespace(csrf_token='unused'))


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setenv('CATS_OCI_HOSTNAME', 'cats.example')
    monkeypatch.setattr(main, 'service_view', lambda *args: {'incomplete': False, 'compliant': True})
    def network_forbidden(*args):
        raise AssertionError('Pull instructions must not contact a registry')
    monkeypatch.setattr(oci_proxy, 'client', network_forbidden)
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        now = datetime.now(timezone.utc)
        service = Service(service_key='nginx', name='Nginx')
        upstream = OCIUpstream(name='Registry', endpoint='https://registry.example')
        db.add_all([service, upstream]); db.flush()
        image = ServiceImage(service_id=service.id, image_reference='registry.example/team/nginx:1.27', image_digest=DIGEST)
        execution = Execution(service_id=service.id, execution_key='scan', scanned_at=now,
                              complete=True, scan_scope='service', raw_payload={})
        mapping = OCIRepository(public_repository='cyber-approved/nginx', upstream_repository='team/nginx',
                                service_id=service.id, upstream_id=upstream.id)
        db.add_all([image, execution, mapping]); db.flush()
        snapshot = dict(service_id=service.id, source_execution_id=execution.id, source_version_id=None,
                        source_payload_digest=payload_digest({}), approval_validity=new_validity(now),
                        artifacts=[dict(kind='image', reference='registry.example/team/nginx@'+DIGEST, digest=DIGEST)])
        approval = CyberApproval(service_id=service.id, source_execution_id=execution.id, variant='current',
            status='approved', snapshot=snapshot, snapshot_digest=snapshot_digest(snapshot), decided_at=now)
        db.add(approval); db.commit()
        auth = viewer(db, service.id)
        yield SimpleNamespace(db=db, service=service, image=image, mapping=mapping, upstream=upstream,
                              approval=approval, execution=execution, auth=auth)
    engine.dispose()


def pull(fixture):
    return instructions.pull_instructions(fixture.service.service_key, fixture.image.id, fixture.db, fixture.auth)


def test_exact_command_uses_service_identity_digest_and_scoped_view_permission(local):
    response = Response()
    result = instructions.pull_instructions('nginx', local.image.id, local.db, local.auth, response)
    assert response.headers['Cache-Control'] == 'private, no-store'
    assert result['status'] == 'available'
    route = result['routes'][0]
    assert route['command'] == f'docker pull cats.example/cyber-approved/{local.service.id}/nginx@{DIGEST}'
    assert route['login_command'] == 'docker login cats.example'
    assert route['login_required'] is True and route['anonymous_pull'] is False
    assert parse_service_repository(route['repository'])[0] == local.service.id
    assert not local.auth.has('release.destination.manage')
    assert instructions.pull_instructions('nginx', local.image.id, local.db, local.auth) == result


def test_service_visibility_changes_login_instructions_but_not_approval(local):
    access = OCIServicePullAccess(service_id=local.service.id, public=True)
    local.db.add(access)
    local.db.commit()
    route = pull(local)['routes'][0]
    assert route['anonymous_pull'] is True and route['login_required'] is False
    assert route['login_command'] is None
    assert route['command'] == f'docker pull cats.example/cyber-approved/{local.service.id}/nginx@{DIGEST}'
    access.public = False
    local.db.commit()
    assert pull(local)['routes'][0]['login_command'] == 'docker login cats.example'
    access.public = True
    local.approval.revoked_at = datetime.now(timezone.utc)
    local.db.commit()
    assert pull(local)['status'] == 'unavailable'


def test_project_mapping_uses_full_repository_path_and_mapping_precedence(local):
    local.mapping.service_id = None
    local.mapping.public_repository = 'cyber-approved/*'
    local.mapping.upstream_repository = 'team/*'
    local.image.image_reference = 'registry.example/team/nested/nginx:1.27'
    snapshot = deepcopy(local.approval.snapshot)
    snapshot['artifacts'][0]['reference'] = 'registry.example/team/nested/nginx@'+DIGEST
    local.approval.snapshot, local.approval.snapshot_digest = snapshot, snapshot_digest(snapshot)
    local.db.commit()
    assert pull(local)['routes'][0]['repository'] == f'cyber-approved/{local.service.id}/nested/nginx'
    other = Service(service_key='other', name='Other')
    local.db.add(other); local.db.flush()
    local.db.add(OCIRepository(public_repository=f'cyber-approved/{local.service.id}/nested/nginx',
        upstream_repository='team/nested/nginx', service_id=other.id, upstream_id=local.upstream.id))
    local.db.commit()
    assert pull(local)['status'] == 'unavailable'


@pytest.mark.parametrize('change', ['revoked', 'wrong_digest', 'wrong_repository', 'disabled', 'inactive', 'removed_image'])
def test_unavailable_never_advertises_a_command(local, change):
    if change == 'revoked':
        local.approval.revoked_at = datetime.now(timezone.utc)
    elif change == 'wrong_digest':
        local.image.image_digest = 'sha256:' + 'b' * 64
    elif change == 'wrong_repository':
        local.image.image_reference = 'registry.example/team/not-nginx:1.27'
    elif change == 'disabled':
        local.mapping.enabled = False
    elif change == 'inactive':
        local.service.lifecycle_status = 'staged'
    else:
        local.image.lifecycle_status = 'removed'
    local.db.commit()
    result = pull(local)
    assert result['status'] == 'unavailable' and result['routes'] == [] and result['reason']


def test_same_bytes_do_not_borrow_another_service_approval(local):
    other = Service(service_key='other', name='Other')
    local.db.add(other); local.db.flush()
    image = ServiceImage(service_id=other.id, image_reference=local.image.image_reference, image_digest=DIGEST)
    mapping = OCIRepository(service_id=other.id, upstream_id=local.upstream.id,
        public_repository='cyber-approved/other-nginx', upstream_repository='team/nginx')
    local.db.add_all([image, mapping])
    local.auth.user.role_assignments[0].service_id = None
    local.db.commit()
    assert pull(local)['status'] == 'available'
    result = instructions.pull_instructions(other.service_key, image.id, local.db, local.auth)
    assert result['status'] == 'unavailable' and not result['routes']


def test_cross_service_image_id_and_view_scope_are_enforced(local):
    other = Service(service_key='other', name='Other')
    local.db.add(other); local.db.flush()
    image = ServiceImage(service_id=other.id, image_reference=local.image.image_reference, image_digest=DIGEST)
    local.db.add(image); local.db.commit()
    for key, identity in [('nginx', image.id), ('other', image.id), ('unknown', local.image.id)]:
        with pytest.raises(HTTPException) as denied:
            instructions.pull_instructions(key, identity, local.db, local.auth)
        assert denied.value.status_code == 404


@pytest.mark.parametrize('value', ['', 'https://cats.example', 'cats.example/path', 'cats.example;whoami',
    'cats.example$(whoami)', 'cats.example\nwhoami', '-cats.example', 'cats.example:0', 'cats.example:65536',
    'cats.example:', 'user@cats.example', 'cats.example --help', '[not-ipv6]'])
def test_missing_or_unsafe_host_cannot_enter_shell_commands(local, monkeypatch, value):
    monkeypatch.setenv('CATS_OCI_HOSTNAME', value)
    result = pull(local)
    assert result['status'] == 'unavailable' and not result['routes'] and result['reason']


@pytest.mark.parametrize('host', ['cats.example:5443', 'localhost:5000', '127.0.0.1:5000', '[::1]:5000'])
def test_registry_authority_supports_configured_ports_and_ipv6(local, monkeypatch, host):
    monkeypatch.setenv('CATS_OCI_HOSTNAME', host)
    result = pull(local)
    assert result['status'] == 'available'
    assert result['routes'][0]['reference'].startswith(host+'/')
    assert result['registry'] == host


def test_missing_digest_is_explicit_and_never_resolves_mutable_tag(local):
    local.image.image_digest = None
    local.db.commit()
    result = pull(local)
    assert result['status'] == 'unavailable' and 'digest' in result['reason'] and not result['routes']


def test_verified_publication_follows_original_identity_into_release_repository(local):
    local.image.image_reference = 'build.example/team/nginx:1.27'
    snapshot = deepcopy(local.approval.snapshot)
    snapshot['artifacts'][0]['reference'] = 'build.example/team/nginx@'+DIGEST
    local.approval.snapshot, local.approval.snapshot_digest = snapshot, snapshot_digest(snapshot)
    target_digest = 'sha256:' + 'd' * 64
    artifact = dict(kind='image', source_digest=DIGEST, reference='registry.example/releases/image-0@'+target_digest,
        digest=target_digest, scan_identity_retained=True, identity_resolution='retained-evidence', verification_status='verified')
    local.approval.publish_status = 'published'
    local.approval.publication = dict(status='published', verification_status='verified', signature_status='verified',
        artifacts=[artifact], manifest=dict(approval_id=local.approval.id,
            snapshot_digest=local.approval.snapshot_digest, artifacts=[artifact]))
    local.mapping.upstream_repository = 'releases/image-0'
    local.db.commit()
    result = pull(local)
    assert result['status'] == 'available'
    assert result['routes'][0]['digest'] == target_digest
    receipt = deepcopy(local.approval.publication)
    receipt['artifacts'][0]['source_digest'] = 'sha256:' + 'e' * 64
    local.approval.publication = receipt
    local.db.commit()
    assert pull(local)['status'] == 'unavailable'


def test_signed_revision_location_uses_original_mapping_identity(local, monkeypatch):
    original_location = local.mapping.upstream_repository
    local.mapping.upstream_repository = 'old/nginx'
    binding = dict(repository_id=local.mapping.id, upstream_id=local.upstream.id,
        endpoint=local.upstream.endpoint, public_repository=local.mapping.public_repository,
        mapping_upstream_repository='old/nginx', upstream_repository=original_location, artifact_id=1, digest=DIGEST)
    manifest = {'artifacts': [{'id': 1, 'digest': DIGEST}], 'distribution_bindings': [binding]}
    revision = release_revisions.ReleaseRevision(service_id=local.service.id, approval_id=local.approval.id,
        manifest=manifest, manifest_digest=snapshot_digest(manifest))
    local.db.add(revision); local.db.flush()
    local.db.add_all([release_revisions.ReleaseRevisionState(revision_id=revision.id, decision='approved'),
        release_revisions.ServiceActiveRelease(service_id=local.service.id, revision_id=revision.id)])
    local.db.commit()
    # Signature mechanics have their own suite; preserve and exercise real
    # signed binding validation, active pointer, and live approval adjudication.
    monkeypatch.setattr(release_revisions, 'validate_activation', lambda *args: None)
    assert pull(local)['status'] == 'available'
    local.mapping.upstream_repository = 'tampered/nginx'
    local.db.commit()
    assert pull(local)['status'] == 'unavailable'


def test_full_mode_imported_image_uses_retained_source_and_verified_local_repository(replica, monkeypatch):
    from app.replica_models import ReplicaRelease, ReplicaServiceState
    from app.replica_integrity import seal_record
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setenv('CATS_OCI_HOSTNAME', 'cats.example')
    with replica.sessions() as db:
        release = db.get(ReplicaRelease, replica.new_id)
        source_digest = 'sha256:' + 'f' * 64
        artifact = dict(release.artifacts[0], reference='registry.example/team/nginx@'+replica.new,
            source_reference='docker.io/library/nginx@'+source_digest, source_digest=source_digest,
            scan_identity_retained=True, identity_resolution='retained-evidence', verification_status='verified')
        release.artifacts = [artifact]
        seal_record(release)
        image = ServiceImage(service_id=replica.service_id, image_reference='nginx:1.27', image_digest=source_digest)
        db.add(image); db.commit()
        auth = viewer(db, replica.service_id)
        result = instructions.pull_instructions('replica-nginx', image.id, db, auth)
        assert result['status'] == 'available'
        assert result['routes'][0]['reference'] == f'cats.example/replica/{replica.service_id}/nginx@{replica.new}'
        db.delete(db.get(ReplicaServiceState, replica.service_id)); db.commit()
        assert instructions.pull_instructions('replica-nginx', image.id, db, auth)['status'] == 'unavailable'
