"""Public service pulls retain the same object and approval boundary."""
import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from starlette.requests import Request

from app import oci_evidence, oci_proxy as proxy
from app.cyber_approvals import CyberApproval
from app.models import AuditEvent, Service, ServiceArchiveEvent
from app.oci_models import OCIPrincipal, OCIRepository, OCIServicePullAccess
from test_oci_proxy import project, registry
from test_replica_authorization import grant, replica


def request(method='GET', authorization=None):
    headers = [] if authorization is None else [(b'authorization', authorization)]
    return Request({'type': 'http', 'method': method, 'path': '/v2/', 'query_string': b'',
        'headers': headers, 'client': ('192.0.2.44', 12345)})


ROBOT = b'Basic ' + base64.b64encode(b'robot:secret')


def visibility(s, service_id, public):
    with s.sessions() as db:
        row = db.get(OCIServicePullAccess, service_id)
        if row is None:
            row = OCIServicePullAccess(service_id=service_id)
            db.add(row)
        row.public = public
        db.commit()


@pytest.fixture
def public_service(project):
    visibility(project, project.service_ids[project.scanned], True)
    return project


def get_manifest(s, reference=None, method='GET', authorization=None, repository=None):
    return proxy.get_manifest(repository or s.routes[s.scanned], reference or s.image,
                              request(method, authorization))


def get_blob(s, method='HEAD'):
    return proxy.get_blob(s.routes[s.scanned], s.blob, request(method))


def get_referrers(s):
    return proxy.referrers(s.routes[s.scanned], s.image, request())


def test_public_service_supports_anonymous_pull_and_audits_its_identity(public_service):
    s = public_service
    assert proxy.ping(request()).status_code == 200
    response = get_manifest(s, 'latest')
    assert response.status_code == 200
    assert response.headers['Docker-Content-Digest'] == s.image
    assert get_manifest(s, method='HEAD').body == b''
    blob = get_blob(s)
    assert blob.status_code == 200 and blob.headers['Content-Length'] == '10'
    assert get_referrers(s).status_code == 200
    with s.sessions() as db:
        rows = db.scalars(select(AuditEvent).where(AuditEvent.action == 'oci.pull')).all()
        assert rows
        assert all(row.detail['principal_id'] is None for row in rows)
        assert all(row.detail['authentication'] == 'anonymous' for row in rows)
        assert all(row.detail['client_address'] == '192.0.2.44' for row in rows)
        assert all(row.detail['service_id'] == s.service_ids[s.scanned] for row in rows)


def test_private_service_and_registry_probe_still_require_login(project):
    with pytest.raises(proxy.Denied) as denied:
        proxy.ping(request())
    assert denied.value.status == 401
    with pytest.raises(proxy.Denied) as denied:
        get_manifest(project)
    assert denied.value.status == 401
    assert project.fetches == []
    assert proxy.ping(request(authorization=ROBOT)).status_code == 200
    assert get_manifest(project, authorization=ROBOT).status_code == 200
    with project.sessions() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == 'oci.pull').order_by(AuditEvent.id.desc()))
        assert event.detail['authentication'] == 'machine'
        assert event.detail['principal_id'] == project.machine_id


def test_private_pull_returns_machine_challenge_and_records_anonymous_denial(project):
    s = project
    incoming = request()
    incoming.scope['path_params'] = {'repository': s.routes[s.scanned]}
    with pytest.raises(proxy.Denied) as denied:
        proxy.get_manifest(s.routes[s.scanned], s.image, incoming)
    assert s.fetches == []
    # The error adapter performs synchronous DB work and returns immediately;
    # drive it directly without a platform-dependent TestClient event loop.
    with pytest.raises(StopIteration) as completed:
        proxy.denied(incoming, denied.value).send(None)
    response = completed.value.value
    assert response.status_code == 401
    assert response.headers['WWW-Authenticate'] == 'Basic realm="CATS OCI"'
    assert json.loads(response.body)['errors'][0]['code'] == 'UNAUTHORIZED'
    with s.sessions() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == 'oci.denied')
            .order_by(AuditEvent.id.desc()))
        assert event.detail['principal_id'] is None
        assert event.detail['authentication'] == 'anonymous'
        assert event.detail['client_address'] == '192.0.2.44'
        assert event.detail['service_id'] == s.service_ids[s.scanned]


def test_public_service_does_not_open_other_service_in_same_project(public_service):
    s = public_service
    assert get_manifest(s).status_code == 200
    with pytest.raises(proxy.Denied) as denied:
        get_manifest(s, repository=s.routes[s.published])
    assert denied.value.status == 401
    visibility(s, s.service_ids[s.published], True)
    assert get_manifest(s, repository=s.routes[s.published]).status_code == 200


@pytest.mark.parametrize('authorization', [b'', b'Bearer token', b'Basic !!!',
    b'Basic ' + base64.b64encode(b'unknown:secret'),
    b'Basic ' + base64.b64encode(b'robot:incorrect'),
    b'Basic ' + base64.b64encode(b'\xff:invalid')])
def test_supplied_bad_credentials_never_fall_back_to_anonymous(public_service, authorization):
    with pytest.raises(proxy.Denied) as denied:
        get_manifest(public_service, authorization=authorization)
    assert denied.value.status == 401
    assert public_service.fetches == []


@pytest.mark.parametrize('condition', ['disabled', 'expired', 'ungranted'])
def test_existing_machine_restrictions_remain_effective_on_public_service(public_service, condition):
    s = public_service
    with s.sessions() as db:
        machine = db.get(OCIPrincipal, s.machine_id)
        if condition == 'disabled':
            machine.enabled = False
        elif condition == 'expired':
            machine.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        else:
            machine.repository_ids = []
        db.commit()
    with pytest.raises(proxy.Denied) as denied:
        get_manifest(s, authorization=ROBOT)
    assert denied.value.status == (403 if condition == 'ungranted' else 401)
    assert s.fetches == []
    assert get_manifest(s).status_code == 200


def test_public_state_and_mapping_changes_apply_to_cached_objects(public_service):
    s = public_service
    assert get_manifest(s).status_code == 200
    assert get_blob(s).status_code == 200
    visibility(s, s.service_ids[s.scanned], False)
    for operation in (get_manifest, get_blob, get_referrers):
        with pytest.raises(proxy.Denied) as denied:
            operation(s)
        assert denied.value.status == 401
    # An existing machine grant still allows the now-private service.
    assert get_manifest(s, authorization=ROBOT).status_code == 200


@pytest.mark.parametrize('state', ['mapping_disabled', 'suspended', 'upstream_disabled', 'staged', 'archived', 'revoked'])
def test_public_visibility_never_bypasses_live_release_or_mapping_denials(public_service, state):
    s = public_service
    assert get_manifest(s).status_code == 200
    assert get_blob(s).status_code == 200
    with s.sessions() as db:
        mapping = db.get(OCIRepository, s.mapping_id)
        if state == 'mapping_disabled':
            mapping.enabled = False
        elif state == 'suspended':
            mapping.suspended = True
        elif state == 'upstream_disabled':
            mapping.upstream.enabled = False
        elif state == 'staged':
            db.get(Service, s.service_ids[s.scanned]).lifecycle_status = 'staged'
        elif state == 'archived':
            db.add(ServiceArchiveEvent(service_id=s.service_ids[s.scanned], action='archive',
                reason='Retired', performed_by='Cyber'))
        else:
            db.get(CyberApproval, s.approvals[s.scanned]).revoked_at = datetime.now(timezone.utc)
        db.commit()
    for operation in (get_manifest, get_blob, get_referrers):
        with pytest.raises(proxy.Denied):
            operation(s)


def test_public_service_does_not_allow_unknown_digest_or_cross_service_bytes(public_service):
    s = public_service
    with pytest.raises((proxy.Denied, proxy.RegistryError)):
        get_manifest(s, 'sha256:' + 'a' * 64)
    visibility(s, s.service_ids[s.published], True)
    assert get_manifest(s).status_code == 200
    # The public second service has identical bytes in a different repository;
    # the first service's warmed graph does not grant access to those blobs.
    with pytest.raises(proxy.Denied):
        proxy.get_blob(s.routes[s.published], s.blob, request('HEAD'))


def test_exact_mapping_cannot_be_bypassed_by_public_project_mapping(public_service):
    s = public_service
    with s.sessions() as db:
        project_mapping = db.get(OCIRepository, s.mapping_id)
        exact = OCIRepository(public_repository=s.routes[s.scanned],
            service_id=s.service_ids[s.published], upstream_id=project_mapping.upstream_id,
            upstream_repository=s.scanned)
        db.add(exact)
        db.commit()
    with pytest.raises(proxy.Denied, match='different service'):
        get_manifest(s)
    assert s.fetches == []


@pytest.mark.parametrize('operation', ['manifest', 'blob', 'referrers'])
def test_visibility_is_rechecked_after_transport_work(public_service, monkeypatch, operation):
    s = public_service
    if operation != 'manifest':
        assert get_manifest(s).status_code == 200
    transport = proxy.client(None)
    name = {'manifest': 'fetch_manifest', 'blob': 'fetch_blob', 'referrers': 'referrers'}[operation]
    original = getattr(transport, name)

    def make_private(*args, **kwargs):
        result = original(*args, **kwargs)
        visibility(s, s.service_ids[s.scanned], False)
        return result

    setattr(transport, name, make_private)
    monkeypatch.setattr(proxy, 'client', lambda mapping: transport)
    with pytest.raises(proxy.Denied) as denied:
        {'manifest': get_manifest, 'blob': get_blob, 'referrers': get_referrers}[operation](s)
    assert denied.value.status == 401


def test_anonymous_read_opt_in_does_not_open_writes_or_offline_bundles(public_service):
    s = public_service
    with s.sessions() as db:
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            with pytest.raises(proxy.Denied) as denied:
                proxy.principal(db, request(method), s.mapping_id, allow_anonymous=True,
                                service_id=s.service_ids[s.scanned])
            assert denied.value.status == 401
    with pytest.raises(proxy.Denied) as denied:
        oci_evidence.offline(s.routes[s.scanned], s.image, request())
    assert denied.value.status == 401


def test_public_imported_service_preserves_scoped_override_audit(replica, monkeypatch):
    # Full-mode imported services use the same sealed release and override
    # evidence as replica mode; public visibility changes only authentication.
    monkeypatch.setenv('CATS_MODE', 'full')
    monkeypatch.setattr(proxy, 'SessionLocal', replica.sessions)
    visibility(replica, replica.service_id, True)

    class Transport:
        def fetch_manifest(self, repository, reference):
            if reference != replica.old:
                raise proxy.RegistryError('Missing', 404)
            return replica.raw, 'application/vnd.oci.image.manifest.v1+json', replica.old

    monkeypatch.setattr(proxy, 'client', lambda mapping: Transport())
    path = f'replica/{replica.service_id}/nginx'
    with pytest.raises(proxy.Denied):
        proxy.get_manifest(path, replica.old, request())
    grant(replica)
    assert proxy.get_manifest(path, replica.old, request()).status_code == 200
    with replica.sessions() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == 'local_override.used')
            .order_by(AuditEvent.id.desc()))
        assert event.detail['principal_id'] is None
        assert event.detail['authentication'] == 'anonymous'
        assert event.detail['service_id'] == replica.service_id
