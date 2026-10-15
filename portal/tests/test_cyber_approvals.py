"""Approval API boundaries; retained evidence generation has its own integration tests."""
import asyncio
import copy
import hashlib
import json
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app import cyber_approvals as approvals
from app import cyber_approval_evidence as evidence
from app.auth import AuthContext
from app.database import Base
from app.durable_jobs import DurableJob
from app.models import Execution, Group, Service, utcnow
from app.secrets import decrypt_secret

PERMISSIONS = ('service.view', 'service.export', 'approval.request', 'approval.decide', 'release.destination.manage')


def auth(service=1, permissions=PERMISSIONS):
    assignment = SimpleNamespace(role=SimpleNamespace(name='Reviewer', permissions=list(permissions)),
                                 service_id=service, group_id=None, group=None)
    return AuthContext(user=SimpleNamespace(id=None, username='reviewer', display_name='Reviewer', role_assignments=[assignment]),
                       session=SimpleNamespace(csrf_token='csrf'))


def request(data=None, token='csrf'):
    async def receive():
        return {'type': 'http.request', 'body': json.dumps(data or {}).encode()}
    return Request({'type': 'http', 'method': 'POST', 'headers': [(b'x-csrf-token', token.encode())]}, receive)


@pytest.fixture
def db(monkeypatch, tmp_path):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        group = Group(name='Delivery')
        service = Service(service_key='one', name='One', groups=[group])
        session.add_all([service, Service(service_key='two', name='Two')])
        session.flush()
        execution = Execution(service_id=service.id, execution_key='scan-one', scanned_at=utcnow(), complete=True,
                              raw_payload={'version': '1.0', 'findings': [{'cve': 'CVE-2026-1234'}]})
        destination = approvals.ApprovedReleaseDestination(name='Approved', endpoint='https://registry.example',
                                                           namespace='approved', group_ids=[group.id])
        session.add_all([execution, destination])
        session.commit()
        monkeypatch.setattr(approvals, 'root', lambda: tmp_path)
        monkeypatch.setattr(approvals, 'record_audit', lambda *args, **kwargs: None)
        monkeypatch.setattr(approvals.signing, 'configuration', lambda _: {'fingerprint': 'key-fingerprint'})
        monkeypatch.setattr(approvals, '_readiness', lambda *args: {
            'ready': True, 'blockers': [], 'execution': execution, 'remediation': None})
        def freeze(db, service, actor, readiness, folder):
            retained = folder / 'all.zip'
            retained.write_bytes(b'retained-evidence')
            return {'version': execution.raw_payload['version'], 'scan_date': execution.scanned_at.isoformat(),
                    'findings': copy.deepcopy(execution.raw_payload['findings']), 'artifacts': [],
                    'evidence': {'path': str(retained), 'digest': 'sha256:' + hashlib.sha256(retained.read_bytes()).hexdigest()}}
        monkeypatch.setattr(evidence, 'freeze', freeze)
        yield session
    engine.dispose()


def create(db, actor=None):
    return asyncio.run(approvals.request_approval(request({'service_key': 'one', 'destination_id': 1,
        'variant': 'current_service', 'rationale': 'Release review'}), db, actor or auth()))


def decide(db, identity, choice='approved', actor=None):
    return asyncio.run(approvals.decide(identity, request({'decision': choice, 'rationale': 'Reviewed retained evidence'}), db, actor or auth()))


def test_submission_freezes_evidence_and_destination_without_private_fields(db):
    result = create(db)
    row = db.get(approvals.CyberApproval, result['id'])
    original = copy.deepcopy(row.snapshot)
    execution = db.get(Execution, row.source_execution_id)
    execution.raw_payload = {'version': '2.0', 'findings': []}
    destination = db.get(approvals.ApprovedReleaseDestination, row.destination_id)
    destination.endpoint = 'https://replacement.example'
    db.commit()
    read = approvals.approval(row.id, db, auth())
    assert row.snapshot == original
    assert read['version'] == '1.0'
    assert read['destination']['endpoint'] == 'https://registry.example'
    assert read['snapshot']['findings'][0]['cve'] == 'CVE-2026-1234'
    assert 'path' not in read['snapshot']['evidence']
    assert read['snapshot_digest'] == approvals.digest(original)
    assert read['evidence_url'].endswith('/download/evidence')


def test_approval_enqueues_once_and_repeated_decision_conflicts(db):
    identity = create(db)['id']
    decided = decide(db, identity)
    assert (decided['status'], decided['publish_status']) == ('approved', 'queued')
    jobs = list(db.scalars(select(DurableJob)))
    assert len(jobs) == 1
    assert jobs[0].id == db.get(approvals.CyberApproval, identity).job_id
    assert jobs[0].payload == {'approval_id': identity}
    with pytest.raises(HTTPException) as conflict:
        decide(db, identity, 'denied')
    assert conflict.value.status_code == 409
    assert len(list(db.scalars(select(DurableJob)))) == 1
    assert db.get(approvals.CyberApproval, identity).status == 'approved'


def test_denial_never_enqueues_and_is_not_an_approved_release(db):
    identity = create(db)['id']
    denied = decide(db, identity, 'denied')
    assert denied['status'] == 'denied'
    assert denied['publish_status'] == 'not_started'
    assert not list(db.scalars(select(DurableJob)))
    assert approvals.releases(db=db, auth=auth())['items'] == []
    with pytest.raises(HTTPException) as missing:
        approvals.release(identity, db, auth())
    assert missing.value.status_code == 404


def test_snapshot_integrity_and_required_rationale_guard_decisions(db):
    identity = create(db)['id']
    with pytest.raises(HTTPException) as invalid:
        asyncio.run(approvals.decide(identity, request({'decision': 'approved', 'rationale': ' '}), db, auth()))
    assert invalid.value.status_code == 422
    row = db.get(approvals.CyberApproval, identity)
    row.snapshot = {**row.snapshot, 'version': 'tampered'}
    db.commit()
    with pytest.raises(HTTPException) as conflict:
        decide(db, identity)
    assert conflict.value.status_code == 409
    assert row.status == 'pending'
    assert not list(db.scalars(select(DurableJob)))


def test_retry_only_failed_approved_release_and_no_duplicate_job(db):
    identity = create(db)['id']
    decide(db, identity)
    row = db.get(approvals.CyberApproval, identity)
    row.publish_status = 'failed'
    db.commit()
    retried = approvals.retry(identity, request(), db, auth())
    assert retried['publish_status'] == 'queued'
    assert len(list(db.scalars(select(DurableJob)))) == 2
    with pytest.raises(HTTPException) as conflict:
        approvals.retry(identity, request(), db, auth())
    assert conflict.value.status_code == 409
    row.publish_status = 'failed'
    row.revoked_at = utcnow()
    db.commit()
    with pytest.raises(HTTPException) as revoked:
        approvals.retry(identity, request(), db, auth())
    assert revoked.value.status_code == 409
    assert len(list(db.scalars(select(DurableJob)))) == 2


@pytest.mark.parametrize('actor,expected', [(auth(2), 404), (auth(1, ('service.view',)), 403), (auth(), 200)])
def test_http_request_scope_and_permission(db, actor, expected):
    app = FastAPI()
    app.include_router(approvals.router)
    app.dependency_overrides[approvals.get_db] = lambda: db
    app.dependency_overrides[approvals.require_user] = lambda: actor
    with TestClient(app) as client:
        response = client.post('/api/cyber-approvals', headers={'X-CSRF-Token': 'csrf'},
                               json={'service_key': 'one', 'destination_id': 1})
    assert response.status_code == expected


def test_csrf_missing_evidence_and_destination_group_gates(db, monkeypatch):
    with pytest.raises(HTTPException) as csrf:
        asyncio.run(approvals.request_approval(request({}, 'bad'), db, auth()))
    assert csrf.value.status_code == 403
    destination = db.get(approvals.ApprovedReleaseDestination, 1)
    destination.group_ids = [999]
    db.commit()
    with pytest.raises(HTTPException) as scoped:
        create(db)
    assert scoped.value.status_code == 422
    monkeypatch.setattr(approvals, '_readiness', lambda *args: {'ready': False, 'blockers': ['Missing image digest']})
    with pytest.raises(HTTPException) as blocked:
        create(db)
    assert blocked.value.status_code == 409
    assert blocked.value.detail['blockers'] == ['Missing image digest']
    assert not list(db.scalars(select(approvals.CyberApproval)))


def test_destination_secrets_rotation_defaults_and_group_validation(db):
    admin = auth(None)
    def save(body):
        return asyncio.run(approvals.save_destination(request(body), db, admin))
    created = save({'name': 'Private', 'endpoint': 'https://private.example', 'namespace': 'approved',
                    'username': 'registry-user', 'password': 'registry-secret', 'group_ids': [1], 'is_default': True})
    row = db.get(approvals.ApprovedReleaseDestination, created['id'])
    assert decrypt_secret(row.password) == 'registry-secret'
    assert decrypt_secret(row.username) == 'registry-user'
    public = json.dumps(approvals.destinations(db, admin))
    assert 'registry-secret' not in public and 'registry-user' not in public
    assert 'password' not in created and 'username' not in created
    save({'id': row.id, 'name': 'Renamed', 'password': ''})
    assert decrypt_secret(row.password) == 'registry-secret'
    save({'name': 'New default', 'endpoint': 'https://other.example', 'is_default': True})
    db.refresh(row)
    assert not row.is_default
    with pytest.raises(HTTPException) as invalid:
        save({'name': 'Invalid', 'endpoint': 'https://invalid.example', 'group_ids': [999]})
    assert invalid.value.status_code == 422
    with pytest.raises(HTTPException) as denied:
        approvals.destinations(db, auth(1, ('service.view',)))
    assert denied.value.status_code == 403


def test_download_rechecks_export_scope_digest_and_containment(db, tmp_path):
    identity = create(db)['id']
    row = db.get(approvals.CyberApproval, identity)
    response = approvals.download(identity, 'evidence', db, auth())
    assert response.filename == 'all.zip'
    with pytest.raises(HTTPException) as permission:
        approvals.download(identity, 'evidence', db, auth(1, ('service.view',)))
    assert permission.value.status_code == 403
    with pytest.raises(HTTPException) as scope:
        approvals.download(identity, 'evidence', db, auth(2))
    assert scope.value.status_code == 404
    with pytest.raises(HTTPException) as unavailable:
        approvals.download(identity, 'offline', db, auth())
    assert unavailable.value.status_code == 404
    path = tmp_path / row.release_key / 'all.zip'
    path.write_bytes(b'changed')
    with pytest.raises(HTTPException) as corrupt:
        approvals.download(identity, 'evidence', db, auth())
    assert corrupt.value.status_code == 409
    outside = tmp_path / 'outside.zip'
    outside.write_bytes(b'outside')
    row.snapshot = {**row.snapshot, 'evidence': {'path': str(outside), 'digest': 'sha256:' + hashlib.sha256(b'outside').hexdigest()}}
    with pytest.raises(HTTPException) as escaped:
        approvals.download(identity, 'evidence', db, auth())
    assert escaped.value.status_code == 409


def test_decision_and_job_roll_back_together_when_audit_fails(db, monkeypatch):
    identity = create(db)['id']
    def failed_audit(*args, **kwargs):
        raise RuntimeError('Audit storage unavailable')
    monkeypatch.setattr(approvals, 'record_audit', failed_audit)
    with pytest.raises(RuntimeError, match='Audit storage unavailable'):
        decide(db, identity)
    db.rollback()
    row = db.get(approvals.CyberApproval, identity)
    assert row.status == 'pending'
    assert row.publish_status == 'not_started'
    assert row.job_id is None
    assert not list(db.scalars(select(DurableJob)))


@pytest.mark.parametrize('path,page', [
    ('/cyber-approvals', 'cyber_approvals'),
    ('/approved-releases', 'approved_releases'),
    ('/admin/approved-release-destinations', 'approved_release_destinations'),
])
def test_registered_pages_serve_react_html_and_page_envelopes(monkeypatch, path, page):
    from app import main
    from app.frontend import PAGE_MEDIA_TYPE
    actor = auth(None)
    monkeypatch.setattr(main, 'page_context', lambda user: {
        'current_user': user.user, 'csrf_token': 'csrf', 'can': user.has})
    registered = [route for route in main.app.routes if getattr(route, 'path', '') == path]
    assert len(registered) == 1
    app = FastAPI()
    app.add_api_route(path, registered[0].endpoint, methods=['GET'])
    app.dependency_overrides[approvals.require_user] = lambda: actor
    with TestClient(app) as client:
        response = client.get(path, headers={'Accept': PAGE_MEDIA_TYPE})
        assert response.status_code == 200
        assert response.json()['page'] == page
        assert response.json()['data']['csrf_token'] == 'csrf'
        assert response.json()['data']['can']['release.destination.manage']['*']
        html = client.get(path)
        assert html.status_code == 200
        assert 'id="cats-bootstrap"' in html.text
        bootstrap = html.text.split('id="cats-bootstrap">', 1)[1].split('</script>', 1)[0]
        assert json.loads(bootstrap)['page'] == page
        app.dependency_overrides[approvals.require_user] = lambda: auth(1, ('service.view',))
        denied = client.get('/admin/approved-release-destinations')
        assert denied.status_code == (403 if path.startswith('/admin') else 404)


def test_service_with_approval_history_cannot_be_deleted(db, monkeypatch):
    from app import main
    identity = create(db)['id']
    monkeypatch.setattr(main, 'check_csrf', lambda *_: None)
    with pytest.raises(HTTPException) as blocked:
        main.delete_service('one', 'delete One', 'Retire service', 'csrf', db, auth())
    assert blocked.value.status_code == 409
    assert 'Archive' in blocked.value.detail
    assert db.get(Service, 1) is not None
    assert db.get(approvals.CyberApproval, identity) is not None


@pytest.mark.parametrize('attribution', ['requested_by_id', 'decided_by_id'])
def test_accounts_referenced_by_approval_history_must_be_retained(db, monkeypatch, attribution):
    from app import main
    from app.models import User
    identity = create(db)['id']
    user = User(username='retained-reviewer', display_name='Retained reviewer')
    db.add(user)
    db.flush()
    setattr(db.get(approvals.CyberApproval, identity), attribution, user.id)
    db.commit()
    monkeypatch.setattr(main, 'check_csrf', lambda *_: None)
    with pytest.raises(HTTPException) as blocked:
        main.delete_user_account(user.id, 'csrf', db, auth())
    assert blocked.value.status_code == 409
    assert 'Disable' in blocked.value.detail
    assert db.get(User, user.id) is not None
    assert getattr(db.get(approvals.CyberApproval, identity), attribution) == user.id


def test_request_automatically_uses_eligible_default(db):
    chosen = approvals.ApprovedReleaseDestination(name='Default', endpoint='https://default.example',
        namespace='approved', group_ids=[], is_default=True)
    db.add(chosen); db.commit()
    result = asyncio.run(approvals.request_approval(request({'service_key': 'one', 'variant': 'current_service'}), db, auth()))
    assert result['destination']['id'] == chosen.id


def test_request_without_publication_setup_can_be_reviewed_then_bound_at_decision(db, monkeypatch):
    destination = db.get(approvals.ApprovedReleaseDestination, 1)
    destination.enabled = False
    db.commit()
    monkeypatch.setattr(approvals.signing, 'configuration', lambda _: {})
    result = asyncio.run(approvals.request_approval(request({'service_key': 'one'}), db, auth()))
    row = db.get(approvals.CyberApproval, result['id'])
    assert row.destination_id is None and row.status == 'pending'
    retained = copy.deepcopy(row.snapshot['evidence'])
    with pytest.raises(HTTPException, match='destination'):
        decide(db, row.id)
    destination.enabled = True
    db.commit()
    with pytest.raises(HTTPException, match='signing'):
        asyncio.run(approvals.decide(row.id, request({'decision':'approved', 'rationale':'Risk reviewed', 'destination_id':1}), db, auth()))
    monkeypatch.setattr(approvals.signing, 'configuration', lambda _: {'enabled':True, 'private_key':'key', 'public_key':'pub', 'fingerprint':'configured'})
    asyncio.run(approvals.decide(row.id, request({'decision':'approved', 'rationale':'Risk reviewed', 'destination_id':1}), db, auth()))
    assert row.destination_id == 1 and row.status == 'approved'
    assert row.snapshot['evidence'] == retained
    assert row.snapshot['signing_fingerprint'] == 'configured'
    assert row.snapshot_digest == approvals.digest(row.snapshot)


def test_no_destination_or_signing_does_not_block_denial(db, monkeypatch):
    db.get(approvals.ApprovedReleaseDestination, 1).enabled = False
    db.commit()
    monkeypatch.setattr(approvals.signing, 'configuration', lambda _: {})
    result = asyncio.run(approvals.request_approval(request({'service_key':'one'}), db, auth()))
    assert decide(db, result['id'], 'denied')['status'] == 'denied'


def test_approval_freezes_configured_expiry_and_retry_never_renews(db, monkeypatch):
    from datetime import timedelta
    monkeypatch.setenv('CATS_CYBER_APPROVAL_VALIDITY_DAYS', '30')
    identity = create(db)['id']
    decided = decide(db, identity)
    row = db.get(approvals.CyberApproval, identity)
    window = copy.deepcopy(row.snapshot['approval_validity'])
    assert window['validity_days'] == 30
    assert decided['validity_status'] == 'valid'
    assert decided['expires_at'] == window['expires_at']
    monkeypatch.setenv('CATS_CYBER_APPROVAL_VALIDITY_DAYS', '180')
    row.publish_status = 'failed'
    db.commit()
    approvals.retry(identity, request(), db, auth())
    assert row.snapshot['approval_validity'] == window
    assert row.snapshot_digest == approvals.digest(row.snapshot)
    old = utcnow() - timedelta(days=31)
    monkeypatch.setenv('CATS_CYBER_APPROVAL_VALIDITY_DAYS', '30')
    row.decided_at = old
    row.snapshot = {**row.snapshot, 'approval_validity': approvals.release_validity.new_validity(old)}
    row.snapshot_digest = approvals.digest(row.snapshot)
    row.publish_status = 'failed'
    db.commit()
    assert approvals.release(identity, db, auth())['validity_status'] == 'expired'
    assert not approvals.release(identity, db, auth())['can_retry']
    with pytest.raises(HTTPException) as error:
        approvals.retry(identity, request(), db, auth())
    assert error.value.status_code == 409
    assert 'expired' in error.value.detail


def test_invalid_expiry_setting_leaves_pending_decision_untouched(db, monkeypatch):
    identity = create(db)['id']
    monkeypatch.setenv('CATS_CYBER_APPROVAL_VALIDITY_DAYS', 'zero')
    with pytest.raises(HTTPException) as error:
        decide(db, identity)
    assert error.value.status_code == 422
    assert db.get(approvals.CyberApproval, identity).status == 'pending'
    assert not list(db.scalars(select(DurableJob)))


def test_approval_uses_saved_cosign_lifetime_and_freezes_it(db, monkeypatch):
    monkeypatch.setenv('CATS_CYBER_APPROVAL_VALIDITY_DAYS', '90')
    setting = approvals.PortalSetting(key=approvals.release_validity.PORTAL_SETTING, value='45')
    db.add(setting)
    db.commit()
    identity = create(db)['id']
    decide(db, identity)
    row = db.get(approvals.CyberApproval, identity)
    window = copy.deepcopy(row.snapshot['approval_validity'])
    assert window['validity_days'] == 45
    setting.value = '180'
    row.publish_status = 'failed'
    db.commit()
    approvals.retry(identity, request(), db, auth())
    assert row.snapshot['approval_validity'] == window
