"""Direct requests exercise the production router and persisted authorization."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import main
from app.auth import SESSION_COOKIE, SYSTEM_ROLES, token_hash
from app.database import get_db
from app.models import Role, Service, ServiceImage, UserRoleAssignment, UserSession
from test_replica_authorization import replica


@pytest.fixture
def portal(replica, monkeypatch):
    with replica.sessions() as db:
        role = Role(name='Administrator', permissions=SYSTEM_ROLES['Administrator'], system=True)
        db.add(role)
        db.flush()
        db.add(UserRoleAssignment(user_id=replica.user_id, role_id=role.id))
        db.add(UserSession(user_id=replica.user_id, token_hash=token_hash('replica-session'),
            csrf_token='replica-csrf', expires_at=replica.now + timedelta(days=1)))
        db.commit()

    def database():
        with replica.sessions() as db:
            yield db

    monkeypatch.setitem(main.app.dependency_overrides, get_db, database)
    # Request dispatch uses the real routes, middleware and session dependencies;
    # lifespan is deliberately not entered to avoid unrelated assessment workers.
    client = TestClient(main.app)
    client.cookies.set(SESSION_COOKIE, 'replica-session')
    client.headers['X-CSRF-Token'] = 'replica-csrf'
    yield client
    client.close()


@pytest.mark.parametrize('method,path', [
    ('POST', '/admin/services/replica-nginx'),
    ('POST', '/services/replica-nginx/delete'),
    ('POST', '/scan'),
    ('POST', '/patch'),
    ('POST', '/services/replica-nginx/remediate'),
    ('POST', '/findings/1/exceptions'),
    ('POST', '/findings/1/poams'),
    ('POST', '/services/replica-nginx/mitigations'),
    ('POST', '/api/risk/services/replica-nginx/assess'),
    ('POST', '/api/risk/services/replica-nginx/decisions'),
    ('POST', '/api/cyber-approvals/1/decision'),
    ('POST', '/api/cyber-approvals'),
    ('POST', '/api/approved-releases/1/revoke'),
    ('POST', '/api/approved-releases/1/revision/extend'),
    ('POST', '/services/replica-nginx/artifacts/images/1/scan'),
    ('POST', '/services/replica-nginx/artifacts/images/1/replace'),
    ('POST', '/services/replica-nginx/scan-schedule'),
    ('POST', '/api/public/jobs/upstream-scan/ingest'),
    ('GET', '/api/public/jobs/upstream-scan/results'),
])
def test_production_router_rejects_authoritative_writes_even_for_administrator(portal, method, path):
    assert any(method in getattr(route, 'methods', set()) and route.path_regex.fullmatch(path)
               for route in main.app.routes), 'Test must exercise a registered production route'
    response = portal.request(method, path, json={})
    assert response.status_code == 403
    assert response.json()['code'] == 'replica_read_only'
    assert {value.strip().lower() for value in response.headers['cache-control'].split(',')} == {'private', 'no-store'}


@pytest.mark.parametrize('operating_mode', ['replica', 'full'])
@pytest.mark.parametrize('service_key', ['replica-nginx', 'local-nginx'])
@pytest.mark.parametrize('local_job', [None, {'status': 'complete'}, {'status': 'error', 'error': 'local error'}])
def test_only_full_mode_reconciles_locally_authored_scan_jobs(replica, portal, monkeypatch, operating_mode, service_key, local_job):
    monkeypatch.setenv('CATS_MODE', operating_mode)
    with replica.sessions() as db:
        service_id = replica.service_id
        if service_key == 'local-nginx':
            service = Service(service_key=service_key, name='Locally authored nginx')
            db.add(service)
            db.flush()
            service_id = service.id
        image = ServiceImage(service_id=service_id, image_reference='registry.example/nginx:approved',
            image_digest=replica.old, scan_status='queued', scan_job_id='publisher-job',
            scan_error='retained diagnostic', updated_at=replica.now - timedelta(days=1))
        db.add(image)
        db.commit()
    monkeypatch.setattr(main, 'PUBLIC_JOBS', {'publisher-job': local_job} if local_job else {})
    response = portal.get(f'/api/services/{service_key}/artifacts/images/status')
    assert response.status_code == 200
    with replica.sessions() as db:
        image = db.scalar(select(ServiceImage).where(ServiceImage.service_id == service_id))
        if operating_mode == 'replica' or service_key == 'replica-nginx':
            assert response.json()['images'][0]['status'] == image.scan_status == 'queued'
            assert response.json()['images'][0]['error'] == image.scan_error == 'retained diagnostic'
            assert image.last_scanned_at is None
        else:
            expected = 'scanned' if local_job and local_job['status'] == 'complete' else 'failed'
            assert response.json()['images'][0]['status'] == image.scan_status == expected
            if expected == 'scanned':
                assert image.last_scanned_at is not None
            else:
                assert image.scan_error != 'retained diagnostic'
