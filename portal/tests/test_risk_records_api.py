"""Supplemental evidence browsing remains bounded, scoped, and non-authoritative."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import risk_routes as routes
from app.auth import AuthContext, require_user
from app.database import Base
from app.intelligence_models import IntelligencePackageInstall, IntelligenceRecord
from app.models import Service
from app.vex_models import VexSource


def auth(permissions=('service.view',), service_id=1):
    assignment = SimpleNamespace(role=SimpleNamespace(name='Viewer', permissions=list(permissions)),
                                 service_id=service_id, group_id=None, group=None)
    return AuthContext(user=SimpleNamespace(id=None, username='viewer', role_assignments=[assignment]),
                       session=SimpleNamespace(csrf_token='csrf'))


@pytest.fixture
def api():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Service(id=1, service_key='one', name='One'),
                    VexSource(id=1, name='Vendor advisory', enabled=True),
                    VexSource(id=2, name='Disabled source', enabled=False)])
        db.commit()
        app = FastAPI()
        app.include_router(routes.router)
        state = {'auth': auth()}
        app.dependency_overrides[require_user] = lambda: state['auth']
        app.dependency_overrides[routes.get_db] = lambda: db
        with TestClient(app) as client:
            yield client, db, state, app
    engine.dispose()


def add_record(db, *, cve='CVE-2026-12345', source_id=1, kind='advisory', data=None, **fields):
    identity = (db.scalar(select(func.max(IntelligenceRecord.id))) or 0) + 1
    item = IntelligenceRecord(id=identity, source_id=source_id, kind=kind, record_id=f'vendor-{identity}',
        cve=cve, product='pkg:rpm/suse/example@1', data=data if data is not None else {'status': 'recommended'},
        sha256=f'{identity:064x}', acquired_at=datetime(2026, 10, 19, tzinfo=timezone.utc),
        source_url='https://vendor.example/advisory', package_version='first-import')
    for key, value in fields.items():
        setattr(item, key, value)
    db.add(item)
    db.commit()
    return item.id


def test_exact_cve_filters_and_cursor_do_not_load_publisher_data(api):
    client, db, _, _ = api
    first = add_record(db)
    second = add_record(db)
    add_record(db, cve='CVE-2026-123456')
    add_record(db, source_id=2)
    add_record(db, kind='vulnerability')
    statements = []
    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(db.get_bind(), 'before_cursor_execute', capture)
    try:
        response = client.get('/api/risk/records', params={'cve': 'CVE-2026-12345', 'kind': 'advisory', 'source_id': 1, 'limit': 1})
    finally:
        event.remove(db.get_bind(), 'before_cursor_execute', capture)
    assert response.status_code == 200
    page = response.json()
    assert [item['id'] for item in page['items']] == [first]
    assert page['next_cursor'] == first
    assert all('intelligence_records.data' not in sql for sql in statements)
    response = client.get('/api/risk/records', params={'cve': 'CVE-2026-12345', 'kind': 'advisory', 'source_id': 1, 'limit': 1, 'cursor': first})
    assert [item['id'] for item in response.json()['items']] == [second]
    assert response.json()['next_cursor'] is None
    assert client.get('/api/risk/records', params={'cve': 'CVE-2026-99999'}).json()['items'] == []


@pytest.mark.parametrize('params', [{}, {'cve': 'CVE-2026-'}, {'cve': '%12345%'}, {'cve': 'cve-2026-12345'},
    {'cve': 'CVE-2026-12345', 'kind': 'vex'}, {'cve': 'CVE-2026-12345', 'limit': 101},
    {'cve': 'CVE-2026-12345', 'limit': 0}, {'cve': 'CVE-2026-12345', 'cursor': -1},
    {'cve': 'CVE-2026-12345', 'cursor': 2**64}, {'cve': 'CVE-2026-12345', 'source_id': 0},
    {'cve': 'CVE-2026-12345', 'source_id': 2**64}])
def test_query_validation(api, params):
    assert api[0].get('/api/risk/records', params=params).status_code == 422


def test_access_requires_authenticated_viewer_and_is_read_only(api):
    client, db, state, app = api
    identity = add_record(db)
    paths = ['/api/risk/records?cve=CVE-2026-12345', f'/api/risk/records/{identity}']
    state['auth'] = auth(())
    assert [client.get(path).status_code for path in paths] == [403, 403]
    state['auth'] = auth(('config.manage',), None)
    assert [client.get(path).status_code for path in paths] == [200, 200]
    del app.dependency_overrides[require_user]
    responses = [client.get(path, follow_redirects=False) for path in paths]
    assert [response.status_code for response in responses] == [303, 303]
    assert all(response.headers['location'].startswith('/login?next=/api/risk/records') for response in responses)
    assert client.post(f'/api/risk/records/{identity}', json={'data': {}}).status_code == 405
    assert db.scalar(select(func.count()).select_from(IntelligenceRecord)) == 1


def test_provenance_is_first_import_not_latest_membership_or_applicability(api):
    client, db, _, _ = api
    identity = add_record(db, source_id=2, data={'status': 'not_affected', 'raw': {'publisher': 'Original'}})
    db.add(IntelligencePackageInstall(version='latest-package', sequence=9, manifest={'sources': []}, counts={}))
    db.commit()
    summary = client.get('/api/risk/records?cve=CVE-2026-12345').json()['items'][0]
    assert summary['provenance']['first_import_package_version'] == 'first-import'
    assert summary['current_package_membership'] == 'not_evaluated'
    assert summary['retained_history'] is True
    assert summary['applicability'] == 'not_evaluated'
    assert summary['category'] == 'supplemental'
    assert summary['source'] == {'id': 2, 'name': 'Disabled source', 'enabled': False}
    assert 'status' not in summary and 'data' not in summary
    detail = client.get(f'/api/risk/records/{identity}').json()
    assert detail['data'] == {'status': 'not_affected', 'raw': {'publisher': 'Original'}}
    assert 'status' not in detail
    assert client.get('/api/risk/records/99999').status_code == 404
    assert client.get(f'/api/risk/records/{2**64}').status_code == 422


def test_summary_truncation_is_explicit_and_oversized_detail_is_not_loaded(api):
    client, db, _, _ = api
    identity = add_record(db, record_id='r' * 1000, product='p' * 5000, source_url='https://example.test/' + 'x' * 5000,
                          data={'raw': 'x' * routes.MAX_RECORD_DETAIL_BYTES})
    response = client.get('/api/risk/records?cve=CVE-2026-12345')
    summary = response.json()['items'][0]
    assert summary['truncated_summary_fields'] == ['record_id', 'product', 'source_url']
    assert len(summary['record_id']) == 512 and len(summary['product']) == 2048
    assert len(summary['provenance']['source_url']) == 4096
    response = client.get(f'/api/risk/records/{identity}')
    assert response.status_code == 413 and len(response.content) < 200


def test_detail_limit_includes_response_wrapper(api, monkeypatch):
    client, db, _, _ = api
    monkeypatch.setattr(routes, 'MAX_RECORD_DETAIL_BYTES', 1024)
    identity = add_record(db, data={'raw': 'x' * 700})
    assert client.get(f'/api/risk/records/{identity}').status_code == 413
