"""Local service visibility defaults to private and remains separate from imports."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from app import main, oci_service_access as access
from app.auth import AuthContext
from app.database import Base
from app.models import AuditEvent, Service
from app.oci_models import OCIRepository, OCIServicePullAccess, OCIUpstream


@pytest.fixture
def service_db(monkeypatch):
    monkeypatch.setenv('CATS_MODE', 'full')
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        services = [Service(service_key='first', name='First'), Service(service_key='second', name='Second')]
        db.add_all(services)
        db.commit()
        yield db, services
    engine.dispose()


def inline(coroutine):
    # Stub request.json has no IO; avoid platform event-loop socket initialization.
    with pytest.raises(StopIteration) as result:
        coroutine.send(None)
    return result.value.value


def request(body, *, token='csrf'):
    async def json_body():
        return body
    return SimpleNamespace(headers={'X-CSRF-Token': token}, json=json_body)


def actor(service_id=None, permissions=('service.view', 'release.destination.manage')):
    assignment = SimpleNamespace(service_id=service_id, group_id=None, group=None,
        role=SimpleNamespace(name='Test role', permissions=list(permissions)))
    user = SimpleNamespace(id=None, username='reviewer', display_name='Reviewer', role_assignments=[assignment])
    return AuthContext(user=user, session=SimpleNamespace(csrf_token='csrf'))


def test_existing_database_adds_empty_visibility_table_without_publishing_services():
    engine = create_engine('sqlite://')
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE services (id INTEGER PRIMARY KEY)'))
        connection.execute(text('INSERT INTO services (id) VALUES (42)'))
        OCIServicePullAccess.__table__.create(connection, checkfirst=True)
        assert connection.execute(select(OCIServicePullAccess.public)).first() is None
        connection.execute(text('INSERT INTO oci_service_pull_access (service_id) VALUES (42)'))
        assert connection.execute(select(OCIServicePullAccess.public)).scalar() is False
        connection.execute(text('UPDATE oci_service_pull_access SET public = TRUE WHERE service_id = 42'))
        OCIServicePullAccess.__table__.create(connection, checkfirst=True)
        assert connection.execute(select(OCIServicePullAccess.public)).scalar() is True
        column = next(c for c in inspect(connection).get_columns('oci_service_pull_access') if c['name'] == 'public')
        assert column['nullable'] is False
    engine.dispose()


def test_missing_settings_and_new_orm_rows_are_private(service_db):
    db, (first, second) = service_db
    assert access.service_pull_is_public(db, first.id) is False
    assert access.service_pull_is_public(db, 999999) is False
    db.add(OCIServicePullAccess(service_id=first.id))
    db.flush()
    assert db.get(OCIServicePullAccess, first.id).public is False
    assert access.get_pull_access(first.id, db, actor()) == {'service_id': first.id, 'public': False}
    assert access.service_pull_is_public(db, second.id) is False


@pytest.mark.parametrize('body', [None, [], {}, {'public': None}, {'public': 0}, {'public': 1},
    {'public': 'true'}, {'public': 'false'}, {'public': []}, {'public': True, 'extra': 'field'}])
def test_visibility_requires_explicit_boolean(service_db, body):
    db, services = service_db
    with pytest.raises(HTTPException) as error:
        inline(access.set_pull_access(services[0].id, request(body), db, actor()))
    assert error.value.status_code == 422
    assert access.service_pull_is_public(db, services[0].id) is False


def test_service_visibility_updates_are_audited_and_isolated(service_db):
    db, (first, second) = service_db
    for public in [True, True, False]:
        assert inline(access.set_pull_access(first.id, request({'public': public}), db, actor())) == {
            'service_id': first.id, 'public': public}
        assert access.service_pull_is_public(db, second.id) is False
    events = list(db.scalars(select(AuditEvent).where(AuditEvent.action == 'oci.service.pull_access').order_by(AuditEvent.id)))
    assert [(e.detail['previous_public'], e.detail['public']) for e in events] == [(False, True), (True, True), (True, False)]


def test_scoped_viewers_read_only_their_services_and_cannot_change_visibility(service_db):
    db, (first, second) = service_db
    viewer = actor(first.id, ('service.view',))
    assert access.get_pull_access(first.id, db, viewer)['public'] is False
    with pytest.raises(HTTPException) as denied:
        access.get_pull_access(second.id, db, viewer)
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as denied:
        inline(access.set_pull_access(first.id, request({'public': True}), db, viewer))
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as denied:
        inline(access.set_pull_access(first.id, request({'public': True}, token='wrong'), db, actor()))
    assert denied.value.status_code == 403
    assert access.service_pull_is_public(db, first.id) is False


def test_unknown_service_cannot_be_made_public(service_db):
    db, _ = service_db
    with pytest.raises(HTTPException) as missing:
        inline(access.set_pull_access(999999, request({'public': True}), db, actor()))
    assert missing.value.status_code == 404


def test_visibility_checks_read_current_storage_instead_of_identity_cache(service_db):
    db, services = service_db
    setting = OCIServicePullAccess(service_id=services[0].id, public=True)
    db.add(setting)
    db.commit()
    assert access.service_pull_is_public(db, setting.service_id)
    db.execute(text('UPDATE oci_service_pull_access SET public = FALSE WHERE service_id = :id'), {'id': setting.service_id})
    assert setting.public is True
    assert access.service_pull_is_public(db, setting.service_id) is False


def test_replica_mapping_refresh_does_not_change_local_service_visibility(service_db):
    from app.replica_authorization import ensure_repository_mappings
    db, (first, second) = service_db
    upstream = OCIUpstream(name='Registry', endpoint='https://registry.example')
    db.add(upstream)
    db.add(OCIServicePullAccess(service_id=first.id, public=True))
    db.flush()
    for service in (first, second):
        state = SimpleNamespace(service_id=service.id, upstream_id=upstream.id)
        ensure_repository_mappings(db, state, [{'repository': 'team/nginx'}])
        ensure_repository_mappings(db, state, [{'repository': 'team/nginx'}])
    assert access.service_pull_is_public(db, first.id)
    assert access.service_pull_is_public(db, second.id) is False
    assert len(list(db.scalars(select(OCIRepository)))) == 2


def test_database_cascade_removes_visibility_for_deleted_services():
    engine = create_engine('sqlite://')
    with engine.begin() as connection:
        connection.exec_driver_sql('PRAGMA foreign_keys=ON')
        connection.execute(text('CREATE TABLE services (id INTEGER PRIMARY KEY)'))
        OCIServicePullAccess.__table__.create(connection)
        connection.execute(text('INSERT INTO services (id) VALUES (42)'))
        connection.execute(text('INSERT INTO oci_service_pull_access (service_id, public) VALUES (42, TRUE)'))
        connection.execute(text('DELETE FROM services WHERE id = 42'))
        assert connection.execute(select(OCIServicePullAccess.public)).first() is None
        connection.execute(text('INSERT INTO services (id) VALUES (42)'))
        assert connection.execute(select(OCIServicePullAccess.public)).first() is None
    engine.dispose()


def test_service_deletion_explicitly_removes_visibility_without_fk_cascades(service_db):
    db, services = service_db
    first = services[0]
    identity = first.id
    db.add(OCIServicePullAccess(service_id=identity, public=True))
    db.commit()
    response = main.delete_service(first.service_key, confirmation='delete '+first.name,
        reason='Removing test service', csrf_token='csrf', db=db, auth=actor())
    assert response.status_code == 303
    assert db.get(Service, identity) is None
    assert db.get(OCIServicePullAccess, identity) is None


def test_replica_mode_allows_only_the_local_visibility_write(service_db, monkeypatch):
    from app.operating_mode import request_available
    monkeypatch.setenv('CATS_MODE', 'replica')
    assert request_available('PUT', '/api/oci/services/42/pull-access')
    for method, path in [('POST', '/api/oci/services/42/pull-access'),
                         ('DELETE', '/api/oci/services/42/pull-access'),
                         ('PUT', '/api/oci/services/42/pull-access/extra'),
                         ('PUT', '/api/oci/services/42/evidence')]:
        assert not request_available(method, path)
    db, services = service_db
    assert inline(access.set_pull_access(services[0].id, request({'public': True}), db, actor()))['public'] is True
