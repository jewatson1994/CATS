import asyncio
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

from app import service_oci as oci
from app.auth import AuthContext
from app.database import Base
from app.models import Service
from app.secrets import decrypt_secret


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY', Fernet.generate_key().decode())
    engine = create_engine('sqlite://', connect_args={'check_same_thread':False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([Service(service_key='one',name='One'),Service(service_key='two',name='Two')])
        session.commit()
        yield session


def auth(service=1, permissions=('service.edit','remediation.execute')):
    assignment = SimpleNamespace(role=SimpleNamespace(name='Service Manager',permissions=list(permissions)),service_id=service,group_id=None,group=None)
    return AuthContext(user=SimpleNamespace(id=None,username='manager',display_name='Manager',role_assignments=[assignment]),session=SimpleNamespace(csrf_token='csrf'))


def request(data=None, token='csrf'):
    body = json.dumps(data or {}).encode()
    async def receive():
        return {'type':'http.request','body':body}
    return Request({'type':'http','method':'POST','headers':[(b'x-csrf-token',token.encode())]},receive)


def save(db, data, destination=None):
    return asyncio.run(oci._save(request(data),'one',destination,db,auth()))


def test_crud_rotation_defaults_and_secret_projection(db):
    first = save(db,{'name':'Private','endpoint':'https://registry.example','namespace':'team/app','username':'manager','password':'secret','is_default':True})
    row = db.get(oci.ServiceOCIDestination,int(first['id']))
    assert decrypt_secret(row.password) == 'secret'
    assert decrypt_secret(row.username) == 'manager'
    assert 'secret' not in json.dumps(first) and 'username' not in first and 'password' not in first
    updated = save(db,{'name':'Rotated','password':'replacement'},row.id)
    assert updated['credentials_configured']
    assert decrypt_secret(row.password) == 'replacement'
    save(db,{'name':'Second','endpoint':'https://other.example','is_default':True})
    assert not row.is_default
    oci.delete(request(),'one',row.id,db,auth())
    assert db.get(oci.ServiceOCIDestination,row.id) is None


def test_cross_service_resolution_and_edit_denied(db):
    first = save(db,{'name':'Private','endpoint':'https://registry.example'})
    with pytest.raises(HTTPException) as exc:
        oci.resolve_destination(db,2,first['id'])
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException):
        asyncio.run(oci._save(request({'name':'Stolen'}),'two',int(first['id']),db,auth()))


@pytest.mark.parametrize('service,permissions,allowed', [(1,('service.edit',),True),(2,('service.edit',),False),(1,('service.view',),False),(None,('service.edit',),True)])
def test_real_scoped_permission_dependency(db,service,permissions,allowed):
    application = FastAPI()
    application.include_router(oci.router)
    from app.auth import require_user
    application.dependency_overrides[require_user] = lambda: auth(service,permissions)
    application.dependency_overrides[oci.get_db] = lambda: db
    client = TestClient(application)
    response = client.post('/api/services/one/oci-destinations',headers={'X-CSRF-Token':'csrf'},json={'name':'Private','endpoint':'https://registry.example'})
    assert response.status_code == (200 if allowed else 403)


@pytest.mark.parametrize('endpoint', ['http://registry.example','https://user:password@registry.example','https://registry.example/path','https://registry.example?x=1','https://registry.example:bad'])
def test_invalid_endpoints_rejected(endpoint):
    with pytest.raises(HTTPException):
        oci.validate_destination({'name':'Private','endpoint':endpoint})


def test_csrf_and_namespace_validation(db):
    with pytest.raises(HTTPException):
        asyncio.run(oci._save(request({},'bad'),'one',None,db,auth()))
    with pytest.raises(HTTPException):
        save(db,{'name':'Private','endpoint':'https://registry.example','namespace':'../escape'})


def test_global_requires_explicit_remediation_configuration(db):
    rows = [{'id':'global-one','endpoint':'https://global.example','use_for_remediation':True}]
    assert oci.resolve_destination(db,2,'global:global-one',rows)['scope'] == 'global'
    rows[0]['use_for_remediation'] = False
    with pytest.raises(HTTPException):
        oci.resolve_destination(db,1,'global:global-one',rows)


def test_connection_capabilities_sanitized_and_no_push_claim(monkeypatch):
    class Opener:
        def open(self,*args,**kwargs):
            raise RuntimeError('secret credential PEM internal exception')
    monkeypatch.setattr(oci.urllib.request,'build_opener',lambda *args:Opener())
    result = oci.test_connection({'endpoint':'https://registry.example'})
    assert 'secret' not in json.dumps(result)
    assert result['push'] == result['helm_oci'] == result['image_publish'] == 'NOT TESTED'


def test_destination_ca_scoped(monkeypatch):
    seen = []
    from contextlib import contextmanager
    @contextmanager
    def trust(certificates):
        seen.append(certificates)
        yield None, {'LOCAL':'trust'}
    monkeypatch.setattr(oci,'ephemeral_trust',trust)
    with oci.destination_trust({'ca_pem':'private-ca'}) as (_,env):
        assert env == {'LOCAL':'trust'}
    with oci.destination_trust({}):
        pass
    assert seen == [[{'pem':'private-ca'}],[]]


def test_invalid_ca_rejected():
    with pytest.raises(HTTPException):
        oci.validate_destination({'name':'Private','endpoint':'https://registry.example','ca_pem':'not a certificate'})


def test_global_destination_preserves_valid_ca_and_rejects_invalid_ca(db):
    from test_admin_config import _certificate
    certificate = _certificate('Private registry CA').decode()
    row = {'id':'global','endpoint':'https://global.example','use_for_remediation':True,'ca_pem':certificate}
    assert oci.resolve_destination(db,1,'global:global',[row])['ca_pem'] == certificate
    row['ca_pem'] = 'invalid certificate'
    with pytest.raises(HTTPException):
        oci.resolve_destination(db,1,'global:global',[row])
