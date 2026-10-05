"""Disposable HQ lifecycle tests; no SSH, containers or remote operations."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import managed_validators as managed
from app.models import Base, ManagedValidator, ManagedValidatorOperation


@pytest.fixture
def sessions(monkeypatch):
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(managed, 'SessionLocal', factory)
    with factory() as db:
        db.add(ManagedValidator(id='host-1', name='Dedicated host', host='192.0.2.5', fingerprint='SHA256:'+'a'*43, fingerprint_confirmed=True))
        db.commit()
    yield factory
    engine.dispose()


def claim(sessions, action):
    with sessions() as db:
        return managed.claim_operation(db, db.get(ManagedValidator,'host-1'), action).id


def healthy():
    return {'validator_id':'host-1', 'ready':True, 'request_schema_versions':['cats.validation/v2'], 'active_jobs':0, 'private_key':'remote-sensitive'}


def evidence():
    return {'status':'VERIFIED', 'cleanup_status':'COMPLETE', 'request_id':'selftest-run',
        'helm_result':{'install':'PASS','release_status':'DEPLOYED'},
        'resource_summary':{'pods':{'expected':1,'ready':1}}}


@pytest.mark.parametrize('health_patch,validation_type,eligible', [
    ({}, 'helm-chart', True),
    ({}, 'oci', True),
    ({}, 'unknown', False),
    ({'request_schema_versions': []}, 'helm-chart', False),
    ({'validation_types': []}, 'helm-chart', False),
    ({'validation_types': ['oci']}, 'helm-chart', False),
    ({'validation_types': ['helm-chart']}, 'helm-chart', True),
    ({'ready': False}, 'helm-chart', False),
    ({'active_jobs': 1, 'max_jobs': 1}, 'helm-chart', False),
])
def test_runner_selection_supports_existing_v2_health(sessions, health_patch, validation_type, eligible):
    with sessions() as db:
        row = db.get(ManagedValidator, 'host-1')
        row.status = 'HEALTHY'
        row.configuration = {'endpoint': 'https://validator.example'}
        row.last_self_test = {'status': 'VERIFIED'}
        row.last_contact_at = datetime.now(timezone.utc)
        row.certificate = {'expires_at': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}
        row.last_health = dict(healthy(), **health_patch)
        db.commit()
        selected = managed.select_configuration(db, {}, validation_type)
        assert bool(selected) is eligible
        if eligible:
            assert selected['managed_validator_id'] == 'host-1'


def test_compare_and_swap_claim_rejects_busy(sessions):
    first=claim(sessions,'preflight')
    with sessions() as db:
        with pytest.raises(HTTPException) as caught:
            managed.claim_operation(db, db.get(ManagedValidator,'host-1'),'provision')
        assert caught.value.status_code == 409
        assert db.get(ManagedValidator,'host-1').active_operation_id == first
        assert db.query(ManagedValidatorOperation).count() == 1


def test_restart_recovery_releases_lock_and_preserves_remote_uncertainty(sessions):
    operation=claim(sessions,'provision')
    with sessions() as db:
        db.get(ManagedValidator,'host-1').configuration={'client_key':'enc:sensitive'}
        db.commit()
    managed.recover_operations()
    with sessions() as db:
        row, op=db.get(ManagedValidator,'host-1'),db.get(ManagedValidatorOperation,operation)
        assert row.status == 'DEGRADED' and row.active_operation_id is None
        assert op.status == 'FAILED' and op.phase == 'INTERRUPTED' and op.finished_at
        assert 'reconciled' in op.error


def test_public_record_excludes_private_persistence(sessions):
    with sessions() as db:
        row=db.get(ManagedValidator,'host-1')
        row.configuration={'client_key':'encrypted-sensitive','client_certificate':'private-config'}
        row.identity={'server_key':'encrypted-sensitive','ca_key':'encrypted-sensitive'}
        db.commit()
        dto=managed.public_record(db,row)
        assert 'configuration' not in dto and 'identity' not in dto
        assert 'encrypted-sensitive' not in json.dumps(dto)


@pytest.mark.parametrize('change', [{'validator_id':'different'}, {'ready':False}, {'request_schema_versions':['cats.validation/v1']}])
def test_health_requires_matching_id_readiness_and_v2(monkeypatch, change):
    monkeypatch.setattr(managed.validator_client,'health',lambda config: healthy() | change)
    with pytest.raises(managed.BootstrapError):
        managed.health_checked({},'host-1')


def test_health_dto_drops_remote_private_fields(monkeypatch):
    monkeypatch.setattr(managed.validator_client,'health',lambda config:healthy())
    result=managed.health_checked({},'host-1')
    assert result['validator_id']=='host-1' and 'private_key' not in result


def test_health_alone_cannot_promote(sessions, monkeypatch):
    operation=claim(sessions,'test')
    monkeypatch.setattr(managed.validator_client,'health',lambda config:healthy())
    credentials={'password':'sensitive'}
    managed.run_operation('host-1',operation,credentials,{})
    with sessions() as db:
        assert db.get(ManagedValidator,'host-1').status == 'DEGRADED'
        assert db.get(ManagedValidatorOperation,operation).status == 'SUCCEEDED'
    assert credentials == {}


class FakeSSH:
    def __init__(self,*args,**kwargs): pass
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def preflight(self,owner_id=None):
        return {'status':'supported','checks':{'docker':True},'facts':{},'warnings':[]}
    def deploy(self,*args): pass


def mock_provision(monkeypatch, result):
    monkeypatch.setattr(managed,'SSHBootstrap',FakeSSH)
    monkeypatch.setattr(managed,'load_release',lambda:{'cats_image':{'reference':'cats:exact','image_id':'sha256:'+'a'*64}})
    monkeypatch.setattr(managed,'create_identity',lambda *args:{'configuration':{'client_key':'enc:sensitive'},'persistence':{'server_key':'enc:sensitive'},'public':{'validator_id':'host-1'},'deployment':{'validator_key':'temporary-sensitive'}})
    monkeypatch.setattr(managed.validator_client,'health',lambda config:healthy())
    monkeypatch.setattr(managed,'selftest_request',lambda release:({'schema_version':'cats.validation/v2'},Path('selftest.zip')))
    monkeypatch.setattr(managed.validator_client,'validate',lambda *args,**kwargs:result)


def test_preflight_succeeds_without_promoting(sessions,monkeypatch):
    monkeypatch.setattr(managed,'SSHBootstrap',FakeSSH)
    operation=claim(sessions,'preflight');credentials={'password':'sensitive'}
    managed.run_operation('host-1',operation,credentials,{})
    with sessions() as db:
        row,op=db.get(ManagedValidator,'host-1'),db.get(ManagedValidatorOperation,operation)
        assert row.status == 'PREFLIGHT_OK' and row.active_operation_id is None
        assert op.status == 'SUCCEEDED' and op.phase == 'COMPLETE'
    assert credentials == {}


def test_provision_requires_real_runtime_evidence_contract(sessions,monkeypatch):
    mock_provision(monkeypatch,evidence())
    operation=claim(sessions,'provision');credentials={'password':'sensitive'}
    managed.run_operation('host-1',operation,credentials,{'resource_warnings':False})
    with sessions() as db:
        row,op=db.get(ManagedValidator,'host-1'),db.get(ManagedValidatorOperation,operation)
        assert row.status == 'HEALTHY' and row.active_operation_id is None
        assert op.status == 'SUCCEEDED' and row.last_self_test['cleanup_status']=='COMPLETE'
    assert credentials == {}


@pytest.mark.parametrize('patch', [ {'cleanup_status':'FAILED'}, {'helm_result':{'install':'PASS','release_status':'DEPLOYED','execution_mode':'PREFLIGHTED_MANIFEST_APPLY'}}, {'resource_summary':{'pods':{'expected':1,'ready':0}}} ])
def test_failed_runtime_evidence_clears_credentials_and_lock(sessions,monkeypatch,patch):
    mock_provision(monkeypatch,evidence() | patch)
    operation=claim(sessions,'provision');credentials={'password':'sensitive'}
    managed.run_operation('host-1',operation,credentials,{'resource_warnings':False})
    with sessions() as db:
        row,op=db.get(ManagedValidator,'host-1'),db.get(ManagedValidatorOperation,operation)
        assert row.status == 'DEGRADED' and row.active_operation_id is None
        assert op.status == 'FAILED' and op.finished_at
        assert 'sensitive' not in op.error
        assert op.error.startswith('Self-test failed:')
    assert credentials == {}


def test_readiness_caches_archive_check_and_returns_copy(monkeypatch):
    clock=[100.0];calls=[]
    monkeypatch.setattr(managed.time,'monotonic',lambda:clock[0])
    monkeypatch.setattr(managed,'READINESS_CACHE',{'expires':0,'value':{}})
    monkeypatch.setattr(managed,'load_release',lambda **kwargs:calls.append(kwargs)  or {'cats_image':{'reference':'cats:exact','image_id':'sha256:exact'}})
    first=managed.readiness();first['ready']=False
    assert managed.readiness()['ready'] is True and calls == [{'verify_assets': False}]
    clock[0]=131
    assert managed.readiness()['ready'] is True and len(calls)==2


def test_restart_clears_selection_for_interrupted_validator(sessions):
    from app.models import PortalSetting
    claim(sessions,'provision')
    with sessions() as db:
        db.add(PortalSetting(key='validator_configuration',value=json.dumps({'managed_validator_id':'host-1','client_key':'encrypted'})))
        db.commit()
    managed.recover_operations()
    with sessions() as db:
        assert json.loads(db.query(PortalSetting).filter_by(key='validator_configuration').one().value)=={}


def test_router_admin_csrf_and_response_envelopes(sessions,monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from types import SimpleNamespace
    application=FastAPI();application.include_router(managed.router)
    def database():
        with sessions() as db:
            yield db
    application.dependency_overrides[managed.get_db]=database
    monkeypatch.setattr(managed,'readiness',lambda:{'ready':False})
    monkeypatch.setattr(managed,'record_audit',lambda *args:None)
    with TestClient(application) as client:
        assert client.get('/api/frontend/settings/validators',follow_redirects=False).status_code in (401,403,303)
        auth=SimpleNamespace(csrf_token='correct',can_manage_group=lambda group:False)
        application.dependency_overrides[managed.require_user]=lambda:auth
        assert client.get('/api/frontend/settings/validators').status_code==403
        auth.can_manage_group=lambda group:True
        listing=client.get('/api/frontend/settings/validators')
        assert listing.status_code==200 and set(listing.json())=={'validators','image_readiness'}
        details=client.get('/api/frontend/settings/validators/host-1')
        assert set(details.json())=={'validator'}
        bad=client.post('/api/frontend/settings/validators',data={'csrf_token':'wrong','name':'New','host':'192.0.2.6'})
        assert bad.status_code==403
        good=client.post('/api/frontend/settings/validators',data={'csrf_token':'correct','name':'New','host':'192.0.2.6'})
        assert good.status_code==200 and set(good.json())=={'validator'}
