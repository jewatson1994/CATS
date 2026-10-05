"""Synthetic structural fixtures are never qualified deployment assets."""
import io
import json
import tarfile
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base
from app.models import ValidatorPayloadBuild
from app import validator_payload_builds as b


@pytest.fixture
def release(tmp_path, monkeypatch):
    root=tmp_path/'assets';root.mkdir()
    entries=[]
    for version in ('22.04','24.04'):
        platform=root/version;platform.mkdir()
        assets={k:k+'.asset' for k in b.RELEASE_ASSETS}
        names=[*assets.values(),'runtime.deb','wheels/native.whl']
        for name in names:
            path=platform/name;path.parent.mkdir(exist_ok=True);path.write_bytes(b'synthetic test fixture')
        with tarfile.open(platform/assets['self_test_chart'],'w:gz') as archive:
            data=b'apiVersion: v2\nname: fixture\nversion: 1.0.0\n'
            member=tarfile.TarInfo('Chart.yaml');member.size=len(data);archive.addfile(member,io.BytesIO(data))
        manifest={'format':1,'os':'ubuntu','os_version':version,'architecture':'amd64','payload_version':'fixture',
            'assets':assets,'packages':['runtime.deb'],'wheels':['wheels/native.whl'],
            'versions':{k:'fixture' for k in b.RELEASE_ASSETS|{'runtime'}},
            'python_version':'3.10' if version=='22.04' else '3.12',
            'runtime':{'engine_version':'28.1.0','packages':['runtime.deb']},
            'qualification':{k:True for k in b.QUALIFICATIONS},
            'node_image_reference':'fixture/node@sha256:'+'a'*64,'self_test_image_reference':'fixture/test@sha256:'+'b'*64,
            'files':{name:{'size':(platform/name).stat().st_size,'sha256':b.digest_file(platform/name),'source':'unit test fixture'} for name in names}}
        file=platform/'validator-assets.json';file.write_text(json.dumps(manifest))
        entries.append({'os':'ubuntu','os_version':version,'architecture':'amd64','path':version,'sha256':b.digest_file(file)})
    (root/'release.json').write_text(json.dumps({'format':1,'cats_version':'test-release','platforms':entries}))
    pin=tmp_path/'seal';pin.write_text(b.digest_file(root/'release.json'))
    monkeypatch.setenv('CATS_VALIDATOR_ASSETS_DIR',str(root))
    monkeypatch.setenv('CATS_VALIDATOR_ASSETS_PIN',str(pin))
    monkeypatch.setenv('CATS_VALIDATOR_PAYLOAD_STORAGE',str(tmp_path/'payloads'))
    assembler=b.builder()
    monkeypatch.setattr(b,'builder',lambda:assembler)
    source=tmp_path/'source';(source/'app').mkdir(parents=True)
    for name in ('validator_server.py','requirements.txt','app/validator_api.py'):
        (source/name).write_text('# source fixture\n')
    (source/'.env').write_text('SECRET=do-not-ship')
    (source/'identity.key').write_text('do-not-ship')
    monkeypatch.setattr(b,'application_root',lambda:source)
    return root,pin,source


@pytest.fixture
def sessions(monkeypatch):
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory=sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(b,'SessionLocal',factory)
    yield factory
    engine.dispose()


def facts(version='22.04'):
    return {'os':'ubuntu','os_version':version,'architecture':'amd64'}


def test_inventory_reports_capable_only_after_all_assets_verified(release,sessions):
    result = b.inventory()
    assert result['managed_validator_capable'] is True
    assert result['managed_validator_assets_omitted'] is False
    root,_,_ = release
    (root/'24.04'/'wheels/native.whl').write_bytes(b'corrupted fixture')
    result = b.inventory()
    assert result['managed_validator_capable'] is False
    assert result['release_platforms'] == []
    assert 'integrity failure' in result['release_failure']


def test_inventory_reports_explicit_development_omission(release,sessions):
    root,pin,_ = release
    pin.unlink()
    (root/'omitted.json').write_text(json.dumps({'format':1,'managed_validator_assets':'omitted'}))
    result = b.inventory()
    assert result['managed_validator_assets_omitted'] is True
    assert result['managed_validator_capable'] is False
    assert 'Managed Validator Assets Not Included' in result['release_failure']


def test_missing_assets_are_not_mistaken_for_explicit_development_omission(release,sessions):
    _,pin,_ = release
    pin.unlink()
    result = b.inventory()
    assert result['managed_validator_assets_omitted'] is False
    assert result['managed_validator_capable'] is False


def test_invalid_omission_marker_never_reports_development_omission(release,sessions):
    root,_,_ = release
    (root/'omitted.json').write_text('{invalid json')
    result = b.inventory()
    assert result['managed_validator_assets_omitted'] is False
    assert result['managed_validator_capable'] is False
    assert result['release_platforms'] == []


def queue(sessions,version='22.04'):
    job=ValidatorPayloadBuild(id=uuid.uuid4().hex,platform=b.platform_key(facts(version)),artifact=facts(version),lease_until=b.now()+timedelta(hours=2))
    with sessions() as db:db.add(job);db.commit()
    return job.id


@pytest.mark.parametrize('version',['22.04','24.04'])
def test_real_assembler_verified_persistent_activation(release,sessions,version,monkeypatch):
    import socket
    monkeypatch.setattr(socket,'create_connection',lambda *a,**k:pytest.fail('Runtime network access'))
    job_id=queue(sessions,version);b.run_build(job_id)
    with sessions() as db:
        job=db.get(ValidatorPayloadBuild,job_id)
        assert job.status=='VERIFIED',job.failure
        assert job.active and job.manifest_sha256==b.digest_file(Path(job.artifact['path'])/'manifest.json')
        assert job.artifact['validator_version'].startswith('test-release-source-')
        assert job.stages and job.artifact['components']=={'verified':9,'total':9}
    root,manifest,digest=b.local_material(facts(version))
    assert root.name==job_id and manifest['os_version']==version
    assert manifest['release_provenance']['release_manifest_sha256']==release[1].read_text().strip()
    assert manifest['release_provenance']['files']['wheels/native.whl']['source']=='unit test fixture'
    assert manifest['release_provenance']['qualification']=={k:True for k in b.QUALIFICATIONS}
    with tarfile.open(root/manifest['assets']['validator']) as archive:
        names=archive.getnames()
        assert 'app/validator_api.py' in names and 'wheels/native.whl' in names
        assert '.env' not in names and 'identity.key' not in names
    assert b.inventory()['available']


@pytest.mark.parametrize('component',sorted(b.RELEASE_ASSETS)+['runtime.deb','wheels/native.whl'])
def test_missing_component_precise_fail_closed(release,sessions,component):
    root,pin,_=release
    base,m=b.load_release_platform(root,pin.read_text(),facts())
    (base/m['assets'].get(component,component)).unlink()
    job_id=queue(sessions);b.run_build(job_id)
    with sessions() as db:
        job=db.get(ValidatorPayloadBuild,job_id)
        assert job.status=='FAILED' and not job.active and not job.manifest_sha256
        assert component in job.failure and 'will not download' in job.failure


def test_rebuild_history_and_prior_active_on_failure(release,sessions):
    first=queue(sessions);b.run_build(first)
    old=b.local_material(facts())
    second=queue(sessions);b.run_build(second)
    assert b.local_material(facts())[0].name==second
    assert b.local_material(facts(),old[2])[0].name==first
    (release[0]/'22.04/runtime.deb').write_bytes(b'tampered')
    third=queue(sessions);b.run_build(third)
    assert b.local_material(facts())[0].name==second
    with sessions() as db:
        assert db.get(ValidatorPayloadBuild,third).status=='FAILED'
        assert len(db.scalars(select(ValidatorPayloadBuild)).all())==3


def test_database_concurrency_and_interruption(sessions):
    first=queue(sessions)
    with pytest.raises(IntegrityError):queue(sessions,'24.04')
    with sessions() as db:
        job=db.get(ValidatorPayloadBuild,first);job.lease_until=b.now()-timedelta(seconds=1);db.commit()
    b.recover_expired()
    with sessions() as db:assert db.get(ValidatorPayloadBuild,first).status=='FAILED'
    assert queue(sessions)


@pytest.mark.parametrize('path',['../secret','/absolute','a/../secret','a\\secret','.'])
def test_unsafe_release_paths(tmp_path,path):
    with pytest.raises(b.AssetError):b.safe_path(tmp_path,path)


def test_trust_and_platform_selection(release):
    root,pin,_=release
    with pytest.raises(b.AssetError,match='integrity'):b.validate_release(root,'0'*64)
    with pytest.raises(b.AssetError,match='missing required'):b.load_release_platform(root,pin.read_text(),facts('20.04'))
    (root/'release.json').write_text('{}')
    with pytest.raises(b.AssetError,match='integrity'):b.load_release_platform(root,pin.read_text(),facts())


@pytest.mark.parametrize('change',[{'python_version':'3.12'},{'qualification':{}},{'runtime':{'engine_version':'27.5.1'}},{'node_image_reference':'fixture:latest'}])
def test_release_qualification_is_mandatory(release,change):
    root,pin,_=release
    file=root/'22.04/validator-assets.json';m=json.loads(file.read_text());m.update(change);file.write_text(json.dumps(m))
    catalog=root/'release.json';data=json.loads(catalog.read_text());data['platforms'][0]['sha256']=b.digest_file(file)
    catalog.write_text(json.dumps(data));pin.write_text(b.digest_file(catalog))
    with pytest.raises(b.AssetError):b.load_release_platform(root,pin.read_text(),facts())


def test_routes_permissions_csrf_concurrency_and_input_boundary(sessions,monkeypatch):
    from types import SimpleNamespace as N
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.auth import require_user
    from app.database import get_db
    permissions={'validator.view','validator.provision'}
    auth=N(user=N(id=None,username='test',display_name='Test'),csrf_token='csrf',has=lambda key,*args:key in permissions)
    app=FastAPI();app.include_router(b.router)
    def session():
        with sessions() as db:yield db
    app.dependency_overrides[get_db]=session;app.dependency_overrides[require_user]=lambda:auth
    monkeypatch.setattr(b.WORKERS,'submit',lambda *args:None)
    url='/api/admin/validators/payload-builds'
    with TestClient(app) as client:
        assert client.post(url,json={}).status_code==403
        permissions.remove('validator.provision')
        assert client.post(url,json={'csrf_token':'csrf'}).status_code==403
        permissions.add('validator.provision')
        assert client.post(url,json={'csrf_token':'csrf','password':'never-store'}).status_code==422
        assert client.post(url,json={'csrf_token':'csrf','os_version':'20.04'}).status_code==422
        response=client.post(url,json={'csrf_token':'csrf'});assert response.status_code==200,response.text
        job=response.json();assert job['status']=='QUEUED' and 'password' not in json.dumps(job)
        assert client.post(url,json={'csrf_token':'csrf'}).status_code==409
        target=url+'/'+job['id']
        assert client.get(target).status_code==200
        for action in ('activate','verify'):
            assert client.post(target+'/'+action,json={}).status_code==403
            assert client.post(target+'/'+action,json={'csrf_token':'csrf'}).status_code==409
        permissions.remove('validator.view')
        assert client.get(target).status_code==403
