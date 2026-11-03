"""Discovery authorization, immutable evidence and existing scan admission."""
from contextlib import nullcontext
import hashlib
import base64
import io
import json
import sys
import zipfile
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import discovery_routes as routes, discovery_worker as worker
from app.auth import AuthContext, require_user
from app.database import Base
from app.models import AuditEvent, Service, Group, ServiceGroup
from app.models import utcnow
from app.discovery_models import DiscoveryInventory, DiscoveryConfirmation
from app.durable_jobs import DurableJob, JobError, claim, execute
from app.discovery_sources import encrypted_writer, decrypted_source, SourceStorageError


@pytest.fixture(autouse=True)
def stub_packaged_intelligence_startup(monkeypatch):
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY',base64.urlsafe_b64encode(b'0'*32).decode())


def scoped_auth(group, permissions=('service.edit', 'scan.ingest')):
    assignment = SimpleNamespace(role=SimpleNamespace(name='Test manager', system=False, permissions=list(permissions)),
        service_id=None, group_id=group.id, group=group)
    return AuthContext(user=SimpleNamespace(id=7, username='reviewer', display_name='Reviewer',
        role_assignments=[assignment]), session=SimpleNamespace(csrf_token='csrf'))


@pytest.fixture
def api(monkeypatch, tmp_path):
    engine = create_engine('sqlite://', connect_args={'check_same_thread':False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT', str(tmp_path))
    with Session(engine) as db:
        db.add_all([Service(id=1, service_key='one', name='One'), Service(id=2, service_key='two', name='Two'),
            Group(id=1, name='One group'), Group(id=2, name='Two group')])
        db.flush()
        db.add_all([ServiceGroup(service_id=1,group_id=1),ServiceGroup(service_id=2,group_id=2)])
        db.commit()
        current = {'auth':scoped_auth(db.get(Group, 1))}
        application = FastAPI()
        application.include_router(routes.router)
        application.dependency_overrides[require_user] = lambda: current['auth']
        application.dependency_overrides[routes.get_db] = lambda: db
        with TestClient(application) as client:
            yield client, db, current
    engine.dispose()


def job(db, identity='own', group=1, status='completed', completeness='complete', nodes=None):
    row = DurableJob(id=identity, kind='discovery', status=status, payload={'group_id':group,
        'source_id':'a'*32,'filename':'images.txt','source_hash':'0'*64,'options':{}}, result={})
    db.add(row)
    db.flush()
    item = DiscoveryInventory(id=identity+'-inventory',job_id=identity,group_id=group,
        source_hash='0'*64,content_hash='1'*64,inventory={'completeness':completeness,
        'roots':[{'id':'root'}], 'nodes':nodes or [], 'images':[{'root_id':'root','reference':'nginx:1.2'}]})
    db.add(item)
    db.commit()
    return row,item


def post(client, path, data=None):
    return client.post('/api/discovery'+path,json=data or {},headers={'X-CSRF-Token':'csrf'})


def test_group_visibility_and_cross_group_actions(api):
    client,db,current=api
    job(db)
    job(db,'foreign',2)
    response=client.get('/api/discovery').json()
    assert [j['id'] for j in response['jobs']] == ['own']
    assert [g['id'] for g in response['groups']] == [1]
    assert [s['id'] for s in response['services']] == [1]
    assert client.get('/api/discovery/foreign').status_code == 404
    for action in ('cancel','retry','confirm','scan','forget-source'):
        assert post(client,'/foreign/'+action).status_code == 404
    assert client.get('/api/discovery/own/compare/foreign').status_code == 404


@pytest.mark.parametrize('action',['cancel','retry','confirm','scan','forget-source'])
@pytest.mark.parametrize('token',[None,'wrong'])
def test_mutations_require_csrf(api, action, token):
    client,db,_=api
    job(db)
    headers={'X-CSRF-Token':token} if token else {}
    response=client.post('/api/discovery/own/'+action,json={},headers=headers)
    assert response.status_code == 403
    assert 'CSRF' in response.json()['detail']


def test_partial_confirmation_requires_ack_and_owning_service(api):
    client,db,_=api
    _,item=job(db,completeness='partial')
    before=json.dumps(item.inventory,sort_keys=True)
    payload={'service_id':1,'root_ids':['root']}
    assert post(client,'/own/confirm',payload).status_code == 422
    assert post(client,'/own/confirm',{**payload,'acknowledge_partial':True,'service_id':2}).status_code == 403
    assert post(client,'/own/confirm',{**payload,'acknowledge_partial':True,'root_ids':['unknown']}).status_code == 422
    response=post(client,'/own/confirm',{**payload,'acknowledge_partial':True})
    assert response.status_code == 200, response.text
    confirmation=db.get(DiscoveryConfirmation,response.json()['inventory_id'])
    assert confirmation.acknowledge_partial and confirmation.confirmed_by == 7
    assert json.dumps(item.inventory,sort_keys=True) == before


@pytest.mark.parametrize('completeness',['invalid','blocked'])
def test_blocked_inventory_never_confirmed(api, completeness):
    client,db,_=api
    job(db,completeness=completeness)
    assert post(client,'/own/confirm',{'service_id':1,'root_ids':['root'],'acknowledge_partial':True}).status_code == 409


def test_retry_creates_new_job_and_cancel_preserves_evidence(api):
    client,db,_=api
    old,item=job(db,status='failed')
    folder=worker.upload_root()/old.payload['source_id']
    folder.mkdir()
    with encrypted_writer(folder/'images.txt','a'*32) as stream:
        stream.write(b'nginx:1.2')
    selected = {'profiles':['prod'], 'component_values':{'release-a':['env/base.yaml','env/prod.yaml']}}
    response=post(client,'/own/retry',{'options':selected})
    assert response.status_code == 200,response.text
    new=db.get(DurableJob,response.json()['job_id'])
    assert new.id != old.id and new.payload['previous_job_id'] == old.id
    assert new.payload['options'] == selected
    assert old.payload['options'] == {} and item.inventory['completeness'] == 'complete'
    assert post(client,'/'+new.id+'/retry').status_code == 409
    assert post(client,'/'+new.id+'/cancel').status_code == 200
    db.refresh(new)
    assert new.status == 'cancelled' and new.cancel_requested


def test_comparison_is_read_only(api):
    client,db,_=api
    _,old=job(db,'old',nodes=[{'id':'gone'},{'id':'same','image':'old'}])
    _,new=job(db,'new',nodes=[{'id':'added'},{'id':'same','image':'new'}])
    before=[json.dumps(x.inventory,sort_keys=True) for x in (old,new)]
    response=client.get('/api/discovery/new/compare/old')
    assert response.json() == {'added':['added'],'removed':['gone'],'changed':['same']}
    assert [json.dumps(x.inventory,sort_keys=True) for x in (old,new)] == before


def test_confirmed_scan_uses_existing_admission_once(api,monkeypatch):
    client,db,_=api
    _,item=job(db)
    calls=[]
    async def prepare(images,**kwargs):
        calls.append((images,kwargs))
        return 'existing-scan'
    fake=SimpleNamespace(_prepare_public_scan=prepare,get_global_configuration=lambda db:{},parse_json=lambda raw,default:default)
    import app
    monkeypatch.setitem(sys.modules,'app.main',fake)
    monkeypatch.setattr(app,'main',fake,raising=False)
    assert post(client,'/own/scan').status_code == 409
    confirmation=post(client,'/own/confirm',{'service_id':1,'root_ids':['root']})
    assert confirmation.status_code == 200,confirmation.text
    first=post(client,'/own/scan')
    assert first.status_code == 200,first.text
    assert post(client,'/own/scan').json() == first.json()
    assert len(calls) == 1 and calls[0][0] == 'nginx:1.2'
    assert calls[0][1]['ingest_service_id'] == 'one'
    assert calls[0][1]['definition_context']['content_hash'] == item.content_hash


@pytest.mark.parametrize('token,filename',[('../escape','images.txt'),('a'*32,'../outside.txt')])
def test_worker_rejects_source_identity_and_traversal(tmp_path,monkeypatch,token,filename):
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT',str(tmp_path))
    with pytest.raises(JobError):
        worker.handle(SimpleNamespace(),{'source_id':token,'filename':filename})


def test_worker_checks_source_hash_before_rendering(tmp_path,monkeypatch,api):
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT',str(tmp_path))
    folder=tmp_path/('a'*32)
    folder.mkdir()
    with encrypted_writer(folder/'images.txt','a'*32) as stream:
        stream.write(b'nginx:1.2')
    with pytest.raises(JobError,match='integrity'):
        worker.handle(SimpleNamespace(check=lambda:None,stage=lambda *args:None,session_factory=lambda: nullcontext(api[1])),{'source_id':'a'*32,'filename':'images.txt','source_hash':'0'*64})


def test_upload_and_reference_admission_are_group_scoped(api):
    client,db,_=api
    form={'group_id':'1','csrf_token':'csrf'}
    response=client.post('/api/discovery',data=form,files={'upload':('images.txt',b'nginx:1.2\n','text/plain')})
    assert response.status_code == 200,response.text
    row=db.get(DurableJob,response.json()['job_id'])
    assert row.payload['group_id'] == 1 and row.status == 'queued'
    assert row.payload['source_hash'] == hashlib.sha256(b'nginx:1.2\n').hexdigest()
    stored=worker.upload_root()/row.payload['source_id']/row.payload['filename']
    assert b'nginx:1.2' not in stored.read_bytes()
    with decrypted_source(stored,row.payload['source_id'],row.payload['source_hash']) as plain:
        assert plain.read_bytes() == b'nginx:1.2\n'
    assert client.post('/api/discovery',data={**form,'group_id':'2','reference':'nginx:1.2'}).status_code == 403
    assert client.post('/api/discovery',data={'group_id':'1','reference':'nginx:1.2'}).status_code == 403


@pytest.fixture
def gitlab_form(monkeypatch):
    project = 'https://gitlab.example.test/team/project'
    monkeypatch.setenv('CATS_DISCOVERY_GITLAB_SOURCES', project)
    return {'group_id': '1', 'csrf_token': 'csrf', 'input_kind': 'gitlab',
            'repository_url': project, 'git_ref': 'release/v2', 'git_token': 'private-read-api-test-token',
            'acknowledge_non_secret': 'true'}


def test_browse_gitlab_refs_is_group_scoped_and_does_not_create_a_job(api, gitlab_form, monkeypatch):
    client, db, _ = api
    choices = {'branches': ['release/main'], 'tags': ['release/v2'], 'truncated': False}
    data = {'group_id': 1, 'repository_url': gitlab_form['repository_url'],
            'git_token': gitlab_form['git_token'], 'search': 'release'}
    calls = []

    def list_refs(url, *, token, trusted_ca_certificates, search):
        calls.append((url, token, search))
        return choices

    monkeypatch.setattr(routes.gitlab, 'list_gitlab_refs', list_refs)
    assert client.post('/api/discovery/gitlab/refs', json=data).status_code == 403
    assert post(client, '/gitlab/refs', {**data, 'group_id': 2}).status_code == 403
    assert not calls
    response = post(client, '/gitlab/refs', data)
    assert response.status_code == 200 and response.json() == choices
    assert calls == [(data['repository_url'], data['git_token'], 'release')]
    assert db.scalar(select(DurableJob.id)) is None
    assert list(worker.upload_root().iterdir()) == []


def test_gitlab_busy_error_leaves_no_partial_archive(api, gitlab_form, monkeypatch):
    client, db, _ = api
    monkeypatch.setattr(routes, '_GITLAB_REQUEST_SLOTS', SimpleNamespace(acquire=lambda blocking: False))
    response = client.post('/api/discovery', data=gitlab_form)
    assert response.status_code == 503 and response.headers['Retry-After'] == '5'
    assert db.scalar(select(DurableJob.id)) is None
    assert list(worker.upload_root().iterdir()) == []


@pytest.mark.parametrize(('changed', 'with_upload', 'status'), [
    ({'group_id': '2'}, False, 403),
    ({'csrf_token': ''}, False, 403),
    ({'acknowledge_non_secret': ''}, False, 422),
    ({'reference': 'example/app:1'}, False, 422),
    ({}, True, 422),
    ({'repository_url': '', 'reference': 'example/app:1', 'input_kind': 'reference'}, False, 422),
    ({'repository_url': 'https://gitlab.example.test/team/another'}, False, 403),
])
def test_gitlab_admission_checks_before_fetch(api, gitlab_form, monkeypatch, changed, with_upload, status):
    client, db, _ = api
    monkeypatch.setattr(routes.gitlab, 'fetch_gitlab_archive', lambda *args, **kwargs: pytest.fail('Unexpected download'))
    files = {'upload': ('images.txt', b'nginx:1')} if with_upload else None
    response = client.post('/api/discovery', data={**gitlab_form, **changed}, files=files)
    assert response.status_code == status, response.text
    assert gitlab_form['git_token'] not in response.text
    assert db.scalar(select(DurableJob.id)) is None
    assert list(worker.upload_root().iterdir()) == []


def test_gitlab_failed_fetch_removes_partial_source(api, gitlab_form, monkeypatch):
    client, db, _ = api

    def fail_fetch(url, ref, stream, **kwargs):
        stream.write(b'incomplete archive')
        raise routes.gitlab.GitLabSourceError('GitLab returned an incomplete response.')

    monkeypatch.setattr(routes.gitlab, 'fetch_gitlab_archive', fail_fetch)
    response = client.post('/api/discovery', data=gitlab_form)
    assert response.status_code == 502, response.text
    assert gitlab_form['git_token'] not in response.text
    assert list(worker.upload_root().iterdir()) == []
    assert db.scalar(select(DurableJob.id)) is None
    assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == 'discovery.submitted')) is None


def test_gitlab_archive_discovery_and_retry_replay_without_credentials(api, gitlab_form, monkeypatch):
    client, db, _ = api
    sha = 'a1' * 20
    wrapper = 'project-' + sha
    selected = {'values_files': ['overrides/values-prod.yaml']}
    expected = {'repository_url': gitlab_form['repository_url'], 'requested_ref': gitlab_form['git_ref'],
                'ref_kind': 'tag', 'commit_sha': sha}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as files:
        files.writestr(f'{wrapper}/manifests/pod.yaml', 'apiVersion: v1\nkind: Pod\nmetadata: {name: web}\nspec: {containers: [{name: app, image: nginx:1.27}]}')
        files.writestr(f'{wrapper}/overrides/values-prod.yaml', 'replicas: 3')
    archive_bytes = archive.getvalue()
    digest = hashlib.sha256(archive_bytes).hexdigest()
    downloads = []

    def serve(request, timeout):
        assert request.get_header('Private-token') == gitlab_form['git_token']
        downloads.append(request.full_url)
        if len(downloads) == 1:
            assert request.full_url.endswith('/repository/tags/release%2Fv2')
            body = json.dumps({'name': 'release/v2', 'commit': {'id': sha}}).encode()
        else:
            assert len(downloads) == 2 and request.full_url.endswith('/archive.zip?sha=' + sha)
            body = archive_bytes
        response = io.BytesIO(body)
        response.status = 200
        response.headers = {'Content-Length': str(len(body))}
        return response

    monkeypatch.setattr(routes.gitlab.request, 'build_opener', lambda *args: SimpleNamespace(open=serve))
    response = client.post('/api/discovery', data={**gitlab_form, 'git_ref_kind': 'tag', 'options': json.dumps(selected)})
    assert response.status_code == 200, response.text
    first_id = response.json()['job_id']
    first = db.get(DurableJob, first_id)
    source_id = first.payload['source_id']
    stored = worker.upload_root() / source_id / first.payload['filename']
    assert b'nginx:1.27' not in stored.read_bytes()
    with decrypted_source(stored, source_id, digest) as plain:
        assert plain.read_bytes() == archive_bytes
    assert client.get('/api/discovery/' + first_id).json()['job']['gitlab_source'] == expected

    session_factory = lambda: Session(db.get_bind())

    def finish_and_check(job_id):
        queued = claim(['discovery'], 'test-worker', session_factory)
        assert queued.id == job_id
        execute(queued, worker.handle, session_factory)
        db.expire_all()
        detail = client.get('/api/discovery/' + job_id).json()
        assert detail['job']['status'] == 'completed', detail['job']['error']
        inventory = detail['inventory']
        assert detail['job']['gitlab_source'] == inventory['gitlab_source'] == expected
        assert inventory['archive_hash'] == digest
        assert [image['reference'] for image in inventory['images']] == ['nginx:1.27']
        assert inventory['candidate_values_files'] == selected['values_files']
        assert inventory['selection']['values_files'] == selected['values_files']
        payload = db.get(DurableJob, job_id).payload
        assert payload['source_id'] == source_id and payload['source_hash'] == digest
        assert gitlab_form['git_token'] not in json.dumps([payload, detail])

    finish_and_check(first_id)
    monkeypatch.delenv('CATS_DISCOVERY_GITLAB_SOURCES')
    retry = post(client, '/' + first_id + '/retry')
    assert retry.status_code == 200, retry.text
    next_id = retry.json()['job_id']
    assert next_id != first_id
    finish_and_check(next_id)
    assert len(downloads) == 2
    assert gitlab_form['git_token'] not in client.get('/api/discovery').text
    events = db.scalars(select(AuditEvent)).all()
    assert any(event.action == 'discovery.submitted' for event in events)
    for event in events:
        assert gitlab_form['git_token'] not in json.dumps([event.action, event.target_type, event.target_id, event.detail])


def test_expired_retry_requires_reupload(api):
    client,db,_=api
    job(db)
    assert post(client,'/own/retry').status_code == 410


def test_retention_preserves_active_sibling_and_inventory(api):
    from app.discovery_retention import cleanup_sources
    client,db,_=api
    old,item=job(db)
    old.created_at=utcnow()-timedelta(days=2)
    active,_=job(db,'active',status='queued')
    folder=worker.upload_root()/old.payload['source_id']
    folder.mkdir()
    source=folder/'images.txt'
    source.write_text('nginx:1.2')
    db.commit()
    factory=lambda:Session(db.get_bind())
    assert cleanup_sources(factory) == 0 and source.exists()
    active.status='completed'
    db.commit()
    assert cleanup_sources(factory) == 1 and not source.exists()
    db.expire_all()
    assert db.get(DiscoveryInventory,item.id).inventory['roots'] == [{'id':'root'}]
    assert db.get(DurableJob,old.id).result['source_expired'] is True
    assert db.get(DurableJob,active.id).result['source_expired'] is True


def test_worker_persists_inventory_and_uses_isolated_runner(api,monkeypatch):
    from app import discovery_engine, discovery_renderer
    client,db,_=api
    row=DurableJob(id='worker-job',kind='discovery',status='running',payload={},result={})
    db.add(row)
    db.commit()
    source_id='b'*32
    folder=worker.upload_root()/source_id
    folder.mkdir()
    data=b'nginx:1.2\n'
    with encrypted_writer(folder/'images.txt',source_id) as stream:
        stream.write(data)
    payload={'source_id':source_id,'filename':'images.txt','source_hash':hashlib.sha256(data).hexdigest(),
             'group_id':1,'options':{}}
    stages=[]
    checkpoints=[]
    def discover(source,options,runner,progress,artifact_resolver=None,supplemental_inputs=None,check_cancelled=None,gitlab_archive=False):
        assert runner is discovery_renderer.isolated_runner
        assert gitlab_archive is False
        assert source.read_bytes() == data
        progress({'stage':'Normalizing','images':1})
        return {'completeness':'complete','roots':[],'nodes':[],'images':[],'metrics':{'images':1}}
    monkeypatch.setattr(discovery_engine,'run_discovery',discover)
    ctx=SimpleNamespace(check=lambda:None,stage=lambda *args:stages.append(args),checkpoint=checkpoints.append,
        session_factory=lambda:Session(db.get_bind()),_owned=lambda session:session.get(DurableJob,row.id))
    result=worker.handle(ctx,payload)
    db.expire_all()
    item=db.get(DiscoveryInventory,result['inventory_id'])
    assert item.group_id == 1 and item.source_hash == payload['source_hash']
    assert item.inventory['archive_hash'] == payload['source_hash']
    assert stages and checkpoints == [{'metrics':{'images':1}}]
    repeated=worker.handle(ctx,payload)
    assert repeated['inventory_id'] == item.id
    assert len(db.scalars(select(DiscoveryInventory).where(DiscoveryInventory.job_id==row.id)).all()) == 1


def test_source_encryption_authenticates_and_removes_scratch(tmp_path):
    source=tmp_path/'archive.zip'
    plaintext=b'repository-password=private-value\n'*100000
    with encrypted_writer(source,'a'*32) as stream:
        for start in range(0,len(plaintext),65536):
            stream.write(plaintext[start:start+65536])
    assert b'private-value' not in source.read_bytes()
    digest=hashlib.sha256(plaintext).hexdigest()
    with decrypted_source(source,'a'*32,digest) as scratch:
        assert scratch.read_bytes() == plaintext
    assert not scratch.exists()
    with pytest.raises(SourceStorageError,match='authentication'):
        with decrypted_source(source,'b'*32,digest):
            pytest.fail('wrong source identity exposed plaintext')
    corrupted=bytearray(source.read_bytes())
    corrupted[-1] ^= 1
    source.write_bytes(corrupted)
    with pytest.raises(SourceStorageError,match='authentication'):
        with decrypted_source(source,'a'*32,digest):
            pytest.fail('tampered source exposed plaintext')


def test_source_storage_missing_key_and_plaintext_fail_closed(tmp_path,monkeypatch):
    source=tmp_path/'source.zip'
    source.write_bytes(b'plaintext must never be accepted'*10)
    with pytest.raises(SourceStorageError,match='not encrypted'):
        with decrypted_source(source,'a'*32,'0'*64):
            pytest.fail('plaintext source accepted')
    monkeypatch.delenv('CATS_CONFIG_ENCRYPTION_KEY')
    with pytest.raises(SourceStorageError,match='not configured'):
        with encrypted_writer(tmp_path/'new.zip','a'*32):
            pytest.fail('missing key accepted')
    assert not (tmp_path/'new.zip').exists()


def test_confirm_stages_one_group_service_with_existing_authority(api):
    client, db, current = api
    job(db)
    current['auth'] = scoped_auth(db.get(Group, 1))
    current['auth'].user.role_assignments[0].role.name = 'Cybersecurity'
    current['auth'].user.role_assignments[0].role.system = True
    response = post(client, '/own/confirm', {'new_service_key':'discovered-service','root_ids':['root']})
    assert response.status_code == 200, response.text
    service = db.scalar(select(Service).where(Service.service_key == 'discovered-service'))
    assert service.lifecycle_status == 'staged'
    assert [g.id for g in service.groups] == [1]
    assert db.get(DiscoveryConfirmation, response.json()['inventory_id']).service_id == service.id


def test_confirm_cannot_stage_without_accounts_authority_or_valid_inventory(api):
    client, db, current = api
    job(db)
    data = {'new_service_key':'unauthorized','root_ids':['root']}
    assert post(client, '/own/confirm', data).status_code == 403
    current['auth'] = scoped_auth(db.get(Group, 1))
    current['auth'].user.role_assignments[0].role.name = 'Cybersecurity'
    current['auth'].user.role_assignments[0].role.system = True
    assert post(client, '/own/confirm', {**data,'root_ids':['unknown']}).status_code == 422
    assert db.scalar(select(Service).where(Service.service_key == 'unauthorized')) is None
    assert post(client, '/own/confirm', {**data,'new_service_key':'one'}).status_code == 409


def test_supplements_are_scoped_immutable_and_encrypted(api, tmp_path):
    client, db, _ = api
    old, original = job(db)
    job(db, 'foreign', 2)
    folder=tmp_path/old.payload['source_id']; folder.mkdir()
    (folder/old.payload['filename']).write_bytes(b'original encrypted source')
    endpoint='/api/discovery/own/supplements'
    fields={'acknowledge_non_secret':'true', 'target_path':'chart'}
    upload={'upload':('values.yaml', b'image: nginx:1', 'text/plain')}
    assert client.post('/api/discovery/foreign/supplements', data=fields, files=upload).status_code == 404
    assert client.post(endpoint, data=fields, files=upload).status_code == 403
    response=client.post(endpoint, data=fields, files=upload, headers={'X-CSRF-Token':'csrf'})
    assert response.status_code == 200, response.text
    new=db.get(DurableJob, response.json()['job_id'])
    supplement=new.payload['supplements'][0]
    assert new.payload['source_id'] == old.payload['source_id']
    assert supplement['parent_inventory_id'] == original.id
    assert supplement['parent_content_hash'] == original.content_hash
    assert 'supplements' not in old.payload
    assert original.content_hash == '1'*64
    encrypted=tmp_path/supplement['source_id']/supplement['filename']
    assert b'image: nginx:1' not in encrypted.read_bytes()
    with decrypted_source(encrypted, supplement['source_id'], supplement['source_hash']) as plain:
        assert plain.read_bytes() == b'image: nginx:1'
    fields['target_path']='../outside'
    assert client.post(endpoint, data=fields, files=upload, headers={'X-CSRF-Token':'csrf'}).status_code == 422


def test_discovery_upload_default_exceeds_old_limit_and_optional_budget(api, monkeypatch):
    client, db, _ = api
    monkeypatch.delenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', raising=False)
    data = b'x' * (33 * 1024 * 1024)
    form = {'group_id': '1', 'csrf_token': 'csrf'}
    response = client.post('/api/discovery', data=form, files={'upload': ('source.zip', data)})
    assert response.status_code == 200, response.text
    row = db.get(DurableJob, response.json()['job_id'])
    assert row.payload['source_hash'] == hashlib.sha256(data).hexdigest()
    monkeypatch.setenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', '4')
    response = client.post('/api/discovery', data=form, files={'upload': ('images.txt', b'nginx:1')})
    assert response.status_code == 413


def test_discovery_budget_has_no_upper_clamp(monkeypatch):
    from app.discovery_limits import limit
    monkeypatch.setenv('CATS_DISCOVERY_MAX_UPLOAD_BYTES', str(1024 * 1024 * 1024))
    assert limit('UPLOAD_BYTES') == 1024 * 1024 * 1024


@pytest.mark.parametrize('failure,status,detail', [
    ('ENOSPC', 507, 'storage'), ('EDQUOT', 507, 'quota'),
    ('ENOMEM', 503, 'memory'), ('MemoryError', 503, 'memory'),
])
@pytest.mark.parametrize('supplement', [False, True])
def test_upload_resource_exhaustion_removes_encrypted_partial(api, tmp_path, monkeypatch, failure, status, detail, supplement):
    import errno
    from contextlib import contextmanager
    client, db, _ = api
    if supplement:
        old, _ = job(db)
        original = tmp_path/old.payload['source_id']; original.mkdir()
        (original/old.payload['filename']).write_bytes(b'original encrypted input')
        endpoint = '/api/discovery/own/supplements'
        fields = {'acknowledge_non_secret': 'true', 'target_path': 'chart'}
    else:
        endpoint = '/api/discovery'
        fields = {'group_id': '1', 'csrf_token': 'csrf'}
    before = set(tmp_path.iterdir())
    @contextmanager
    def failing_writer(path, identity):
        # Preserve the real encrypted writer's partial-write behavior.
        with encrypted_writer(path, identity) as stream:
            def fail(data):
                stream.write(data)
                if failure == 'MemoryError':
                    raise MemoryError()
                raise OSError(getattr(errno, failure), 'private path should not escape')
            yield SimpleNamespace(write=fail)
    monkeypatch.setattr(routes, 'encrypted_writer', failing_writer)
    response = client.post(endpoint, data=fields, files={'upload': ('values.yaml', b'image: nginx:1')}, headers={'X-CSRF-Token': 'csrf'})
    assert response.status_code == status, response.text
    assert detail in response.json()['detail']
    assert 'private path' not in response.text
    assert set(tmp_path.iterdir()) == before
    assert len(db.scalars(select(DurableJob)).all()) == int(supplement)


@pytest.mark.parametrize('selection', [[], {'release': 'values.yaml'}, {'release': [1]}, {'release': None}])
def test_component_values_requires_ordered_path_lists(api, selection):
    client, db, _ = api
    old, _ = job(db)
    folder = worker.upload_root() / old.payload['source_id']
    folder.mkdir()
    with encrypted_writer(folder / 'images.txt', 'a'*32) as stream:
        stream.write(b'nginx:1.2')
    assert post(client, '/own/retry', {'options': {'component_values': selection}}).status_code == 422
