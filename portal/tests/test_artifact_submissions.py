"""Exercise project bearer, immutable retry identity and real scan queue admission over HTTP."""
import io
import json
import tarfile
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import artifact_submissions as submissions, main
from app.auth import SYSTEM_ROLES, token_hash
from app.database import Base, get_db
from app.models import AuditEvent, Execution, Group, Role, Service, ServiceVersion, User, UserRoleAssignment, utcnow
from app.project_credentials import ProjectCredential
from app.scan_coordination import ScanJob

PATH = '/api/v1/artifact-submissions'
TOKEN = 'cats_project_' + 'a' * 43
OTHER = 'cats_project_' + 'b' * 43
SECOND_PROJECT = 'cats_project_' + 'c' * 43
HEADERS = {'Authorization': 'Bearer ' + TOKEN, 'Idempotency-Key': 'build-12:scan'}


@pytest.fixture
def portal(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///' + (tmp_path / 'project.sqlite').as_posix(),
                           connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, autoflush=False, expire_on_commit=False)
    app = FastAPI()
    app.include_router(submissions.router)
    def database():
        with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    root = tmp_path / 'jobs'
    monkeypatch.setattr(main, 'PUBLIC_JOB_ROOT', root)
    monkeypatch.setenv('CATS_MODE', 'full')
    with sessions() as db:
        group = Group(name='cyber')
        actor = User(username='issuer', display_name='Manager')
        role = Role(name='Service manager', permissions=SYSTEM_ROLES['Service Manager'])
        for key, secrets in [('alpha', [TOKEN, SECOND_PROJECT]), ('beta', [OTHER])]:
            service = Service(service_key=key, name=key.title(), groups=[group])
            db.add(UserRoleAssignment(user=actor, role=role, service=service))
            db.flush()
            for secret in secrets:
                db.add(ProjectCredential(service=service, created_by_id=actor.id, owning_group_id=group.id,
                    project_label='project', token_hash=token_hash(secret), scopes=['artifacts.submit'],
                    expires_at=utcnow()+timedelta(days=1)))
        db.commit()
    with TestClient(app) as client:
        yield client, sessions, root
    engine.dispose()


def _tar(files):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w:gz') as archive:
        for name, text in files.items():
            raw = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return content.getvalue()


def test_submit_status_replay_and_ingested_execution(portal):
    client, sessions, root = portal
    body = {'reference': 'registry.example/team/api:2', 'version': '2.0'}
    response = client.post(PATH, json=body, headers=HEADERS)
    assert response.status_code == 202, response.text
    receipt = response.json()
    assert (receipt['kind'], receipt['scan_status'], receipt['ingest_status']) == ('image', 'queued', 'pending')
    assert receipt['service_key'] == 'alpha' and receipt['duplicate'] is False
    assert response.headers['location'] == receipt['status_url']
    assert response.headers['cache-control'] == 'private, no-store'
    job_id = receipt['job_id']
    assert (root / job_id / 'input.tar.gz').is_file()
    duplicate = client.post(PATH, json=body, headers=HEADERS)
    assert duplicate.status_code == 200 and duplicate.json() == {**receipt, 'duplicate': True}
    conflict = client.post(PATH, json={**body, 'version':'3'}, headers=HEADERS)
    assert conflict.status_code == 409
    assert list(root.iterdir()) == [root/job_id]
    with sessions() as db:
        row = db.get(ScanJob, job_id)
        assert row.payload['ingest_service_id'] == 'alpha' and row.payload['project_credential_id']
        assert db.scalar(select(func.count()).select_from(ScanJob)) == 1
        audit = db.scalar(select(AuditEvent).where(AuditEvent.action == 'project_credential.used'))
        assert audit.detail['operation'] == 'artifact.submitted' and TOKEN not in json.dumps(audit.detail)
        with pytest.raises(HTTPException, match='409'):
            submissions.clear_service_submissions(db, receipt['service_id'])
        version = ServiceVersion(service_id=receipt['service_id'], version='2.0')
        db.add(version)
        db.flush()
        execution = Execution(service_id=receipt['service_id'], service_version_id=version.id, execution_key='public:'+job_id,
            scanned_at=utcnow(), complete=True, scan_scope='evidence', raw_payload={})
        db.add(execution)
        db.commit()
        execution_id = execution.id
        assert client.get(receipt['status_url'], headers=HEADERS).json()['execution_id'] is None
        row.payload = {**row.payload, 'pipeline_execution_id':execution_id, 'ingested':True}
        row.status = 'complete'
        db.commit()
    status = client.get(receipt['status_url'], headers={'Authorization': HEADERS['Authorization']})
    assert status.status_code == 200
    assert status.json()['execution_id'] == execution_id and status.json()['ingest_status'] == 'ingested'
    for wrong in [OTHER, SECOND_PROJECT]:
        assert client.get(receipt['status_url'], headers={'Authorization': 'Bearer '+wrong}).status_code == 404
    assert client.get(receipt['status_url']).status_code == 401


@pytest.mark.parametrize(('file', 'content', 'kind'), [
    ('service.tgz', _tar({'api/Chart.yaml':'apiVersion: v2\nname: api\nversion: 1.0.0\n'}), 'helm-chart'),
    ('image.tgz', _tar({'manifest.json':json.dumps([{'RepoTags':['team/api:1'], 'Config':'config.json', 'Layers':[]}]),
                       'config.json':'{}'}), 'docker-archive'),
    ('compose.yaml', b'services:\n  api:\n    image: example/api:1\n', 'compose'),
])
def test_streamed_upload_auto_detects_and_binds_bytes(portal, file, content, kind):
    client, sessions, root = portal
    response = client.post(PATH, files={'file':(file, content)}, headers=HEADERS)
    assert response.status_code == 202, response.text
    assert response.json()['kind'] == kind
    job_id = response.json()['id']
    assert client.post(PATH, files={'file':(file, content)}, headers=HEADERS).status_code == 200
    assert client.post(PATH, files={'file':(file, content+b'x')}, headers=HEADERS).status_code == 409
    assert not (root / job_id / 'submission-input').exists()
    assert (root / job_id / 'input.tar.gz').is_file()


def test_rejects_unscoped_credentials_unknown_fields_and_oversize_inputs(portal, monkeypatch):
    client, sessions, root = portal
    assert client.post(PATH, json={'reference':'api'}, headers={**HEADERS, 'Authorization':'Bearer global'}).status_code == 401
    for extra in [{'service_key':'beta'}, {'values':'password: secret'}, {'replace':True}]:
        assert client.post(PATH, json={'reference':'api', **extra}, headers=HEADERS).status_code == 422
    assert client.post(PATH, json={'reference':'https://example.com/file.tar'}, headers=HEADERS).status_code == 422
    assert client.post(PATH, json={'reference':'api'}, headers={'Authorization':HEADERS['Authorization']}).status_code == 422
    monkeypatch.setenv('CATS_PUBLIC_MAX_IMAGE_ARCHIVE_BYTES', '4')
    monkeypatch.setenv('CATS_PUBLIC_MAX_CHART_BYTES', '4')
    assert client.post(PATH, headers=HEADERS, files={'file':('x.yaml', b'12345')}).status_code == 413
    headers = {**HEADERS, 'content-type':'application/json'}
    assert client.post(PATH, headers=headers, content=iter([b'x'*8192, b'y'*8193])).status_code == 413
    assert client.post(PATH, headers={**headers, 'content-length':'bad'}, content=b'{}').status_code == 400
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(ScanJob)) == 0
        credential = db.scalar(select(ProjectCredential).where(ProjectCredential.token_hash == token_hash(TOKEN)))
        credential.scopes = ['evidence.write']
        db.commit()
    assert client.post(PATH, json={'reference':'api'}, headers=HEADERS).status_code == 403


def test_simultaneous_identical_retries_enqueue_once(portal):
    client, sessions, root = portal
    with ThreadPoolExecutor(max_workers=2) as workers:
        responses = list(workers.map(lambda _: client.post(PATH, json={'reference':'api:latest'}, headers=HEADERS), range(2)))
    assert sorted(r.status_code for r in responses) == [200,202], [r.text for r in responses]
    assert responses[0].json()['id'] == responses[1].json()['id']
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(ScanJob)) == 1
    assert len(list(root.iterdir())) == 1


def test_failed_admission_releases_key_and_removes_staging(portal, monkeypatch):
    client, sessions, root = portal
    monkeypatch.setenv('CATS_SCAN_QUEUE_CAPACITY', '1')
    first = client.post(PATH, json={'reference':'example/a:1'}, headers=HEADERS).json()
    headers = {**HEADERS, 'Idempotency-Key':'build-13:scan'}
    response = client.post(PATH, json={'reference':'example/b:1'}, headers=headers)
    assert response.status_code == 429
    assert list(root.iterdir()) == [root/first['id']]
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(submissions.ProjectArtifactSubmission)) == 1
        db.get(ScanJob, first['id']).status = 'cancelled'
        db.commit()
    assert client.post(PATH, json={'reference':'example/b:1'}, headers=headers).status_code == 202
    assert client.get(first['status_url'], headers=headers).json()['ingest_status'] == 'failed'
    with sessions() as db:
        db.delete(db.get(ScanJob, first['id']))
        db.commit()
    status = client.get(first['status_url'], headers=headers).json()
    assert status['scan_status'] == status['ingest_status'] == 'expired' and status['execution_id'] is None


def test_rejects_truncated_multipart_and_unexpected_field_names(portal):
    client, sessions, root = portal
    data = b'--cats\r\nContent-Disposition: form-data; name="file"; filename="input.yaml"\r\n\r\nservices:\n'
    headers = {**HEADERS, 'Content-Type': 'multipart/form-data; boundary=cats'}
    assert client.post(PATH, headers=headers, content=iter([data])).status_code == 400
    assert client.post(PATH, headers=HEADERS, files={'file':('../other.yaml', b'contents')}).status_code == 422
    assert client.post(PATH, headers=HEADERS, files={'file':('input.yaml', b'contents')},
                       data={'ingest_service_id':'beta'}).status_code == 422
    assert not root.exists()


def test_changed_owning_group_rolls_back_prepared_job_and_staging(portal, monkeypatch):
    from app import pipeline_scan_dispatch
    client, sessions, root = portal
    prepare = pipeline_scan_dispatch.prepare_scan
    def moved_service(*args, **kwargs):
        job = prepare(*args, **kwargs)
        job.payload = {**job.payload, 'pipeline_owning_group_id': job.payload['pipeline_owning_group_id'] + 1}
        return job
    monkeypatch.setattr(pipeline_scan_dispatch, 'prepare_scan', moved_service)
    result = client.post(PATH, json={'reference':'example/app:1'}, headers=HEADERS)
    assert result.status_code == 403
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(ScanJob)) == 0
        assert db.scalar(select(func.count()).select_from(submissions.ProjectArtifactSubmission)) == 0
    assert not list(root.iterdir())
