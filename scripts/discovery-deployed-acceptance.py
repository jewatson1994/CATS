"""Opt-in deployed acceptance driver; run inside Discovery image against disposable DB.

The worker must run separately with the same database, encryption key and upload
volume. This driver never calls handle() or substitutes native renderer functions.
Run with PYTHONPATH=/app python /acceptance/discovery-deployed-acceptance.py.
The PowerShell companion provisions and removes isolated Docker resources.

Scope: real database, encrypted storage, deployed worker, sandboxed native tools,
request parsing, confirmation and durable Scan admission. Authentication context
is supplied by this driver; HTTP login/browser UI and downstream scanner execution
are outside this test. The first source is submitted through the durable queue;
the supplement exercises its actual multipart route. No production data is used.
"""
import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import uuid
import zipfile

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from starlette.requests import Request
from app.database import Base, engine, SessionLocal
from app import discovery_routes as routes
from app.auth import AuthContext
from app.models import Group, Service, ServiceGroup, User
from app.discovery_models import DiscoveryInventory, DiscoveryScan
from app.discovery_sources import encrypted_writer
from app.durable_jobs import DurableJob, submit


def request(data):
    async def receive():
        return {'type': 'http.request', 'body': json.dumps(data).encode(), 'more_body': False}
    return Request({'type': 'http', 'method': 'POST', 'headers': [(b'x-csrf-token', b'acceptance')]}, receive)


def acceptance_auth(db, group_id, user_id):
    assignment = SimpleNamespace(role=SimpleNamespace(name='Acceptance', system=False,
        permissions=['service.edit', 'scan.ingest']), service_id=None, group_id=group_id,
        group=db.get(Group, group_id))
    return AuthContext(user=SimpleNamespace(id=user_id, username='acceptance', display_name='Acceptance',
        role_assignments=[assignment]), session=SimpleNamespace(csrf_token='acceptance'))


def supplemental_request():
    boundary = 'acceptance-boundary'
    parts = []
    for name, value in [('target_path', 'compose'), ('acknowledge_non_secret', 'true')]:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n')
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="upload"; filename="runtime.env"\r\nContent-Type: application/octet-stream\r\n\r\nSETTING=nonsecret\nPASSWORD=ACCEPTANCE_SECRET_VALUE\n\r\n--{boundary}--\r\n')
    async def receive():
        return {'type': 'http.request', 'body': ''.join(parts).encode(), 'more_body': False}
    return Request({'type': 'http', 'method': 'POST', 'headers': [(b'x-csrf-token', b'acceptance'),
        (b'content-type', f'multipart/form-data; boundary={boundary}'.encode())]}, receive)


def wait_for_worker(job_id):
    deadline = time.monotonic() + (600 if os.getenv("DISCOVERY_ACCEPTANCE_ARCHIVE") else 150)
    while time.monotonic() < deadline:
        with SessionLocal() as db:
            row = db.get(DurableJob, job_id)
            if row.status in ('completed', 'failed', 'cancelled'):
                assert row.status == 'completed', (row.status, row.result)
                break
        time.sleep(1)
    else:
        raise AssertionError('Separate deployed worker did not complete job within the acceptance deadline')


def main():
    assert engine.dialect.name == 'postgresql', 'Use a disposable PostgreSQL database'
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        group = Group(name='Deployed acceptance ' + uuid.uuid4().hex)
        service = Service(service_key='acceptance-' + uuid.uuid4().hex, name='Acceptance')
        user = User(username='acceptance-' + uuid.uuid4().hex, display_name='Acceptance')
        db.add_all([group, service, user])
        db.flush()
        db.add(ServiceGroup(service_id=service.id, group_id=group.id))
        db.commit()
        group_id, service_id, user_id = group.id, service.id, user.id
    archive = os.getenv('DISCOVERY_ACCEPTANCE_ARCHIVE')
    if archive:
        content = Path(archive).read_bytes()
        token = uuid.uuid4().hex
        folder = Path(os.environ['CATS_DISCOVERY_UPLOAD_ROOT']) / token
        folder.mkdir()
        with encrypted_writer(folder / 'repository.zip', token) as stream:
            stream.write(content)
        with SessionLocal() as db:
            row = submit(db, kind='discovery', payload={'group_id': group_id,
                'source_id': token, 'filename': 'repository.zip',
                'source_hash': hashlib.sha256(content).hexdigest(), 'options': json.loads(os.getenv('DISCOVERY_ACCEPTANCE_OPTIONS', '{}'))}, dedupe_key=token)
            job_id = row.id
        wait_for_worker(job_id)
        with SessionLocal() as db:
            row = db.get(DurableJob, job_id)
            inventory = db.get(DiscoveryInventory, row.result['inventory_id']).inventory
            print(json.dumps(inventory), flush=True)
            assert inventory['roots'], inventory['diagnostics']
            if os.getenv('HELM_ALLOW_NETWORK') == 'true':
                assert inventory['images'], inventory['diagnostics']
        return
    files = {
        'chart/Chart.yaml': 'apiVersion: v2\nname: acceptance\nversion: 1.0.0\n',
        'chart/templates/pod.yaml': 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: helm\nspec:\n  containers:\n  - name: app\n    image: nginx:1.27\n',
        'kustom/kustomization.yaml': 'resources:\n- pod.yaml\nimages:\n- name: redis\n  newTag: "7.4"\n',
        'kustom/pod.yaml': 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: kustom\nspec:\n  containers:\n  - name: app\n    image: redis:7\n',
        'compose/compose.yaml': 'include: [extra.yaml]\nservices:\n  web:\n    extends: {file: base.yaml, service: base}\n    env_file: runtime.env\n  debug:\n    image: busybox:1.37\n    profiles: [debug]\n',
        'compose/base.yaml': 'services: {base: {image: alpine:3.21}}\n',
        'compose/extra.yaml': 'services: {cache: {image: redis:7.4}}\n',
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as bundle:
        for name, value in files.items():
            bundle.writestr(name, value)
    content = archive.getvalue()
    token = uuid.uuid4().hex
    folder = Path(os.environ['CATS_DISCOVERY_UPLOAD_ROOT']) / token
    folder.mkdir(parents=True)
    with encrypted_writer(folder / 'sources.zip', token) as stream:
        stream.write(content)
    assert not (folder / 'sources.zip').read_bytes().startswith(b'PK')
    with SessionLocal() as db:
        row = submit(db, kind='discovery', payload={
            'group_id': group_id, 'source_id': token, 'filename': 'sources.zip',
            'source_hash': hashlib.sha256(content).hexdigest(), 'options': {'profiles': ['debug']}}, dedupe_key=token)
        job_id = row.id
    wait_for_worker(job_id)
    with SessionLocal() as db:
        row = db.get(DurableJob, job_id)
        parent = db.get(DiscoveryInventory, row.result['inventory_id'])
        assert parent.inventory['completeness'] == 'partial', parent.inventory
        parent_id, parent_hash = parent.id, parent.content_hash
        parent_job_id = job_id
        auth = acceptance_auth(db, group_id, user_id)
        supplied = asyncio.run(routes.supplement(job_id, supplemental_request(), auth, db))
        job_id = supplied['job_id']
    assert job_id != parent_job_id
    wait_for_worker(job_id)
    with SessionLocal() as db:
        row = db.get(DurableJob, job_id)
        item = db.get(DiscoveryInventory, row.result['inventory_id'])
        inventory = item.inventory
        print(json.dumps({'job_id': job_id, 'completeness': inventory['completeness'], 'diagnostics': inventory.get('diagnostics')}), flush=True)
        assert inventory['completeness'] == 'complete', inventory.get('diagnostics')
        references = {image['reference'] for image in inventory['images']}
        assert {'nginx:1.27', 'redis:7.4', 'alpine:3.21', 'busybox:1.37'} <= references, references
        assert {'helm', 'kustomize', 'compose'} <= set(inventory['tool_versions']), inventory['tool_versions']
        inventory_id, content_hash = item.id, item.content_hash
        assert db.get(DiscoveryInventory, parent_id).content_hash == parent_hash
        assert inventory.get('supplemental_provenance'), inventory
        if os.getenv('CATS_DISCOVERY_RENDER_CACHE') == 'true':
            assert inventory['metrics']['render_cache_hits'] >= 2, inventory['metrics']
            assert inventory['metrics']['render_cache_misses'] >= 1, inventory['metrics']
        assert 'ACCEPTANCE_SECRET_VALUE' not in json.dumps(inventory)
        auth = acceptance_auth(db, group_id, user_id)
        confirmation = asyncio.run(routes.confirm(job_id, request({'service_id': service_id,
            'root_ids': [root['id'] for root in inventory['roots']]}), auth, db))
        confirmation_id = confirmation['confirmed_inventory_id']
        scan = asyncio.run(routes.scan(job_id, request({'confirmation_id': confirmation_id}), auth, db))
        again = asyncio.run(routes.scan(job_id, request({'confirmation_id': confirmation_id}), auth, db))
        assert again['job_id'] == scan['job_id']
        assert db.get(DiscoveryScan, confirmation_id).scan_job_id == scan['job_id']
        from app import main as portal
        queued = portal.PUBLIC_JOBS[scan['job_id']]
        assert queued['status'] == 'queued'
        assert queued['ingest_service_db_id'] == service_id
        assert queued['owner_user_id'] == user_id
        assert queued['definition_context']['discovery_inventory_id'] == inventory_id
        assert queued['definition_context']['discovery_confirmation_id'] == confirmation_id
        assert (portal.PUBLIC_JOB_ROOT / scan['job_id'] / 'input.tar.gz').is_file()
        assert {'nginx:1.27', 'redis:7.4', 'alpine:3.21', 'busybox:1.37'} <= set(queued['image_list'].splitlines())
    for statement in ('UPDATE discovery_inventories SET content_hash = :replacement WHERE id = :id',
                      'DELETE FROM discovery_inventories WHERE id = :id'):
        try:
            with engine.begin() as db:
                db.execute(text(statement), {'id': inventory_id, 'replacement': 'f' * 64})
        except DBAPIError as exc:
            assert 'immutable' in str(exc)
        else:
            raise AssertionError('Database allowed immutable inventory mutation')
    with SessionLocal() as db:
        assert db.get(DiscoveryInventory, inventory_id).content_hash == content_hash
    print(json.dumps({'result': 'PASS', 'worker_job': job_id, 'inventory_id': inventory_id,
        'scan_job': scan['job_id'], 'tool_versions': inventory['tool_versions'], 'metrics': inventory['metrics'],
        'checks': ['encrypted source', 'partial to complete supplemental rerun', 'parent evidence preserved', 'Compose include/extends/env_file/profile', 'secret redaction', 'separate durable worker', 'native Helm/Kustomize/Compose',
                   'immutable PostgreSQL evidence', 'review confirmation', 'durable Scan linkage', 'idempotent handoff']}), flush=True)


if __name__ == '__main__':
    main()
