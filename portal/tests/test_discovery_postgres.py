"""Opt-in PostgreSQL discovery persistence and database evidence guards."""
import base64
import hashlib
import os
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models import Group, Service, ServiceGroup, User
from app.discovery_models import DiscoveryInventory, DiscoveryConfirmation, DiscoveryDistribution, DiscoveryDistributionScan
from app.discovery_sources import encrypted_writer
from app.discovery_worker import handle
from app.durable_jobs import DurableJob, JobContext, claim, execute, submit


@pytest.fixture
def postgres():
    if not os.getenv('CATS_TEST_POSTGRES_URL'):
        pytest.skip('Requires disposable PostgreSQL')
    url=os.environ['CATS_TEST_POSTGRES_URL']
    engine=create_engine(url)
    schema='cats_discovery_test_'+uuid.uuid4().hex
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated=create_engine(url,connect_args={'options':f'-c search_path={schema}'})
    sessions=sessionmaker(bind=isolated,expire_on_commit=False)
    try:
        Base.metadata.create_all(isolated)
        yield isolated, sessions
    finally:
        isolated.dispose()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


def test_postgres_encrypted_discovery_and_immutable_evidence(postgres, monkeypatch, tmp_path):
    isolated, sessions = postgres
    monkeypatch.setenv('CATS_DISCOVERY_UPLOAD_ROOT',str(tmp_path))
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY',base64.urlsafe_b64encode(b'1'*32).decode())
    token=uuid.uuid4().hex
    folder=tmp_path/token
    folder.mkdir()
    data=b'nginx:1.27\nredis:7.4\n'
    with encrypted_writer(folder/'images.txt',token) as stream:
        stream.write(data)
    payload={'group_id':1,'source_id':token,'filename':'images.txt',
             'source_hash':hashlib.sha256(data).hexdigest(),'options':{}}
    with sessions() as db:
        db.add(Group(id=1,name='Discovery test'))
        db.commit()
        submitted=submit(db,kind='discovery',payload=payload,dedupe_key=token)
    claimed=claim(('discovery',),'discovery-integration',sessions)
    assert claimed and claimed.id == submitted.id
    ctx=JobContext(claimed,sessions)
    result=handle(ctx,payload)
    ctx.finish(result)
    with sessions() as db:
        item=db.get(DiscoveryInventory,result['inventory_id'])
        assert item.group_id == 1
        assert item.source_hash == payload['source_hash']
        assert item.inventory['images']
        assert db.get(DurableJob,claimed.id).status == 'completed'
        assert result['completeness'] == item.inventory['completeness']
    for statement in ('UPDATE discovery_inventories SET content_hash = :replacement WHERE id = :id',
                      'DELETE FROM discovery_inventories WHERE id = :id'):
        with pytest.raises(DBAPIError,match='immutable'):
            with isolated.begin() as db:
                db.execute(text(statement),{'id':result['inventory_id'],'replacement':'f'*64})
    with sessions() as db:
        assert db.get(DiscoveryInventory,result['inventory_id']).source_hash == payload['source_hash']


def test_postgres_cancel_running_worker_and_published_inventory(postgres):
    from fastapi import HTTPException
    from app.discovery_routes import cancel
    from test_discovery_routes import scoped_auth
    _, sessions = postgres
    class CancelRequest:
        headers = {}
        async def stream(self):
            yield b'{"csrf_token":"csrf"}'
    with sessions() as db:
        db.add_all([Group(id=1, name='Group'), User(id=7, username='manager', display_name='Manager')])
        db.commit()
        active = submit(db, kind='discovery', payload={'group_id': 1})
        submitted_id = active.id
    claimed = claim(('discovery',), 'cancel-test', sessions)
    def handler(ctx, payload):
        with sessions() as db:
            result = asyncio.run(cancel(submitted_id, CancelRequest(), scoped_auth(db.get(Group, 1)), db))
            assert result['job']['status'] == 'running' and result['job']['cancel_requested']
        ctx.check()
        pytest.fail('Worker failed to acknowledge cancellation')
    execute(claimed, handler, sessions)
    with sessions() as db:
        assert db.get(DurableJob, submitted_id).status == 'cancelled'
        db.add(DurableJob(id='published', kind='discovery', status='running', payload={'group_id': 1},
                          result={'inventory_id': 'published-inventory'}))
        db.commit()
        with pytest.raises(HTTPException) as conflict:
            asyncio.run(cancel('published', CancelRequest(), scoped_auth(db.get(Group, 1)), db))
        assert conflict.value.status_code == 409
        assert not db.get(DurableJob, 'published').cancel_requested


def test_postgres_distribution_admission_is_atomic_and_immutable(postgres, monkeypatch):
    from fastapi import HTTPException
    from app import scan_coordination as scans
    from app.cyber_approvals import digest
    isolated, sessions = postgres
    monkeypatch.setattr(scans, 'SessionLocal', sessions)
    selected = dict(images=['a:1'], inventory_id='inventory', source_hash='a'*64, content_hash='b'*64,
                    root_ids=['chart'], discovery_completeness='complete',
                    image_occurrences=[{'reference': 'a:1', 'root_id': 'chart', 'component_id': 'workload'}])
    checksum = digest(selected)
    with sessions() as db:
        db.add_all([User(id=1, username='manager', display_name='Manager'), Group(id=1, name='Group'),
                    Service(id=1, service_key='service', name='Service'),
                    DurableJob(id='done', kind='discovery', status='completed', payload={})])
        db.flush()
        db.add(ServiceGroup(service_id=1, group_id=1))
        db.add(DiscoveryInventory(id='inventory', job_id='done', group_id=1, source_hash='a'*64,
                                  content_hash='b'*64, inventory={}))
        db.flush()
        db.add(DiscoveryConfirmation(id='confirmed', inventory_id='inventory', service_id=1,
                                     confirmed_by=1, root_ids=[]))
        db.flush()
        distribution = DiscoveryDistribution(id='distribution', confirmation_id='confirmed', service_id=1,
                                             name='Subset', selection=selected, selection_digest=checksum)
        db.add(distribution)
        db.commit()
        context = distribution.scan_context()
    payload = dict(status='queued', ingest_scope='distribution', ingest_service_id='service',
                   image_list='a:1', definition_context=context)
    barrier = Barrier(2)
    def launch(key):
        barrier.wait(timeout=10)
        try:
            scans.DurableJobs()[key] = payload
        except scans.DistributionScanInProgress as active:
            return active.job_id
        return key
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.map(launch, ['scan-a', 'scan-b'])
    assert first == second
    with sessions() as db:
        receipts = db.scalars(select(DiscoveryDistributionScan)).all()
        assert [(r.distribution_id, r.scan_job_id) for r in receipts] == [('distribution', first)]
        assert [r.id for r in db.scalars(select(scans.ScanJob))] == [first]
    with pytest.raises(HTTPException):
        scans.DurableJobs()['forged'] = {**payload, 'image_list': 'outside:1'}
    with pytest.raises(HTTPException):
        scans.DurableJobs()['forged-owners'] = {**payload, 'definition_context': {**context, 'discovery_images': []}}
    for statement in ["DELETE FROM discovery_distribution_scans", "UPDATE discovery_distributions SET name='changed'"]:
        with pytest.raises(DBAPIError, match='immutable'):
            with isolated.begin() as db:
                db.execute(text(statement))
