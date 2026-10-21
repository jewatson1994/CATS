"""Opt-in PostgreSQL discovery persistence and database evidence guards."""
import base64
import hashlib
import os
import uuid
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models import Group
from app.discovery_models import DiscoveryInventory
from app.discovery_sources import encrypted_writer
from app.discovery_worker import handle
from app.durable_jobs import DurableJob, JobContext, claim, submit


@pytest.mark.skipif(not os.getenv('CATS_TEST_POSTGRES_URL'), reason='Requires disposable PostgreSQL')
def test_postgres_encrypted_discovery_and_immutable_evidence(monkeypatch, tmp_path):
    url=os.environ['CATS_TEST_POSTGRES_URL']
    engine=create_engine(url)
    schema='cats_discovery_test_'+uuid.uuid4().hex
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated=create_engine(url,connect_args={'options':f'-c search_path={schema}'})
    sessions=sessionmaker(bind=isolated,expire_on_commit=False)
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
    try:
        Base.metadata.create_all(isolated)
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
    finally:
        isolated.dispose()
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
