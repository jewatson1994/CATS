"""Real Harbor transport + actual CATS authorization using disposable evidence.

This fixture seeds a synthetic completed scan/approval, not a real scanner run or
human Cyber decision. It never writes to the deployed CATS database.
"""
import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys


def main(root):
    root = Path(root).resolve()
    os.environ['DATABASE_URL'] = 'sqlite://'
    os.environ['CATS_BOOTSTRAP_USERNAME'] = 'fixture'
    os.environ['CATS_BOOTSTRAP_PASSWORD'] = 'disposable-fixture-only'
    os.environ['CATS_OCI_CACHE_DIR'] = str(root / 'proxy-cache')
    from cryptography.fernet import Fernet
    os.environ['CATS_CONFIG_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'portal'))
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app import oci_proxy as proxy
    from app.database import Base
    from app.models import Service, Execution
    from app.oci_models import OCIUpstream, OCIRepository, OCIPrincipal
    from app.cyber_approvals import CyberApproval, digest as snapshot_digest
    from app.execution_summaries import payload_digest
    from app.release_validity import new_validity
    from app.secrets import encrypt_secret
    evidence = json.loads((root / 'smoke-results.json').read_text())
    password = json.loads((root / 'credentials.json').read_text())['admin']
    engine = create_engine('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    proxy.SessionLocal = sessions
    now = datetime.now(timezone.utc)
    with sessions() as db:
        service = Service(service_key='harbor-integration', name='Disposable Harbor fixture')
        upstream = OCIUpstream(name='fixture-harbor', endpoint=evidence['endpoint'],
            username=encrypt_secret('admin'), password=encrypt_secret(password),
            ca_pem=(root / 'harbor/tls/server.crt').read_text())
        db.add_all([service, upstream]); db.flush()
        execution = Execution(service_id=service.id, execution_key='synthetic-fixture',
            scanned_at=now, complete=True, scan_scope='service', raw_payload={})
        mapping = OCIRepository(public_repository='fixture/image', service_id=service.id,
            upstream_id=upstream.id, upstream_repository=evidence['repository'])
        db.add_all([execution, mapping]); db.flush()
        snapshot = dict(service_id=service.id, source_execution_id=execution.id,
            source_version_id=None, source_payload_digest=payload_digest({}),
            approval_validity=new_validity(now), artifacts=[dict(kind='image',
                reference=evidence['endpoint'].removeprefix('https://')+'/'+evidence['repository']+'@'+evidence['digest'],
                digest=evidence['digest'])])
        approval = CyberApproval(service_id=service.id, source_execution_id=execution.id,
            variant='current', status='approved', snapshot=snapshot,
            snapshot_digest=snapshot_digest(snapshot), decided_at=now)
        machine = OCIPrincipal(name='fixture', secret_hash=hashlib.sha256(b'fixture-token').hexdigest(),
            repository_ids=[mapping.id], expires_at=now+timedelta(hours=1))
        db.add_all([approval, machine]); db.commit(); approval_id = approval.id
    client = TestClient(proxy.app)
    client.headers['Authorization'] = 'Basic '+base64.b64encode(b'fixture:fixture-token').decode()
    path = '/v2/fixture/image/'
    assert client.get('/v2/').status_code == 200
    response = client.get(path+'manifests/'+evidence['tag'])
    assert response.status_code == 200, response.text
    assert response.headers['Docker-Content-Digest'] == evidence['digest']
    assert client.head(path+'manifests/'+evidence['digest']).status_code == 200
    response = client.get(path+'blobs/'+evidence['blob'])
    assert response.status_code == 200
    assert 'sha256:'+hashlib.sha256(response.content).hexdigest() == evidence['blob']
    assert client.get(path+'blobs/'+evidence['blob'], headers={'Range':'bytes=1-20'}).status_code == 206
    assert client.get(path+'referrers/'+evidence['digest']).status_code == 200
    with sessions() as db:
        db.get(CyberApproval, approval_id).revoked_at = datetime.now(timezone.utc)
        db.commit()
    assert client.get(path+'manifests/'+evidence['digest']).status_code == 403
    assert client.get(path+'blobs/'+evidence['blob']).status_code == 403
    assert client.get(path+'referrers/'+evidence['digest']).status_code == 403
    result = {'checks': ['actual CATS authorization and compliance engine', 'Harbor tag pull',
        'digest HEAD', 'blob digest integrity', 'range', 'referrers', 'revoked manifest denied',
        'revoked cached blob denied', 'revoked referrers denied'],
        'evidence': 'Synthetic DB scan/approval fixture; no scanner or human approval exercised'}
    (root / 'proxy-results.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    engine.dispose()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='.test-temp/harbor-local')
    main(parser.parse_args().root)
