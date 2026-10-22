from types import SimpleNamespace
import pytest
from app import oci_proxy as proxy, oci_evidence as evidence, cyber_approvals as approvals
from test_oci_proxy import setup, digest
from app.models import Execution
from app.durable_jobs import now

@pytest.fixture
def bundle(setup, monkeypatch, tmp_path):
    s = setup
    # Production includes this router in the standalone proxy app.
    if not any(getattr(route, 'path', '') == '/api/oci/evidence/{repository:path}/manifests/{digest}/offline' for route in proxy.app.routes):
        proxy.app.include_router(evidence.router)
    monkeypatch.setattr(approvals, 'root', lambda: tmp_path)
    data = b'unchanged Cyber signed bundle fixture'
    folder = tmp_path / 'retained'
    folder.mkdir()
    path = folder / 'bundle.zip'
    path.write_bytes(data)
    with s.sessions() as db:
        execution = Execution(service_id=1, execution_key='evidence-source', scanned_at=now(), complete=True, raw_payload={})
        db.add(execution); db.flush()
        row = approvals.CyberApproval(service_id=1, source_execution_id=execution.id, release_key='retained',
            variant='current_service', status='approved', publish_status='published', snapshot={}, snapshot_digest=approvals.digest({}))
        db.add(row); db.flush()
        row.publication = {'status':'published','verification_status':'verified','signature_status':'verified',
            'manifest':{'approval_id':row.id,'snapshot_digest':row.snapshot_digest},
            'bundle_path':str(path),'bundle_digest':digest(data)}
        db.commit()
        identity = row.id
    def authorize(db, mapping, value):
        return SimpleNamespace(allowed=value in s.allowed and mapping.enabled and not mapping.suspended,
            reason='test_denied', approval_id=identity)
    monkeypatch.setattr(proxy, 'authorize', authorize)
    return SimpleNamespace(**vars(s), path=path, data=data, identity=identity,
        url='/api/oci/evidence/project/image/manifests/'+s.image+'/offline')


def test_original_bundle_and_digest_returned(bundle):
    response = bundle.client.get(bundle.url)
    assert response.status_code == 200
    assert response.content == bundle.data
    assert response.headers['x-cats-evidence-digest'] == digest(bundle.data)
    assert response.headers['cache-control'] == 'private, no-store'

@pytest.mark.parametrize('mode',['modified','outside','unsigned','wrong_receipt'])
def test_unverified_or_unconfined_bundle_denied(bundle, mode):
    if mode == 'modified':
        bundle.path.write_bytes(b'modified')
    else:
        with bundle.sessions() as db:
            row = db.get(approvals.CyberApproval, bundle.identity)
            value = dict(row.publication)
            if mode == 'outside':
                path = bundle.path.parent.parent / 'outside.zip'
                path.write_bytes(bundle.data)
                value['bundle_path'] = str(path)
            elif mode == 'unsigned':
                value['signature_status'] = 'unsigned'
            else:
                value['manifest'] = {'approval_id':999,'snapshot_digest':row.snapshot_digest}
            row.publication = value
            db.commit()
    assert bundle.client.get(bundle.url).status_code in (403,404)


def test_policy_denial_and_machine_revocation_apply_to_evidence(bundle):
    from app.oci_models import OCIPrincipal
    bundle.allowed.clear()
    assert bundle.client.get(bundle.url).status_code == 403
    bundle.allowed.add(bundle.image)
    with bundle.sessions() as db:
        db.get(OCIPrincipal, bundle.machine_id).enabled = False
        db.commit()
    assert bundle.client.get(bundle.url).status_code == 401


def test_changed_approval_before_send_is_denied(bundle, monkeypatch):
    calls=[]
    def changed(*args):
        calls.append(1)
        return SimpleNamespace(allowed=True, reason='', approval_id=bundle.identity if len(calls)==1 else 999)
    monkeypatch.setattr(proxy, 'authorize', changed)
    assert bundle.client.get(bundle.url).status_code == 403
    assert len(calls) == 2


def test_digest_and_credentials_required(bundle):
    assert bundle.client.get(bundle.url.replace(bundle.image,'latest')).status_code == 400
    assert bundle.client.get(bundle.url, headers={'Authorization':''}).status_code == 401


def test_repository_grant_is_required(bundle):
    from app.oci_models import OCIPrincipal
    with bundle.sessions() as db:
        db.get(OCIPrincipal, bundle.machine_id).repository_ids = []
        db.commit()
    assert bundle.client.get(bundle.url).status_code == 403


def test_revocation_during_integrity_check_is_rechecked(bundle, monkeypatch):
    from app.oci_models import OCIPrincipal
    original = evidence.hashlib.file_digest
    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        with bundle.sessions() as db:
            db.get(OCIPrincipal, bundle.machine_id).enabled = False
            db.commit()
        return result
    monkeypatch.setattr(evidence.hashlib, 'file_digest', revoke)
    assert bundle.client.get(bundle.url).status_code == 401
