from datetime import timedelta
import json
from types import SimpleNamespace as N
import uuid
import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.database import Base, get_db
from app.auth import require_user
from app.models import ManagedValidator, ValidatorProvisioningAttempt, ValidatorTrustDomain
from app import validator_management as m, validator_enrollment as e
from app.secrets import encrypt_secret, decrypt_secret

@pytest.fixture
def factory(monkeypatch):
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions=sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(m,'SessionLocal',sessions)
    monkeypatch.setenv('CATS_CONFIG_ENCRYPTION_KEY',Fernet.generate_key().decode())
    yield sessions
    engine.dispose()

def validator(db):
    v=ManagedValidator(id=uuid.uuid4().hex,name='Test validator',host='192.168.1.30',username='ubuntu',ssh_port=22,api_port=8443,
        ssh_fingerprint='SHA256:trusted',preflight={'status':'supported','facts':{'architecture':'amd64'}})
    db.add(v);db.commit();return v

def csr(v,host=None,identity=None):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    return (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,identity or v.id)]))
        .add_extension(x509.SubjectAlternativeName([e.host_name(host or v.host),x509.UniformResourceIdentifier('urn:cats:validator:'+(identity or v.id))]),False)
        .sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())

def test_persistent_dedicated_ca_and_authorized_csr(factory):
    with factory() as db:
        domain=e.trust_domain(db);db.commit();identity=domain.id
        assert decrypt_secret(domain.encrypted_key).startswith('-----BEGIN PRIVATE KEY-----')
        assert domain.encrypted_key.startswith('enc:v1:')
        v=validator(db)
        attempt=N(validator_id=v.id,status='RUNNING',action='provision',host_fingerprint=v.ssh_fingerprint)
        cert,metadata=e.sign_csr(domain,v,csr(v),authorized_attempt=attempt)
        assert x509.load_pem_x509_certificate(cert.encode()).issuer==x509.load_pem_x509_certificate(domain.certificate.encode()).subject
        assert metadata['validator_id']==v.id and metadata['status']=='active'
        for bad in (csr(v,host='192.168.1.31'),csr(v,identity='other')):
            with pytest.raises(ValueError):e.sign_csr(domain,v,bad,authorized_attempt=attempt)
        attempt.host_fingerprint='changed'
        with pytest.raises(ValueError):e.sign_csr(domain,v,csr(v),authorized_attempt=attempt)
    with factory() as db:
        assert e.trust_domain(db).id==identity
        assert len(db.scalars(select(ValidatorTrustDomain)).all())==1

def test_no_duplicate_active_jobs_and_interrupted_secrets_retired(factory):
    from sqlalchemy.exc import IntegrityError
    with factory() as db:
        v=validator(db);vid=v.id
        a=ValidatorProvisioningAttempt(id=uuid.uuid4().hex,validator_id=vid,action='provision',status='RUNNING',
            encrypted_credentials=encrypt_secret('secret'),lease_until=m.now()-timedelta(seconds=1))
        db.add(a);db.commit();aid=a.id
        db.add(ValidatorProvisioningAttempt(id=uuid.uuid4().hex,validator_id=vid,action='provision'))
        with pytest.raises(IntegrityError):db.commit()
        db.rollback()
    m.maintenance()
    with factory() as db:
        a=db.get(ValidatorProvisioningAttempt,aid)
        assert a.status=='FAILED' and a.encrypted_credentials is None

@pytest.mark.parametrize('condition',['good','stale','expired','revoked','failed_selftest','disabled','unhealthy'])
def test_scheduler_selects_only_eligible_managed_identity(factory,condition):
    with factory() as db:
        v=validator(db);v.status='READY';v.configuration={'endpoint':'https://managed'};v.health={'ready':True}
        v.certificate={'status':'active','expires_at':(m.now()+timedelta(days=1)).isoformat()}
        v.last_seen=m.now();v.last_self_test={'status':'VERIFIED'}
        if condition=='stale':v.last_seen=m.now()-timedelta(minutes=3)
        if condition=='expired':v.certificate={**v.certificate,'expires_at':m.now().isoformat()}
        if condition=='revoked':v.certificate={**v.certificate,'status':'revoked'}
        if condition=='failed_selftest':v.last_self_test={'status':'FAILED'}
        if condition=='disabled':v.enabled=False
        if condition=='unhealthy':v.health={'ready':False}
        db.commit()
        assert m.select_configuration(db,{'endpoint':'https://manual'})['endpoint']==('https://managed' if condition=='good' else 'https://manual')

def test_routes_permissions_csrf_secret_projection_and_remove(factory,monkeypatch):
    permissions={'validator.view','validator.create','validator.test','validator.provision','validator.remove'}
    auth=N(user=N(id=None,username='test',display_name='Test'),csrf_token='csrf',has=lambda key,*args:key in permissions)
    app=FastAPI();app.include_router(m.router)
    def session():
        with factory() as db:yield db
    app.dependency_overrides[get_db]=session;app.dependency_overrides[require_user]=lambda:auth
    monkeypatch.setattr(m,'payload_status',lambda:{'available':False})
    with TestClient(app) as client:
        assert client.post('/api/admin/validators',json={'name':'VM'}).status_code==403
        permissions.remove('validator.create')
        assert client.post('/api/admin/validators',json={'csrf_token':'csrf'}).status_code==403
        permissions.add('validator.create')
        response=client.post('/api/admin/validators',json={'csrf_token':'csrf','name':'VM','host':'192.168.1.30','username':'ubuntu'})
        assert response.status_code==200,response.text
        vid=response.json()['id'];url='/api/admin/validators/'+vid
        assert client.post(url+'/trust',json={'csrf_token':'csrf','fingerprint':'unknown'}).status_code==409
        assert client.post(url+'/remove',json={'csrf_token':'csrf'}).status_code==422
        assert client.post(url+'/remove',json={'csrf_token':'csrf','confirm':True}).status_code==200
        assert client.get(url).status_code==404
        assert client.get('/api/admin/validators').json()['validators']==[]


def test_failed_self_test_cannot_be_restored_by_health(factory,monkeypatch):
    with factory() as db:
        v=validator(db);vid=v.id;v.status='DEGRADED';v.configuration={'endpoint':'https://managed'}
        v.certificate={'status':'active'};v.last_self_test={'status':'FAILED','cleanup_status':'UNVERIFIED'};db.commit()
    monkeypatch.setattr(m,'check_health',lambda config:{'ready':True,'validator_id':vid})
    m.maintenance()
    with factory() as db:
        assert db.get(ManagedValidator,vid).status=='DEGRADED'


def test_upgrade_requires_explicit_confirmation(factory):
    with factory() as db:
        v=validator(db)
        with pytest.raises(Exception) as error:m.enqueue(db,N(),v,'upgrade',{})
        assert error.value.status_code==422
