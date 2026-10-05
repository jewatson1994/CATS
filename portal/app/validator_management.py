"""HQ management of the existing validator protocol and temporary SSH bootstrap."""
from concurrent.futures import ThreadPoolExecutor
import asyncio
from datetime import datetime, timedelta, timezone
import hmac
import json
import os
from pathlib import Path
import re
import time
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update, or_, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import load_only
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from .auth import require_permission, record_audit, aware
from .database import get_db, SessionLocal
from .models import ManagedValidator, ValidatorProvisioningAttempt, ValidatorTrustDomain, PortalSetting
from .secrets import encrypt_secret, decrypt_secret
from .validator_bootstrap import SSHBootstrap, validate_target
from .validator_payload import select_payload, payload_catalog
from .validator_enrollment import trust_domain, sign_csr, operational_configuration
from . import validator_client, validator_payload_builds

router = APIRouter(prefix='/api/admin/validators', tags=['managed validators'])
WORKERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix='validator-provisioning')
ACTIVE = {'QUEUED','RUNNING'}
BOOTSTRAP = {'provision','reenroll','upgrade'}
_PAYLOAD_STATUS = {}

def now():
    return datetime.now(timezone.utc)

def payload_material(facts=None):
    local = validator_payload_builds.local_material(facts, session_factory=SessionLocal)
    if local is not None:
        return local
    root = Path(os.environ.get('CATS_VALIDATOR_PAYLOAD_DIR','/opt/cats/validator/payload'))
    expected = os.environ.get('CATS_VALIDATOR_PAYLOAD_SHA256','')
    if not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('A trusted CATS_VALIDATOR_PAYLOAD_SHA256 is required')
    material = select_payload(root, expected, facts)
    manifest = material[1]
    with SessionLocal() as db:
        record = db.scalar(select(PortalSetting).where(PortalSetting.key == 'validator.external_payload_metadata'))
        if record is None:
            record = PortalSetting(key='validator.external_payload_metadata', value='{}')
            db.add(record)
        prior = json.loads(record.value)
        platform = {k: manifest[k] for k in ('os', 'os_version', 'architecture', 'payload_version')}
        platforms = prior.get('platforms', []) if prior.get('digest') == expected else []
        platforms = [p for p in platforms if any(p.get(k) != platform[k] for k in ('os', 'os_version', 'architecture'))]
        record.value = json.dumps({'available': True, 'digest': expected, 'root': str(root), 'platforms': platforms + [platform]})
        db.commit()
    return material

def external_payload_status():
    key=(os.getenv('CATS_VALIDATOR_PAYLOAD_DIR'),os.getenv('CATS_VALIDATOR_PAYLOAD_SHA256'))
    cached=_PAYLOAD_STATUS.get(key)
    if cached and time.monotonic()-cached[0]<60:return dict(cached[1])
    try:
        root = Path(os.environ.get('CATS_VALIDATOR_PAYLOAD_DIR','/opt/cats/validator/payload'))
        expected = os.environ.get('CATS_VALIDATOR_PAYLOAD_SHA256','')
        entries = payload_catalog(root, expected)
        platforms=[]
        for entry in entries:
            _, manifest, _ = select_payload(root, expected, entry)
            platforms.append({k:manifest[k] for k in ('os','os_version','architecture','payload_version')})
        result={'available':True,'digest':expected,'platforms':platforms}
    except Exception:
        result={'available':False,'reason':'Configure a complete verified offline payload and its trusted manifest SHA256 before provisioning.'}
    _PAYLOAD_STATUS.clear();_PAYLOAD_STATUS[key]=(time.monotonic(),result)
    return dict(result)

def payload_status():
    inventory = validator_payload_builds.metadata_inventory(session_factory=SessionLocal)
    if not inventory['available']:
        with SessionLocal() as db:
            record = db.scalar(select(PortalSetting.value).where(PortalSetting.key == 'validator.external_payload_metadata'))
            external = json.loads(record) if record else {}
        if (external.get('digest') == os.getenv('CATS_VALIDATOR_PAYLOAD_SHA256') and
                external.get('root') == os.getenv('CATS_VALIDATOR_PAYLOAD_DIR', '/opt/cats/validator/payload')):
            inventory.update(external, source='external')
    return inventory


def authorized_payload(facts, digest):
    local = validator_payload_builds.local_material(facts, digest, session_factory=SessionLocal)
    return local if local is not None else payload_material(facts)


def public_attempt(a):
    return {k:getattr(a,k) for k in ('id','action','status','stage','stages','failure','cancel_requested','payload_digest',
                                   'host_fingerprint','started_at','completed_at','created_at')}

def provisioning_readiness(v, inventory=None):
    """Durable prerequisites; credentials and acknowledgments remain request state."""
    preflight = v.preflight or {}
    facts = preflight.get('facts') or {}
    host_checks = preflight.get('checks') or {}
    status = preflight.get('status')
    checks = {}

    def check(name, ready, reason, **details):
        checks[name] = {'ready': bool(ready), **details}
        if not ready:
            checks[name]['reason'] = reason

    check('fingerprint', v.ssh_fingerprint, 'Confirm the discovered SSH fingerprint.')
    check('connectionTest', bool(preflight), 'Complete an authenticated Test Connection.')
    check('preflight', status in {'supported', 'supported_with_warnings'}
          and not any(value is False for value in host_checks.values()),
          'Complete a supported authenticated host preflight.', status=status)
    check('sudo', host_checks.get('sudo', facts.get('sudo')) is True,
          'The authenticated host preflight must confirm sudo access.',
          password_required=facts.get('sudo_password_required'))
    check('apiPort', host_checks.get('api_port') is True,
          'The validator API port must be available or belong to the existing validator service.')
    platform = {key: facts.get(key) for key in ('os', 'os_version', 'architecture')}
    try:
        if not all(platform.values()):
            raise ValueError('Host platform has not been detected')
        # Polling reads durable verification records without inspecting assets.
        # Enqueue and the worker independently revalidate the actual assets.
        inventory = payload_status() if inventory is None else inventory
        matching = [entry for entry in inventory.get('platforms', [])
                    if all(entry.get(key) == value for key, value in platform.items())]
        if not inventory.get('available') or len(matching) != 1:
            raise ValueError('No unique verified host payload')
        check('payload', True, '', platform=platform, digest=inventory.get('digest'))
    except Exception:
        description = ' '.join(str(platform[key] or 'unknown') for key in ('os', 'os_version', 'architecture'))
        check('payload', False,
              f'No compatible verified {description} validator installation payload is configured.',
              platform=platform)
    reasons = [item['reason'] for item in checks.values() if not item['ready']]
    return {'ready': not reasons, 'checks': checks, 'blocking_reasons': reasons}


def public_validator(v, db=None, *, inventory=None):
    result = {k:getattr(v,k) for k in ('id','name','host','ssh_port','username','api_port','labels','status','enabled',
        'ssh_fingerprint','preflight','health','certificate','last_seen','last_self_test','created_at')}
    result['provisioning_readiness'] = provisioning_readiness(v, inventory)
    if db is not None:
        result['attempts'] = [public_attempt(a) for a in db.scalars(select(ValidatorProvisioningAttempt)
            .where(ValidatorProvisioningAttempt.validator_id==v.id).order_by(ValidatorProvisioningAttempt.created_at.desc()).limit(30))]
    return result

def get_validator(db, validator_id):
    v = db.get(ManagedValidator, validator_id)
    if not v or v.status == 'REMOVED':
        raise HTTPException(404, 'Validator not found')
    return v

async def body(request, auth):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data)>131072:
            raise HTTPException(413,'Request exceeds size limit')
    try:
        value = json.loads(data or b'{}')
    except (ValueError, UnicodeError):
        raise HTTPException(422,'Invalid JSON')
    if not isinstance(value,dict):
        raise HTTPException(422,'Expected a JSON object')
    supplied = value.pop('csrf_token', '') or request.headers.get('X-CSRF-Token','')
    if not isinstance(supplied,str) or not hmac.compare_digest(auth.csrf_token,supplied):
        raise HTTPException(403,'Invalid CSRF token')
    return value

def credentials(value):
    mode=value.get('auth_mode','password')
    keys=('password','sudo_password') if mode=='password' else ('private_key','passphrase','sudo_password')
    if mode not in {'password','key'} or not value.get(keys[0]):
        raise HTTPException(422,'Supply temporary authentication credentials')
    result={k:value[k] for k in keys if value.get(k)}
    if any(not isinstance(v,str) or len(v)>65536 or '\x00' in v for v in result.values()):
        raise HTTPException(422,'Invalid bootstrap credentials')
    return result

def target(v):
    return {k:getattr(v,k) for k in ('host','ssh_port','username','api_port')}

@router.get('')
def listing(db=Depends(get_db), auth=Depends(require_permission('validator.view'))):
    # Read metadata once; operation authorization verifies assets independently.
    inventory = payload_status()
    fields = ('id','name','host','ssh_port','username','api_port','labels','status','enabled',
              'ssh_fingerprint','preflight','health','certificate','last_seen','last_self_test','created_at')
    validators = db.scalars(select(ManagedValidator)
        .options(load_only(*(getattr(ManagedValidator, name) for name in fields)))
        .where(ManagedValidator.status!='REMOVED').order_by(ManagedValidator.created_at))
    return {'validators':[public_validator(v, inventory=inventory) for v in validators], 'payload':inventory}

@router.post('')
async def create(request:Request, db=Depends(get_db), auth=Depends(require_permission('validator.create'))):
    value=await body(request,auth)
    try:
        fields=validate_target(value.get('host',''), value.get('ssh_port',22), value.get('username','ubuntu'), value.get('api_port',8443))
        name=value.get('name','').strip()
        if not name or len(name)>120 or any(ord(c)<32 for c in name): raise ValueError()
    except (ValueError,TypeError,AttributeError):
        raise HTTPException(422,'Invalid validator name or target')
    v=ManagedValidator(id=uuid.uuid4().hex,name=name,**fields)
    db.add(v); db.flush(); record_audit(db,auth,'validator.created','managed_validator',v.id,host=v.host)
    db.commit(); return public_validator(v,db)

@router.get('/{validator_id}')
def detail(validator_id:str,db=Depends(get_db),auth=Depends(require_permission('validator.view'))):
    return public_validator(get_validator(db,validator_id),db)

def ensure_idle(db,v):
    if db.scalar(select(ValidatorProvisioningAttempt.id).where(ValidatorProvisioningAttempt.validator_id==v.id,
            ValidatorProvisioningAttempt.status.in_(ACTIVE))):
        raise HTTPException(409,'A validator operation is already active')

@router.post('/{validator_id}/connection')
async def connection(validator_id:str,request:Request,db=Depends(get_db),auth=Depends(require_permission('validator.test'))):
    value=await body(request,auth); v=get_validator(db,validator_id); ensure_idle(db,v)
    try:
        if not value.get('password') and not value.get('private_key'):
            fingerprint=await asyncio.to_thread(SSHBootstrap(target(v),{}).discover_fingerprint)
            v.discovered_fingerprint=fingerprint
            record_audit(db,auth,'validator.host_key_discovered','managed_validator',v.id,fingerprint=fingerprint)
            db.commit(); return {'trust_required':True,'fingerprint':fingerprint}
        if not v.ssh_fingerprint: raise HTTPException(409,'Confirm the SSH fingerprint before authenticating')
        temporary=credentials(value)
        host_target=target(v);pin=v.ssh_fingerprint
        def probe():
            try:
                with SSHBootstrap(host_target,temporary,pin) as ssh:return ssh.preflight()
            finally:temporary.clear()
        v.preflight=await asyncio.to_thread(probe)
        record_audit(db,auth,'validator.connection_tested','managed_validator',v.id,status=v.preflight['status'])
        db.commit(); return {'preflight':v.preflight}
    except HTTPException: raise
    except Exception:
        record_audit(db,auth,'validator.connection_failed','managed_validator',v.id)
        db.commit(); raise HTTPException(422,'SSH connection or preflight failed. Check the confirmed host key, credentials, sudo access and connectivity.')

@router.post('/{validator_id}/trust')
async def trust(validator_id:str,request:Request,db=Depends(get_db),auth=Depends(require_permission('validator.provision'))):
    value=await body(request,auth); v=get_validator(db,validator_id); ensure_idle(db,v)
    fingerprint=value.get('fingerprint')
    if not isinstance(fingerprint,str) or not v.discovered_fingerprint or not hmac.compare_digest(fingerprint,v.discovered_fingerprint):
        raise HTTPException(409,'Discover the host key before explicitly confirming it')
    v.ssh_fingerprint=fingerprint; v.discovered_fingerprint=None; v.preflight={}
    record_audit(db,auth,'validator.host_key_trusted','managed_validator',v.id,fingerprint=fingerprint)
    db.commit(); return public_validator(v,db)

def enqueue(db,auth,v,action,value):
    ensure_idle(db,v)
    if action=='upgrade' and value.get('confirm_upgrade') is not True:
        raise HTTPException(422,'Explicit upgrade confirmation required')
    temporary=None; digest=None
    if action in BOOTSTRAP:
        if not v.ssh_fingerprint or v.preflight.get('status') not in {'supported','supported_with_warnings'}:
            raise HTTPException(409,'Confirm the SSH host key and complete a supported preflight first')
        if any(check is False for check in v.preflight.get('checks', {}).values()):
            raise HTTPException(409,'Resolve failed host preflight checks before provisioning')
        if v.preflight.get('warnings') and value.get('acknowledge_warnings') is not True:
            raise HTTPException(409,'Acknowledge the resource warnings')
        try:
            _,manifest,digest=payload_material(v.preflight.get('facts',{}))
            temporary=encrypt_secret(json.dumps(credentials(value)))
        except HTTPException: raise
        except Exception: raise HTTPException(409,'Verified payload or encrypted credential storage is unavailable for this host')
    elif not v.configuration or v.certificate.get('status')!='active':
        raise HTTPException(409,'Validator does not have an active operational identity')
    a=ValidatorProvisioningAttempt(id=uuid.uuid4().hex,validator_id=v.id,operator_id=auth.user.id,action=action,
        encrypted_credentials=temporary,payload_digest=digest,host_fingerprint=v.ssh_fingerprint)
    db.add(a)
    if action!='test': v.status='PROVISIONING' if action in BOOTSTRAP else 'SELF_TESTING' if action=='self-test' else 'ROTATING'
    record_audit(db,auth,'validator.'+action+'_requested','managed_validator',v.id,attempt_id=a.id)
    try: db.commit()
    except IntegrityError:
        db.rollback(); raise HTTPException(409,'A validator operation is already active')
    WORKERS.submit(run_attempt,a.id)
    return {'attempt':public_attempt(a)}

def action_route(action,permission):
    async def endpoint(validator_id:str,request:Request,db=Depends(get_db),auth=Depends(require_permission(permission))):
        value=await body(request,auth);return enqueue(db,auth,get_validator(db,validator_id),action,value)
    return endpoint

for path, action, permission in [('provision','provision','provision'),('repair','provision','provision'),
    ('reenroll','reenroll','provision'),('re-enroll','reenroll','provision'),('upgrade','upgrade','upgrade'),
    ('test','test','test'),('self-test','self-test','self_test'),('rotate','rotate','rotate_certificate'),
    ('rotate-certificate','rotate','rotate_certificate')]:
    router.add_api_route('/{validator_id}/'+path,action_route(action,'validator.'+permission),methods=['POST'])

@router.post('/{validator_id}/cancel')
async def cancel(validator_id:str,request:Request,db=Depends(get_db),auth=Depends(require_permission('validator.provision'))):
    await body(request,auth);v=get_validator(db,validator_id)
    a=db.scalar(select(ValidatorProvisioningAttempt).where(ValidatorProvisioningAttempt.validator_id==v.id,
        ValidatorProvisioningAttempt.status.in_(ACTIVE)))
    if not a: raise HTTPException(409,'No active operation')
    a.cancel_requested=True;record_audit(db,auth,'validator.cancel_requested','managed_validator',v.id,attempt_id=a.id)
    db.commit();return {'status':'CANCEL_REQUESTED'}

@router.post('/{validator_id}/remove')
async def remove(validator_id:str,request:Request,db=Depends(get_db),auth=Depends(require_permission('validator.remove'))):
    value=await body(request,auth);v=get_validator(db,validator_id);ensure_idle(db,v)
    if value.get('confirm') is not True: raise HTTPException(422,'Explicit removal confirmation required')
    v.status='REMOVED';v.enabled=False;v.configuration={};v.certificate={**v.certificate,'status':'revoked','revoked_at':now().isoformat()}
    record_audit(db,auth,'validator.removed','managed_validator',v.id,remote_software='retained',fingerprint=v.certificate.get('fingerprint'))
    db.commit();return {'status':'REMOVED'}

class OperationCancelled(Exception): pass

def stage(attempt_id,name,detail=None):
    with SessionLocal() as db:
        a=db.get(ValidatorProvisioningAttempt,attempt_id)
        if not a or a.status!='RUNNING' or a.cancel_requested: raise OperationCancelled()
        a.stage=name;a.lease_until=now()+timedelta(minutes=40)
        a.stages=[*a.stages,{'name':name,'status':'RUNNING','started_at':now().isoformat(),'detail':detail}]
        db.commit()

def complete_stage(attempt_id,detail=None):
    with SessionLocal() as db:
        a=db.get(ValidatorProvisioningAttempt,attempt_id)
        entries=list(a.stages); entries[-1]={**entries[-1],'status':'COMPLETE','completed_at':now().isoformat(),'detail':detail}
        a.stages=entries;db.commit()

def step(attempt_id,name,operation):
    stage(attempt_id,name); result=operation();complete_stage(attempt_id);return result

def check_health(config):
    result=validator_client.health(config)
    if not result.get('ready') or result.get('validator_id')!=config['expected_validator_id'] or 'cats.validation/v2' not in result.get('protocol_versions',[]):
        raise ValueError('Validator health, identity or protocol is incompatible')
    if not all(result.get('capabilities',{}).get(k) for k in ('docker','kind','helm','kubectl')):
        raise ValueError('Validator runtime capabilities are unavailable')
    return result

def startup_health(config):
    deadline=time.monotonic()+30
    while True:
        try:return check_health(config)
        except Exception:
            if time.monotonic()>=deadline:raise
            time.sleep(1)

def self_test(attempt_id,config):
    submitted=step(attempt_id,'SELF_TEST_START',lambda:validator_client.self_test(config))
    job=submitted['id'];deadline=time.monotonic()+int(os.getenv('CATS_VALIDATOR_SELF_TEST_TIMEOUT','1200'))
    stage(attempt_id,'KIND_HELM_SELF_TEST')
    cancellation_sent=False
    while time.monotonic()<deadline:
        with SessionLocal() as db:
            if db.get(ValidatorProvisioningAttempt,attempt_id).cancel_requested:
                # Continue polling to obtain real cleanup evidence before cancelling HQ.
                cancelled=True
            else: cancelled=False
        if cancelled and not cancellation_sent:
            validator_client.self_test_cancel(config,job)
            cancellation_sent=True
        state=validator_client.self_test_result(config,job)
        if state.get('status') not in {'QUEUED','RUNNING'}:
            result=state.get('result',{})
            if cancelled and result.get('cleanup_status')=='COMPLETE':
                complete_stage(attempt_id,{'validation_id':job,'cleanup_status':'COMPLETE','cancelled':True})
                raise OperationCancelled()
            if state.get('status')!='PASSED' or result.get('status')!='VERIFIED' or result.get('cleanup_status')!='COMPLETE':
                raise ValueError('Self-test did not verify the runtime and cleanup')
            complete_stage(attempt_id,{'validation_id':job,'cleanup_status':'COMPLETE'})
            if cancelled: raise OperationCancelled()
            return {'id':job,'status':'VERIFIED','cleanup_status':'COMPLETE','completed_at':now().isoformat()}
        time.sleep(2)
    raise TimeoutError('Self-test timed out; cleanup is not verified')

def run_attempt(attempt_id):
    ssh=None; temporary={};success=False; cancelled=False
    try:
        with SessionLocal() as db:
            changed=db.execute(update(ValidatorProvisioningAttempt).where(ValidatorProvisioningAttempt.id==attempt_id,
                ValidatorProvisioningAttempt.status=='QUEUED').values(status='RUNNING',started_at=now(),lease_until=now()+timedelta(minutes=40))).rowcount
            db.commit()
            if not changed:return
            a=db.get(ValidatorProvisioningAttempt,attempt_id);v=db.get(ManagedValidator,a.validator_id)
            action=a.action;validator_id=v.id;config=dict(v.configuration);host_target=target(v);pin=a.host_fingerprint
            temporary=json.loads(decrypt_secret(a.encrypted_credentials)) if a.encrypted_credentials else {}
        if action in BOOTSTRAP:
            ssh=SSHBootstrap(host_target,temporary,pin)
            step(attempt_id,'SSH_HOST_KEY_AUTHENTICATION',ssh.__enter__)
            preflight=step(attempt_id,'HOST_PREFLIGHT',ssh.preflight)
            if preflight['status'] not in {'supported','supported_with_warnings'}:
                raise ValueError('Host is incompatible with the authorized payload')
            with SessionLocal() as db:
                authorized_digest=db.get(ValidatorProvisioningAttempt,attempt_id).payload_digest
            root,manifest,digest=step(attempt_id,'PAYLOAD_VALIDATION',lambda:authorized_payload(preflight['facts'],authorized_digest))
            with SessionLocal() as db:
                a=db.get(ValidatorProvisioningAttempt,attempt_id)
                if digest!=a.payload_digest:raise ValueError('Payload changed after authorization')
                record_audit(db,None,'validator.release_provenance_verified','managed_validator',validator_id,
                             attempt_id=a.id,payload_digest=digest,
                             release_provenance=manifest.get('release_provenance',{}))
                db.commit()
            with SessionLocal() as db:
                approved=db.get(ManagedValidator,validator_id).preflight.get('warnings',[])
                if set(preflight.get('warnings',[]))-set(approved):
                    raise ValueError('New preflight warnings require another connection test and acknowledgment')
            step(attempt_id,'PAYLOAD_TRANSFER',lambda:ssh.transfer_payload(root,manifest))
            install_config={'api_port':host_target['api_port'],'validator_id':validator_id,'host':host_target['host'],
                            'node_image':manifest['node_image_reference']}
            step(attempt_id,'RUNTIME_ACCOUNT_SERVICE_INSTALLATION',lambda:ssh.install(install_config))
            csr=step(attempt_id,'VALIDATOR_IDENTITY_GENERATION',lambda:ssh.generate_csr(validator_id,host_target['host']))
        elif action=='rotate':
            step(attempt_id,'MTLS_IDENTITY_CHECK',lambda:check_health(config))
            response=step(attempt_id,'VALIDATOR_IDENTITY_GENERATION',lambda:validator_client.certificate_csr(config))
            if response.get('validator_id')!=validator_id:raise ValueError('CSR identity mismatch')
            csr=response['csr']
        if action in BOOTSTRAP or action=='rotate':
            stage(attempt_id,'CSR_ENROLLMENT')
            with SessionLocal() as db:
                domain=trust_domain(db);db.commit()
                a=db.get(ValidatorProvisioningAttempt,attempt_id);v=db.get(ManagedValidator,validator_id)
                cert,metadata=sign_csr(domain,v,csr,authorized_attempt=a)
                new_config=operational_configuration(domain,v,metadata)
                ca=domain.certificate
                fingerprint=x509.load_pem_x509_certificate(domain.client_certificate.encode()).fingerprint(hashes.SHA256()).hex()
            complete_stage(attempt_id)
            if ssh:
                step(attempt_id,'CERTIFICATE_INSTALLATION',lambda:ssh.install_certificates(cert,ca,fingerprint,install_config))
                step(attempt_id,'SERVICE_STARTUP',ssh.start_service)
            else:
                step(attempt_id,'CERTIFICATE_INSTALLATION',lambda:validator_client.install_certificate(config,cert,ca))
            config=new_config
            # Persist the new identity before verification, so failures remain repairable.
            with SessionLocal() as db:
                v=db.get(ManagedValidator,validator_id)
                history=list(v.certificate.get('history',[]))
                if v.certificate.get('fingerprint'):history.append({k:v.certificate.get(k) for k in ('fingerprint','serial','expires_at')})
                v.configuration=config;v.certificate={**metadata,'history':history[-20:]};db.commit()
        health=step(attempt_id,'MTLS_API_HEALTH',lambda:startup_health(config) if action in BOOTSTRAP else check_health(config))
        test_result=self_test(attempt_id,config) if action!='test' else None
        if ssh:step(attempt_id,'BOOTSTRAP_WORKSPACE_CLEANUP',ssh.cleanup)
        stage(attempt_id,'BOOTSTRAP_SECRET_RETIREMENT')
        temporary.clear()
        if ssh:ssh.__exit__(None,None,None);ssh=None
        with SessionLocal() as db:
            a=db.get(ValidatorProvisioningAttempt,attempt_id);a.encrypted_credentials=None;db.commit()
        complete_stage(attempt_id)
        with SessionLocal() as db:
            a=db.get(ValidatorProvisioningAttempt,attempt_id)
            if a.cancel_requested:raise OperationCancelled()
            v=db.get(ManagedValidator,validator_id);v.health=health;v.last_seen=now()
            if test_result:v.last_self_test=test_result
            if test_result or v.last_self_test.get('status')=='VERIFIED':v.status='READY'
            a.status='SUCCEEDED';a.stage=v.status;a.completed_at=now()
            record_audit(db,None,'validator.operation_succeeded','managed_validator',v.id,attempt_id=a.id,operation=action)
            db.commit();success=True
    except Exception as exc:
        cancelled=isinstance(exc,OperationCancelled)
        with SessionLocal() as db:
            a=db.get(ValidatorProvisioningAttempt,attempt_id)
            if a:
                a.status='CANCELLED' if cancelled else 'FAILED';a.completed_at=now()
                # No raw SSH errors, host output, credentials or key material in diagnostics.
                a.failure=('Cancelled; inspect remote cleanup before retrying.' if cancelled else
                    f'{a.stage} failed ({type(exc).__name__}). Check the host and retained stage history, then retry with fresh credentials.')
                if a.stages:a.stages=[*a.stages[:-1],{**a.stages[-1],'status':a.status,'completed_at':now().isoformat()}]
                v=db.get(ManagedValidator,a.validator_id);v.status='DEGRADED' if v.configuration else 'FAILED'
                if a.action!='test':
                    v.last_self_test={'status':'FAILED','cleanup_status':'UNVERIFIED','attempt_id':a.id}
                a.encrypted_credentials=None
                record_audit(db,None,'validator.operation_failed','managed_validator',v.id,attempt_id=a.id,stage=a.stage,status=a.status)
                db.commit()
    finally:
        temporary.clear()
        if ssh:
            cleanup_status='COMPLETE'
            try:ssh.cleanup()
            except Exception:cleanup_status='FAILED'
            finally:ssh.__exit__(None,None,None)
            with SessionLocal() as db:
                a=db.get(ValidatorProvisioningAttempt,attempt_id)
                if a:
                    a.stages=[*a.stages,{'name':'FAILURE_WORKSPACE_CLEANUP','status':cleanup_status,'completed_at':now().isoformat()}]
                    record_audit(db,None,'validator.cleanup','managed_validator',a.validator_id,
                                 attempt_id=a.id,status=cleanup_status)
                    db.commit()
        with SessionLocal() as db:
            a=db.get(ValidatorProvisioningAttempt,attempt_id)
            if a and a.encrypted_credentials:a.encrypted_credentials=None;db.commit()

def select_configuration(db,manual,validation_type=None):
    """Only recently checked, independently self-tested managed identities schedule work."""
    candidates=db.scalars(select(ManagedValidator).where(ManagedValidator.enabled.is_(True),ManagedValidator.status=='READY')
        .order_by(ManagedValidator.last_seen.desc())).all()
    for v in candidates:
        cert=v.certificate
        try:valid_until=datetime.fromisoformat(cert['expires_at'])
        except (KeyError,ValueError,TypeError):continue
        if cert.get('status')!='active' or valid_until<=now()+timedelta(minutes=5):continue
        if not v.last_seen or aware(v.last_seen)<now()-timedelta(seconds=120):continue
        if not v.health.get('ready') or v.last_self_test.get('status')!='VERIFIED':continue
        if validation_type and validation_type not in v.health.get('validation_types',[]):continue
        if isinstance(v.health.get('active_jobs'),int) and isinstance(v.health.get('max_jobs'),int):
            if v.health['active_jobs']>=v.health['max_jobs']:continue
        return dict(v.configuration)
    # Explicit manual configuration remains an independent supported enrollment path.
    return manual

def maintenance():
    """Reclaim expired workers and refresh mTLS health; never recover SSH secrets."""
    validator_payload_builds.recover_expired(session_factory=SessionLocal)
    with SessionLocal() as db:
        stale=db.scalars(select(ValidatorProvisioningAttempt).where(or_(
            and_(ValidatorProvisioningAttempt.status=='RUNNING',ValidatorProvisioningAttempt.lease_until<now()),
            and_(ValidatorProvisioningAttempt.status=='QUEUED',ValidatorProvisioningAttempt.created_at<now()-timedelta(minutes=10))))).all()
        for a in stale:
            a.status='FAILED';a.failure='Worker lease expired. Remote cleanup is unverified; retry with fresh credentials.'
            a.encrypted_credentials=None;a.completed_at=now()
            v=db.get(ManagedValidator,a.validator_id);v.status='DEGRADED' if v.configuration else 'FAILED'
            if a.action!='test':v.last_self_test={'status':'FAILED','cleanup_status':'UNVERIFIED','attempt_id':a.id}
            record_audit(db,None,'validator.worker_interrupted','managed_validator',v.id,attempt_id=a.id)
        queued=list(db.scalars(select(ValidatorProvisioningAttempt.id).where(ValidatorProvisioningAttempt.status=='QUEUED')))
        validators=[(v.id,dict(v.configuration)) for v in db.scalars(select(ManagedValidator).where(
            ManagedValidator.enabled.is_(True),ManagedValidator.status.in_(['READY','DEGRADED'])))]
        db.commit()
    for job in queued:WORKERS.submit(run_attempt,job)
    for validator_id,config in validators:
        if not config:continue
        try:result=check_health(config)
        except Exception:result={'ready':False,'reason':'mTLS health check failed','checked_at':now().isoformat()}
        with SessionLocal() as db:
            v=db.get(ManagedValidator,validator_id)
            if v.status not in {'READY','DEGRADED'} or v.configuration!=config:continue
            v.health=result
            if result.get('ready'):
                v.last_seen=now()
                if v.last_self_test.get('status')=='VERIFIED' and v.certificate.get('status')=='active':v.status='READY'
            else:v.status='DEGRADED'
            db.commit()
