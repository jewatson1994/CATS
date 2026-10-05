"""Local-only assembly of managed payloads from image-pinned release assets.

No vendor executable is run here. Runtime trust originates in a read-only
release manifest pinned during image construction, then in persisted HQ records.
External payloads retain their separate environment-pinned trust path.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .auth import require_permission, record_audit
from .database import SessionLocal, get_db
from .models import ValidatorPayloadBuild, PortalSetting
from .validator_payload import REQUIRED, validate_payload

router = APIRouter(prefix='/api/admin/validators', tags=['managed validators'])
WORKERS = ThreadPoolExecutor(max_workers=1, thread_name_prefix='validator-payload')
RELEASE_ASSETS = REQUIRED - {'validator'}
QUALIFICATIONS = ('runtime_packages', 'python_wheels', 'image_digests', 'self_test')


class AssetError(ValueError):
    """An actionable, credential-free release or artifact failure."""


def now():
    return datetime.now(timezone.utc)


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def safe_path(root, name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
        raise AssetError('Unsafe declared release asset path')
    relative = PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name or name == '.':
        raise AssetError('Unsafe declared release asset path')
    root = Path(root)
    path = root / name
    if root.is_symlink() or any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts)+1)):
        raise AssetError('Release asset symlinks are forbidden')
    if not path.resolve().is_relative_to(root.resolve()):
        raise AssetError('Release asset escapes its directory')
    return path


def pinned_json(path, expected):
    if not re.fullmatch(r'[a-f0-9]{64}', str(expected)):
        raise AssetError('CATS release is missing its trusted managed-validator asset manifest SHA256')
    if path.is_symlink() or not path.is_file():
        raise AssetError(f'Missing packaged release asset: {path}. Rebuild CATS with the complete validator asset set. CATS will not download missing assets at runtime.')
    if path.stat().st_size > 1024 * 1024:
        raise AssetError('Release asset manifest exceeds size limit')
    actual = digest_file(path)
    if actual != expected:
        raise AssetError(f'Asset integrity failure: {path.name}. Expected SHA256: {expected}. Actual SHA256: {actual}.')
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise AssetError('Invalid release asset manifest JSON') from None
    if not isinstance(value, dict):
        raise AssetError('Invalid release asset manifest')
    return value


def validate_release(root, expected_sha256):
    root = Path(root)
    value = pinned_json(root / 'release.json', expected_sha256)
    if root.is_symlink() or value.get('format') != 1 or not isinstance(value.get('cats_version'), str) or not value['cats_version'].strip():
        raise AssetError('CATS release asset format/build identity is missing')
    entries = value.get('platforms')
    if not isinstance(entries, list) or not entries:
        raise AssetError('CATS release has no packaged validator platforms')
    platforms = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise AssetError('Invalid packaged validator platform')
        platform = tuple(entry.get(k) for k in ('os','os_version','architecture'))
        if platform[0] != 'ubuntu' or platform[1] not in ('22.04','24.04') or platform[2] not in ('amd64','arm64') or platform in platforms:
            raise AssetError('Unsupported or duplicate packaged validator platform')
        platforms.add(platform)
        safe_path(root, entry.get('path'))
        if not re.fullmatch(r'[a-f0-9]{64}', str(entry.get('sha256'))):
            raise AssetError('Platform asset manifest is missing a trusted SHA256')
    return value


def load_release_platform(root, expected_sha256, facts):
    catalog = validate_release(root, expected_sha256)
    entries = [e for e in catalog['platforms'] if all(e[k] == facts.get(k) for k in ('os','os_version','architecture'))]
    if len(entries) != 1:
        raise AssetError('CATS release is missing required managed-validator platform: '+platform_key(facts))
    entry = entries[0]
    base = safe_path(root, entry['path'])
    m = pinned_json(base / 'validator-assets.json', entry['sha256'])
    if m.get('format') != 1 or any(m.get(k) != entry[k] for k in ('os','os_version','architecture')):
        raise AssetError('Packaged assets do not match the requested platform')
    if not isinstance(m.get('payload_version'), str) or not m['payload_version'].strip():
        raise AssetError('Release payload version is missing')
    versions = m.get('versions', {})
    if not isinstance(versions, dict) or any(not isinstance(versions.get(k), str) or not versions[k].strip() for k in RELEASE_ASSETS | {'runtime'}):
        raise AssetError('Release assets must record every component version')
    for key in ('node_image_reference', 'self_test_image_reference'):
        if not re.fullmatch(r'[A-Za-z0-9_./:-]+@sha256:[a-f0-9]{64}', str(m.get(key,''))):
            raise AssetError('Release images require qualified digest-pinned references')
    qualifications = m.get('qualification', {})
    if not isinstance(qualifications, dict) or any(qualifications.get(k) is not True for k in QUALIFICATIONS):
        raise AssetError('Release lacks complete offline runtime, wheel, image identity or self-test qualification')
    runtime = m.get('runtime', {})
    if not isinstance(runtime, dict) or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', str(runtime.get('engine_version',''))) or int(runtime['engine_version'].split('.')[0]) < 28:
        raise AssetError('Packaged runtime must be a qualified Docker Engine 28+ release')
    if m.get('python_version') != ('3.10' if facts['os_version']=='22.04' else '3.12'):
        raise AssetError('Packaged Python wheel closure does not match the native Ubuntu Python runtime')
    assets = m.get('assets', {})
    if not isinstance(assets, dict) or set(assets) != RELEASE_ASSETS:
        missing = sorted(RELEASE_ASSETS-set(assets)) if isinstance(assets, dict) else sorted(RELEASE_ASSETS)
        raise AssetError('Missing packaged release asset declaration: '+', '.join(missing or ['unexpected component']))
    packages, wheels = m.get('packages'), m.get('wheels')
    if not isinstance(packages, list) or not packages or runtime.get('packages') != packages or len(packages) != len(set(packages)):
        raise AssetError('Missing or incomplete qualified offline runtime package set')
    if not isinstance(wheels, list) or not wheels or len(wheels) != len(set(wheels)):
        raise AssetError('Missing complete native Python wheel closure')
    if not all(isinstance(p,str) and p.endswith('.deb') for p in packages) or not all(isinstance(w,str) and w.startswith('wheels/') and w.endswith('.whl') for w in wheels):
        raise AssetError('Invalid offline packages or Python wheels')
    files = m.get('files', {})
    required = set(assets.values()) | set(packages) | set(wheels)
    if not isinstance(files, dict) or set(files) != required:
        raise AssetError('Release asset manifest must cover the exact component, package and wheel closure')
    names = {path:key for key,path in assets.items()}
    for name, record in files.items():
        path = safe_path(base, name)
        component = names.get(name, name)
        if not path.is_file():
            raise AssetError(f'Missing packaged release asset: {component}; {platform_key(facts)}. Expected: {path}. CATS will not download missing assets at runtime. Rebuild CATS with the complete validator asset set.')
        if not isinstance(record, dict) or not isinstance(record.get('source'), str) or not record['source'].strip() or not isinstance(record.get('size'), int) or record['size'] <= 0 or not re.fullmatch(r'[a-f0-9]{64}', str(record.get('sha256',''))):
            raise AssetError(f'Missing release provenance, size or SHA256 for {component}')
        actual = digest_file(path)
        if path.stat().st_size != record['size'] or actual != record['sha256']:
            raise AssetError(f'Asset integrity failure: {component}. Expected SHA256: {record["sha256"]}. Actual SHA256: {actual}.')
    return base, {**m, 'cats_version':catalog['cats_version']}


def release_location():
    root = Path(os.getenv('CATS_VALIDATOR_ASSETS_DIR','/opt/cats/validator-assets'))
    pin = Path(os.getenv('CATS_VALIDATOR_ASSETS_PIN','/opt/cats/validator-assets.sha256'))
    if pin.is_symlink() or not pin.is_file():
        raise AssetError(f'CATS release is missing required managed-validator asset: {pin}. Rebuild CATS with the complete validator asset set. CATS will not download missing assets at runtime.')
    if pin.stat().st_size > 128:
        raise AssetError('Invalid image-pinned release asset digest')
    return root, pin.read_text().strip()


def storage_root():
    return Path(os.getenv('CATS_VALIDATOR_PAYLOAD_STORAGE','/app/data/validator-payloads'))


def application_root():
    return Path(__file__).resolve().parents[1]


def platform_key(facts):
    return '-'.join(str(facts.get(k,'')) for k in ('os','os_version','architecture'))


def public_build(job):
    return {**job.artifact, 'id':job.id, 'status':job.status, 'stage':job.stage,
            'stages':job.stages, 'failure':job.failure, 'manifest_sha256':job.manifest_sha256,
            'active':job.active, 'created_at':job.created_at, 'completed_at':job.completed_at}


def artifact_path(job):
    root = storage_root()
    if not re.fullmatch(r'[a-f0-9]{32}', job.id):
        raise AssetError('Invalid local payload artifact identifier')
    return safe_path(root, job.id)


def verified_material(job, facts=None):
    if job.status != 'VERIFIED' or not job.manifest_sha256:
        raise AssetError('Local payload has not passed verification')
    path = artifact_path(job)
    manifest = validate_payload(path, job.manifest_sha256)
    if facts and any(manifest[k] != facts.get(k) for k in ('os','os_version','architecture')):
        raise AssetError('No compatible verified local payload is active')
    return path, manifest, job.manifest_sha256


def local_material(facts=None, digest=None, session_factory=None):
    with (session_factory or SessionLocal)() as db:
        query = select(ValidatorPayloadBuild).where(ValidatorPayloadBuild.status=='VERIFIED')
        query = query.where(ValidatorPayloadBuild.manifest_sha256==digest) if digest else query.where(ValidatorPayloadBuild.active.is_(True))
        if facts:
            query = query.where(ValidatorPayloadBuild.platform==platform_key(facts))
        jobs = db.scalars(query).all()
        if not jobs:
            return None
        if len(jobs) != 1:
            raise AssetError('Exactly one compatible active local payload is required')
        return verified_material(jobs[0], facts)


def metadata_inventory(session_factory=None):
    """Render durable build verification records without touching payload files.

    Readiness is advisory: activation and provisioning still revalidate bytes.
    The supported build targets are declared by the builder API, not discovered
    by inspecting image archives during a list request.
    """
    with (session_factory or SessionLocal)() as db:
        jobs = db.scalars(select(ValidatorPayloadBuild)
            .order_by(ValidatorPayloadBuild.created_at.desc(), ValidatorPayloadBuild.id.desc()).limit(20)).all()
        active = db.scalars(select(ValidatorPayloadBuild).where(
            ValidatorPayloadBuild.active.is_(True), ValidatorPayloadBuild.status == 'VERIFIED')).all()
        stored = db.scalar(select(PortalSetting.value).where(PortalSetting.key == 'validator.release_metadata'))
        release = json.loads(stored) if stored else {}
        platforms = [{k: job.artifact.get(k) for k in
                      ('os', 'os_version', 'architecture', 'payload_version')} for job in active]
        return {'builds': [public_build(job) for job in jobs],
                'release_platforms': release.get('release_platforms', [
                    {'os': 'ubuntu', 'os_version': version, 'architecture': arch}
                    for version in ('22.04', '24.04') for arch in ('amd64', 'arm64')]),
                'managed_validator_capable': release.get('managed_validator_capable', bool(active)),
                'managed_validator_assets_omitted': release.get('managed_validator_assets_omitted', False),
                'release_failure': release.get('release_failure'),
                'available': bool(active), 'platforms': platforms, 'source': 'local',
                'digest': active[0].manifest_sha256 if active else None,
                'verification_source': 'persisted',
                'reason': None if active else 'Build or explicitly verify a payload before provisioning.'}


def inventory(session_factory=None):
    with (session_factory or SessionLocal)() as db:
        jobs = db.scalars(select(ValidatorPayloadBuild).order_by(ValidatorPayloadBuild.created_at.desc()).limit(20)).all()
        result = {'builds':[public_build(j) for j in jobs], 'release_platforms':[],
                  'managed_validator_capable':False, 'managed_validator_assets_omitted':False}
        try:
            asset_root = Path(os.getenv('CATS_VALIDATOR_ASSETS_DIR','/opt/cats/validator-assets'))
            marker = asset_root / 'omitted.json'
            if marker.is_file() and not marker.is_symlink() and marker.stat().st_size <= 1024:
                omitted = json.loads(marker.read_bytes())
                if isinstance(omitted, dict) and omitted.get('format') == 1 and omitted.get('managed_validator_assets') == 'omitted':
                    result['managed_validator_assets_omitted'] = True
                    raise AssetError('Managed Validator Assets Not Included. Rebuild the CATS release image with managed validator assets to enable Build Payload.')
            root,pin = release_location()
            release = validate_release(root,pin)
            for entry in release['platforms']:
                load_release_platform(root,pin,entry)
            result['release_platforms']=[{k:e[k] for k in ('os','os_version','architecture')} for e in release['platforms']]
            result['managed_validator_capable']=True
        except (ValueError,OSError) as exc:
            result['release_failure']=str(exc)
        record = db.scalar(select(PortalSetting).where(PortalSetting.key == 'validator.release_metadata'))
        if record is None:
            record = PortalSetting(key='validator.release_metadata', value='{}')
            db.add(record)
        record.value = json.dumps({key: result.get(key) for key in (
            'release_platforms', 'managed_validator_capable', 'managed_validator_assets_omitted', 'release_failure')})
        db.commit()
        active = db.scalars(select(ValidatorPayloadBuild).where(ValidatorPayloadBuild.active.is_(True))).all()
        if active:
            try:
                platforms=[]
                for job in active:
                    _,m,_=verified_material(job)
                    platforms.append({k:m[k] for k in ('os','os_version','architecture','payload_version')})
                result.update(available=True,platforms=platforms,source='local',digest=active[0].manifest_sha256)
            except (ValueError,OSError) as exc:
                result.update(available=False,reason=str(exc))
        return result


def builder():
    path = Path('/opt/cats/scripts/build-managed-validator-payload.py')
    if not path.exists():
        path = application_root().parent / 'scripts/build-managed-validator-payload.py'
    if not path.is_file() or path.is_symlink():
        raise AssetError('CATS release is missing its existing managed-validator payload builder')
    spec = importlib.util.spec_from_file_location('cats_payload_assembler',path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.assemble


def package_application(destination, base, manifest):
    source = application_root()
    paths = [source/'validator_server.py',source/'requirements.txt']
    # Ship source modules, never mutable HQ data, templates, env files or keys.
    paths += sorted(p for p in (source/'app').rglob('*.py') if '__pycache__' not in p.parts and not any(part.startswith('.') for part in p.relative_to(source).parts))
    if not all(p.is_file() and not p.is_symlink() for p in paths) or not any(p.parent.name=='app' for p in paths):
        raise AssetError('CATS release is missing its current validator application source or launcher')
    content = hashlib.sha256()
    with tarfile.open(destination,'w:gz') as archive:
        for path in paths:
            if any(parent.is_symlink() for parent in path.parents if parent!=source.parent):
                raise AssetError('Validator application source contains an unsafe symlink')
            name=path.relative_to(source).as_posix()
            content.update(name.encode()+b'\0'+bytes.fromhex(digest_file(path)))
            archive.add(path,arcname=name,recursive=False)
        for name in manifest['wheels']:
            archive.add(safe_path(base,name),arcname=name,recursive=False)
    return manifest['cats_version']+'-source-'+content.hexdigest()


def progress(job_id, name):
    with SessionLocal() as db:
        job=db.get(ValidatorPayloadBuild,job_id)
        if not job or job.status!='RUNNING':
            raise AssetError('Payload build lease was lost')
        job.stage=name; job.lease_until=now()+timedelta(hours=2)
        completed=[{**stage,'status':'COMPLETE'} for stage in job.stages]
        job.stages=[*completed,{'name':name,'status':'RUNNING','at':now().isoformat()}]
        db.commit()


def activate_in_db(db, job):
    verified_material(job)
    db.execute(update(ValidatorPayloadBuild).where(ValidatorPayloadBuild.platform==job.platform).values(active=False))
    db.flush()
    job.active=True


def run_build(job_id):
    stage=None
    try:
        with SessionLocal() as db:
            claimed=db.execute(update(ValidatorPayloadBuild).where(ValidatorPayloadBuild.id==job_id,ValidatorPayloadBuild.status=='QUEUED').values(status='RUNNING',lease_until=now()+timedelta(hours=2))).rowcount
            db.commit()
            if not claimed:return
            job=db.get(ValidatorPayloadBuild,job_id); facts={k:job.artifact[k] for k in ('os','os_version','architecture')}
        progress(job_id,'Verifying packaged assets')
        release,pin=release_location();base,m=load_release_platform(release,pin,facts)
        root=storage_root()
        if root.is_symlink():raise AssetError('Payload storage must not be a symlink')
        root.mkdir(parents=True,exist_ok=True)
        stage=root/('.stage-'+job_id);stage.mkdir(mode=0o700)
        progress(job_id,'Packaging validator application')
        validator_version=package_application(stage/'validator.tar.gz',base,m)
        progress(job_id,'Preparing offline Python dependencies')
        assets={**m['assets'],'validator':'validator.tar.gz'}
        groups=[('Preparing runtime packages',m['packages']),('Adding Kind',[assets['kind']]),
                ('Adding kubectl',[assets['kubectl']]),('Adding Helm',[assets['helm']]),
                ('Adding Kind node image',[assets['node_image']]),('Adding self-test image',[assets['self_test_image']]),
                ('Adding self-test chart',[assets['self_test_chart']])]
        for label,names in groups:
            progress(job_id,label)
            for name in names:
                target=safe_path(stage,name);target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(safe_path(base,name),target)
        specification={k:m[k] for k in ('os','os_version','architecture','node_image_reference','self_test_image_reference','packages')}
        specification.update(format=1,payload_version=m['payload_version']+'-'+job_id,
            assets=assets,versions={**m['versions'],'validator':validator_version},cats_version=m['cats_version'])
        specification['release_provenance'] = {
            'release_manifest_sha256':pin, 'cats_version':m['cats_version'],
            'files':m['files'], 'qualification':m['qualification'],
            'python_version':m['python_version'], 'runtime':m['runtime'],
        }
        if isinstance(m.get('provenance'),dict):
            specification['release_provenance']['build']=m['provenance']
        if isinstance(m.get('qualification_evidence'),dict):
            specification['release_provenance']['qualification_evidence']=m['qualification_evidence']
        (stage/'specification.json').write_text(json.dumps(specification,sort_keys=True)+'\n')
        progress(job_id,'Generating manifest')
        output=root/job_id
        digest=builder()(stage,output)
        progress(job_id,'Verifying payload')
        manifest=validate_payload(output,digest)
        # Recheck the pinned asset closure to detect changes while assembly ran.
        load_release_platform(release,pin,facts)
        for path in output.rglob('*'):
            path.chmod(0o555 if path.is_dir() else 0o444)
        output.chmod(0o555)
        with SessionLocal() as db:
            job=db.get(ValidatorPayloadBuild,job_id)
            if job.status!='RUNNING':raise AssetError('Payload build lease was lost')
            job.manifest_sha256=digest
            job.artifact={**facts,'path':str(output),'payload_version':manifest['payload_version'],
                'validator_version':validator_version,'cats_version':m['cats_version'],
                'versions':manifest['versions'],'components':{'verified':9,'total':9},'trust_source':'image-pinned-release-assets',
                'release_provenance':manifest['release_provenance']}
            job.status='VERIFIED';job.stage='Complete';job.completed_at=now()
            job.stages=[{**stage,'status':'COMPLETE'} for stage in job.stages]
            activate_in_db(db,job)
            record_audit(db,None,'validator.payload_verified','validator_payload',job.id,manifest_sha256=digest,platform=job.platform,operator_id=job.operator_id,release_provenance=manifest['release_provenance'])
            db.commit()
    except Exception as exc:
        with SessionLocal() as db:
            job=db.get(ValidatorPayloadBuild,job_id)
            if job and job.status in ('QUEUED','RUNNING'):
                job.status='FAILED';job.stage='Payload build failed';job.completed_at=now()
                job.stages=[{**stage,'status':'FAILED' if stage.get('status')=='RUNNING' else stage.get('status')} for stage in job.stages]
                # Never expose arbitrary exception text from libraries or source files.
                job.failure=str(exc) if isinstance(exc,AssetError) else f'Payload assembly or verification failed ({type(exc).__name__}); no payload was activated.'
                record_audit(db,None,'validator.payload_build_failed','validator_payload',job.id,stage=job.stage,operator_id=job.operator_id)
                db.commit()
    finally:
        if stage and stage.is_dir():shutil.rmtree(stage)


def recover_expired(session_factory=None):
    with (session_factory or SessionLocal)() as db:
        jobs=db.scalars(select(ValidatorPayloadBuild).where(ValidatorPayloadBuild.status.in_(('QUEUED','RUNNING')),ValidatorPayloadBuild.lease_until<now())).all()
        for job in jobs:
            job.status='FAILED';job.failure='Payload build was interrupted. Rebuild Payload to retry; the prior verified payload remains available.'
            job.stage='Payload build interrupted';job.completed_at=now()
        db.commit()


def get_build(db, job_id):
    job=db.get(ValidatorPayloadBuild,job_id)
    if not job:raise HTTPException(404,'Payload build not found')
    return job


@router.post('/payload-builds')
async def enqueue(request:Request,db=Depends(get_db),auth=Depends(require_permission('validator.provision'))):
    from .validator_management import body
    value=await body(request,auth)
    facts={k:value.get(k,default) for k,default in [('os','ubuntu'),('os_version','22.04'),('architecture','amd64')]}
    if facts['os']!='ubuntu' or facts['os_version'] not in ('22.04','24.04') or facts['architecture'] not in ('amd64','arm64'):
        raise HTTPException(422,'Unsupported validator payload platform')
    # Credentials, filesystem paths and executable commands are not build inputs.
    if set(value)-set(facts):raise HTTPException(422,'Only the target platform may be supplied')
    job=ValidatorPayloadBuild(id=uuid.uuid4().hex,platform=platform_key(facts),artifact=facts,
        operator_id=auth.user.id,lease_until=now()+timedelta(hours=2))
    db.add(job)
    try:
        db.flush();record_audit(db,auth,'validator.payload_build_requested','validator_payload',job.id,platform=job.platform)
        db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,'A payload build is already in progress') from None
    WORKERS.submit(run_build,job.id)
    return public_build(job)


@router.get('/payload-builds/{job_id}')
def detail(job_id:str,db=Depends(get_db),auth=Depends(require_permission('validator.view'))):
    return public_build(get_build(db,job_id))


@router.post('/payload-builds/{job_id}/verify')
async def verify(job_id:str,request:Request,db=Depends(get_db),auth=Depends(require_permission('validator.provision'))):
    from .validator_management import body
    await body(request,auth);job=get_build(db,job_id)
    try:verified_material(job)
    except (ValueError,OSError) as exc:raise HTTPException(409,'Payload integrity verification failed; no activation performed') from exc
    record_audit(db,auth,'validator.payload_reverified','validator_payload',job.id,manifest_sha256=job.manifest_sha256)
    db.commit();return public_build(job)


@router.post('/payload-builds/{job_id}/activate')
async def activate(job_id:str,request:Request,db=Depends(get_db),auth=Depends(require_permission('validator.provision'))):
    from .validator_management import body
    await body(request,auth);job=get_build(db,job_id)
    try:
        activate_in_db(db,job)
        record_audit(db,auth,'validator.payload_activated','validator_payload',job.id,manifest_sha256=job.manifest_sha256)
        db.commit()
    except (ValueError,OSError,IntegrityError) as exc:
        db.rollback();raise HTTPException(409,'Payload activation failed; retry after verification') from exc
    return public_build(job)
