import os, json, hashlib, subprocess, sys, io, tarfile
from pathlib import Path
from urllib.parse import urljoin
import requests
from cryptography.fernet import Fernet
sys.path.insert(0,'/source/portal')
os.environ['CATS_CONFIG_ENCRYPTION_KEY']=Fernet.generate_key().decode()
from app import signing, release_signing
root=Path('/test'); os.chdir(root)
env=dict(os.environ, COSIGN_PASSWORD='temporary-test-password')
if not (root/'key.key').exists(): subprocess.run(['cosign','generate-key-pair','--output-key-prefix','/test/key'],env=env,check=True,capture_output=True)
saved=signing.store_keys((root/'key.key').read_bytes(),(root/'key.pub').read_bytes(),env['COSIGN_PASSWORD'],True)
material=signing.job_material({signing.SETTING:json.dumps(saved)},'push')
manifest=root/'release-manifest.json';manifest.write_text('{"purpose":"cats.approved-release-revision.v1","test":true}')
result=release_signing.sign_release_manifest(manifest,root/'signed',material)
assert result['status']=='signed',result
sig=root/'signed'/result['signature_file'];pub=root/'signed'/result['public_key_file']
assert release_signing.verify_release_manifest(manifest,sig,pub,saved['fingerprint'])['status']=='verified'
manifest.write_bytes(manifest.read_bytes()+b' ')
assert release_signing.verify_release_manifest(manifest,sig,pub,saved['fingerprint'])['status']=='verification_failed'
print('PASS real encrypted-key Cosign signing, pinned-key verification, tamper rejection',flush=True)
endpoint='https://registry:5000'; repo='lifecycle/image';session=requests.Session();session.trust_env=False;session.verify=str(root/'server.crt')
def blob(data,media):
 digest='sha256:'+hashlib.sha256(data).hexdigest()
 r=session.post(endpoint+'/v2/'+repo+'/blobs/uploads/',timeout=15);r.raise_for_status()
 location=urljoin(endpoint,r.headers['Location']);location+=('&' if '?' in location else '?')+'digest='+digest
 r=session.put(location,data=data,headers={'Content-Type':'application/octet-stream'},timeout=15);r.raise_for_status()
 return dict(mediaType=media,digest=digest,size=len(data))
stream=io.BytesIO()
with tarfile.open(fileobj=stream,mode='w') as archive:
 data=b'isolated lifecycle image\n';info=tarfile.TarInfo('fixture.txt');info.size=len(data);info.mode=0o644;archive.addfile(info,io.BytesIO(data))
layer_bytes=stream.getvalue()
config_bytes=json.dumps(dict(architecture='amd64',os='linux',config={},rootfs=dict(type='layers',diff_ids=['sha256:'+hashlib.sha256(layer_bytes).hexdigest()]))).encode()
config=blob(config_bytes,'application/vnd.oci.image.config.v1+json')
layer=blob(layer_bytes,'application/vnd.oci.image.layer.v1.tar')
media='application/vnd.oci.image.manifest.v1+json'; raw=json.dumps(dict(schemaVersion=2,mediaType=media,config=config,layers=[layer]),separators=(',',':')).encode()
r=session.put(endpoint+'/v2/'+repo+'/manifests/stable',data=raw,headers={'Content-Type':media},timeout=15);r.raise_for_status()
evidence=dict(endpoint=endpoint,repository=repo,tag='stable',digest='sha256:'+hashlib.sha256(raw).hexdigest(),blob=layer['digest'])
(root/'smoke-results.json').write_text(json.dumps(evidence));(root/'credentials.json').write_text('{"admin":"unused-local-registry"}')
import gateway
gateway.main(root)

import active
active.main(root,material,session,endpoint,repo,raw,config,layer)

if os.getenv('CATS_CLIENT_PROBE'):
 import clients
 clients.main(root,session,endpoint)
