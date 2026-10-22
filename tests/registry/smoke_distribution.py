"""Isolated real Distribution TLS/Basic interoperability; removes only its own container."""
import datetime, hashlib, io, ipaddress, json, pathlib, secrets, subprocess, sys, tarfile, time
from urllib.parse import urljoin
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from portal.app.oci_transport import RegistryClient, ContentCache, RegistryError
IMAGE='registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
HELPER='httpd@sha256:3440c39d8d6f54fa9ad2549e5a60c19ddd435faadc29c1ad28aa795f71888889'

def main():
 root=pathlib.Path('.test-temp/distribution-local').resolve();root.mkdir(parents=True,exist_ok=True)
 name='cats-distribution-fixture-'+secrets.token_hex(4); port=18543; endpoint=f'https://localhost:{port}'
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'CATS isolated registry fixture')])
 now=datetime.datetime.now(datetime.timezone.utc)
 cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
  .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=2))
  .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
  .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256()))
 (root/'server.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 (root/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 password=secrets.token_urlsafe(32)
 hashed=subprocess.run(['docker','run','--rm',HELPER,'htpasswd','-Bbn','fixture',password],check=True,capture_output=True).stdout
 (root/'htpasswd').write_bytes(hashed)
 subprocess.run(['docker','run','-d','--name',name,'-p',f'127.0.0.1:{port}:5000','--mount',f'type=bind,src={root},dst=/fixture,readonly',
  '-e','REGISTRY_HTTP_TLS_CERTIFICATE=/fixture/server.crt','-e','REGISTRY_HTTP_TLS_KEY=/fixture/server.key',
  '-e','REGISTRY_AUTH=htpasswd','-e','REGISTRY_AUTH_HTPASSWD_REALM=CATS fixture','-e','REGISTRY_AUTH_HTPASSWD_PATH=/fixture/htpasswd',IMAGE],check=True,capture_output=True)
 try:
  session=requests.Session();session.verify=str(root/'server.crt');session.auth=('fixture',password)
  for _ in range(30):
   try:
    if session.get(endpoint+'/v2/',timeout=2).status_code==200:break
   except requests.RequestException:pass
   time.sleep(1)
  else:raise RuntimeError('Registry startup timeout')
  repo='fixture/image'
  def blob(raw,media):
   digest='sha256:'+hashlib.sha256(raw).hexdigest()
   response=session.post(endpoint+f'/v2/{repo}/blobs/uploads/',timeout=10);response.raise_for_status()
   location=urljoin(endpoint,response.headers['Location']);location+=('&' if '?' in location else '?')+'digest='+digest
   response=session.put(location,data=raw,headers={'Content-Type':'application/octet-stream'},timeout=10);response.raise_for_status()
   return {'mediaType':media,'size':len(raw),'digest':digest}
  output=io.BytesIO()
  with tarfile.open(fileobj=output,mode='w') as archive:
   data=b'CATS real Distribution interoperability fixture';entry=tarfile.TarInfo('fixture.txt');entry.size=len(data);archive.addfile(entry,io.BytesIO(data))
  layer=output.getvalue(); layer_descriptor=blob(layer,'application/vnd.oci.image.layer.v1.tar')
  config=blob(json.dumps({'architecture':'amd64','os':'linux','rootfs':{'type':'layers','diff_ids':[layer_descriptor['digest']]}}).encode(),'application/vnd.oci.image.config.v1+json')
  media='application/vnd.oci.image.manifest.v1+json'
  raw=json.dumps({'schemaVersion':2,'mediaType':media,'config':config,'layers':[layer_descriptor]},separators=(',',':')).encode()
  response=session.put(endpoint+f'/v2/{repo}/manifests/stable',data=raw,headers={'Content-Type':media},timeout=10);response.raise_for_status()
  config={'endpoint':endpoint,'username':'fixture','password':password,'ca_pem':(root/'server.crt').read_text()}
  client=RegistryClient(config);actual,actual_media,digest=client.fetch_manifest(repo,'stable')
  assert actual==raw and actual_media==media
  assert client.fetch_manifest(repo,digest)[0]==raw
  cache=ContentCache(root/'cache');assert client.fetch_blob(repo,layer_descriptor['digest'],cache).read_bytes()==layer
  checks=['TLS custom CA','Basic authentication','tag and digest manifests preserve bytes','streamed blob SHA-256']
  for label,override in [('anonymous denied',{'username':'','password':''}),('wrong password denied',{'password':'wrong'}),('untrusted CA denied',{'ca_pem':''})]:
   try:RegistryClient({**config,**override}).fetch_manifest(repo,'stable')
   except RegistryError:checks.append(label)
   else:raise AssertionError(label)
  result={'registry':IMAGE,'endpoint':endpoint,'repository':repo,'manifest_digest':digest,'blob_bytes':len(layer),'checks':checks,'container_cleanup':'removed in finally'}
  (root/'smoke-results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
 finally:
  subprocess.run(['docker','rm','-f',name],check=True,capture_output=True)
if __name__=='__main__':main()
