"""Seed synthetic private OCI content and test the actual Harbor TLS/Bearer path."""
import argparse, hashlib, io, json, pathlib, sys, tarfile, time
from urllib.parse import urljoin
import requests
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))
from portal.app.oci_transport import RegistryClient, ContentCache, RegistryError

def main(root,port):
 root=pathlib.Path(root).resolve(); endpoint=f'https://localhost:{port}'
 cert=root/'harbor/tls/server.crt'; password=json.loads((root/'credentials.json').read_text())['admin']
 session=requests.Session(); session.verify=str(cert); session.auth=('admin',password)
 for attempt in range(60):
  try:
   response=session.get(endpoint+'/api/v2.0/health',timeout=5)
   if response.ok and response.json().get('status')=='healthy': break
  except requests.RequestException: pass
  time.sleep(2)
 else: raise RuntimeError('Harbor did not become healthy')
 session.headers['X-Harbor-CSRF-Token']=response.headers.get('X-Harbor-CSRF-Token','')
 session.cookies.clear()
 response=session.post(endpoint+'/api/v2.0/projects',json={'project_name':'cats-fixture','public':False},timeout=15)
 assert response.status_code in (201,409), response.status_code
 repo='cats-fixture/image'
 token=session.get(endpoint+'/service/token',params={'service':'harbor-registry','scope':f'repository:{repo}:pull,push'},timeout=15)
 token.raise_for_status(); session.auth=None; session.cookies.clear(); session.headers.pop('X-Harbor-CSRF-Token',None); headers={'Authorization':'Bearer '+token.json()['token']}
 def blob(payload,media):
  digest='sha256:'+hashlib.sha256(payload).hexdigest()
  session.cookies.clear()
  start=session.post(endpoint+f'/v2/{repo}/blobs/uploads/',headers=headers,auth=(),timeout=15); start.raise_for_status()
  location=urljoin(endpoint,start.headers['Location']); location+=('&' if '?' in location else '?')+'digest='+digest
  session.cookies.clear()
  put=session.put(location,data=payload,headers={**headers,'Content-Type':'application/octet-stream'},auth=(),timeout=30); put.raise_for_status()
  return {'mediaType':media,'digest':digest,'size':len(payload)}
 content=b'Harbor genuine interoperability fixture\n'*65536
 buffer=io.BytesIO()
 with tarfile.open(fileobj=buffer,mode='w') as archive:
  info=tarfile.TarInfo('fixture.txt');info.size=len(content);info.mode=0o644;archive.addfile(info,io.BytesIO(content))
 layer=buffer.getvalue()
 config_bytes=json.dumps({'architecture':'amd64','os':'linux','config':{},'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer).hexdigest()]}},separators=(',',':')).encode()
 config=blob(config_bytes,'application/vnd.oci.image.config.v1+json')
 descriptor=blob(layer,'application/vnd.oci.image.layer.v1.tar')
 media='application/vnd.oci.image.manifest.v1+json'
 raw=json.dumps({'schemaVersion':2,'mediaType':media,'config':config,'layers':[descriptor]},separators=(',',':')).encode()
 session.cookies.clear()
 put=session.put(endpoint+f'/v2/{repo}/manifests/stable',data=raw,headers={**headers,'Content-Type':media},auth=(),timeout=15);put.raise_for_status()
 client=RegistryClient({'endpoint':endpoint,'username':'admin','password':password,'ca_pem':cert.read_text()})
 actual,actual_type,digest=client.fetch_manifest(repo,'stable'); assert actual==raw
 cache=ContentCache(root/'client-cache',max_bytes=16*1024*1024)
 path=client.fetch_blob(repo,descriptor['digest'],cache);assert path.read_bytes()==layer
 actual_by_digest=client.fetch_manifest(repo,digest);assert actual_by_digest[0]==raw
 anonymous=RegistryClient({'endpoint':endpoint,'ca_pem':cert.read_text()})
 try: anonymous.fetch_manifest(repo,'stable')
 except RegistryError: pass
 else: raise AssertionError('Private repository allowed anonymous pull')
 refs=client.referrers(repo,digest)
 result={'harbor':'v2.15.4','endpoint':endpoint,'repository':repo,'tag':'stable','digest':digest,'blob':descriptor['digest'],'blob_bytes':len(layer),'checks':['real TLS custom CA','private project','Bearer pull','raw manifest identity','digest pull','streamed blob integrity','anonymous denied','referrers endpoint'],'referrers':len(refs.get('manifests',[]))}
 (root/'smoke-results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--root',default='.test-temp/harbor-local');parser.add_argument('--port',type=int,default=18443);args=parser.parse_args();main(args.root,args.port)
