"""Real host Docker/Helm clients coordinate through disposable marker files."""
import io,json,hashlib,tarfile,time,threading
from datetime import datetime,timedelta,timezone
from urllib.parse import urljoin
import uvicorn,requests

def main(root,session,endpoint):
 from app import oci_proxy as proxy
 from app.database import SessionLocal
 from app.models import Service,Execution
 from app.oci_models import OCIUpstream,OCIRepository,OCIPrincipal
 from app.cyber_approvals import CyberApproval,digest
 from app.execution_summaries import payload_digest
 from app.release_validity import new_validity
 evidence=json.loads((root/'smoke-results.json').read_text())
 repo='lifecycle/chart';stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w:gz') as archive:
  for name,data in {'fixture/Chart.yaml':b'apiVersion: v2\nname: fixture\nversion: 0.1.0\n', 'fixture/templates/config.yaml':b'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture\n'}.items():
   item=tarfile.TarInfo(name);item.size=len(data);archive.addfile(item,io.BytesIO(data))
 def upload(data,media):
  d='sha256:'+hashlib.sha256(data).hexdigest();r=session.post(endpoint+'/v2/'+repo+'/blobs/uploads/',timeout=15);r.raise_for_status()
  url=urljoin(endpoint,r.headers['Location']);r=session.put(url+('&' if '?' in url else '?')+'digest='+d,data=data,timeout=15);r.raise_for_status()
  return dict(mediaType=media,digest=d,size=len(data))
 chart_config=upload(b'{"name":"fixture","version":"0.1.0"}','application/vnd.cncf.helm.config.v1+json')
 chart_layer=upload(stream.getvalue(),'application/vnd.cncf.helm.chart.content.v1.tar+gzip')
 raw=json.dumps(dict(schemaVersion=2,mediaType='application/vnd.oci.image.manifest.v1+json',config=chart_config,layers=[chart_layer])).encode()
 chart_digest='sha256:'+hashlib.sha256(raw).hexdigest()
 r=session.put(endpoint+'/v2/'+repo+'/manifests/0.1.0',data=raw,headers={'Content-Type':'application/vnd.oci.image.manifest.v1+json'},timeout=15);r.raise_for_status()
 now=datetime.now(timezone.utc);approval_ids=[];mapping_ids=[]
 with SessionLocal() as db:
  upstream=OCIUpstream(name='client-registry',endpoint=endpoint,ca_pem=(root/'server.crt').read_text());db.add(upstream);db.flush()
  for name,upstream_repo,artifact_digest in [('image',evidence['repository'],evidence['digest']),('fixture',repo,chart_digest)]:
   service=Service(service_key='client-'+name,name=name);db.add(service);db.flush()
   execution=Execution(service_id=service.id,execution_key='client-'+name,scanned_at=now,complete=True,scan_scope='service',raw_payload={});db.add(execution)
   mapping=OCIRepository(service_id=service.id,public_repository='clients/'+name,upstream_id=upstream.id,upstream_repository=upstream_repo);db.add(mapping);db.flush();mapping_ids.append(mapping.id)
   snapshot=dict(service_id=service.id,source_execution_id=execution.id,source_version_id=None,source_payload_digest=payload_digest({}),approval_validity=new_validity(now),artifacts=[dict(kind='image' if name=='image' else 'chart',reference='registry:5000/'+upstream_repo+'@'+artifact_digest,digest=artifact_digest)])
   approval=CyberApproval(service_id=service.id,source_execution_id=execution.id,variant='current',status='approved',snapshot=snapshot,snapshot_digest=digest(snapshot),decided_at=now);db.add(approval);db.flush();approval_ids.append(approval.id)
  db.add(OCIPrincipal(name='client-robot',secret_hash=hashlib.sha256(b'fixture-token').hexdigest(),repository_ids=mapping_ids,expires_at=now+timedelta(hours=1)));db.commit()
 server=uvicorn.Server(uvicorn.Config(proxy.app,host='0.0.0.0',port=18083,log_level='error'));threading.Thread(target=server.run,daemon=True).start()
 for _ in range(100):
  if server.started:break
  time.sleep(.1)
 client=requests.Session();client.trust_env=False;client.auth=('client-robot','fixture-token');timings=[]
 for _ in range(10):
  start=time.perf_counter();r=client.get('http://127.0.0.1:18083/v2/clients/image/manifests/stable',timeout=30);assert r.status_code==200,r.text;timings.append(round((time.perf_counter()-start)*1000,2))
 (root/'clients-ready.json').write_text(json.dumps({'digest':evidence['digest'],'lookup_ms':timings}))
 def wait(name):
  for _ in range(600):
   if (root/name).exists():return
   time.sleep(.5)
  raise RuntimeError('Host client probe did not complete: '+name)
 wait('clients-pulled')
 with SessionLocal() as db:
  for identity in approval_ids:db.get(CyberApproval,identity).revoked_at=datetime.now(timezone.utc)
  db.commit()
 (root/'clients-revoked').touch();wait('clients-finished');server.should_exit=True
