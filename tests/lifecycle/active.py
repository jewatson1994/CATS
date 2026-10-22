"""Real signed revisions/HTTP with explicitly synthetic scan and validation evidence."""
import hashlib,json,threading,time
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
from pathlib import Path
import requests,uvicorn
from sqlalchemy import select

def main(root, material, session, endpoint, repo, old_raw, config, layer):
 from app import oci_proxy as proxy, release_revisions as rr
 from app.database import SessionLocal
 from app.models import Service,Execution,PatchExecution,DeploymentValidationRun,User
 from app.artifact_catalog import register_artifact,assign_artifact,record_patch_lineage
 from app.oci_models import OCIUpstream,OCIRepository,OCIPrincipal
 from app.cyber_approvals import CyberApproval,digest
 from app.execution_summaries import payload_digest
 from app.release_validity import new_validity
 now=datetime.now(timezone.utc); media='application/vnd.oci.image.manifest.v1+json'
 raw=json.dumps(dict(schemaVersion=2,mediaType=media,config=config,layers=[layer],annotations={'fixture':'patched'}),separators=(',',':')).encode()
 patched='sha256:'+hashlib.sha256(raw).hexdigest();old='sha256:'+hashlib.sha256(old_raw).hexdigest()
 response=session.put(endpoint+'/v2/'+repo+'/manifests/patched',data=raw,headers={'Content-Type':media},timeout=15);response.raise_for_status()
 # The upstream stable tag deliberately still resolves to the original bytes.
 assert session.get(endpoint+'/v2/'+repo+'/manifests/stable',headers={'Accept':media},timeout=15).content==old_raw
 auth=SimpleNamespace(has=lambda *a:True); revision_ids=[]; approval_ids=[]
 with SessionLocal() as db:
  user=db.scalar(select(User)); assert user
  source=register_artifact(db,digest=old,media_type=media,platform='linux/amd64')
  target=register_artifact(db,digest=patched,media_type=media,platform='linux/amd64')
  upstream=OCIUpstream(name='active-registry',endpoint=endpoint,ca_pem=(root/'server.crt').read_text());db.add(upstream);db.flush()
  mappings=[]
  for key in ['active-one','active-two']:
   service=Service(service_key=key,name=key);db.add(service);db.flush()
   execution=Execution(service_id=service.id,execution_key=key,scanned_at=now,complete=True,scan_scope='service',raw_payload={});db.add(execution)
   mapping=OCIRepository(public_repository=key+'/image',service_id=service.id,upstream_id=upstream.id,upstream_repository=repo);db.add(mapping);db.flush();mappings.append(mapping.id)
   for artifact in [source,target]:assign_artifact(db,service_id=service.id,artifact_id=artifact.id)
   src='registry:5000/'+repo+'@'+old;dst='registry:5000/'+repo+'@'+patched
   receipt=dict(status='complete',patch_status='PATCHED',delivery_status='delivered',source_image=src,immutable_destination=dst,signature_status='verified',signature=dict(image=dst,generator='cosign',key_fingerprint=material[0]['signing_fingerprint'],verified_at=now.isoformat()),artifact_validation='docker-load',validated_source='flattened-rootfs',vulnerabilities_before=4,vulnerabilities_after=0)
   patch=PatchExecution(job_key=key,service_id=service.id,requested_by_id=user.id,source_mode='registry',output_mode='publish',status='complete',source_image=src,destination_image=dst,summary={'artifact_receipt':receipt});db.add(patch);db.flush()
   record_patch_lineage(db,patch_execution_id=patch.id,source_artifact_id=source.id,output_artifact_id=target.id)
   db.add(DeploymentValidationRun(run_key=key,service_id=service.id,artifact_reference=dst,status='VERIFIED'));db.flush()
   snapshot=dict(service_id=service.id,source_execution_id=execution.id,source_version_id=None,source_payload_digest=payload_digest({}),approval_validity=new_validity(now),artifacts=[dict(kind='image',reference=dst,digest=patched)],signing_fingerprint=material[0]['signing_fingerprint'],release_revision=dict(base_revision_id=None,artifact_ids=[target.id],distribution_bindings=[dict(repository_id=mapping.id,tag='stable',artifact_id=target.id)]))
   approval=CyberApproval(service_id=service.id,source_execution_id=execution.id,variant='current_service',status='approved',snapshot=snapshot,snapshot_digest=digest(snapshot),decided_at=now,decided_by_id=user.id);db.add(approval);db.flush();approval_ids.append(approval.id)
   revision=rr.propose(db,auth,approval.id);rr.decide(db,auth,revision.id,0);db.flush()
   rr.publish_manifest(db,approval,material);rr.activate(db,auth,revision.id,0);revision_ids.append(revision.id)
  machine=OCIPrincipal(name='active-robot',secret_hash=hashlib.sha256(b'fixture-token').hexdigest(),repository_ids=mappings,expires_at=now+timedelta(hours=1));db.add(machine);db.commit()
 server=uvicorn.Server(uvicorn.Config(proxy.app,host='127.0.0.1',port=18082,log_level='error'));threading.Thread(target=server.run,daemon=True).start()
 for _ in range(100):
  if server.started:break
  time.sleep(.1)
 client=requests.Session();client.trust_env=False;client.auth=('active-robot','fixture-token')
 def get(service,reference):return client.get('http://127.0.0.1:18082/v2/'+service+'/image/manifests/'+reference,timeout=30)
 for service in ['active-one','active-two']:
  response=get(service,'stable');assert response.status_code==200,response.text
  assert response.content==raw and response.headers['Docker-Content-Digest']==patched
  assert get(service,old).status_code==403 # Digest request cannot substitute patched bytes.
 with SessionLocal() as db:
  state=db.get(rr.ReleaseRevisionState,revision_ids[0]);rr.restrict(db,auth,revision_ids[0],state.version,'revoke','fixture service-specific revoke');db.commit()
 assert get('active-one','stable').status_code==403
 assert get('active-two','stable').status_code==200
 # Tamper with service two's actual detached manifest, preserving the active pointer.
 with SessionLocal() as db:folder=rr.manifest_directory(db.get(rr.ReleaseRevision,revision_ids[1]))
 manifest=folder/'release-manifest.json';manifest.write_bytes(manifest.read_bytes()+b' ')
 assert get('active-two','stable').status_code==403
 server.should_exit=True
 result={'checks':['real Cosign signed revision activation on PostgreSQL','stable tag returns patched digest while upstream tag remains original','original digest never substituted','shared artifact independent service revocation','tampered signed manifest denied over HTTP'],'limitations':'Patch scan receipts, deployment validation and Cyber decisions are synthetic fixture records; no actual patch or scanner run.'}
 (root/'active-results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2),flush=True)
