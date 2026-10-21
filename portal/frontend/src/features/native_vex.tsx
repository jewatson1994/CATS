import {useState} from 'react';
import {can, requestJson, type PageData} from '../api';
import {useResource, IntelligenceSettings} from './risk_intelligence';

type Row=Record<string, any>;
export function VexEvidence({serviceKey,findingId,expanded=false}:{serviceKey:string,findingId?:number,expanded?:boolean}) {
  const [open,setOpen]=useState(false);
  if(expanded)return <section className="panel padded"><h2>Automatic VEX disposition and evidence</h2><Evidence serviceKey={serviceKey} findingId={findingId}/></section>;
  return <details className="panel padded" onToggle={e=>setOpen(e.currentTarget.open)}><summary>Automatic VEX disposition and evidence</summary>{open&&<Evidence serviceKey={serviceKey} findingId={findingId}/>}</details>;
}
function Evidence({serviceKey,findingId}:{serviceKey:string,findingId?:number}) {
  const [after,setAfter]=useState(0);
  const resource=useResource(`/api/risk/services/${encodeURIComponent(serviceKey)}/native-vex?after=${after}${findingId?`&finding_id=${findingId}`:''}`);
  const value=resource.value;
  if(!value)return <p role="status">{resource.error||'Loading VEX evidence…'}</p>;
  return <><p>Automatic exclusion: <strong>{value.enabled?'Enabled':'Disabled'}</strong>. {value.current?'Current evaluation.':'Evaluation pending, failed or stale; VEX cannot exclude these observations.'} Original scanner evidence is retained. This is the current service evaluation; historical approval snapshots remain unchanged.</p>
    {value.evaluation&&<p>Evaluated: {value.evaluation.evaluated_at} · Valid until: {value.evaluation.valid_until} · Policy version: {value.evaluation.policy_version}</p>}
    <table><thead><tr><th>Finding / observation</th><th>Effective disposition</th><th>Evidence</th></tr></thead><tbody>{value.items.filter((o:Row)=>!findingId||o.finding_id===findingId).map((o:Row)=><tr key={o.id}><td>{o.finding_id} / {o.observation_id}</td><td>{o.effective_disposition==='vex_not_affected'?'VEX Excluded':o.effective_disposition==='resolved'?'Resolved':o.effective_disposition==='exception'?'Accepted exception':'Actionable under existing policy'}</td><td><p>{o.evidence.component?.package || 'Unknown component'} {o.evidence.component?.version || ''}{o.evidence.component?.image ? ` in ${o.evidence.component.image}` : ''}</p><p>{(o.evidence.reasons || []).join('; ') || o.evidence.status || 'No applicable evidence'}</p><details><summary>Applicability, identity and provenance</summary><pre className="risk-json">{JSON.stringify(o.evidence,null,2)}</pre></details></td></tr>)}</tbody></table>
    {!value.items.length&&<p>No evaluated observations available.</p>}<button disabled={!after} onClick={()=>setAfter(0)}>First page</button> <button disabled={!value.next_after} onClick={()=>setAfter(value.next_after)}>Next observations</button></>;
}
export function VexSettings({data}:{data:PageData}) {
  return can(data,'config.manage')?<><Policy data={data}/><IntelligenceSettings data={data}/></>:null;
}
function Policy({data}:{data:PageData}) {
  const policy=useResource('/api/risk/native-vex/policy'),[preview,setPreview]=useState<Row|null>(null),[busy,setBusy]=useState(false),[notice,setNotice]=useState('');
  async function inspect(after=0){setBusy(true);setNotice('');try{setPreview(await requestJson<Row>(`/api/risk/native-vex/preview?after=${after}`));}catch(e){setNotice(e instanceof Error?e.message:'Preview failed.');}finally{setBusy(false);}}
  async function save(){if(!policy.value)return;setBusy(true);setNotice('');try{await requestJson('/api/risk/native-vex/policy',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':data.csrf_token||''},body:JSON.stringify({enabled:!policy.value.enabled,version:policy.value.version})});setNotice('Policy saved. Classification follows current validated evidence.');setPreview(null);policy.refresh();}catch(e){setNotice(e instanceof Error?e.message:'Save failed.');setPreview(null);policy.refresh();}finally{setBusy(false);}}
  return <section className="panel padded"><h2>Automatic VEX Not Affected Exclusion</h2><p>Default: Disabled. Only authoritative, current, fully applicable Not Affected evidence can exclude an observation. Mixed findings remain actionable. Scanner evidence and human decisions are retained.</p><p>Current policy: <strong>{policy.value?(policy.value.enabled?'Enabled':'Disabled'):'Loading…'}</strong></p><button disabled={busy||!policy.value} onClick={()=>void inspect()}>Preview exclusion impact</button>
    {preview&&<><p>{preview.note} Counts compare disabled with enabled exclusion; other compliance requirements still apply.</p><table><thead><tr><th>Service</th><th>Actionable before → after</th><th>Non-compliant before → after</th><th>Service compliance before → after</th></tr></thead><tbody>{preview.items.map((s:Row)=><tr key={s.service_id}><td>{s.name}</td><td>{s.eligible_before} → {s.eligible_after}</td><td>{s.noncompliant_before} → {s.noncompliant_after}</td><td>{s.compliance_before === true ? 'Compliant' : s.compliance_before === false ? 'Non-compliant' : 'Unavailable'} → {s.compliance_after === true ? 'Compliant' : s.compliance_after === false ? 'Non-compliant' : 'Unavailable'}</td></tr>)}</tbody></table>{preview.next_after&&<button disabled={busy} onClick={()=>void inspect(preview.next_after)}>Next services</button>}</>}
    <p><button disabled={busy||!policy.value||(!policy.value.enabled&&preview?.version!==policy.value.version)} onClick={()=>void save()}>{policy.value?.enabled?'Disable':'Enable'} automatic exclusion</button></p><p role="status">{notice||policy.error}</p></section>;
}

export function VexPoamReview({serviceKey,findingId}:{serviceKey:string,findingId:number}) {
  const resource=useResource(`/api/risk/services/${encodeURIComponent(serviceKey)}/native-vex?finding_id=${findingId}`);
  const value=resource.value;
  const excluded=value?.finding_disposition==='vex_not_affected';
  return <>{excluded&&<p className="risk-callout" role="status">Cyber review required: this finding is currently fully VEX Excluded. This existing POA&amp;M entry remains open until the authorized review and closure workflow is completed.</p>}<VexEvidence serviceKey={serviceKey} findingId={findingId}/></>;
}
