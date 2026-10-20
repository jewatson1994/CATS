import {useEffect, useState, type FormEvent, type ReactNode} from 'react';
import {requestJson, type PageData} from '../api';
import './risk_intelligence.css';
import {AdminTabs, Heading} from './admin_shared';
import {IntelligenceCoverage, ObservationIntelligence} from './risk_coverage';

type Row = Record<string, any>;
const pretty = (value: unknown) => JSON.stringify(value, null, 2);
const text = (value: unknown) => value == null ? 'Not available' : typeof value === 'object' ? pretty(value) : String(value);
const errorText = (error: unknown) => error instanceof Error ? error.message : 'Request failed.';
export function useResource(url: string) {
  const [value,setValue]=useState<Row|null>(null), [error,setError]=useState(''),[revision,setRevision]=useState(0);
  useEffect(()=>{const controller=new AbortController();setValue(null);setError('');
    requestJson<Row>(url,{signal:controller.signal}).then(v=>{if(!controller.signal.aborted)setValue(v);}).catch(e=>{if(!controller.signal.aborted)setError(errorText(e));});
    return ()=>controller.abort();},[url,revision]);
  return {value,error,refresh:()=>setRevision(v=>v+1)};
}
function Field({label,children}:{label:string,children:ReactNode}) {return <label className="risk-field"><span>{label}</span>{children}</label>;}
function Json({value}:{value:unknown}) {return <pre className="risk-json">{pretty(value)}</pre>;}
function useAction(data:PageData) {
  const [busy,setBusy]=useState(false),[notice,setNotice]=useState('');
  async function run(url:string,payload:Row|File,after?:(v:Row)=>void) {
    setBusy(true);setNotice('');try {const file=payload instanceof File;
      const result=await requestJson<Row>(url,{method:'POST',headers:{'X-CSRF-Token':data.csrf_token||'','Content-Type':file?'application/octet-stream':'application/json'},body:file?payload:JSON.stringify(payload)});
      setNotice('Saved.');after?.(result);
    }catch(e){setNotice(errorText(e));}finally{setBusy(false);}
  }
  return {run,busy,notice};
}
function Assessment({assessment}:{assessment:Row}) {
  const [page,setPage]=useState(0);
  const details=assessment.details||[],summary=assessment.summary||{};
  return <>
    {assessment.provenance?.preview && <p className="risk-callout">Preview only. This calculation does not change the assigned policy.</p>}
    {assessment.stale && <p className="risk-callout">Reassessment needed: {(assessment.stale_reasons||[]).join(', ')}</p>}
    <div className="risk-metrics">
      <div><span>Highest technical score</span><strong>{summary.assessment_state==='no_scan'?'No scan':summary.max_score ?? '—'}</strong></div>
      <div><span>Findings</span><strong>{summary.findings ?? 0}</strong></div>
      <div><span>With uncertainty</span><strong>{summary.uncertain ?? 0}</strong></div>
      <div><span>Assessed</span><strong className="risk-date">{new Date(assessment.as_of).toLocaleString()}</strong></div>
    </div>
    <IntelligenceCoverage assessment={assessment}/>
    <p>Category counts: {Object.entries(summary.counts||{}).map(([k,v])=>`${k}: ${v}`).join(' · ')}</p>
    <div className="risk-table"><table><thead><tr><th>Vulnerability</th><th>Technical risk</th><th>Evidence and calculation</th></tr></thead><tbody>
      {details.slice(page*25,(page+1)*25).map((f:Row)=><tr key={f.finding_id}><td>{f.cve}</td><td>{f.band} · {f.score}{f.uncertain && <span className="risk-warning"> · uncertain</span>}</td><td><details><summary>Review {f.observations.length} component observation(s)</summary>{f.observations.map((o:Row,i:number)=><div className="risk-observation" key={i}><strong>{o.package||'Unknown component'} {o.installed_version||''}</strong><p>{o.image} {o.image_digest}</p><p>KEV: {text(o.kev)} · EPSS: {text(o.epss)}</p><ul>{o.reasons?.map((r:string)=><li key={r}>{r}</li>)}</ul><ObservationIntelligence observation={o} assessmentId={assessment.id}/></div>)}</details></td></tr>)}
    </tbody></table></div>
    {details.length>25 && <div className="risk-actions"><button disabled={page===0} onClick={()=>setPage(p=>p-1)}>Previous findings</button><span>{page+1} / {Math.ceil(details.length/25)}</span><button disabled={(page+1)*25>=details.length} onClick={()=>setPage(p=>p+1)}>Next findings</button></div>}
    <details><summary>Policy, source versions and calculation provenance</summary><Json value={assessment.provenance}/></details>
  </>;
}
function DecisionForm({data,service,refresh}:{data:PageData,service:Row,refresh:()=>void}) {
  const action=useAction(data),[kind,setKind]=useState(service.decision_kinds[0]||'');
  async function submit(e:FormEvent<HTMLFormElement>) {e.preventDefault();const f=new FormData(e.currentTarget);const payload=Object.fromEntries(f.entries());
    await action.run(`/api/risk/services/${encodeURIComponent(service.service.service_key)}/decisions`,{...payload,kind,assessment_id:service.assessment.id,evidence_refs:String(payload.evidence_refs).split('\n').map(s=>s.trim()).filter(Boolean),expires_at:new Date(String(payload.expires_at)).toISOString()},refresh);
  }
  if(!service.decision_kinds.length||!service.assessment)return null;
  return <details className="risk-section"><summary>Record a human risk decision</summary><p>Decisions are informational and retain the reviewer, authority, evidence and expiration. They do not approve publication or authorize workloads.</p><form onSubmit={submit}>
    <div className="risk-grid"><Field label="Decision authority"><select value={kind} onChange={e=>setKind(e.target.value)}>{service.decision_kinds.map((k:string)=><option key={k} value={k}>{k.replaceAll('_',' ')}</option>)}</select></Field>
    <Field label="Decision"><select name="decision"><option value="accept">Accept risk</option><option value="mitigate">Conditional / mitigate</option><option value="reject">Reject</option><option value="reassess">Reassess</option></select></Field>
    <Field label="Expires / reassess by"><input name="expires_at" type="datetime-local" required/></Field></div>
    <div className="risk-grid">{[['mission_impact','Mission impact'],['controls','Compensating controls'],['justification','Decision justification'],['evidence_refs','Evidence references (one per line)']].map(([name,label])=><Field key={name} label={label}><textarea name={name} required maxLength={10000}/></Field>)}</div>
    <button disabled={action.busy}>Record decision</button><p role="status">{action.notice}</p></form></details>;
}
export function ServiceView({data,serviceKey,configuration}:{data:PageData,serviceKey:string,configuration:Row|null}) {
  const resource=useResource(`/api/risk/services/${encodeURIComponent(serviceKey)}`),action=useAction(data),[job,setJob]=useState(''),[jobState,setJobState]=useState<Row|null>(null),[selected,setSelected]=useState<Row|null>(null);
  useEffect(()=>{if(!job)return;let cancelled=false;let timer:ReturnType<typeof setTimeout>;
    async function poll(){try{const value=await requestJson<Row>(`/api/risk/jobs/${job}`);if(cancelled)return;setJobState(value);
      if(['queued','running','retrying'].includes(value.status))timer=setTimeout(poll,2000);
      else if(value.status==='completed'){resource.refresh();if(value.result?.assessment_id){const a=await requestJson<Row>(`/api/risk/assessments/${value.result.assessment_id}`);if(!cancelled)setSelected(a);}}
    }catch(e){if(!cancelled)setJobState({status:'error',error:errorText(e)});}}
    void poll();return()=>{cancelled=true;clearTimeout(timer);};
  // Resource refresh is intentionally triggered only when the selected job completes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[job]);
  const value=resource.value;
  if(!value)return <p role="status">{resource.error||'Loading assessment…'}</p>;
  return <section className="risk-section"><div className="risk-heading"><div><h2>{value.service.name}</h2><p>Cached compliance: {text(value.compliance)} · Profile: {value.policy?`${value.policy.name} v${value.policy.version}`:'Built-in default'}</p></div>
    {value.can_assess && <div className="risk-actions"><button disabled={action.busy} onClick={()=>{setSelected(null);void action.run(`/api/risk/services/${encodeURIComponent(serviceKey)}/assess`,{},v=>setJob(v.job_id));}}>Reassess</button>{configuration && <button disabled={action.busy} onClick={()=>void action.run(`/api/risk/services/${encodeURIComponent(serviceKey)}/assess`,{configuration},v=>setJob(v.job_id))}>Preview draft policy</button>}</div>}</div>
    <p className="risk-muted">Compliance cache recorded: {value.compliance_cached_at?new Date(value.compliance_cached_at).toLocaleString():'not available'}. Review the Services page for current compliance.</p><p role="status">{action.notice}{jobState && ` ${jobState.status}: ${jobState.error||jobState.stage||''}`}</p>
    {(selected||value.assessment)?<Assessment key={(selected||value.assessment).id} assessment={selected||value.assessment}/>:<p>No assessment yet. Queue a calculation to prepare evidence for review.</p>}
    <DecisionForm key={value.assessment?.id||'none'} data={data} service={value} refresh={resource.refresh}/>
    <details className="risk-section"><summary>Assessment history ({value.history.length} most recent)</summary><div className="risk-actions">{value.history.map((a:Row)=><button key={a.id} onClick={()=>requestJson<Row>(`/api/risk/assessments/${a.id}`).then(setSelected).catch(e=>setJobState({status:'error',error:errorText(e)}))}>{new Date(a.as_of).toLocaleString()} · #{a.id}</button>)}</div></details>
    <h3>Human decisions</h3>{!value.decisions.length?<p>No human risk decision recorded.</p>:value.decisions.map((d:Row)=><details className="risk-section" key={d.id}><summary>{d.kind.replaceAll('_',' ')}: {d.decision} · {d.created_by}{d.expired?' · expired':''}</summary><p>Assessment #{d.assessment_id} · expires {new Date(d.expires_at).toLocaleString()}</p><Json value={d.payload}/></details>)}
  </section>;
}
function Profiles({data,group,draft,setDraft}:{data:PageData,group:Row,draft:Row,setDraft:(v:Row)=>void}) {
  const resource=useResource(`/api/risk/profiles?group_id=${group.id}`),action=useAction(data),[name,setName]=useState(''),[parent,setParent]=useState<number|null>(null);
  function change(key:string,value:any,section?:string){setDraft(section?{...draft,[section]:{...draft[section],[key]:value}}:{...draft,[key]:value});}
  function number(key:string,label:string,help:string,min=0,max=100,section?:string){return <label className="risk-editor-field" key={key}><span>{label}</span><input aria-label={label} type="number" required min={min} max={max} step="any" value={(section?draft[section]?.[key]:draft[key])??''} onChange={e=>change(key,e.target.value===''?'':Number(e.target.value),section)}/><small>{help}</small></label>;}
  const thresholds=draft.thresholds;
  const thresholdError=thresholds && !(thresholds.low===0 && thresholds.medium>0 && thresholds.high>thresholds.medium && thresholds.critical>thresholds.high)?'Thresholds must increase: Low (0), Medium, High, then Critical.':'';
  return <section className="risk-section"><h2>Risk Profiles</h2><p>Set how findings are prioritized for <strong>{group.name}</strong>. Save a version, preview it in Assessments, then assign it to this group.</p>
    <form onSubmit={e=>{e.preventDefault();if(!thresholdError)void action.run('/api/risk/profiles',{group_id:group.id,name,configuration:draft,parent_policy_id:parent},resource.refresh);}}>
    <div className="risk-grid"><Field label="Profile name"><input required value={name} placeholder="e.g. Production services" maxLength={120} onChange={e=>setName(e.target.value)}/></Field><Field label="Start from a saved version"><select value={parent??''} onChange={e=>{const p=resource.value?.items.find((p:Row)=>p.id===Number(e.target.value));if(p){setName(p.name);setParent(p.id);setDraft(p.configuration);}}}><option value="" disabled>New profile using default settings</option>{resource.value?.items.map((p:Row)=><option key={p.id} value={p.id}>{p.name} v{p.version}</option>)}</select></Field></div>
    <section className="risk-editor-section"><h3>Risk levels</h3><p>Choose the minimum score for each level. Scores range from 0 to 100; Low always starts at 0.</p>
      <div className="risk-editor-grid">{['medium','high','critical'].map(k=>number(k,`${k[0].toUpperCase()+k.slice(1)} starts at`,'Minimum score for this level.',0,100,'thresholds'))}</div>
      {thresholdError&&<p role="alert">{thresholdError}</p>}
    </section>
    <section className="risk-editor-section"><h3>Starting scores</h3><p>Each finding starts with its reported severity score. Evidence and age can adjust it.</p><div className="risk-editor-grid">{['critical','high','medium','low','negligible','unknown'].map(k=>number(k,`${k[0].toUpperCase()+k.slice(1)} severity`,'Base points before adjustments.',0,100,'severity_weights'))}</div></section>
    <details className="risk-editor-section"><summary>Evidence and age adjustments</summary><p>Added points increase review priority. Final scores are capped at 100.</p><div className="risk-editor-grid">
      {number('kev_override','Known exploited minimum','Minimum score when listed in CISA KEV.')}
      {number('epss_weight','Exploit likelihood points','Maximum added points, scaled by EPSS probability.')}
      {number('fix_weight','Available fix points','Added when a fix is available.')}
      {number('age_weight','Age points','Maximum points added as a finding ages.')}
      {number('age_days','Days to maximum age points','Days until the full age adjustment applies.',1,3650)}
      {number('missing_floor','Uncertain evidence minimum','Minimum score when evidence is missing or uncertain.')}
      {number('uncertainty_weight','Uncertainty points','Added when evidence is missing, stale or conflicting.')}
      {number('max_age_hours','Refresh after (hours)','Assessment freshness window before reassessment is needed.',1,720)}
    </div></details>
    <details className="risk-editor-section"><summary>Risk reductions and decision labels</summary><p>Multipliers apply only with sufficiently certain evidence. A value of 1 keeps the score; 0.25 retains 25% of it.</p><div className="risk-editor-grid">
      {number('exception_multiplier','Exception multiplier','Score retained for an excepted finding.',0,1)}
      {number('vex_not_affected_multiplier','VEX not affected multiplier','Score retained for applicable, trusted, current VEX evidence.',0,1)}
    </div><div className="risk-grid">{Object.entries(draft.authority_labels||{}).map(([k,v])=><Field key={k} label={k==='ao_decision'?'Authorizing official label':k==='recommendation'?'Recommendation label':'Delegated approval label'}><input required maxLength={120} value={String(v)} onChange={e=>change(k,e.target.value,'authority_labels')}/></Field>)}</div></details>
    <details className="risk-editor-section"><summary>View configuration JSON</summary><Json value={draft}/></details>
    <div className="risk-editor-save"><button disabled={action.busy||!!thresholdError||!name.trim()}>Save new version</button><span>Saves to {group.name}. Assignment is a separate step.</span></div><p role="status">{action.notice}</p>
    </form>
    <p>Services use their single owning group's profile, inheriting from a parent group when no profile is assigned. Otherwise, the built-in default applies.</p>
    <div className="risk-table"><table><thead><tr><th>Profile version</th><th>Created</th><th>Assignment</th></tr></thead><tbody>{resource.value?.items.map((p:Row)=><tr key={p.id}><td>{p.name} v{p.version}<details><summary>Configuration</summary><Json value={p.configuration}/></details></td><td>{p.created_by}<br/>{new Date(p.created_at).toLocaleString()}</td><td><button disabled={action.busy} onClick={()=>void action.run('/api/risk/assignments',{scope:'group',scope_id:group.id,policy_id:p.id})}>Assign to {group.name}</button></td></tr>)}</tbody></table></div>{resource.value?.items.length===0&&<p>No profiles saved for this group.</p>}<p role="status">{resource.error}</p>
  </section>;
}
const countLabels: Record<string,string> = {sources:'Sources', vex_documents:'VEX documents', vex_statements:'VEX statements', records:'General records', products:'Products', vex_products:'VEX products', vex:'VEX documents', advisory:'Advisories', vulnerability:'Vulnerabilities', exploitation:'Exploitation records', risk_enrichment:'Risk enrichment records'};
function PackageCounts({counts}:{counts:Row}) {
  return <dl className="risk-package-counts">{Object.entries(counts).filter(([kind])=>kind!=='vex'||counts.vex_documents==null).map(([kind,count])=><div key={kind}><dt>{countLabels[kind]||kind.replaceAll('_',' ')}</dt><dd>{text(count)}</dd></div>)}</dl>;
}
function EmbeddedPackage({value}:{value:Row}) {
  const healthCounts=(value.sources||[]).reduce((counts:Row,s:Row)=>{const state=s.health||'unknown';counts[state]=(counts[state]||0)+1;return counts;},{});
  return <section className="risk-package" aria-label="Embedded intelligence package">
    <h3>Embedded intelligence package</h3>
    <p>Intelligence is acquired during package builds and loaded locally. Deployment does not refresh upstream evidence. Source links are audit references.</p>
    <dl className="risk-package-meta"><div><dt>Package version</dt><dd>{value.version||'None installed'}</dd></div><div><dt>Status</dt><dd>{value.status}</dd></div><div><dt>Built at</dt><dd>{value.built_at||'Not available'}</dd></div><div><dt>Installed at</dt><dd>{value.installed_at||'Not available'}</dd></div></dl>
    {value.last_error&&<p role="alert" className="risk-warning">Package load failed: {value.last_error}. Any previously installed package remains the available evidence.</p>}
    <PackageCounts counts={value.counts||{}}/><h4>Source health</h4><PackageCounts counts={healthCounts}/>
    <h4>Packaged source inventory</h4>
    <p>This inventory includes general vulnerability intelligence as well as VEX. Freshness follows each source's evidence dates.</p>
    {!value.sources?.length?<p>No packaged sources installed.</p>:<div className="risk-table"><table><thead><tr><th>Source / coverage</th><th>Acquisition and freshness</th><th>Latest package snapshot counts</th></tr></thead><tbody>{value.sources.map((s:Row)=><tr key={s.id}><td><strong>{s.name||s.id}</strong><p>{text(s.coverage||s.category)}</p><p>{s.trusted?'Authority configured':'Untrusted'} · {s.enabled?'Enabled':'Disabled'}</p>{typeof s.url==='string'&&s.url.startsWith('https://')&&<a href={s.url} target="_blank" rel="noreferrer">Source audit reference</a>}</td><td>{s.health}<p>Acquired: {s.acquired_at||'Not available'}</p><p>Freshness window: {s.max_age_days==null?'Not available':s.max_age_days+' days from acquisition'}</p>{s.expires_at&&<p>Expires: {s.expires_at}</p>}{s.last_error&&<p className="risk-warning">{s.last_error}</p>}</td><td><PackageCounts counts={s.counts||{}}/></td></tr>)}</tbody></table></div>}
    <details><summary>Coverage and exclusions</summary><p>Missing evidence is not a claim that a product is unaffected.</p><Json value={value.exclusions||[]}/></details>
  </section>;
}
export function Sources({data}:{data:PageData}) {
  const resource=useResource('/api/risk/sources'),action=useAction(data),[source,setSource]=useState(''),[kind,setKind]=useState('snapshot'),[file,setFile]=useState<File|null>(null);
  function configure(e:FormEvent<HTMLFormElement>){e.preventDefault();const f=new FormData(e.currentTarget);void action.run('/api/risk/sources',{name:f.get('name'),allowed_hosts:String(f.get('hosts')).split('\n').map(x=>x.trim()).filter(Boolean),trusted:f.get('trusted')==='on',trust_reason:f.get('trust_reason'),authoritative_prefixes:String(f.get('prefixes')).split('\n').map(x=>x.trim()).filter(Boolean),max_age_days:Number(f.get('days')),public_key:f.get('key')||null},resource.refresh);}
  return <section className="risk-section"><h2>Intelligence sources</h2>{resource.value?.embedded_package&&<EmbeddedPackage value={resource.value.embedded_package}/>}<h3>Configured VEX sources</h3><p>No feeds are downloaded at startup. Signed offline snapshots are verified against the pinned source key. A manual document upload stays unverified.</p>
    <div className="risk-table"><table><thead><tr><th>Source / trust scope</th><th>Health and freshness</th><th>Repository</th></tr></thead><tbody>{resource.value?.items.map((s:Row)=><tr key={s.id}><td><strong>{s.name}</strong><p>{s.enabled?'Enabled':'Disabled'} · {s.trusted?'Authority configured':'Untrusted'}</p><p>{s.trust_reason}</p><code>{s.authoritative_prefixes?.join(', ')}</code></td><td>{s.health||'Unknown'}<p>{s.last_error||'No reported error'}</p><p>Last success: {s.last_success?new Date(s.last_success).toLocaleString():'Never'}</p><p>Expires after {s.max_age_days} days · pinned key {s.key_configured?'configured':'absent'}</p></td><td>{s.documents} retained documents<br/>{s.statement_count_state==='lower_bound'?`${Number(s.statement_count_lower_bound).toLocaleString()}+ retained statements (total not counted)`:`${s.statements} retained statements`}<p><button disabled={action.busy} onClick={()=>void action.run(`/api/risk/sources/${s.id}/state`,{enabled:!s.enabled},resource.refresh)}>{s.enabled?'Disable':'Enable'} source</button></p></td></tr>)}</tbody></table></div>
    <h3>Import offline intelligence</h3><form onSubmit={e=>{e.preventDefault();if(file)void action.run(`/api/risk/sources/${source}/${kind}`,file,resource.refresh);}}><div className="risk-grid"><Field label="Configured source"><select required value={source} onChange={e=>setSource(e.target.value)}><option value="">Choose source</option>{resource.value?.items.map((s:Row)=><option key={s.id} value={s.id}>{s.name}</option>)}</select></Field><Field label="Import type"><select value={kind} onChange={e=>setKind(e.target.value)}><option value="snapshot">Signed snapshot (4 MiB maximum)</option><option value="documents">Unverified VEX document (4 MiB maximum)</option></select></Field><Field label="File"><input required type="file" onChange={e=>setFile(e.target.files?.[0]||null)}/></Field></div><button disabled={action.busy||!file||!source}>{kind==='snapshot'?'Verify and import':'Import as unverified'}</button></form>
    <details className="risk-section"><summary>Configure a source</summary><p>An existing source name updates its configuration. Re-enter its pinned public key and authority scope when updating.</p><form onSubmit={configure}><div className="risk-grid"><Field label="Source name"><input name="name" required maxLength={200}/></Field><Field label="Maximum age (days)"><input name="days" type="number" min="1" max="3650" defaultValue="30" required/></Field><Field label="Allowed HTTPS hostnames (one per line)"><textarea name="hosts"/></Field><Field label="Authoritative PURL prefixes (one per line)"><textarea name="prefixes" placeholder="pkg:rpm/redhat/"/></Field><Field label="Why this publisher is authoritative"><textarea name="trust_reason"/></Field><Field label="Pinned snapshot signing public key (PEM)"><textarea name="key" spellCheck={false}/></Field></div><label className="risk-check"><input type="checkbox" name="trusted"/>Trust this source within the stated product scope</label><button disabled={action.busy}>Save source configuration</button></form></details>
    <p role="status">{resource.error||action.notice}</p><details><summary>Researched source catalog (disabled by default)</summary><div className="risk-table"><table><thead><tr><th>Provider</th><th>Format / coverage</th><th>Authority and adapter limits</th></tr></thead><tbody>{resource.value?.catalog.map((s:Row)=><tr key={s.id}><td><a href={s.url} target="_blank" rel="noreferrer">{s.name}</a></td><td>{s.format}<p>{s.coverage}</p></td><td>{s.trust}<p>{s.authority}</p></td></tr>)}</tbody></table></div></details>
  </section>;
}
export function Explorer() {
  const [query,setQuery]=useState(''),[status,setStatus]=useState(''),[filter,setFilter]=useState(''),[after,setAfter]=useState(0),[original,setOriginal]=useState<Row|null>(null),[error,setError]=useState('');
  const resource=useResource(`/api/risk/statements?q=${encodeURIComponent(filter)}&status=${status}&after=${after}`);
  return <section className="risk-section"><h2>VEX Explorer</h2><form className="risk-actions" onSubmit={e=>{e.preventDefault();setFilter(query);setAfter(0);}}><Field label="CVE, package, PURL, product, version or source"><input value={query} maxLength={200} onChange={e=>setQuery(e.target.value)}/></Field><Field label="Status"><select value={status} onChange={e=>{setStatus(e.target.value);setAfter(0);}}><option value="">All statements</option>{['affected','not_affected','fixed','under_investigation'].map(s=><option key={s}>{s}</option>)}</select></Field><button>Search</button></form><p>These are publisher statements. Applicability, freshness and conflicts are evaluated against each service component in its assessment.</p>
    <div className="risk-table"><table><thead><tr><th>Vulnerability / product</th><th>Statement</th><th>Provenance</th></tr></thead><tbody>{resource.value?.items.map((s:Row)=><tr key={s.id}><td>{s.cve}<p><code>{s.product_id}</code></p></td><td>{s.status}{s.withdrawn?' · withdrawn':''}<p>{s.justification}</p><p>{s.impact}</p><p>{s.action}</p><details><summary>Normalized identity</summary><Json value={s.identity}/></details></td><td>{s.source}<p>{s.verification} · {s.issued_at}</p><button onClick={()=>requestJson<Row>(`/api/risk/documents/${s.document_id}`).then(setOriginal).catch(e=>setError(errorText(e)))}>Original document</button></td></tr>)}</tbody></table></div><p role="status">{error||resource.error}</p><div className="risk-actions"><button disabled={!after} onClick={()=>setAfter(0)}>First page</button><button disabled={!resource.value?.next_after} onClick={()=>setAfter(resource.value?.next_after)}>Next page</button></div>{original&&<details open><summary>Original document #{original.id}</summary><button onClick={()=>setOriginal(null)}>Close</button><Json value={original}/></details>}
  </section>;
}
function GroupRisk({data,group,caps}:{data:PageData,group:Row,caps:Row}) {
  const [tab,setTab]=useState('Risk Profiles'),[query,setQuery]=useState(''),[search,setSearch]=useState(''),[after,setAfter]=useState(0),[selected,setSelected]=useState<Row|null>(null),[draft,setDraft]=useState<Row|null>(null);
  const services=useResource(`/api/risk/services?group_id=${group.id}&q=${encodeURIComponent(search)}&after=${after}`);
  return <><nav className="risk-tabs" aria-label="Risk Policy">{['Risk Profiles','Assessments'].map(t=><button key={t} aria-current={tab===t?'page':undefined} onClick={()=>setTab(t)}>{t}</button>)}</nav>
    {tab==='Risk Profiles'&&<Profiles data={data} group={group} draft={draft||caps.default_policy} setDraft={setDraft}/>}
    {tab==='Assessments'&&<><form className="risk-service-search risk-section" onSubmit={e=>{e.preventDefault();setSearch(query);setAfter(0);}}><div className="risk-search-row"><Field label="Find a service"><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Service name or key"/></Field><button>Search</button></div><div className="risk-search-row"><Field label="Service"><select value={selected?.service_key||''} onChange={e=>setSelected(services.value?.items.find((s:Row)=>s.service_key===e.target.value)||null)}><option value="">Choose a service</option>{services.value?.items.map((s:Row)=><option key={s.id} value={s.service_key}>{s.name}</option>)}</select></Field><button type="button" disabled={!after} onClick={()=>setAfter(0)}>First</button><button type="button" disabled={!services.value?.next_after} onClick={()=>setAfter(services.value?.next_after)}>More services</button></div><p role="status">{services.error}</p></form>{selected?<ServiceView key={selected.service_key} data={data} serviceKey={selected.service_key} configuration={draft}/>:<p>Select a service owned by {group.name} to review its assessment and decision history.</p>}</>}
  </>;
}
export function Page({data}:{data:PageData}) {
  const capabilities=useResource('/api/risk/capabilities'),[groupId,setGroupId]=useState(String(data.selected_group_id||''));
  const caps=capabilities.value,group=caps?.groups?.find((g:Row)=>String(g.id)===groupId);
  return <div className="risk-policy-page"><Heading title="Risk Policy" description="Manage risk profiles and review assessments for each service's owning group."/><AdminTabs data={data} selected="risk"/>
    <div className="risk-intelligence"><p className="risk-callout"><strong>Informational only.</strong> Risk Profiles and human decisions do not change compliance, remediation, publication or runtime enforcement.</p>
    {!caps?<p role="status">{capabilities.error||'Loading permissions…'}</p>:<><section className="risk-section risk-group-picker"><Field label="Owning group"><select value={group?.id||''} onChange={e=>setGroupId(e.target.value)}><option value="">Choose a group</option>{caps.groups.map((g:Row)=><option key={g.id} value={g.id}>{g.name}</option>)}</select></Field><p>Only groups you can manage are listed. Each service has one owning group.</p></section>{group?<GroupRisk key={group.id} data={data} group={group} caps={caps}/>:<p>{caps.groups.length?'Choose a group to manage its risk policy.':'You do not have permission to manage risk policy for any group.'}</p>}</>}
    </div></div>;
}

export function ServiceRisk({data,serviceKey}:{data:PageData,serviceKey:string}) {
  const [open,setOpen]=useState(false);
  return <details className="panel padded" onToggle={e=>setOpen(e.currentTarget.open)}><summary>Risk Profile, technical assessment and Cyber decisions</summary>{open&&<ServiceView data={data} serviceKey={serviceKey} configuration={null}/>}</details>;
}
export function IntelligenceSettings({data}:{data:PageData}) {
  const [open,setOpen]=useState(false);
  return <details className="panel padded" onToggle={e=>setOpen(e.currentTarget.open)}><summary>Intelligence sources and VEX explorer</summary>{open&&<><Sources data={data}/><Explorer/></>}</details>;
}
