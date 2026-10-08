import {useEffect, useRef, useState} from 'react';
import {can, requestJson, type PageData} from '../api';
import {usePoll, type PollStatus} from '../hooks/usePoll';
import {AdminTabs, Heading} from './admin_shared';
import {StageProgress, type Stage, type StageState} from '../components/ui';
import './validators.css';
type RecordData = Record<string, any>;
const base = '/api/frontend/settings/validators';
const active = new Set(['PROVISIONING','ENROLLING','STARTING','TESTING','REMOVING']);
const factLabels: Record<string,string> = {memory_bytes:'Memory',cpus:'CPU cores',disk_free_bytes:'Free disk',os:'Operating system',os_version:'OS version',architecture:'Architecture',docker_version:'Docker',cgroup_version:'Cgroup version',default_runtime:'Runtime',cgroup_driver_name:'Cgroup driver'};
const words = (value: string) => value.replaceAll('_', ' ').replaceAll('-', ' ');
const provisionStages = [['PREFLIGHT','Checking host readiness'], ['VERIFYING_RELEASE','Verifying image archives'], ['DEPLOYING','Transferring images and deploying CATS'], ['HEALTH','Checking trusted API health'], ['SELF_TEST','Running validation self-test'], ['COMPLETE','Ready']];
function OperationStages({item}: {item: RecordData}) {
  const stages = ['provision','rotate'].includes(item.action) ? provisionStages : [[item.phase || 'PENDING', words(item.phase || 'Pending')]];
  const index = stages.findIndex(([phase]) => phase === item.phase);
  const succeeded = item.status === 'SUCCEEDED';
  const progress: Stage[] = stages.map(([phase,label], position) => {
    const state: StageState = succeeded || position < index ? 'complete' : position === index ? ['FAILED','CANCELLED'].includes(item.status) ? 'failed' : 'current' : 'pending';
    return {key: phase, label, state, detail: state === 'complete' ? 'Completed' : state === 'current' ? 'In progress' : state === 'failed' ? words(item.status) : 'Waiting'};
  });
  return <div className="validator-progress"><p role="status">{succeeded ? 'Completed' : words(item.status || 'Pending') + ': ' + (stages[index]?.[1] || words(item.phase || 'Pending'))}</p><StageProgress label="Operation stages" orientation={stages.length > 1 ? 'horizontal' : 'vertical'} stages={progress}/></div>;
}

export function Page({data}: {data: PageData}) {
  const [rows, setRows] = useState<RecordData[]>(data.validators || []);
  const [imageReadiness, setImageReadiness] = useState<RecordData>(data.image_readiness || {});
  const [selected, select] = useState<string>(String(data.validators?.[0]?.id || ''));
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState('');
  const [method, setMethod] = useState('password');
  const [credentials, setCredentials] = useState({password:'',private_key:'',passphrase:'',sudo_password:''});
  const [confirmed, confirm] = useState(false), [dedicated, dedicate] = useState(false), [warnings, acknowledge] = useState(false), [remove, removing] = useState(false);
  const revision = useRef(0);
  const current = rows.find(row => String(row.id) === selected);
  const history = [...(current?.history || current?.operations || [])].sort((a:RecordData,b:RecordData) => Number(b.id === current?.active_operation_id) - Number(a.id === current?.active_operation_id) || String(b.started_at || '').localeCompare(String(a.started_at || '')));
  const latest = history[0];
  const allowed = (action: string) => can(data, `validator.${action}`);
  const replace = (record: RecordData) => setRows(previous => previous.some(row => String(row.id) === String(record.id)) ? previous.map(row => String(row.id) === String(record.id) ? record : row) : [...previous, record]);
  async function refresh() {const token = revision.current; try {const result = await requestJson<{validators: RecordData[];image_readiness:RecordData}>(base); if (token === revision.current) {setRows(result.validators);setImageReadiness(result.image_readiness || {});}} catch (cause) {setError(String(cause instanceof Error ? cause.message : cause));}}
  useEffect(() => {confirm(false);dedicate(false);acknowledge(false);removing(false);setCredentials({password:'',private_key:'',passphrase:'',sudo_password:''});}, [selected]);
  // While an operation runs: one request at a time, cancelled on change or
  // unmount, paused while hidden, backoff on errors, stop when it settles.
  const operating = Boolean(!busy && current && (active.has(current.status) || current.active_operation_id));
  const settled = (record: RecordData) => !active.has(record.status) && !record.active_operation_id;
  const validatorPoll = usePoll<{validator: RecordData} & PollStatus>({
    url: operating && current ? `${base}/${encodeURIComponent(current.id)}?operation=${encodeURIComponent(String(current.active_operation_id || current.status))}` : null,
    intervalMs: 3000, maxIntervalMs: 15000,
    load: async (url, signal) => {
      const token = revision.current;
      const result = await requestJson<{validator: RecordData} & PollStatus>(url.split('?')[0], {signal});
      return {...result, token};
    },
    isTerminal: result => settled(result.validator),
    // A result fetched before one of this page's own actions finished is ignored.
    onStatus: result => {if (result.token === revision.current) replace(result.validator);},
  });
  async function submit(action: string, form?: HTMLFormElement) {
    const body = form ? new FormData(form) : new FormData(); body.set('csrf_token',data.csrf_token || '');
    if (['preflight','provision','rotate','remove'].includes(action)) {body.set('auth_method',method);Object.entries(credentials).forEach(([key,value]) => body.set(key,value));}
    if (action === 'confirm') body.set('fingerprint',current?.fingerprint || '');
    body.set('dedicated_host',String(dedicated));body.set('resource_warnings',String(warnings));
    body.set('operation_id',String(current?.active_operation_id || current?.history?.find((item:RecordData) => ['pending','running'].includes(String(item.status).toLowerCase()))?.id || ''));
    revision.current++;
    setCredentials({password:'',private_key:'',passphrase:'',sudo_password:''});setBusy(true);setError('');setMessage('');
    try {const result = await requestJson<{validator:RecordData;message?:string}>(action === 'add' ? base : `${base}/${encodeURIComponent(current!.id)}/${action}`,{method:'POST',body});replace(result.validator);select(String(result.validator.id));setMessage(result.message || `${words(action)} request submitted. Temporary credentials cleared.`);form?.reset();}
    catch(cause) {setError(cause instanceof Error ? cause.message : 'Request failed.');} finally {revision.current++;setBusy(false);}
  }
  const running = busy || active.has(current?.status) || !!current?.active_operation_id;
  const preflight = current?.preflight || {}, facts = preflight.facts || {};
  const preflightReady = ['supported','supported_with_warnings','ready','passed'].includes(String(preflight.status).toLowerCase());
  const health = current?.last_health || current?.health || {}, selfTest = current?.last_self_test || current?.self_test || {};
  const credentialsInput = (key:keyof typeof credentials,label:string,multiline=false) => <label>{label}{multiline ? <textarea autoComplete="off" value={credentials[key]} onChange={event => setCredentials({...credentials,[key]:event.target.value})}/> : <input type="password" autoComplete="new-password" value={credentials[key]} onChange={event => setCredentials({...credentials,[key]:event.target.value})}/>}</label>;
  return <div className="validators-workspace"><Heading title="Validators" description="Deploy CATS to a dedicated Docker-ready Ubuntu host, then validate over its trusted API."/><AdminTabs data={data} selected="configuration"/><p><a href="/admin/configuration#integrations">Settings / Integrations</a></p>
    <aside className="validator-notice"><strong>Dedicated virtual machine required</strong><p>The validator controls Docker through the host socket. This grants control equivalent to root. Use a dedicated VM with no unrelated workloads. Docker must already be installed and running.</p></aside>
    {validatorPoll.error && <p role="status" className="page-refresh-notice">Live validator status is unavailable; retrying.</p>}{message && <p role="status" className="save-confirmation">{message}</p>}{error && <p role="alert">{error}</p>}
    <div className="validator-layout"><section className="panel padded"><div className="validator-title"><h2>Your validators</h2><button disabled={busy} onClick={refresh}>Refresh</button></div>
      {rows.length ? rows.map(row => <button className={`validator-choice ${String(row.id)===selected?'selected':''}`} key={row.id} onClick={() => select(String(row.id))}><strong>{row.name}</strong><span>{row.host}</span><span className="validator-badge">{words(row.status || 'NEW')}</span></button>) : <p>No validators configured yet.</p>}
      {allowed('add') && <details><summary>Add validator</summary><form onSubmit={event => {event.preventDefault();void submit('add',event.currentTarget);}}><label>Name<input name="name" required maxLength={100}/></label><label>Host address<input name="host" required/></label><label>SSH username<input name="ssh_username" required/></label><div className="validator-grid"><label>SSH port<input name="ssh_port" type="number" min="1" max="65535" defaultValue="22"/></label><label>API port<input name="api_port" type="number" min="1" max="65535" defaultValue="8443"/></label></div><button disabled={busy}>Add validator</button></form></details>}
    </section><section className="panel padded">{current ? <><div className="validator-title"><div><h2>{current.name}</h2><p>{current.host}:{current.api_port || 8443}</p></div><span className="validator-badge">{words(current.status || 'NEW')}</span></div>
      <section className="validator-section"><h3>1. Verify host identity</h3><p>Confirm the fingerprint using a trusted source before sending credentials.</p><code className="validator-fingerprint">{current.fingerprint || 'Fingerprint not discovered'}</code><div className="validator-actions">{allowed('preflight') && <button disabled={running} onClick={() => submit('discover')}>Discover SSH fingerprint</button>}</div>{current.fingerprint && !current.fingerprint_confirmed && allowed('preflight') && <><label className="validator-check"><input type="checkbox" checked={confirmed} onChange={event => confirm(event.target.checked)}/>I verified this fingerprint with the host administrator</label><button disabled={running || !confirmed} onClick={() => submit('confirm')}>Confirm fingerprint</button></>}{current.fingerprint_confirmed && <p className="validator-good">Fingerprint confirmed</p>}</section>
      <section className="validator-section"><h3>2. Host readiness</h3>{preflight.status ? <><p className="validator-badge">{words(preflight.status)}</p><dl className="validator-facts">{Object.entries(facts).filter(([key,value]) => value != null && !['epoch'].includes(key)).map(([key,value]) => <div key={key}><dt>{factLabels[key] || words(key)}</dt><dd>{typeof value === 'boolean' ? value?'Yes':'No' : key.endsWith('_bytes') ? `${(Number(value)/1024**3).toFixed(1)} GiB` : String(value)}</dd></div>)}</dl><div className="validator-checks">{Object.entries(preflight.checks || {}).map(([key,value]) => <div key={key}><span>{words(key)}</span><strong className={value?'validator-good':'validator-bad'}>{value?'Passed':'Needs attention'}</strong></div>)}</div>{preflight.warnings?.length>0 && <aside className="validator-notice"><strong>Review before provisioning</strong><ul>{preflight.warnings.map((warning:string) => <li key={warning}>{warning}</li>)}</ul><label className="validator-check"><input type="checkbox" checked={warnings} onChange={event => acknowledge(event.target.checked)}/>I acknowledge these warnings</label></aside>}</> : <p>Run host preflight to check Ubuntu version, resources and Docker readiness.</p>}</section>
      {(allowed('preflight') || allowed('provision') || allowed('remove')) && <section className="validator-section"><h3>Temporary SSH credentials</h3><p>Cleared after every submission. Normal validation uses the trusted API.</p><label>Authentication method<select value={method} onChange={event => {setMethod(event.target.value);setCredentials({password:'',private_key:'',passphrase:'',sudo_password:''});}}><option value="password">Password</option><option value="private_key">Private key</option></select></label>{method==='password' ? credentialsInput('password','Temporary password') : <>{credentialsInput('private_key','Temporary SSH private key',true)}{credentialsInput('passphrase','Private key passphrase')}</>}{credentialsInput('sudo_password','Sudo password (if required)')}<div className="validator-actions">{allowed('preflight') && <button disabled={running || !current.fingerprint_confirmed} onClick={() => submit('preflight')}>Test SSH and run preflight</button>}</div>
      <h3>3. Deploy CATS validator</h3><p>{imageReadiness.ready ? `Application image ready: ${imageReadiness.image_reference || 'current CATS image'}` : imageReadiness.reason || 'A verified CATS image is required before provisioning.'}</p><label className="validator-check"><input type="checkbox" checked={dedicated} onChange={event => dedicate(event.target.checked)}/>This is a dedicated VM; I acknowledge Docker socket access grants root-equivalent control</label>{allowed('provision') && <button disabled={running || !current.fingerprint_confirmed || !preflightReady || !dedicated || (!!preflight.warnings?.length && !warnings) || !imageReadiness.ready} onClick={() => submit('provision')}>Provision validator</button>}{allowed('provision') && current.certificate?.expires_at && <button disabled={running || !current.fingerprint_confirmed || !preflightReady || !dedicated || (!!preflight.warnings?.length && !warnings) || !imageReadiness.ready} onClick={() => submit('rotate')}>Rotate certificate</button>}</section>}
      <section className="validator-section"><h3>4. Verify operation</h3><div className="validator-grid"><article><h4>API health</h4><p>{health.status || 'Not tested'}</p><p>{health.message || health.error || 'Checks trusted identity and protocol compatibility.'}</p></article><article><h4>Validation self-test</h4><p>{selfTest.status || 'Not run'}</p><p>{selfTest.message || selfTest.error || 'Creates a temporary Kind cluster and verifies validation and cleanup.'}</p></article></div><div className="validator-actions">{current.status === 'HEALTHY' && allowed('provision') && <button disabled={busy} onClick={() => submit('select')}>Use for deployment validation</button>}{allowed('test') && <button disabled={running} onClick={() => submit('test')}>Test connection</button>}{allowed('selftest') && <button disabled={running} onClick={() => submit('self-test')}>Run self-test</button>}{(active.has(current.status) || !!current.active_operation_id) && allowed('cancel') && <button disabled={busy} onClick={() => submit('cancel')}>Cancel operation</button>}</div><p>Last successful contact: {current.last_contact_at || 'Not yet connected'}</p><p>Certificate: {current.certificate?.expires_at ? `expires ${current.certificate.expires_at}` : 'Not enrolled'}</p></section>
      <section className="validator-section"><h3>{current.active_operation_id ? 'Current operation' : 'Latest operation'}</h3>{latest ? <><strong>{words(latest.action || 'Operation')} · {words(latest.status || '')}</strong><OperationStages item={latest}/><p>Started: {latest.started_at}</p>{latest.error && <p role="alert">{latest.error}</p>}{history.length > 1 && <details><summary>Previous operations ({history.length - 1})</summary><ol className="validator-history">{history.slice(1).map((item:RecordData) => <li key={item.id}><strong>{words(item.action || 'Operation')} · {words(item.status || '')}</strong><p>Started: {item.started_at}</p>{item.error && <p>{item.error}</p>}</li>)}</ol></details>}</> : <p>No operations recorded yet.</p>}</section>
      {allowed('remove') && current.status !== 'REMOVED' && <details><summary>Remove validator</summary><p>Removes only the CATS validator deployment and retires its certificate. Docker and unrelated workloads remain.</p><label className="validator-check"><input type="checkbox" checked={remove} onChange={event => removing(event.target.checked)}/>Confirm removal of {current.name}</label><button disabled={running || !remove} onClick={() => submit('remove')}>Remove validator</button></details>}
    </> : <p>Select a validator or add a dedicated host to get started.</p>}</section></div></div>;
}
