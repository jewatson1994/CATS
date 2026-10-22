import {useEffect, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';
import '../styles/discovery.css';
import {StageProgress} from '../components/ui';
type Id = string | number;
interface Job {id: string; status: string; stage?: string; progress?: number; group_id?: Id; error?: string; result?: {confirmed_inventory_id?: Id}}
interface Root {id: string; path: string; technology: string; completeness?: unknown}
interface Node {id: string; kind: string; name: string; root_id?: string; state?: string; provenance?: unknown}
interface Inventory {roots: Root[]; nodes: Node[]; edges?: unknown[]; images: {reference: string; root_id?: string; component_id?: string; provenance?: unknown}[]; diagnostics?: {code?: string; path?: string; message?: string; value_paths?: string[]}[]; completeness?: unknown; metrics?: Record<string, unknown>; selection?: Record<string, unknown>; candidate_values_files?: string[]; candidate_environments?: unknown[]}
interface Catalog {jobs: Job[]; services: {id: Id; name: string; service_key: string; group_id?: Id}[]; groups: {id: Id; name: string; can_stage?: boolean}[]}
const terminal = new Set(['complete', 'completed', 'failed', 'cancelled', 'succeeded']);
const describe = (value: unknown): string => value == null ? 'Unknown' : typeof value === 'string' ? value : JSON.stringify(value, null, 2);
export function isPartial(value: unknown): boolean {
  if (value === true || value === 'complete') return false;
  if (typeof value === 'object' && value !== null && 'status' in value) return isPartial((value as {status: unknown}).status);
  return true;
}
function Evidence({value}: {value: unknown}) {return value == null ? null : <details className="discovery-evidence"><summary>Source evidence</summary><pre>{describe(value)}</pre></details>;}
export function Page({data}: {data: PageData}) {
  const [catalog, setCatalog] = useState<Catalog>({jobs: [], services: [], groups: []});
  const [selected, setSelected] = useState(''); const [job, setJob] = useState<Job | null>(null);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [resolution, setResolution] = useState('{}');
  const [valuesSearch, setValuesSearch] = useState('');
  const [newService, setNewService] = useState('');
  const [group, setGroup] = useState(''); const [service, setService] = useState('');
  const [roots, setRoots] = useState<string[]>([]); const [acknowledged, setAcknowledged] = useState(false);
  const [confirmed, setConfirmed] = useState(false); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(''); const [refresh, setRefresh] = useState(0);
  const [comparison, setComparison] = useState<unknown>(null); const [previous, setPrevious] = useState(''); const [scanUrl, setScanUrl] = useState(''); const [source, setSource] = useState('upload');
  useEffect(() => {
    const controller = new AbortController();
    requestJson<Catalog>('/api/discovery', {signal: controller.signal}).then(result => {setCatalog(result); setSelected(current => current || result.jobs[0]?.id || "");}).catch(cause => {if (!controller.signal.aborted) setError(String(cause.message || cause));});
    return () => controller.abort();
  }, [refresh]);
  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const response = await requestJson<{job: Job; inventory: Inventory | null}>(`/api/discovery/${encodeURIComponent(selected)}`, {signal: controller.signal});
        if (controller.signal.aborted) return;
        setJob(response.job); setInventory(response.inventory);
        if (response.inventory) setResolution(JSON.stringify(response.inventory.selection || {}, null, 2));
        if (response.job.result?.confirmed_inventory_id) setConfirmed(true);
        if (!terminal.has(response.job.status)) timer = setTimeout(poll, 2000);
      } catch (cause) {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not refresh discovery.');}
    };
    void poll(); return () => {controller.abort(); clearTimeout(timer);};
  }, [selected, refresh]);
  const open = (id: string) => {setSelected(id); setJob(null); setInventory(null); setRoots([]); setAcknowledged(false); setConfirmed(false); setService(''); setNewService(''); setScanUrl(''); setComparison(null); setPrevious(''); setError('');};
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const body = new FormData(event.currentTarget);
    body.set('csrf_token', data.csrf_token || '');
    body.set('options', JSON.stringify({environment: body.get('environment') || '', values_files: String(body.get('values_files') || '').split('\n').map(value => value.trim()).filter(Boolean)}));
    if (body.get('reference_version')) {const options = JSON.parse(String(body.get('options'))); options.reference_version = String(body.get('reference_version')).trim(); body.set('options', JSON.stringify(options));} body.delete('reference_version');
    body.delete('environment'); body.delete('values_files'); setBusy(true); setError('');
    try {const result = await requestJson<{job_id: string}>('/api/discovery', {method: 'POST', body}); if (!result.job_id) throw new Error('Discovery did not return a job ID.'); open(result.job_id); setRefresh(value => value + 1);}
    catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not start discovery.');} finally {setBusy(false);}
  };
  const supplement = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const body = new FormData(event.currentTarget);
    body.set('csrf_token', data.csrf_token || '');
    try {
      const options: unknown = JSON.parse(resolution);
      if (!options || Array.isArray(options) || typeof options !== 'object') throw new Error('Settings must be a JSON object.');
      body.set('options', JSON.stringify(options));
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Invalid settings.'); return;}
    setBusy(true); setError('');
    try {
      const result = await requestJson<{job_id: string}>(`/api/discovery/${encodeURIComponent(selected)}/supplements`, {method: 'POST', body});
      if (!result.job_id) throw new Error('Discovery did not return a job ID.');
      open(result.job_id); setRefresh(value => value + 1);
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not supply dependencies.');}
    finally {setBusy(false);}
  };
  const action = async (name: string, payload: Record<string, unknown> = {}) => {
    setBusy(true); setError('');
    try {
      const result = await requestJson<{job_id?: string; url?: string}>(`/api/discovery/${encodeURIComponent(selected)}/${name}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csrf_token: data.csrf_token || '', ...payload})});
      if (name === 'confirm') setConfirmed(true);
      if (name === 'scan' && result.url) {const url = new URL(result.url, window.location.origin); if (url.origin === window.location.origin) setScanUrl(url.pathname + url.search);}
      if (name === 'retry' && result.job_id) open(result.job_id);
      setRefresh(value => value + 1);
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'The action could not be completed.');} finally {setBusy(false);}
  };
  let selectedValues: string[] = [];
  try { const paths = JSON.parse(resolution).values_files; selectedValues = Array.isArray(paths) ? paths.filter((path): path is string => typeof path === 'string') : []; } catch { /* Advanced editor may be incomplete. */ }
  const chooseValues = (paths: string[]) => {try {setResolution(JSON.stringify({...JSON.parse(resolution), values_files: paths}, null, 2));} catch {setError('Correct the advanced settings JSON first.');}};
  const needsAttention = Boolean(inventory && (isPartial(inventory.completeness) || !inventory.images.length));
  const partial = inventory ? isPartial(inventory.completeness) || inventory.roots.filter(root => roots.includes(root.id)).some(root => isPartial(root.completeness)) : false;
  const jobGroup = job?.group_id == null ? group : String(job.group_id);
  const services = catalog.services.filter(item => String(item.group_id) === jobGroup);
  return <div className="discovery-workspace"><section className="heading"><div><p className="eyebrow">DEPLOYMENT INTELLIGENCE</p><h1>Discovery</h1><p>Understand a deployment before you choose what to scan.</p></div></section>
    <section className="panel padded discovery-progress" aria-label="Discovery workflow"><StageProgress label="Discovery workflow" stages={[
      {key: 'discover', label: '1. Discover', state: !job ? 'pending' : job.status === 'failed' ? 'failed' : terminal.has(job.status) ? 'complete' : 'current', detail: job ? job.stage || job.status : 'Upload a source'},
      {key: 'review', label: '2. Review', state: confirmed ? 'complete' : inventory ? 'current' : 'pending', detail: inventory ? `${inventory.images.length} images found` : 'Inventory appears after discovery'},
      {key: 'confirm', label: '3. Confirm', state: confirmed ? 'complete' : 'pending', detail: confirmed ? 'Inventory recorded' : 'Associate with a service'},
      {key: 'scan', label: '4. Scan', state: scanUrl ? 'current' : 'pending', detail: scanUrl ? <a href={scanUrl}>View scan progress</a> : confirmed ? 'Ready to start' : 'Separate action after confirmation'},
    ]}/></section>
    <p className="discovery-intro">Upload a deployment, review its images, then choose what to scan. Discovery never runs repository scripts or deploys workloads.</p>
    {error && <div role="alert" className="notice notice-error">{error} <button type="button" className="secondary-button" onClick={() => {setError(''); setRefresh(value => value + 1);}}>Refresh</button></div>}
    <div className="discovery-layout"><aside><section className="panel"><h2>1. Discover a source</h2><form onSubmit={submit}>
      <label>Owning group<select name="group_id" value={group} required onChange={event => setGroup(event.target.value)}><option value="">Select a group</option>{catalog.groups.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label>Source type<select value={source} onChange={event => setSource(event.target.value)}><option value="upload">Upload files or archive</option><option value="reference">Remote reference</option></select></label>
      {source === 'upload' ? <label>Deployment input<input type="file" name="upload" required/></label> : <label>OCI image or chart reference<input name="reference" required placeholder="docker.io/library/nginx:1.27 or oci://…"/></label>}
      <details><summary>Configuration context (optional)</summary><label>Chart version (for a mirror reference)<input name="reference_version" placeholder="Exact mirrored version or digest"/></label><label>Environment<input name="environment" placeholder="e.g. staging"/></label><label>Values files, in override order<textarea name="values_files" rows={3} placeholder={'values.yaml\nvalues-staging.yaml'}/></label><p className="muted">Paths are relative to the input. Later values files override earlier files. Provide non-secret configuration only.</p></details>
      <p className="muted">Inspect repository archives, Helm charts, Kubernetes YAML, Kustomize and Compose definitions. Unsupported or incomplete content is reported for review.</p>
      <button disabled={busy || !catalog.groups.length}>{busy ? 'Working…' : 'Start discovery'}</button>
    </form></section></aside>
    <div><section className="panel"><h2>2. Review inventory</h2>{!selected ? <div className="discovery-empty"><h3>Start with the deployment, not just an image</h3><p>Discover roots, components and image references, then review their source evidence and any gaps before confirming a service inventory.</p></div> : <><p className="muted">Owning group: {catalog.groups.find(item => String(item.id) === jobGroup)?.name || jobGroup || 'Loading…'}</p><p className="discovery-status" role="status">{job ? job.status === 'completed' && needsAttention ? 'Needs attention - Review unresolved configuration' : `${job.status} · ${job.stage || 'Discovery'}` : 'Loading discovery…'}</p>{job && <>{!(job.status === 'completed' && needsAttention) && <progress aria-label="Discovery progress" max={100} value={Math.max(0, Math.min(100, job.progress || 0))}/>} {job.error && <p role="alert">{job.error}</p>}<div className="discovery-actions">{!terminal.has(job.status) && <button className="secondary-button" disabled={busy} onClick={() => void action('cancel')}>Cancel discovery</button>}{terminal.has(job.status) && <button className="secondary-button" disabled={busy} onClick={() => void action('retry')}>{job.status === 'completed' ? 'Rediscover as new version' : 'Retry discovery'}</button>}</div></>}
      {inventory && <><div className="discovery-metrics"><div><strong>{inventory.roots.length}</strong> Deployment roots</div><div><strong>{inventory.nodes.length}</strong> Components</div><div><strong>{inventory.images.length}</strong> Image references</div></div><p><strong>Completeness:</strong> {describe(inventory.completeness)}</p>
      {!inventory.roots.length && <p>No deployment roots were found. Review the diagnostics and try another input.</p>}
      <details className="discovery-resolution" open={Boolean(inventory.images.length === 0 || inventory.diagnostics?.some(item => item.code === "native_render_failed"))}><summary>Resolve configuration and rediscover</summary>{inventory.images.length === 0 && <p className="notice"><strong>No images were rendered.</strong> Review the chart errors and select configuration below before trying again. Retrying unchanged settings will usually produce the same result.</p>}{inventory.diagnostics?.filter(item => item.code === 'native_render_failed').map((item, index) => <div className="notice" key={index}><strong>Chart configuration needs attention</strong><p>{item.path}</p><p>{item.message}</p>{Boolean(item.value_paths?.length) && <><p>Values referenced by the chart validation (missing or invalid):</p><ul>{item.value_paths?.map(path => <li key={path}><code>{path}</code></li>)}</ul></>}<p>Choose configuration for your deployment. Repository examples are suggestions to review, not production defaults. Do not supply secret values.</p></div>)}
      <p className="discovery-config-help">Chart defaults are already loaded. Add overrides for your environment below; files apply in the order shown. Your previous inventory is preserved.</p><h3>Select values files</h3><label>Find configuration in this archive<input type="search" value={valuesSearch} onChange={event => setValuesSearch(event.target.value)} placeholder="Search by file name, environment or directory"/></label>
      <select aria-label="Add values file" value="" onChange={event => {if(event.target.value) chooseValues([...selectedValues, event.target.value]);}}><option value="">Choose a values file from the archive</option>{(inventory.candidate_values_files || []).filter(path => !selectedValues.includes(path) && path.toLowerCase().includes(valuesSearch.toLowerCase())).map(path => <option key={path} value={path}>{path}</option>)}</select>
      <p className="muted">{selectedValues.length ? `${selectedValues.length} override files selected, in application order` : 'Using chart defaults only. No additional values files selected.'}</p><ol className="discovery-values-order">{selectedValues.map((path, index) => <li key={path}><span className="discovery-values-path">{path}</span><span className="discovery-values-actions"><button className="secondary-button" type="button" disabled={index === 0} onClick={() => {const next = [...selectedValues]; [next[index - 1], next[index]] = [next[index], next[index - 1]]; chooseValues(next);}}>Move earlier</button> <button className="secondary-button" type="button" onClick={() => chooseValues(selectedValues.filter(item => item !== path))}>Remove</button></span></li>)}</ol>
      <button disabled={busy} onClick={() => {try {void action('retry', {options: JSON.parse(resolution)});} catch {setError('Correct the advanced settings JSON first.');}}}>Render with selected values</button><p className="muted">Select non-secret paths from this source. Supported settings: environment, ordered values_files, compose_files, profiles, chart_map and source_map. Each retry preserves the previous inventory. Administrators configure external artifacts in the worker mirror.</p>{Boolean(inventory.candidate_environments?.length) && <Evidence value={inventory.candidate_environments}/>}<details><summary>Advanced configuration</summary><label>Resolution settings<textarea rows={10} value={resolution} onChange={event => setResolution(event.target.value)}/></label><button disabled={busy} onClick={() => {try {const options: unknown = JSON.parse(resolution); if (!options || Array.isArray(options) || typeof options !== 'object') throw new Error('Settings must be a JSON object.'); void action('retry', {options});} catch (cause) {setError(cause instanceof Error ? cause.message : 'Invalid settings.');}}}>Resolve as new version</button></details></details>
      {inventory.roots.map(root => <article className="discovery-root" key={root.id}><label className="discovery-root-choice"><input type="checkbox" checked={roots.includes(root.id)} disabled={confirmed || busy} onChange={event => setRoots(previous => event.target.checked ? [...previous, root.id] : previous.filter(id => id !== root.id))}/><strong>{root.path || root.id}</strong><span className="badge">{root.technology}</span></label><p className="muted">{describe(root.completeness)}</p><details><summary>Components and source evidence</summary><ul>{inventory.nodes.filter(node => node.root_id === root.id).map(node => <li key={node.id}><strong>{node.name}</strong> · {node.kind} · {node.state || 'unknown'}<Evidence value={node.provenance}/></li>)}</ul></details><h4>Images</h4>{inventory.images.filter(image => image.root_id === root.id).map((image, index) => <div className="discovery-image" key={`${image.reference}-${index}`}><code>{image.reference}</code><Evidence value={image.provenance}/></div>)}</article>)}
      <details className="discovery-diagnostics" ><summary>Diagnostics ({inventory.diagnostics?.length || 0})</summary>{inventory.diagnostics?.length ? inventory.diagnostics.map((diagnostic, index) => <pre key={index}>{describe(diagnostic)}</pre>) : <p>No diagnostics reported.</p>}</details>
<details><summary>Supply missing files</summary><p className="muted">Add non-secret values, charts or dependency files to this discovery. Existing files are preserved. Use a new path and update the resolution settings above to select replacement configuration. The new version retains the earlier inventory and records the supplied artifact hash.</p><form onSubmit={supplement}><label>Missing files or archive<input type="file" name="upload" required disabled={busy}/></label><label>Destination directory<input name="target_path" defaultValue="dependencies" required placeholder="dependencies" disabled={busy}/><span className="muted">Relative to the original source root. Archive paths are preserved within this directory.</span></label><label className="discovery-root-choice"><input type="checkbox" name="acknowledge_non_secret" value="true" required disabled={busy}/>These files contain no passwords, tokens, private keys or other secrets.</label><p className="muted">Uses the resolution settings above. Unchanged supported renders can be reused when worker caching is enabled.</p><button disabled={busy || job?.status !== 'completed'}>Add files and resolve new version</button></form></details><details><summary>Compare immutable versions</summary><label>Previous discovery<select value={previous} onChange={event => {setPrevious(event.target.value); setComparison(null);}}><option value="">Choose a previous discovery</option>{catalog.jobs.filter(item => item.id !== selected && item.status === 'completed' && String(item.group_id) === jobGroup).map(item => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label><button className="secondary-button" disabled={!previous || busy} onClick={async () => {setBusy(true); try {setComparison(await requestJson(`/api/discovery/${encodeURIComponent(selected)}/compare/${encodeURIComponent(previous)}`));} catch (cause) {setError(cause instanceof Error ? cause.message : 'Comparison failed.');} finally {setBusy(false);}}}>Compare versions</button>{comparison !== null && <pre>{describe(comparison)}</pre>}<p className="muted">Added, removed and changed component IDs are reported. Rediscovery creates a new inventory and preserves earlier evidence.</p></details><details><summary>Complete inventory and relationships</summary><pre className="discovery-raw">{describe(inventory)}</pre></details></>}
      </>}</section>{inventory && <section className="panel"><h2>3. Confirm service inventory</h2><p className="muted">{['blocked', 'invalid'].includes(String(inventory.completeness)) ? 'This inventory cannot be confirmed. Resolve the diagnostics and rediscover.' : 'Choose a service in the owning group, or stage a new service when your role permits it.'}</p><p>Select deployment roots above and associate the reviewed inventory with a service. Confirmation records the inventory; scanning is a separate action.</p><label>Service<select value={service} disabled={confirmed || busy} onChange={event => setService(event.target.value)}><option value="">Select an existing service</option>{catalog.groups.find(item => String(item.id) === jobGroup)?.can_stage && <option value="new">Stage a new service</option>}{services.map(item => <option key={item.id} value={item.id}>{item.name} ({item.service_key})</option>)}</select></label>{service === 'new' && <label>New service key<input value={newService} maxLength={120} disabled={confirmed || busy} onChange={event => setNewService(event.target.value)} placeholder="A unique service key"/><span className="muted">Created in this discovery's owning group when you confirm.</span></label>}{partial && <label className="discovery-root-choice"><input type="checkbox" checked={acknowledged} disabled={confirmed || busy} onChange={event => setAcknowledged(event.target.checked)}/>I acknowledge this inventory is partial or unresolved and have reviewed its diagnostics.</label>}
      <button disabled={busy || confirmed || job?.status !== 'completed' || ['blocked', 'invalid'].includes(String(inventory.completeness)) || !service || (service === 'new' && !newService.trim()) || !roots.length || (partial && !acknowledged)} onClick={() => void action('confirm', {...(service === 'new' ? {new_service_key: newService.trim()} : {service_id: Number(service)}), root_ids: roots, acknowledge_partial: acknowledged})}>{confirmed ? 'Inventory confirmed' : 'Confirm inventory'}</button>
      {confirmed && <div className="discovery-scan"><h3>4. Scan confirmed inventory</h3><p>Start a scan only when you are ready to assess the confirmed image inventory.</p>{scanUrl ? <a href={scanUrl} className="secondary-button">View scan progress</a> : <button disabled={busy} onClick={() => void action('scan')}>Start scan</button>}</div>}</section>}</div></div></div>;
}
