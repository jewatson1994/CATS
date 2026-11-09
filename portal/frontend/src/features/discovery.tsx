import {useEffect, useRef, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';
import '../styles/discovery.css';
import {StageProgress} from '../components/ui';
import {DiscoveryTuning, type TuningInventory} from './discovery-tuning';
type Id = string | number;
interface GitLabSource {repository_url: string; requested_ref: string; commit_sha: string; ref_kind?: 'branch' | 'tag'}
interface GitLabRevision {name: string; kind?: string}
interface GitLabRefs {branches: string[]; tags: string[]; truncated: boolean}
interface Job {id: string; status: string; stage?: string; progress?: number; group_id?: Id; filename?: string; created_at?: string; cancel_requested?: boolean; error?: string; result?: {confirmed_inventory_id?: Id}; gitlab_source?: GitLabSource; options?: Record<string, unknown>; workspace_id?: string; previous_job_id?: string}
interface Root {id: string; path: string; chart_name?: string; chart_version?: string; technology: string; completeness?: unknown; state?: string; chart_type?: string}
interface Node {id: string; kind: string; name: string; root_id?: string; state?: string; provenance?: unknown}
interface Inventory extends TuningInventory {completeness?: unknown; images: {reference: string; root_id?: string; component_id?: string; provenance?: unknown}[]; gitlab_source?: GitLabSource; roots: Root[]; nodes: Node[]; metrics?: Record<string, unknown>; selection?: Record<string, unknown>; candidate_environments?: unknown[]}
interface Catalog {jobs: Job[]; services: {id: Id; name: string; service_key: string; group_id?: Id}[]; groups: {id: Id; name: string; can_stage?: boolean}[]}
interface ResolutionOptions extends Record<string, unknown> {values_files?: string[]; component_values?: Record<string, string[]>; component_overrides?: Record<string, string>}
const isRecord = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value));
function parseSettings(text: string): ResolutionOptions {
  let value: unknown;
  try {value = JSON.parse(text);} catch {throw new Error('Correct the advanced settings JSON before rendering.');}
  if (!isRecord(value)) throw new Error('Settings must be a JSON object.');
  const paths = (item: unknown): item is string[] => Array.isArray(item) && item.every(path => typeof path === 'string');
  if ('values_files' in value && !paths(value.values_files)) throw new Error('values_files must be a list of file paths.');
  if ('component_values' in value && (!isRecord(value.component_values) || !Object.values(value.component_values).every(paths))) throw new Error('component_values must map each resource to a list of file paths.');
  if ('component_overrides' in value && (!isRecord(value.component_overrides) || !Object.values(value.component_overrides).every(item => typeof item === 'string'))) throw new Error('component_overrides must map each resource to YAML text.');
  return value as ResolutionOptions;
}
const terminal = new Set(['complete', 'completed', 'failed', 'cancelled', 'succeeded']);
const runLabel = (job: Job) => [job.gitlab_source?.repository_url || job.filename, job.id].filter(Boolean).join(' · ');
const runStatus = (job: Job) => job.cancel_requested && !terminal.has(job.status) ? 'Cancellation requested' : [job.status, job.stage].filter(Boolean).join(' · ');
const describe = (value: unknown): string => value == null ? 'Unknown' : typeof value === 'string' ? value : JSON.stringify(value, null, 2);
export function isPartial(value: unknown): boolean {
  if (value === true || value === 'complete') return false;
  if (typeof value === 'object' && value !== null && 'status' in value) return isPartial((value as {status: unknown}).status);
  return true;
}
function Evidence({value}: {value: unknown}) {return value == null ? null : <details className="discovery-evidence"><summary>Source evidence</summary><pre>{describe(value)}</pre></details>;}
function ChartDefault({node}: {node: Node}) {
  const source = Array.isArray(node.provenance) ? node.provenance[0] : null;
  if (typeof source?.enabled !== 'boolean') return null;
  return <span className="badge">{source.enabled ? 'Enabled in source' : 'Disabled in source'}</span>;
}
function GitLabRevisionPicker({group, csrfToken, disabled, revision, choose}: {
  group: string; csrfToken: string; disabled: boolean; revision: GitLabRevision; choose: (revision: GitLabRevision) => void;
}) {
  const [refs, setRefs] = useState<GitLabRefs | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const lookup = useRef<AbortController | null>(null);
  useEffect(() => () => lookup.current?.abort(), []);
  const load = async (form: HTMLFormElement) => {
    const repository = form.elements.namedItem('repository_url') as HTMLInputElement;
    if (!repository.reportValidity()) return;
    const token = form.elements.namedItem('git_token') as HTMLInputElement;
    const controller = new AbortController();
    lookup.current?.abort(); lookup.current = controller;
    setLoading(true); setError(''); setRefs(null);
    try {
      const result = await requestJson<GitLabRefs>('/api/discovery/gitlab/refs', {
        method: 'POST', signal: controller.signal, headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({group_id: Number(group), csrf_token: csrfToken, repository_url: repository.value,
          git_token: token.value || undefined, search: revision.kind ? undefined : revision.name || undefined}),
      });
      if (!controller.signal.aborted) setRefs(result);
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load branches and tags.');
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  };
  return <>
    <label>Branch or tag (optional)<input name="git_ref" value={revision.name} placeholder="Default branch" onChange={event => choose({name: event.target.value})}/></label>
    {revision.kind && <input type="hidden" name="git_ref_kind" value={revision.kind}/>}
    <button type="button" className="secondary-button" disabled={disabled || loading || !group} onClick={event => void load(event.currentTarget.form!)}>
      {loading ? 'Loading branches and tags…' : 'Load branches and tags'}
    </button>
    {error && <p role="alert">{error}</p>}
    {refs && <>
      {refs.branches.length || refs.tags.length ? <label>Available branches and tags<select value={revision.kind ? revision.kind + '/' + revision.name : ''} onChange={event => {
        const option = event.currentTarget.selectedOptions[0];
        choose({name: option.label, kind: option.dataset.kind});
      }}>
        <option value="" disabled>Choose a branch or tag</option>
        <optgroup label="Branches">{refs.branches.map(name => <option key={name} value={'branch/' + name} data-kind="branch">{name}</option>)}</optgroup>
        <optgroup label="Tags">{refs.tags.map(name => <option key={name} value={'tag/' + name} data-kind="tag">{name}</option>)}</optgroup>
      </select></label> : <p className="muted">No matching branches or tags were found.</p>}
      {refs.truncated && <p className="muted">More results are available. Enter part of a name in the branch or tag field and load the list again.</p>}
    </>}
  </>;
}
export function Page({data}: {data: PageData}) {
  const [catalog, setCatalog] = useState<Catalog>({jobs: [], services: [], groups: []});
  const [ongoing, setOngoing] = useState<Job[] | null>(null);
  const [ongoingError, setOngoingError] = useState('');
  const [ongoingRefresh, setOngoingRefresh] = useState(0);
  const sourceForm = useRef<HTMLFormElement>(null);
  const [selected, setSelected] = useState(''); const [job, setJob] = useState<Job | null>(null);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [failedPassInventory, setFailedPassInventory] = useState<Inventory | null>(null);
  const [inventoryJobId, setInventoryJobId] = useState('');
  const loadedInventory = useRef('');
  const loadedSettings = useRef('');
  const pendingSettings = useRef('');
  const missingFiles = useRef<HTMLDetailsElement>(null);
  const [sourceExpanded, setSourceExpanded] = useState(true);
  const [acknowledgeNonSecret, setAcknowledgeNonSecret] = useState(false);
  const [resolution, setResolution] = useState('{}');
  const [newService, setNewService] = useState('');
  const [group, setGroup] = useState(''); const [service, setService] = useState('');
  const [roots, setRoots] = useState<string[]>([]); const [acknowledged, setAcknowledged] = useState(false);
  const [confirmed, setConfirmed] = useState(false); const [actionBusy, setActionBusy] = useState(false);
  const [submittingSource, setSubmittingSource] = useState('');
  const [gitRevision, setGitRevision] = useState<GitLabRevision>({name: ''});
  const [gitLookupVersion, setGitLookupVersion] = useState(0);
  const resetGitLookup = () => {
    setGitLookupVersion(value => value + 1);
    setGitRevision(current => current.kind ? {name: ''} : current);
  };
  const busy = actionBusy || Boolean(submittingSource);
  const [error, setError] = useState(''); const [refresh, setRefresh] = useState(0);
  const [comparison, setComparison] = useState<unknown>(null); const [previous, setPrevious] = useState(''); const [scanUrl, setScanUrl] = useState(''); const [source, setSource] = useState('upload');
  useEffect(() => {
    const controller = new AbortController();
    requestJson<Catalog>('/api/discovery', {signal: controller.signal}).then(result => {if (!controller.signal.aborted) setCatalog(result);}).catch(cause => {if (!controller.signal.aborted) setError(String(cause.message || cause));});
    return () => controller.abort();
  }, [refresh]);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const result = await requestJson<{jobs: Job[]}>('/api/discovery/ongoing', {signal: controller.signal});
        if (controller.signal.aborted) return;
        setOngoing(result.jobs); setOngoingError('');
        timer = setTimeout(poll, result.jobs.length ? 5000 : 30000);
      } catch (cause) {
        if (!controller.signal.aborted) setOngoingError(cause instanceof Error ? cause.message : 'Could not load ongoing discoveries.');
      }
    };
    void poll();
    return () => {controller.abort(); clearTimeout(timer);};
  }, [refresh, ongoingRefresh]);
  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const response = await requestJson<{job: Job; inventory: Inventory | null; previous_inventory?: Inventory; previous_inventory_job_id?: string}>(`/api/discovery/${encodeURIComponent(selected)}`, {signal: controller.signal});
        if (controller.signal.aborted) return;
        setJob(response.job);
        const savedOptions = response.job.options ?? response.inventory?.selection ?? response.previous_inventory?.selection;
        const finished = terminal.has(response.job.status);
        if (loadedSettings.current !== selected) {
          setResolution(JSON.stringify(savedOptions || {}, null, 2));
          loadedSettings.current = selected;
          if (!finished) pendingSettings.current = selected;
        } else if (pendingSettings.current === selected && finished && savedOptions) {
          setResolution(JSON.stringify(savedOptions, null, 2));
        }
        if (pendingSettings.current === selected && finished) pendingSettings.current = '';
        const invalidPass = response.inventory?.completeness === 'invalid';
        const retainPrevious = invalidPass && Boolean(response.previous_inventory || (loadedInventory.current && loadedInventory.current !== selected));
        setFailedPassInventory(retainPrevious ? response.inventory : null);
        const visibleInventory = retainPrevious ? response.previous_inventory : response.inventory || (!loadedInventory.current ? response.previous_inventory : null);
        const visibleJob = retainPrevious || !response.inventory ? response.previous_inventory_job_id : selected;
        if (visibleInventory && visibleJob && loadedInventory.current !== visibleJob) {
          setInventory(visibleInventory); setInventoryJobId(visibleJob); loadedInventory.current = visibleJob;
          setRoots(current => current.filter(id => visibleInventory.roots.some(root => root.id === id && root.state !== 'library' && root.chart_type !== 'library')));
          setSourceExpanded(false);
        }
        if (response.job.result?.confirmed_inventory_id) setConfirmed(true);
        if (!terminal.has(response.job.status)) timer = setTimeout(poll, 2000);
      } catch (cause) {if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not refresh discovery.');}
    };
    void poll(); return () => {controller.abort(); clearTimeout(timer);};
  }, [selected, refresh]);
  const open = (id: string) => {setSelected(id); setJob(null); setInventory(null); setFailedPassInventory(null); setInventoryJobId(''); loadedInventory.current = ''; loadedSettings.current = ''; pendingSettings.current = ''; setRoots([]); setAcknowledged(false); setAcknowledgeNonSecret(false); setConfirmed(false); setService(''); setNewService(''); setScanUrl(''); setComparison(null); setPrevious(''); setError(''); setResolution('{}');};
  const continuePass = (id: string) => {
    loadedSettings.current = id;
    pendingSettings.current = id;
    setSelected(id); setJob({id, status: 'queued', group_id: job?.group_id, filename: job?.filename, gitlab_source: job?.gitlab_source});
    setFailedPassInventory(null); setConfirmed(false); setAcknowledged(false); setScanUrl(''); setComparison(null); setPrevious(selected);
  };
  const startFresh = () => {
    open(''); setSourceExpanded(true); sourceForm.current?.reset(); setGroup(''); setSource('upload'); setGitRevision({name: ''});
    setTimeout(() => sourceForm.current?.querySelector('select')?.focus(), 0);
  };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const body = new FormData(event.currentTarget);
    const tokenInput = event.currentTarget.elements.namedItem('git_token');
    if (tokenInput instanceof HTMLInputElement) {
      tokenInput.value = '';
      setGitLookupVersion(value => value + 1);
    }
    body.set('csrf_token', data.csrf_token || '');
    body.set('options', JSON.stringify({environment: body.get('environment') || '', values_files: String(body.get('values_files') || '').split('\n').map(value => value.trim()).filter(Boolean)}));
    if (body.get('reference_version')) {const options = JSON.parse(String(body.get('options'))); options.reference_version = String(body.get('reference_version')).trim(); body.set('options', JSON.stringify(options));} body.delete('reference_version');
    body.delete('environment'); body.delete('values_files'); setSubmittingSource(source); setError('');
    try {const result = await requestJson<{job_id: string}>('/api/discovery', {method: 'POST', body}); if (!result.job_id) throw new Error('Discovery did not return a job ID.'); open(result.job_id); setRefresh(value => value + 1);}
    catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not start discovery.');} finally {setSubmittingSource('');}
  };
  const supplement = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const body = new FormData(event.currentTarget);
    body.set('csrf_token', data.csrf_token || '');
    try {
      const options = validatedOptions();
      body.set('options', JSON.stringify(options));
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Invalid settings.'); return;}
    setActionBusy(true); setError('');
    try {
      const result = await requestJson<{job_id: string}>(`/api/discovery/${encodeURIComponent(selected)}/supplements`, {method: 'POST', body});
      if (!result.job_id) throw new Error('Discovery did not return a job ID.');
      continuePass(result.job_id); setRefresh(value => value + 1);
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not supply dependencies.');}
    finally {setActionBusy(false);}
  };
  const action = async (name: string, payload: Record<string, unknown> = {}, target = selected) => {
    setActionBusy(true); setError('');
    try {
      const result = await requestJson<{job_id?: string; job?: Job; url?: string}>(`/api/discovery/${encodeURIComponent(target)}/${name}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({csrf_token: data.csrf_token || '', ...payload})});
      if (name === 'cancel' && result.job) {
        const updated = result.job;
        if (updated.id === selected) setJob(updated);
        setOngoing(current => current?.map(item => item.id === updated.id ? updated : item).filter(item => !terminal.has(item.status)) ?? null);
      }
      if (name === 'confirm') setConfirmed(true);
      if (name === 'scan' && result.url) {const url = new URL(result.url, window.location.origin); if (url.origin === window.location.origin) setScanUrl(url.pathname + url.search);}
      if (name === 'retry') {
        if (!result.job_id) throw new Error('Discovery did not return a job ID. Your settings and previous results are preserved.');
        continuePass(result.job_id);
      }
      if (target === selected) setRefresh(value => value + 1);
      else setOngoingRefresh(value => value + 1);
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'The action could not be completed.');} finally {setActionBusy(false);}
  };
  let settings: ResolutionOptions = {};
  try {settings = parseSettings(resolution);} catch { /* Preserve incomplete or invalid advanced edits without breaking resource controls. */ }
  const selectedValues = settings.values_files || [];
  const componentValues = settings.component_values || {};
  const componentOverrides = settings.component_overrides || {};
  const chooseValues = (paths: string[]) => {try {setResolution(JSON.stringify({...parseSettings(resolution), values_files: paths}, null, 2));} catch {setError('Correct the advanced settings JSON first.');}};
  const chooseComponentValues = (id: string, paths: string[]) => {try {const options = parseSettings(resolution); setResolution(JSON.stringify({...options, component_values: {...options.component_values, [id]: paths}}, null, 2));} catch {setError('Correct the advanced settings JSON first.');}};
  const chooseComponentOverride = (id: string, yaml: string) => {try {const options = parseSettings(resolution); setResolution(JSON.stringify({...options, component_overrides: {...options.component_overrides, [id]: yaml}}, null, 2)); setAcknowledgeNonSecret(false);} catch {setError('Correct the advanced settings JSON first.');}};
  const validatedOptions = () => {
    const options = parseSettings(resolution);
    if (Object.values(options.component_overrides || {}).some(value => value.trim()) && !acknowledgeNonSecret) throw new Error('Confirm that the configuration overrides contain no secrets before rendering.');
    return options;
  };
  const renderChanges = () => {
    try {
      const options = validatedOptions();
      void action('retry', {options, ...(acknowledgeNonSecret ? {acknowledge_non_secret: true} : {})});
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Invalid settings.');}
  };
  const rendering = Boolean(job && !terminal.has(job.status));
  const currentInventory = Boolean(inventory && inventoryJobId === selected);
  const needsAttention = Boolean(inventory && isPartial(inventory.completeness));
  const partial = inventory ? isPartial(inventory.completeness) || inventory.roots.filter(root => roots.includes(root.id)).some(root => isPartial(root.completeness)) : false;
  const jobGroup = job?.group_id == null ? group : String(job.group_id);
  const gitlabSource = inventory?.gitlab_source || job?.gitlab_source;
  const services = catalog.services.filter(item => String(item.group_id) === jobGroup);
  return <div className="discovery-workspace"><section className="heading"><div><p className="eyebrow">DEPLOYMENT INTELLIGENCE</p><h1>Discovery</h1><p>Understand a deployment before you choose what to scan.</p></div></section>
    <section className="panel padded discovery-progress" aria-label="Discovery workflow"><StageProgress label="Discovery workflow" stages={[
      {key: 'discover', label: '1. Discover', state: !job ? 'pending' : job.status === 'failed' ? 'failed' : job.status === 'cancelled' ? 'skipped' : terminal.has(job.status) ? 'complete' : 'current', detail: job ? job.stage || job.status : 'Choose a source'},
      {key: 'review', label: '2. Render and tune', state: confirmed ? 'complete' : inventory ? 'current' : 'pending', detail: inventory ? `${inventory.images.length} images found` : 'Inventory appears after discovery'},
      {key: 'confirm', label: '3. Confirm', state: confirmed ? 'complete' : 'pending', detail: confirmed ? 'Inventory recorded' : 'Associate with a service'},
      {key: 'scan', label: '4. Scan', state: scanUrl ? 'current' : 'pending', detail: scanUrl ? <a href={scanUrl}>View scan progress</a> : confirmed ? 'Ready to start' : 'Separate action after confirmation'},
    ]}/></section>
    <p className="discovery-intro">Choose a deployment source, review its images, then choose what to scan. Discovery never runs repository scripts or deploys workloads.</p>
    {error && <div role="alert" className="notice notice-error">{error} <button type="button" className="secondary-button" onClick={() => {setError(''); setRefresh(value => value + 1);}}>Refresh</button></div>}
    <section className="panel discovery-runs" aria-label="Discovery runs">
      <div className="discovery-runs-header"><h2>Ongoing discoveries</h2>
        {catalog.jobs.length > 0 && <label>Recent discoveries<select value="" disabled={busy} onChange={event => open(event.target.value)}>
          <option value="" disabled>Open a recent run</option>
          {catalog.jobs.map(item => <option key={item.id} value={item.id} disabled={item.id === selected}>{runLabel(item)}</option>)}
        </select></label>}
      </div>
      {ongoingError ? <p role="alert">{ongoingError} <button className="secondary-button" onClick={() => setOngoingRefresh(value => value + 1)}>Reload ongoing discoveries</button></p> :
        !ongoing ? <p>Loading ongoing discoveries…</p> : !ongoing.length ? <p className="muted">No discoveries are currently queued or running.</p> :
        <ul className="discovery-runs-list">{ongoing.map(item => <li key={item.id}>
          <div><strong>{runLabel(item)}</strong><small>{[catalog.groups.find(owner => String(owner.id) === String(item.group_id))?.name, item.created_at && new Date(item.created_at).toLocaleString(), runStatus(item)].filter(Boolean).join(' · ')}</small></div>
          <div className="discovery-run-actions"><button className="secondary-button" disabled={busy || item.id === selected} aria-label={`Open discovery ${runLabel(item)}`} onClick={() => open(item.id)}>{item.id === selected ? 'Open in review' : 'Open'}</button>
            <button className="secondary-button" disabled={busy || item.cancel_requested} aria-label={`Cancel discovery ${runLabel(item)}`} onClick={() => void action('cancel', {}, item.id)}>Cancel</button></div>
        </li>)}</ul>}
    </section>
    <div className="discovery-layout"><aside><details className="panel discovery-source" open={sourceExpanded} onToggle={event => setSourceExpanded(event.currentTarget.open)}><summary>1. Discover a source</summary><form ref={sourceForm} onSubmit={submit}>
      <label>Owning group<select name="group_id" value={group} required onChange={event => {setGroup(event.target.value); resetGitLookup();}}><option value="">Select a group</option>{catalog.groups.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label>Source type<select value={source} onChange={event => {setSource(event.target.value); setGitRevision({name: ''});}}><option value="upload">Upload files or archive</option><option value="reference">Remote reference</option><option value="gitlab">GitLab repository</option></select></label>
      {source === 'upload' && <label>Deployment input<input type="file" name="upload" required/></label>}
      {source === 'reference' && <label>OCI image or chart reference<input name="reference" required placeholder="docker.io/library/nginx:1.27 or oci://…"/></label>}
      {source === 'gitlab' && <>
        <input type="hidden" name="input_kind" value="gitlab"/>
        <label>GitLab repository URL<input type="url" name="repository_url" required placeholder="https://gitlab.example.com/team/project" onChange={resetGitLookup}/></label>
        <label>Access token (optional)<input type="password" name="git_token" autoComplete="off" aria-describedby="gitlab-token-help" onChange={resetGitLookup}/></label>
        <p id="gitlab-token-help" className="muted">For a private project, supply a read-only GitLab token with the <code>read_api</code> scope. Discovery uses it to list revisions and fetch this submission.</p>
        <GitLabRevisionPicker key={gitLookupVersion} group={group} csrfToken={data.csrf_token || ''} disabled={busy} revision={gitRevision} choose={setGitRevision}/>
        <p className="muted">Use an approved GitLab instance or project. Discovery downloads the selected revision when you start. For offline discovery, upload a repository archive.</p>
        <label className="discovery-root-choice"><input type="checkbox" name="acknowledge_non_secret" value="true" required/>I confirm the repository files contain no passwords, tokens, private keys or other secrets.</label>
      </>}
      <details><summary>Configuration context (optional)</summary>{source !== 'gitlab' && <label>Chart version (for a mirror reference)<input name="reference_version" placeholder="Exact mirrored version or digest"/></label>}<label>Environment<input name="environment" placeholder="e.g. staging"/></label><label>Values files, in override order<textarea name="values_files" rows={3} placeholder={'values.yaml\nvalues-staging.yaml'}/></label><p className="muted">Paths are relative to the input. Later values files override earlier files. Provide non-secret configuration only.</p></details>
      <p className="muted">Inspect repository archives, Helm charts, Kubernetes YAML, Kustomize and Compose definitions. Unsupported or incomplete content is reported for review.</p>
      <button disabled={busy || !catalog.groups.length}>{submittingSource === 'gitlab' ? 'Fetching repository…' : busy ? 'Working…' : 'Start discovery'}</button>
    </form></details></aside>
    <div><section className="panel"><h2>2. Render and tune</h2>{!selected ? <div className="discovery-empty"><h3>No discovery selected</h3><p>Start a discovery or open a run above to review its progress and inventory.</p></div> : <>
      <div className="discovery-review-header"><p><strong>{job ? runLabel(job) : selected}</strong><br/><span className="muted">Owning group: {catalog.groups.find(item => String(item.id) === jobGroup)?.name || jobGroup || 'Loading…'}</span></p>
        <button className="secondary-button" disabled={busy} onClick={startFresh}>New discovery</button></div>
      <p className="discovery-status" role="status">{job ? job.status === 'completed' && needsAttention ? 'Needs attention - Review unresolved configuration' : runStatus(job) : 'Loading discovery…'}</p>
      {job && <>{!(job.status === 'completed' && needsAttention) && <progress aria-label="Discovery progress" max={100} value={Math.max(0, Math.min(100, job.progress || 0))}/>} {job.error && <p role="alert">{job.error}</p>}
        <div className="discovery-actions">{!terminal.has(job.status) && <button className="secondary-button" disabled={busy || job.cancel_requested} onClick={() => void action('cancel')}>Cancel discovery</button>}{terminal.has(job.status) && !inventory && <button className="secondary-button" disabled={busy} onClick={() => void action('retry')}>{job.status === 'completed' ? 'Rediscover as new version' : 'Retry discovery'}</button>}</div></>}
      {gitlabSource && <div className="discovery-image"><h3>GitLab source</h3><p><code>{gitlabSource.repository_url}</code></p>
        <p>{gitlabSource.ref_kind === 'tag' ? 'Tag ' : gitlabSource.ref_kind === 'branch' ? 'Branch ' : ''}<code>{gitlabSource.requested_ref || 'Default branch'}</code></p>
        <p>Resolved commit <code>{gitlabSource.commit_sha}</code></p></div>}
      {inventory && <><div className="discovery-metrics"><div><strong>{inventory.roots.length}</strong> Deployment roots</div><div><strong>{inventory.nodes.length}</strong> Components</div><div><strong>{inventory.images.length}</strong> Image references</div></div><p><strong>Completeness:</strong> {describe(inventory.completeness)}</p>
      {!inventory.roots.length && <p>No deployment roots were found. Review the diagnostics and try another input.</p>}
      {!currentInventory && <p className="notice" role="status">{rendering ? 'Rendering your changes. Previous results stay visible until this pass finishes.' : 'This pass did not produce a new inventory. Your previous results and tuning settings are preserved; correct the issue and render again.'}</p>}
      {failedPassInventory && <details className="discovery-diagnostics notice notice-error" open><summary>Latest render errors ({failedPassInventory.diagnostics?.length || 0})</summary><p>These errors are from your latest attempt. The inventory below is from the last usable render.</p>{failedPassInventory.diagnostics?.map((diagnostic, index) => <pre key={index}>{describe(diagnostic)}</pre>)}</details>}
      <DiscoveryTuning inventory={inventory} selectedValues={selectedValues} componentValues={componentValues}
        componentOverrides={componentOverrides} acknowledgeNonSecret={acknowledgeNonSecret} busy={busy || rendering}
        onValuesChange={chooseValues} onComponentValuesChange={chooseComponentValues} onComponentOverrideChange={chooseComponentOverride}
        onAcknowledgeNonSecret={setAcknowledgeNonSecret} onRender={renderChanges} onSupplyFiles={() => {
          if (missingFiles.current) {missingFiles.current.open = true; missingFiles.current.scrollIntoView?.({behavior: 'smooth', block: 'center'}); missingFiles.current.querySelector('input')?.focus();}
        }}/>
      <details><summary>Advanced configuration</summary><p className="muted">Settings are retained between renders. Later values files override earlier files. External artifacts must be available in the worker mirror.</p>
        {Boolean(inventory.candidate_environments?.length) && <Evidence value={inventory.candidate_environments}/>}
        <label>Resolution settings<textarea rows={10} value={resolution} disabled={busy || rendering} onChange={event => {setResolution(event.target.value); setAcknowledgeNonSecret(false);}}/></label>
      </details>
      <details className="discovery-inventory"><summary>Review discovered inventory and select deployment roots ({inventory.roots.length})</summary>
      {inventory.roots.map(root => <article className="discovery-root" key={root.id}><label className="discovery-root-choice"><input type="checkbox" checked={roots.includes(root.id)} disabled={confirmed || busy || root.state === 'library' || root.chart_type === 'library'} onChange={event => setRoots(previous => event.target.checked ? [...previous, root.id] : previous.filter(id => id !== root.id))}/>{root.chart_name
          ? <><strong>{root.chart_name}{root.chart_version && ` ${root.chart_version}`}</strong><span>{root.path || root.id}</span></>
          : <strong>{root.path || root.id}</strong>}<span className="badge">{root.technology}</span></label><p className="muted">{root.state === 'library' || root.chart_type === 'library' ? 'Library · evidence only' : describe(root.completeness)}</p><details><summary>Components and source evidence</summary><ul>{inventory.nodes.filter(node => node.root_id === root.id).map(node => <li key={node.id}><strong>{node.name}</strong> · {node.kind} · {node.state || 'unknown'} <ChartDefault node={node}/><Evidence value={node.provenance}/></li>)}</ul></details><h4>Images</h4>{inventory.images.filter(image => image.root_id === root.id).map((image, index) => <div className="discovery-image" key={`${image.reference}-${index}`}><code>{image.reference}</code><Evidence value={image.provenance}/></div>)}</article>)}
      </details>
      <details className="discovery-diagnostics" ><summary>Diagnostics ({inventory.diagnostics?.length || 0})</summary>{inventory.diagnostics?.length ? inventory.diagnostics.map((diagnostic, index) => <pre key={index}>{describe(diagnostic)}</pre>) : <p>No diagnostics reported.</p>}</details>
<details ref={missingFiles}><summary>Supply missing files</summary><p className="muted">Add non-secret values, charts or dependency files to this discovery. Existing files are preserved. Use a new path and update the resolution settings above to select replacement configuration. The new version retains the earlier inventory and records the supplied artifact hash.</p><form onSubmit={supplement}><label>Missing files or archive<input type="file" name="upload" required disabled={busy}/></label><label>Destination directory<input name="target_path" defaultValue="dependencies" required placeholder="dependencies" disabled={busy}/><span className="muted">Relative to the original source root. Archive paths are preserved within this directory.</span></label><label className="discovery-root-choice"><input type="checkbox" name="acknowledge_non_secret" value="true" required disabled={busy}/>These files contain no passwords, tokens, private keys or other secrets.</label><p className="muted">Keeps your tuning settings and previous results. Successful unchanged renders are reused when caching is available.</p><button disabled={busy || rendering}>Add files and render again</button></form></details><details><summary>Compare immutable versions</summary><label>Previous discovery<select value={previous} onChange={event => {setPrevious(event.target.value); setComparison(null);}}><option value="">Choose a previous discovery</option>{catalog.jobs.filter(item => item.id !== selected && item.status === 'completed' && String(item.group_id) === jobGroup).map(item => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label><button className="secondary-button" disabled={!previous || busy} onClick={async () => {setActionBusy(true); try {setComparison(await requestJson(`/api/discovery/${encodeURIComponent(selected)}/compare/${encodeURIComponent(previous)}`));} catch (cause) {setError(cause instanceof Error ? cause.message : 'Comparison failed.');} finally {setActionBusy(false);}}}>Compare versions</button>{comparison !== null && <pre>{describe(comparison)}</pre>}<p className="muted">Added, removed and changed component IDs are reported. Rediscovery creates a new inventory and preserves earlier evidence.</p></details><details><summary>Complete inventory and relationships</summary><pre className="discovery-raw">{describe(inventory)}</pre></details></>}
      </>}</section>{inventory && <section className="panel"><h2>3. Confirm service inventory</h2><p className="muted">{['blocked', 'invalid'].includes(String(inventory.completeness)) ? 'This inventory cannot be confirmed. Resolve the diagnostics and rediscover.' : 'Choose a service in the owning group, or stage a new service when your role permits it.'}</p><p>Select deployment roots above and associate the reviewed inventory with a service. Confirmation records the inventory; scanning is a separate action.</p><label>Service<select value={service} disabled={confirmed || busy} onChange={event => setService(event.target.value)}><option value="">Select an existing service</option>{catalog.groups.find(item => String(item.id) === jobGroup)?.can_stage && <option value="new">Stage a new service</option>}{services.map(item => <option key={item.id} value={item.id}>{item.name} ({item.service_key})</option>)}</select></label>{service === 'new' && <label>New service key<input value={newService} maxLength={120} disabled={confirmed || busy} onChange={event => setNewService(event.target.value)} placeholder="A unique service key"/><span className="muted">Created in this discovery's owning group when you confirm.</span></label>}{partial && <label className="discovery-root-choice"><input type="checkbox" checked={acknowledged} disabled={confirmed || busy} onChange={event => setAcknowledged(event.target.checked)}/>I acknowledge this inventory is partial or unresolved and have reviewed its diagnostics.</label>}
      <button disabled={busy || confirmed || !currentInventory || job?.status !== 'completed' || ['blocked', 'invalid'].includes(String(inventory.completeness)) || !service || (service === 'new' && !newService.trim()) || !roots.length || (partial && !acknowledged)} onClick={() => void action('confirm', {...(service === 'new' ? {new_service_key: newService.trim()} : {service_id: Number(service)}), root_ids: roots, acknowledge_partial: acknowledged})}>{confirmed ? 'Inventory confirmed' : 'Confirm inventory'}</button>
      {confirmed && <div className="discovery-scan"><h3>4. Scan confirmed inventory</h3><p>Start a scan only when you are ready to assess the confirmed image inventory.</p>{scanUrl ? <a href={scanUrl} className="secondary-button">View scan progress</a> : <button disabled={busy} onClick={() => void action('scan')}>Start scan</button>}</div>}</section>}</div></div></div>;
}
