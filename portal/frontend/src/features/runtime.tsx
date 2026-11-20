import {useEffect, useState, type FormEvent} from 'react';
import {ApiError, requestJson, type PageData} from '../api';
import {PageHeader, StatusBadge, type Tone} from '../components/ui';
import {visibleTimeout} from '../hooks/visibleTimer';
import {RuntimeIssues, ScanCompliance, issueReason, type IssueFilters, type RuntimeCompliance, type RuntimeIssue} from './RuntimeIssues';
import './runtime.css';

type Environment = {id: number; name: string; kind: 'kubernetes' | 'docker'; service_ids: number[]; service_scope?: 'all' | 'selected'; created_at: string; can_manage?: boolean};
type Coverage = 'never_reported' | 'fresh' | 'stale' | 'incomplete' | 'revoked';
type DisplayCoverage = Coverage | 'checking' | 'unchecked';
type Agent = {id: string; environment_id: number; name: string; source_id: string; version: string; enabled: boolean;
  last_seen_at: string | null; observed_at: string | null; inventory_observed_at?: string | null; complete: boolean;
  errors: string[]; coverage: Coverage; workload_count: number};
type Workload = {pod?: string; workload_kind?: string; container_kind?: string; agent_id: string; environment_id: number; uid: string; namespace: string; workload: string; container: string;
  node: string; image_ref: string; image_id: string; state: string; chart_name: string; chart_version: string; helm_release: string; observed_at?: string | null;
  compliance: RuntimeCompliance};
export type RuntimeOverview = {environments: Environment[]; agents: Agent[]; workloads: Workload[]; services: {id: number; name: string}[];
  permissions: {manage: boolean}; inventory_truncated?: boolean; total_workloads?: number; next_offset?: number | null; total_issues?: number; next_issue_offset?: number | null; issues?: RuntimeIssue[];
  namespaces?: {environment_id: number; name: string; workload_count: number; issue_count: number}[];
  clusters?: {id: number; coverage: Coverage | 'unlinked'; workload_count: number; agent_count: number; namespace_count: number; issue_count: number; inventory_truncated?: boolean}[]};
type LinkingKey = {linking_key: string; expires_at: string; environment_id: number};
const coverageLabels: Record<DisplayCoverage, string> = {never_reported: 'Never reported', fresh: 'Fresh report', stale: 'Stale report', incomplete: 'Incomplete report', revoked: 'Revoked', checking: 'Checking coverage', unchecked: 'Coverage unchecked'};
const coverageTones: Record<DisplayCoverage, Tone> = {never_reported: 'neutral', fresh: 'info', stale: 'warning', incomplete: 'warning', revoked: 'neutral', checking: 'neutral', unchecked: 'warning'};
const STALE_MS = 5 * 60 * 1000;
const PAGE_SIZE = 200;
const OVERVIEW_URL = `/api/runtime?limit=${PAGE_SIZE}&issue_limit=${PAGE_SIZE}`;
const complianceLabels: Record<Workload['compliance']['status'], string> = {approved: 'Approved', excepted: 'Excepted', noncompliant: 'Noncompliant', unverified: 'Unverified'};
const dateText = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : 'Not reported';
const errorText = (error: unknown) => error instanceof Error ? error.message : 'The request could not be completed.';

function EnvironmentForm({environment, services, busy, save, cancel}: {
  environment?: Environment; services: RuntimeOverview['services']; busy: boolean;
  save: (value: {name: string; kind: Environment['kind']; service_scope: 'all' | 'selected'; service_ids: number[]}) => Promise<void>; cancel: () => void;
}) {
  const [name, setName] = useState(environment?.name || '');
  const [kind, setKind] = useState<Environment['kind']>(environment?.kind || 'kubernetes');
  const [scope, setScope] = useState<'all' | 'selected'>(environment ? environment.service_scope || 'selected' : 'all');
  const [serviceIds, setServiceIds] = useState<number[]>(environment?.service_ids || []);
  function submit(event: FormEvent<HTMLFormElement>) {event.preventDefault(); if (name.trim() && (scope === 'all' || serviceIds.length) && !busy) void save({name: name.trim(), kind, service_scope: scope, service_ids: scope === 'all' ? [] : serviceIds});}
  return <section className="panel padded runtime-form" aria-label={environment ? 'Edit environment' : 'New environment'}>
    <h2>{environment ? 'Edit environment' : 'New environment'}</h2>
    <form onSubmit={submit}>
      <label>Environment name<input required maxLength={160} placeholder="Core Cluster 01" value={name} onChange={event => setName(event.target.value)}/></label>
      <p className="muted">Choose a stable name your team recognizes. The agent reports its source identity separately.</p>
      <label>Runtime type<select value={kind} disabled={!!environment || busy} onChange={event => setKind(event.target.value as Environment['kind'])}>
        <option value="kubernetes">Kubernetes</option><option value="docker">Docker</option>
      </select></label>
      <fieldset disabled={busy}><legend>Services in approval scope</legend>
        <label>Approval scope<select value={scope} onChange={event => setScope(event.target.value as 'all' | 'selected')}>
          <option value="all">All active CATS services</option><option value="selected">Selected services</option></select></label>
        {scope === 'all' ? <p>New active services are included automatically.</p> : <>
        {services.length ? <div className="runtime-services">{services.map(service => <label key={service.id}>
          <input type="checkbox" checked={serviceIds.includes(service.id)} onChange={event => setServiceIds(previous => event.target.checked ? [...previous, service.id] : previous.filter(id => id !== service.id))}/>{service.name}
        </label>)}</div> : <p>No services are available to select.</p>}
        {!serviceIds.length && <p className="runtime-notice">Select at least one CATS service.</p>}</>}
      </fieldset>
      <div className="runtime-actions"><button disabled={busy || !name.trim() || (scope === 'selected' && !serviceIds.length)}>{busy ? 'Saving…' : environment ? 'Save environment' : 'Create environment'}</button>
        <button type="button" className="secondary-button" disabled={busy} onClick={cancel}>Cancel</button></div>
    </form>
  </section>;
}

function LinkingInstructions({token, environment, close}: {token: LinkingKey; environment: Environment; close: () => void}) {
  const [copyMessage, setCopyMessage] = useState('');
  useEffect(() => {
    const remaining = new Date(token.expires_at).getTime() - Date.now();
    const timer = window.setTimeout(close, Math.max(0, Math.min(remaining, 2147483647)));
    return () => window.clearTimeout(timer);
  }, [token.expires_at, close]);
  async function copy() {
    try {await navigator.clipboard.writeText(token.linking_key); setCopyMessage('Linking key copied.');}
    catch {setCopyMessage('Select and copy the linking key below.');}
  }
  return <section className="panel padded runtime-linking" aria-label="Link an agent">
    <h3>Link an agent to {environment.name}</h3>
    <p>Copy this one-use key before closing this panel. It expires <strong>{dateText(token.expires_at)}</strong>. Issuing another key for this environment replaces this key.</p>
    <label>Linking key<textarea readOnly autoComplete="off" spellCheck={false} value={token.linking_key}/></label>
    <div className="runtime-actions"><button type="button" onClick={() => void copy()}>Copy linking key</button><button type="button" className="secondary-button" onClick={close}>Close linking key</button></div>
    {copyMessage && <p role="status">{copyMessage}</p>}
    {environment.kind === 'kubernetes' ? <>
      <h4>Install the Kubernetes agent</h4>
      <p>Save the key in a private file named <code>linking-key</code>. Set <code>CATS_URL</code> to the portal HTTPS address reachable from the cluster, then run this command with the packaged chart.</p>
      <pre><code>{['helm upgrade --install cats-runtime ./cats-runtime-0.1.0.tgz', '  --namespace cats-runtime --create-namespace',
        '  --set-string catsUrl="$CATS_URL"', '  --set-file linkingKey=./linking-key'].join(' \\\n')}</code></pre>
      <p>For a published chart, replace the chart file with <code>oci://ghcr.io/jewatson1994/charts/cats-runtime --version 0.1.0</code>.</p>
      <p>To keep the key out of Helm release history, provision a Secret in the release namespace with the field <code>linking-key</code> and replace the last flag with <code>--set-string linkingKeySecret=SECRET_NAME</code>. For private portal certificates, set <code>caSecret</code> to a Secret containing <code>ca.crt</code>.</p>
    </> : <p>On the Docker host, follow the systemd install in <code>runtime-agent/README.md</code> with the portal HTTPS address and this linking key.</p>}
    <p className="muted">After installation, the agent and its first report appear under this environment.</p>
  </section>;
}

export function Page({data}: {data: PageData}) {
  const [overview, setOverview] = useState<RuntimeOverview | null>(null);
  const [tab, setTab] = useState<'clusters' | 'agents' | 'issues'>('clusters');
  const [issueFilters, setIssueFilters] = useState<IssueFilters>({environmentId: null, namespace: '', code: ''});
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [refresh, setRefresh] = useState(0), [loading, setLoading] = useState(true), [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState(''), [actionError, setActionError] = useState(''), [message, setMessage] = useState('');
  const [form, setForm] = useState<'new' | 'edit' | null>(null);
  const [linkingKey, setLinkingKey] = useState<LinkingKey | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [refreshedAt, setRefreshedAt] = useState<string | null>(null);
  const [clock, setClock] = useState(Date.now);
  useEffect(() => {
    const controller = new AbortController();
    let cancelNext: (() => void) | undefined;
    async function load() {
      setLoading(true);
      try {
        const result = await requestJson<RuntimeOverview>(OVERVIEW_URL, {signal: controller.signal});
        if (!controller.signal.aborted) {
          setOverview(result); setLoadError(''); setClock(Date.now()); setRefreshedAt(new Date().toISOString());
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          setLoadError(errorText(error));
          if (error instanceof ApiError && [401, 403].includes(error.status)) {setOverview(null); setLinkingKey(null); setForm(null);}
        }
      }
      finally {
        if (!controller.signal.aborted) {
          setLoading(false);
          cancelNext = visibleTimeout(() => void load(), 30000);
        }
      }
    }
    void load();
    return () => {controller.abort(); cancelNext?.();};
  }, [refresh]);
  useEffect(() => {
    const deadlines = (overview?.agents || []).filter(agent => agent.coverage === 'fresh')
      .flatMap(agent => [agent.last_seen_at, agent.observed_at].map(value => Date.parse(value || '') + STALE_MS + 1))
      .filter(value => Number.isFinite(value) && value > clock);
    if (!deadlines.length) return;
    const timer = window.setTimeout(() => setClock(Date.now()), Math.max(0, Math.min(...deadlines) - Date.now()));
    return () => window.clearTimeout(timer);
  }, [overview, clock]);
  useEffect(() => {
    const visible = () => {if (document.visibilityState !== 'hidden') setClock(Date.now());};
    document.addEventListener('visibilitychange', visible);
    return () => document.removeEventListener('visibilitychange', visible);
  }, []);
  function displayCoverage(agent: Agent): DisplayCoverage {
    if (agent.coverage !== 'fresh') return agent.coverage;
    if ([agent.last_seen_at, agent.observed_at].some(value => !value || !Number.isFinite(Date.parse(value)) || clock - Date.parse(value) > STALE_MS)) return 'stale';
    if (loadError) return 'unchecked';
    return loading ? 'checking' : 'fresh';
  }
  const selected = overview?.environments.find(environment => environment.id === selectedId) || overview?.environments[0];
  const agents = overview?.agents.filter(agent => agent.environment_id === selected?.id) || [];
  const issuesPage = tab === 'issues';
  const filterId = issuesPage ? issueFilters.environmentId : selected?.id ?? null;
  const limited = issuesPage ? (overview?.total_issues ?? 0) > (overview?.issues?.length ?? 0) : overview?.inventory_truncated;
  const needsPage = tab !== 'agents' && Boolean(offset || (limited && filterId !== null) || (issuesPage && (issueFilters.namespace || issueFilters.code)));
  const query = new URLSearchParams();
  query.set(issuesPage ? 'issue_offset' : 'offset', String(offset));
  if (filterId !== null) query.set('environment_id', String(filterId));
  if (issuesPage && issueFilters.namespace) query.set('issue_namespace', issueFilters.namespace);
  if (issuesPage && issueFilters.code) query.set('issue_code', issueFilters.code);
  const pageUrl = needsPage ? `${OVERVIEW_URL}&${query}` : null;
  const [inventoryPage, setInventoryPage] = useState<{source: RuntimeOverview; url: string; data: RuntimeOverview} | null>(null);
  const [pageError, setPageError] = useState('');
  useEffect(() => {
    setPageError('');
    if (!overview || !pageUrl) return;
    const controller = new AbortController();
    requestJson<RuntimeOverview>(pageUrl, {signal: controller.signal}).then(result => {
      if (!controller.signal.aborted) setInventoryPage({source: overview, url: pageUrl, data: result});
    }).catch(cause => {
      if (controller.signal.aborted) return;
      if (cause instanceof ApiError && [401, 403].includes(cause.status)) {
        setOverview(null); setInventoryPage(null); setLinkingKey(null); setForm(null); setLoadError(errorText(cause));
      } else setPageError(errorText(cause));
    });
    return () => controller.abort();
  }, [overview, pageUrl]);
  const activePage = pageUrl ? (inventoryPage?.source === overview && inventoryPage?.url === pageUrl ? inventoryPage.data : null) : overview;
  const workloads = activePage?.workloads.filter(workload => workload.environment_id === selected?.id) || [];
  const agentById = new Map(overview?.agents.map(agent => [agent.id, agent]));
  const environmentById = new Map(overview?.environments.map(environment => [environment.id, environment]));
  const summaryById = new Map(overview?.clusters?.map(cluster => [cluster.id, cluster]));
  const issueView = overview && {...overview, issues: activePage?.issues, total_issues: activePage?.total_issues};
  const uncertainCoverage = new Map(overview?.agents.filter(agent => agent.enabled && displayCoverage(agent) !== 'fresh').map(agent => [agent.environment_id, displayCoverage(agent)]));
  const namespaces = activePage?.namespaces?.filter(item => item.environment_id === selected?.id) || [];
  const nextOffset = issuesPage ? activePage?.next_issue_offset : activePage?.next_offset;
  const pageType = issuesPage ? 'issues' : 'observations';
  const pageControls = (Boolean(offset) || nextOffset != null) && <nav className="runtime-actions" aria-label="Inventory pages">
    <button type="button" className="secondary-button" disabled={!offset || !activePage} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Previous {pageType}</button>
    <button type="button" className="secondary-button" disabled={nextOffset == null} onClick={() => {if (nextOffset != null) setOffset(nextOffset);}}>Next {pageType}</button>
  </nav>;
  const mayManage = overview?.permissions.manage === true;
  const selectedManage = mayManage && selected?.can_manage !== false;
  const enabledAgents = agents.filter(agent => agent.enabled);
  const incompleteCoverage = !enabledAgents.length || enabledAgents.some(agent => displayCoverage(agent) !== 'fresh');
  function changeTab(next: typeof tab) {
    setTab(next); setOffset(0); setForm(null); setRevoking(null); setLinkingKey(null); setActionError(''); setMessage('');
  }
  function openEnvironment(id: number) {changeTab('clusters'); setSelectedId(id);}
  function revokeControl(agent: Agent) {
    if (!mayManage || !agent.enabled || environmentById.get(agent.environment_id)?.can_manage === false) return null;
    return revoking === agent.id ? <div className="runtime-revoke"><p>Revoke {agent.name || 'this agent'}? This credential will stop accepting reports. The agent can enroll again using a new linking key.</p>
      <div className="runtime-actions"><button type="button" disabled={busy} onClick={() => void revokeAgent(agent.id)}>Confirm revoke</button>
        <button type="button" className="secondary-button" disabled={busy} onClick={() => setRevoking(null)}>Cancel revoke</button></div></div>
      : <button type="button" className="secondary-button" disabled={busy} onClick={() => setRevoking(agent.id)}>Revoke agent</button>;
  }
  async function mutate<T>(url: string, value: unknown = {}, method = 'POST'): Promise<T> {
    return requestJson<T>(url, {method, headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: JSON.stringify(value)});
  }
  async function saveEnvironment(value: {name: string; kind: Environment['kind']; service_scope: 'all' | 'selected'; service_ids: number[]}) {
    setBusy(true); setActionError(''); setMessage('');
    try {
      const saved = await (form === 'edit' && selected ? mutate<Environment>(`/api/runtime/environments/${selected.id}`, {name: value.name, service_scope: value.service_scope, service_ids: value.service_ids}, 'PUT') : mutate<Environment>('/api/runtime/environments', value));
      setOverview(previous => previous && {...previous, environments: previous.environments.some(environment => environment.id === saved.id)
        ? previous.environments.map(environment => environment.id === saved.id ? saved : environment) : [...previous.environments, saved]});
      setSelectedId(saved.id); setLinkingKey(null);
      setForm(null); setMessage('Environment saved.'); setRefresh(value => value + 1);
    } catch (error) {setActionError(errorText(error));} finally {setBusy(false);}
  }
  async function linkAgent() {
    if (!selected) return;
    setBusy(true); setActionError(''); setMessage(''); setLinkingKey(null);
    try {setLinkingKey(await mutate<LinkingKey>(`/api/runtime/environments/${selected.id}/link-tokens`));}
    catch (error) {setActionError(errorText(error));} finally {setBusy(false);}
  }
  async function revokeAgent(id: string) {
    setBusy(true); setActionError(''); setMessage('');
    try {await mutate(`/api/runtime/agents/${encodeURIComponent(id)}/revoke`); setRevoking(null); setMessage('Agent revoked. It can no longer submit reports.'); setRefresh(value => value + 1);}
    catch (error) {setActionError(errorText(error));} finally {setBusy(false);}
  }
  return <div className="runtime-workspace">
    <PageHeader title="Clusters & agents" description="Review agent reports, observed containers and release compliance across your Kubernetes clusters and Docker hosts."
      actions={<><button type="button" className="secondary-button" disabled={loading || busy} onClick={() => setRefresh(value => value + 1)}>{loading ? 'Refreshing…' : 'Refresh'}</button>
        {mayManage && <button type="button" disabled={busy} onClick={() => {changeTab('clusters'); setForm('new');}}>New environment</button>}</>}/>
    {loadError && <p role="alert" className="runtime-notice">{loadError}{overview && ' The last loaded observations are shown; current coverage could not be checked.'}</p>}
    {overview && loading && !loadError && <p role="status">Checking current coverage. Retained observations are shown until refresh completes.</p>}
    {actionError && <p role="alert" className="runtime-notice">{actionError}</p>}{message && <p role="status">{message}</p>}
    {!overview && loading && <p role="status">Loading runtime environments…</p>}
    {form && overview && <EnvironmentForm key={`${form}-${selected?.id}`} environment={form === 'edit' ? selected : undefined} services={overview.services} busy={busy} save={saveEnvironment} cancel={() => setForm(null)}/>}
    {overview && <nav className="runtime-view-nav" aria-label="Runtime views">
      {(['clusters', 'agents', 'issues'] as const).map(view => <button key={view} type="button" disabled={busy}
        className="secondary-button" aria-pressed={tab === view} onClick={() => changeTab(view)}>
        {{clusters: 'Clusters and hosts', agents: 'All agents', issues: 'Issues'}[view]}</button>)}
    </nav>}
    {pageError && <p className="runtime-notice" role="alert">{pageError} <button type="button" onClick={() => setRefresh(n => n + 1)}>Retry inventory</button></p>}
    {needsPage && !activePage && !pageError && <p role="status">Loading {pageType}.</p>}
    {tab === 'agents' && overview && <section className="panel padded" aria-label="All linked agents"><h2>Linked agents ({overview.agents.length})</h2>
      {overview.agents.length ? <div className="runtime-table"><table><thead><tr><th>Agent</th><th>Cluster or host</th><th>Report coverage</th><th>Last contact</th><th>Actions</th></tr></thead>
        <tbody>{overview.agents.map(agent => <tr key={agent.id}><th scope="row">{agent.name || 'Runtime agent'}<span>{agent.source_id}</span></th>
          <td><button type="button" className="link-button" disabled={busy} onClick={() => openEnvironment(agent.environment_id)}>{environmentById.get(agent.environment_id)?.name}</button></td>
          <td><StatusBadge value={displayCoverage(agent)} label={coverageLabels[displayCoverage(agent)]} tone={coverageTones[displayCoverage(agent)]}/></td>
          <td>{dateText(agent.last_seen_at)}</td><td>{revokeControl(agent)}</td></tr>)}</tbody></table></div> : <p>No agents have enrolled.</p>}</section>}
    {tab === 'issues' && issueView && <RuntimeIssues overview={issueView} filters={issueFilters}
      selectFilters={filters => {setIssueFilters(filters); setOffset(0);}} currentRead={!!activePage && !loading && !loadError}
      currentCoverage={id => {const agent = agentById.get(id); return !!agent && displayCoverage(agent) === 'fresh';}}/>}
    {overview && tab === 'clusters' && <div className="runtime-layout">
      <aside className="panel padded runtime-environments" aria-label="Environments"><h2>Clusters and hosts <span className="muted">({overview.environments.length})</span></h2>
        {overview.environments.length ? overview.environments.map(environment => {
          const summary = summaryById.get(environment.id);
          const coverage = summary?.coverage === 'fresh' ? uncertainCoverage.get(environment.id) || 'fresh' : summary?.coverage;
          return <button type="button" className="runtime-environment" key={environment.id} aria-pressed={selected?.id === environment.id} disabled={busy}
          onClick={() => openEnvironment(environment.id)}>
          <strong>{environment.name}</strong><span>{environment.kind === 'kubernetes' ? 'Kubernetes' : 'Docker'}</span>
          {coverage && <span className="runtime-coverage">{coverage === 'unlinked' ? 'No agent linked' : coverageLabels[coverage]}</span>}
          {summary && <small>{summary.agent_count} agents · {summary.namespace_count} namespaces · {summary.issue_count} reported issues</small>}
        </button>;}) : <p>Add an environment, then link an agent to start collecting observations.</p>}
      </aside>
      {selected && <div className="runtime-detail">
        <section className="panel padded" aria-label="Environment details"><div className="runtime-section-heading"><div><h2>{selected.name}</h2><p className="muted">{selected.kind === 'kubernetes' ? 'Kubernetes cluster' : 'Docker host'}</p></div>
          {selectedManage && <div className="runtime-actions"><button type="button" className="secondary-button" disabled={busy} onClick={() => {setForm('edit'); setLinkingKey(null);}}>Edit environment</button>
            <button type="button" disabled={busy || (selected.service_scope !== 'all' && !selected.service_ids.length)} onClick={() => void linkAgent()}>Link agent</button></div>}</div>
          <p><strong>Approval scope:</strong> {selected.service_scope === 'all' ? 'All active CATS services' : selected.service_ids.length ? selected.service_ids.map(id => overview.services.find(service => service.id === id)?.name || `Service ${id}`).join(', ') : 'No services selected — workload approval is unverified.'}</p>
          <p className="muted">Last refreshed: {dateText(refreshedAt)}. Updates every 30 seconds while this page is visible.</p>
          <button type="button" className="link-button" disabled={busy} onClick={() => {changeTab('issues'); setIssueFilters({environmentId: selected.id, namespace: '', code: ''});}}>View issues for {selected.name}</button>
          {incompleteCoverage && <p className="runtime-notice">Current runtime compliance is not established. Coverage is missing, stale, incomplete, revoked, or awaiting a successful refresh; retained observations do not establish what is running now.</p>}
        </section>
        {selectedManage && linkingKey?.environment_id === selected.id && <LinkingInstructions token={linkingKey} environment={selected} close={() => setLinkingKey(null)}/>}
        <section className="panel padded" aria-label="Agents"><h2>Agents</h2>
          {!agents.length && <p>No agent has been linked. Coverage is not yet available.</p>}
          <div className="runtime-agent-list">{agents.map(agent => <article className="runtime-agent" key={agent.id}>
            <div className="runtime-section-heading"><h3>{agent.name || 'Runtime agent'}</h3><StatusBadge value={displayCoverage(agent)} label={coverageLabels[displayCoverage(agent)]} tone={coverageTones[displayCoverage(agent)]}/></div>
            <dl className="runtime-agent-facts"><div><dt>Source identity</dt><dd><code>{agent.source_id || 'Not reported'}</code></dd></div><div><dt>Agent version</dt><dd>{agent.version || 'Not reported'}</dd></div>
              <div><dt>Last contact</dt><dd>{dateText(agent.last_seen_at)}</dd></div><div><dt>Latest report observed</dt><dd>{dateText(agent.observed_at)}</dd></div>
              <div><dt>Inventory observed</dt><dd>{dateText(agent.inventory_observed_at ?? agent.observed_at)}</dd></div><div><dt>Retained workloads</dt><dd>{agent.workload_count}</dd></div></dl>
            {agent.coverage === 'incomplete' && <p className="runtime-notice">The latest report is incomplete. Any retained inventory may be from an earlier complete report.</p>}
            {!!agent.errors.length && <details><summary>Report issues ({agent.errors.length})</summary><ul>{agent.errors.map((error, index) => <li key={index}>{error}</li>)}</ul></details>}
            {revokeControl(agent)}
          </article>)}</div>
        </section>
        {namespaces.length > 0 && <section className="panel padded"><details><summary>Namespaces ({namespaces.length})</summary><div className="runtime-table"><table>
          <thead><tr><th>Namespace</th><th>Observations</th><th>Reported issues</th></tr></thead><tbody>{namespaces.map(ns => <tr key={ns.name}>
          <th scope="row">{ns.name}</th><td>{ns.workload_count}</td><td>{ns.issue_count}</td></tr>)}</tbody></table></div></details></section>}
        <section className="panel padded" aria-label="Observed workloads"><h2>Observed workloads</h2>
          <p>Approval compares the observed image identity with releases in this environment’s service scope. Helm labels describe agent-reported attribution; chart provenance is unverified.</p>
          {activePage?.inventory_truncated && <p className="runtime-notice" role="status">Showing {activePage.workloads.length} of {activePage.total_workloads ?? 'more'} observations on this inventory page.</p>}
          {!workloads.length ? (activePage && <p>No workload observations are available for this environment.</p>) : <div className="runtime-table"><table><caption>Retained workload observations for {selected.name}</caption>
            <thead><tr><th scope="col">Workload</th><th scope="col">Image identity</th><th scope="col">Report coverage</th><th scope="col">Release match</th><th scope="col">Scan compliance</th><th scope="col">Helm attribution</th></tr></thead>
            <tbody>{workloads.map((workload, index) => {
              const agent = agentById.get(workload.agent_id);
              const coverage = agent && displayCoverage(agent);
              const current = coverage === 'fresh';
              const status = workload.compliance.status;
              const tone: Tone = status === 'noncompliant' && current ? 'danger' : status === 'approved' && current ? 'success' : status === 'excepted' || status === 'unverified' ? 'warning' : 'neutral';
              return <tr key={`${workload.agent_id}-${workload.uid}-${workload.container}-${index}`}>
                <th scope="row"><strong>{workload.workload || workload.uid}</strong><span>{workload.namespace || 'No namespace'} · {workload.container || 'Container not named'}</span>{workload.pod && <span>Pod {workload.pod}</span>}<span>{workload.node || 'Node not reported'} · {workload.state || 'State not reported'}</span></th>
                <td><code>{workload.image_ref || 'Image reference not reported'}</code><code>{workload.image_id || 'Image digest not reported'}</code></td>
                <td><StatusBadge value={coverage || 'unavailable'} label={coverage ? coverageLabels[coverage] : 'Coverage unavailable'} tone={coverage ? coverageTones[coverage] : 'neutral'}/>
                  <span>{dateText(workload.observed_at ?? agent?.inventory_observed_at ?? agent?.observed_at)}</span></td>
                <td><StatusBadge value={status} label={complianceLabels[status]} tone={tone}/>{!current && <span>Retained observation only</span>}<span>{issueReason(workload.compliance.reason)}</span></td>
                <td><ScanCompliance assessment={workload.compliance.scan_assessment} current={current}/></td>
                <td>{workload.chart_name || workload.helm_release ? <><span>{[workload.chart_name, workload.chart_version].filter(Boolean).join(' ') || 'Chart not reported'}</span><span>{workload.helm_release || 'Release not reported'}</span><span className="muted">Unverified provenance</span></> : <span>Not reported</span>}</td>
              </tr>;
            })}</tbody></table></div>}
        </section>
      </div>}
    </div>}
    {tab !== 'agents' && pageControls}
  </div>;
}
