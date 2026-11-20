import {useRef, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';
import {safeReference} from '../components/Form';
import {EmptyState, ErrorState, Loading, StatusBadge} from '../components/ui';
import {useReplicaResource} from '../hooks/useReplicaResource';
import {AdminTabs, Heading} from './admin_shared';

const sourcesApi = '/api/admin/topic-polling/sources';
type Group = {id: number; name: string};
type ScopeMode = 'group' | 'instance';
type NamespaceRoute = {namespace: string; claim_group_id: number};
type Match = {
  gitlab_project_id: number; project_path: string; web_url?: string; default_branch?: string;
  commit_sha?: string; claim_group_id?: number | null;
  status: 'new_commit' | 'unchanged' | 'conflict' | 'skipped'; reason?: string;
};
const countLabels = {
  matched: 'Matched projects', new_commits: 'New commits', unchanged_commits: 'Unchanged commits',
  conflicts: 'Conflicts', skipped: 'Skipped', failed_projects: 'Project errors', no_longer_eligible: 'Left scope',
  excluded: 'Excluded by worker',
} as const;
const exclusionLabels = {outside_namespace: 'Outside approved namespaces', no_default_branch: 'No default branch', archived: 'Archived'} as const;
type PollJob = Partial<Record<keyof typeof countLabels, number>> & {
  id: string; status: string; stage?: string; error?: string | null; project_errors?: {gitlab_project_id: number; message: string}[];
  details?: Match[]; truncated?: boolean; excluded_by_reason?: Partial<Record<keyof typeof exclusionLabels, number>>;
};
type Source = {
  id: number; name: string; origin: string; namespace: string; topic: string;
  claim_group_id: number | null; scope_mode?: ScopeMode; namespace_routes?: NamespaceRoute[];
  enabled: boolean; poll_seconds: number; has_token: boolean;
  last_attempt_at?: string | null; last_success_at?: string | null; last_error?: string | null;
  latest_job?: PollJob | null; latest_preview?: PollJob | null;
};
type SourceList = {sources: Source[]; groups: Group[]};
type Project = {id: number; project_path: string; default_branch?: string; commit_sha?: string; status: string;
  error?: string | null; revision_id?: number | null; can_retry: boolean};
type Projects = {projects: Project[]; page: number; pages: number; total: number};
const timeLabel = (time?: string | null) => time ? new Date(time).toLocaleString() : 'Never';
const groupLabel = (groups: Group[], id?: number | null) =>
  id == null ? '—' : groups.find(group => group.id === id)?.name ?? `Group #${id}`;
const activeJob = (job?: PollJob | null) => job?.status === 'queued' || job?.status === 'running';
const refreshWhileActive = (list: SourceList) => list.sources.some(source =>
  activeJob(source.latest_job) || activeJob(source.latest_preview)) ? 5000 : 0;

function SourceProjects({source, data}: {source: Source; data: PageData}) {
  const [page, setPage] = useState(1), [retrying, setRetrying] = useState<number | null>(null);
  const [error, setError] = useState(''), [notice, setNotice] = useState('');
  const prefix = sourcesApi + '/' + source.id;
  const list = useReplicaResource<Projects>(prefix + '/projects?page=' + page);
  async function retry(revision: number) {
    setRetrying(revision); setError(''); setNotice('');
    try {
      await requestJson(prefix + '/revisions/' + revision + '/retry', {method: 'POST', headers: {'X-CSRF-Token': data.csrf_token || ''}});
      setNotice('Revision queued for retry.'); list.reload();
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not retry this revision.');}
    finally {setRetrying(null);}
  }
  return <section aria-label={'Projects from ' + source.name}><div className="button-row"><h4>Discovered projects</h4>
    <button type="button" className="secondary-button" onClick={list.reload}>Refresh projects</button></div>
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {list.error ? <ErrorState title="Projects could not be loaded" onRetry={list.reload}>{list.error}</ErrorState> :
      !list.value ? <Loading label="Loading projects…"/> : <>
        {!list.value.projects.length ? <p>No projects recorded for this source.</p> :
          <div className="table-wrap"><table><thead><tr><th>Project</th><th>Default branch</th><th>Revision</th><th>Processing</th></tr></thead>
            <tbody>{list.value.projects.map(project => <tr key={project.id}><td>{project.project_path}</td><td>{project.default_branch || 'Unknown'}</td>
              <td><code className="wrap-text">{project.commit_sha || 'Unknown'}</code></td><td><StatusBadge value={project.status}
                label={project.status === 'out_of_scope' ? 'No longer matches this source' : undefined}/>
                {project.error && <p>{project.error}</p>}{project.can_retry && project.revision_id != null &&
                  <button type="button" className="secondary-button" disabled={retrying !== null} onClick={() => void retry(project.revision_id!)}>
                    {retrying === project.revision_id ? 'Queuing…' : 'Retry revision'}</button>}</td></tr>)}</tbody></table></div>}
        {list.value.pages > 1 && <nav className="pager" aria-label="Source project pages">
          <button className="secondary-button" disabled={list.value.page <= 1} onClick={() => setPage(list.value!.page - 1)}>Previous page</button>
          <span>Page {list.value.page} of {list.value.pages} · {list.value.total} projects</span>
          <button className="secondary-button" disabled={list.value.page >= list.value.pages} onClick={() => setPage(list.value!.page + 1)}>Next page</button></nav>}
      </>}
  </section>;
}

function SourceForm({source, groups, data, onSaved}: {
  source?: Source; groups: Group[]; data: PageData; onSaved: () => void;
}) {
  const [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const [clearToken, setClearToken] = useState(false);
  const [mode, setMode] = useState<ScopeMode>(source?.scope_mode ?? 'group');
  const [routes, setRoutes] = useState(() => source?.namespace_routes?.length
    ? source.namespace_routes.map((route, key) => ({...route, key}))
    : [{key: 0, namespace: '', claim_group_id: 0}]);
  const nextRoute = useRef(routes.length);
  const submitting = useRef(false);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current) return;
    submitting.current = true;
    const form = event.currentTarget, fields = new FormData(form);
    const token = String(fields.get('token') || '');
    setBusy(true); setError('');
    try {
      await requestJson(source ? sourcesApi + '/' + source.id : sourcesApi, {
        method: source ? 'PUT' : 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''},
        body: JSON.stringify({
          name: fields.get('name'), enabled: fields.has('enabled'), poll_seconds: Number(fields.get('poll_seconds')),
          origin: source?.origin ?? fields.get('origin'), topic: source?.topic ?? fields.get('topic'),
          ...(mode === 'instance' ? {scope_mode: mode, namespace_routes: routes.map(route =>
            ({namespace: route.namespace.trim(), claim_group_id: route.claim_group_id}))}
            : {namespace: source?.namespace ?? fields.get('namespace'),
               claim_group_id: source?.claim_group_id ?? Number(fields.get('claim_group_id'))}),
          ...(clearToken ? {clear_token: true} : token ? {token} : {}),
        }),
      });
      form.reset(); setClearToken(false);
      if (!source) {
        setMode('group');
        setRoutes([{key: 0, namespace: '', claim_group_id: 0}]);
      }
      onSaved();
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not save the source.');}
    finally {submitting.current = false; setBusy(false);}
  }
  return <form onSubmit={save}>
    <fieldset disabled={busy} className="config-grid">
      <label>Source name<input name="name" required maxLength={160} defaultValue={source?.name}/></label>
      {!source && <>
        <label>GitLab HTTPS origin<input type="url" name="origin" required maxLength={255} placeholder="https://gitlab.example.org"/></label>
        <label>Project topic<input name="topic" required maxLength={128} placeholder="cats"/></label>
        <label>Search scope<select value={mode} onChange={event => setMode(event.target.value as ScopeMode)}>
          <option value="group">One GitLab group and its subgroups</option>
          <option value="instance">Across approved GitLab namespaces</option></select></label>
      </>}
      {!source && mode === 'group' && <>
        <label>Namespace<input name="namespace" required maxLength={255} placeholder="platform/engineering"/></label>
        <label>Claim group<select name="claim_group_id" required defaultValue=""><option value="" disabled>Select a group</option>
          {groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
      </>}
      {mode === 'instance' && <fieldset>
        <legend>Approved namespaces</legend>
        <p>Choose which CATS group can claim projects from each GitLab namespace and its subgroups.</p>
        {routes.map((route, index) => <div key={route.key} className="button-row">
          <label>Namespace {index + 1}<input required maxLength={255} value={route.namespace} placeholder="platform/engineering"
            onChange={event => setRoutes(routes.map(item => item.key === route.key ? {...item, namespace: event.target.value} : item))}/></label>
          <label>Claim group {index + 1}<select required value={route.claim_group_id || ''}
            onChange={event => setRoutes(routes.map(item => item.key === route.key ? {...item, claim_group_id: Number(event.target.value)} : item))}>
            <option value="" disabled>Select a group</option>
            {groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
          {routes.length > 1 && <button type="button" className="secondary-button" aria-label={`Remove namespace ${index + 1}`}
            onClick={() => setRoutes(routes.filter(item => item.key !== route.key))}>Remove</button>}
        </div>)}
        <button type="button" className="secondary-button" onClick={() => {
          const key = nextRoute.current++;
          setRoutes([...routes, {key, namespace: '', claim_group_id: 0}]);
        }}>Add namespace</button>
      </fieldset>}
      <label>Polling interval (seconds)<input type="number" name="poll_seconds" required min={30} max={86400} defaultValue={source?.poll_seconds ?? 300}/></label>
      <label>{source?.has_token ? 'Replacement access token' : 'Access token (optional)'}
        <input name="token" type="password" autoComplete="new-password" disabled={clearToken}/></label>
      {source?.has_token && <label><input type="checkbox" checked={clearToken} onChange={event => setClearToken(event.target.checked)}/> Remove stored token</label>}
      <label><input type="checkbox" name="enabled" defaultChecked={source?.enabled ?? false}/> Enable automatic polling</label>
    </fieldset>
    {error && <p role="alert">{error}</p>}
    <button disabled={busy || (!source && !groups.length)}>{busy ? 'Saving…' : source ? 'Save changes' : 'Add source'}</button>
  </form>;
}

type RunKind = 'poll' | 'preview';
function MatchDetails({kind, sourceId, jobId, groups}: {kind: RunKind; sourceId: number; jobId: string; groups: Group[]}) {
  const labels = {new_commit: 'New commit', unchanged: 'Unchanged', conflict: 'Routing conflict', skipped: 'Skipped'};
  const result = useReplicaResource<Pick<Source, 'latest_job' | 'latest_preview'>>(`${sourcesApi}/${sourceId}/results`);
  if (result.error) return <ErrorState title="Could not load match details" onRetry={result.reload}>{result.error}</ErrorState>;
  if (!result.value) return <Loading label="Loading match details."/>;
  const job = kind === 'preview' ? result.value.latest_preview : result.value.latest_job;
  if (!job || job.id !== jobId) return <p>A newer run is available. Refresh status to view its results.</p>;
  const details = job.details || [];
  if (!details.length) return <p>No project details recorded for this run.</p>;
  return <>
    {job.truncated && <p>Showing {details.length} project details. Totals include all results.</p>}
    <div className="table-wrap"><table aria-label={kind === 'preview' ? 'Preview matches' : 'Poll matches'}><thead><tr>
      <th>Project</th><th>Branch and commit</th><th>Claim group</th><th>Result</th></tr></thead>
      <tbody>{details.map(row => {
        const url = safeReference(row.web_url);
        return <tr key={row.gitlab_project_id}>
          <td>{url ? <a href={url} rel="noreferrer" target="_blank">{row.project_path}</a> : row.project_path}</td>
          <td>{row.default_branch}<div><code className="wrap-text">{row.commit_sha}</code></div></td>
          <td>{groupLabel(groups, row.claim_group_id)}</td>
          <td><StatusBadge value={row.status} label={labels[row.status]}/>{row.reason && <p>{row.reason}</p>}</td></tr>;
      })}</tbody></table></div>
  </>;
}

function RunResults({kind, sourceId, job, groups, expanded, toggle}: {
  kind: RunKind; sourceId: number; job: PollJob; groups: Group[]; expanded: boolean; toggle: () => void;
}) {
  const preview = kind === 'preview';
  const title = preview ? 'Latest preview' : 'Latest poll';
  const canExpand = !activeJob(job) && Boolean(job.matched || job.skipped || job.conflicts || job.failed_projects);
  return <section aria-label={title}>
    <div className="button-row"><h4>{title}</h4><StatusBadge value={job.status}/><span>{job.stage}</span>
      {canExpand && <button type="button" className="secondary-button" aria-expanded={expanded} onClick={toggle}>
        {expanded ? 'Hide' : 'Show'} {kind} matches</button>}</div>
    {job.error && <p role="alert">{job.error}</p>}
    {typeof job.matched === 'number' && <dl className="kv-grid kv-cols-3">
      {(Object.keys(countLabels) as (keyof typeof countLabels)[])
        .filter(key => typeof job[key] === 'number' && !(preview && key === 'no_longer_eligible'))
        .map(key => <div key={key}><dt>{countLabels[key]}</dt><dd>{job[key]}</dd></div>)}
    </dl>}
    {Boolean(job.excluded) && <ul aria-label="Reasons projects were excluded">
      {(Object.keys(exclusionLabels) as (keyof typeof exclusionLabels)[]).filter(key => job.excluded_by_reason?.[key]).map(key =>
        <li key={key}>{exclusionLabels[key]} ({job.excluded_by_reason?.[key]})</li>)}
    </ul>}
    {expanded && canExpand && <MatchDetails key={job.id} sourceId={sourceId} kind={kind} jobId={job.id} groups={groups}/>}
    {!!job.project_errors?.length && <details><summary>Project errors from the latest {kind} ({job.project_errors.length})</summary>
      <ul>{job.project_errors.map((issue, index) => <li key={issue.gitlab_project_id + '-' + index}>
        GitLab project {issue.gitlab_project_id} · {issue.message}</li>)}</ul></details>}
  </section>;
}

function SourceCard({source, groups, data, reload}: {source: Source; groups: Group[]; data: PageData; reload: () => void}) {
  const [editing, setEditing] = useState(false), [busy, setBusy] = useState<RunKind | null>(null);
  const [expanded, setExpanded] = useState<RunKind | null>(null);
  const [projectsOpen, setProjectsOpen] = useState(false);
  const [message, setMessage] = useState(''), [error, setError] = useState('');
  async function queue(kind: RunKind) {
    setBusy(kind); setError(''); setMessage('');
    try {
      await requestJson(sourcesApi + '/' + source.id + '/' + kind, {method: 'POST', headers: {'X-CSRF-Token': data.csrf_token || ''}});
      setMessage(kind === 'preview' ? 'Preview queued. The worker will check project metadata only.' : 'Poll queued.');
      setExpanded(kind); reload();
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not queue the ' + kind + '.');}
    finally {setBusy(null);}
  }
  return <article className="panel padded" aria-label={source.name}>
    <h3>{source.name}</h3><StatusBadge value={source.enabled ? 'enabled' : 'disabled'}/>
    <dl className="kv-grid kv-cols-3">
      <div><dt>GitLab origin</dt><dd>{source.origin}</dd></div><div><dt>Topic</dt><dd>{source.topic}</dd></div>
      {source.scope_mode === 'instance' ? <div><dt>Approved namespaces and claim groups</dt><dd><ul>
        {source.namespace_routes?.map(route => <li key={route.namespace}>{route.namespace} → {groupLabel(groups, route.claim_group_id)}</li>)}
      </ul></dd></div> : <><div><dt>Namespace</dt><dd>{source.namespace}</dd></div>
        <div><dt>Claim group</dt><dd>{groupLabel(groups, source.claim_group_id)}</dd></div></>}
      <div><dt>Poll interval</dt><dd>{source.poll_seconds} seconds</dd></div>
      <div><dt>Access token</dt><dd>{source.has_token ? 'Configured' : 'Not configured'}</dd></div>
      <div><dt>Last attempt</dt><dd>{timeLabel(source.last_attempt_at)}</dd></div>
      <div><dt>Last success</dt><dd>{timeLabel(source.last_success_at)}</dd></div>
    </dl>
    {source.last_error && source.last_error !== source.latest_job?.error && <p role="alert">{source.last_error}</p>}
    {source.latest_job && <RunResults kind="poll" sourceId={source.id} job={source.latest_job} groups={groups} expanded={expanded === 'poll'}
      toggle={() => setExpanded(expanded === 'poll' ? null : 'poll')}/>}
    {source.latest_preview && <RunResults kind="preview" sourceId={source.id} job={source.latest_preview} groups={groups} expanded={expanded === 'preview'}
      toggle={() => setExpanded(expanded === 'preview' ? null : 'preview')}/>}
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <div className="button-row"><button type="button" onClick={() => void queue('poll')} disabled={busy !== null || !source.enabled || activeJob(source.latest_job)}>
      {busy === 'poll' ? 'Queuing…' : 'Poll now'}</button>
      <button type="button" className="secondary-button" onClick={() => void queue('preview')} disabled={busy !== null || activeJob(source.latest_preview)}>
        {busy === 'preview' ? 'Queuing preview…' : 'Preview matches'}</button>
      <button type="button" className="secondary-button" aria-expanded={editing} onClick={() => setEditing(!editing)}>{editing ? 'Close editor' : 'Edit source'}</button>
      <button type="button" className="secondary-button" aria-expanded={projectsOpen} onClick={() => setProjectsOpen(!projectsOpen)}>Projects</button></div>
    {editing && <SourceForm data={data} groups={groups} source={source} onSaved={() => {setEditing(false); setMessage('Source saved.'); reload();}}/>}
    {projectsOpen && <SourceProjects source={source} data={data}/>}
  </article>;
}

export function Page({data}: {data: PageData}) {
  const enabled = data.cats_mode !== 'replica' && data.may_manage_topic_sources === true;
  const list = useReplicaResource<SourceList>(enabled ? sourcesApi : null, refreshWhileActive);
  const [notice, setNotice] = useState('');
  if (!enabled) return <ErrorState title="Topic polling is unavailable"/>;
  return <div className="admin-workspace"><Heading title="GitLab topic polling" description="Choose the GitLab projects CATS checks for new revisions and the group that can claim them."/>
    <AdminTabs data={data} selected="topic-polling"/>
    <div className="settings-workspace-main">
      {list.error ? <ErrorState title="Could not load polling sources" onRetry={list.reload}>{list.error}</ErrorState> :
       !list.value ? <Loading label="Loading polling sources…"/> : <>
        <section aria-label="Configured sources"><div className="button-row"><h2>Configured sources</h2>
          <button type="button" className="secondary-button" onClick={list.reload}>Refresh status</button></div>
          {!list.value.sources.length && <EmptyState title="No GitLab sources configured">Add a source and enable polling to discover projects.</EmptyState>}
          {list.value.sources.map(source => <SourceCard key={source.id} source={source} groups={list.value!.groups} data={data} reload={list.reload}/>)}
        </section>
        <section className="panel padded"><h2>Add a source</h2>
          {notice && <p role="status">{notice}</p>}
          {!list.value.groups.length && <p>Create a service group before adding a source.</p>}
          <p>Use an HTTPS origin approved in <code>CATS_DISCOVERY_GITLAB_SOURCES</code>. Save a disabled source to preview its matches before enabling polling.</p>
          <SourceForm data={data} groups={list.value.groups} onSaved={() => {setNotice('Source added.'); list.reload();}}/>
        </section>
      </>}
    </div>
  </div>;
}
