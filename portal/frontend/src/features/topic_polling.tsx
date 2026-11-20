import {useRef, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';
import {EmptyState, ErrorState, Loading, StatusBadge} from '../components/ui';
import {useReplicaResource} from '../hooks/useReplicaResource';
import {AdminTabs, Heading} from './admin_shared';

const sourcesApi = '/api/admin/topic-polling/sources';
type Group = {id: number; name: string};
type Source = {
  id: number; name: string; origin: string; namespace: string; topic: string;
  claim_group_id: number; enabled: boolean; poll_seconds: number; has_token: boolean;
  last_attempt_at?: string | null; last_success_at?: string | null; last_error?: string | null;
  latest_job?: {status: string; stage?: string; project_errors?: {gitlab_project_id: number; message: string}[]} | null;
};
type SourceList = {sources: Source[]; groups: Group[]};
type Project = {id: number; project_path: string; default_branch?: string; commit_sha?: string; status: string;
  error?: string | null; revision_id?: number | null; can_retry: boolean};
type Projects = {projects: Project[]; page: number; pages: number; total: number};
const timeLabel = (time?: string | null) => time ? new Date(time).toLocaleString() : 'Never';

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
          origin: source?.origin ?? fields.get('origin'), namespace: source?.namespace ?? fields.get('namespace'),
          topic: source?.topic ?? fields.get('topic'), claim_group_id: source?.claim_group_id ?? Number(fields.get('claim_group_id')),
          ...(clearToken ? {clear_token: true} : token ? {token} : {}),
        }),
      });
      form.reset(); setClearToken(false); onSaved();
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not save the source.');}
    finally {submitting.current = false; setBusy(false);}
  }
  return <form onSubmit={save}>
    <fieldset disabled={busy} className="config-grid">
      <label>Source name<input name="name" required maxLength={160} defaultValue={source?.name}/></label>
      {!source && <>
        <label>GitLab HTTPS origin<input type="url" name="origin" required maxLength={255} placeholder="https://gitlab.example.org"/></label>
        <label>Namespace<input name="namespace" required maxLength={255} placeholder="platform/engineering"/></label>
        <label>Project topic<input name="topic" required maxLength={255} placeholder="cats"/></label>
        <label>Claim group<select name="claim_group_id" required defaultValue=""><option value="" disabled>Select a group</option>
          {groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select></label>
      </>}
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

function SourceCard({source, groups, data, reload}: {source: Source; groups: Group[]; data: PageData; reload: () => void}) {
  const [editing, setEditing] = useState(false), [busy, setBusy] = useState(false);
  const [projectsOpen, setProjectsOpen] = useState(false);
  const [message, setMessage] = useState(''), [error, setError] = useState('');
  async function poll() {
    setBusy(true); setError(''); setMessage('');
    try {
      await requestJson(sourcesApi + '/' + source.id + '/poll', {method: 'POST', headers: {'X-CSRF-Token': data.csrf_token || ''}});
      setMessage('Poll queued.'); reload();
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not queue a poll.');}
    finally {setBusy(false);}
  }
  const group = groups.find(item => item.id === source.claim_group_id);
  return <article className="panel padded" aria-label={source.name}>
    <h3>{source.name}</h3><StatusBadge value={source.enabled ? 'enabled' : 'disabled'}/>
    <dl className="kv-grid kv-cols-3">
      <div><dt>GitLab origin</dt><dd>{source.origin}</dd></div><div><dt>Namespace</dt><dd>{source.namespace}</dd></div>
      <div><dt>Topic</dt><dd>{source.topic}</dd></div><div><dt>Claim group</dt><dd>{group?.name || source.claim_group_id}</dd></div>
      <div><dt>Poll interval</dt><dd>{source.poll_seconds} seconds</dd></div>
      <div><dt>Access token</dt><dd>{source.has_token ? 'Configured' : 'Not configured'}</dd></div>
      <div><dt>Last attempt</dt><dd>{timeLabel(source.last_attempt_at)}</dd></div>
      <div><dt>Last success</dt><dd>{timeLabel(source.last_success_at)}</dd></div>
      {source.latest_job && <div><dt>Latest poll</dt><dd><StatusBadge value={source.latest_job.status}/> {source.latest_job.stage}</dd></div>}
    </dl>
    {source.last_error && <p role="alert">{source.last_error}</p>}
    {!!source.latest_job?.project_errors?.length && <details><summary>Project errors from the latest poll ({source.latest_job.project_errors.length})</summary>
      <ul>{source.latest_job.project_errors.map((issue, index) => <li key={issue.gitlab_project_id + '-' + index}>
        GitLab project {issue.gitlab_project_id} · {issue.message}</li>)}</ul></details>}
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <div className="button-row"><button type="button" onClick={() => void poll()} disabled={busy || !source.enabled}>{busy ? 'Queuing…' : 'Poll now'}</button>
      <button type="button" className="secondary-button" aria-expanded={editing} onClick={() => setEditing(!editing)}>{editing ? 'Close editor' : 'Edit source'}</button>
      <button type="button" className="secondary-button" aria-expanded={projectsOpen} onClick={() => setProjectsOpen(!projectsOpen)}>Projects</button></div>
    {editing && <SourceForm data={data} groups={groups} source={source} onSaved={() => {setEditing(false); setMessage('Source saved.'); reload();}}/>}
    {projectsOpen && <SourceProjects source={source} data={data}/>}
  </article>;
}

export function Page({data}: {data: PageData}) {
  const enabled = data.cats_mode !== 'replica' && data.may_manage_topic_sources === true;
  const list = useReplicaResource<SourceList>(enabled ? sourcesApi : null);
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
          <p>Use an HTTPS origin approved in <code>CATS_DISCOVERY_GITLAB_SOURCES</code>. The namespace, topic and claim group are fixed when you add the source.</p>
          <SourceForm data={data} groups={list.value.groups} onSaved={() => {setNotice('Source added.'); list.reload();}}/>
        </section>
      </>}
    </div>
  </div>;
}
