import {useEffect, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';
import {useReplica} from '../operatingMode';
type Row = Record<string, any>;
const localDate = (value: string | number) => {const date = new Date(value); return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);};
type Kind = 'upstreams' | 'repositories' | 'principals';
const isProjectMapping = (repository?: string) => Boolean(repository?.endsWith('/*'));

function RepositoryFields({row, upstreams, services}: {row: Row; upstreams: Row[]; services: Row[]}) {
  const replica = useReplica();
  const [publicName, setPublicName] = useState<string>(row.public_repository || '');
  const project = isProjectMapping(publicName);
  const fixedProject = row.id && isProjectMapping(row.public_repository);
  return <>
    <p>For a whole Harbor project, enter a project name followed by /* in both repository fields. A pull uses the service identified by approval evidence for the requested artifact.</p>
    <label>Public repository<input name="public_repository" required placeholder="project/image or project/*" value={publicName} readOnly={fixedProject} onChange={event => setPublicName(event.target.value)}/></label>
    <label>Upstream repository<input name="upstream_repository" required placeholder={project ? 'harbor-project/*' : 'harbor-project/image'} readOnly={fixedProject} defaultValue={row.upstream_repository}/></label>
    <label>Upstream<select name="upstream_id" required disabled={fixedProject} defaultValue={row.upstream_id || ''}><option value="">Select upstream</option>{upstreams.map(upstream => <option key={upstream.id} value={upstream.id}>{upstream.name}</option>)}</select></label>
    {fixedProject && <p>To change either project or the upstream registry, create a mapping with a new public name and grant access to it.</p>}
    {!project && <label>Service<select name="service_id" required defaultValue={row.service_id || ''}><option value="">Select service</option>{services.map(service => <option key={service.id} value={service.id}>{service.name}</option>)}</select></label>}
    {(replica ? ['max_approval_age_days'] : ['max_scan_age_days', 'max_approval_age_days']).map(key => <label key={key}>{key === 'max_scan_age_days' ? 'Maximum scan age (days)' : replica ? 'Local maximum release age (days)' : 'Maximum approval age (days)'}<input type="number" min="1" max="3650" name={key} defaultValue={row.policy?.[key]}/></label>)}
    <p>{replica ? 'This local limit can shorten release validity. The signed approval expiry always applies; synchronization failures never extend it.' : 'Optional age limits only shorten existing compliance and approval validity.'}</p>
    <label><input type="checkbox" name="suspended" defaultChecked={row.suspended}/>Suspend distribution</label>
  </>;
}

export function OCIDistribution({data}: {data: PageData}) {
  const replica = useReplica();
  const [rows, setRows] = useState<Record<Kind, Row[]>>({upstreams: [], repositories: [], principals: []});
  const [status, setStatus] = useState<Row>({}), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const [editing, setEditing] = useState<{kind: Kind; row: Row} | null>(null), [busy, setBusy] = useState(false), [secret, setSecret] = useState('');
  async function refresh() {
    try {const [upstreams, repositories, principals, overview] = await Promise.all([
      requestJson<Row[]>('/api/oci/upstreams'), requestJson<Row[]>('/api/oci/repositories'), requestJson<Row[]>('/api/oci/principals'), requestJson<Row>('/api/oci/status/overview')]);
      setRows({upstreams: Array.isArray(upstreams) ? upstreams : [], repositories: Array.isArray(repositories) ? repositories : [], principals: Array.isArray(principals) ? principals : []}); setStatus(overview || {});
    } catch (e) {setError(e instanceof Error ? e.message : 'Could not load distribution settings.');}
  }
  useEffect(() => {void refresh();}, []);
  async function action(path: string, method: string, body: Row = {}) {
    const testMapping = body.reference && rows.repositories.find(row => path === `repositories/${row.id}/test`);
    if (testMapping && isProjectMapping(testMapping.public_repository)) {
      const repository = window.prompt(`Concrete public repository within ${testMapping.public_repository}`);
      if (!repository) return false;
      body = {...body, repository};
    }
    setBusy(true); setError(''); setNotice(''); setSecret('');
    try {const result = await requestJson<Row>('/api/oci/' + path, {method, headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, ...(method !== 'DELETE' ? {body: JSON.stringify(body)} : {})});
      if (result.secret) setSecret(result.secret);
      setNotice(result.message || 'Distribution settings saved.'); await refresh(); return true;
    } catch (e) {setError(e instanceof Error ? e.message : 'Request failed.'); return false;} finally {setBusy(false);}
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!editing) return;
    const form = new FormData(event.currentTarget), {kind, row} = editing, body: Row = {enabled: form.has('enabled')};
    if (kind === 'upstreams') {
      body.name = form.get('name'); body.endpoint = form.get('endpoint');
      for (const key of ['username', 'password', 'ca_pem']) if (form.get(key)) body[key] = form.get(key);
      for (const key of ['token_realms', 'redirect_origins']) body[key] = String(form.get(key) || '').split(/\r?\n/).map(v => v.trim()).filter(Boolean);
    } else if (kind === 'repositories') {
      for (const key of ['public_repository', 'upstream_repository']) body[key] = form.get(key);
      body.service_id = form.has('service_id') ? Number(form.get('service_id')) : null;
      body.upstream_id = form.has('upstream_id') ? Number(form.get('upstream_id')) : row.upstream_id;
      body.suspended = form.has('suspended'); body.policy = {};
      for (const key of (replica ? ['max_approval_age_days'] : ['max_scan_age_days', 'max_approval_age_days'])) if (form.get(key)) body.policy[key] = Number(form.get(key));
    } else {
      body.name = form.get('name'); body.repository_ids = form.getAll('repository_ids').map(Number);
      if (form.get('expires_at')) body.expires_at = new Date(String(form.get('expires_at'))).toISOString();
    }
    if (await action(kind + (row.id ? '/' + row.id : ''), row.id ? 'PUT' : 'POST', body)) setEditing(null);
  }
  return <section className="panel padded"><h2>Approved artifact distribution</h2>
    <p>{replica ? 'Map local OCI repositories to imported services. Pulls require trusted exact digest evidence and a valid imported approval or a specifically scoped local Cyber override.' : 'Map individual repositories or whole Harbor projects. Pulls require exact digest evidence, a current Cyber approval and current service compliance.'}</p>
    <p>{status.available_repositories ?? '—'} available mappings · {status.active_principals ?? '—'} active machine accounts. {status.proxy_health}</p>
    {error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {secret && <div role="status"><p>Save this machine password now. It is shown once; use the machine account name as the registry login username.</p><code>{secret}</code><button type="button" onClick={() => setSecret('')}>Dismiss password</button></div>}
    {(['upstreams', 'repositories', 'principals'] as Kind[]).map(kind => <section key={kind}><h3>{kind === 'upstreams' ? 'Upstream registries' : kind === 'repositories' ? 'Repository mappings' : 'Machine accounts'}</h3>
      <div className="table-wrap"><table><thead><tr><th>Name</th><th>Configuration</th><th>Status</th><th>Actions</th></tr></thead><tbody>{rows[kind].map(row => <tr key={row.id}>
        <td>{row.name || row.public_repository}</td><td>{kind === 'upstreams' ? row.endpoint : kind === 'repositories' ? `${row.upstream_repository} · ${isProjectMapping(row.public_repository) ? 'Service from approval evidence' : 'Service ' + row.service_id}` : `${row.repository_ids.length} mapping grants · expires ${row.expires_at}`}</td>
        <td>{row.suspended ? 'Suspended' : row.enabled ? 'Enabled' : 'Disabled'}</td><td><button disabled={busy} type="button" onClick={() => setEditing({kind, row})}>Edit</button>
        {kind === 'principals' && <button disabled={busy} type="button" onClick={() => {if (window.confirm('Replace this machine password? The current password will stop working immediately.')) void action(`principals/${row.id}/rotate`, 'POST');}}>Rotate password</button>}
        <button disabled={busy} type="button" onClick={() => {if (window.confirm(kind === 'repositories' ? 'Disable this mapping and remove machine grants?' : 'Delete this configuration?')) void action(`${kind}/${row.id}`, 'DELETE');}}>{kind === 'repositories' ? 'Disable and revoke grants' : 'Delete'}</button>
        {kind === 'repositories' && <button disabled={busy} type="button" onClick={() => {const reference = window.prompt('Manifest tag or digest to test (does not grant distribution approval)', 'latest'); if (reference) void action(`repositories/${row.id}/test`, 'POST', {reference});}}>Test connection</button>}</td></tr>)}{!rows[kind].length && <tr><td colSpan={4} className="empty table-empty">None configured yet.</td></tr>}</tbody></table></div>
      <button type="button" disabled={busy} onClick={() => setEditing({kind, row: {}})}>Add {kind === 'principals' ? 'machine account' : kind === 'repositories' ? 'mapping' : 'upstream'}</button></section>)}
    {editing && <form className="approval-form" key={editing.kind + (editing.row.id || 'new')} onSubmit={submit}><h3>{editing.row.id ? 'Edit' : 'Add'} {editing.kind}</h3>
      {editing.kind === 'upstreams' && <><label>Name<input name="name" required defaultValue={editing.row.name}/></label><label>HTTPS registry endpoint<input name="endpoint" type="url" required defaultValue={editing.row.endpoint}/></label><label>Username<input name="username" autoComplete="off"/></label><label>Password<input name="password" type="password" autoComplete="new-password"/></label><label>Additional CA certificates (PEM, optional)<textarea name="ca_pem"/></label><p>Connections use system roots and the trusted CA certificates configured in CATS. Additional certificates apply only to this registry. Leave credentials and additional CA blank to retain existing settings.</p>{['token_realms', 'redirect_origins'].map(key => <label key={key}>{key === 'token_realms' ? 'Allowed HTTPS token realms (one per line)' : 'Allowed HTTPS redirect origins (one per line)'}<textarea name={key} defaultValue={(editing.row[key] || []).join('\n')}/></label>)}</>}
      {editing.kind === 'repositories' && <RepositoryFields row={editing.row} upstreams={rows.upstreams} services={status.services || []}/>}
      {editing.kind === 'principals' && <><label>Machine account name<input name="name" required defaultValue={editing.row.name}/></label><label>Expiry<input name="expires_at" type="datetime-local" required defaultValue={localDate(editing.row.expires_at || Date.now() + 90 * 86400000)}/></label><fieldset><legend>Repository grants</legend>{rows.repositories.map(row => <label key={row.id}><input name="repository_ids" type="checkbox" value={row.id} defaultChecked={(editing.row.repository_ids || []).includes(row.id)}/>{row.public_repository}{isProjectMapping(row.public_repository) && ' (whole project)'}</label>)}</fieldset></>}
      <label><input type="checkbox" name="enabled" defaultChecked={editing.row.enabled !== false}/>Enabled</label><div className="dialog-actions"><button type="button" disabled={busy} onClick={() => setEditing(null)}>Cancel</button><button disabled={busy}>Save</button></div></form>}
  </section>;
}
