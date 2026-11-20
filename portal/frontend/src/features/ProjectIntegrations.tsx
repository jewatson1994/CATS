import {useEffect, useId, useState, type FormEvent} from 'react';
import {can, onSessionEnded, requestJson, type PageData} from '../api';
import {StatusBadge} from '../components/ui';

const scopeNames = {'artifacts.submit': 'Submit artifacts', 'evidence.write': 'Write scan evidence'} as const;
type Scope = keyof typeof scopeNames;
interface Credential {
  id: number;
  project_label: string;
  service_key: string;
  scopes: Scope[];
  status: 'active' | 'inactive' | 'expired' | 'revoked';
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
}

const chartExample = [
  'curl --fail-with-body --silent --show-error "$CATS_PORTAL_URL/api/v1/artifact-submissions"',
  '  -H "Authorization: Bearer $CATS_PROJECT_TOKEN"',
  '  -H "Idempotency-Key: $CATS_SUBMISSION_KEY"',
  '  -F "file=@chart.tgz" -F "version=1.2.3"',
].join(' \\\n');

function CredentialForm({busy, issue, cancel}: {
  busy: boolean; issue: (label: string, scopes: Scope[], days: number) => void; cancel: () => void;
}) {
  const [label, setLabel] = useState(''), [days, setDays] = useState('30');
  const [scopes, setScopes] = useState<Scope[]>(['artifacts.submit']);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (label.trim() && scopes.length && !busy) issue(label.trim(), scopes, Number(days));
  }
  return <form className="service-control-editor" onSubmit={submit}>
    <div className="service-control-fields">
      <label>Project label<input required maxLength={120} value={label} disabled={busy} autoComplete="off"
        onChange={event => setLabel(event.target.value)} placeholder="Payments build pipeline"/></label>
      <label>Expires in days<input type="number" required min={1} max={365} step={1} value={days}
        disabled={busy} onChange={event => setDays(event.target.value)}/></label>
    </div>
    <fieldset disabled={busy}><legend>Credential scopes</legend>
      {(Object.keys(scopeNames) as Scope[]).map(scope => <label className="project-credential-scope" key={scope}>
        <input type="checkbox" checked={scopes.includes(scope)} onChange={event =>
          setScopes(event.target.checked ? [...scopes, scope] : scopes.filter(item => item !== scope))}/>
        {scopeNames[scope]} <code>{scope}</code></label>)}
    </fieldset>
    <div className="service-control-actions"><button disabled={busy || !label.trim() || !scopes.length}>Issue credential</button>
      <button type="button" className="secondary-button" disabled={busy} onClick={cancel}>Cancel</button></div>
  </form>;
}

export function ProjectIntegrations({data}: {data: PageData}) {
  const service = data.view.service, serviceKey: string = service.service_key;
  const root = '/api/services/' + encodeURIComponent(serviceKey) + '/project-credentials';
  const active = !data.view.archive && service.lifecycle_status === 'active';
  const canIssue = active && service.groups?.length === 1 && can(data, 'scan.ingest', service.id);
  const [expanded, setExpanded] = useState(window.location.hash === '#project-integrations');
  const [credentials, setCredentials] = useState<Credential[] | null>(null), [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false), [creating, setCreating] = useState(false);
  const [confirming, setConfirming] = useState<number | null>(null);
  const [issued, setIssued] = useState<{credential: Credential; token: string} | null>(null);
  const [error, setError] = useState(''), [notice, setNotice] = useState('');
  const panelId = useId();

  useEffect(() => {
    if (!expanded) return;
    const controller = new AbortController();
    setError(''); setCredentials(null);
    requestJson<{credentials: Credential[]}>(root, {signal: controller.signal}).then(result => {
      if (!controller.signal.aborted) setCredentials(result.credentials);
    }).catch(cause => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load CI credentials.');
    });
    return () => controller.abort();
  }, [root, expanded, attempt]);
  useEffect(() => {
    const clear = () => setIssued(null);
    window.addEventListener('pagehide', clear);
    const unsubscribe = onSessionEnded(clear);
    return () => {window.removeEventListener('pagehide', clear); unsubscribe();};
  }, []);

  function toggle() {
    setIssued(null); setCreating(false); setConfirming(null); setNotice(''); setError('');
    setExpanded(!expanded);
  }
  async function mutate<T>(path: string, body: object): Promise<T> {
    return requestJson<T>(path, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''},
      body: JSON.stringify({csrf_token: data.csrf_token || '', ...body})});
  }
  async function issue(label: string, scopes: Scope[], days: number) {
    if (busy || !canIssue) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await mutate<{credential: Credential; token: string}>(root, {project_label: label, scopes, expires_in_days: days});
      setCredentials(rows => [result.credential, ...(rows || [])]); setCreating(false); setIssued(result);
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not issue a credential.');}
    finally {setBusy(false);}
  }
  async function revoke(row: Credential) {
    if (busy || confirming !== row.id) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await mutate<{credential: Credential}>(root + '/' + row.id + '/revoke', {});
      setCredentials(rows => rows?.map(item => item.id === row.id ? result.credential : item) || []);
      if (issued?.credential.id === row.id) setIssued(null);
      setConfirming(null); setNotice('Revoked credential for ' + row.project_label + '.');
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not revoke the credential.');}
    finally {setBusy(false);}
  }
  async function copy(value: string, label: string) {
    try {await navigator.clipboard.writeText(value); setNotice(label + ' copied.');}
    catch {setNotice('Select the text to copy it manually.');}
  }

  return <section id="project-integrations" className="panel service-control-card project-integrations" aria-label="Project integrations">
    <div className="service-control-heading"><div className="service-control-title"><h2>Project integrations</h2></div>
      <button type="button" className="secondary-button" disabled={busy} aria-expanded={expanded} aria-controls={panelId}
        onClick={toggle}>{expanded ? 'Close credentials' : 'Manage credentials'}</button></div>
    <p className="service-control-description">Manage CI credentials bound to <code>{serviceKey}</code>.</p>
    {expanded && <div id={panelId}>
      {error && <div role="alert"><p>{error}</p><button type="button" disabled={busy} onClick={() => setAttempt(value => value + 1)}>Reload credentials</button></div>}
      {notice && <p role="status">{notice}</p>}
      {!credentials && !error && <p role="status">Loading CI credentials.</p>}
      {issued && <section className="service-control-editor" aria-label="One-time project token">
        <h3>Token for {issued.credential.project_label}</h3><p>Save this token as a masked CI secret named <code>CATS_PROJECT_TOKEN</code>. CATS shows it once.</p>
        <code className="project-integration-secret">{issued.token}</code>
        <div className="service-control-actions"><button type="button" onClick={() => void copy(issued.token, 'Token')}>Copy token</button>
          <button type="button" className="secondary-button" onClick={() => {setIssued(null); setNotice('');}}>Dismiss token</button></div>
      </section>}
      {credentials && <>
        {credentials.length ? <div className="table-wrap"><table><caption className="sr-only">CI credentials for {serviceKey}</caption>
          <thead><tr><th>Project</th><th>Scopes</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>{credentials.map(row => <tr key={row.id}><td>{row.project_label}</td><td>{row.scopes.map(scope => scopeNames[scope] || scope).join(', ')}</td>
            <td><time dateTime={row.expires_at}>{new Date(row.expires_at).toLocaleString()}</time></td><td><StatusBadge value={row.status}/></td>
            <td>{['active', 'inactive'].includes(row.status) && (confirming === row.id
              ? <div className="service-control-actions"><button type="button" className="danger-button" disabled={busy}
                  onClick={() => void revoke(row)}>Confirm revocation</button><button type="button" disabled={busy} onClick={() => setConfirming(null)}>Cancel</button></div>
              : <button type="button" className="secondary-button" disabled={busy} aria-label={'Revoke ' + row.project_label}
                  onClick={() => {setConfirming(row.id); setError(''); setNotice('');}}>Revoke</button>)}</td></tr>)}</tbody>
        </table></div> : <p>No project credentials have been issued for this service.</p>}
        {canIssue && !issued && (creating ? <CredentialForm busy={busy} issue={issue} cancel={() => setCreating(false)}/> :
          <button type="button" disabled={busy} onClick={() => {setCreating(true); setConfirming(null); setNotice('');}}>New credential</button>)}
        {!canIssue && <p className="service-control-help">{!active ? 'New credentials require an active service.' : service.groups?.length !== 1
          ? 'Assign one owning group before issuing a credential.' : 'Issuing a credential requires scan ingestion permission for this service.'}</p>}
      </>}
      <details className="service-control-history"><summary>CI submission example</summary>
        <p>To submit a Helm chart, use a token with <code>artifacts.submit</code>. Set <code>CATS_PORTAL_URL</code> to the portal HTTPS origin and <code>CATS_SUBMISSION_KEY</code> to a unique build and artifact identifier. Reuse the key when retrying the same upload.</p>
        <pre><code>{chartExample}</code></pre><div className="service-control-actions">
          <button type="button" className="secondary-button" onClick={() => void copy(chartExample, 'Example')}>Copy submission example</button>
          <a href="/api/v1/pipeline/openapi.json">CI API schema</a></div>
      </details>
    </div>}
  </section>;
}
