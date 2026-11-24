import {useEffect, useState, type FormEvent} from 'react';
import {requestJson} from '../api';

const base = '/api/admin/log-forwarding';
type Source = {
  id: string;
  name: string;
  allow_audit: boolean;
  allow_diagnostics: boolean;
  revoked: boolean;
  last_received_at?: string | null;
};
type Issued = {source: Source; token: string};
type Relay = {
  state: 'unconfigured' | 'waiting' | 'active' | 'retrying';
  pending: number;
  last_sent_at: string | null;
  last_error: string | null;
  dropped_operational: number;
};
const relayStates: Record<Relay['state'], string> = {
  unconfigured: 'Setup required', waiting: 'Waiting for first delivery', active: 'Connected', retrying: 'Retrying delivery',
};

function useLogStatus<T>(path: string) {
  const [revision, setRevision] = useState(0);
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    requestJson<T>(base + path, {signal: controller.signal}).then(result => {
      if (!controller.signal.aborted) {setValue(result); setError('');}
    }).catch(cause => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load status.');
    });
    return () => controller.abort();
  }, [path, revision]);
  return {value, error, refresh: () => setRevision(current => current + 1)};
}

function Timestamp({value}: {value: string}) {
  return <time dateTime={value}>{new Date(value).toLocaleString()}</time>;
}

export function ReplicaRelay() {
  const {value, error, refresh} = useLogStatus<Relay>('/relay');
  return <section className="panel padded configuration-panel" aria-label="HQ log relay">
    <h2>HQ log relay</h2><p>This replica sends its audit trail, diagnostics and component logs to HQ. HQ manages the external destinations.</p>
    {error && <p role="alert">{error}</p>}
    {value ? <><p><strong>{relayStates[value.state]}</strong> · {value.pending} queued</p>
      <p>Last sent: {value.last_sent_at ? <Timestamp value={value.last_sent_at}/> : 'Never'}</p>
      {value.dropped_operational > 0 && <p>Operational copies dropped: {value.dropped_operational}</p>}
      {value.last_error && <p>Last error: {value.last_error}</p>}
      {value.state === 'unconfigured' && <p>Enroll this replica under Component reporters at HQ, then set <code>CATS_AUDIT_HQ_URL</code> and <code>CATS_AUDIT_HQ_TOKEN</code> in the replica configuration.</p>}</>
      : !error && <p role="status">Loading relay status.</p>}
    <button type="button" className="secondary-button" onClick={refresh}>Refresh relay status</button>
  </section>;
}

function SourceManager({csrf, close}: {csrf: string; close: () => void}) {
  const {value, error: readError, refresh} = useLogStatus<{sources: Source[]}>('/sources');
  const [enroll, setEnroll] = useState(false);
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrf};
  async function issue(path: string, body?: string) {
    if (busy || issued) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await requestJson<Issued>(base + '/sources' + path, {method: 'POST', headers, body});
      setIssued(result); setEnroll(false);
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not issue a reporter token.');}
    finally {setBusy(false); refresh();}
  }
  function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fields = new FormData(e.currentTarget);
    const allow_audit = fields.has('allow_audit'), allow_diagnostics = fields.has('allow_diagnostics');
    if (!allow_audit && !allow_diagnostics) {setError('Select at least one category this reporter can send.'); return;}
    void issue('', JSON.stringify({name: String(fields.get('name') || '').trim(), allow_audit, allow_diagnostics}));
  }
  async function revoke(source: Source) {
    if (busy || issued || !window.confirm('Revoke the token for ' + source.name + '? HQ will reject further reports from this credential.')) return;
    setBusy(true); setError(''); setNotice('');
    try {
      await requestJson(base + '/sources/' + encodeURIComponent(source.id) + '/revoke', {method: 'POST', headers});
      setNotice('Credential revoked for ' + source.name + '.');
    } catch (cause) {setError(cause instanceof Error ? cause.message : 'Could not revoke the credential.');}
    finally {setBusy(false); refresh();}
  }

  return <><p>Enroll each replica or standalone reporter separately. A credential authorizes that reporter to submit the selected categories to HQ.</p>
    <div className="config-actions"><button type="button" disabled={busy || enroll || !!issued} onClick={() => {setEnroll(true); setError(''); setNotice('');}}>Enroll reporter</button>
      <button type="button" className="secondary-button" onClick={refresh}>Refresh reporters</button><button type="button" className="secondary-button" disabled={busy || !!issued} onClick={close}>Close reporters</button></div>
    {readError && <p role="alert">{readError}</p>}{error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    {enroll && <form onSubmit={create} aria-label="Enroll component reporter"><fieldset disabled={busy}><legend>New reporter</legend>
      <label>Reporter name<input name="name" required maxLength={160} placeholder="e.g. Site B replica"/></label>
      <fieldset><legend>Allowed categories</legend>
        <label className="policy-check"><input type="checkbox" name="allow_audit" defaultChecked/>Security audit events</label>
        <label className="policy-check"><input type="checkbox" name="allow_diagnostics" defaultChecked/>Diagnostics and component logs</label>
      </fieldset>
      <div className="config-actions"><button>Generate reporter token</button><button type="button" className="secondary-button" onClick={() => {setEnroll(false); setError('');}}>Cancel</button></div>
    </fieldset></form>}
    {issued && <div role="region" aria-label="New reporter credential">
      <h3>Token for {issued.source.name}</h3><p>Save this token now. Use HTTPS to submit events to <code>/api/v1/component-logs/events</code> with bearer authentication.</p>
      <label>One-time reporter token<input readOnly value={issued.token} autoComplete="off" spellCheck={false} onFocus={e => e.target.select()}/></label>
      <p>On a replica, set <code>CATS_AUDIT_HQ_URL</code> to the HQ HTTPS origin and <code>CATS_AUDIT_HQ_TOKEN</code> to this token.</p>
      <button type="button" onClick={() => setIssued(null)}>I saved the token</button>
    </div>}
    {!value && !readError && <p role="status">Loading reporters.</p>}
    {value?.sources.length === 0 && <p>No enrolled reporters.</p>}
    {!!value?.sources.length && <div className="diagnostic-table-scroll"><table><thead><tr><th>Reporter</th><th>Allowed categories</th><th>Status</th><th>Credential</th></tr></thead>
      <tbody>{value.sources.map(source => <tr key={source.id}><td>{source.name}</td>
        <td>{[source.allow_audit && 'Audit', source.allow_diagnostics && 'Diagnostics and component logs'].filter(Boolean).join(', ')}</td>
        <td>{source.revoked ? 'Revoked' : 'Enrolled'}{source.last_received_at ? <p>Last received: <Timestamp value={source.last_received_at}/></p>
          : source.last_received_at === null && <p>No events received yet.</p>}</td>
        <td>{!source.revoked && <div className="config-actions"><button className="secondary-button" type="button" disabled={busy || !!issued}
          onClick={() => {if (window.confirm('Replace the active token for ' + source.name + '? Update the reporter with the replacement token.')) void issue('/' + encodeURIComponent(source.id) + '/rotate');}}>Rotate token</button>
          <button type="button" className="secondary-button" disabled={busy || !!issued} onClick={() => void revoke(source)}>Revoke token</button></div>}</td>
      </tr>)}</tbody></table></div>}
  </>;
}

export function LogSources({csrf}: {csrf: string}) {
  const [open, setOpen] = useState(false);
  return <section className="panel padded configuration-panel" aria-label="Component reporters">
    <h2>Component reporters</h2>
    {open ? <SourceManager csrf={csrf} close={() => setOpen(false)}/> : <button type="button" className="secondary-button" aria-expanded={false} onClick={() => setOpen(true)}>Manage reporters</button>}
  </section>;
}
