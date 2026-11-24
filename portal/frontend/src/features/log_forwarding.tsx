import {useEffect, useState, type FormEvent} from 'react';
import {requestJson, type PageData} from '../api';

const destinationsUrl = '/api/admin/log-forwarding/destinations';
const kinds = {syslog: 'Syslog', splunk: 'Splunk HTTP Event Collector', azure: 'Azure Log Analytics'};
type Kind = keyof typeof kinds;
type Config = Record<string, string | number>;
interface Destination {
  id: number;
  name: string;
  kind: Kind;
  config: Config;
  enabled: boolean;
  audit: boolean;
  diagnostics: boolean;
  has_secret: boolean;
  pending: number;
  last_sent_at: string | null;
  last_error: string | null;
}
interface DestinationInput {
  name: string;
  kind: Kind;
  config: Config;
  enabled: boolean;
  audit: boolean;
  diagnostics: boolean;
  secret?: string;
}

function DestinationEditor({destination, busy, onSave, onCancel}: {
  destination?: Destination;
  busy: boolean;
  onSave: (values: DestinationInput) => void;
  onCancel: () => void;
}) {
  const [kind, setKind] = useState<Kind>(destination?.kind ?? 'syslog');
  const config = destination?.config ?? {};
  const [transport, setTransport] = useState(String(config.transport ?? 'tls'));
  const [port, setPort] = useState(String(config.port ?? 6514));
  const [error, setError] = useState('');
  const locked = Boolean(destination);
  const textField = (name: string, label: string, options: {required?: boolean; type?: string; editable?: boolean; placeholder?: string} = {}) =>
    <label>{label}<input name={name} type={options.type ?? 'text'} placeholder={options.placeholder} defaultValue={config[name] ?? ''}
      required={options.required ?? true} readOnly={locked && !options.editable}/></label>;

  function selectTransport(next: string) {
    if (port === (transport === 'tls' ? '6514' : '514')) setPort(next === 'tls' ? '6514' : '514');
    setTransport(next);
  }

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fields = new FormData(e.currentTarget);
    const audit = fields.has('audit'), diagnostics = fields.has('diagnostics');
    if (fields.has('enabled') && !audit && !diagnostics) {setError('Select at least one event source.'); return;}
    setError('');
    const configKeys = kind === 'syslog' ? ['host'] : kind === 'splunk' ? ['url', 'index', 'sourcetype']
      : ['endpoint', 'rule_id', 'stream', 'tenant_id', 'client_id', 'cloud'];
    if (kind !== 'syslog' || transport === 'tls') configKeys.push('ca_pem');
    const values: Config = {};
    for (const key of configKeys) {
      const value = String(fields.get(key) ?? config[key] ?? '').trim();
      if (value) values[key] = value;
    }
    if (kind === 'syslog') {values.transport = transport; values.port = Number(port);}
    const secret = fields.get('secret');
    onSave({name: String(fields.get('name') ?? '').trim(), kind, config: values,
      enabled: fields.has('enabled'), audit, diagnostics, ...(typeof secret === 'string' && secret ? {secret} : {})});
  }

  return <form onSubmit={submit} aria-label={destination ? 'Edit log destination' : 'New log destination'}>
    <fieldset disabled={busy}><legend>{destination ? 'Edit destination' : 'Add destination'}</legend>
      <div className="config-grid">
        <label>Destination name<input name="name" required maxLength={120} defaultValue={destination?.name ?? ''}/></label>
        <label>Destination type<select value={kind} disabled={locked} onChange={e => {setKind(e.target.value as Kind); setError('');}}>
          {Object.entries(kinds).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      </div>
      {locked && <p className="muted">To send to a different receiver, add a destination.</p>}
      <div key={kind} className="config-grid">
        {kind === 'syslog' && <>
          {textField('host', 'Collector IP or hostname')}
          <label>Transport<select value={transport} disabled={locked} onChange={e => selectTransport(e.target.value)}>
            <option value="tls">TCP with TLS</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          <label>Port<input name="port" type="number" min={1} max={65535} step={1} required readOnly={locked} value={port} onChange={e => setPort(e.target.value)}/></label>
        </>}
        {kind === 'splunk' && <>
          {textField('url', 'HEC URL', {type: 'url', placeholder: 'https://splunk.example:8088'})}
          {textField('index', 'Index (optional)', {required: false})}
          {textField('sourcetype', 'Source type (optional)', {required: false, editable: true})}
        </>}
        {kind === 'azure' && <>
          {textField('endpoint', 'Logs ingestion endpoint', {type: 'url'})}
          {textField('rule_id', 'Data collection rule immutable ID', {placeholder: 'dcr-…'})}
          {textField('stream', 'Stream name', {placeholder: 'Custom-CatsAudit'})}
          {textField('tenant_id', 'Microsoft Entra tenant ID')}
          {textField('client_id', 'Application (client) ID')}
          <label>Azure cloud<select name="cloud" disabled={locked} defaultValue={config.cloud ?? 'public'}>
            <option value="public">Azure public</option><option value="government">Azure Government</option><option value="china">Azure China</option>
          </select></label>
        </>}
        {kind !== 'syslog' && <label>{kind === 'splunk' ? 'HEC token' : 'Client secret'}<input name="secret" type="password" maxLength={16384} autoComplete="new-password" required={!destination?.has_secret}/>
          {destination?.has_secret && <small>A credential is saved. Enter a replacement to rotate it or change the trusted CA.</small>}</label>}
      </div>
      {(kind !== 'syslog' || transport === 'tls') && <details><summary>Certificate authority</summary><label>Trusted CA certificate (PEM, optional)
        <textarea name="ca_pem" rows={4} defaultValue={config.ca_pem ?? ''} spellCheck={false}/></label></details>}
      <fieldset><legend>Event sources</legend>
        <label className="policy-check"><input name="audit" type="checkbox" defaultChecked={destination?.audit ?? true}/>Security audit trail</label>
        <label className="policy-check"><input name="diagnostics" type="checkbox" defaultChecked={destination?.diagnostics ?? false}/>Operational diagnostics</label>
      </fieldset>
      <label className="policy-check"><input name="enabled" type="checkbox" defaultChecked={destination?.enabled ?? true}/>Enable forwarding</label>
      {error && <p role="alert">{error}</p>}
      <div className="config-actions"><button type="submit">Save destination</button><button className="secondary-button" type="button" onClick={onCancel}>Cancel</button></div>
    </fieldset>
  </form>;
}

function ForwardingPanel({csrf}: {csrf: string}) {
  const [destinations, setDestinations] = useState<Destination[] | null>(null);
  const [editor, setEditor] = useState<Destination | 'new' | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [readError, setReadError] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    requestJson<{destinations: Destination[]}>(destinationsUrl, {signal: controller.signal}).then(result => {
      if (!controller.signal.aborted) {setDestinations(result.destinations); setReadError('');}
    }).catch(cause => {
      if (!controller.signal.aborted) setReadError(cause instanceof Error ? cause.message : 'Could not load destinations.');
    });
    return () => controller.abort();
  }, [revision]);

  async function mutate(action: () => Promise<string>) {
    if (busy) return;
    setBusy(true); setError(''); setNotice('');
    try {setNotice(await action());}
    catch (cause) {setError(cause instanceof Error ? cause.message : 'The destination request failed.');}
    finally {setBusy(false); setRevision(value => value + 1);}
  }
  const headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrf};
  function save(values: DestinationInput) {
    const editing = editor && editor !== 'new';
    void mutate(async () => {
      await requestJson(editing ? destinationsUrl + '/' + editor.id : destinationsUrl,
        {method: editing ? 'PUT' : 'POST', headers, body: JSON.stringify(values)});
      setEditor(null);
      return 'Destination saved.';
    });
  }
  function test(row: Destination) {
    void mutate(async () => {
      const result = await requestJson<{event_id: string}>(destinationsUrl + '/' + row.id + '/test', {method: 'POST', headers});
      return 'Test event queued for ' + row.name + '. Search the receiver for ' + result.event_id + '.';
    });
  }
  function replay(row: Destination) {
    if (!window.confirm('Forward retained audit history to ' + row.name + '?')) return;
    void mutate(async () => {
      await requestJson(destinationsUrl + '/' + row.id + '/replay', {method: 'POST', headers});
      return 'Retained audit replay requested for ' + row.name + '.';
    });
  }
  function remove(row: Destination) {
    const prompt = row.pending ? 'Remove ' + row.name + ' and discard its ' + row.pending + ' pending delivery copies? Original logs are retained.'
      : 'Remove ' + row.name + ' from log forwarding?';
    if (!window.confirm(prompt)) return;
    void mutate(async () => {
      const query = row.pending ? '?discard_count=' + row.pending : '';
      await requestJson(destinationsUrl + '/' + row.id + query, {method: 'DELETE', headers});
      setEditor(null);
      return 'Destination removed.';
    });
  }

  return <section id="log-forwarding" className="panel padded configuration-panel" aria-label="Log forwarding">
    <h2>Log forwarding</h2><p>Send events from all CATS groups to one or more receivers.</p>
    <div className="config-actions"><button type="button" disabled={busy || editor !== null} onClick={() => {setError(''); setNotice(''); setEditor('new');}}>Add destination</button>
      <button type="button" className="secondary-button" disabled={busy} onClick={() => setRevision(value => value + 1)}>Refresh status</button></div>
    {readError && <p role="alert">{readError}</p>}
    {error && <p role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {editor && <DestinationEditor key={editor === 'new' ? 'new' : editor.id} destination={editor === 'new' ? undefined : editor} busy={busy} onSave={save} onCancel={() => {setEditor(null); setError('');}}/>}
    {destinations === null && !readError && <p role="status">Loading destinations.</p>}
    {destinations?.length === 0 && !editor && <p>No forwarding destinations configured.</p>}
    {!!destinations?.length && <div className="diagnostic-table-scroll"><table>
      <thead><tr><th>Destination</th><th>Sources</th><th>Delivery status</th><th>Actions</th></tr></thead>
      <tbody>{destinations.map(row => <tr key={row.id}>
        <td><strong>{row.name}</strong><br/>{kinds[row.kind]}<br/><small>{row.kind === 'syslog' ? row.config.host + ':' + row.config.port : row.config.url || row.config.endpoint}</small></td>
        <td>{[row.audit && 'Security audit', row.diagnostics && 'Diagnostics'].filter(Boolean).join(', ')}</td>
        <td>{row.enabled ? 'Enabled' : 'Paused'} · {row.pending} queued<br/>Last sent: {row.last_sent_at ? <time dateTime={row.last_sent_at}>{new Date(row.last_sent_at).toLocaleString()}</time> : 'Never'}
          {row.last_error && <p>Last error: {row.last_error}</p>}</td>
        <td><div className="config-actions"><button type="button" className="secondary-button" disabled={busy || editor !== null} onClick={() => {setError(''); setNotice(''); setEditor(row);}}>Edit</button>
          <button type="button" className="secondary-button" disabled={busy || editor !== null} onClick={() => test(row)}>Send test event</button>
          {row.enabled && row.audit && <button type="button" className="secondary-button" disabled={busy || editor !== null} onClick={() => replay(row)}>Replay retained audit</button>}
          {!row.enabled && <button type="button" className="secondary-button" disabled={busy || editor !== null} onClick={() => remove(row)}>Remove</button>}</div></td>
      </tr>)}</tbody></table></div>}
  </section>;
}

export function LogForwarding({data}: {data: PageData}) {
  return data.may_manage_log_forwarding === true ? <ForwardingPanel csrf={data.csrf_token ?? ''}/> : null;
}
