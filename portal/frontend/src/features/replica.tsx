import {OverrideIndicator} from '../components/OverrideIndicator';
import {useEffect, useState, type FormEvent} from 'react';
import {can, requestJson, type PageData} from '../api';
import {ServiceTabs} from '../components/ServiceHeader';
import {StatusBadge} from '../components/ui';

type Row = Record<string, any>;
const date = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : '—';
const errorText = (error: unknown) => error instanceof Error ? error.message : 'The operation failed.';
const rows = (value: any): Row[] => Array.isArray(value) ? value : value?.releases || value?.items || [];

function useResource<T>(url: string) {
  const [value, setValue] = useState<T | null>(null), [error, setError] = useState(''), [version, setVersion] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    requestJson<T>(url, {signal: controller.signal}).then(value => {if (!controller.signal.aborted) {setValue(value); setError('');}})
      .catch(error => {if (!controller.signal.aborted) setError(errorText(error));});
    return () => controller.abort();
  }, [url, version]);
  return {value, error, reload: () => setVersion(version => version + 1)};
}
async function mutate(data: PageData, url: string, body: Row, method = 'POST') {
  return requestJson<Row>(url, {method, headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: JSON.stringify(body)});
}
function ErrorMessage({error}: {error: string}) {return error ? <p className="error" role="alert">{error}</p> : null;}
function SourceFields({source, upstreams}: {source?: Row; upstreams: Row[]}) {
  return <><label>Name<input name="name" defaultValue={source?.name} required/></label><label>Local registry<select name="upstream_id" defaultValue={source?.upstream_id || ''} required><option value="">Select a registry</option>{source && !upstreams.some(row => row.id === source.upstream_id) && <option value={source.upstream_id}>Registry #{source.upstream_id} (existing)</option>}{upstreams.map(row => <option key={row.id} value={row.id}>{row.name} — {row.endpoint}</option>)}</select></label><label>Release repository<input name="repository" defaultValue={source?.repository} placeholder="approved/service/releases or approved/*" required/></label><label>Trusted publisher fingerprints<textarea name="trusted_publishers" defaultValue={source?.trusted_publishers?.join('\n')} placeholder="Comma or space separated SHA-256 signing-key fingerprints" required/></label><label>Synchronization interval (seconds)<input type="number" name="poll_seconds" min="10" max="86400" defaultValue={source?.poll_seconds || 300} required/></label><p>Obtain publisher fingerprints independently from a trusted administrator. Keys included with releases must match these pins. Expiration and revocation are enforced locally.</p>{source && <p>A source with imported services keeps its registry and repository binding. Add a separate source for a different registry or scope.</p>}</>;
}

export function Page({data}: {data: PageData}) {
  const status = useResource<Row>('/api/replica/status'), upstreams = useResource<Row[]>('/api/oci/upstreams');
  const [error, setError] = useState(''), [notice, setNotice] = useState(''), [busy, setBusy] = useState(false);
  const administer = can(data, 'replica.admin'), configureRegistry = can(data, 'release.destination.manage');
  const run = async (action: () => Promise<unknown>, success: string) => {
    setBusy(true); setError(''); setNotice('');
    try {await action(); setNotice(success); status.reload(); upstreams.reload();} catch (error) {setError(errorText(error));} finally {setBusy(false);}
  };
  const registry = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = event.currentTarget, values = new FormData(form);
    void run(async () => {await mutate(data, '/api/oci/upstreams', Object.fromEntries(values)); form.reset();}, 'Local registry saved.');
  };
  const source = (event: FormEvent<HTMLFormElement>, existing?: Row) => {
    event.preventDefault(); const form = event.currentTarget, values = new FormData(form);
    void run(async () => {await mutate(data, existing ? `/api/replica/sources/${existing.id}` : '/api/replica/sources', {name: values.get('name'), repository: values.get('repository'),
      upstream_id: Number(values.get('upstream_id')), trusted_publishers: String(values.get('trusted_publishers') || '').split(/[\s,]+/).filter(Boolean),
      poll_seconds: Number(values.get('poll_seconds')), enabled: existing ? existing.enabled : true}, existing ? 'PUT' : 'POST'); if (!existing) form.reset();}, 'Release source saved.');
  };
  return <><section className="heading"><div><p className="eyebrow">LOCAL OPERATIONS</p><h1>Replica administration</h1><p>Discover signed releases from this environment’s registry. No connection to the publishing CATS system is required.</p></div>
    <div><button type="button" className="secondary-button" onClick={status.reload}>Refresh status</button>{can(data, 'replica.sync') && <button type="button" disabled={busy} onClick={() => void run(() => mutate(data, '/api/replica/sync', {source_id: null}), 'Synchronization queued.')}>Synchronize now</button>}</div></section>
    <nav aria-label="Replica administration"><a href="/admin">Accounts and roles</a> · <a href="/admin/approved-release-destinations">Registry access and proxy</a> · <a href="/admin/configuration">Authentication and trust</a> · <a href="/admin/audit">Audit</a></nav>
    <ErrorMessage error={error || status.error}/>{notice && <p role="status">{notice}</p>}
    <section className="panel padded"><h2>Release sources</h2>{!status.value && !status.error && <p role="status">Loading replication health…</p>}
      {status.value?.sources?.length ? <div className="table-scroll"><table><thead><tr><th>Source</th><th>Repository</th><th>Polling</th><th>Health</th><th>Last synchronization</th><th>Actions</th></tr></thead><tbody>{status.value.sources.map((row: Row) => <tr key={row.id}><td>{row.name}</td><td><code>{row.repository}</code></td><td>{row.poll_seconds} seconds</td><td><StatusBadge value={row.enabled ? row.last_error ? 'failed' : 'enabled' : 'disabled'}/>{row.last_error && <p>{row.last_error}</p>}</td><td>{date(row.last_success_at || row.last_sync_at)}</td><td>{can(data, 'replica.sync') && <button disabled={busy || !row.enabled} onClick={() => void run(() => mutate(data, '/api/replica/sync', {source_id: row.id}), 'Synchronization queued.')}>Synchronize</button>}{administer && <button disabled={busy} onClick={() => void run(() => mutate(data, `/api/replica/sources/${row.id}`, {enabled: !row.enabled}, 'PUT'), 'Source updated.')}>{row.enabled ? 'Disable' : 'Enable'}</button>}</td></tr>)}</tbody></table></div> : status.value && <p>No release sources configured.</p>}
      {administer && <><details><summary>Add release source</summary><form onSubmit={event => source(event)} className="form-grid"><SourceFields upstreams={upstreams.value || []}/><button disabled={busy}>Save source</button></form></details>{status.value?.sources?.map((row: Row) => <details key={row.id}><summary>Edit {row.name}</summary><form onSubmit={event => source(event, row)} className="form-grid"><SourceFields source={row} upstreams={upstreams.value || []}/><button disabled={busy}>Update {row.name}</button></form></details>)}</>}
    </section>
    {configureRegistry && <section className="panel padded"><h2>Local registries</h2><ErrorMessage error={upstreams.error}/>{upstreams.value?.map(row => <p key={row.id}><strong>{row.name}</strong> · {row.endpoint} · Credentials {row.credentials_configured ? 'configured' : 'not configured'} · Custom CA {row.ca_configured ? 'configured' : 'not configured'}</p>)}<details><summary>Add local registry</summary><form onSubmit={registry} className="form-grid"><label>Name<input name="name" required/></label><label>HTTPS endpoint<input name="endpoint" type="url" placeholder="https://registry.local" required/></label><label>Username<input name="username" autoComplete="off"/></label><label>Password or robot token<input name="password" type="password" autoComplete="new-password"/></label><label>Trusted CA certificates (PEM)<textarea name="ca_pem"/></label><button disabled={busy}>Save registry</button></form></details></section>}
    <section className="panel padded"><h2>Synchronization history and import failures</h2>{status.value?.jobs?.length ? <div className="table-scroll"><table><thead><tr><th>Created</th><th>Stage</th><th>Status</th><th>Details</th></tr></thead><tbody>{status.value.jobs.map((row: Row) => <tr key={row.id}><td>{date(row.created_at)}</td><td>{row.stage || '—'}</td><td><StatusBadge value={row.status}/></td><td>{row.error || row.message || row.detail || '—'}</td></tr>)}</tbody></table></div> : <p>No synchronization attempts recorded.</p>}</section>
    <section className="panel padded"><h2>Imported services</h2>{status.value?.services?.map((row: Row) => <p key={row.id || row.service_id}><a href={`/services/${encodeURIComponent(row.service_key || row.source_service_id)}`}>{row.service_name || row.service_key || row.source_service_id}</a> · Sequence {row.high_sequence} · Last synchronized {date(row.last_sync_at)}</p>) || null}<a href="/approved-releases">View release history and expiration</a></section>
  </>;
}

export function Releases({data: _data}: {data: PageData}) {
  const service = new URLSearchParams(window.location.search).get('service') || '';
  const resource = useResource<Row[] | Row>(`/api/replica/releases${service ? `?service_key=${encodeURIComponent(service)}` : ''}`);
  return <><section className="heading"><div><p className="eyebrow">VERIFIED OCI EVIDENCE</p><h1>Imported approved releases</h1><p>Release authorization, expiration and history are preserved from the publishing system. Mission-continuity overrides are shown separately.</p></div><button onClick={resource.reload}>Refresh</button></section>{service && <ServiceTabs serviceKey={service} active="releases"/>}<ErrorMessage error={resource.error}/>{!resource.value && !resource.error && <p role="status">Loading releases…</p>}{resource.value && !rows(resource.value).length && <p>No verified releases have been imported.</p>}{rows(resource.value).map(row => <section className="panel padded" key={row.id}><h2><a href={`/services/${encodeURIComponent(row.service_key || '')}`}>{row.service_name || row.service_key || `Service ${row.service_id}`}</a> · Release {row.sequence}</h2><StatusBadge value={row.status}/><OverrideIndicator serviceKey={row.service_key} releaseId={row.id}/><dl className="kv-grid"><div><dt>Approved</dt><dd>{date(row.approved_at)}</dd></div><div><dt>Expires</dt><dd>{date(row.expires_at)}</dd></div><div><dt>Revoked</dt><dd>{date(row.revoked_at)}</dd></div><div><dt>Imported</dt><dd>{date(row.imported_at)}</dd></div><div><dt>Publisher</dt><dd><code>{row.publisher}</code></dd></div><div><dt>Signed manifest</dt><dd><code>{row.manifest_digest}</code></dd></div></dl>{row.evidence_url && <p><a href={row.evidence_url}>Download immutable release evidence</a></p>}<p><a href={`/services/${encodeURIComponent(row.service_key || '')}/cyber-overrides?release_id=${row.id}`}>Cyber overrides and enforcement history</a></p><details><summary>Approved artifact inventory ({row.artifacts?.length || 0})</summary>{row.artifacts?.map((artifact: Row, index: number) => <p key={artifact.digest || index}><code>{artifact.repository || artifact.name || artifact.reference} {artifact.digest}</code>{artifact.proxy_repositories?.map((repository: string) => <span className="cell-stack" key={repository}>Local pull path: <code>{repository}@{artifact.digest}</code></span>)}</p>)}</details></section>)}</>;
}

export function Overrides({data}: {data: PageData}) {
  const service = data.service, base = `/api/services/${encodeURIComponent(service.service_key)}/local-overrides`;
  const resource = useResource<Row>(base), releases = useResource<Row[] | Row>(`/api/replica/releases?service_id=${service.id}`);
  const [error, setError] = useState(''), [busy, setBusy] = useState(false), [notice, setNotice] = useState('');
  const [uses, setUses] = useState<Record<string, Row[]>>({});
  const params = new URLSearchParams(window.location.search);
  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form = event.currentTarget, values = new FormData(form); setBusy(true); setError(''); setNotice('');
    try {
      const body: Row = Object.fromEntries(values);
      body.release_id = Number(body.release_id); body.digest = body.digest || null;
      body.expires_at = body.expires_at ? new Date(body.expires_at).toISOString() : null;
      body.review_at = body.review_at ? new Date(body.review_at).toISOString() : null;
      body.elevated_risk_acknowledged = values.has('elevated_risk_acknowledged');
      await mutate(data, base, body); form.reset(); resource.reload(); setNotice('Local Cyber override created. Authoritative release approval is unchanged.');
    } catch (error) {setError(errorText(error));} finally {setBusy(false);}
  };
  const revoke = async (event: FormEvent<HTMLFormElement>, id: number) => {
    event.preventDefault(); const values = new FormData(event.currentTarget); setBusy(true); setError('');
    try {await mutate(data, `${base}/${id}/revoke`, {reason: values.get('reason')}); resource.reload(); setNotice('Override revoked. Subsequent pulls must satisfy normal policy or another valid override.');}
    catch (error) {setError(errorText(error));} finally {setBusy(false);}
  };
  return <><a className="back" href={`/services/${encodeURIComponent(service.service_key)}`}>Back to {service.name}</a><section className="heading"><div><p className="eyebrow">LOCAL CYBER AUTHORITY</p><h1>Cyber overrides · {service.name}</h1><p>Mission-continuity exceptions accept specific policy failures. They never bypass signature, digest, publisher trust or evidence integrity checks.</p></div><button onClick={resource.reload}>Refresh</button></section><ServiceTabs serviceKey={service.service_key} active="overrides"/><ErrorMessage error={error || resource.error || releases.error}/>{notice && <p role="status">{notice}</p>}
    {can(data, 'local_override.create', service.id) && <details open={params.has('release_id') || params.has('digest')} className="panel padded"><summary>Create mission-continuity override</summary><form onSubmit={event => void create(event)} className="form-grid"><label>Imported release<select name="release_id" defaultValue={params.get('release_id') || ''} required><option value="">Select a release</option>{rows(releases.value).map(row => <option key={row.id} value={row.id}>Release {row.sequence} · {row.status}</option>)}</select></label><label>Policy failure<select name="denial_condition" defaultValue={params.get('denial_condition') || 'superseded'}><option value="superseded">Superseded release</option><option value="expired">Expired release</option><option value="revoked">Revoked release</option></select></label><label>Specific digest (blank applies to the exact signed release inventory)<input name="digest" pattern="sha256:[a-f0-9]{64}" defaultValue={params.get('digest') || ''} placeholder="sha256:…"/></label><label>Mission impact<textarea name="mission_impact" required/></label><label>Justification<textarea name="justification" required/></label><label>Explicit risk acceptance<textarea name="risk_acceptance" required/></label><label>Expires (blank means indefinite)<input type="datetime-local" name="expires_at"/></label><label>Review date (optional)<input type="datetime-local" name="review_at"/></label><label><input type="checkbox" name="elevated_risk_acknowledged"/>I acknowledge the elevated risk of overriding a revoked release.</label><button disabled={busy}>Create local Cyber override</button></form></details>}
    {resource.value && !resource.value.overrides?.length && <p>No local Cyber overrides.</p>}{resource.value?.overrides?.map((row: Row) => <article key={row.id} className="panel padded"><h2>Override #{row.id} · Release {row.release_id}</h2><StatusBadge value={row.status}/>{row.status === 'active' && <p><strong>Mission-continuity exception — normal approval remains {row.denial_condition}.</strong></p>}<dl className="kv-grid"><div><dt>Duration</dt><dd>{row.expires_at ? `Until ${date(row.expires_at)}` : 'Indefinite — explicit revocation required'}</dd></div><div><dt>Approver</dt><dd>{row.created_by_display_name || row.created_by_username || row.created_by_id}</dd></div><div><dt>Created</dt><dd>{date(row.created_at)}</dd></div><div><dt>Last usage</dt><dd>{date(row.last_usage_at)}</dd></div><div><dt>Review</dt><dd>{date(row.review_at)}</dd></div></dl><h3>Mission impact</h3><p>{row.mission_impact}</p><h3>Justification</h3><p>{row.justification}</p><h3>Risk acceptance</h3><p>{row.risk_acceptance}</p><details><summary>Authorized immutable digests ({row.digests?.length || 0})</summary>{row.digests?.map((digest: string) => <p key={digest}><code>{digest}</code></p>)}</details>{row.revocation && <p>Revoked {date(row.revocation.revoked_at)} by account {row.revocation.revoked_by_id}: {row.revocation.reason}</p>}{row.status === 'active' && can(data, 'local_override.revoke', service.id) && <form onSubmit={event => void revoke(event, row.id)}><label>Revocation reason<input name="reason" required/></label><button disabled={busy}>Revoke immediately</button></form>}{can(data, 'local_override.view_audit', service.id) && <button onClick={() => void requestJson<Row | Row[]>(`${base}/${row.id}/uses`).then(value => setUses(previous => ({...previous, [row.id]: Array.isArray(value) ? value : value.uses || []}))).catch(error => setError(errorText(error)))}>View usage history</button>}{uses[row.id]?.map((use, index) => <p key={use.id || index}>{date(use.created_at)} · <code>{use.digest || use.detail?.digest}</code> · {use.action || 'Override used'}</p>)}</article>)}</>;
}
