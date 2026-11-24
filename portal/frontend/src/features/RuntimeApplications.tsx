import {useEffect, useState} from 'react';
import {requestJson} from '../api';

type Service = {id: number; name: string};
type Application = {id: number; name: string; namespace: string; environment: string; environment_id: number;
  cluster_role: string; present: boolean; fingerprint: string; service_id: number | null; service: string | null;
  discovered_at: string; last_observed_at: string; components: Record<string, string>[]; can_assign: boolean;
  can_create: boolean; assignment_blocker?: string; services: Service[]; suggestions: {service_id: number; confidence: string; evidence: string[]}[]};
type Candidate = {id: number; environment: string; service: string; namespace: string; version: number;
  proposed_version: string; current: boolean; approval_id: number | null; status: string; assessment_status: string; href: string | null};
type Inventory = {applications: Application[]; candidates: Candidate[]; next_offset: number | null};

function ApplicationDetails({app, csrf, refresh}: {app: Application; csrf: string; refresh: () => void}) {
  const [target, setTarget] = useState(''), [key, setKey] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function assign() {
    setBusy(true);
    setError('');
    try {
      await requestJson('/api/runtime/applications/' + app.id + '/assignment', {method: 'POST',
        headers: {'X-CSRF-Token': csrf, 'Content-Type': 'application/json'}, body: JSON.stringify({
          expected_fingerprint: app.fingerprint, expected_service_id: app.service_id,
          ...(target === 'new' ? {new_service_key: key} : {service_id: Number(target)})})});
      setTarget('');
      refresh();
    } catch (e) {setError(e instanceof Error ? e.message : 'Assignment failed.');}
    finally {setBusy(false);}
  }
  return <details className="panel">
    <summary><strong>{app.name}</strong> · {app.environment} / {app.namespace} · {app.service || 'Unassigned'}{!app.present && ' · No longer observed'}</summary>
    <p>{app.cluster_role} cluster · First seen {new Date(app.discovered_at).toLocaleString()} · Last seen {new Date(app.last_observed_at).toLocaleString()}</p>
    <div className="table-wrap"><table><caption>Discovered components</caption><thead><tr><th>Workload</th><th>Container</th><th>Image and digest</th><th>Helm release and chart</th></tr></thead>
      <tbody>{app.components.map((c, i) => <tr key={i}><td>{c.workload_kind} {c.workload}</td><td>{c.container} {c.container_kind}</td>
        <td>{c.desired_image || c.image_ref}<br/><code>{c.image_id || 'Runtime digest unavailable'}</code></td>
        <td>{[c.helm_release, c.chart_name, c.chart_version].filter(Boolean).join(' · ') || '—'}{c.chart_digest && <p><code>{c.chart_digest}</code></p>}</td></tr>)}</tbody></table></div>
    {app.suggestions.length > 0 && <ul aria-label="Suggested services">{app.suggestions.map(s =>
      <li key={s.service_id}>{app.services.find(v => v.id === s.service_id)?.name} · {s.confidence} confidence · {s.evidence.join(', ')}</li>)}</ul>}
    {app.assignment_blocker && <p>{app.assignment_blocker}</p>}
    {app.can_assign && <form onSubmit={event => {event.preventDefault(); void assign();}}>
      <label>Assign to service<select required value={target} onChange={event => setTarget(event.target.value)}>
        <option value="">Select a service</option>{app.services.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
        {app.can_create && <option value="new">Create a new service</option>}</select></label>
      {target === 'new' && <label>New service key<input required maxLength={120} value={key} onChange={event => setKey(event.target.value)}/></label>}
      <button disabled={busy || !target}>{target === 'new' ? 'Create service and assign' : 'Assign application'}</button>
      {error && <p role="alert">{error}</p>}</form>}
  </details>;
}

export function RuntimeApplications({csrf, replica = false}: {csrf: string; replica?: boolean}) {
  const [open, setOpen] = useState(() => new URLSearchParams(window.location.search).has('runtime_applications'));
  const [data, setData] = useState<Inventory>(), [error, setError] = useState('');
  const [offset, setOffset] = useState(0), [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    setData(undefined);
    setError('');
    requestJson<Inventory>('/api/runtime/applications?offset=' + offset, {signal: controller.signal})
      .then(value => {if (!controller.signal.aborted) setData(value);})
      .catch(e => {if (!controller.signal.aborted) setError(e instanceof Error ? e.message : 'Inventory could not be loaded.');});
    return () => controller.abort();
  }, [open, offset, revision]);
  const details = (app: Application) => <ApplicationDetails key={app.id} app={app} csrf={csrf} refresh={() => setRevision(n => n + 1)}/>;
  return <section id="runtime-applications" className="panel">
    <button className="secondary-button" aria-expanded={open} onClick={() => setOpen(!open)}>{replica ? 'Discovered applications' : 'Discovered applications and release candidates'}</button>
    {open && <div><h2>Unassigned applications</h2>
      {error && <p role="alert">{error}</p>}{!error && !data && <p role="status">Loading inventory…</p>}
      {data && <>
        {!data.applications.some(a => !a.service_id) && <p>No unassigned applications on this page.</p>}
        {data.applications.filter(a => !a.service_id).map(details)}
        {data.applications.some(a => a.service_id) && <><h2>Service associations</h2>{data.applications.filter(a => a.service_id).map(details)}</>}
        {data.candidates.length > 0 && <><h2>Release candidates</h2><table><thead><tr><th>Service and version</th><th>Source</th><th>Assessment</th><th>Review</th></tr></thead>
          <tbody>{data.candidates.map(c => <tr key={c.id}><td>{c.service} · {c.proposed_version}</td>
              <td>{c.environment} / {c.namespace}</td><td>{c.assessment_status}</td>
              <td>{c.href ? <a href={c.href}>Revision {c.version}</a> : <>Revision {c.version}</>} · {!c.current && !c.approval_id ? 'Superseded' : c.status}</td></tr>)}</tbody></table></>}
        {offset > 0 && <button onClick={() => setOffset(Math.max(0, offset - 50))}>Previous page</button>}
        {data.next_offset != null && <button onClick={() => setOffset(data.next_offset!)}>Next page</button>}</>}
      <button className="secondary-button" onClick={() => setRevision(n => n + 1)}>Refresh inventory</button>
    </div>}
  </section>;
}
