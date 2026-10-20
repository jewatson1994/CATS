import {VexEvidence} from './native_vex';
import {useEffect, useState, type FormEvent} from 'react';
import {can, requestJson, type PageData} from '../api';
import {StatusBadge} from '../components/ui';
import {ServiceTabs} from '../components/ServiceHeader';
import {AdminTabs, Heading} from './admin_shared';
import './cyber_approvals.css';
import {ApprovalFindings} from './approval_findings';

type Row = Record<string, any>;
const variantLabel = (variant: string) => variant === 'cats_remediated' ? 'CATS Remediated' : 'Current Service';
const message = (error: unknown) => error instanceof Error ? error.message : 'The request could not be completed.';
const list = (value: any): Row[] => Array.isArray(value) ? value : value?.items || [];
const label = (value: any): string => value == null ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value);
function useResource(url: string) {
  const [value, setValue] = useState<Row | null>(null), [error, setError] = useState(''), [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setValue(null); setError('');
    requestJson<Row>(url, {signal: controller.signal}).then(value => {if (!controller.signal.aborted) setValue(value);}).catch(error => {if (!controller.signal.aborted) setError(message(error));});
    return () => controller.abort();
  }, [url, revision]);
  return {value, error, refresh: () => setRevision(value => value + 1)};
}
async function mutate(data: PageData, url: string, body: Row) {
  return requestJson<Row>(url, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: JSON.stringify(body)});
}
function PublicationDiagnostic({publication}: {publication: Row}) {
  const diagnostic = publication.diagnostic;
  if (!diagnostic && !publication.correlation_id) return null;
  return <dl className="approval-metadata" aria-label="Publication failure details">
    {diagnostic?.stage && <div><dt>Failed step</dt><dd>{label(diagnostic.stage)}</dd></div>}
    {diagnostic?.cause && <div><dt>Cause</dt><dd>{label(diagnostic.cause)}</dd></div>}
    {diagnostic?.http_status != null && <div><dt>Registry HTTP status</dt><dd>{label(diagnostic.http_status)}</dd></div>}
    {diagnostic?.exit_code != null && <div><dt>Tool exit code</dt><dd>{label(diagnostic.exit_code)}</dd></div>}
    {diagnostic?.os_error != null && <div><dt>System error number</dt><dd>{label(diagnostic.os_error)}</dd></div>}
    {publication.correlation_id && <div><dt>Correlation ID</dt><dd><code>{label(publication.correlation_id)}</code></dd></div>}
  </dl>;
}
function ResourceState({error, pending}: {error: string; pending: boolean}) {
  return error ? <p className="error" role="alert">{error}</p> : pending ? <p role="status">Loading…</p> : null;
}
const currentApproval = (row: Row) => ['valid', 'expiring_soon'].includes(row.validity_status);
function Badges({row}: {row: Row}) {
  return <div className="approval-badges">{row.revoked && <StatusBadge value="revoked" label="Revoked" tone="danger"/>}<span>Cyber decision: <StatusBadge value={row.status || 'pending'}/></span><span>Publication: <StatusBadge value={row.publish_status || 'not_started'}/></span>{row.status === 'approved' && <span>Authorization: <StatusBadge value={row.validity_status || 'reapproval_required'} label={(row.validity_status || 'reapproval_required').replaceAll('_', ' ')}/></span>}{row.expires_at && <span>Expires: {new Date(row.expires_at).toLocaleString()}</span>}</div>;
}
function EvidenceSection({title, value}: {title: string; value: any}) {
  const [open, setOpen] = useState(false);
  const rows = value == null ? [] : Array.isArray(value) ? value : [value];
  return <details className="approval-support-section" open={open} onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>{title} <span className="approval-count">{rows.length.toLocaleString()}</span></summary>
    {open && <div>{!rows.length ? <p>None recorded in this snapshot.</p> : rows.map((row, index) => <details key={index} className="approval-evidence"><summary>{typeof row === 'object' && row !== null ? row.cve || row.title || row.name || row.finding || row.image || row.reference || row.ref || `Record ${index + 1}` : label(row)}</summary>{typeof row === 'object' && row !== null ? <dl className="approval-metadata">{Object.entries(row).map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{label(value)}</dd></div>)}</dl> : <p>{label(row)}</p>}</details>)}</div>}
  </details>;
}
const dateLabel = (value: any) => !value ? 'Not recorded' : Number.isNaN(Date.parse(value)) ? label(value) : new Date(value).toLocaleString();
function SnapshotDetails({snapshot}: {snapshot: Row}) {
  const [open, setOpen] = useState(false);
  return <details className="approval-support-section" onToggle={event => setOpen(event.currentTarget.open)}><summary>Complete snapshot</summary>{open && <pre className="approval-json">{JSON.stringify(snapshot, null, 2)}</pre>}</details>;
}

function ServiceAtAGlance({snapshot}: {snapshot: Row}) {
  const [expanded, setExpanded] = useState(false);
  const overview = snapshot.overview || {};
  const context = snapshot.service_context || {};
  const architecture = context.architecture;
  const deploymentTypes = Array.isArray(context.deployment_types) ? context.deployment_types : [];
  const componentLabel = (kind: string) => kind.replace(/^Compose/, 'Compose ').replace(/([a-z])([A-Z])/g, '$1 $2');
  const ports: Row[] = Array.isArray(overview.ports) ? overview.ports.filter((port: any) => port && typeof port === 'object') : [];
  const artifacts: Row[] | null = Array.isArray(snapshot.artifacts) ? snapshot.artifacts : Array.isArray(overview.artifacts) ? overview.artifacts : null;
  const count = (kind: string) => artifacts?.filter(item => String(item.kind || item.type).toLowerCase() === kind).length;
  return <section className="panel padded approval-service-summary" aria-label="Service at a glance">
    <div className="approval-service-title"><div><h2>Service at a glance</h2><p className="approval-muted">Declared configuration in this review snapshot · network reachability is not verified.</p></div>
      <div className="approval-service-counts">{artifacts ? <><span className="approval-count">{count('image')} images</span><span className="approval-count">{count('chart')} Helm charts</span></> : <span className="approval-muted">Artifact inventory not recorded</span>}</div>
    </div>
    <div className="approval-service-context">
      <div><h3>Purpose</h3><p>{context.description || 'Description not recorded in this snapshot.'}</p></div>
      <dl><div><dt>Owner</dt><dd>{context.owner || 'Not recorded'}</dd></div><div><dt>Deployment type</dt><dd>{deploymentTypes.length ? deploymentTypes.join(' + ') : 'Not recorded'}{deploymentTypes.length === 1 && deploymentTypes[0] === 'Container images' && <small>Deployment configuration not recorded</small>}</dd></div></dl>
    </div>
    <div className="approval-architecture-summary"><h3>Architecture at a glance</h3>
      {architecture ? <><div className="approval-service-counts">{Object.entries(architecture.components || {}).map(([kind, count]) => <span className="approval-count" key={kind}>{String(count)} {componentLabel(kind)}</span>)}<span className="approval-count">{architecture.relationships} relationships</span></div>
        <p className="approval-muted">Declared configuration · runtime reachability is not verified.{architecture.incomplete ? ' Coverage is incomplete; review retained evidence.' : ''}{architecture.unresolved > 0 ? ` ${architecture.unresolved} components have no established relationship.` : ''}</p></>
        : <p className="approval-muted">Architecture was not recorded in this snapshot.</p>}
    </div>
    <h3>Ports &amp; protocols <span className="approval-count">{ports.length ? ports.length.toLocaleString() : 'Not recorded'}</span></h3>
    {ports.length ? <><div className="approval-ports-wrap"><table className="approval-ports-table"><caption className="approval-muted">{overview.source || 'Retained service configuration'}</caption><thead><tr><th>Service / workload</th><th>Port</th><th>Protocol</th><th>Declaration / boundary</th></tr></thead><tbody>
      {(expanded ? ports : ports.slice(0, 6)).map((port, index) => <tr key={index}><td>{port.service || 'Not recorded'}{port.namespace && <small>{port.namespace}</small>}</td><td>{port.port || 'Not recorded'}</td><td>{port.protocol || 'Not recorded'}</td><td>{port.declared_by && port.declared_by !== '—' ? port.declared_by : 'Not recorded'}{port.boundary && <small>{port.boundary}</small>}{port.fqdn && <small>{port.fqdn}</small>}{port.source_file && <small>{port.source_file}</small>}</td></tr>)}
    </tbody></table></div>{ports.length > 6 && <button type="button" className="approval-ports-toggle" aria-expanded={expanded} onClick={() => setExpanded(value => !value)}>{expanded ? 'Show fewer ports' : `Show all ${ports.length} port declarations`}</button>}</> : <p className="approval-muted">Ports and protocols were not recorded in this snapshot. This does not establish that the service has no network exposure.</p>}
  </section>;
}

export function RequestApproval({data, serviceKey}: {data: PageData; serviceKey: string}) {
  const [selection, setSelection] = useState('current_service'), [candidates, setCandidates] = useState<Row[]>([]);
  const variant = selection === 'current_service' ? 'current_service' : 'cats_remediated';
  const remediation = variant === 'cats_remediated' ? selection.slice('cats_remediated:'.length) : '';
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [created, setCreated] = useState<Row | null>(null);
  const query = new URLSearchParams({variant});
  if (remediation) query.set('remediation_id', remediation);
  const readiness = useResource(`/api/services/${encodeURIComponent(serviceKey)}/cyber-approval-readiness?${query}`);
  const ready = readiness.value;
  useEffect(() => {if (ready) setCandidates(list(ready.remediations));}, [ready]);
  const allowed = ready?.can_request ?? data.can_request ?? can(data, 'approval.request', ready?.service_id ?? data.service?.id);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (!ready?.ready || !allowed || busy) return;
    setBusy(true); setError('');
    try {setCreated(await mutate(data, '/api/cyber-approvals', {service_key: serviceKey, variant, remediation_id: remediation || undefined}));}
    catch (error) {setError(message(error)); readiness.refresh();} finally {setBusy(false);}
  };
  if (created) return <section className="panel padded"><h2>Cyber approval requested</h2><p role="status">The snapshot is ready for Cyber review.</p><a href={`/cyber-approvals?id=${encodeURIComponent(created.id)}`}>Review request #{created.id}</a></section>;
  return <section className="panel padded"><h2>Request Cyber Approval</h2><p>Choose the release to submit. Cyber reviews vulnerabilities, configuration coverage, mitigations, exceptions and deployment verification.</p><form className="approval-form" onSubmit={submit}><label>Release variant<select disabled={busy} value={selection} onChange={event => setSelection(event.target.value)}><option value="current_service">Current Service</option>{candidates.map(row => <option key={row.id} value={`cats_remediated:${row.id}`}>CATS Remediated · {row.label || row.id}</option>)}</select></label><ResourceState error={readiness.error} pending={!ready && !readiness.error}/>{ready && <><div className="approval-readiness" role="status"><StatusBadge value={ready.ready ? 'ready' : 'blocked'} label={ready.ready ? 'Ready for Cyber review' : 'Evidence incomplete'}/><p>Version: {ready.version || 'Unknown'} · Scan date: {ready.scan_date || 'Not recorded'}</p>{!!ready.blockers?.length && <ul>{ready.blockers.map((reason: string, index: number) => <li key={index}>{reason}</li>)}</ul>}</div>{!allowed && <p>You do not have permission to request Cyber approval for this service.</p>}</>}<ResourceState error={error} pending={false}/><button disabled={busy || !ready?.ready || !allowed}>{busy ? 'Submitting…' : 'Request Cyber Approval'}</button></form></section>;
}

function Decision({data, row, refresh}: {data: PageData; row: Row; refresh: () => void}) {
  const [decision, setDecision] = useState('approved'), [rationale, setRationale] = useState(''), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [destination, setDestination] = useState('');
  const selectedDestination = destination || String(list(row.destinations)[0]?.id || '');
  if (!row.can_decide || row.status !== 'pending') return null;
  async function submit(event: FormEvent) {
    event.preventDefault(); if (!rationale.trim()) return; setBusy(true); setError('');
    try {await mutate(data, `/api/cyber-approvals/${row.id}/decision`, {decision, rationale: rationale.trim(), ...(selectedDestination ? {destination_id:Number(selectedDestination)} : {})}); refresh();}
    catch (error) {setError(message(error));} finally {setBusy(false);}
  }
  return <section className="panel padded"><h2>Cyber decision</h2><p>Review the retained snapshot above. An approval authorizes signed publication to the recorded destination. Review any tag-only image identity limitations before approving.</p><form className="approval-form" onSubmit={submit}><label>Decision<select value={decision} onChange={event => setDecision(event.target.value)}><option value="approved">Approve</option><option value="denied">Deny</option></select></label>{!row.destination?.id && !!row.destinations && <label>Approved release destination<select value={selectedDestination} onChange={event => setDestination(event.target.value)}><option value="">Configure a destination before approving</option>{list(row.destinations).map(item => <option key={item.id} value={item.id}>{item.name} · {item.endpoint}/{item.namespace}</option>)}</select></label>}<label>Decision rationale<textarea required minLength={3} maxLength={10000} value={rationale} onChange={event => setRationale(event.target.value)}/></label><ResourceState error={error} pending={false}/><button disabled={busy || rationale.trim().length < 3}>{busy ? 'Saving decision…' : decision === 'approved' ? 'Approve snapshot' : 'Deny snapshot'}</button></form></section>;
}

export function ApprovalDetail({data, id}: {data: PageData; id: string}) {
  const resource = useResource(`/api/cyber-approvals/${encodeURIComponent(id)}`), row = resource.value;
  const snapshot = row?.snapshot || {};
  return <div className="approval-review"><a className="back" href="/cyber-approvals">← All approvals</a>
    <ResourceState error={resource.error} pending={!row && !resource.error}/>
    {row && <>
      <section className="approval-review-header panel padded">
        <div><p className="eyebrow">CYBER REVIEW · REQUEST #{row.id}</p><h1>{row.service_name || row.service_key}</h1><p>{variantLabel(row.variant)} · Version {row.version || snapshot.version || 'Unknown'}</p><Badges row={row}/>{row.service_key&&<VexEvidence serviceKey={row.service_key}/>}</div>
        <div className="approval-review-context"><span>Snapshot scan</span><strong>{dateLabel(row.scan_date || snapshot.scan_date)}</strong><small>Frozen evidence · later service changes do not update this review.</small>{row.evidence_url && <a href={row.evidence_url}>Download retained evidence ↗</a>}</div>
      </section>
      {!!snapshot.review_notes?.length && <section className="approval-review-notes panel padded"><h2>Cyber review considerations</h2><ul>{snapshot.review_notes.map((note: string, index: number) => <li key={index}>{note}</li>)}</ul></section>}
      <ServiceAtAGlance snapshot={snapshot}/>
      <ApprovalFindings findings={snapshot.findings} intelligence={snapshot.risk_intelligence}/>
      <section className="panel padded approval-support"><h2>Supporting evidence</h2><p>Review configuration, risk decisions, and the artifacts included in this request.</p>
        <div className="approval-support-grid">
          <EvidenceSection title="Artifacts" value={snapshot.artifacts || snapshot.images}/>
          <EvidenceSection title="Configuration findings" value={snapshot.findings?.configuration || snapshot.findings?.policy_findings}/>
          <EvidenceSection title="Mitigations" value={snapshot.mitigations}/>
          <EvidenceSection title="Exceptions" value={snapshot.exceptions}/>
          <EvidenceSection title="Remediation findings summary" value={snapshot.findings?.summary}/>
          <EvidenceSection title="Remediation provenance" value={snapshot.remediation || snapshot.provenance}/>
        </div>
        <details className="approval-support-section"><summary>Request record</summary><dl className="approval-metadata">{[['Requested', dateLabel(row.requested_at)], ['Requested by', row.requested_by], ['Destination', row.destination?.name], ['Registry', row.destination?.endpoint], ['Namespace', row.destination?.namespace], ['Snapshot digest', row.snapshot_digest || snapshot.digest], ['Request context', row.rationale], ['Decision rationale', row.decision_rationale], ['Decided', dateLabel(row.decided_at)]].map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{label(value) || '—'}</dd></div>)}</dl></details>
        <SnapshotDetails snapshot={snapshot}/>
      </section>
      <Decision data={data} row={row} refresh={resource.refresh}/>
      {row.status === 'approved' && <section className="panel padded"><h2>Approved release publication</h2><p>The Cyber decision is approved. Publication status: <StatusBadge value={row.publish_status || 'pending'}/></p><a href={`/approved-releases?id=${encodeURIComponent(row.release_id || row.publication?.release_id || row.id)}`}>Open approved release</a></section>}
    </>}
  </div>;
}

export function Page({data}: {data: PageData}) {
  const params = new URLSearchParams(window.location.search), id = params.get('id') || data.approval_id;
  const service = params.get('service') || data.service_key || '';
  return id ? <ApprovalDetail key={id} data={data} id={String(id)}/> : <ApprovalList data={data} serviceKey={service}/>;
}
function ApprovalList({data, serviceKey}: {data: PageData; serviceKey: string}) {
  const [status, setStatus] = useState('');
  const query = new URLSearchParams(); if (serviceKey) query.set('service', serviceKey); if (status) query.set('status', status);
  const resource = useResource(`/api/cyber-approvals?${query}`), rows = list(resource.value);
  return <><section className="heading"><div><p className="eyebrow">CYBER REVIEW</p><h1>Approvals</h1><p>Review immutable service snapshots and track decisions independently of publication.</p></div><a className="secondary-button" href="/approved-releases">Approved Releases</a></section>{serviceKey && <><ServiceTabs serviceKey={serviceKey} active="approvals"/><VexEvidence serviceKey={serviceKey}/><RequestApproval key={serviceKey} data={data} serviceKey={serviceKey}/></>}<section className="panel padded"><div className="panel-head"><h2>{serviceKey ? `${serviceKey} requests` : 'Approval queue'}</h2><label>Decision status<select value={status} onChange={event => setStatus(event.target.value)}><option value="">All decisions</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="denied">Denied</option></select></label><button type="button" className="secondary-button" onClick={resource.refresh}>Refresh</button></div><ResourceState error={resource.error} pending={!resource.value && !resource.error}/>{resource.value && <><p>{resource.value.total ?? rows.length} requests</p><div className="table-wrap"><table><thead><tr>{['Service / snapshot', 'Variant', 'Requested', 'Decision', 'Publication'].map(name => <th key={name}>{name}</th>)}</tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><a href={`/cyber-approvals?id=${row.id}`}>{row.service_name || row.service_key} · {row.version || row.label || `#${row.id}`}</a></td><td>{variantLabel(row.variant)}</td><td>{row.requested_at || '—'}</td><td><StatusBadge value={row.status}/></td><td><StatusBadge value={row.publish_status || 'not_started'}/></td></tr>)}</tbody></table></div>{!rows.length && <p>No requests match this view. Open a service and choose Request Cyber Approval to start a review.</p>}</>}</section></>;
}

export function Releases({data}: {data: PageData}) {
  const id = new URLSearchParams(window.location.search).get('id') || data.release_id;
  return id ? <ReleaseDetail key={id} data={data} id={String(id)}/> : <ReleaseList/>;
}
function ReleaseList() {
  const serviceKey = new URLSearchParams(window.location.search).get('service') || '';
  const [query, setQuery] = useState(''), [variant, setVariant] = useState('');
  const resource = useResource(`/api/approved-releases${serviceKey ? `?service=${encodeURIComponent(serviceKey)}` : ''}`), rows = list(resource.value).filter(row => (!variant || row.variant === variant) && `${row.service_name} ${row.service_key} ${row.version}`.toLowerCase().includes(query.toLowerCase()));
  return <><section className="heading"><div><p className="eyebrow">TRUSTED DELIVERY</p><h1>Approved Releases</h1><p>Cyber-approved snapshots, their publication progress, and immutable deployment artifacts.</p></div><a className="secondary-button" href="/cyber-approvals">Approvals</a></section>{serviceKey && <ServiceTabs serviceKey={serviceKey} active="releases"/>}<section className="panel padded"><div className="approval-filters"><label>Find a release<input value={query} onChange={event => setQuery(event.target.value)} placeholder="Service or version"/></label><label>Variant<select value={variant} onChange={event => setVariant(event.target.value)}><option value="">All variants</option><option value="current_service">Current Service</option><option value="cats_remediated">CATS Remediated</option></select></label><button type="button" className="secondary-button" onClick={resource.refresh}>Refresh</button></div><ResourceState error={resource.error} pending={!resource.value && !resource.error}/><div className="approval-release-grid">{rows.map(row => <article className="approval-release-card" key={row.id}><h2><a href={`/approved-releases?id=${row.id}`}>{row.service_name || row.service_key}</a></h2><p>{row.version || row.label} · {variantLabel(row.variant)}</p><Badges row={{...row, status: 'approved'}}/><p>Scan date: {row.scan_date || 'Not recorded'}</p><p>Destination: {row.destination?.name || 'Recorded in release'}</p></article>)}</div>{resource.value && !rows.length && <p>No approved releases match this view.</p>}</section></>;
}
function ArtifactLinks({value}: {value: any}) {
  const rows = Array.isArray(value) ? value : value && typeof value === 'object' ? Object.entries(value).map(([name, url]) => ({name, url})) : [];
  return <ul>{rows.map((row: Row, index: number) => {const href = row.url || row.href || row.download_url; return <li key={index}>{typeof href === 'string' && href.startsWith('/') && !href.startsWith('//') ? <a href={href}>{row.name || row.label || 'Download evidence'}</a> : <span>{row.name || row.label || label(row)}</span>}</li>;})}</ul>;
}
export function ReleaseDetail({data, id}: {data: PageData; id: string}) {
  const resource = useResource(`/api/approved-releases/${encodeURIComponent(id)}`), row = resource.value;
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function retry() {setBusy(true); setError(''); try {await mutate(data, `/api/approved-releases/${encodeURIComponent(id)}/retry`, {}); resource.refresh();} catch (error) {setError(message(error));} finally {setBusy(false);}}
  const publication = row?.publication || {}, artifacts = row?.artifacts || publication.artifacts || [];
  return <><a className="back" href="/approved-releases">All approved releases</a><ResourceState error={resource.error} pending={!row && !resource.error}/>{row && <><section className="heading"><div><p className="eyebrow">APPROVED RELEASE · #{row.id}</p><h1>{row.service_name || row.service_key}</h1><p>{row.version || row.label} · {variantLabel(row.variant)} · Scan date: {row.scan_date || 'Not recorded'}</p><Badges row={{...row, status: 'approved'}}/></div><button className="secondary-button" type="button" onClick={resource.refresh}>Refresh publication</button></section><section className="panel padded"><h2>Publication</h2>{row.revoked && <p className="error" role="alert">This release has been revoked and is no longer authorized for deployment. {row.revocation_reason}</p>}<p>{row.revoked ? 'Retained artifacts and evidence are shown for audit history.' : !currentApproval(row) ? 'This release needs a new Cyber approval before deployment. Retained downloads are available for audit history.' : row.publish_status === 'published' ? 'Published artifacts are ready to retrieve using their immutable references.' : 'This snapshot is Cyber approved. Artifact delivery is not complete until publication succeeds.'}</p><p>Destination: {row.destination?.name} · <code>{row.destination?.endpoint}/{row.destination?.namespace}</code></p>{(row.publish_error || publication.error) && <p className="error" role="alert">{row.publish_error || publication.error}</p>}{row.publish_status === 'failed' && <PublicationDiagnostic publication={publication}/>}<ResourceState error={error} pending={false}/>{!row.revoked && currentApproval(row) && row.publish_status === 'failed' && (row.can_retry ?? can(data, 'approval.decide', row.service_id)) && <button type="button" disabled={busy} onClick={retry}>{busy ? 'Queuing publication…' : 'Retry publication'}</button>}<p><a href={`/cyber-approvals?id=${row.approval_id || row.id}`}>Review Cyber decision and snapshot</a></p></section><section className="panel padded"><h2>Immutable artifacts</h2>{publication.release?.reference && <p>Release manifest: <code className="approval-ref">{publication.release.reference}</code></p>}{!list(artifacts).length && <p>Artifact references will appear when publication completes.</p>}{list(artifacts).map((artifact, index) => <article className="approval-evidence" key={index}><h3>{artifact.name || artifact.kind || artifact.type || `Artifact ${index + 1}`}</h3><code className="approval-ref">{artifact.immutable_ref || artifact.ref || artifact.reference || artifact.digest}</code>{artifact.digest && <p>Digest: <code>{artifact.digest}</code></p>}<EvidenceSection title="Signature verification" value={artifact.signature || artifact.signature_evidence}/></article>)}</section><section className="panel padded"><h2>Signature and release evidence</h2><EvidenceSection title="Signing evidence" value={row.signature || publication.signature || publication.release?.signature || row.signature_evidence || (publication.signing_fingerprint ? {signing_fingerprint:publication.signing_fingerprint} : undefined)}/><ArtifactLinks value={row.evidence_links || publication.evidence_links || (row.evidence_url ? [{name:'Download retained evidence',url:row.evidence_url}] : [])}/><h3>Offline bundle</h3><ArtifactLinks value={row.offline_links || publication.offline_links || (row.offline_bundle_url ? [{name:'Download offline release bundle', url:row.offline_bundle_url}] : [])}/><h3>Pull and deployment instructions</h3>{row.publish_status === 'published' && !row.revoked && currentApproval(row) && publication.release?.reference && <pre className="approval-json">{`oras pull ${publication.release.reference}`}</pre>}<p>Verify the signatures and approval expiry against the signing key fingerprint supplied independently by your Cyber approver. A signature-only check does not enforce expiry. Registry access controls and deployment admission policies determine who can retrieve and deploy these artifacts.</p><pre className="approval-json">{row.pull_instructions || publication.pull_instructions || row.destination?.pull_instructions || 'Use the offline bundle README to verify the retained release and import it into your registry. Map the approved image digests into your environment-specific Helm values before deploying the retained charts.'}</pre>{row.deploy_instructions && <pre className="approval-json">{row.deploy_instructions}</pre>}</section></>}</>;
}

export function Destinations({data}: {data: PageData}) {
  const resource = useResource('/api/approved-release-destinations'), [editing, setEditing] = useState<Row | null>(null), [notice, setNotice] = useState('');
  return <><Heading title="Approved Release Destinations" description="Configure the OCI registries used to publish Cyber-approved service snapshots."/><AdminTabs data={data} selected="release-destinations"/><section className="panel padded"><h2>Registry destinations</h2><ResourceState error={resource.error} pending={!resource.value && !resource.error}/>{notice && <p role="status">{notice}</p>}<div className="table-wrap"><table><thead><tr>{['Name', 'Endpoint / namespace', 'Group IDs', 'Credentials', 'Default', 'Actions'].map(name => <th key={name}>{name}</th>)}</tr></thead><tbody>{list(resource.value).map(row => <tr key={row.id}><td>{row.name}</td><td>{row.endpoint}/{row.namespace}</td><td>{(row.group_ids || []).join(', ') || 'All permitted groups'}</td><td>{(row.credentials_configured || row.has_credentials) ? 'Configured' : 'Not configured'}</td><td>{row.is_default ? 'Yes' : 'No'}</td><td><button className="secondary-button" type="button" onClick={() => {setEditing(row); setNotice('');}}>Edit {row.name}</button></td></tr>)}</tbody></table></div><button type="button" className="secondary-button" onClick={() => {setEditing({}); setNotice('');}}>Add destination</button></section>{editing && <DestinationForm key={editing.id || 'new'} data={data} row={editing} cancel={() => setEditing(null)} saved={() => {setEditing(null); setNotice('Destination saved.'); resource.refresh();}}/>}<section className="panel padded"><h2>Signing configuration</h2><p>Approved releases use the global signing configuration. Destination credentials are retained on the server and are never returned to this page.</p><a href="/admin/configuration">Manage global signing settings</a></section></>;
}
function DestinationForm({data, row, cancel, saved}: {data: PageData; row: Row; cancel: () => void; saved: () => void}) {
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    const body: Row = {id: row.id, name: form.get('name'), endpoint: form.get('endpoint'), namespace: form.get('namespace'), group_ids: String(form.get('group_ids') || '').split(',').map(value => value.trim()).filter(Boolean).map(Number), is_default: form.get('is_default') === 'on', enabled: form.get('enabled') === 'on', username: form.get('username'), pull_instructions: form.get('pull_instructions')};
    if (body.group_ids.some((id: number) => !Number.isInteger(id) || id < 1)) {setError('Group IDs must be positive whole numbers separated by commas.'); return;}
    if (form.get('password')) body.password = form.get('password');
    if (form.get('ca_pem')) body.ca_pem = form.get('ca_pem');
    setBusy(true); setError(''); try {await mutate(data, '/api/approved-release-destinations', body); saved();} catch (error) {setError(message(error));} finally {setBusy(false);}
  }
  return <section className="panel padded"><h2>{row.id ? 'Edit destination' : 'Add destination'}</h2><form className="approval-form" onSubmit={submit}><label>Registry name<input name="name" required defaultValue={row.name || ''}/></label><label>Registry endpoint<input name="endpoint" required defaultValue={row.endpoint || ''} type="url" placeholder="https://registry.example.com"/></label><label>Namespace<input name="namespace" required defaultValue={row.namespace || ''} placeholder="approved"/></label><label>Permitted group IDs<input name="group_ids" defaultValue={(row.group_ids || []).join(', ')} placeholder="1, 2"/></label><label>Registry username<input name="username" defaultValue={row.username || ''} autoComplete="off"/></label><label>Registry password / token<input type="password" name="password" autoComplete="new-password"/></label>{row.id && <p>Leave the password and custom CA blank to retain their current values.</p>}<label>Custom CA certificate (PEM)<textarea name="ca_pem"/></label><label className="approval-checkbox"><input type="checkbox" name="enabled" defaultChecked={row.enabled !== false}/>Available for new requests</label><label className="approval-checkbox"><input type="checkbox" name="is_default" defaultChecked={row.is_default || false}/>Default destination</label><label>Pull and deployment instructions<textarea name="pull_instructions" defaultValue={row.pull_instructions || ''}/></label><ResourceState error={error} pending={false}/><div className="dialog-actions"><button type="button" className="secondary-button" disabled={busy} onClick={cancel}>Cancel</button><button disabled={busy}>{busy ? 'Saving…' : 'Save destination'}</button></div></form></section>;
}
