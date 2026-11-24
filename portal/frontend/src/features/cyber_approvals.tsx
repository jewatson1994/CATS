import {VexEvidence} from './native_vex';
import {OCIDistribution} from './oci_distribution';
import {useEffect, useState, type FormEvent} from 'react';
import {ReleaseRevision} from './release_revision';
import {DistributionDetails, FrozenDistribution} from './service-distributions';
import {can, requestJson, type PageData} from '../api';
import {EmptyState, humanize, PageHeader, StageProgress, StatusBadge, type Stage} from '../components/ui';
import {DataGrid, type GridColumn} from '../components/DataGrid';
import {ServiceTabs} from '../components/ServiceHeader';
import {AdminTabs, Heading} from './admin_shared';
import './cyber_approvals.css';
import {ApprovalFindings} from './approval_findings';
import {ReleaseImagePullInstructions} from '../components/ImagePullInstructions';

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
  return {value, error, update: setValue, refresh: () => setRevision(value => value + 1)};
}
async function mutate(data: PageData, url: string, body: Row) {
  return requestJson<Row>(url, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': data.csrf_token || ''}, body: JSON.stringify(body)});
}
function PublicationDiagnostic({publication}: {publication: Row}) {
  const diagnostic = publication.diagnostic;
  if (!diagnostic && !publication.correlation_id) return null;
  const legacyRedirect = !diagnostic?.redirect_reason && [301, 302, 303, 307, 308].includes(diagnostic?.http_status);
  return <><dl className="approval-metadata" aria-label="Publication failure details">
    {diagnostic?.stage && <div><dt>Failed step</dt><dd>{label(diagnostic.stage)}</dd></div>}
    {diagnostic?.cause && <div><dt>Cause</dt><dd>{label(diagnostic.cause)}</dd></div>}
    {diagnostic?.http_status != null && <div><dt>Registry HTTP status</dt><dd>{label(diagnostic.http_status)}</dd></div>}
    {diagnostic?.operation && <div><dt>Registry operation</dt><dd><code>{diagnostic.operation}</code></dd></div>}
    {diagnostic?.registry_origin && <div><dt>Registry origin</dt><dd><code>{diagnostic.registry_origin}</code></dd></div>}
    {diagnostic?.redirect_from_origin && <div><dt>Redirect issued by</dt><dd><code>{diagnostic.redirect_from_origin}</code></dd></div>}
    {diagnostic?.redirect_origin && <div><dt>Redirect target</dt><dd><code>{diagnostic.redirect_origin}</code></dd></div>}
    {diagnostic?.exit_code != null && <div><dt>Tool exit code</dt><dd>{label(diagnostic.exit_code)}</dd></div>}
    {diagnostic?.os_error != null && <div><dt>System error number</dt><dd>{label(diagnostic.os_error)}</dd></div>}
    {publication.correlation_id && <div><dt>Correlation ID</dt><dd><code>{label(publication.correlation_id)}</code></dd></div>}
  </dl>
    {diagnostic?.redirect_reason === 'unapproved_blob_origin' && diagnostic.redirect_origin && <p>
      Ask your registry administrator to confirm the redirect target is trusted storage.
      Then add that origin to <code>CATS_OCI_BLOB_REDIRECT_ORIGINS</code>, recreate <code>remediation-worker</code>, and retry publication.
    </p>}
    {legacyRedirect && <p>This attempt did not record the redirect target. Retry publication with the updated worker to see where the request was redirected.</p>}
  </>;
}
function ResourceState({error, pending}: {error: string; pending: boolean}) {
  return error ? <p className="error" role="alert">{error}</p> : pending ? <p role="status">Loading…</p> : null;
}
const currentApproval = (row: Row) => ['valid', 'expiring_soon'].includes(row.validity_status);
function Badges({row, showExpiry = true}: {row: Row; showExpiry?: boolean}) {
  return <div className="approval-badges">{row.revoked && <StatusBadge value="revoked" label="Revoked" tone="danger"/>}<span>Cyber decision: <StatusBadge value={row.status || 'pending'}/></span><span>Publication: <StatusBadge value={row.publish_status || 'not_started'}/></span>{row.status === 'approved' && <span>Authorization: <StatusBadge value={row.revoked ? 'revoked' : row.validity_status || 'reapproval_required'} label={row.revoked ? 'Revoked' : humanize(row.validity_status || 'reapproval_required')}/></span>}{showExpiry && row.expires_at && <span>Expires: {dateLabel(row.expires_at)}</span>}</div>;
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

function destinationAddress(destination: Row) {
  return destination.endpoint ? `${destination.endpoint}/${destination.namespace || 'cyber-approved'}` : '';
}

function RegistryAddress({destination, label}: {destination: Row; label: string}) {
  return <p className="release-destination"><span className="approval-muted">{label}</span>
    <strong>{destination.name}</strong><code>{destinationAddress(destination)}</code></p>;
}

function RuntimeInventory({evidence}: {evidence: Row}) {
  const source = evidence.source || {};
  return <><dl className="approval-metadata">
      <div><dt>Environment</dt><dd>{source.cluster || source.environment_name || 'Unknown'}</dd></div>
      <div><dt>Namespace</dt><dd>{source.namespace || evidence.namespace || 'Unknown'}</dd></div>
      <div><dt>Proposed version</dt><dd>{evidence.proposed_version}</dd></div>
      <div><dt>Candidate revision</dt><dd>{evidence.revision}</dd></div>
      <div><dt>Cluster role</dt><dd>{humanize(source.role || 'Unknown')}</dd></div>
      <div><dt>Inventory fingerprint</dt><dd><code>{evidence.fingerprint}</code></dd></div>
    </dl>
    {list(evidence.applications).map(app => <details key={app.identity} className="approval-support-section">
      <summary>{app.name} · {list(app.components).length} containers</summary>
      <div className="approval-ports-wrap"><table className="approval-ports-table"><thead><tr><th>Workload</th><th>Container</th><th>Declared image</th><th>Running image</th></tr></thead>
        <tbody>{list(app.components).map((item, i) => <tr key={i}><td>{item.workload_kind} {item.workload}</td><td>{item.container}</td>
          <td><code>{item.desired_image || item.image_ref || 'Unknown'}</code></td><td><code>{item.image_id || 'Unknown'}</code></td></tr>)}</tbody></table></div>
    </details>)}
    <EvidenceSection title="Image inventory" value={evidence.images}/>
    <EvidenceSection title="Helm chart inventory" value={evidence.charts}/>
  </>;
}

function RuntimeEvidence({evidence}: {evidence: Row}) {
  const assessments = list(evidence.assessments), findings = list(evidence.findings);
  const comparison = evidence.comparison, risk = evidence.risk;
  const [visibleFindings, setVisibleFindings] = useState(25);
  return <section aria-label="Runtime candidate evidence"><h2>Runtime inventory and assessment</h2>
    <RuntimeInventory evidence={evidence}/>
    <details className="approval-support-section"><summary>Artifact assessments and SBOMs <span className="approval-count">{assessments.length}</span></summary>
      {assessments.map((item, i) => <div key={i}><h3>{item.reference || item.name}</h3><p><StatusBadge value={item.status}/> {item.reason}</p>
        {item.execution_id != null && <p>Scan #{item.execution_id} · {dateLabel(item.scan_date)} · Job {item.job_id}</p>}
        {list(item.sboms).map((sbom, j) => <p key={j}>{sbom.name || sbom.format} <code>{sbom.sha256}</code></p>)}
        {Array.isArray(item.catalog_matches) && (item.catalog_matches.length
          ? <div className="approval-ports-wrap"><table className="approval-ports-table"><caption>Service catalog entries with the assessed digest</caption>
            <thead><tr><th>Artifact</th><th>Catalog media type</th><th>Catalog platform</th><th>Service roles</th></tr></thead>
            <tbody>{list(item.catalog_matches).map(match => <tr key={match.artifact_id}><td>#{match.artifact_id}</td><td>{match.media_type}</td>
              <td>{match.platform}</td><td>{match.roles.join(', ')}</td></tr>)}</tbody>
          </table></div> : <p>No service catalog entries match this assessed digest.</p>)}
      </div>)}
    </details>
    {risk && <><h3>Risk and threat intelligence</h3><p>Highest score {risk.maximum_score ?? 'unavailable'} · {risk.uncertain_findings ?? 'Unknown'} uncertain findings · Intelligence {risk.intelligence_current ? 'current' : 'unavailable or stale'}</p>
      <EvidenceSection title="Risk policy and intelligence sources" value={risk}/></>}
    <details className="approval-support-section"><summary>Findings <span className="approval-count">{findings.length}</span></summary>
      {!findings.length && <p>No findings recorded.</p>}
      {!!findings.length && <div className="approval-ports-wrap"><table className="approval-ports-table"><thead><tr><th>Vulnerability</th><th>Affected image and package</th><th>Risk</th><th>VEX</th><th>KEV</th><th>EPSS</th></tr></thead>
        <tbody>{findings.slice(0, visibleFindings).map((item, i) => <tr key={i}><td>{item.cve}<small>{item.severity}</small></td>
          <td>{item.package} {item.installed_version}<small>{item.image}</small>{item.fixed_version && <small>Fixed in {item.fixed_version}</small>}</td>
          <td>{item.score ?? 'Unknown'} {item.band}{item.uncertain && <small>Uncertain</small>}</td><td>{humanize(item.vex?.decision || item.vex?.status || 'unknown')}</td>
          <td>{item.kev === true ? 'Listed' : item.kev === false ? 'Unlisted' : 'Unknown'}</td><td>{typeof item.epss === 'number' ? (100 * item.epss).toFixed(2) + '%' : 'Unknown'}</td></tr>)}</tbody></table></div>}
      {findings.length > visibleFindings && <button type="button" onClick={() => setVisibleFindings(n => n + 25)}>Show more findings</button>}
    </details>
    {comparison && <><h3>Changes from the active release</h3>
      {comparison.baseline_available ? <><p>Version {comparison.version || 'unknown'} · Revision #{comparison.revision_id} · {list(comparison.added).length} added, {Array.isArray(comparison.removed) ? comparison.removed.length + ' removed' : 'removals unknown'}, {list(comparison.updated).length} updated.</p>
        <p>{comparison.vulnerabilities_comparable ? `${comparison.new_vulnerabilities.length} new and ${comparison.resolved_vulnerabilities.length} resolved vulnerabilities.` : 'Vulnerability comparison unavailable.'} Risk score change {comparison.risk?.delta ?? 'unavailable'}.</p>
        <EvidenceSection title="Artifact and vulnerability changes" value={comparison}/></> : <p>{comparison.reason}</p>}</>}
  </section>;
}

export function RequestApproval({data, serviceKey, amendmentProposalId, distributionId, runtimeCandidateId}: {data: PageData; serviceKey: string; amendmentProposalId?: number; distributionId?: string; runtimeCandidateId?: string}) {
  const [selection, setSelection] = useState('current_service'), [lastCandidates, setLastCandidates] = useState<Row[]>([]);
  const [additionalId, setAdditionalId] = useState('');
  const remediation = selection.startsWith('cats_remediated:') ? selection.slice('cats_remediated:'.length) : '';
  const variant = remediation ? 'cats_remediated' : 'current_service';
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [created, setCreated] = useState<Row | null>(null);
  const query = new URLSearchParams({variant});
  if (remediation) query.set('remediation_id', remediation);
  if (distributionId) query.set('distribution_id', distributionId);
  if (runtimeCandidateId) query.set('runtime_candidate_id', runtimeCandidateId);
  const readiness = useResource(`/api/services/${encodeURIComponent(serviceKey)}/cyber-approval-readiness?${query}`);
  const ready = readiness.value;
  const candidates = ready ? list(ready.remediations) : lastCandidates;
  useEffect(() => {if (ready) setLastCandidates(list(ready.remediations));}, [ready]);
  const allowed = runtimeCandidateId ? ready?.can_request === true : ready?.can_request ?? data.can_request ?? can(data, 'approval.request', ready?.service_id ?? data.service?.id);
  const cyberDestinations = list(ready?.destinations);
  const primary = cyberDestinations.find(item => item.is_default) || [...cyberDestinations].sort((a, b) => Number(a.id) - Number(b.id))[0];
  const additionalOptions = list(ready?.additional_destinations);
  const selectedAdditional = ready?.can_select_additional_destination && additionalOptions.find(item => item.id === additionalId);
  const destinationUnavailable = Boolean(ready && additionalId && !selectedAdditional);
  const selectionMatches = !distributionId || String(ready?.distribution?.id) === distributionId;
  const runtime = ready?.runtime_candidate;
  const canSubmitEvidence = ready?.ready && selectionMatches && (!distributionId || Number.isInteger(ready.source_execution_id))
    && (!runtimeCandidateId || (String(runtime?.id) === runtimeCandidateId && ready.review_digest));
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (!canSubmitEvidence || !allowed || busy || destinationUnavailable) return;
    setBusy(true); setError('');
    try {setCreated(await mutate(data, '/api/cyber-approvals', {service_key: serviceKey, variant, remediation_id: remediation || undefined, ...(selectedAdditional ? {additional_destination_id: selectedAdditional.id} : {}), ...(amendmentProposalId ? {amendment_proposal_id: amendmentProposalId} : {}), ...(distributionId ? {distribution_id: distributionId, expected_source_execution_id: ready.source_execution_id} : {}), ...(runtimeCandidateId ? {runtime_candidate_id: Number(runtimeCandidateId), review_digest: ready.review_digest} : {})}));}
    catch (error) {setError(message(error)); readiness.refresh();} finally {setBusy(false);}
  };
  if (created) return <section className="panel padded"><h2>Cyber approval requested</h2><p role="status">The snapshot is ready for Cyber review.</p><a href={`/cyber-approvals?id=${encodeURIComponent(created.id)}`}>Review request #{created.id}</a></section>;
  if (runtimeCandidateId && ready?.historical_inventory) {
    const inventory = ready.historical_inventory;
    return <section className="panel padded"><h2>Superseded runtime candidate for {serviceKey}</h2>
      <p>Inventory recorded {dateLabel(inventory.created_at)}. This draft was superseded before submission.</p>
      <RuntimeInventory evidence={inventory}/>
      {!!list(inventory.blockers).length && <><h3>Recorded inventory blockers</h3><ul>{list(inventory.blockers).map((value, i) => <li key={i}>{String(value)}</li>)}</ul></>}
      <h3>Candidate history</h3><ol>{list(inventory.history).map((event, i) => <li key={i}>
        <time dateTime={event.recorded_at}>{dateLabel(event.recorded_at)}</time>{' · '}
        {humanize(String(event.action).replace('runtime.candidate.', ''))} · {event.actor}
        {event.detail?.status && <> · {event.detail.previous} → {event.detail.status}</>}
        {event.detail?.job_id && <> · Scan job <code>{event.detail.job_id}</code></>}
        {event.detail?.reference && <> · <code>{event.detail.reference}</code></>}
      </li>)}</ol></section>;
  }
  if (runtimeCandidateId && runtime?.approval_id && !['returned', 'draft'].includes(runtime.status)) {
    return <section className="panel padded"><h2>Runtime candidate review</h2><p><StatusBadge value={runtime.status}/></p>
      <a href={`/cyber-approvals?id=${runtime.approval_id}`}>Open submitted snapshot and Cyber decision</a></section>;
  }
  return <section className="panel padded"><h2>{runtimeCandidateId ? `Review runtime release candidate for ${serviceKey}` : 'Request Cyber Approval'}</h2>{runtime?.decision_rationale && <p role="note">Cyber returned this submission for changes. {runtime.decision_rationale} <a href={`/cyber-approvals?id=${runtime.approval_id}`}>Previous review</a></p>}{ready?.runtime_evidence && <RuntimeEvidence evidence={ready.runtime_evidence}/>} {amendmentProposalId && <p role="note">Amendment proposal #{amendmentProposalId} requires an actual fresh service assessment containing the replacement artifact. Selecting a proposal does not run an assessment or prove that its evidence is current. Retain the new assessment and service validation before submitting; the server verifies the evidence and current base revision.</p>}{!runtimeCandidateId && <p>Choose the release to submit. Cyber reviews vulnerabilities, configuration coverage, mitigations, exceptions and deployment verification.</p>}{!runtimeCandidateId && !amendmentProposalId && <p><a href={`/services/${encodeURIComponent(serviceKey)}?artifacts=true#service-distributions`}>Choose a saved service distribution</a></p>}
    <form className="approval-form" onSubmit={submit}>{runtimeCandidateId ? null : distributionId ? <div><h3>Distribution for review</h3>{ready?.distribution && selectionMatches ? <><strong>{ready.distribution.name}</strong><DistributionDetails selection={ready.distribution}/></> : <code>{distributionId}</code>}</div> : <label>Release variant<select disabled={busy} value={selection} onChange={event => setSelection(event.target.value)}><option value="current_service">Current Service</option>{candidates.map(row => <option key={row.id} value={`cats_remediated:${row.id}`}>CATS Remediated · {row.label || row.id}</option>)}</select></label>}<ResourceState error={readiness.error} pending={!ready && !readiness.error}/>{ready && <><div className="approval-readiness" role="status"><StatusBadge value={canSubmitEvidence ? 'ready' : 'blocked'} label={canSubmitEvidence ? 'Ready for Cyber review' : 'Evidence incomplete'}/><p>Version: {ready.version || 'Unknown'} · Scan date: {ready.scan_date || 'Not recorded'}</p>{distributionId && !canSubmitEvidence && !ready.blockers?.length && <p>A completed scan for this distribution is required.</p>}{!!ready.blockers?.length && <ul>{ready.blockers.map((reason: string, index: number) => <li key={index}>{reason}</li>)}</ul>}</div>
      <fieldset disabled={busy}><legend>Release destinations</legend>
        {primary ? <RegistryAddress label="Cyber destination" destination={primary}/> : <p>Cyber must configure a registry before approving publication.</p>}
        {allowed && ready.can_select_additional_destination && <>
          {additionalOptions.length > 0 && <label>Additional service destination (optional)
            <select value={selectedAdditional ? additionalId : ''} onChange={event => setAdditionalId(event.target.value)}>
              <option value="">Cyber destination only</option>
              {additionalOptions.map(item => <option key={item.id} value={item.id}>{item.name} ({destinationAddress(item)})</option>)}
            </select></label>}
          <p>{additionalOptions.length ? 'Selecting an additional destination sends the approved release and its body of evidence to both registries.' : 'To send the approved release and its body of evidence to a second registry, add a service OCI destination.'}</p>
          <a href={`/services/${encodeURIComponent(serviceKey)}?remediations=true`}>Manage OCI destinations in Service remediation</a>
        </>}
        {destinationUnavailable && <p role="alert">The selected service destination is no longer available.{' '}
          <button type="button" className="secondary-button" onClick={() => setAdditionalId('')}>Clear selection</button></p>}
      </fieldset>
      {!allowed && <p>You do not have permission to request Cyber approval for this service.</p>}</>}<ResourceState error={error} pending={false}/>{(!runtimeCandidateId || allowed) && <button disabled={busy || !canSubmitEvidence || !allowed || destinationUnavailable}>{busy ? 'Submitting…' : runtimeCandidateId ? 'Submit for Cyber Review' : 'Request Cyber Approval'}</button>}</form></section>;
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
  return <section className="panel padded"><h2>Cyber decision</h2><p>Review the retained snapshot above. An approval authorizes publication of the signed release and its body of evidence to the listed destinations. Review any tag-only image identity limitations before approving.</p><form className="approval-form" onSubmit={submit}><label>Decision<select value={decision} onChange={event => setDecision(event.target.value)}><option value="approved">Approve</option><option value="denied">{row.runtime_candidate_id ? 'Reject' : 'Deny'}</option>{row.runtime_candidate_id && <option value="returned">Return for changes</option>}</select></label>{!row.destination?.id && !!row.destinations && <label>Approved release destination<select value={selectedDestination} onChange={event => setDestination(event.target.value)}><option value="">Configure a destination before approving</option>{list(row.destinations).map(item => <option key={item.id} value={item.id}>{item.name} · {destinationAddress(item)}</option>)}</select></label>}<label>Decision rationale<textarea required minLength={3} maxLength={10000} value={rationale} onChange={event => setRationale(event.target.value)}/></label><ResourceState error={error} pending={false}/><button disabled={busy || rationale.trim().length < 3}>{busy ? 'Saving decision…' : decision === 'approved' ? 'Approve snapshot' : decision === 'returned' ? 'Return for changes' : row.runtime_candidate_id ? 'Reject snapshot' : 'Deny snapshot'}</button></form></section>;
}

export function Reassessment({data, row}: {data: PageData; row: Row}) {
  const url = `/api/cyber-approvals/${row.id}/reassessment`, resource = useResource(url);
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const schedule = resource.value?.schedule, artifacts = row.snapshot?.artifacts || [];
  const eligible = !row.revoked && artifacts.length > 0 && artifacts.every((item: Row) => item.kind === 'image' && !item.archive_path && item.format !== 'docker-archive' && /@sha256:[0-9a-f]{64}$/.test(item.reference || ''));
  const permitted = ['service.view', 'service.edit', 'service.export', 'approval.request', 'scan.ingest'].every(permission => can(data, permission, row.service_id));
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    setBusy(true); setError(''); setNotice('');
    try {
      await requestJson(url, {method:'PUT', headers:{'Content-Type':'application/json','X-CSRF-Token':data.csrf_token || ''}, body:JSON.stringify({interval_days:Number(form.get('interval_days')),enabled:form.get('enabled') === 'on'})});
      setNotice('Reassessment schedule saved.'); resource.refresh();
    } catch (error) {setError(message(error));} finally {setBusy(false);}
  }
  return <section className="panel padded" aria-label="Scheduled reassessment"><h2>Scheduled reassessment</h2>
    <p>Rescan the approved image digests. Successful assessments create a new request for Cyber review; they do not extend this approval.</p>
    <ResourceState error={resource.error || error} pending={!resource.value && !resource.error}/>
    {notice && <p role="status">{notice}</p>}
    {schedule && <p>{schedule.enabled ? 'Enabled' : 'Disabled'} · Every {schedule.interval_days} days · Next scheduled: {dateLabel(schedule.next_run)}</p>}
    {!eligible ? <p>Automatic reassessment requires a non-revoked approval containing only registry images pinned to digests. Charts and archives need a full assessment.</p> : !permitted ? <p>A scoped Service Manager with scan ingestion and approval request access can manage this schedule.</p> : resource.value && <form key={JSON.stringify(schedule)} className="approval-form" onSubmit={save}>
      <label>Reassessment interval (days)<input name="interval_days" type="number" min="1" max="365" required defaultValue={schedule?.interval_days || 7}/></label>
      <label className="approval-checkbox"><input type="checkbox" name="enabled" defaultChecked={schedule?.enabled ?? true}/>Enable scheduled reassessment</label>
      <button disabled={busy}>{busy ? 'Saving schedule...' : 'Save reassessment schedule'}</button>
    </form>}
    <button type="button" className="secondary-button" disabled={busy} onClick={resource.refresh}>Refresh reassessment status</button>
    {resource.value && !(resource.value.events || []).length && <p>No reassessment events recorded.</p>}
    {(resource.value?.events || []).map((event: Row) => <article key={event.id} className="approval-evidence"><StatusBadge value={event.state}/>{event.detail && <p>{event.detail}</p>}{event.scan_id && <p>Scan: <code>{event.scan_id}</code></p>}{event.renewal_id && <a href={`/cyber-approvals?id=${event.renewal_id}`}>Review renewal #{event.renewal_id}</a>}</article>)}
  </section>;
}

/**
 * Separates the automated technical assessment (the frozen evidence snapshot) from the human Cyber
 * decision and from publication. Presentation of recorded states only; no state is derived or changed.
 */
function ReviewTrack({row, snapshot}: {row: Row; snapshot: Row}) {
  const scanned = row.scan_date || snapshot.scan_date;
  const decision = String(row.status || 'pending');
  const publish = String(row.publish_status || 'not_started');
  const stages: Stage[] = [
    {key: 'assessment', label: 'Technical assessment', state: scanned ? 'complete' : 'pending', detail: scanned ? `Automated evidence snapshot · ${dateLabel(scanned)}` : 'Snapshot scan not recorded'},
    {key: 'decision', label: 'Cyber decision', state: decision === 'approved' ? 'complete' : decision === 'denied' ? 'failed' : 'warning',
      detail: decision === 'pending' ? 'Awaiting a human Cyber reviewer' : `${humanize(decision)}${row.decided_at ? ` · ${dateLabel(row.decided_at)}` : ''}`},
    {key: 'publication', label: 'Publication', state: publish === 'published' ? 'complete' : publish === 'failed' ? 'failed' : ['publishing', 'queued', 'running', 'in_progress'].includes(publish) ? 'current' : decision === 'approved' ? 'warning' : 'pending',
      detail: decision === 'approved' ? humanize(publish) : 'Starts after approval'},
  ];
  return <section className="panel padded review-track" aria-label="Review progress"><StageProgress stages={stages} label="Assessment, decision and publication"/></section>;
}

export function ApprovalDetail({data, id}: {data: PageData; id: string}) {
  const resource = useResource(`/api/cyber-approvals/${encodeURIComponent(id)}`), row = resource.value;
  const snapshot = row?.snapshot || {};
  return <div className="approval-review"><a className="back" href="/cyber-approvals">← All approvals</a>
    <ResourceState error={resource.error} pending={!row && !resource.error}/>
    {row && <>
      <section className="approval-review-header panel padded">
        <div><p className="eyebrow">CYBER REVIEW · REQUEST #{row.id}</p><h1>{row.service_name || row.service_key}</h1><p>{row.label || variantLabel(row.variant)} · Version {row.version || snapshot.version || 'Unknown'}</p><Badges row={row}/>{!row.runtime_candidate_id && row.service_key && <VexEvidence serviceKey={row.service_key}/>}</div>
        <div className="approval-review-context"><span>Snapshot scan</span><strong>{dateLabel(row.scan_date || snapshot.scan_date)}</strong><small>Frozen evidence · later service changes do not update this review.</small>{row.evidence_url && <a href={row.evidence_url}>Download retained evidence ↗</a>}{row.submission_url && <a href={row.submission_url}>Download original submission ↗</a>}</div>
      </section>
      <ReviewTrack row={row} snapshot={snapshot}/>
      <FrozenDistribution selection={snapshot.distribution}/>
      {snapshot.runtime_evidence && <section className="panel padded"><RuntimeEvidence evidence={snapshot.runtime_evidence}/></section>}
      {row.runtime_candidate_id && row.decision_rationale && <section className="panel padded"><h2>Cyber decision rationale</h2><p>{row.decision_rationale}</p>{row.can_resubmit && <a href={`/cyber-approvals?service=${encodeURIComponent(row.service_key)}&runtime_candidate_id=${row.runtime_candidate_id}`}>Review candidate for resubmission</a>}</section>}
      {!!snapshot.review_notes?.length && <section className="approval-review-notes panel padded"><h2>Cyber review considerations</h2><ul>{snapshot.review_notes.map((note: string, index: number) => <li key={index}>{note}</li>)}</ul></section>}
      <ServiceAtAGlance snapshot={snapshot}/>
      <ApprovalFindings findings={snapshot.findings} intelligence={snapshot.risk_intelligence}/>
      <section className="panel padded approval-support"><h2>Supporting evidence</h2><p>Artifact references show the sources submitted for review. After publication, Approved Releases shows the registry references to deploy.</p>
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
      {(row.destination?.id || row.additional_destination) && <section className="panel padded" aria-label="Requested release destinations">
        <h2>Requested release destinations</h2>
        {row.destination?.id && <RegistryAddress label="Cyber destination" destination={row.destination}/>}
        {row.additional_destination && <RegistryAddress label="Additional service destination" destination={row.additional_destination}/>}
      </section>}
      <Decision data={data} row={row} refresh={resource.refresh}/>
      {row.status === 'approved' && !row.runtime_candidate_id && (snapshot.distribution ? <section className="panel padded">
        <h2>Reassess this distribution</h2>
        <p>Open <a href={`/services/${encodeURIComponent(row.service_key)}?artifacts=true#service-distributions`}>Service distributions</a>, scan <strong>{snapshot.distribution.name}</strong>, and submit its new evidence for Cyber review.</p>
      </section> : <Reassessment data={data} row={row}/>)}
      {row.status === 'approved' && <section className="panel padded"><h2>Approved release publication</h2><p>The Cyber decision is approved. Publication status: <StatusBadge value={row.publish_status || 'pending'}/></p><a href={`/approved-releases?id=${encodeURIComponent(row.release_id || row.publication?.release_id || row.id)}`}>Open approved release</a></section>}
    </>}
  </div>;
}

export function Page({data}: {data: PageData}) {
  const params = new URLSearchParams(window.location.search), id = params.get('id') || data.approval_id;
  const service = params.get('service') || data.service_key || '';
  const runtimeId = params.get('runtime_candidate_id');
  if (!id && service && runtimeId) return <><ServiceTabs serviceKey={service} active="approvals"/><RequestApproval key={service + runtimeId} data={data} serviceKey={service} runtimeCandidateId={runtimeId}/></>;
  return id ? <ApprovalDetail key={id} data={data} id={String(id)}/> : <ApprovalList data={data} serviceKey={service} distributionId={params.get('distribution_id') || undefined}/>;
}
function ApprovalList({data, serviceKey, distributionId}: {data: PageData; serviceKey: string; distributionId?: string}) {
  const [status, setStatus] = useState('');
  const query = new URLSearchParams(); if (serviceKey) query.set('service', serviceKey); if (status) query.set('status', status);
  const resource = useResource(`/api/cyber-approvals?${query}`), rows = list(resource.value);
  const total = resource.value?.total ?? rows.length;
  const columns: GridColumn<Row>[] = [
    {key: 'service', header: 'Service / snapshot', identifier: true, hideable: false, value: row => `${row.service_name || row.service_key} ${row.version || ''}`,
      render: row => <a href={`/cyber-approvals?id=${row.id}`}>{row.service_name || row.service_key} · {row.version || row.label || `#${row.id}`}{row.distribution_name && <> · {row.distribution_name}</>}</a>},
    {key: 'variant', header: 'Variant', value: row => row.label || variantLabel(row.variant), render: row => row.label || variantLabel(row.variant)},
    {key: 'requested', header: 'Requested', type: 'date', value: row => row.requested_at, render: row => row.requested_at || '—'},
    {key: 'decision', header: 'Cyber decision', hideable: false, value: row => row.status, description: 'Human Cyber reviewer decision on the frozen snapshot',
      render: row => <StatusBadge value={row.status} size="sm"/>},
    {key: 'publication', header: 'Publication', value: row => row.publish_status || 'not_started', description: 'Delivery of approved artifacts (separate from the decision)',
      render: row => <StatusBadge value={row.publish_status || 'not_started'} size="sm"/>},
  ];
  return <><PageHeader eyebrow="Cyber review" title="Approvals" description="Review immutable service snapshots and track decisions independently of publication."
    actions={<a className="secondary-button" href="/approved-releases">Approved Releases</a>}/>
    {serviceKey && <><ServiceTabs serviceKey={serviceKey} active="approvals"/><VexEvidence serviceKey={serviceKey}/><RequestApproval key={serviceKey + ':' + (distributionId || '')} data={data} serviceKey={serviceKey} distributionId={distributionId}/></>}
    <section className="panel"><DataGrid<Row> id="cyber-approvals" label={serviceKey ? `${serviceKey} requests` : 'Approval queue'} title={serviceKey ? `${serviceKey} requests` : 'Approval queue'}
      description={resource.value ? `${total} ${total === 1 ? 'request' : 'requests'}` : undefined}
      toolbar={<label className="inline-field">Decision status<select value={status} onChange={event => setStatus(event.target.value)}><option value="">All decisions</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="denied">Denied / rejected</option><option value="returned">Returned for changes</option></select></label>}
      trailingActions={<button type="button" className="secondary-button" onClick={resource.refresh}>Refresh</button>}
      above={resource.error ? <ResourceState error={resource.error} pending={false}/> : null}
      columns={columns} rows={rows} rowKey={row => row.id} loading={!resource.value && !resource.error}
      // Sorting covers the dataset only when the API returned every matching request.
      sort={total <= rows.length ? {mode: 'client'} : {mode: 'none'}}
      empty={<EmptyState title="No requests match this view.">Open a service and choose Request Cyber Approval to start a review.</EmptyState>}/></section></>;
}

export function Releases({data}: {data: PageData}) {
  const id = new URLSearchParams(window.location.search).get('id') || data.release_id;
  return id ? <ReleaseDetail key={id} data={data} id={String(id)}/> : <ReleaseList/>;
}
function ReleaseList() {
  const serviceKey = new URLSearchParams(window.location.search).get('service') || '';
  const [query, setQuery] = useState(''), [variant, setVariant] = useState('');
  const resource = useResource(`/api/approved-releases${serviceKey ? `?service=${encodeURIComponent(serviceKey)}` : ''}`), all = list(resource.value);
  const rows = all.filter(row => (!variant || row.variant === variant) && `${row.service_name} ${row.service_key} ${row.version} ${row.distribution_name || ''} ${row.approved_by || ''}`.toLowerCase().includes(query.toLowerCase()));
  const columns: GridColumn<Row>[] = [
    {key: 'service', header: 'Service', identifier: true, hideable: false, value: row => row.service_name || row.service_key,
      render: row => <a href={`/approved-releases?id=${row.id}`}>{row.service_name || row.service_key}{row.distribution_name && <> · {row.distribution_name}</>}</a>},
    {key: 'version', header: 'Version', value: row => row.version || row.label, render: row => row.version || row.label || '—'},
    {key: 'variant', header: 'Variant', value: row => row.label || variantLabel(row.variant), render: row => row.label || variantLabel(row.variant)},
    {key: 'authorization', header: 'Authorization', hideable: false, value: row => row.revoked ? 'revoked' : row.validity_status, description: 'Whether the approval currently authorizes deployment',
      render: row => row.revoked ? <StatusBadge value="revoked" label="Revoked" tone="danger" size="sm"/> : <StatusBadge value={row.validity_status || 'reapproval_required'} label={humanize(row.validity_status || 'reapproval_required')} size="sm"/>},
    {key: 'publication', header: 'Publication', hideable: false, value: row => row.publish_status || 'not_started', render: row => <StatusBadge value={row.publish_status || 'not_started'} size="sm"/>},
    {key: 'approved_by', header: 'Approved by', hideable: false, value: row => row.approved_by || '', render: row => row.approved_by || 'Not recorded'},
    {key: 'expires', header: 'Expires', type: 'date', value: row => row.expires_at, render: row => row.expires_at ? new Date(row.expires_at).toLocaleString() : '—'},
    {key: 'scan', header: 'Scan date', type: 'date', value: row => row.scan_date, render: row => dateLabel(row.scan_date)},
    {key: 'destination', header: 'Destination', value: row => row.destination?.name, render: row => row.destination?.name || 'Recorded in release'},
  ];
  const filtered = Boolean(query || variant);
  return <><PageHeader eyebrow="Trusted delivery" title="Approved Releases" description="Cyber-approved snapshots, their publication progress, and immutable deployment artifacts."
    actions={<><a className="secondary-button" href="/imported-releases">Imported approved releases</a><a className="secondary-button" href="/cyber-approvals">Approvals</a></>}/>
    {serviceKey && <ServiceTabs serviceKey={serviceKey} active="releases"/>}
    <section className="panel"><DataGrid<Row> id="approved-releases" label="Approved releases" title="Approved releases"
      description={resource.value ? `${rows.length} of ${all.length} releases` : undefined}
      toolbar={<div className="approval-filters inline-filters" role="search" aria-label="Find releases"><label className="inline-field">Find a release<input value={query} onChange={event => setQuery(event.target.value)} placeholder="Service, version, distribution or approver"/></label>
        <label className="inline-field">Variant<select value={variant} onChange={event => setVariant(event.target.value)}><option value="">All variants</option><option value="current_service">Current Service</option><option value="cats_remediated">CATS Remediated</option></select></label></div>}
      trailingActions={<button type="button" className="secondary-button" onClick={resource.refresh}>Refresh</button>}
      above={resource.error ? <ResourceState error={resource.error} pending={false}/> : null}
      columns={columns} rows={rows} rowKey={row => row.id} loading={!resource.value && !resource.error} sort={{mode: 'client'}}
      rowClassName={row => row.revoked ? 'row-revoked' : undefined}
      empty={<EmptyState kind={filtered ? 'filtered' : 'empty'} title="No approved releases match this view."/>}/></section></>;
}
function ArtifactLinks({value}: {value: any}) {
  const rows = Array.isArray(value) ? value : value && typeof value === 'object' ? Object.entries(value).map(([name, url]) => ({name, url})) : [];
  return <ul>{rows.map((row: Row, index: number) => {const href = row.url || row.href || row.download_url; return <li key={index}>{typeof href === 'string' && href.startsWith('/') && !href.startsWith('//') ? <a href={href}>{row.name || row.label || 'Download evidence'}</a> : <span>{row.name || row.label || label(row)}</span>}</li>;})}</ul>;
}
function ReleaseReference({value, title}: {value: string; title: string}) {
  const [notice, setNotice] = useState('');
  async function copy() {
    try {await window.navigator.clipboard.writeText(value); setNotice('Copied.');}
    catch {setNotice('Select the reference to copy it manually.');}
  }
  return <div className="release-reference"><div><span className="approval-muted">{title}</span><code className="approval-ref">{value}</code></div>
    <button type="button" className="secondary-button" aria-label={`Copy ${title.toLowerCase()}`} onClick={copy}>Copy</button>
    {notice && <small role="status">{notice}</small>}
  </div>;
}

export function ReleaseDetail({data, id}: {data: PageData; id: string}) {
  // A different release must never inherit an open confirmation or pending action.
  return <ReleaseDetailView key={id} data={data} id={id}/>;
}
function ReleaseDetailView({data, id}: {data: PageData; id: string}) {
  const resource = useResource(`/api/approved-releases/${encodeURIComponent(id)}`), row = resource.value;
  const [busy, setBusy] = useState<'retry' | 'revoke' | 'additional-release' | 'additional-revocation' | null>(null), [error, setError] = useState('');
  const [confirming, setConfirming] = useState(false), [rationale, setRationale] = useState(''), [notice, setNotice] = useState('');
  async function retry() {
    if (busy) return;
    setBusy('retry'); setError(''); setNotice('');
    try {await mutate(data, `/api/approved-releases/${encodeURIComponent(id)}/retry`, {}); resource.refresh();}
    catch (error) {setError(message(error));} finally {setBusy(null);}
  }
  async function retryAdditional(kind: 'release' | 'revocation') {
    if (busy) return;
    setBusy(`additional-${kind}`); setError(''); setNotice('');
    try {
      const result = await mutate(data, `/api/approved-releases/${encodeURIComponent(id)}/additional-deliveries/${kind}/retry`, {});
      resource.update(result);
      setNotice(`Additional ${kind} delivery queued.`);
    } catch (cause) {setError(message(cause));} finally {setBusy(null);}
  }
  async function revoke(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || row?.can_revoke !== true || rationale.trim().length < 3) return;
    setBusy('revoke'); setError(''); setNotice('');
    try {
      const result = await mutate(data, `/api/approved-releases/${encodeURIComponent(id)}/revoke`, {rationale: rationale.trim()});
      resource.update(result); setConfirming(false); setRationale(''); setNotice('Release revoked. Future pulls must satisfy another current approval.');
    } catch (error) {setError(message(error));} finally {setBusy(null);}
  }
  const publication = row?.publication || {}, artifacts = list(row?.artifacts || publication.artifacts || []);
  const images = list(row?.snapshot?.artifacts).map((artifact, index) => ({artifact, index}))
    .filter(({artifact}) => artifact?.kind === 'image');
  const revocation = publication.revocation || {};
  const publishing = ['queued', 'publishing'].includes(row?.publish_status);
  const canRetry = row?.publish_status === 'failed' && (row.revoked
    ? row.can_retry === true && Boolean(revocation.portable)
    : currentApproval(row) && (row.can_retry ?? can(data, 'approval.decide', row.service_id)));
  return <div className="release-detail">
    <a className="back" href="/approved-releases">All approved releases</a>
    <ResourceState error={resource.error} pending={!row && !resource.error}/>
    {notice && <p className="release-notice" role="status">{notice}</p>}
    {row && <>
      <section className="release-heading" aria-label="Release summary">
        <div><p className="eyebrow">APPROVED RELEASE · #{row.id}</p><h1>{row.service_name || row.service_key}</h1>
          <p className="approval-muted">{row.version || row.label || 'Version not recorded'} · {variantLabel(row.variant)}{row.distribution_name && <> · {row.distribution_name}</>}</p>
          <Badges row={{...row, status: 'approved'}} showExpiry={false}/>
        </div>
        <div className="release-actions"><button className="secondary-button" type="button" disabled={!!busy} onClick={resource.refresh}>Refresh publication</button>
          {row.can_revoke === true && !row.revoked && <button className="release-danger-button" type="button" disabled={!!busy || confirming} onClick={() => {setConfirming(true); setError(''); setNotice('');}}>Revoke release</button>}
        </div>
      </section>
      <dl className="release-facts" aria-label="Release approval details">
        <div><dt>Approved by</dt><dd>{row.approved_by || 'Not recorded'}</dd></div>
        <div><dt>Approved on</dt><dd>{dateLabel(row.decided_at)}</dd></div>
        <div><dt>Expires</dt><dd>{dateLabel(row.expires_at)}</dd></div>
        <div><dt>Scan date</dt><dd>{dateLabel(row.scan_date)}</dd></div>
      </dl>
      {row.revoked && <div className="release-revoked" role="alert"><strong>This release has been revoked and is no longer authorized for deployment.</strong>
        {row.revocation_reason && <p>{row.revocation_reason}</p>}{row.revoked_at && <small>Revoked {dateLabel(row.revoked_at)}</small>}
      </div>}
      {confirming && row.can_revoke === true && !row.revoked && <section className="panel padded release-confirmation" aria-label="Confirm release revocation">
        <h2>Revoke release #{row.id}</h2><p>This withdraws the Cyber approval and blocks future CATS pulls authorized by this release. Running containers and images already downloaded are not removed. Retained evidence remains available for audit.</p>
        {row.snapshot?.portable_release && row.destination && <p>CATS will publish a signed revocation. Other CATS installations enforce it after synchronization.</p>}
        <form className="approval-form" onSubmit={revoke}><label>Revocation reason<textarea required minLength={3} maxLength={10000} value={rationale} disabled={!!busy} onChange={event => setRationale(event.target.value)} autoFocus/></label>
          <ResourceState error={error} pending={false}/><div className="release-actions"><button type="submit" className="release-danger-button" disabled={!!busy || rationale.trim().length < 3}>{busy === 'revoke' ? 'Revoking release…' : 'Confirm revocation'}</button>
            <button type="button" className="secondary-button" disabled={!!busy} onClick={() => {setConfirming(false); setRationale(''); setError('');}}>Cancel</button></div>
        </form>
      </section>}
      <section className="panel padded release-publication" aria-label="Release publication">
        <div className="release-section-heading"><h2>Publication</h2><a href={`/cyber-approvals?id=${row.approval_id || row.id}`}>Review Cyber decision and snapshot</a></div>
        <p>{row.revoked ? 'Retained artifacts and evidence are shown for audit history.' : !currentApproval(row) ? 'This release needs a new Cyber approval before deployment. Retained downloads are available for audit history.' : row.publish_status === 'published' ? 'Published artifacts are ready to retrieve using their immutable references.' : 'This snapshot is Cyber approved. Artifact delivery is not complete until publication succeeds.'}</p>
        {row.destination?.name ? <RegistryAddress label="Cyber destination" destination={row.destination}/> : <p>Cyber destination not recorded.</p>}
        {publishing && !row.revoked && <p className="approval-muted">Revocation is available after publication completes or fails.</p>}
        {row.revoked && revocation.status && <p>Signed revocation: <StatusBadge value={revocation.status}/>{['queued', 'publishing'].includes(revocation.status) && ' Other CATS installations update after publication and synchronization.'}</p>}
        {(row.publish_error || publication.error || revocation.error) && <p className="error" role="alert">{row.publish_error || publication.error || revocation.error}</p>}
        {row.publish_status === 'failed' && <PublicationDiagnostic publication={row.revoked && revocation.diagnostic ? revocation : publication}/>}
        {!confirming && <ResourceState error={error} pending={false}/>}
        {canRetry && <button type="button" className="secondary-button" disabled={!!busy} onClick={retry}>{busy === 'retry' ? 'Queuing publication…' : row.revoked ? 'Retry revocation publication' : 'Retry publication'}</button>}
      </section>
      {row.additional_destination && <section className="panel padded release-publication" aria-label="Additional service delivery">
        <h2>Additional service delivery</h2>
        <RegistryAddress label="Service destination" destination={row.additional_destination}/>
        {list(row.additional_deliveries).length === 0 && <p>Delivery of the approved release and its body of evidence has not started.</p>}
        {list(row.additional_deliveries).map(delivery => {
          const kind: 'release' | 'revocation' = delivery.kind === 'revocation' ? 'revocation' : 'release';
          return <div key={kind}>
            <p>{kind === 'revocation' ? 'Signed revocation' : 'Approved release and body of evidence'} <StatusBadge value={delivery.status}/></p>
            {delivery.reference && <ReleaseReference title={kind === 'revocation' ? 'Additional revocation reference' : 'Additional release reference'} value={delivery.reference}/>}
            {delivery.error && <p role="alert">{delivery.error}</p>}
            {delivery.can_retry && <button type="button" className="secondary-button" disabled={!!busy || confirming}
              onClick={() => void retryAdditional(kind)}>Retry additional {kind} delivery</button>}
          </div>;
        })}
      </section>}
      <FrozenDistribution selection={row.snapshot?.distribution}/>
      {row.snapshot?.runtime_evidence && <section className="panel padded"><RuntimeEvidence evidence={row.snapshot.runtime_evidence}/>
        {row.submission_url && <a href={row.submission_url}>Download original submission ↗</a>}</section>}
      {images.length > 0 && <section className="panel padded" aria-label="Pull release images from CATS">
        <h2>Pull release images from CATS</h2>
        <p>Use each image’s digest-pinned reference in your deployment. These images come from this release’s approved snapshot.</p>
        <ul className="release-artifact-list">{images.map(({artifact, index}) =>
          <li key={index}><code className="image-ref">{artifact.reference}</code>
            {currentApproval(row) && !row.revoked && <ReleaseImagePullInstructions releaseId={row.id} index={index} reference={artifact.reference}/>}
          </li>)}</ul>
      </section>}
      <div className="release-content-grid">
        <section className="panel padded release-artifacts" aria-label="Immutable artifacts">
          <div className="release-section-heading"><h2>Immutable artifacts</h2><span className="approval-count">{artifacts.length} {artifacts.length === 1 ? 'artifact' : 'artifacts'}</span></div>
          {publication.release?.reference && <ReleaseReference title="Release manifest" value={publication.release.reference}/>}
          {!artifacts.length && <p className="approval-muted">Artifact references will appear when publication completes.</p>}
          <ul className="release-artifact-list">{artifacts.map((artifact, index) => {
            const reference = artifact.immutable_ref || artifact.ref || artifact.reference || artifact.digest;
            const name = artifact.name || humanize(artifact.kind || artifact.type || `Artifact ${index + 1}`);
            return <li key={index}><h3>{name}</h3>{reference && <ReleaseReference title={`${name} reference`} value={reference}/>}
              {artifact.digest && !String(reference || '').includes(artifact.digest) && <p className="approval-muted">Digest: <code className="approval-ref">{artifact.digest}</code></p>}
              <EvidenceSection title="Signature verification" value={artifact.signature || artifact.signature_evidence}/>
            </li>;
          })}</ul>
        </section>
        <section className="panel padded release-evidence" aria-label="Release evidence and downloads"><h2>Evidence and downloads</h2>
          <p className="approval-muted">Retained evidence for this exact release.</p>
          <ArtifactLinks value={row.evidence_links || publication.evidence_links || (row.evidence_url ? [{name:'Download retained evidence',url:row.evidence_url}] : [])}/>
          <ArtifactLinks value={row.offline_links || publication.offline_links || (row.offline_bundle_url ? [{name:'Download offline release bundle',url:row.offline_bundle_url}] : [])}/>
          {!row.evidence_links && !publication.evidence_links && !row.evidence_url && !row.offline_links && !publication.offline_links && !row.offline_bundle_url && <p className="approval-muted">No downloads are available for this account.</p>}
          <EvidenceSection title="Signing evidence" value={row.signature || publication.signature || publication.release?.signature || row.signature_evidence || (publication.signing_fingerprint ? {signing_fingerprint:publication.signing_fingerprint} : undefined)}/>
          <details className="approval-support-section"><summary>Pull and deployment instructions</summary>
            {row.publish_status === 'published' && !row.revoked && currentApproval(row) && publication.release?.reference && <pre className="approval-json">{`oras pull ${publication.release.reference}`}</pre>}
            <p>Verify signatures and approval expiry with the signing key fingerprint supplied independently by your Cyber approver. A signature alone does not establish current authorization.</p>
            <pre className="approval-json">{row.pull_instructions || publication.pull_instructions || row.destination?.pull_instructions || 'Use the offline bundle README to verify the retained release and import it into your registry. Map the approved image digests into your environment-specific Helm values before deploying the retained charts.'}</pre>
            {row.deploy_instructions && <pre className="approval-json">{row.deploy_instructions}</pre>}
          </details>
        </section>
      </div>
      <ReleaseRevision key={`${id}:${row.revoked_at || row.revoked || ''}`} compact hideMissing readOnly={!!row.revoked} showDistribution={!row.snapshot?.distribution} data={data} approvalId={String(row.approval_id || row.id)} serviceId={row.service_id}/>
    </>}
  </div>;
}

export function Destinations({data}: {data: PageData}) {
  const resource = useResource('/api/approved-release-destinations'), [editing, setEditing] = useState<Row | null>(null), [notice, setNotice] = useState('');
  return <><Heading title="Approved Release Destinations" description="Configure the Cyber registries that receive approved releases and their evidence. Service managers can select an additional service registry when requesting approval."/><AdminTabs data={data} selected="release-destinations"/><section className="panel padded"><h2>Registry destinations</h2><ResourceState error={resource.error} pending={!resource.value && !resource.error}/>{notice && <p role="status">{notice}</p>}<div className="table-wrap"><table><thead><tr>{['Name', 'Endpoint / namespace', 'Group IDs', 'Credentials', 'Default', 'Actions'].map(name => <th key={name}>{name}</th>)}</tr></thead><tbody>{list(resource.value).map(row => <tr key={row.id}><td>{row.name}</td><td>{destinationAddress(row)}</td><td>{(row.group_ids || []).join(', ') || 'All permitted groups'}</td><td>{(row.credentials_configured || row.has_credentials) ? 'Configured' : 'Not configured'}</td><td>{row.is_default ? 'Yes' : 'No'}</td><td><button className="secondary-button" type="button" onClick={() => {setEditing(row); setNotice('');}}>Edit {row.name}</button></td></tr>)}{!list(resource.value).length && <tr><td colSpan={6} className="empty table-empty">No registry destinations configured yet.</td></tr>}</tbody></table></div><button type="button" className="secondary-button" onClick={() => {setEditing({}); setNotice('');}}>Add destination</button></section>{editing && <DestinationForm key={editing.id || 'new'} data={data} row={editing} cancel={() => setEditing(null)} saved={() => {setEditing(null); setNotice('Destination saved.'); resource.refresh();}}/>}<section className="panel padded"><h2>Signing configuration</h2><p>Approved releases use the global signing configuration. Destination credentials are retained on the server and are never returned to this page.</p><a href="/admin/configuration">Manage global signing settings</a></section><OCIDistribution data={data}/></>;
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
  return <section className="panel padded"><h2>{row.id ? 'Edit destination' : 'Add destination'}</h2><form className="approval-form" onSubmit={submit}><label>Registry name<input name="name" required defaultValue={row.name || ''}/></label><label>Registry endpoint<input name="endpoint" required defaultValue={row.endpoint || ''} type="url" placeholder="https://registry.example.com"/></label><label>Namespace<input name="namespace" required defaultValue={row.namespace || ''} placeholder="approved"/></label><label>Permitted group IDs<input name="group_ids" defaultValue={(row.group_ids || []).join(', ')} placeholder="1, 2"/></label><label>Registry username<input name="username" defaultValue={row.username || ''} autoComplete="off"/></label><label>Registry password / token<input type="password" name="password" autoComplete="new-password"/></label>{row.id && <p>Leave the password and custom CA blank to retain their current values.</p>}<label>Custom CA certificate (PEM)<textarea name="ca_pem"/></label><label className="approval-checkbox"><input type="checkbox" name="enabled" defaultChecked={row.enabled !== false}/>Available for new requests</label><label className="approval-checkbox"><input type="checkbox" name="is_default" defaultChecked={row.is_default || false}/>Default Cyber destination</label><label>Pull and deployment instructions<textarea name="pull_instructions" defaultValue={row.pull_instructions || ''}/></label><ResourceState error={error} pending={false}/><div className="dialog-actions"><button type="button" className="secondary-button" disabled={busy} onClick={cancel}>Cancel</button><button disabled={busy}>{busy ? 'Saving…' : 'Save destination'}</button></div></form></section>;
}
