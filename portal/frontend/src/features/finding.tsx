import {VexEvidence} from './native_vex';
import {lazy, Suspense} from 'react';
import {can, type PageData} from '../api';
import {safeReference} from '../components/Form';
import {Callout, MetricCard, MetricGrid, PageHeader, SeverityBadge, StatusBadge} from '../components/ui';
const Remediate = lazy(() => import('./remediations').then(module => ({default:module.Remediate})));

export function Page({data}: {data: PageData}) {
  const {service, finding, evidence, risk} = data;
  const root = `/services/${encodeURIComponent(service.service_key)}`;
  const references: string[] = evidence.urls || [];
  const classification = data.remediation_classification || {};
  return <><PageHeader back={{href: root, label: service.name}} eyebrow="Advisory detail" title={finding.cve}
      status={<StatusBadge size="lg" value={finding.active ? 'active' : 'resolved'} label={finding.active ? 'Active' : 'Resolved'} tone={finding.active ? 'danger' : 'success'}/>}
      meta={<><span>{service.name}</span><span>Namespace: {evidence.namespace || 'Unknown'}</span>{finding.first_seen && <span>First seen {finding.first_seen}</span>}</>}
      actions={data.remediation_enabled && finding.active && can(data, 'remediation.execute', service.id) ? <Suspense fallback={<button disabled>Loading remediation...</button>}><Remediate data={data} finding_type="vulnerability" finding_id={finding.id}/></Suspense> : undefined}/>
    <Callout tone={classification.classification && classification.classification !== 'NOT REMEDIABLE' ? 'info' : 'neutral'} title="Remediation classification"
      actions={<StatusBadge value={classification.classification} label={classification.classification} tone={classification.classification && classification.classification !== 'NOT REMEDIABLE' ? 'info' : 'neutral'}/>}>{classification.reason}</Callout>
    <VexEvidence serviceKey={service.service_key} findingId={finding.id}/><MetricGrid label="Finding risk" className="metric-grid-compact finding-metrics">
      <MetricCard label="Severity" value={<SeverityBadge severity={finding.severity}/>}/>
      <MetricCard label="KEV" value={risk.kev ? <StatusBadge value="kev" label="Known exploited" tone="danger"/> : 'No'}/>
      <MetricCard label="EPSS" value={Number(risk.epss || 0).toFixed(2)} hint="Exploit prediction score"/>
      <MetricCard label="Current age" value={data.age == null ? '—' : `${data.age} days`}/>
      <MetricCard label="First seen" value={finding.first_seen || '—'}/>
      <MetricCard label="Due date" value={data.due_date || '—'}/>
      <MetricCard label="Recurrences" value={finding.recurrence_count ?? 0}/>
    </MetricGrid>
    <section className="detail-grid"><article className="panel detail-panel"><h2>Description</h2><p>{evidence.description || 'No description was supplied by the scanner.'}</p><dl><dt>Data source</dt><dd>{evidence.data_source ? <a href={safeReference(evidence.data_source)}>{evidence.data_source}</a> : '—'}</dd><dt>Package type</dt><dd>{evidence.package_type || '—'}</dd><dt>Last seen</dt><dd>{finding.last_seen}</dd><dt>Exception</dt><dd>{data.exception ? `Accepted until ${data.exception.expires_at} by ${data.exception.approved_by}` : 'None'}</dd></dl></article><article className="panel detail-panel"><h2>CVSS</h2>{evidence.cvss?.length ? evidence.cvss.map((score: any, index: number) => <div className="cvss-entry" key={index}><strong>{score.baseScore ?? '—'}</strong><code>{score.vector || 'No vector'}</code></div>) : <p>No CVSS data was supplied.</p>}<h2>References</h2><ul className="reference-list">{references.length ? references.map((url, index) => <li key={index}><a href={safeReference(url)}>{url}</a></li>) : <li>No references supplied.</li>}</ul></article></section>
    <section className="panel"><div className="panel-head"><div><h2>Currently affected</h2><p>Image and package evidence from the latest complete assessment.</p></div></div><div className="table-wrap"><table><thead><tr>{['Image', 'Package', 'Installed', 'Fixed versions'].map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{data.current_observations.length ? data.current_observations.map((item: any, index: number) => <tr key={index}><td><code>{item.image}</code></td><td>{item.package || '—'}</td><td>{item.installed_version || '—'}</td><td>{item.fixed_version || '—'}</td></tr>) : <tr><td colSpan={4} className="empty">No current affected image.</td></tr>}</tbody></table></div></section></>;
}

export function Watchlist({data}: {data: PageData}) {
  const {match, service} = data;
  return <><PageHeader back={{href: `/services/${encodeURIComponent(service.service_key)}?finding_state=warnings`, label: `${service.name} warnings`}} eyebrow="Warning evidence" title={match.component_name}
      status={<StatusBadge value="warning" label="Watchlist match" tone="warning"/>} description={`Configured Dependency Watchlist match in ${service.name}. This warning does not change compliance status.`}/><section className="panel padded"><dl className="detail-grid-list">{[['Component', match.component_name], ['Version', match.component_version], ['Ecosystem', match.ecosystem], ['PURL', match.component_purl], ['Image', match.image], ['SBOM scan', `${match.execution_key} · ${match.scanned_at}`], ['Watchlist entry', `${match.entry.purl || match.entry.name} ${match.entry.version_constraint || ''}`]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || '—'}</dd></div>)}</dl><p><a href={`/services/${encodeURIComponent(service.service_key)}?finding_state=warnings`}>Back to warnings</a></p></section></>;
}
